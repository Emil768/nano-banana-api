-- Картинки ассистента: приватная выдача + удаление файлов через 5 дней.
-- Прогнать один раз в Supabase → SQL Editor. Повторный запуск безопасен.

-- 1. Когда файлы картинок сообщения удалены по сроку. Текст и промт остаются.
alter table assistant_messages
  add column if not exists images_deleted_at timestamptz;

-- Для фоновой чистки: ищет старые сообщения с живыми картинками
create index if not exists assistant_messages_images_purge_idx
  on assistant_messages (created_at)
  where image_url is not null and images_deleted_at is null;

-- 2. Старые записи: из полной публичной ссылки оставляем только path в бакете.
--    https://<проект>.supabase.co/storage/v1/object/public/assistant-images/123/abc.png → 123/abc.png
--    (у сообщений юзера ссылок может быть несколько через перевод строки — меняем все)
update assistant_messages
set image_url = regexp_replace(
  image_url,
  'https?://[^/]+/storage/v1/object/public/assistant-images/',
  '',
  'g'
)
where image_url like '%/storage/v1/object/public/assistant-images/%';

-- Проверка: должно быть 0
select count(*) as still_full_urls
from assistant_messages
where image_url like 'http%';

-- 3. После того как проверишь, что картинки в чате открываются:
--    Storage → assistant-images → Edit bucket → выключить Public.
