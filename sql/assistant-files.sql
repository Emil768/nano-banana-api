-- Документы и файлы с кодом в ИИ-ассистенте. Прогнать после assistant-window.sql.
-- Повторный запуск безопасен.

-- Что прикрепил юзер: [{ path, name, size, kind, truncated, chars }]
-- и извлечённый текст, который видит модель (остаётся после удаления файлов по сроку)
alter table assistant_messages
  add column if not exists files      jsonb,
  add column if not exists files_text text;

-- Чистка по сроку теперь ищет и сообщения с документами
drop index if exists assistant_messages_images_purge_idx;
create index if not exists assistant_messages_attachments_purge_idx
  on assistant_messages (created_at)
  where (image_url is not null or files is not null) and images_deleted_at is null;

-- Приватный бакет под оригиналы (бэк создаст его и сам при первой загрузке)
insert into storage.buckets (id, name, public)
values ('assistant-files', 'assistant-files', false)
on conflict (id) do nothing;
