-- Новости для модалки на сайте. Заполняет scripts/publish_news.py.
-- Скрин лежит прямо в строке (base64), отдаёт его бэк: /api/news/:id/image.
-- На сайте показывается последняя строка с active = true.

create table if not exists news (
  id bigint generated always as identity primary key,
  post_id integer,
  link text not null,
  image_base64 text not null,
  image_type text not null default 'image/jpeg',
  active boolean not null default true,
  created_at timestamptz not null default now()
);

-- Доступ только через service role (бэк и скрипт), анонимам — ничего.
alter table news enable row level security;
