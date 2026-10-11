-- Лимит ассистента: окно 5 часов вместо суток + статистика возвратов.
-- Прогнать один раз в Supabase → SQL Editor (после assistant-private-images.sql).
-- Повторный запуск безопасен.

-- 1. Окно лимита (Профи/Мега/Ультра) и сутки МСК для скрытого потолка
alter table user_settings
  add column if not exists assistant_window_units bigint not null default 0, -- расход в текущем окне
  add column if not exists assistant_window_start timestamptz,               -- now > start + 5ч → окно истекло
  add column if not exists assistant_day_units    bigint not null default 0, -- только для скрытого потолка
  add column if not exists assistant_day_date     date;

-- Дневные колонки из первой версии больше не нужны (их создала assistant.sql, данных там нет)
alter table user_settings
  drop column if exists assistant_usage_units,
  drop column if exists assistant_usage_date;

-- 2. Статистика: возвращаются ли в чаты и смотрят ли картинки
alter table assistant_conversations
  add column if not exists last_opened_at timestamptz;

alter table assistant_messages
  add column if not exists last_viewed_at timestamptz;
