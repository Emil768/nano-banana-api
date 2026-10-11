-- Имя для обращения в ИИ-ассистенте («Привет, Эмиль!»).
-- Бэк записывает его при каждом входе: Telegram — first_name, Google — given_name.
-- Только добавляет колонку, повторный запуск безопасен. У уже вошедших имя появится после следующего входа.
alter table user_settings
  add column if not exists display_name text;
