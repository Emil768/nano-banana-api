-- ИИ-ассистент (/assistant). Прогнать один раз в Supabase → SQL Editor.
-- Только добавляет: существующие колонки и данные не трогает, повторный запуск безопасен.

-- 1. Учёт ассистента у юзера (та же user_settings, что у бота).
alter table user_settings
  add column if not exists assistant_usage_units      bigint    not null default 0, -- расход за текущий день (МСК)
  add column if not exists assistant_usage_date       date,                         -- не сегодня → расход считается 0
  add column if not exists assistant_trial_units_used bigint    not null default 0, -- потрачено из пробного, не сбрасывается
  add column if not exists assistant_tier             text,                         -- NULL | 'pro' | 'mega' | 'ultra'
  add column if not exists assistant_tier_until       timestamptz;

-- 2. Какой уровень ассистента выдаёт пакет. Пустое — пакет уровень не даёт (Старт).
--    Цены и генерации — в sql/tariffs-2026-10.sql, его прогонять отдельно.
alter table user_price
  add column if not exists assistant_tier text;

-- 3. Диалоги и сообщения. Тип user_id берём как у user_settings.id
--    (у Google-юзеров id строковый, вида g…), чтобы внешний ключ сошёлся.
do $$
declare
  id_type text;
begin
  select format_type(a.atttypid, a.atttypmod) into id_type
  from pg_attribute a
  where a.attrelid = 'public.user_settings'::regclass
    and a.attname = 'id' and not a.attisdropped;

  execute format($f$
    create table if not exists assistant_conversations (
      id          bigserial   primary key,
      user_id     %s          not null references user_settings(id) on delete cascade,
      title       text        not null default 'Новый чат',
      created_at  timestamptz not null default now(),
      updated_at  timestamptz not null default now()
    )$f$, id_type);
end $$;

create table if not exists assistant_messages (
  id              bigserial   primary key,
  conversation_id bigint      not null references assistant_conversations(id) on delete cascade,
  role            text        not null check (role in ('user', 'assistant', 'tool')),
  content         text        not null default '',
  image_url       text,
  tool_name       text,
  tokens_in       integer     not null default 0,
  tokens_out      integer     not null default 0,
  units           bigint      not null default 0,
  cost_usd        numeric(12, 6) not null default 0,
  created_at      timestamptz not null default now()
);

create index if not exists assistant_conversations_user_updated_idx
  on assistant_conversations (user_id, updated_at desc);
create index if not exists assistant_messages_conv_created_idx
  on assistant_messages (conversation_id, created_at);
-- Дневной бюджет и статистика считаются по created_at всех сообщений
create index if not exists assistant_messages_created_idx
  on assistant_messages (created_at);

-- Таблицы читает только бэк (service role). Включаем RLS без политик,
-- чтобы анонимный ключ Supabase их не видел.
alter table assistant_conversations enable row level security;
alter table assistant_messages enable row level security;

-- 4. Публичный бакет под картинки ассистента (бэк создаст его и сам при первой загрузке).
insert into storage.buckets (id, name, public)
values ('assistant-images', 'assistant-images', true)
on conflict (id) do nothing;

-- 5. Кто упёрся в лимит — для дневной статистики.
create table if not exists assistant_limit_hits (
  id          bigserial   primary key,
  user_id     text        not null,
  reason      text        not null, -- trial | daily | hard_cap
  created_at  timestamptz not null default now()
);
create index if not exists assistant_limit_hits_created_idx
  on assistant_limit_hits (created_at);
alter table assistant_limit_hits enable row level security;
