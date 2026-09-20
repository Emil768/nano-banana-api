-- Промокоды. Коды придумываются вручную; код живой, пока текущий момент
-- внутри окна starts_at…ends_at. Обе границы необязательны: пустой starts_at —
-- «действует сразу», пустой ends_at — «без срока». Выключить досрочно:
-- ends_at = now().
--
-- type — только метка канала, для которого код задуман. Пилюлей на сайте
-- светится код с type = 'web'; применить вручную можно любой живой код,
-- независимо от типа.

create table if not exists promo_codes (
  id          bigserial primary key,
  code        text        not null,
  title       text,
  percent     integer     not null check (percent between 1 and 100),
  type        text        not null default 'web' check (type in ('web', 'bot', 'partner')),
  starts_at   timestamptz,
  ends_at     timestamptz,
  created_at  timestamptz not null default now()
);

-- Код сравнивается без учёта регистра: на фронте ввод приводится к верхнему.
create unique index if not exists promo_codes_code_key
  on promo_codes (upper(code));

create index if not exists promo_codes_lookup_idx
  on promo_codes (type, ends_at);

-- Пример: код на сайт, −20%, живёт неделю.
-- insert into promo_codes (code, title, percent, type, starts_at, ends_at)
-- values ('K7M2XP4Q', 'Осенний запуск', 20, 'web', now(), now() + interval '7 days');


-- Пакеты, на которые скидка не распространяется.
-- Отметь promo_excluded = true — и промокод на этот тариф не подействует
-- ни в ценах на сайте, ни в сумме, которая уходит в оплату.

alter table user_price
  add column if not exists promo_excluded boolean not null default false;

-- Стартовый пакет без скидки:
-- update user_price set promo_excluded = true where name ilike '%Старт%';

-- В user_price_free колонку не добавляем: FREE-тарифы не используются.
-- Если понадобится, тот же alter — код прочитает её сам, без правок.
