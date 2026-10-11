-- Новые тарифы (октябрь 2026). Прогнать ПОСЛЕ sql/assistant.sql.
-- Меняет только витрину пакетов: балансы юзеров не трогает, уже купленное остаётся.
-- Если бот берёт пакеты из user_price — у него цены тоже поменяются.
--
-- Сначала посмотри, что сейчас в таблице:
--   select * from user_price order by price_rub;
-- Строки ищутся по старой цене. Если цены уже другие — поправь where.

begin;

update user_price set generations = 10,                    assistant_tier = null    where price_rub = 99;
update user_price set generations = 55,                    assistant_tier = 'pro'   where price_rub = 499;
update user_price set generations = 120,                   assistant_tier = 'mega'  where price_rub = 999;
update user_price set generations = 260, price_rub = 1999, assistant_tier = 'ultra' where price_rub = 2999;

-- Должно быть ровно 4 строки: 99/10, 499/55 pro, 999/120 mega, 1999/260 ultra
select * from user_price order by price_rub;

commit;
