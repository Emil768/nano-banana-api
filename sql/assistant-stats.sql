-- Статистика ИИ-ассистента за день (МСК). Supabase → SQL Editor.
-- Другой день: в CTE day замени выражение на, например, date '2026-10-20'.

with day as (
  select ((now() at time zone 'Europe/Moscow')::date) as d
),
bounds as (
  select (d::timestamp at time zone 'Europe/Moscow') as from_ts,
         ((d + 1)::timestamp at time zone 'Europe/Moscow') as to_ts
  from day
),
answers as (
  select m.*, c.user_id
  from assistant_messages m
  join assistant_conversations c on c.id = m.conversation_id, bounds b
  where m.created_at >= b.from_ts and m.created_at < b.to_ts
)
select
  (select d from day)                                                   as day_msk,
  count(*) filter (where role = 'assistant')                            as requests,
  count(distinct user_id) filter (where role = 'user')                  as users,
  round(coalesce(sum(cost_usd), 0), 4)                                  as cost_usd,
  round(coalesce(avg(cost_usd) filter (where role = 'assistant'), 0), 6) as avg_cost_per_request_usd,
  count(*) filter (where role = 'tool' and image_url is not null)       as images_generated,
  (select count(distinct h.user_id) from assistant_limit_hits h, bounds b
    where h.created_at >= b.from_ts and h.created_at < b.to_ts)         as users_hit_limit
from answers;
