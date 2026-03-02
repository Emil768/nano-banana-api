# Nano Banana Backend

Готовый backend для:
- входа через Telegram Widget (`/auth/telegram/callback`);
- идентификации пользователя по `chat_id` в Supabase;
- проксирования генерации (`/api/generate-image`) с скрытым API-ключом.
- оплаты и пополнения генераций через webhook (`/api/webhooks/platega`).

## 1) Что нужно от тебя

1. Хостинг с Node.js (18+).
2. Домен API (пример: `https://api.nanobananaa.ru`).
3. Данные:
   - `TELEGRAM_BOT_TOKEN`
   - `SUPABASE_URL`
   - `SUPABASE_SERVICE_ROLE_KEY`
   - `LAOZHANG_API_KEY`
4. Таблица Supabase, где есть `chat_id` (или свое имя колонки).

## 2) Быстрый запуск

```bash
cd backend
npm install
cp .env.example .env
npm start
```

## 3) Важные .env поля

- `FRONTEND_ORIGIN=https://nanobananaa.ru`
- `FRONTEND_SUCCESS_REDIRECT=https://nanobananaa.ru/generate.html`
- `FRONTEND_ERROR_REDIRECT=https://nanobananaa.ru/generate.html?auth_error=1`
- `COOKIE_DOMAIN=.nanobananaa.ru`
- `COOKIE_SECURE=true`
- `SUPABASE_USERS_TABLE=users`
- `SUPABASE_CHAT_ID_COLUMN=chat_id`
- `SUPABASE_BALANCE_COLUMN=balance`
- `SUPABASE_BALANCE_FREE_COLUMN=balance_free`
- `SUPABASE_TOTAL_SUM_COLUMN=total_sum`
- `SUPABASE_PRICES_TABLE=user_price`
- `SUPABASE_PRICES_FREE_TABLE=user_price_free`
- `SUPABASE_PRICE_ID_COLUMN=id`
- `SUPABASE_PRICE_NAME_COLUMN=name`
- `SUPABASE_PRICE_GENERATIONS_COLUMN=generations`
- `SUPABASE_PRICE_AMOUNT_COLUMN=price_rub`
- `SUPABASE_VERSION_COLUMN=version`
- `LAOZHANG_AUTH_MODE=bearer` (или `query`)
- `LAOZHANG_URL_FREE=https://api.laozhang.ai/v1beta/models/gemini-2.5-flash-image:generateContent`
- `SUPABASE_SOURCE_COLUMN=` (опционально: если есть отдельная колонка для источника)
- `PAYMENT_PROVIDER_URL=https://app.platega.io/transaction/process`
- `PAYMENT_PROVIDER_API_KEY=...`
- `PAYMENT_PROVIDER_AUTH_MODE=none` (`none`/`bearer`/`header`)
- `PAYMENT_PROVIDER_KEY_HEADER=x-api-key`
- `PAYMENT_PROVIDER_MERCHANT_ID=...` (для Platega)
- `PAYMENT_PROVIDER_SECRET=...` (для Platega)
- `PAYMENT_PROVIDER_MERCHANT_HEADER=X-MerchantId`
- `PAYMENT_PROVIDER_SECRET_HEADER=X-Secret`
- `PAYMENT_METHOD=2`
- `PAYMENT_RETURN_URL=https://nanobananaa.ru/generate.html`
- `PAYMENT_CURRENCY=RUB`
- `PAYMENT_WEBHOOK_SECRET=...` (рекомендуется)
- `PAYMENT_WEBHOOK_SECRET_HEADER=x-webhook-secret`

## 4) Что указывать в Telegram Widget

В `pages/generate.html`:

```html
<script async src="https://telegram.org/js/telegram-widget.js?22"
  data-telegram-login="nano_bananaa_ai_bot"
  data-size="large"
  data-auth-url="https://api.nanobananaa.ru/auth/telegram/callback"
  data-request-access="write">
</script>
```

В BotFather `/setdomain`:

`nanobananaa.ru`  
или если виджет стоит на поддомене:
`www.nanobananaa.ru`

## 5) Что делает callback

`GET /auth/telegram/callback`:
- валидирует `hash` Telegram;
- проверяет свежесть `auth_date`;
- берет `id` как `chat_id`;
- ищет пользователя в Supabase по `chat_id`;
- при `AUTO_CREATE_USER=true` создаст запись, если ее нет (минимум только `chat_id`);
- ставит cookie `chatid` и `tg_session`;
- редиректит на `FRONTEND_SUCCESS_REDIRECT`.

## 6) API фронту

- `GET /health`
- `GET /auth/me` (нужна cookie)
- `POST /auth/logout`
- `POST /api/version` (нужна cookie, body: `{ "version": "pro" | "free" }`)
- `GET /api/pricing?version=pro|free` (нужна cookie)
- `POST /api/payments/create` (нужна cookie, body: `{ "planId": 1, "version": "pro" | "free" }`)
- `POST /api/webhooks/platega` (webhook от платежки)
- `POST /api/generate-image` (нужна cookie)

## 7) Проверка после деплоя

1. Открыть `https://nanobananaa.ru/generate.html`
2. Нажать "Сгенерировать" -> открыть Telegram Login
3. После входа должен быть редирект обратно на страницу
4. Проверить `GET https://api.nanobananaa.ru/auth/me` (должен вернуть `authenticated: true`)
5. Запустить генерацию

## 8) Миграция под переключатель версии

Добавь колонки в `user_settings`:

```sql
alter table user_settings
add column if not exists version text default 'pro';

alter table user_settings
add column if not exists balance_free integer default 0;
```

## 9) Важно по безопасности

- Не хранить `SUPABASE_SERVICE_ROLE_KEY` и `LAOZHANG_API_KEY` во фронте.
- Использовать только HTTPS.
- В проде лучше оставить `COOKIE_SECURE=true`.
