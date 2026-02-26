# Nano Banana Backend

Готовый backend для:
- входа через Telegram Widget (`/auth/telegram/callback`);
- идентификации пользователя по `chat_id` в Supabase;
- проксирования генерации (`/api/generate-image`) с скрытым API-ключом.

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
- `LAOZHANG_AUTH_MODE=bearer` (или `query`)

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
- при `AUTO_CREATE_USER=true` создаст запись, если ее нет;
- ставит cookie `chatid` и `tg_session`;
- редиректит на `FRONTEND_SUCCESS_REDIRECT`.

## 6) API фронту

- `GET /health`
- `GET /auth/me` (нужна cookie)
- `POST /auth/logout`
- `POST /api/generate-image` (нужна cookie)

## 7) Проверка после деплоя

1. Открыть `https://nanobananaa.ru/generate.html`
2. Нажать "Сгенерировать" -> открыть Telegram Login
3. После входа должен быть редирект обратно на страницу
4. Проверить `GET https://api.nanobananaa.ru/auth/me` (должен вернуть `authenticated: true`)
5. Запустить генерацию

## 8) Важно по безопасности

- Не хранить `SUPABASE_SERVICE_ROLE_KEY` и `LAOZHANG_API_KEY` во фронте.
- Использовать только HTTPS.
- В проде лучше оставить `COOKIE_SECURE=true`.
