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
   - `FEEDBACK_CHAT_ID` — chat id хелпера/группы для отзывов с `/feedback`
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
- `FRONTEND_SUCCESS_REDIRECT=https://nanobananaa.ru`
- `FRONTEND_ERROR_REDIRECT=https://nanobananaa.ru?auth_error=1`
- `COOKIE_DOMAIN=.nanobananaa.ru`
- `COOKIE_SECURE=true`
- `SUPABASE_USERS_TABLE=users`
- `SUPABASE_CHAT_ID_COLUMN=chat_id`
- `SUPABASE_BALANCE_COLUMN=balance`
- `SUPABASE_TOTAL_SUM_COLUMN=total_sum`
- `SUPABASE_PRICES_TABLE=user_price`
- `SUPABASE_PRICE_ID_COLUMN=id`
- `SUPABASE_PRICE_NAME_COLUMN=name`
- `SUPABASE_PRICE_GENERATIONS_COLUMN=generations`
- `SUPABASE_PRICE_AMOUNT_COLUMN=price_rub`
- `SUPABASE_VERSION_COLUMN=version` — колонка общая с ботом; сайт только ставит `PRO` новым юзерам
- `SUPABASE_PROMO_TABLE=promo_codes` — таблица промокодов (схема: `sql/promo_codes.sql`)
- `LAOZHANG_AUTH_MODE=bearer` (или `query`)
- `LAOZHANG_URL=https://api.laozhang.ai/v1/images/generations` — полный URL шага 1 (GPT Images); хост из того же значения используется для относительного `LAOZHANG_GEMINI_MODEL`.
- `GPT_MODEL=gpt-image-2.5-flare-vip` — модель для шага 1 (Images API)
- `LAOZHANG_GEMINI_MODEL=/v1beta/models/…:generateContent` — шаг 2 (Gemini): путь на том же хосте или полный URL

Порядок для `POST /api/generate-image`: каскад (1) flare-модель из `GPT_MODEL`, (2) обычная `gpt-image-2` из `GPT_FALLBACK_MODEL` (пусто — шаг выключен), (3) Gemini (`LAOZHANG_GEMINI_MODEL`). В ответе могут быть `fallbackTier`, `cascadeTotal`, `reconnectNotices`. При `"transparentBackground": true` к запросу GPT Images добавляются `background: "transparent"` и `output_format: "png"`, а шаги 2 и 3 не подключаются: прозрачный фон умеет только flare. Если она не справилась — **422** `TRANSPARENT_UNAVAILABLE` (или `TRANSPARENT_SAFETY`, если отказала модерация), генерация не списывается. Флаг `"gptOnly": true` (шлёт страница «Убрать фон») увеличивает таймаут ожидания модели до 5 минут.

- `VISION_MODEL=gemini-3-flash-preview` — «Промт по фото» (`POST /api/describe-image`): модель, которая описывает картинку
- `VISION_MODEL_FALLBACK=gpt-4.1-mini` — запасная, если основная не ответила
- `VISION_GEMINI_NATIVE=false` — `true`: Gemini зовётся нативным API (inline_data), а не через chat/completions
- `DESCRIBE_PER_MINUTE=10` — защита от скриптов: не больше N описаний в минуту на юзера (дневного лимита нет)

- `SEEDANCE_API_KEY=` — ключ для видео (Seedance, laozhang); пусто — используется `LAOZHANG_API_KEY`
- `SEEDANCE_API_BASE=https://api2.laozhang.ai/seedance/api/v3`
- `SEEDANCE_MODEL=doubao-seedance-2-0-fast-260128`
- `SEEDANCE_RESOLUTION=720p`
- `SEEDANCE_RATIO=adaptive` — `16:9`/`4:3`/`1:1`/`3:4`/`9:16`/`21:9`/`adaptive`

`POST /api/generate-video/start` создаёт задачу через `POST {SEEDANCE_API_BASE}/contents/generations/tasks` (image-to-video: текст промпта + `image_url` с `role: "reference_image"`), `GET /api/generate-video/status` опрашивает `GET {SEEDANCE_API_BASE}/contents/generations/tasks/{id}` пока `status` не станет `succeeded`/`completed` (видео — в `content.video_url`) или `failed`/`expired`. См. https://docs.laozhang.ai/en/api-capabilities/seedance2-video-generation

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
- `PAYMENT_RETURN_URL=https://nanobananaa.ru`
- `PAYMENT_CURRENCY=RUB`
- `PAYMENT_WEBHOOK_SECRET=...` (рекомендуется)
- `PAYMENT_WEBHOOK_SECRET_HEADER=x-webhook-secret`

## 4) Что указывать в Telegram Widget

В `index.html`:

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
- `GET /api/pricing` (нужна cookie)
- `POST /api/payments/create` (нужна cookie, body: `{ "planId": 1, "promoCode"?: "..." }`)
- `POST /api/webhooks/platega` (webhook от платежки)
- `POST /api/generate-image` (нужна cookie)

## 7) Проверка после деплоя

1. Открыть `https://nanobananaa.ru/`
2. Нажать "Сгенерировать" -> открыть Telegram Login
3. После входа должен быть редирект обратно на страницу
4. Проверить `GET https://api.nanobananaa.ru/auth/me` (должен вернуть `authenticated: true`)
5. Запустить генерацию

## 8) Важно по безопасности

- Не хранить `SUPABASE_SERVICE_ROLE_KEY`, `LAOZHANG_API_KEY` и `SEEDANCE_API_KEY` во фронте.
- Использовать только HTTPS.
- В проде лучше оставить `COOKIE_SECURE=true`.
