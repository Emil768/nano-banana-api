import crypto from "node:crypto";
import https from "node:https";
import dotenv from "dotenv";
import express from "express";
import cors from "cors";
import cookieParser from "cookie-parser";
import { createClient } from "@supabase/supabase-js";
import { registerDescribeRoutes } from "./describe.js";


dotenv.config();

const app = express();
const PORT = Number(process.env.PORT || 3000);

const normalizeEnv = (value, fallback = "") => {
  const raw = (value ?? "").toString().trim();
  if (!raw) return fallback;
  return raw.replace(/^['"]|['"]$/g, "");
};

const FRONTEND_ORIGIN = normalizeEnv(
  process.env.FRONTEND_ORIGIN,
  "https://nanobananaa.ru"
);

const ALLOWED_ORIGINS = normalizeEnv(
  process.env.ALLOWED_ORIGINS,
  FRONTEND_ORIGIN
)
  .split(",")
  .map((origin) => origin.trim())
  .filter(Boolean);

const FRONTEND_SUCCESS_REDIRECT =
  normalizeEnv(process.env.FRONTEND_SUCCESS_REDIRECT) || FRONTEND_ORIGIN;

const FRONTEND_ERROR_REDIRECT =
  normalizeEnv(process.env.FRONTEND_ERROR_REDIRECT) ||
  `${FRONTEND_ORIGIN}?auth_error=1`;

const POST_AUTH_REDIRECT_COOKIE = "post_auth_redirect";

const TELEGRAM_BOT_TOKEN = normalizeEnv(process.env.TELEGRAM_BOT_TOKEN);
const TELEGRAM_WIDGET_MAX_AGE_SECONDS = Number(
  process.env.TELEGRAM_WIDGET_MAX_AGE_SECONDS || 300
);
/** Chat id хелпер-аккаунта (или группы), куда слать отзывы с /feedback. */
const FEEDBACK_CHAT_ID = normalizeEnv(process.env.FEEDBACK_CHAT_ID);

const GOOGLE_CLIENT_ID = normalizeEnv(process.env.GOOGLE_CLIENT_ID);
const GOOGLE_CLIENT_SECRET = normalizeEnv(process.env.GOOGLE_CLIENT_SECRET);
/** Явный redirect URI из Google Cloud Console (если задан — используется вместо авто). */
const GOOGLE_REDIRECT_URI_ENV = normalizeEnv(process.env.GOOGLE_REDIRECT_URI);
const AUTH_SESSION_SECRET =
  normalizeEnv(process.env.AUTH_SESSION_SECRET) || TELEGRAM_BOT_TOKEN;

const COOKIE_DOMAIN = normalizeEnv(process.env.COOKIE_DOMAIN) || undefined;
const COOKIE_SECURE = String(process.env.COOKIE_SECURE || "true") === "true";
const COOKIE_SAMESITE = normalizeEnv(process.env.COOKIE_SAMESITE, "Lax");
const COOKIE_MAX_AGE_SECONDS = Number(
  process.env.COOKIE_MAX_AGE_SECONDS || 2592000
);

const SUPABASE_URL = normalizeEnv(process.env.SUPABASE_URL);
const SUPABASE_SERVICE_ROLE_KEY = normalizeEnv(
  process.env.SUPABASE_SERVICE_ROLE_KEY
);
const SUPABASE_USERS_TABLE = normalizeEnv(
  process.env.SUPABASE_USERS_TABLE,
  "users"
);
/** Имя колонки идентификатора пользователя; значения всегда строки (Telegram / Google `g…`). */
const SUPABASE_CHAT_ID_COLUMN = normalizeEnv(
  process.env.SUPABASE_CHAT_ID_COLUMN,
  "chat_id"
);
const SUPABASE_BALANCE_COLUMN = normalizeEnv(
  process.env.SUPABASE_BALANCE_COLUMN,
  "balance"
);
const SUPABASE_SOURCE_COLUMN = normalizeEnv(process.env.SUPABASE_SOURCE_COLUMN);
const SUPABASE_TOTAL_SUM_COLUMN = normalizeEnv(
  process.env.SUPABASE_TOTAL_SUM_COLUMN,
  "total_sum"
);
const SUPABASE_PRICES_TABLE = normalizeEnv(
  process.env.SUPABASE_PRICES_TABLE,
  "user_price"
);
const SUPABASE_PRICE_ID_COLUMN = normalizeEnv(
  process.env.SUPABASE_PRICE_ID_COLUMN,
  "id"
);
const SUPABASE_PRICE_NAME_COLUMN = normalizeEnv(
  process.env.SUPABASE_PRICE_NAME_COLUMN,
  "name"
);
const SUPABASE_PRICE_GENERATIONS_COLUMN = normalizeEnv(
  process.env.SUPABASE_PRICE_GENERATIONS_COLUMN,
  "generations"
);
const SUPABASE_PRICE_AMOUNT_COLUMN = normalizeEnv(
  process.env.SUPABASE_PRICE_AMOUNT_COLUMN,
  "price_rub"
);
/** Пакеты с `true` в этой колонке промокод не удешевляет. */
const SUPABASE_PRICE_PROMO_EXCLUDED_COLUMN = normalizeEnv(
  process.env.SUPABASE_PRICE_PROMO_EXCLUDED_COLUMN,
  "promo_excluded"
);
const SUPABASE_VERSION_COLUMN = normalizeEnv(
  process.env.SUPABASE_VERSION_COLUMN,
  "version"
);
const SUPABASE_PROMO_TABLE = normalizeEnv(
  process.env.SUPABASE_PROMO_TABLE,
  "promo_codes"
);
/**
 * Тип промокода — только метка канала: пилюлей на сайте светится `web`,
 * но ввести руками и применить можно любой живой код (`web`, `bot`, `partner`).
 */
const PROMO_SITE_TYPE = "web";
const AUTO_CREATE_USER =
  String(process.env.AUTO_CREATE_USER || "true") === "true";

const normalizeLaozhangPath = (value) => {
  const raw = normalizeEnv(value);
  if (!raw) return "";
  const fromUrl = raw.match(/^https?:\/\/[^/]+(\/.*)$/i)?.[1] || raw;
  const withLeadingSlash = fromUrl.startsWith("/") ? fromUrl : `/${fromUrl}`;
  return withLeadingSlash.replace("/v1/beta/", "/v1beta/");
};

const normalizeLaozhangHost = (value) =>
  normalizeEnv(value)
    .replace(/^https?:\/\//i, "")
    .replace(/\/+$/, "");

/**
 * `LAOZHANG_URL` — полный URL GPT Images (например `https://api.laozhang.ai/v1/images/generations`).
 * Хост оттуда же используется для относительного `LAOZHANG_GEMINI_MODEL`.
 */
function resolveLaozhangImagesEnv() {
  const raw = normalizeEnv(process.env.LAOZHANG_URL);
  if (!raw) return { imagesFullUrl: "", primaryHost: "" };

  if (/^https?:\/\//i.test(raw)) {
    try {
      const u = new URL(raw);
      const path = (u.pathname || "").replace(/\/+$/, "") || "";
      const origin = u.origin;
      let imagesFullUrl = path ? `${origin}${path}` : origin;
      imagesFullUrl = imagesFullUrl.replace(/\/v1\/beta\//gi, "/v1beta/");
      return {
        imagesFullUrl,
        primaryHost: u.hostname || "",
      };
    } catch {
      return { imagesFullUrl: "", primaryHost: "" };
    }
  }

  return { imagesFullUrl: "", primaryHost: "" };
}

const { imagesFullUrl: LAOZHANG_IMAGES_URL, primaryHost: LAOZHANG_PRIMARY_HOST } =
  resolveLaozhangImagesEnv();

const LAOZHANG_API_KEY = normalizeEnv(process.env.LAOZHANG_API_KEY);
const LAOZHANG_AUTH_MODE = normalizeEnv(
  process.env.LAOZHANG_AUTH_MODE,
  "bearer"
).toLowerCase();

/** Шаг 1 каскада: flare-модель GPT Images (Laozhang). Только она умеет прозрачный фон. Env `GPT_MODEL`. */
const GPT_MODEL = normalizeEnv(
  process.env.GPT_MODEL,
  "gpt-image-2.5-flare-vip"
);

/**
 * Шаг 2: обычная gpt-image-2 — запасная для flare, если та лежит.
 * Прозрачный фон не умеет, поэтому для него не подключается. Env `GPT_FALLBACK_MODEL`; пусто — шаг выключен.
 */
const GPT_FALLBACK_MODEL = normalizeEnv(
  process.env.GPT_FALLBACK_MODEL ?? "gpt-image-2",
  ""
);

/** Шаг 3 (запасной, кроме прозрачного фона): Gemini `generateContent` — путь на хосте или полный URL. Env `LAOZHANG_GEMINI_MODEL`. */
const LAOZHANG_GEMINI_MODEL = normalizeEnv(
  process.env.LAOZHANG_GEMINI_MODEL,
  "/v1beta/models/gemini-3.1-flash-image-preview:generateContent"
);

function resolveLaozhangAbsoluteUrl(host, pathOrFullUrl) {
  const raw = normalizeEnv(pathOrFullUrl);
  if (!raw) return "";
  const normalizedFull = raw.replace("/v1/beta/", "/v1beta/");
  if (/^https?:\/\//i.test(normalizedFull)) return normalizedFull;
  const h = normalizeLaozhangHost(host);
  if (!h) return "";
  const path = normalizeLaozhangPath(normalizedFull);
  return path ? `https://${h}${path}` : "";
}

const PAYMENT_PROVIDER_URL =
  normalizeEnv(process.env.PAYMENT_PROVIDER_URL) ||
  "https://app.platega.io/transaction/process";
const PAYMENT_PROVIDER_API_KEY = normalizeEnv(
  process.env.PAYMENT_PROVIDER_API_KEY
);
const PAYMENT_PROVIDER_MERCHANT_ID = normalizeEnv(
  process.env.PAYMENT_PROVIDER_MERCHANT_ID
);
const PAYMENT_PROVIDER_SECRET = normalizeEnv(
  process.env.PAYMENT_PROVIDER_SECRET
);
const PAYMENT_PROVIDER_MERCHANT_HEADER = normalizeEnv(
  process.env.PAYMENT_PROVIDER_MERCHANT_HEADER,
  "X-MerchantId"
);
const PAYMENT_PROVIDER_SECRET_HEADER = normalizeEnv(
  process.env.PAYMENT_PROVIDER_SECRET_HEADER,
  "X-Secret"
);
const PAYMENT_PROVIDER_AUTH_MODE = (
  normalizeEnv(process.env.PAYMENT_PROVIDER_AUTH_MODE, "none") || "none"
).toLowerCase();
const PAYMENT_PROVIDER_KEY_HEADER = normalizeEnv(
  process.env.PAYMENT_PROVIDER_KEY_HEADER,
  "x-api-key"
);
const PAYMENT_METHOD = Number(process.env.PAYMENT_METHOD || 2);
const PAYMENT_RETURN_URL =
  normalizeEnv(process.env.PAYMENT_RETURN_URL) || FRONTEND_ORIGIN;
const PAYMENT_CURRENCY = normalizeEnv(process.env.PAYMENT_CURRENCY, "RUB");
const WEBHOOK_SECRET = normalizeEnv(process.env.PAYMENT_WEBHOOK_SECRET);
const WEBHOOK_SECRET_HEADER = normalizeEnv(
  process.env.PAYMENT_WEBHOOK_SECRET_HEADER,
  "x-webhook-secret"
);


/** Seedance (laozhang) видео: см. https://docs.laozhang.ai/en/api-capabilities/seedance2-video-generation */
const SEEDANCE_API_KEY = normalizeEnv(
  process.env.SEEDANCE_API_KEY || process.env.LAOZHANG_API_KEY
);
const SEEDANCE_API_BASE = normalizeEnv(
  process.env.SEEDANCE_API_BASE,
  "https://api2.laozhang.ai/seedance/api/v3"
);
const SEEDANCE_MODEL = normalizeEnv(
  process.env.SEEDANCE_MODEL,
  "doubao-seedance-2-0-fast-260128"
);
const SEEDANCE_RESOLUTION = normalizeEnv(process.env.SEEDANCE_RESOLUTION, "720p");
const SEEDANCE_RATIO = normalizeEnv(process.env.SEEDANCE_RATIO, "adaptive");
const TMPFILES_UPLOAD_URL = normalizeEnv(
  process.env.TMPFILES_UPLOAD_URL,
  "https://tmpfiles.org/api/v1/upload"
);

/** @type {Map<string, { chatId: string, cost: number, createdAt: number }>} */
const videoJobMetaByTaskId = new Map();
/** @type {Map<string, { videoUrl: string, balance: number }>} */
const videoJobResultByTaskId = new Map();

if (!SUPABASE_URL || !SUPABASE_SERVICE_ROLE_KEY) {
  console.warn(
    "SUPABASE_URL или SUPABASE_SERVICE_ROLE_KEY не задан. Проверка юзера отключится."
  );
}

const supabase =
  SUPABASE_URL && SUPABASE_SERVICE_ROLE_KEY
    ? createClient(SUPABASE_URL, SUPABASE_SERVICE_ROLE_KEY, {
        auth: { persistSession: false },
      })
    : null;

app.set("trust proxy", 1);
app.use(cookieParser());
app.use(express.json({ limit: "40mb" }));
app.use(express.urlencoded({ extended: true }));
app.use(
  cors({
    origin: (origin, callback) => {
      if (!origin || ALLOWED_ORIGINS.includes(origin)) {
        callback(null, true);
        return;
      }
      callback(new Error("Origin is not allowed by CORS"));
    },
    credentials: true,
  })
);

function signTelegramDataCheck(dataObj, botToken) {
  /** Только поля, которые подписывает Telegram Login Widget. */
  const telegramKeys = new Set([
    "id",
    "first_name",
    "last_name",
    "username",
    "photo_url",
    "auth_date",
  ]);

  const sortedPairs = Object.keys(dataObj)
    .filter(
      (k) =>
        telegramKeys.has(k) &&
        dataObj[k] !== undefined &&
        dataObj[k] !== null &&
        String(dataObj[k]).length > 0
    )
    .sort()
    .map((k) => `${k}=${dataObj[k]}`);

  const dataCheckString = sortedPairs.join("\n");
  const secretKey = crypto.createHash("sha256").update(botToken).digest();

  return crypto
    .createHmac("sha256", secretKey)
    .update(dataCheckString)
    .digest("hex");
}

function isTelegramAuthDataValid(query) {
  if (!TELEGRAM_BOT_TOKEN) {
    return { valid: false, reason: "bot token not configured" };
  }

  if (!query.hash) {
    return { valid: false, reason: "no hash" };
  }

  const expectedHash = signTelegramDataCheck(query, TELEGRAM_BOT_TOKEN);
  if (expectedHash !== query.hash) {
    return { valid: false, reason: "hash mismatch" };
  }

  const authDate = Number(query.auth_date || 0);
  if (!authDate) {
    return { valid: false, reason: "no auth_date" };
  }

  const ageSeconds = Math.floor(Date.now() / 1000) - authDate;
  if (ageSeconds > TELEGRAM_WIDGET_MAX_AGE_SECONDS) {
    return { valid: false, reason: "auth_date expired" };
  }

  return { valid: true };
}

function setChatCookies(req, res, chatId) {
  const isLocalHost =
    req.hostname === "127.0.0.1" || req.hostname === "localhost";

  const common = {
    secure: isLocalHost ? false : COOKIE_SECURE,
    sameSite: isLocalHost ? "Lax" : COOKIE_SAMESITE,
    domain: COOKIE_DOMAIN,
    maxAge: COOKIE_MAX_AGE_SECONDS * 1000,
    path: "/",
  };

  // Только подписанный токен: голый chat_id в куке подделывается кем угодно.
  const token = createSessionToken(chatId);
  if (token) res.cookie("tg_session", token, { ...common, httpOnly: true });
}

function createSessionToken(chatId) {
  if (!AUTH_SESSION_SECRET) return "";
  const exp =
    Math.floor(Date.now() / 1000) + Math.max(COOKIE_MAX_AGE_SECONDS, 3600);
  const base = `${chatId}.${exp}`;
  const sig = crypto
    .createHmac("sha256", AUTH_SESSION_SECRET)
    .update(base)
    .digest("hex");
  return `${base}.${sig}`;
}

function getBackendPublicUrl(req) {
  const fromEnv = normalizeEnv(process.env.BACKEND_PUBLIC_URL).replace(/\/$/, "");
  if (fromEnv) return fromEnv;

  const railway = normalizeEnv(process.env.RAILWAY_PUBLIC_DOMAIN);
  if (railway) return `https://${railway}`;

  const proto = String(req.get("x-forwarded-proto") || req.protocol || "https");
  const host = String(req.get("host") || "");
  if (host) return `${proto}://${host}`;

  return "";
}

function resolveGoogleRedirectUri(req) {
  if (GOOGLE_REDIRECT_URI_ENV) return GOOGLE_REDIRECT_URI_ENV;
  const base = getBackendPublicUrl(req);
  return base ? `${base}/auth/google/callback` : "";
}

function verifySessionToken(tokenValue) {
  if (!AUTH_SESSION_SECRET || !tokenValue) return null;

  const token = String(tokenValue || "").trim();
  const [chatIdRaw, expRaw, sigRaw] = token.split(".");

  if (!chatIdRaw || !expRaw || !sigRaw) return null;

  const exp = Number(expRaw);
  if (!Number.isFinite(exp) || exp < Math.floor(Date.now() / 1000)) {
    return null;
  }

  const base = `${chatIdRaw}.${expRaw}`;
  const expectedSig = crypto
    .createHmac("sha256", AUTH_SESSION_SECRET)
    .update(base)
    .digest("hex");

  const expectedBuf = Buffer.from(expectedSig, "hex");
  const sigBuf = Buffer.from(String(sigRaw), "hex");

  if (expectedBuf.length !== sigBuf.length) return null;
  if (!crypto.timingSafeEqual(expectedBuf, sigBuf)) return null;

  return String(chatIdRaw);
}

function isAllowedFrontendOrigin(origin) {
  return ALLOWED_ORIGINS.includes(String(origin || "").replace(/\/$/, ""));
}

function normalizeFrontendRedirectTarget(value) {
  const raw = normalizeEnv(value);
  if (!raw) return null;

  // Relative path like "/feedback.html"
  if (raw.startsWith("/")) {
    return raw;
  }

  // Absolute URL — only from ALLOWED_ORIGINS (local + prod)
  try {
    const target = new URL(raw);
    if (!isAllowedFrontendOrigin(target.origin)) return null;
    return `${target.origin}${target.pathname}${target.search}${target.hash}`;
  } catch {
    return null;
  }
}

function buildSuccessRedirectUrlWithOverride(chatId, redirectOverride) {
  const token = createSessionToken(chatId);
  const normalized = normalizeFrontendRedirectTarget(redirectOverride);

  let baseRedirect = FRONTEND_SUCCESS_REDIRECT;
  if (normalized) {
    baseRedirect = normalized.startsWith("/")
      ? new URL(normalized, FRONTEND_ORIGIN).toString()
      : normalized;
  }

  if (!token) return baseRedirect;

  try {
    const target = new URL(baseRedirect);
    target.searchParams.set("session", token);
    return target.toString();
  } catch {
    const glue = baseRedirect.includes("?") ? "&" : "?";
    return `${baseRedirect}${glue}session=${encodeURIComponent(token)}`;
  }
}

function resolvePostAuthRedirect(req) {
  const fromQuery = normalizeFrontendRedirectTarget(req.query?.redirect);
  if (fromQuery) return fromQuery;

  const fromCookie = normalizeFrontendRedirectTarget(req.cookies?.[POST_AUTH_REDIRECT_COOKIE]);
  if (fromCookie) return fromCookie;

  return null;
}

async function getUserByChatId(chatId) {
  if (!supabase) return null;

  const { data, error } = await supabase
    .from(SUPABASE_USERS_TABLE)
    .select("*")
    .eq(SUPABASE_CHAT_ID_COLUMN, String(chatId))
    .maybeSingle();

  if (error) throw error;
  return data || null;
}

async function createUserIfMissing(chatId) {
  if (!supabase) return null;

  const insertPayload = {
    [SUPABASE_CHAT_ID_COLUMN]: String(chatId),
    [SUPABASE_BALANCE_COLUMN]: 1,
    // balance_free и version — колонки, общие с ботом; FREE-режима больше нет
    balance_free: 0,
    [SUPABASE_TOTAL_SUM_COLUMN]: 0,
    [SUPABASE_VERSION_COLUMN]: "PRO",
    format_photo: "auto",
    type_photo: "4K",
    select_type: "photo",
    status: "null",
    style_photo: "empty",
  };

  const { data, error } = await supabase
    .from(SUPABASE_USERS_TABLE)
    .insert(insertPayload)
    .select("*")
    .single();

  if (error) throw error;
  return data;
}

const BALANCE_CAS_MAX_ATTEMPTS = 6;

/**
 * Атомарно списывает `cost` с баланса через compare-and-swap (UPDATE ... WHERE
 * balanceColumn = <прочитанное значение>) с ретраями при конфликте.
 * Без этого при параллельных запросах все они читают один и тот же баланс,
 * все проходят проверку "хватает ли" и все списывают независимо — баланс
 * может улететь в минус, а провайдер уже реально оплачен за каждую генерацию.
 */
async function reserveBalance(chatId, balanceColumn, cost) {
  if (!supabase) return { ok: true, balance: null };

  let known = null;
  for (let attempt = 0; attempt < BALANCE_CAS_MAX_ATTEMPTS; attempt++) {
    if (known == null) {
      const user = await getUserByChatId(chatId);
      const raw = Number(user?.[balanceColumn]);
      known = Number.isFinite(raw) ? raw : 0;
    }

    if (known < cost) {
      return { ok: false, balance: known };
    }

    const next = known - cost;
    const { data, error } = await supabase
      .from(SUPABASE_USERS_TABLE)
      .update({ [balanceColumn]: next })
      .eq(SUPABASE_CHAT_ID_COLUMN, chatId)
      .eq(balanceColumn, known)
      .select(balanceColumn);

    if (error) throw error;

    if (Array.isArray(data) && data.length > 0) {
      return { ok: true, balance: next };
    }

    // Кто-то параллельно уже изменил баланс — перечитываем и пробуем снова.
    known = null;
  }

  console.error("reserveBalance: CAS conflict exceeded retries", {
    chatId,
    balanceColumn,
    cost,
  });
  return { ok: false, balance: known ?? 0 };
}

/** Возврат ранее списанного `cost` (напр. при неудачной генерации). Тоже CAS. */
async function refundBalance(chatId, balanceColumn, cost) {
  if (!supabase || cost <= 0) return null;

  let known = null;
  for (let attempt = 0; attempt < BALANCE_CAS_MAX_ATTEMPTS; attempt++) {
    if (known == null) {
      const user = await getUserByChatId(chatId);
      const raw = Number(user?.[balanceColumn]);
      known = Number.isFinite(raw) ? raw : 0;
    }

    const next = known + cost;
    const { data, error } = await supabase
      .from(SUPABASE_USERS_TABLE)
      .update({ [balanceColumn]: next })
      .eq(SUPABASE_CHAT_ID_COLUMN, chatId)
      .eq(balanceColumn, known)
      .select(balanceColumn);

    if (error) throw error;

    if (Array.isArray(data) && data.length > 0) {
      return next;
    }

    known = null;
  }

  console.error("refundBalance: CAS conflict exceeded retries — manual fix needed", {
    chatId,
    balanceColumn,
    cost,
  });
  return null;
}

async function getPricingPlanById(planId, tableName = SUPABASE_PRICES_TABLE) {
  if (!supabase) return null;

  const { data, error } = await supabase
    .from(tableName)
    .select("*")
    .eq(SUPABASE_PRICE_ID_COLUMN, planId)
    .maybeSingle();

  if (error) throw error;
  return data || null;
}

async function getPricingPlans(tableName = SUPABASE_PRICES_TABLE) {
  if (!supabase) return [];

  const { data, error } = await supabase
    .from(tableName)
    .select("*")
    .order(SUPABASE_PRICE_ID_COLUMN, { ascending: true });

  if (error) throw error;
  return Array.isArray(data) ? data : [];
}

function mapPlanForFrontend(plan) {
  return {
    id: plan?.[SUPABASE_PRICE_ID_COLUMN],
    name: plan?.[SUPABASE_PRICE_NAME_COLUMN],
    generations: Number(plan?.[SUPABASE_PRICE_GENERATIONS_COLUMN] || 0),
    price_rub: Number(plan?.[SUPABASE_PRICE_AMOUNT_COLUMN] || 0),
    promo_excluded: isPlanPromoExcluded(plan),
  };
}

/** Колонки может не быть (старая база) — тогда скидка действует как обычно. */
function isPlanPromoExcluded(plan) {
  return plan?.[SUPABASE_PRICE_PROMO_EXCLUDED_COLUMN] === true;
}

function normalizePromoCode(value) {
  return String(value || "")
    .trim()
    .toUpperCase();
}

/** Код живой, если текущий момент внутри окна (границы необязательны). */
function isPromoLive(promo, now = Date.now()) {
  if (!promo) return false;

  const startsAt = promo.starts_at ? Date.parse(promo.starts_at) : null;
  const endsAt = promo.ends_at ? Date.parse(promo.ends_at) : null;

  if (Number.isFinite(startsAt) && now < startsAt) return false;
  if (Number.isFinite(endsAt) && now >= endsAt) return false;

  return true;
}

function mapPromoForFrontend(promo) {
  return {
    code: normalizePromoCode(promo?.code),
    title: promo?.title || "",
    percent: Number(promo?.percent || 0),
    type: String(promo?.type || PROMO_SITE_TYPE),
    endsAt: promo?.ends_at || null,
  };
}

/**
 * Итоговая цена со скидкой. Тот же расчёт повторён на фронте
 * (`applyPromoDiscount` в assets/js/index.js) — держать формулы одинаковыми,
 * иначе показанная сумма разойдётся с той, что уходит провайдеру.
 */
function applyPromoDiscount(amount, percent) {
  const base = Number(amount || 0);
  const off = Number(percent || 0);

  if (!Number.isFinite(base) || base <= 0) return 0;
  if (!Number.isFinite(off) || off <= 0) return base;

  return Math.max(1, Math.round((base * (100 - Math.min(off, 100))) / 100));
}

async function getPromoByCode(code) {
  if (!supabase) return null;

  const normalized = normalizePromoCode(code);
  if (!normalized) return null;

  const { data, error } = await supabase
    .from(SUPABASE_PROMO_TABLE)
    .select("*")
    .ilike("code", normalized)
    .limit(1);

  if (error) throw error;

  const promo = Array.isArray(data) ? data[0] : null;
  return promo && normalizePromoCode(promo.code) === normalized ? promo : null;
}

/** Активный код для пилюли на сайте: только `web`, ближайший по окончанию. */
async function getActiveSitePromo() {
  if (!supabase) return null;

  const { data, error } = await supabase
    .from(SUPABASE_PROMO_TABLE)
    .select("*")
    .eq("type", PROMO_SITE_TYPE)
    .order("ends_at", { ascending: true, nullsFirst: false })
    .limit(10);

  if (error) throw error;

  const rows = Array.isArray(data) ? data : [];
  return rows.find((promo) => isPromoLive(promo)) || null;
}

/**
 * Проверка кода перед применением на сайте. Тип не ограничивает: любой живой
 * код проходит, где бы его ни раздали.
 * Возвращает `{ promo }` либо `{ reason }` — причину отказа.
 */
async function resolvePromoForSite(code) {
  const normalized = normalizePromoCode(code);
  if (!normalized) return { reason: "empty" };

  const promo = await getPromoByCode(normalized);
  if (!promo) return { reason: "not_found" };
  if (!isPromoLive(promo)) return { reason: "expired" };

  return { promo };
}

/**
 * Разбор payload платежа: `${chatId}-${planId}` либо `${chatId}-${planId}-p${percent}`
 * при оплате с промокодом. Суффикс необязателен — платежи, созданные до промокодов,
 * разбираются по-старому.
 * И user id, и id тарифа в БД — строки (Telegram: цифры, Google: `g…`, тариф: число или uuid).
 */
function parseWebhookPayload(payloadValue) {
  let raw = String(payloadValue || "").trim();
  if (!raw) return null;

  let discountPercent = 0;

  const tailDash = raw.lastIndexOf("-");
  const tail = tailDash > 0 ? raw.slice(tailDash + 1) : "";
  if (/^p\d{1,3}$/.test(tail)) {
    discountPercent = Number(tail.slice(1));
    raw = raw.slice(0, tailDash);
  }

  const lastDash = raw.lastIndexOf("-");
  if (lastDash <= 0) return null;

  const chatId = raw.slice(0, lastDash).trim();
  const planId = raw.slice(lastDash + 1).trim();

  if (!chatId || !planId) {
    return null;
  }

  return {
    chatId,
    planId,
    discountPercent,
  };
}

function buildLaozhangUpstreamCandidates(upstreamFullUrl) {
  if (!upstreamFullUrl) return [];
  return [upstreamFullUrl];
}

function buildLaozhangRequest(url, options = {}) {
  const apiKey = options.apiKey ?? LAOZHANG_API_KEY;
  const authMode = (
    options.authMode ?? LAOZHANG_AUTH_MODE
  ).toLowerCase();
  const headers = { "Content-Type": "application/json" };
  let requestUrl = url;

  if (authMode === "query") {
    const glue = requestUrl.includes("?") ? "&" : "?";
    requestUrl = `${requestUrl}${glue}key=${encodeURIComponent(apiKey)}`;
  } else {
    headers.Authorization = `Bearer ${apiKey}`;
  }

  return { requestUrl, headers };
}

function parseJsonOrRaw(rawText) {
  try {
    return rawText ? JSON.parse(rawText) : {};
  } catch {
    return { raw: rawText };
  }
}

function resolvePaymentProviderHeaders() {
  const providerHeaders = {
    "Content-Type": "application/json",
  };

  if (PAYMENT_PROVIDER_MERCHANT_ID) {
    providerHeaders[PAYMENT_PROVIDER_MERCHANT_HEADER] =
      PAYMENT_PROVIDER_MERCHANT_ID;
  }

  if (PAYMENT_PROVIDER_SECRET) {
    providerHeaders[PAYMENT_PROVIDER_SECRET_HEADER] = PAYMENT_PROVIDER_SECRET;
  }

  if (PAYMENT_PROVIDER_API_KEY) {
    if (PAYMENT_PROVIDER_AUTH_MODE === "bearer") {
      providerHeaders.Authorization = `Bearer ${PAYMENT_PROVIDER_API_KEY}`;
    } else if (PAYMENT_PROVIDER_AUTH_MODE === "header") {
      providerHeaders[PAYMENT_PROVIDER_KEY_HEADER] = PAYMENT_PROVIDER_API_KEY;
    }
  }

  return providerHeaders;
}

function resolvePaymentUrl(raw) {
  return (
    raw?.paymentUrl ||
    raw?.payment_url ||
    raw?.url ||
    raw?.redirect ||
    raw?.redirectUrl ||
    raw?.redirect_url ||
    raw?.link ||
    raw?.data?.payment_url ||
    raw?.data?.url ||
    null
  );
}

function resolveChatIdFromRequest(req) {
  const authHeader = String(req.headers.authorization || "");
  const token = authHeader.startsWith("Bearer ")
    ? authHeader.slice(7).trim()
    : "";

  const chatIdFromToken = verifySessionToken(token);
  if (chatIdFromToken) return String(chatIdFromToken);

  const chatIdFromCookie = verifySessionToken(req.cookies?.tg_session);
  if (chatIdFromCookie) return String(chatIdFromCookie);

  return "";
}

function requireChatId(req, res, next) {
  const chatId = resolveChatIdFromRequest(req);
  if (!chatId) {
    return res.status(401).json({
      error: "Не авторизован. Войдите через Telegram или Google.",
    });
  }

  req.chatId = String(chatId);
  next();
}

function extractPromptText(body = {}) {
  const directCandidates = [
    body?.prompt,
    body?.text,
    body?.input,
    body?.contents?.[0]?.parts
      ?.map((p) => p?.text)
      .filter(Boolean)
      .join(" "),
  ].filter((value) => typeof value === "string" && value.trim());

  return directCandidates[0] || "";
}

function extractInlineImagesFromRequestBody(body = {}) {
  /** @type {{ mimeType: string, data: string }[]} */
  const images = [];

  const flat = Array.isArray(body?.images) ? body.images : [];
  for (const item of flat) {
    const data = typeof item?.data === "string" ? item.data.trim() : "";
    if (!data) continue;
    images.push({
      mimeType: String(item?.mimeType || item?.mime_type || "image/jpeg"),
      data,
    });
  }
  if (images.length) return images;

  /** Одно фото как у бота / multipart-форм: `{ image: { data, mimeType } }`. */
  const one = body?.image;
  if (one && typeof one === "object" && !Array.isArray(one)) {
    const data = typeof one.data === "string" ? one.data.trim() : "";
    if (data) {
      images.push({
        mimeType: String(one.mimeType || one.mime_type || "image/jpeg"),
        data,
      });
      return images;
    }
  }

  const parts = Array.isArray(body?.contents?.[0]?.parts)
    ? body.contents[0].parts
    : [];

  parts.forEach((part) => {
    const inline = part?.inline_data || part?.inlineData;
    const data = typeof inline?.data === "string" ? inline.data.trim() : "";
    if (!data) return;
    images.push({
      mimeType: String(inline?.mime_type || inline?.mimeType || "image/jpeg"),
      data,
    });
  });

  return images;
}

function resolveVideoGenerationCost(sound, durationRaw) {
  const duration = String(durationRaw) === "10" ? "10" : "5";
  const withSound = Boolean(sound);
  if (duration === "5" && !withSound) return 5;
  if (duration === "10" && !withSound) return 10;
  if (duration === "5" && withSound) return 10;
  if (duration === "10" && withSound) return 20;
  return 5;
}

/**
 * Страница tmpfiles (HTML) -> прямая ссылка на файл для image_urls.
 * tmpfiles.org больше не отдаёт файл по /dl/<id>/<name> напрямую (302 -> HTML-страница):
 * реальная прямая ссылка теперь содержит доп. токен (`/dl/<ts>.<hash>/<id>/<name>`),
 * который есть только в HTML самой страницы файла — приходится её распарсить.
 */
async function resolveTmpfilesDlUrl(pageUrl) {
  const s = String(pageUrl || "").trim();
  if (!s) return "";

  try {
    const res = await fetch(s);
    if (!res.ok) return "";
    const html = await res.text();
    const match = html.match(/href="(https?:\/\/tmpfiles\.org\/dl\/[^"]+)"/i);
    return match ? match[1] : "";
  } catch {
    return "";
  }
}

async function uploadBufferToTmpfiles(buffer, filename, mimeType) {
  const form = new FormData();
  const blob = new Blob([buffer], { type: mimeType || "image/jpeg" });
  form.append("file", blob, filename || "ref.jpg");

  const res = await fetch(TMPFILES_UPLOAD_URL, {
    method: "POST",
    body: form,
  });

  const json = await res.json().catch(() => ({}));
  const statusOk =
    String(json?.status || "").toLowerCase() === "success" ||
    json?.success === true ||
    json?.ok === true;

  const pageUrl =
    json?.data?.url ||
    json?.data?.URL ||
    json?.url ||
    json?.data?.file?.url ||
    "";

  if (!res.ok || !statusOk || !pageUrl) {
    const msg =
      typeof json?.message === "string"
        ? json.message
        : "Не удалось загрузить файл на tmpfiles.org";
    return { ok: false, error: msg };
  }

  return { ok: true, pageUrl: String(pageUrl) };
}

function extractSeedanceTaskId(payload) {
  return String(payload?.id || payload?.task_id || payload?.taskId || "").trim();
}

function extractVideoUrlFromSeedanceRecord(record) {
  return String(
    record?.content?.video_url ||
      record?.result_url ||
      record?.data?.content?.video_url ||
      ""
  ).trim();
}

function normalizeSeedanceState(stateRaw) {
  return String(stateRaw || "")
    .trim()
    .toLowerCase();
}

function isSeedancePendingState(state) {
  return ["queued", "running"].includes(state);
}

function isSeedanceFailedState(state) {
  return ["failed", "expired"].includes(state);
}

function isSeedanceSuccessState(state) {
  return ["succeeded", "completed"].includes(state);
}

/**
 * Node fetch() (undici) обрывает соединение на середине ответа именно с этим
 * апстримом (SocketError "other side closed", 392-393 байта и тишина) —
 * воспроизводится стабильно, при этом classic `https`-модуль и curl читают
 * тот же ответ без проблем. Поэтому здесь — сырой https.request вместо fetch.
 */
function seedanceFetchJson(pathname, init = {}) {
  const base = new URL(SEEDANCE_API_BASE);
  const target = pathname.startsWith("http")
    ? new URL(pathname)
    : new URL(`${base.pathname.replace(/\/$/, "")}${pathname}`, base);

  const headers = { ...(init.headers || {}) };
  const hasAuthHeader = Object.keys(headers).some(
    (key) => key.toLowerCase() === "authorization"
  );
  if (!hasAuthHeader) {
    headers["Authorization"] = `Bearer ${SEEDANCE_API_KEY}`;
  }

  const body = typeof init.body === "string" ? init.body : undefined;
  if (body) headers["Content-Length"] = Buffer.byteLength(body);

  return new Promise((resolve, reject) => {
    const req = https.request(
      {
        hostname: target.hostname,
        path: `${target.pathname}${target.search}`,
        method: init.method || "GET",
        headers,
      },
      (res) => {
        const chunks = [];
        res.on("data", (chunk) => chunks.push(chunk));
        res.on("end", () => {
          const text = Buffer.concat(chunks).toString("utf8");
          let raw = {};
          try {
            raw = text ? JSON.parse(text) : {};
          } catch {
            console.error("Seedance response is not valid JSON.", {
              status: res.statusCode,
              bodyPreview: text.slice(0, 500),
            });
          }
          resolve({
            response: {
              ok: Number(res.statusCode) >= 200 && Number(res.statusCode) < 300,
              status: res.statusCode,
            },
            raw,
          });
        });
        res.on("error", reject);
      }
    );
    req.on("error", reject);
    if (body) req.write(body);
    req.end();
  });
}

function pruneVideoJobMaps() {
  const maxAgeMs = 3 * 60 * 60 * 1000;
  const now = Date.now();
  for (const [id, meta] of videoJobMetaByTaskId) {
    if (now - meta.createdAt > maxAgeMs) {
      videoJobMetaByTaskId.delete(id);
      videoJobResultByTaskId.delete(id);
    }
  }
}

app.get("/health", (_req, res) => {
  res.json({ ok: true });
});

async function sendTelegramMessage(chatId, text) {
  if (!TELEGRAM_BOT_TOKEN) {
    throw new Error("TELEGRAM_BOT_TOKEN is not configured");
  }
  if (!chatId) {
    throw new Error("FEEDBACK_CHAT_ID is not configured");
  }

  const url = `https://api.telegram.org/bot${TELEGRAM_BOT_TOKEN}/sendMessage`;
  const response = await fetch(url, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({
      chat_id: chatId,
      text,
      disable_web_page_preview: true,
    }),
  });

  const data = await response.json().catch(() => ({}));
  if (!response.ok || data?.ok === false) {
    const detail =
      typeof data?.description === "string"
        ? data.description
        : `HTTP ${response.status}`;
    throw new Error(`Telegram sendMessage failed: ${detail}`);
  }

  return data;
}

function clampFeedbackText(value, max = 2000) {
  return String(value ?? "")
    .trim()
    .slice(0, max);
}

app.post("/api/feedback", async (req, res) => {
  try {
    if (!TELEGRAM_BOT_TOKEN || !FEEDBACK_CHAT_ID) {
      return res.status(503).json({
        error: "Отзывы временно недоступны. Попробуйте позже.",
        code: "FEEDBACK_NOT_CONFIGURED",
      });
    }

    const rating = Number(req.body?.rating);
    if (!Number.isInteger(rating) || rating < 1 || rating > 5) {
      return res.status(400).json({
        error: "Укажите оценку от 1 до 5.",
        code: "INVALID_RATING",
      });
    }

    const liked = clampFeedbackText(req.body?.liked);
    const improve = clampFeedbackText(req.body?.improve);
    if (!liked && !improve) {
      return res.status(400).json({
        error: "Заполните хотя бы одно текстовое поле.",
        code: "EMPTY_FEEDBACK",
      });
    }

    const username = clampFeedbackText(req.body?.username, 64).replace(
      /^@+/,
      ""
    );
    const chatIdFromClient = clampFeedbackText(
      req.body?.chat_id ?? req.body?.chatId,
      64
    );
    const who = username
      ? `@${username}`
      : chatIdFromClient
        ? `ID ${chatIdFromClient}`
        : "Гость";

    const stars = "★".repeat(rating) + "☆".repeat(5 - rating);
    const lines = [
      "📝 Новый отзыв с сайта",
      "",
      `👤 ${who}`,
      `⭐ Оценка: ${stars} (${rating}/5)`,
    ];

    if (liked) {
      lines.push("", "👍 Понравилось:", liked);
    }
    if (improve) {
      lines.push("", "🔧 Можно улучшить:", improve);
    }

    await sendTelegramMessage(FEEDBACK_CHAT_ID, lines.join("\n"));
    return res.json({ ok: true });
  } catch (error) {
    console.error("feedback error", error);
    return res.status(500).json({
      error: "Не удалось отправить отзыв. Попробуйте позже.",
      code: "FEEDBACK_SEND_FAILED",
    });
  }
});

app.get("/auth/telegram/callback", async (req, res) => {
  try {
    const check = isTelegramAuthDataValid(req.query);

    if (!check.valid) {
      return res.redirect(
        `${FRONTEND_ERROR_REDIRECT}&reason=${encodeURIComponent(check.reason)}`
      );
    }

    const chatId = String(req.query.id || "");
    if (!chatId) {
      return res.redirect(`${FRONTEND_ERROR_REDIRECT}&reason=no_id`);
    }

    let user = await getUserByChatId(chatId);
    if (!user && AUTO_CREATE_USER) {
      user = await createUserIfMissing(chatId);
    }

    setChatCookies(req, res, chatId);
    const redirectTarget = resolvePostAuthRedirect(req);
    return res.redirect(buildSuccessRedirectUrlWithOverride(chatId, redirectTarget));
  } catch (error) {
    console.error("telegram callback error", error);
    return res.redirect(`${FRONTEND_ERROR_REDIRECT}&reason=server_error`);
  }
});

app.get("/auth/google/start", (req, res) => {
  if (!GOOGLE_CLIENT_ID || !GOOGLE_CLIENT_SECRET) {
    return res
      .status(503)
      .type("text/plain")
      .send(
        "Google OAuth не настроен: задайте GOOGLE_CLIENT_ID и GOOGLE_CLIENT_SECRET на сервере."
      );
  }

  const redirectUri = resolveGoogleRedirectUri(req);
  if (!redirectUri) {
    return res
      .status(500)
      .type("text/plain")
      .send(
        "Не удалось определить URL бэкенда. Задайте BACKEND_PUBLIC_URL или GOOGLE_REDIRECT_URI."
      );
  }

  const state = crypto.randomBytes(24).toString("hex");
  const isLocalHost =
    req.hostname === "127.0.0.1" || req.hostname === "localhost";

  const common = {
    secure: isLocalHost ? false : COOKIE_SECURE,
    sameSite: isLocalHost ? "Lax" : COOKIE_SAMESITE,
    domain: COOKIE_DOMAIN,
    maxAge: 600000,
    path: "/",
  };

  res.cookie("google_oauth_state", state, { ...common, httpOnly: true });

  const redirectTarget = resolvePostAuthRedirect(req);
  if (redirectTarget) {
    res.cookie(POST_AUTH_REDIRECT_COOKIE, redirectTarget, {
      ...common,
      httpOnly: true,
    });
  }

  const params = new URLSearchParams({
    client_id: GOOGLE_CLIENT_ID,
    redirect_uri: redirectUri,
    response_type: "code",
    scope: "openid email profile",
    state,
    access_type: "online",
    prompt: "select_account",
  });

  res.redirect(`https://accounts.google.com/o/oauth2/v2/auth?${params}`);
});

app.get("/auth/google/callback", async (req, res) => {
  const clearStateCookie = () => {
    const isLocalHost =
      req.hostname === "127.0.0.1" || req.hostname === "localhost";
    const base = {
      secure: isLocalHost ? false : COOKIE_SECURE,
      sameSite: isLocalHost ? "Lax" : COOKIE_SAMESITE,
      domain: COOKIE_DOMAIN,
      path: "/",
    };
    res.clearCookie("google_oauth_state", base);
  };

  try {
    if (req.query.error) {
      clearStateCookie();
      return res.redirect(
        `${FRONTEND_ERROR_REDIRECT}&reason=${encodeURIComponent(
          String(req.query.error)
        )}`
      );
    }

    const code = String(req.query.code || "").trim();
    const state = String(req.query.state || "").trim();
    const cookieState = String(req.cookies?.google_oauth_state || "").trim();

    if (!code || !state || !cookieState || state !== cookieState) {
      clearStateCookie();
      return res.redirect(`${FRONTEND_ERROR_REDIRECT}&reason=oauth_state`);
    }

    clearStateCookie();

    if (!GOOGLE_CLIENT_ID || !GOOGLE_CLIENT_SECRET) {
      return res.redirect(`${FRONTEND_ERROR_REDIRECT}&reason=no_google_config`);
    }

    const redirectUri = resolveGoogleRedirectUri(req);
    if (!redirectUri) {
      return res.redirect(`${FRONTEND_ERROR_REDIRECT}&reason=no_redirect_uri`);
    }

    const tokenRes = await fetch("https://oauth2.googleapis.com/token", {
      method: "POST",
      headers: { "Content-Type": "application/x-www-form-urlencoded" },
      body: new URLSearchParams({
        code,
        client_id: GOOGLE_CLIENT_ID,
        client_secret: GOOGLE_CLIENT_SECRET,
        redirect_uri: redirectUri,
        grant_type: "authorization_code",
      }),
    });

    const tokenJson = await tokenRes.json().catch(() => ({}));
    if (!tokenRes.ok || !tokenJson.access_token) {
      return res.redirect(`${FRONTEND_ERROR_REDIRECT}&reason=token_exchange`);
    }

    const userinfoRes = await fetch(
      "https://www.googleapis.com/oauth2/v3/userinfo",
      {
        headers: { Authorization: `Bearer ${tokenJson.access_token}` },
      }
    );

    const profile = await userinfoRes.json().catch(() => ({}));
    const sub = String(profile.sub || "").trim();

    if (!sub) {
      return res.redirect(`${FRONTEND_ERROR_REDIRECT}&reason=no_sub`);
    }

    const chatId = `g${sub}`;

    let user = await getUserByChatId(chatId);
    if (!user && AUTO_CREATE_USER) {
      try {
        user = await createUserIfMissing(chatId);
      } catch (_createErr) {
        return res.redirect(
          `${FRONTEND_ERROR_REDIRECT}&reason=create_user_failed`
        );
      }
    }

    if (!user) {
      if (!supabase) {
        return res.redirect(
          `${FRONTEND_ERROR_REDIRECT}&reason=no_supabase`
        );
      }
      if (!AUTO_CREATE_USER) {
        return res.redirect(
          `${FRONTEND_ERROR_REDIRECT}&reason=auto_create_off`
        );
      }
      return res.redirect(`${FRONTEND_ERROR_REDIRECT}&reason=user_not_created`);
    }

    setChatCookies(req, res, chatId);
    const redirectTarget = resolvePostAuthRedirect(req);
    res.clearCookie(POST_AUTH_REDIRECT_COOKIE, {
      secure: COOKIE_SECURE,
      sameSite: COOKIE_SAMESITE,
      domain: COOKIE_DOMAIN,
      path: "/",
    });
    return res.redirect(buildSuccessRedirectUrlWithOverride(chatId, redirectTarget));
  } catch (_error) {
    return res.redirect(`${FRONTEND_ERROR_REDIRECT}&reason=server_error`);
  }
});

app.get("/auth/me", requireChatId, async (req, res) => {
  try {
    let user = await getUserByChatId(req.chatId);

    if (!user && AUTO_CREATE_USER) {
      user = await createUserIfMissing(req.chatId);
    }

    if (!user) {
      return res
        .status(401)
        .json({ authenticated: false, error: "Пользователь не найден" });
    }

    return res.json({
      authenticated: true,
      chat_id: req.chatId,
      balance:
        SUPABASE_BALANCE_COLUMN in user ? user[SUPABASE_BALANCE_COLUMN] : null,
      user,
    });
  } catch (error) {
    console.error("auth/me error", error);
    return res
      .status(500)
      .json({ authenticated: false, error: "Ошибка сервера" });
  }
});

app.post("/auth/logout", (_req, res) => {
  const base = {
    secure: COOKIE_SECURE,
    sameSite: COOKIE_SAMESITE,
    domain: COOKIE_DOMAIN,
    path: "/",
  };

  res.clearCookie("chatid", base);
  res.clearCookie("tg_session", base);
  res.clearCookie("google_oauth_state", base);
  res.json({ ok: true });
});

app.get("/api/pricing", requireChatId, async (req, res) => {
  try {
    const plans = await getPricingPlans(SUPABASE_PRICES_TABLE);

    return res.json({
      plans: plans.map(mapPlanForFrontend),
    });
  } catch (error) {
    console.error("pricing error", error);
    return res.status(500).json({ error: "Не удалось загрузить тарифы" });
  }
});

/** Активный код для пилюли под кнопкой «Создать». Без авторизации: показываем всем. */
app.get("/api/promo/active", async (_req, res) => {
  try {
    if (!supabase) return res.json({ promo: null });

    const promo = await getActiveSitePromo();
    return res.json({ promo: promo ? mapPromoForFrontend(promo) : null });
  } catch (error) {
    console.error("promo/active error", error);
    return res.json({ promo: null });
  }
});

app.post("/api/promo/validate", requireChatId, async (req, res) => {
  try {
    if (!supabase) {
      return res.status(500).json({ error: "Supabase не настроен" });
    }

    const { promo, reason } = await resolvePromoForSite(req.body?.code);
    if (!promo) {
      return res.json({ valid: false, reason });
    }

    return res.json({ valid: true, promo: mapPromoForFrontend(promo) });
  } catch (error) {
    console.error("promo/validate error", error);
    return res.status(500).json({ error: "Не удалось проверить промокод" });
  }
});

app.post("/api/payments/create", requireChatId, async (req, res) => {
  try {
    if (!supabase) {
      return res.status(500).json({ error: "Supabase не настроен" });
    }

    const planId = req.body?.planId;
    if (planId === undefined || planId === null || planId === "") {
      return res.status(400).json({ error: "planId обязателен" });
    }

    const plan = await getPricingPlanById(planId, SUPABASE_PRICES_TABLE);

    if (!plan) {
      return res.status(404).json({ error: "Тариф не найден" });
    }

    const generations = Number(plan?.[SUPABASE_PRICE_GENERATIONS_COLUMN] || 0);
    const amount = Number(plan?.[SUPABASE_PRICE_AMOUNT_COLUMN] || 0);

    if (!Number.isFinite(generations) || generations <= 0) {
      return res
        .status(400)
        .json({ error: "Некорректное количество генераций" });
    }

    if (!Number.isFinite(amount) || amount <= 0) {
      return res.status(400).json({ error: "Некорректная сумма тарифа" });
    }

    // Скидку считает бэк: сумма с фронта не принимается вообще.
    let promo = null;
    if (normalizePromoCode(req.body?.promoCode)) {
      const resolved = await resolvePromoForSite(req.body.promoCode);
      if (!resolved.promo) {
        return res.status(400).json({
          error: "Промокод недействителен",
          reason: resolved.reason,
        });
      }
      promo = resolved.promo;
    }

    // Помеченный пакет скидку не получает, даже если промокод верный.
    const discountPercent =
      promo && !isPlanPromoExcluded(plan) ? Number(promo.percent || 0) : 0;
    const finalAmount = applyPromoDiscount(amount, discountPercent);

    const payload = discountPercent
      ? `${req.chatId}-${plan[SUPABASE_PRICE_ID_COLUMN]}-p${discountPercent}`
      : `${req.chatId}-${plan[SUPABASE_PRICE_ID_COLUMN]}`;
    const providerRequestBody = {
      paymentMethod: PAYMENT_METHOD,
      description: `Оплата ${generations} генераций для юзера ${
        req.chatId
      }${promo ? ` по промокоду ${promo.code} (−${discountPercent}%)` : ""}`,
      paymentDetails: {
        amount: finalAmount,
        currency: PAYMENT_CURRENCY,
      },
      return: PAYMENT_RETURN_URL,
      payload,
    };

    const providerHeaders = resolvePaymentProviderHeaders();
    const missingProviderCredentials =
      !providerHeaders[PAYMENT_PROVIDER_MERCHANT_HEADER] ||
      !providerHeaders[PAYMENT_PROVIDER_SECRET_HEADER];

    if (missingProviderCredentials) {
      return res.status(500).json({
        error:
          "Платежи не настроены: отсутствуют X-MerchantId/X-Secret в конфигурации backend.",
      });
    }

    const providerResponse = await fetch(PAYMENT_PROVIDER_URL, {
      method: "POST",
      headers: providerHeaders,
      body: JSON.stringify(providerRequestBody),
    });

    const rawText = await providerResponse.text();
    const raw = parseJsonOrRaw(rawText);

    if (!providerResponse.ok) {
      return res.status(502).json({
        error: raw?.error || "Провайдер оплаты вернул ошибку",
        details: raw,
      });
    }

    const paymentUrl = resolvePaymentUrl(raw);
    if (!paymentUrl) {
      return res.status(502).json({
        error: "Провайдер не вернул ссылку на оплату",
        details: raw,
      });
    }

    return res.json({
      ok: true,
      paymentUrl,
      raw,
      amount: finalAmount,
      basePrice: amount,
      promoCode: promo ? normalizePromoCode(promo.code) : null,
      discountPercent,
    });
  } catch (error) {
    console.error("payments/create error", error);
    return res.status(500).json({ error: "Не удалось создать платеж" });
  }
});

app.post("/api/webhooks/platega", async (req, res) => {
  try {
    if (WEBHOOK_SECRET) {
      const incomingSecret = String(req.headers[WEBHOOK_SECRET_HEADER] || "");
      if (incomingSecret !== WEBHOOK_SECRET) {
        return res.status(401).json({ error: "invalid webhook secret" });
      }
    }

    const body = req.body || {};
    const statusRaw =
      body?.status || body?.payment_status || body?.state || body?.event || "";
    const status = String(statusRaw).toLowerCase();

    const payloadValue =
      body?.payload ||
      body?.data?.payload ||
      body?.object?.payload ||
      body?.transaction?.payload;

    const parsed = parseWebhookPayload(payloadValue);
    if (!parsed) {
      return res.status(400).json({ error: "invalid payload format" });
    }

    const { chatId, planId, discountPercent } = parsed;

    if (status === "pending") {
      return res.json({ ok: true, pending: true, status });
    }

    if (["canceled", "chargebacked"].includes(status)) {
      return res.json({ ok: true, ignored: true, status });
    }

    if (status !== "confirmed") {
      return res.json({ ok: true, ignored: true, status });
    }

    const user = await getUserByChatId(chatId);
    if (!user) {
      return res.status(404).json({ error: "user not found" });
    }

    const plan = await getPricingPlanById(planId, SUPABASE_PRICES_TABLE);

    if (!plan) {
      return res.status(404).json({ error: "pricing plan not found" });
    }

    const generations = Number(plan?.[SUPABASE_PRICE_GENERATIONS_COLUMN] || 0);
    // Генерации выдаём полностью, в total_sum пишем реально оплаченное.
    const priceRub = applyPromoDiscount(
      Number(plan?.[SUPABASE_PRICE_AMOUNT_COLUMN] || 0),
      discountPercent
    );
    const currentBalance = Number(user?.[SUPABASE_BALANCE_COLUMN] || 0);
    const currentTotalSum = Number(user?.[SUPABASE_TOTAL_SUM_COLUMN] || 0);

    const nextBalance = Number.isFinite(currentBalance)
      ? currentBalance + (Number.isFinite(generations) ? generations : 0)
      : generations;

    const nextTotalSum = Number.isFinite(currentTotalSum)
      ? currentTotalSum + (Number.isFinite(priceRub) ? priceRub : 0)
      : priceRub;

    const { error: updateError } = await supabase
      .from(SUPABASE_USERS_TABLE)
      .update({
        [SUPABASE_BALANCE_COLUMN]: nextBalance,
        [SUPABASE_TOTAL_SUM_COLUMN]: nextTotalSum,
      })
      .eq(SUPABASE_CHAT_ID_COLUMN, chatId);

    if (updateError) {
      throw updateError;
    }


    return res.json({
      ok: true,
      chat_id: chatId,
      plan_id: planId,
      payment_id: planId,
      balance: nextBalance,
      total_sum: nextTotalSum,
    });
  } catch (error) {
    console.error("webhook error", error);
    return res.status(500).json({ error: "webhook processing failed" });
  }
});

app.post("/api/generate-image", requireChatId, async (req, res) => {
  /** Если оплата зарезервирована, но упадём с исключением ниже — вернуть деньги в catch. */
  let pendingRefund = null;
  try {
    if (!LAOZHANG_API_KEY) {
      return res.status(500).json({ error: "LAOZHANG_API_KEY не настроен" });
    }

    let user = await getUserByChatId(req.chatId);
    if (!user && AUTO_CREATE_USER) {
      user = await createUserIfMissing(req.chatId);
    }

    if (!user) {
      return res
        .status(401)
        .json({ error: "Пользователь не найден в Supabase" });
    }

    const rawBalance = Number(user?.[SUPABASE_BALANCE_COLUMN]);
    const currentBalance = Number.isFinite(rawBalance) ? rawBalance : 0;
    const requestedCount = Math.max(1, Number(req.body?.numberOfImages || 1));

    if (currentBalance < requestedCount) {
      return res.status(402).json({
        error: "Недостаточно генераций. Пополните баланс.",
        code: "INSUFFICIENT_BALANCE",
        balance: currentBalance,
        required: 1,
      });
    }

    const upstreamPayloadBase = { ...req.body };

    const rawImagesInBody = Array.isArray(req.body?.images)
      ? req.body.images
      : [];
    const hasImageObject =
      req.body?.image != null && typeof req.body.image === "object";
    const inlineImages = extractInlineImagesFromRequestBody(upstreamPayloadBase);
    if (
      (rawImagesInBody.length > 0 || hasImageObject) &&
      inlineImages.length === 0
    ) {
      return res.status(422).json({
        error:
          "Нужен base64 в images[].data или в image.data, не только mimeType. Прикрепите файл заново.",
        code: "MISSING_IMAGE_DATA",
      });
    }

    const geminiNeedsHost =
      Boolean(normalizeEnv(process.env.LAOZHANG_GEMINI_MODEL)) &&
      !/^https?:\/\//i.test(normalizeEnv(process.env.LAOZHANG_GEMINI_MODEL));
    if (geminiNeedsHost && !LAOZHANG_PRIMARY_HOST) {
      return res.status(500).json({
        error:
          "Задайте LAOZHANG_URL полным URL (https://…) или укажите LAOZHANG_GEMINI_MODEL полным адресом.",
      });
    }

    let candidateUrl = "";
    if (LAOZHANG_IMAGES_URL) {
      const upstreamCandidates = buildLaozhangUpstreamCandidates(
        LAOZHANG_IMAGES_URL
      );
      if (upstreamCandidates.length) {
        candidateUrl = upstreamCandidates[0];
      }
    }

    const geminiFullUrl = resolveLaozhangAbsoluteUrl(
      LAOZHANG_PRIMARY_HOST,
      LAOZHANG_GEMINI_MODEL
    );

    if (!candidateUrl && !geminiFullUrl) {
      return res.status(500).json({
        error:
          "Нет канала генерации: задайте LAOZHANG_URL и/или LAOZHANG_GEMINI_MODEL",
      });
    }

    const transparentBackground = req.body?.transparentBackground === true;
    // Прозрачный фон умеет только flare-модель (GPT_MODEL): Gemini не подключаем,
    // при её сбое честно отвечаем, что прозрачность недоступна.
    // JPEG без альфа-канала: с background=transparent API вернёт ошибку, поэтому всегда PNG.
    const imageOutputParams = transparentBackground
      ? { background: "transparent", output_format: "png" }
      : {};

    const buildOpenAiStyleJsonBody = (model) => {
      const prompt = extractPromptText(upstreamPayloadBase);
      const body = {
        model,
        prompt,
        n: Math.max(1, requestedCount),
        response_format: "b64_json",
        ...imageOutputParams,
      };

      return body;
    };

    const toBlobFromBase64 = (base64, mimeType) => {
      const clean = String(base64 || "").trim().replace(/^data:.*?;base64,/i, "");
      const buffer = Buffer.from(clean, "base64");
      return new Blob([buffer], { type: mimeType || "image/jpeg" });
    };

    const downloadImageAsBase64 = async (url) => {
      const r = await fetch(url);
      if (!r.ok) {
        throw new Error(`Не удалось скачать изображение: ${r.status}`);
      }
      const mimeType =
        String(r.headers.get("content-type") || "").trim() || "image/png";
      const ab = await r.arrayBuffer();
      const b64 = Buffer.from(ab).toString("base64");
      return { imageData: b64, mimeType };
    };

    const extractImagesFromRaw = async (rawData) => {
      /** @type {{ imageData: string, mimeType: string }[]} */
      const out = [];

      // OpenAI Images API shape: { data: [{ b64_json | url }] }
      const dataArr = Array.isArray(rawData?.data) ? rawData.data : [];
      for (const item of dataArr) {
        if (typeof item?.b64_json === "string" && item.b64_json.trim()) {
          out.push({ imageData: item.b64_json.trim(), mimeType: "image/png" });
          continue;
        }
        if (typeof item?.url === "string" && item.url.trim()) {
          out.push(await downloadImageAsBase64(item.url.trim()));
        }
      }

      if (out.length) return out;

      // Back-compat: previously handled Gemini-like inline_data.
      const parts =
        rawData?.candidates?.[0]?.content?.parts ||
        rawData?.data?.candidates?.[0]?.content?.parts ||
        [];

      const inline = Array.isArray(parts)
        ? parts
            .map((part) => {
              const inner = part?.inline_data || part?.inlineData;
              if (typeof inner?.data !== "string") return null;
              return {
                imageData: String(inner.data).trim(),
                mimeType: String(inner?.mime_type || inner?.mimeType || "image/png"),
              };
            })
            .filter(Boolean)
        : [];

      return inline;
    };

    const generatedImages = [];
    const generationErrors = [];

    const normalizeUpstreamErrorMessage = (rawError) => {
      if (typeof rawError === "string" && rawError.trim()) return rawError;
      if (rawError?.message) return String(rawError.message);
      if (rawError?.localized_message)
        return String(rawError.localized_message);
      if (rawError?.type) return String(rawError.type);
      return "Ошибка сервиса";
    };

    const laozhangSocketRetries = Math.max(
      0,
      Math.min(3, Number(process.env.LAOZHANG_SOCKET_RETRIES || 1))
    );
    const laozhangSocketRetryDelayMs = Math.max(
      500,
      Number(process.env.LAOZHANG_SOCKET_RETRY_DELAY_MS || 2500)
    );

    let lastError = {
      index: 1,
      status: 502,
      message: "Ошибка сервиса",
    };

    const attemptUpstream = async (url, apiKey, attemptIndex, model) => {
      const prompt = extractPromptText(upstreamPayloadBase);

      const useEdits = inlineImages.length > 0;
      const endpointUrl = url;
      const { requestUrl, headers } = buildLaozhangRequest(endpointUrl, {
        apiKey,
      });

      let upstreamResponse;
      const startedAt = Date.now();
      const controller = new AbortController();
      // Только страница «Убрать фон» (флаг gptOnly от неё) ждёт дольше —
      // генерации с главной, в т.ч. с прозрачным фоном, работают как раньше
      const configuredTimeoutMs = req.body?.gptOnly === true
        ? 300_000
        : Number(process.env.LAOZHANG_TIMEOUT_MS || 180_000);
      const timeoutMs =
        Number.isFinite(configuredTimeoutMs) && configuredTimeoutMs > 0
          ? Math.min(Math.max(configuredTimeoutMs, 10_000), 10 * 60_000)
          : 180_000;
      const timeout = setTimeout(() => controller.abort(), timeoutMs);

      const fetchUrl = useEdits
        ? requestUrl.replace(/\/images\/generations\b/i, "/images/edits")
        : requestUrl;

      try {
        if (!useEdits) {
          const jsonBody = buildOpenAiStyleJsonBody(model);
          upstreamResponse = await fetch(fetchUrl, {
            method: "POST",
            signal: controller.signal,
            headers,
            body: JSON.stringify(jsonBody),
          });
        } else {
          // Images edits: multipart — model, prompt, image (@file).
          const form = new FormData();
          form.append("model", model);
          form.append(
            "prompt",
            prompt ||
              "Use the provided image as the source. Preserve subject and composition."
          );

          inlineImages.forEach((item, index) => {
            const blob = toBlobFromBase64(item.data, item.mimeType);
            const ext = (item.mimeType || "").includes("png") ? "png" : "jpg";
            form.append(
              "image",
              blob,
              index === 0 ? `source.${ext}` : `source${index}.${ext}`
            );
          });

          for (const [key, value] of Object.entries(imageOutputParams)) {
            form.append(key, value);
          }

          const multipartHeaders = new Headers();
          if (headers.Authorization)
            multipartHeaders.set("Authorization", headers.Authorization);

          upstreamResponse = await fetch(fetchUrl, {
            method: "POST",
            signal: controller.signal,
            headers: multipartHeaders,
            body: form,
          });
        }
      } finally {
        clearTimeout(timeout);
      }

      const raw = await upstreamResponse.json().catch(() => ({}));

      if (!upstreamResponse.ok) {
        console.warn("Laozhang upstream non-OK response.", {
          attempt: attemptIndex,
          model,
          status: upstreamResponse.status,
          elapsed_ms: Date.now() - startedAt,
          useEdits,
          requestUrl: fetchUrl,
          body_preview: JSON.stringify(raw || {}).slice(0, 900),
        });
        lastError = {
          index: attemptIndex,
          status: upstreamResponse.status,
          message: normalizeUpstreamErrorMessage(raw?.error || raw),
        };
        return false;
      }

      const extractedImages = await extractImagesFromRaw(raw);

      if (!extractedImages.length) {
        lastError = {
          index: attemptIndex,
          status: 502,
          message: "Сервис вернул ответ без изображения",
        };
        return false;
      }

      for (const item of extractedImages) {
        generatedImages.push({
          imageData: item.imageData,
          mimeType: item.mimeType,
          raw,
        });
      }
      return true;
    };

    const attemptGeminiUpstream = async (url, apiKey, attemptIndex) => {
      const prompt = extractPromptText(upstreamPayloadBase);
      const parts = [];
      const text = typeof prompt === "string" ? prompt.trim() : "";
      if (text) parts.push({ text });

      for (const img of inlineImages) {
        const clean = String(img.data || "")
          .trim()
          .replace(/^data:.*?;base64,/i, "");
        if (!clean) continue;
        parts.push({
          inline_data: {
            mime_type: img.mimeType || "image/jpeg",
            data: clean,
          },
        });
      }

      if (!parts.length) {
        parts.push({
          text: "Generate an image according to the user request.",
        });
      }

      const jsonBody = {
        contents: [{ role: "user", parts }],
        generationConfig: {
          responseModalities: ["TEXT", "IMAGE"],
        },
      };

      const { requestUrl, headers } = buildLaozhangRequest(url, {
        apiKey,
      });

      let upstreamResponse;
      const startedAt = Date.now();
      const controller = new AbortController();
      const configuredTimeoutMs = Number(process.env.LAOZHANG_TIMEOUT_MS || 180_000);
      const timeoutMs =
        Number.isFinite(configuredTimeoutMs) && configuredTimeoutMs > 0
          ? Math.min(Math.max(configuredTimeoutMs, 10_000), 10 * 60_000)
          : 180_000;
      const timeout = setTimeout(() => controller.abort(), timeoutMs);

      try {
        upstreamResponse = await fetch(requestUrl, {
          method: "POST",
          signal: controller.signal,
          headers,
          body: JSON.stringify(jsonBody),
        });
      } finally {
        clearTimeout(timeout);
      }

      const raw = await upstreamResponse.json().catch(() => ({}));

      if (!upstreamResponse.ok) {
        console.warn("Laozhang Gemini upstream non-OK response.", {
          attempt: attemptIndex,
          status: upstreamResponse.status,
          elapsed_ms: Date.now() - startedAt,
          requestUrl,
          body_preview: JSON.stringify(raw || {}).slice(0, 900),
        });
        lastError = {
          index: attemptIndex,
          status: upstreamResponse.status,
          message: normalizeUpstreamErrorMessage(
            raw?.error || raw?.message || raw
          ),
        };
        return false;
      }

      const extractedImages = await extractImagesFromRaw(raw);

      if (!extractedImages.length) {
        lastError = {
          index: attemptIndex,
          status: 502,
          message: "Сервис вернул ответ без изображения",
        };
        return false;
      }

      for (const item of extractedImages) {
        generatedImages.push({
          imageData: item.imageData,
          mimeType: item.mimeType,
          raw,
        });
      }
      return true;
    };

    const runLaozhangAttempt = async (url, apiKey, attemptIndex, model) => {
      const effectiveUrlForLog =
        inlineImages.length > 0
          ? String(url).replace(/\/images\/generations\b/i, "/images/edits")
          : String(url);

      const maxSocketAttempts = 1 + laozhangSocketRetries;

      for (let socketTry = 0; socketTry < maxSocketAttempts; socketTry++) {
        const startedAt = Date.now();
        if (socketTry > 0) {
          await new Promise((r) =>
            setTimeout(r, laozhangSocketRetryDelayMs)
          );
          console.warn("Laozhang socket retry after transient failure.", {
            attempt: attemptIndex,
            socketTry: socketTry + 1,
            url: effectiveUrlForLog,
          });
        }

        try {
          const ok = await attemptUpstream(url, apiKey, attemptIndex, model);
          if (ok) return true;
          return false;
        } catch (error) {
          const cause = error?.cause;
          const netCode = error?.code || cause?.code || "";
          const causeMsg = String(cause?.message || "");
          const transient =
            netCode === "EPIPE" ||
            netCode === "UND_ERR_SOCKET" ||
            /other side closed|ECONNRESET|ETIMEDOUT/i.test(causeMsg);

          console.error("Laozhang upstream fetch exception.", {
            attempt: attemptIndex,
            socketTry: socketTry + 1,
            elapsed_ms: Date.now() - startedAt,
            message: String(error?.message || error || "unknown error"),
            name: error?.name || "",
            code: netCode,
            errno: error?.errno || cause?.errno || "",
            syscall: error?.syscall || cause?.syscall || "",
            cause: cause
              ? {
                  name: cause?.name,
                  message: causeMsg,
                  code: cause?.code,
                }
              : null,
            url: effectiveUrlForLog,
            hint:
              netCode === "EPIPE" || netCode === "UND_ERR_SOCKET"
                ? "Соединение с API оборвалось во время запроса (сеть, таймаут или обрыв на стороне upstream)."
                : undefined,
          });

          const isAbort = error?.name === "AbortError";
          lastError = {
            index: attemptIndex,
            status: isAbort ? 504 : 503,
            message:
              error?.message ||
              (isAbort ? "timeout" : "Ошибка сервиса"),
          };

          if (transient && !isAbort && socketTry < maxSocketAttempts - 1) {
            continue;
          }
          return false;
        }
      }

      return false;
    };

    const runGeminiAttempt = async (url, apiKey, attemptIndex) => {
      const effectiveUrlForLog = String(url);
      const maxSocketAttempts = 1 + laozhangSocketRetries;

      for (let socketTry = 0; socketTry < maxSocketAttempts; socketTry++) {
        const startedAt = Date.now();
        if (socketTry > 0) {
          await new Promise((r) =>
            setTimeout(r, laozhangSocketRetryDelayMs)
          );
          console.warn("Laozhang Gemini socket retry after transient failure.", {
            attempt: attemptIndex,
            socketTry: socketTry + 1,
            url: effectiveUrlForLog,
          });
        }

        try {
          const ok = await attemptGeminiUpstream(url, apiKey, attemptIndex);
          if (ok) return true;
          return false;
        } catch (error) {
          const cause = error?.cause;
          const netCode = error?.code || cause?.code || "";
          const causeMsg = String(cause?.message || "");
          const transient =
            netCode === "EPIPE" ||
            netCode === "UND_ERR_SOCKET" ||
            /other side closed|ECONNRESET|ETIMEDOUT/i.test(causeMsg);

          console.error("Laozhang Gemini upstream fetch exception.", {
            attempt: attemptIndex,
            socketTry: socketTry + 1,
            elapsed_ms: Date.now() - startedAt,
            message: String(error?.message || error || "unknown error"),
            name: error?.name || "",
            code: netCode,
            errno: error?.errno || cause?.errno || "",
            syscall: error?.syscall || cause?.syscall || "",
            cause: cause
              ? {
                  name: cause?.name,
                  message: causeMsg,
                  code: cause?.code,
                }
              : null,
            url: effectiveUrlForLog,
            hint:
              netCode === "EPIPE" || netCode === "UND_ERR_SOCKET"
                ? "Соединение с API оборвалось во время запроса (сеть, таймаут или обрыв на стороне upstream)."
                : undefined,
          });

          const isAbort = error?.name === "AbortError";
          lastError = {
            index: attemptIndex,
            status: isAbort ? 504 : 503,
            message:
              error?.message ||
              (isAbort ? "timeout" : "Ошибка сервиса"),
          };

          if (transient && !isAbort && socketTry < maxSocketAttempts - 1) {
            continue;
          }
          return false;
        }
      }

      return false;
    };

    const tierDefs = [];
    if (candidateUrl) {
      tierDefs.push({
        run: () => runLaozhangAttempt(candidateUrl, LAOZHANG_API_KEY, 1, GPT_MODEL),
      });
    }
    // Цепочка для обычных фото: flare → gpt-image-2 → Gemini.
    // Прозрачный фон умеет только flare — запасные для него не подключаем.
    if (
      candidateUrl &&
      !transparentBackground &&
      GPT_FALLBACK_MODEL &&
      GPT_FALLBACK_MODEL !== GPT_MODEL
    ) {
      tierDefs.push({
        run: () =>
          runLaozhangAttempt(candidateUrl, LAOZHANG_API_KEY, 2, GPT_FALLBACK_MODEL),
      });
    }
    // Gemini не умеет прозрачный фон — вместо PNG с альфой молча вернул бы обычную картинку.
    if (geminiFullUrl && !transparentBackground) {
      tierDefs.push({
        run: () => runGeminiAttempt(geminiFullUrl, LAOZHANG_API_KEY, 3),
      });
    }
    const reservation = await reserveBalance(
      req.chatId,
      SUPABASE_BALANCE_COLUMN,
      requestedCount
    );
    if (!reservation.ok) {
      return res.status(402).json({
        error: "Недостаточно генераций. Пополните баланс.",
        code: "INSUFFICIENT_BALANCE",
        balance: reservation.balance,
        required: requestedCount,
      });
    }
    let nextBalance = reservation.balance;
    pendingRefund = { column: SUPABASE_BALANCE_COLUMN, amount: requestedCount };

    const cascadeTotal = tierDefs.length;
    const reconnectNotices = [];
    let fallbackTierUsed = 0;

    for (let i = 0; i < tierDefs.length; i++) {
      if (i > 0) {
        const msg = `Переподключаемся x${i + 1}/${cascadeTotal}…`;
        reconnectNotices.push(msg);
        console.warn("Laozhang cascade", {
          step: i + 1,
          total: cascadeTotal,
          message: msg,
        });
      }
      generatedImages.length = 0;
      const ok = await tierDefs[i].run();
      if (ok) {
        fallbackTierUsed = i + 1;
        break;
      }
    }

    if (!generatedImages.length) {
      const refunded = await refundBalance(
        req.chatId,
        SUPABASE_BALANCE_COLUMN,
        requestedCount
      );
      if (refunded != null) nextBalance = refunded;

      generationErrors.push(lastError);
      const msg = String(lastError?.message || "");
      const safetyRejected =
        /safety|rejected by the|content policy|moderation|not allowed/i.test(
          msg
        );
      if (safetyRejected) {
        return res.status(422).json({
          error:
            "Запрос отклонён модерацией провайдера. Смените формулировку или другое фото.",
          code: "GENERATION_SAFETY",
          details: generationErrors,
          balance: nextBalance,
        });
      }
      const socketLikeFailure =
        Number(lastError?.status) === 503 &&
        /fetch failed|socket|timeout/i.test(msg);
      // Прозрачный фон делает только flare-модель, запасных нет — говорим прямо
      if (transparentBackground) {
        // 451 = модерация провайдера (content_safety): сообщение у неё пустое,
        // общая проверка на «safety» выше её не ловит
        const moderated = Number(lastError?.status) === 451;
        return res.status(422).json({
          error: moderated
            ? "Модерация нейросети не пропустила это фото. Генерация не списана — попробуйте другое фото."
            : "Прозрачный фон сейчас недоступен — нейросеть не ответила. Генерация не списана, попробуйте позже.",
          code: moderated ? "TRANSPARENT_SAFETY" : "TRANSPARENT_UNAVAILABLE",
          details: generationErrors,
          balance: nextBalance,
        });
      }
      return res.status(502).json({
        error: socketLikeFailure
          ? "Соединение с сервисом генерации оборвалось (часто на запросах с фото). Повторите через несколько секунд."
          : "Ошибка генерации, попробуйте еще раз через 10 секунд",
        code: "GENERATION_FAILED_ALL",
        details: generationErrors,
        balance: nextBalance,
      });
    }

    const chargedCount = generatedImages.length;

    // Зарезервировали requestedCount, но реально сгенерировалось меньше — вернём разницу.
    if (chargedCount < requestedCount) {
      const refunded = await refundBalance(
        req.chatId,
        SUPABASE_BALANCE_COLUMN,
        requestedCount - chargedCount
      );
      if (refunded != null) nextBalance = refunded;
    }

    pendingRefund = null;
    return res.json({
      imageData: generatedImages[0].imageData,
      images: generatedImages.map((item) => ({
        data: item.imageData,
        mimeType: item.mimeType || "image/png",
      })),
      balance: nextBalance,
      charged: chargedCount,
      requested: requestedCount,
      partial: generatedImages.length < requestedCount,
      failed: Math.max(0, requestedCount - generatedImages.length),
      errors: generationErrors,
      fallbackTier: fallbackTierUsed,
      cascadeTotal,
      reconnectNotices:
        fallbackTierUsed > 1 ? reconnectNotices : [],
    });
  } catch (error) {
    console.error("generate error", error);
    if (pendingRefund) {
      try {
        await refundBalance(
          req.chatId,
          pendingRefund.column,
          pendingRefund.amount
        );
      } catch (refundError) {
        console.error(
          "generate error: refund after exception also failed",
          refundError
        );
      }
    }
    return res.status(500).json({ error: "Внутренняя ошибка сервера" });
  }
});

app.post("/api/generate-video/start", requireChatId, async (req, res) => {
  try {
    if (!SEEDANCE_API_KEY) {
      return res.status(500).json({ error: "SEEDANCE_API_KEY не настроен" });
    }

    let user = await getUserByChatId(req.chatId);
    if (!user && AUTO_CREATE_USER) {
      user = await createUserIfMissing(req.chatId);
    }

    if (!user) {
      return res
        .status(401)
        .json({ error: "Пользователь не найден в Supabase" });
    }

    const rawBalance = Number(user?.[SUPABASE_BALANCE_COLUMN]);
    const currentBalance = Number.isFinite(rawBalance) ? rawBalance : 0;

    const sound = Boolean(req.body?.sound);
    const duration = String(req.body?.duration) === "10" ? "10" : "5";
    const cost = resolveVideoGenerationCost(sound, duration);

    if (currentBalance < cost) {
      return res.status(402).json({
        error: "Недостаточно генераций. Пополните баланс.",
        code: "INSUFFICIENT_BALANCE",
        balance: currentBalance,
        required: cost,
      });
    }

    const promptText = extractPromptText(req.body);

    const imageBase64 = String(req.body?.imageBase64 || "").trim();
    if (!imageBase64) {
      return res.status(400).json({ error: "Нужно загрузить изображение." });
    }

    let buffer;
    try {
      buffer = Buffer.from(imageBase64, "base64");
    } catch {
      return res.status(400).json({ error: "Некорректное изображение." });
    }

    const maxBytes = 18 * 1024 * 1024;
    if (!buffer.length || buffer.length > maxBytes) {
      return res.status(413).json({ error: "Файл слишком большой." });
    }

    const mimeType = String(req.body?.mimeType || "image/jpeg").trim();
    const ext =
      mimeType.includes("png") ? "png" : mimeType.includes("webp") ? "webp" : "jpg";

    const upload = await uploadBufferToTmpfiles(
      buffer,
      `ref.${ext}`,
      mimeType
    );

    if (!upload.ok) {
      return res.status(502).json({
        error: upload.error || "Не удалось загрузить картинку.",
        code: "TMPFILES_UPLOAD_FAILED",
      });
    }

    const imageUrl = await resolveTmpfilesDlUrl(upload.pageUrl);
    if (!imageUrl) {
      return res.status(502).json({
        error: "Не удалось получить прямую ссылку на изображение.",
        code: "TMPFILES_RESOLVE_FAILED",
      });
    }

    const { response: seedanceRes, raw: seedanceRaw } = await seedanceFetchJson(
      "/contents/generations/tasks",
      {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          model: SEEDANCE_MODEL,
          content: [
            { type: "text", text: promptText },
            {
              type: "image_url",
              image_url: { url: imageUrl },
              role: "reference_image",
            },
          ],
          ratio: SEEDANCE_RATIO,
          duration: Number(duration),
          resolution: SEEDANCE_RESOLUTION,
          generate_audio: sound,
        }),
      }
    );

    const taskId = extractSeedanceTaskId(seedanceRaw);

    if (!seedanceRes.ok || !taskId) {
      const msg =
        typeof seedanceRaw?.error?.message === "string" && seedanceRaw.error.message.trim()
          ? seedanceRaw.error.message
          : typeof seedanceRaw?.message === "string" && seedanceRaw.message.trim()
            ? seedanceRaw.message
            : "Не удалось создать задачу видео.";
      return res.status(502).json({
        error: msg,
        code: "SEEDANCE_CREATE_FAILED",
        raw: seedanceRaw,
      });
    }

    pruneVideoJobMaps();
    videoJobMetaByTaskId.set(taskId, {
      chatId: String(req.chatId),
      cost,
      createdAt: Date.now(),
    });

    return res.json({
      taskId,
      cost,
    });
  } catch (error) {
    console.error("generate-video start error", error);
    return res.status(500).json({ error: "Внутренняя ошибка сервера" });
  }
});

app.get("/api/generate-video/status", requireChatId, async (req, res) => {
  try {
    if (!SEEDANCE_API_KEY) {
      return res.status(500).json({ error: "SEEDANCE_API_KEY не настроен" });
    }

    const taskId = String(req.query?.taskId || "").trim();
    if (!taskId) {
      return res.status(400).json({ error: "Нужен taskId." });
    }

    const meta = videoJobMetaByTaskId.get(taskId);
    if (!meta || meta.chatId !== String(req.chatId)) {
      return res.status(404).json({ error: "Задача не найдена." });
    }

    if (videoJobResultByTaskId.has(taskId)) {
      const cached = videoJobResultByTaskId.get(taskId);
      return res.json({
        state: "success",
        videoUrl: cached.videoUrl,
        balance: cached.balance,
        charged: cached.cost,
        cached: true,
      });
    }

    const { response: seedanceRes, raw: seedanceRaw } = await seedanceFetchJson(
      `/contents/generations/tasks/${encodeURIComponent(taskId)}`,
      { method: "GET" }
    );

    const state = normalizeSeedanceState(seedanceRaw?.status);

    if (!seedanceRes.ok) {
      return res.status(502).json({
        error:
          typeof seedanceRaw?.error?.message === "string"
            ? seedanceRaw.error.message
            : "Ошибка Seedance API",
        code: "SEEDANCE_STATUS_HTTP",
      });
    }

    if (isSeedancePendingState(state)) {
      return res.json({
        state: "pending",
        seedanceState: seedanceRaw?.status || state,
      });
    }

    if (isSeedanceFailedState(state)) {
      videoJobMetaByTaskId.delete(taskId);
      return res.json({
        state: "failed",
        error:
          String(seedanceRaw?.error?.message || "").trim() ||
          "Генерация видео не удалась.",
        failCode: seedanceRaw?.error?.code || "",
      });
    }

    if (!isSeedanceSuccessState(state)) {
      return res.json({
        state: "pending",
        seedanceState: seedanceRaw?.status || state,
      });
    }

    const videoUrl = extractVideoUrlFromSeedanceRecord(seedanceRaw);
    if (!videoUrl) {
      return res.status(502).json({
        error: "Сервис не вернул ссылку на видео.",
        code: "SEEDANCE_NO_VIDEO_URL",
      });
    }

    let user = await getUserByChatId(req.chatId);
    if (!user && AUTO_CREATE_USER) {
      user = await createUserIfMissing(req.chatId);
    }
    if (!user) {
      return res.status(401).json({ error: "Пользователь не найден." });
    }


    // CAS вместо read-then-write: несколько параллельных опросов статуса одной
    // и той же задачи (или разных задач) не должны списать баланс дважды/в минус.
    const reservation = await reserveBalance(
      req.chatId,
      SUPABASE_BALANCE_COLUMN,
      meta.cost
    );
    if (!reservation.ok) {
      return res.status(402).json({
        error: "Недостаточно генераций на момент завершения.",
        code: "INSUFFICIENT_BALANCE",
        balance: reservation.balance,
        required: meta.cost,
      });
    }
    const nextBalance = reservation.balance;


    videoJobResultByTaskId.set(taskId, {
      videoUrl,
      balance: nextBalance,
      cost: meta.cost,
    });
    videoJobMetaByTaskId.delete(taskId);

    return res.json({
      state: "success",
      videoUrl,
      balance: nextBalance,
      charged: meta.cost,
    });
  } catch (error) {
    console.error("generate-video status error", error);
    return res.status(500).json({ error: "Внутренняя ошибка сервера" });
  }
});

// «Промт по фото»: POST /api/describe-image (логика — в describe.js)
registerDescribeRoutes(app, {
  requireChatId,
  buildLaozhangRequest,
  apiKey: LAOZHANG_API_KEY,
  apiHost: LAOZHANG_PRIMARY_HOST,
  normalizeEnv,
});

const server = app.listen(PORT, () => {
  const addr = server.address();
  if (!server.listening || !addr) {
    return;
  }

  console.log(
    `Config: table=${SUPABASE_USERS_TABLE}, chatColumn=${SUPABASE_CHAT_ID_COLUMN}, versionColumn=${SUPABASE_VERSION_COLUMN}, pricesTable=${SUPABASE_PRICES_TABLE}, origins=${ALLOWED_ORIGINS.join(
      ","
    )}`
  );

  console.log(
    `Payments: provider=${PAYMENT_PROVIDER_URL}, authMode=${PAYMENT_PROVIDER_AUTH_MODE}, return=${PAYMENT_RETURN_URL}, merchant=${
      PAYMENT_PROVIDER_MERCHANT_ID ? "set" : "missing"
    }, secret=${PAYMENT_PROVIDER_SECRET ? "set" : "missing"}`
  );

  console.log(
    `Seedance video: apiKey=${SEEDANCE_API_KEY ? "set" : "missing"}, base=${SEEDANCE_API_BASE}, model=${SEEDANCE_MODEL}`
  );

  console.log(
    `Laozhang cascade: GPT_MODEL=${GPT_MODEL} → GPT_FALLBACK_MODEL=${GPT_FALLBACK_MODEL || "—"} → LAOZHANG_GEMINI_MODEL=${LAOZHANG_GEMINI_MODEL || "—"}`
  );

  console.log(
    `Feedback: chatId=${FEEDBACK_CHAT_ID ? "set" : "missing"}, botToken=${
      TELEGRAM_BOT_TOKEN ? "set" : "missing"
    }`
  );

  console.log(`Backend started on port ${PORT}`);
});

server.on("error", (err) => {
  if (err?.code === "EADDRINUSE") {
    console.error(
      `Port ${PORT} is already in use. Stop the other process or set PORT in .env`
    );
  } else {
    console.error("Server listen error:", err);
  }
  process.exit(1);
});
