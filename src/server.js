import crypto from "node:crypto";
import dotenv from "dotenv";
import express from "express";
import cors from "cors";
import cookieParser from "cookie-parser";
import { createClient } from "@supabase/supabase-js";

import promptsLibrary from "./prompts.json" with { type: "json" };

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
  normalizeEnv(process.env.FRONTEND_SUCCESS_REDIRECT) ||
  `${FRONTEND_ORIGIN}/generate.html`;

const FRONTEND_ERROR_REDIRECT =
  normalizeEnv(process.env.FRONTEND_ERROR_REDIRECT) ||
  `${FRONTEND_ORIGIN}/generate.html?auth_error=1`;

const TELEGRAM_BOT_TOKEN = normalizeEnv(process.env.TELEGRAM_BOT_TOKEN);
const TELEGRAM_WIDGET_MAX_AGE_SECONDS = Number(
  process.env.TELEGRAM_WIDGET_MAX_AGE_SECONDS || 300
);

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
const SUPABASE_BALANCE_FREE_COLUMN = normalizeEnv(
  process.env.SUPABASE_BALANCE_FREE_COLUMN,
  "balance_free"
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
const SUPABASE_PRICES_FREE_TABLE = normalizeEnv(
  process.env.SUPABASE_PRICES_FREE_TABLE,
  "user_price_free"
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
const SUPABASE_VERSION_COLUMN = normalizeEnv(
  process.env.SUPABASE_VERSION_COLUMN,
  "version"
);
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

const LAOZHANG_URL = normalizeLaozhangPath(process.env.LAOZHANG_URL);
const LAOZHANG_URL_FREE = normalizeLaozhangPath(process.env.LAOZHANG_URL_FREE);
const LAOZHANG_API_KEY = normalizeEnv(process.env.LAOZHANG_API_KEY);
const LAOZHANG_AUTH_MODE = normalizeEnv(
  process.env.LAOZHANG_AUTH_MODE,
  "bearer"
).toLowerCase();

const LAOZHANG_PRIMARY_HOST = normalizeLaozhangHost(process.env.LAOZHANG_URL_1);
const LAOZHANG_HOSTS = [
  normalizeLaozhangHost(process.env.LAOZHANG_URL_1),
  normalizeLaozhangHost(process.env.LAOZHANG_URL_2),
  normalizeLaozhangHost(process.env.LAOZHANG_URL_3),
].filter(Boolean);

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
  normalizeEnv(process.env.PAYMENT_RETURN_URL) ||
  `${FRONTEND_ORIGIN}/generate.html`;
const PAYMENT_CURRENCY = normalizeEnv(process.env.PAYMENT_CURRENCY, "RUB");
const WEBHOOK_SECRET = normalizeEnv(process.env.PAYMENT_WEBHOOK_SECRET);
const WEBHOOK_SECRET_HEADER = normalizeEnv(
  process.env.PAYMENT_WEBHOOK_SECRET_HEADER,
  "x-webhook-secret"
);

const OPENROUTER_API_KEY = normalizeEnv(process.env.OPENROUTER_API_KEY);
const OPENROUTER_MODEL = normalizeEnv(process.env.OPENROUTER_MODEL);

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

const sseClientsByChatId = new Map();

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
  const sortedPairs = Object.keys(dataObj)
    .filter(
      (k) => k !== "hash" && dataObj[k] !== undefined && dataObj[k] !== null
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

  res.cookie("chatid", String(chatId), { ...common, httpOnly: false });
  res.cookie("tg_session", "1", { ...common, httpOnly: true });
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

function buildSuccessRedirectUrl(chatId) {
  const token = createSessionToken(chatId);
  if (!token) return FRONTEND_SUCCESS_REDIRECT;

  try {
    const target = new URL(FRONTEND_SUCCESS_REDIRECT);
    target.searchParams.set("session", token);
    return target.toString();
  } catch {
    const glue = FRONTEND_SUCCESS_REDIRECT.includes("?") ? "&" : "?";
    return `${FRONTEND_SUCCESS_REDIRECT}${glue}session=${encodeURIComponent(
      token
    )}`;
  }
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
    [SUPABASE_BALANCE_FREE_COLUMN]: 0,
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
  };
}

/**
 * Разбор payload платежа: `${chatId}-${planId}`.
 * И user id, и id тарифа в БД — строки (Telegram: цифры, Google: `g…`, тариф: число или uuid).
 */
function parseWebhookPayload(payloadValue) {
  const raw = String(payloadValue || "").trim();
  if (!raw) return null;

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
  };
}

function normalizeVersionRuntime(value) {
  return String(value || "").toLowerCase() === "free" ? "free" : "pro";
}

function normalizeVersionStorage(value) {
  return normalizeVersionRuntime(value) === "free" ? "FREE" : "PRO";
}

function resolveVersionConfig(versionRuntime) {
  if (versionRuntime === "free") {
    return {
      versionRuntime: "free",
      versionStorage: "FREE",
      balanceColumn: SUPABASE_BALANCE_FREE_COLUMN,
      pricesTable: SUPABASE_PRICES_FREE_TABLE,
      upstreamPath: LAOZHANG_URL_FREE,
    };
  }

  return {
    versionRuntime: "pro",
    versionStorage: "PRO",
    balanceColumn: SUPABASE_BALANCE_COLUMN,
    pricesTable: SUPABASE_PRICES_TABLE,
    upstreamPath: LAOZHANG_URL,
  };
}

function buildLaozhangUpstreamCandidates(upstreamPath) {
  if (!upstreamPath) return [];
  if (!LAOZHANG_PRIMARY_HOST) return [];
  return [`https://${LAOZHANG_PRIMARY_HOST}${upstreamPath}`];
}

function buildLaozhangRequest(url) {
  const headers = { "Content-Type": "application/json" };
  let requestUrl = url;

  if (LAOZHANG_AUTH_MODE === "query") {
    const glue = requestUrl.includes("?") ? "&" : "?";
    requestUrl = `${requestUrl}${glue}key=${encodeURIComponent(
      LAOZHANG_API_KEY
    )}`;
  } else {
    headers.Authorization = `Bearer ${LAOZHANG_API_KEY}`;
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

function emitSseEvent(chatId, eventName, payload = {}) {
  const subscribers = sseClientsByChatId.get(String(chatId));
  if (!subscribers?.size) return;

  const eventPayload = JSON.stringify({
    chat_id: String(chatId),
    ts: Date.now(),
    ...payload,
  });

  subscribers.forEach((client) => {
    client.write(`event: ${eventName}\ndata: ${eventPayload}\n\n`);
  });
}

function resolveChatIdFromRequest(req, options = {}) {
  const { allowQuerySession = false } = options;

  const chatIdFromCookie = req.cookies?.chatid;
  if (chatIdFromCookie) return String(chatIdFromCookie);

  const authHeader = String(req.headers.authorization || "");
  const token = authHeader.startsWith("Bearer ")
    ? authHeader.slice(7).trim()
    : "";

  const chatIdFromToken = verifySessionToken(token);
  if (chatIdFromToken) return String(chatIdFromToken);

  if (allowQuerySession) {
    const queryToken = String(req.query?.session || "").trim();
    const chatIdFromQueryToken = verifySessionToken(queryToken);
    if (chatIdFromQueryToken) return String(chatIdFromQueryToken);
  }

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

async function checkPromptWithOpenRouter(prompt) {
  if (!OPENROUTER_API_KEY) {
    return {
      ok: true,
      safe: true,
      shouldBlock: false,
      hasClearIntent: true,
    };
  }

  const schema = {
    name: "prompt_safety_check",
    strict: true,
    schema: {
      type: "object",
      properties: {
        safe: { type: "boolean" },
        shouldBlock: { type: "boolean" },
        riskLevel: {
          type: "string",
          enum: ["low", "medium", "high"],
        },
        reasons: {
          type: "array",
          items: { type: "string" },
        },
        suggestedRewrite: {
          anyOf: [{ type: "string" }, { type: "null" }],
        },
        shortMessageRu: { type: "string" },
      },
      required: [
        "safe",
        "shouldBlock",
        "riskLevel",
        "reasons",
        "suggestedRewrite",
        "shortMessageRu",
      ],
      additionalProperties: false,
    },
  };

  const response = await fetch(
    "https://openrouter.ai/api/v1/chat/completions",
    {
      method: "POST",
      headers: {
        Authorization: `Bearer ${OPENROUTER_API_KEY}`,
        "Content-Type": "application/json",
        "HTTP-Referer": FRONTEND_ORIGIN,
        "X-Title": "NanoBanana Prompt Filter",
      },
      body: JSON.stringify({
        model: OPENROUTER_MODEL,
        temperature: 0,
        messages: [
          {
            role: "system",
            content: `Проверь текстовый prompt для генерации изображения.
            Верни только JSON:
            {"shouldBlock":false,"hasClearIntent":true}

          Правила:
          - shouldBlock=true, ТОЛЬКО: обнажёнка, кровь.
          - hasClearIntent=false, если это бессмысленный набор символов, случайные буквы, мусорный текст или слишком расплывчатый запрос, по которому непонятно, что рисовать.
          - Короткие, но понятные запросы (например "кот в шляпе") считаются нормальными.
          - Ничего кроме JSON не пиши.`,
          },
          {
            role: "user",
            content: prompt,
          },
        ],
        response_format: {
          type: "json_schema",
          json_schema: {
            name: "prompt_safety_check",
            strict: true,
            schema: {
              type: "object",
              properties: {
                shouldBlock: { type: "boolean" },
                hasClearIntent: { type: "boolean" },
              },
              required: ["shouldBlock", "hasClearIntent"],
              additionalProperties: false,
            },
          },
        },
      }),
    }
  );

  if (!response.ok) {
    const raw = await response.text();
    throw new Error(`OpenRouter error ${response.status}: ${raw}`);
  }

  const data = await response.json();
  const content = data?.choices?.[0]?.message?.content;
  const parsed = JSON.parse(content);

  return {
    ok: true,
    model: OPENROUTER_MODEL,
    shouldBlock: Boolean(parsed.shouldBlock),
    hasClearIntent: Boolean(parsed.hasClearIntent),
  };
}

app.get("/health", (_req, res) => {
  res.json({ ok: true });
});

app.get("/api/prompts", (req, res) => {
  res.json(promptsLibrary);
});

app.get("/api/events", (req, res) => {
  const chatId = resolveChatIdFromRequest(req, { allowQuerySession: true });
  if (!chatId) {
    return res.status(401).json({
      error: "Не авторизован. Войдите через Telegram или Google.",
    });
  }

  res.setHeader("Content-Type", "text/event-stream");
  res.setHeader("Cache-Control", "no-cache, no-transform");
  res.setHeader("Connection", "keep-alive");
  res.setHeader("X-Accel-Buffering", "no");
  res.flushHeaders?.();

  const clients = sseClientsByChatId.get(chatId) || new Set();
  clients.add(res);
  sseClientsByChatId.set(chatId, clients);

  res.write(
    `event: connected\ndata: ${JSON.stringify({
      ok: true,
      chat_id: chatId,
      ts: Date.now(),
    })}\n\n`
  );

  const heartbeat = setInterval(() => {
    res.write(`: ping ${Date.now()}\n\n`);
  }, 25000);

  req.on("close", () => {
    clearInterval(heartbeat);
    const active = sseClientsByChatId.get(chatId);
    if (!active) return;
    active.delete(res);
    if (!active.size) sseClientsByChatId.delete(chatId);
  });
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
    return res.redirect(buildSuccessRedirectUrl(chatId));
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
    return res.redirect(buildSuccessRedirectUrl(chatId));
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
      balance_free:
        SUPABASE_BALANCE_FREE_COLUMN in user
          ? user[SUPABASE_BALANCE_FREE_COLUMN]
          : null,
      version: normalizeVersionRuntime(user?.[SUPABASE_VERSION_COLUMN]),
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

app.post("/api/version", requireChatId, async (req, res) => {
  try {
    if (!supabase) {
      return res.status(500).json({ error: "Supabase не настроен" });
    }

    const versionRuntime = normalizeVersionRuntime(req.body?.version);
    const versionStorage = normalizeVersionStorage(req.body?.version);

    const { error } = await supabase
      .from(SUPABASE_USERS_TABLE)
      .update({ [SUPABASE_VERSION_COLUMN]: versionStorage })
      .eq(SUPABASE_CHAT_ID_COLUMN, req.chatId);

    if (error) {
      if (error?.code === "PGRST204") {
        return res.status(400).json({
          error: `Добавь колонку '${SUPABASE_VERSION_COLUMN}' в таблицу '${SUPABASE_USERS_TABLE}' для сохранения версии.`,
        });
      }
      throw error;
    }

    return res.json({ ok: true, version: versionRuntime });
  } catch (error) {
    console.error("version update error", error);
    return res.status(500).json({ error: "Не удалось сохранить версию" });
  }
});

app.get("/api/pricing", requireChatId, async (req, res) => {
  try {
    const version = normalizeVersionRuntime(req.query?.version);
    const versionCfg = resolveVersionConfig(version);
    const plans = await getPricingPlans(versionCfg.pricesTable);

    return res.json({
      version: versionCfg.versionRuntime,
      plans: plans.map(mapPlanForFrontend),
    });
  } catch (error) {
    console.error("pricing error", error);
    return res.status(500).json({ error: "Не удалось загрузить тарифы" });
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

    const requestedVersion = normalizeVersionRuntime(req.body?.version);
    const versionCfg = resolveVersionConfig(requestedVersion);
    const plan = await getPricingPlanById(planId, versionCfg.pricesTable);

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

    const payload = `${req.chatId}-${plan[SUPABASE_PRICE_ID_COLUMN]}`;
    const providerRequestBody = {
      paymentMethod: PAYMENT_METHOD,
      description: `Оплата ${generations} генераций (${versionCfg.versionRuntime.toUpperCase()}) для юзера ${
        req.chatId
      }`,
      paymentDetails: {
        amount,
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
      version: versionCfg.versionRuntime,
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

    const { chatId, planId } = parsed;

    if (status === "pending") {
      emitSseEvent(chatId, "payment_pending", {
        type: "payment_pending",
        status,
        plan_id: planId,
      });
      return res.json({ ok: true, pending: true, status });
    }

    if (["canceled", "chargebacked"].includes(status)) {
      emitSseEvent(chatId, "payment_failed", {
        type: "payment_failed",
        status,
        plan_id: planId,
      });
      return res.json({ ok: true, ignored: true, status });
    }

    if (status !== "confirmed") {
      emitSseEvent(chatId, "payment_failed", {
        type: "payment_failed",
        status: status || "unknown",
        plan_id: planId,
      });
      return res.json({ ok: true, ignored: true, status });
    }

    const user = await getUserByChatId(chatId);
    if (!user) {
      return res.status(404).json({ error: "user not found" });
    }

    const selectedVersion = normalizeVersionRuntime(
      user?.[SUPABASE_VERSION_COLUMN]
    );
    const versionCfg = resolveVersionConfig(selectedVersion);
    const plan = await getPricingPlanById(planId, versionCfg.pricesTable);

    if (!plan) {
      return res.status(404).json({ error: "pricing plan not found" });
    }

    const generations = Number(plan?.[SUPABASE_PRICE_GENERATIONS_COLUMN] || 0);
    const priceRub = Number(plan?.[SUPABASE_PRICE_AMOUNT_COLUMN] || 0);
    const currentBalance = Number(user?.[versionCfg.balanceColumn] || 0);
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
        [versionCfg.balanceColumn]: nextBalance,
        [SUPABASE_TOTAL_SUM_COLUMN]: nextTotalSum,
      })
      .eq(SUPABASE_CHAT_ID_COLUMN, chatId);

    if (updateError) {
      throw updateError;
    }

    emitSseEvent(chatId, "balance_update", {
      type: "balance_update",
      version: versionCfg.versionRuntime,
      balance: nextBalance,
      total_sum: nextTotalSum,
    });

    return res.json({
      ok: true,
      chat_id: chatId,
      version: versionCfg.versionRuntime,
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

    const requestedVersion = normalizeVersionRuntime(
      req.body?.version || user?.[SUPABASE_VERSION_COLUMN]
    );
    const versionCfg = resolveVersionConfig(requestedVersion);
    const rawBalance = Number(user?.[versionCfg.balanceColumn]);
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

    const promptText = extractPromptText(req.body);

    if (promptText.trim()) {
      const moderation = await checkPromptWithOpenRouter(promptText);

      if (moderation.shouldBlock) {
        return res.status(422).json({
          error:
            moderation.shortMessageRu ||
            "Запрос содержит 18+ контент и не может быть отправлен в генерацию.",
          code: "PROMPT_BLOCKED",
          moderation: {
            safe: moderation.safe,
            shouldBlock: moderation.shouldBlock,
            riskLevel: moderation.riskLevel,
            reasons: moderation.reasons,
            suggestedRewrite: null,
            model: moderation.model,
          },
        });
      }
    }

    const upstreamCandidates = buildLaozhangUpstreamCandidates(
      versionCfg.upstreamPath
    );

    if (!versionCfg.upstreamPath) {
      return res.status(500).json({
        error:
          requestedVersion === "free"
            ? "LAОZHANG_URL_FREE не настроен"
            : "LAOZHANG_URL не настроен",
      });
    }

    if (!upstreamCandidates.length) {
      return res.status(500).json({
        error: "Не настроен хост LAOZHANG_URL_1",
      });
    }

    const upstreamPayloadBase = { ...req.body };
    delete upstreamPayloadBase.version;

    if (upstreamPayloadBase?.generationConfig?.imageConfig) {
      const imageCfg = upstreamPayloadBase.generationConfig.imageConfig;
      if (
        typeof imageCfg.aspectRatio === "string" &&
        !imageCfg.aspectRatio.trim()
      ) {
        delete imageCfg.aspectRatio;
      }
    }

    const extractImagesFromRaw = (rawData) => {
      const normalizeImageString = (value, fallbackMime = "image/png") => {
        if (typeof value !== "string" || !value.trim()) return null;

        const trimmed = value.trim();
        const dataUrlMatch = trimmed.match(/^data:(.+?);base64,(.+)$/i);

        if (dataUrlMatch) {
          return {
            imageData: dataUrlMatch[2],
            mimeType: dataUrlMatch[1] || fallbackMime,
          };
        }

        return {
          imageData: trimmed,
          mimeType: fallbackMime,
        };
      };

      const parts =
        rawData?.candidates?.[0]?.content?.parts ||
        rawData?.data?.candidates?.[0]?.content?.parts ||
        [];

      const inlineImages = parts
        .map((part) => {
          const inline = part?.inline_data || part?.inlineData;
          if (typeof inline?.data !== "string") return null;
          return {
            imageData: inline.data,
            mimeType: inline?.mime_type || inline?.mimeType || "image/png",
          };
        })
        .filter(Boolean);

      if (inlineImages.length) return inlineImages;

      const simpleCandidates = [
        normalizeImageString(rawData?.imageData, "image/png"),
        normalizeImageString(rawData?.image, "image/png"),
        normalizeImageString(rawData?.data?.[0]?.b64_json, "image/png"),
        normalizeImageString(rawData?.output?.[0]?.b64_json, "image/png"),
        normalizeImageString(
          rawData?.predictions?.[0]?.bytesBase64Encoded,
          "image/png"
        ),
      ].filter(Boolean);

      if (simpleCandidates.length) return simpleCandidates;
      return [];
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

    const upstreamPayload = {
      ...upstreamPayloadBase,
    };

    const candidateUrl = upstreamCandidates[0];

    let lastError = {
      index: 1,
      status: 502,
      message: "Ошибка сервиса",
    };

    try {
      const { requestUrl, headers } = buildLaozhangRequest(candidateUrl);

      const upstreamResponse = await fetch(requestUrl, {
        method: "POST",
        headers,
        body: JSON.stringify(upstreamPayload),
      });

      const raw = await upstreamResponse.json().catch(() => ({}));

      if (!upstreamResponse.ok) {
        lastError = {
          index: 1,
          status: upstreamResponse.status,
          message: normalizeUpstreamErrorMessage(raw?.error || raw),
        };
      } else {
        const extractedImages = extractImagesFromRaw(raw);

        if (!extractedImages.length) {
          lastError = {
            index: 1,
            status: 502,
            message: "Сервис вернул ответ без изображения",
          };
        } else {
          for (const item of extractedImages) {
            generatedImages.push({
              imageData: item.imageData,
              mimeType: item.mimeType,
              raw,
            });
          }
        }
      }
    } catch (error) {
      lastError = {
        index: 1,
        status: 503,
        message: error?.message || "Ошибка сервиса",
      };
    }

    if (!generatedImages.length) {
      generationErrors.push(lastError);
      return res.status(502).json({
        error: "Ошибка генерации, попробуйте еще раз через 10 секунд",
        code: "GENERATION_FAILED_ALL",
        details: generationErrors,
      });
    }

    let nextBalance = null;
    const chargedCount = generatedImages.length;

    if (supabase) {
      nextBalance = Math.max(0, currentBalance - chargedCount);

      const { error: updateError } = await supabase
        .from(SUPABASE_USERS_TABLE)
        .update({
          [versionCfg.balanceColumn]: nextBalance,
          [SUPABASE_VERSION_COLUMN]: versionCfg.versionStorage,
        })
        .eq(SUPABASE_CHAT_ID_COLUMN, req.chatId);

      if (updateError) {
        console.error("balance update error", updateError);
        nextBalance = currentBalance;
      }
    }

    return res.json({
      imageData: generatedImages[0].imageData,
      images: generatedImages.map((item) => ({
        data: item.imageData,
        mimeType: item.mimeType || "image/png",
      })),
      raw: generatedImages[0].raw,
      balance: nextBalance,
      charged: chargedCount,
      requested: requestedCount,
      partial: generatedImages.length < requestedCount,
      failed: Math.max(0, requestedCount - generatedImages.length),
      errors: generationErrors,
      version: versionCfg.versionRuntime,
    });
  } catch (error) {
    console.error("generate error", error);
    return res.status(500).json({ error: "Внутренняя ошибка сервера" });
  }
});

app.listen(PORT, () => {
  console.log(
    `Config: table=${SUPABASE_USERS_TABLE}, chatColumn=${SUPABASE_CHAT_ID_COLUMN}, versionColumn=${SUPABASE_VERSION_COLUMN}, pricesTable=${SUPABASE_PRICES_TABLE}, pricesFreeTable=${SUPABASE_PRICES_FREE_TABLE}, origins=${ALLOWED_ORIGINS.join(
      ","
    )}`
  );

  console.log(
    `Payments: provider=${PAYMENT_PROVIDER_URL}, authMode=${PAYMENT_PROVIDER_AUTH_MODE}, return=${PAYMENT_RETURN_URL}, merchant=${
      PAYMENT_PROVIDER_MERCHANT_ID ? "set" : "missing"
    }, secret=${PAYMENT_PROVIDER_SECRET ? "set" : "missing"}`
  );

  console.log(
    `Prompt filter: model=${OPENROUTER_MODEL}, openrouterKey=${
      OPENROUTER_API_KEY ? "set" : "missing"
    }`
  );

  console.log(`Backend started on port ${PORT}`);
});
