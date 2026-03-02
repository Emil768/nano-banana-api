import crypto from "node:crypto";
import dotenv from "dotenv";
import express from "express";
import cors from "cors";
import cookieParser from "cookie-parser";
import { createClient } from "@supabase/supabase-js";

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

const normalizeLaozhangEndpoint = (value, fallback) => {
  const raw = normalizeEnv(value, fallback);
  return raw.replace("/v1/beta/", "/v1beta/");
};

const LAOZHANG_URL =
  normalizeLaozhangEndpoint(
    process.env.LAOZHANG_URL,
    "https://api.laozhang.ai/v1beta/models/gemini-3-pro-image-preview:generateContent"
  ) ||
  "https://api.laozhang.ai/v1beta/models/gemini-3-pro-image-preview:generateContent";
const LAOZHANG_URL_FREE =
  normalizeLaozhangEndpoint(
    process.env.LAOZHANG_URL_FREE,
    "https://api.laozhang.ai/v1beta/models/gemini-2.5-flash-image:generateContent"
  ) ||
  "https://api.laozhang.ai/v1beta/models/gemini-2.5-flash-image:generateContent";
const LAOZHANG_API_KEY = normalizeEnv(process.env.LAOZHANG_API_KEY);
const LAOZHANG_AUTH_MODE = normalizeEnv(
  process.env.LAOZHANG_AUTH_MODE,
  "bearer"
).toLowerCase();
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
  if (!TELEGRAM_BOT_TOKEN)
    return { valid: false, reason: "bot token not configured" };
  if (!query.hash) return { valid: false, reason: "no hash" };

  const expectedHash = signTelegramDataCheck(query, TELEGRAM_BOT_TOKEN);
  if (expectedHash !== query.hash)
    return { valid: false, reason: "hash mismatch" };

  const authDate = Number(query.auth_date || 0);
  if (!authDate) return { valid: false, reason: "no auth_date" };

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
    // Chrome rejects SameSite=None cookies without Secure on local http.
    sameSite: isLocalHost ? "Lax" : COOKIE_SAMESITE,
    domain: COOKIE_DOMAIN,
    maxAge: COOKIE_MAX_AGE_SECONDS * 1000,
    path: "/",
  };

  // This cookie is readable by frontend to keep current flow working.
  res.cookie("chatid", String(chatId), { ...common, httpOnly: false });
  // Session marker cookie for backend checks.
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

function verifySessionToken(tokenValue) {
  if (!AUTH_SESSION_SECRET || !tokenValue) return null;
  const token = String(tokenValue || "").trim();
  const [chatIdRaw, expRaw, sigRaw] = token.split(".");
  if (!chatIdRaw || !expRaw || !sigRaw) return null;
  const exp = Number(expRaw);
  if (!Number.isFinite(exp) || exp < Math.floor(Date.now() / 1000)) return null;
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

function parseWebhookPayload(payloadValue) {
  const parts = String(payloadValue || "").split("-");
  const chatIdRaw = parts[0];
  const paymentIdRaw = parts[parts.length - 1];
  const chatId = Number(chatIdRaw);
  const paymentId = Number(paymentIdRaw);
  if (!Number.isFinite(chatId) || !Number.isFinite(paymentId)) {
    return null;
  }
  return {
    chatId: String(chatId),
    paymentId,
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
      upstreamUrl: LAOZHANG_URL_FREE,
    };
  }
  return {
    versionRuntime: "pro",
    versionStorage: "PRO",
    balanceColumn: SUPABASE_BALANCE_COLUMN,
    pricesTable: SUPABASE_PRICES_TABLE,
    upstreamUrl: LAOZHANG_URL,
  };
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
  if (chatIdFromCookie) {
    return String(chatIdFromCookie);
  }

  const authHeader = String(req.headers.authorization || "");
  const token = authHeader.startsWith("Bearer ")
    ? authHeader.slice(7).trim()
    : "";
  const chatIdFromToken = verifySessionToken(token);
  if (chatIdFromToken) {
    return String(chatIdFromToken);
  }

  if (allowQuerySession) {
    const queryToken = String(req.query?.session || "").trim();
    const chatIdFromQueryToken = verifySessionToken(queryToken);
    if (chatIdFromQueryToken) {
      return String(chatIdFromQueryToken);
    }
  }

  return "";
}

function requireChatId(req, res, next) {
  const chatId = resolveChatIdFromRequest(req);
  if (!chatId) {
    return res
      .status(401)
      .json({ error: "Не авторизован. Войди через Telegram." });
  }
  req.chatId = String(chatId);
  next();
}

app.get("/health", (_req, res) => {
  res.json({ ok: true });
});

app.get("/api/events", (req, res) => {
  const chatId = resolveChatIdFromRequest(req, { allowQuerySession: true });
  if (!chatId) {
    return res
      .status(401)
      .json({ error: "Не авторизован. Войди через Telegram." });
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
    if (!active.size) {
      sseClientsByChatId.delete(chatId);
    }
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
    if (!user) {
      user = await createUserIfMissing(chatId);
    }

    setChatCookies(req, res, chatId);
    return res.redirect(buildSuccessRedirectUrl(chatId));
  } catch (error) {
    console.error("telegram callback error", error);
    return res.redirect(`${FRONTEND_ERROR_REDIRECT}&reason=server_error`);
  }
});

app.get("/auth/me", requireChatId, async (req, res) => {
  try {
    let user = await getUserByChatId(req.chatId);
    if (!user) {
      user = await createUserIfMissing(req.chatId);
      if (!user) {
        return res
          .status(401)
          .json({ authenticated: false, error: "Пользователь не найден" });
      }
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
    const { chatId, paymentId } = parsed;

    const isPending = status === "pending";
    if (isPending) {
      emitSseEvent(chatId, "payment_pending", {
        type: "payment_pending",
        status,
        payment_id: paymentId,
      });
      return res.json({ ok: true, pending: true, status });
    }

    const isFailure = ["canceled", "chargebacked"].includes(status);
    if (isFailure) {
      emitSseEvent(chatId, "payment_failed", {
        type: "payment_failed",
        status,
        payment_id: paymentId,
      });
      return res.json({ ok: true, ignored: true, status });
    }

    const isSuccess = status === "confirmed";
    if (!isSuccess) {
      emitSseEvent(chatId, "payment_failed", {
        type: "payment_failed",
        status: status || "unknown",
        payment_id: paymentId,
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
    const plan = await getPricingPlanById(paymentId, versionCfg.pricesTable);
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
      payment_id: paymentId,
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
    if (!user) {
      user = await createUserIfMissing(req.chatId);
      if (!user) {
        return res
          .status(401)
          .json({ error: "Пользователь не найден в Supabase" });
      }
    }

    const requestedVersion = normalizeVersionRuntime(
      req.body?.version || user?.[SUPABASE_VERSION_COLUMN]
    );
    const versionCfg = resolveVersionConfig(requestedVersion);
    const requestedCount = Math.max(
      1,
      Math.min(4, Number.parseInt(req.body?.numberOfImages ?? 1, 10) || 1)
    );
    const rawBalance = Number(user?.[versionCfg.balanceColumn]);
    const currentBalance = Number.isFinite(rawBalance) ? rawBalance : 0;
    if (currentBalance < requestedCount) {
      return res.status(402).json({
        error: "Недостаточно генераций. Пополните баланс.",
        code: "INSUFFICIENT_BALANCE",
        balance: currentBalance,
        required: requestedCount,
      });
    }

    const reqHeaders = { "Content-Type": "application/json" };
    let upstreamUrl = versionCfg.upstreamUrl;
    if (LAOZHANG_AUTH_MODE === "query") {
      const glue = upstreamUrl.includes("?") ? "&" : "?";
      upstreamUrl = `${upstreamUrl}${glue}key=${encodeURIComponent(
        LAOZHANG_API_KEY
      )}`;
    } else {
      reqHeaders.Authorization = `Bearer ${LAOZHANG_API_KEY}`;
    }

    const upstreamPayloadBase = { ...req.body };
    delete upstreamPayloadBase.version;
    delete upstreamPayloadBase.numberOfImages;
    const extractImageFromRaw = (rawData) => {
      const parts =
        rawData?.candidates?.[0]?.content?.parts ||
        rawData?.data?.candidates?.[0]?.content?.parts ||
        [];
      const imagePart = parts.find((part) => {
        const inline = part?.inline_data || part?.inlineData;
        return typeof inline?.data === "string";
      });
      if (!imagePart) return null;
      const inline = imagePart?.inline_data || imagePart?.inlineData;
      return {
        imageData: inline?.data || null,
        mimeType: inline?.mime_type || inline?.mimeType || "image/png",
      };
    };

    const generatedImages = [];
    const generationErrors = [];
    const MAX_UPSTREAM_ATTEMPTS = 3;
    const RETRY_DELAY_MS = 1200;
    const sleep = (ms) => new Promise((resolve) => setTimeout(resolve, ms));
    const normalizeUpstreamErrorMessage = (rawError) => {
      if (typeof rawError === "string" && rawError.trim()) return rawError;
      if (rawError?.message) return String(rawError.message);
      if (rawError?.localized_message) return String(rawError.localized_message);
      if (rawError?.type) return String(rawError.type);
      return "Ошибка сервиса";
    };

    for (let i = 0; i < requestedCount; i += 1) {
      const upstreamPayload = {
        ...upstreamPayloadBase,
        numberOfImages: 1,
      };
      let generatedItem = null;
      let lastError = {
        index: i + 1,
        status: 502,
        message: "Ошибка сервиса",
      };

      for (let attempt = 1; attempt <= MAX_UPSTREAM_ATTEMPTS; attempt += 1) {
        try {
          const upstreamResponse = await fetch(upstreamUrl, {
            method: "POST",
            headers: reqHeaders,
            body: JSON.stringify(upstreamPayload),
          });
          const raw = await upstreamResponse.json().catch(() => ({}));
          if (!upstreamResponse.ok) {
            lastError = {
              index: i + 1,
              status: upstreamResponse.status,
              message: normalizeUpstreamErrorMessage(raw?.error || raw),
            };
            if (attempt < MAX_UPSTREAM_ATTEMPTS) {
              await sleep(RETRY_DELAY_MS);
              continue;
            }
            break;
          }

          const extracted = extractImageFromRaw(raw);
          if (!extracted?.imageData) {
            lastError = {
              index: i + 1,
              status: 502,
              message: "Ошибка сервиса",
            };
            if (attempt < MAX_UPSTREAM_ATTEMPTS) {
              await sleep(RETRY_DELAY_MS);
              continue;
            }
            break;
          }

          generatedItem = {
            imageData: extracted.imageData,
            mimeType: extracted.mimeType,
            raw,
          };
          break;
        } catch (error) {
          lastError = {
            index: i + 1,
            status: 503,
            message: error?.message || "Ошибка сервиса",
          };
          if (attempt < MAX_UPSTREAM_ATTEMPTS) {
            await sleep(RETRY_DELAY_MS);
          }
        }
      }

      if (generatedItem) {
        generatedImages.push(generatedItem);
      } else {
        generationErrors.push(lastError);
      }
    }

    if (!generatedImages.length) {
      return res.status(502).json({
        error: "Ошибка генерации, попробуйте еще раз через 10 секунд",
        code: "GENERATION_FAILED_ALL",
        details: generationErrors,
      });
    }

    let nextBalance = null;
    if (supabase) {
      nextBalance = Math.max(0, currentBalance - generatedImages.length);
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
      charged: generatedImages.length,
      requested: requestedCount,
      partial: generatedImages.length < requestedCount,
      failed: requestedCount - generatedImages.length,
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
  console.log(`Backend started on port ${PORT}`);
});
