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
const ALLOWED_ORIGINS = normalizeEnv(process.env.ALLOWED_ORIGINS, FRONTEND_ORIGIN)
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
const SUPABASE_PRICES_TABLE = normalizeEnv(process.env.SUPABASE_PRICES_TABLE, "user_price");
const SUPABASE_PRICES_FREE_TABLE = normalizeEnv(
  process.env.SUPABASE_PRICES_FREE_TABLE,
  "user_price_free"
);
const SUPABASE_PRICE_ID_COLUMN = normalizeEnv(process.env.SUPABASE_PRICE_ID_COLUMN, "id");
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
const SUPABASE_VERSION_COLUMN = normalizeEnv(process.env.SUPABASE_VERSION_COLUMN, "version");
const AUTO_CREATE_USER =
  String(process.env.AUTO_CREATE_USER || "true") === "true";

const LAOZHANG_URL =
  normalizeEnv(process.env.LAOZHANG_URL) ||
  "https://api.laozhang.ai/v1beta/models/gemini-3-pro-image-preview:generateContent";
const LAOZHANG_URL_FREE =
  normalizeEnv(process.env.LAOZHANG_URL_FREE) ||
  "https://api.laozhang.ai/v1beta/models/gemini-2.5-flash-image:generateContent";
const LAOZHANG_API_KEY = normalizeEnv(process.env.LAOZHANG_API_KEY);
const LAOZHANG_AUTH_MODE = (
  normalizeEnv(process.env.LAOZHANG_AUTH_MODE, "bearer")
).toLowerCase();
const PAYMENT_PROVIDER_URL =
  normalizeEnv(process.env.PAYMENT_PROVIDER_URL) ||
  "https://app.platega.io/transaction/process";
const PAYMENT_PROVIDER_API_KEY = normalizeEnv(process.env.PAYMENT_PROVIDER_API_KEY);
const PAYMENT_PROVIDER_MERCHANT_ID = normalizeEnv(process.env.PAYMENT_PROVIDER_MERCHANT_ID);
const PAYMENT_PROVIDER_SECRET = normalizeEnv(process.env.PAYMENT_PROVIDER_SECRET);
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
  normalizeEnv(process.env.PAYMENT_RETURN_URL) || `${FRONTEND_ORIGIN}/generate.html`;
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
  const isLocalHost = req.hostname === "127.0.0.1" || req.hostname === "localhost";
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
  const exp = Math.floor(Date.now() / 1000) + Math.max(COOKIE_MAX_AGE_SECONDS, 3600);
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
    return `${FRONTEND_SUCCESS_REDIRECT}${glue}session=${encodeURIComponent(token)}`;
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

async function createUserIfMissing(chatId, source = "telegram_widget") {
  if (!supabase) return null;
  const insertPayload = {
    [SUPABASE_CHAT_ID_COLUMN]: String(chatId),
    [SUPABASE_VERSION_COLUMN]: "PRO",
  };
  if (SUPABASE_SOURCE_COLUMN) {
    insertPayload[SUPABASE_SOURCE_COLUMN] = source;
  }
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
  const [chatIdRaw, maybeVersionRaw, maybePaymentIdRaw] = String(payloadValue || "").split("-");
  const hasVersion =
    String(maybeVersionRaw || "").toLowerCase() === "free" ||
    String(maybeVersionRaw || "").toLowerCase() === "pro";
  const version = hasVersion ? normalizeVersionRuntime(maybeVersionRaw) : "pro";
  const paymentIdRaw = hasVersion ? maybePaymentIdRaw : maybeVersionRaw;
  const chatId = Number(chatIdRaw);
  const paymentId = Number(paymentIdRaw);
  if (!Number.isFinite(chatId) || !Number.isFinite(paymentId)) {
    return null;
  }
  return {
    chatId: String(chatId),
    version,
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
    providerHeaders[PAYMENT_PROVIDER_MERCHANT_HEADER] = PAYMENT_PROVIDER_MERCHANT_ID;
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

function requireChatId(req, res, next) {
  const chatIdFromCookie = req.cookies?.chatid;
  if (chatIdFromCookie) {
    req.chatId = String(chatIdFromCookie);
    next();
    return;
  }

  const authHeader = String(req.headers.authorization || "");
  const token = authHeader.startsWith("Bearer ") ? authHeader.slice(7).trim() : "";
  const chatIdFromToken = verifySessionToken(token);
  const chatId = chatIdFromToken || "";
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

    if (!user && !AUTO_CREATE_USER) {
      return res.redirect(`${FRONTEND_ERROR_REDIRECT}&reason=user_not_found`);
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
    const user = await getUserByChatId(req.chatId);
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
        SUPABASE_BALANCE_FREE_COLUMN in user ? user[SUPABASE_BALANCE_FREE_COLUMN] : null,
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
      return res.status(400).json({ error: "Некорректное количество генераций" });
    }
    if (!Number.isFinite(amount) || amount <= 0) {
      return res.status(400).json({ error: "Некорректная сумма тарифа" });
    }

    const payload = `${req.chatId}-${versionCfg.versionRuntime}-${plan[SUPABASE_PRICE_ID_COLUMN]}`;
    const providerRequestBody = {
      paymentMethod: PAYMENT_METHOD,
      description: `Оплата ${generations} генераций (${versionCfg.versionRuntime.toUpperCase()}) для юзера ${req.chatId}`,
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

    return res.json({ ok: true, paymentUrl, raw, version: versionCfg.versionRuntime });
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
    const isSuccess =
      !status ||
      ["success", "succeeded", "paid", "completed", "ok"].includes(status);
    if (!isSuccess) {
      return res.json({ ok: true, ignored: true, status });
    }

    const payloadValue =
      body?.payload ||
      body?.data?.payload ||
      body?.object?.payload ||
      body?.transaction?.payload;
    const parsed = parseWebhookPayload(payloadValue);
    if (!parsed) {
      return res.status(400).json({ error: "invalid payload format" });
    }

    const { chatId, version, paymentId } = parsed;
    const versionCfg = resolveVersionConfig(version);
    const plan = await getPricingPlanById(paymentId, versionCfg.pricesTable);
    if (!plan) {
      return res.status(404).json({ error: "pricing plan not found" });
    }

    const user = await getUserByChatId(chatId);
    if (!user) {
      return res.status(404).json({ error: "user not found" });
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

    const user = await getUserByChatId(req.chatId);
    if (!user) {
      return res
        .status(401)
        .json({ error: "Пользователь не найден в Supabase" });
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
      const imagePart = parts.find(
        (part) => part?.inline_data?.data || part?.inlineData?.data
      );
      return imagePart?.inline_data?.data || imagePart?.inlineData?.data || null;
    };

    const generatedImages = [];
    const generationErrors = [];
    for (let i = 0; i < requestedCount; i += 1) {
      const upstreamPayload = {
        ...upstreamPayloadBase,
        numberOfImages: 1,
      };
      const upstreamResponse = await fetch(upstreamUrl, {
        method: "POST",
        headers: reqHeaders,
        body: JSON.stringify(upstreamPayload),
      });
      const raw = await upstreamResponse.json().catch(() => ({}));
      if (!upstreamResponse.ok) {
        generationErrors.push({
          index: i + 1,
          status: upstreamResponse.status,
          message: raw?.error?.message || raw?.error || "Ошибка апстрима",
        });
        continue;
      }

      const imageData = extractImageFromRaw(raw);
      if (!imageData) {
        generationErrors.push({
          index: i + 1,
          status: 502,
          message: "Апстрим не вернул изображение",
        });
        continue;
      }
      generatedImages.push({ imageData, raw });
    }

    if (!generatedImages.length) {
      return res.status(502).json({
        error: "Не удалось сгенерировать изображения",
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
      images: generatedImages.map((item) => item.imageData),
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
