import crypto from "node:crypto";
import dotenv from "dotenv";
import express from "express";
import cors from "cors";
import cookieParser from "cookie-parser";
import { createClient } from "@supabase/supabase-js";

dotenv.config();

const app = express();
const PORT = Number(process.env.PORT || 3000);

const FRONTEND_ORIGIN = process.env.FRONTEND_ORIGIN || "https://nanobananaa.ru";
const FRONTEND_SUCCESS_REDIRECT =
  process.env.FRONTEND_SUCCESS_REDIRECT || `${FRONTEND_ORIGIN}/generate.html`;
const FRONTEND_ERROR_REDIRECT =
  process.env.FRONTEND_ERROR_REDIRECT ||
  `${FRONTEND_ORIGIN}/generate.html?auth_error=1`;

const TELEGRAM_BOT_TOKEN = process.env.TELEGRAM_BOT_TOKEN || "";
const TELEGRAM_WIDGET_MAX_AGE_SECONDS = Number(
  process.env.TELEGRAM_WIDGET_MAX_AGE_SECONDS || 300
);

const COOKIE_DOMAIN = process.env.COOKIE_DOMAIN || undefined;
const COOKIE_SECURE = String(process.env.COOKIE_SECURE || "true") === "true";
const COOKIE_SAMESITE = process.env.COOKIE_SAMESITE || "Lax";
const COOKIE_MAX_AGE_SECONDS = Number(
  process.env.COOKIE_MAX_AGE_SECONDS || 2592000
);

const SUPABASE_URL = process.env.SUPABASE_URL || "";
const SUPABASE_SERVICE_ROLE_KEY = process.env.SUPABASE_SERVICE_ROLE_KEY || "";
const SUPABASE_USERS_TABLE = process.env.SUPABASE_USERS_TABLE || "users";
const SUPABASE_CHAT_ID_COLUMN =
  process.env.SUPABASE_CHAT_ID_COLUMN || "chat_id";
const SUPABASE_BALANCE_COLUMN =
  process.env.SUPABASE_BALANCE_COLUMN || "balance";
const SUPABASE_SOURCE_COLUMN = process.env.SUPABASE_SOURCE_COLUMN || "";
const AUTO_CREATE_USER =
  String(process.env.AUTO_CREATE_USER || "true") === "true";

const LAOZHANG_URL =
  process.env.LAOZHANG_URL ||
  "https://api.laozhang.ai/v1beta/models/gemini-3-pro-image-preview:generateContent";
const LAOZHANG_API_KEY = process.env.LAOZHANG_API_KEY || "";
const LAOZHANG_AUTH_MODE = (
  process.env.LAOZHANG_AUTH_MODE || "bearer"
).toLowerCase();

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
app.use(
  cors({
    origin: FRONTEND_ORIGIN,
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

function setChatCookies(res, chatId) {
  const common = {
    secure: COOKIE_SECURE,
    sameSite: COOKIE_SAMESITE,
    domain: COOKIE_DOMAIN,
    maxAge: COOKIE_MAX_AGE_SECONDS * 1000,
    path: "/",
  };

  // This cookie is readable by frontend to keep current flow working.
  res.cookie("chatid", String(chatId), { ...common, httpOnly: false });
  // Session marker cookie for backend checks.
  res.cookie("tg_session", "1", { ...common, httpOnly: true });
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

function requireChatId(req, res, next) {
  const chatId = req.cookies?.chatid;
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

    setChatCookies(res, chatId);
    return res.redirect(FRONTEND_SUCCESS_REDIRECT);
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

    const reqHeaders = { "Content-Type": "application/json" };
    let upstreamUrl = LAOZHANG_URL;
    if (LAOZHANG_AUTH_MODE === "query") {
      const glue = upstreamUrl.includes("?") ? "&" : "?";
      upstreamUrl = `${upstreamUrl}${glue}key=${encodeURIComponent(
        LAOZHANG_API_KEY
      )}`;
    } else {
      reqHeaders.Authorization = `Bearer ${LAOZHANG_API_KEY}`;
    }

    const upstreamResponse = await fetch(upstreamUrl, {
      method: "POST",
      headers: reqHeaders,
      body: JSON.stringify(req.body),
    });

    const raw = await upstreamResponse.json().catch(() => ({}));
    if (!upstreamResponse.ok) {
      return res.status(upstreamResponse.status).json({
        error: raw?.error?.message || raw?.error || "Ошибка апстрима",
        details: raw,
      });
    }

    const parts =
      raw?.candidates?.[0]?.content?.parts ||
      raw?.data?.candidates?.[0]?.content?.parts ||
      [];
    const imagePart = parts.find(
      (part) => part?.inline_data?.data || part?.inlineData?.data
    );
    const imageData =
      imagePart?.inline_data?.data || imagePart?.inlineData?.data || null;

    if (!imageData) {
      return res.status(502).json({
        error: "Апстрим не вернул изображение",
        details: raw,
      });
    }

    return res.json({ imageData, raw });
  } catch (error) {
    console.error("generate error", error);
    return res.status(500).json({ error: "Внутренняя ошибка сервера" });
  }
});

app.listen(PORT, () => {
  console.log(`Backend started on port ${PORT}`);
});
