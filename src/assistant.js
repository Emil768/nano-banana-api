// ИИ-ассистент (/assistant): чат с моделью через laozhang (OpenAI-compatible, SSE)
// и один инструмент generate_image поверх общего пайплайна генерации.
//
// Юзер видит только процент использования. Внутри — «единицы»:
//   units = tokens_in + tokens_out * ASSISTANT_OUT_WEIGHT
// Все лимиты и цены — в env, см. README.

import { readFile } from "node:fs/promises";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const SYSTEM_PROMPT_PATH = join(
  dirname(fileURLToPath(import.meta.url)),
  "../prompts/assistant-system.md"
);

const num = (name, fallback) => {
  const raw = Number(String(process.env[name] ?? "").replace(/^['"]|['"]$/g, ""));
  return Number.isFinite(raw) && String(process.env[name] ?? "").trim() !== ""
    ? raw
    : fallback;
};
const str = (name, fallback) =>
  String(process.env[name] ?? "").trim().replace(/^['"]|['"]$/g, "") || fallback;

const CFG = {
  model: str("ASSISTANT_MODEL", "gpt-6-luna"),
  modelLabel: str("ASSISTANT_MODEL_LABEL", "GPT-6 Luna"),
  apiUrl: str("ASSISTANT_API_URL", "https://api.laozhang.ai/v1/chat/completions"),
  priceIn: num("ASSISTANT_PRICE_IN", 0.1), // $ за 1M входных токенов
  priceOut: num("ASSISTANT_PRICE_OUT", 0.5), // $ за 1M выходных
  maxTokens: num("ASSISTANT_MAX_TOKENS", 800),
  outWeight: num("ASSISTANT_OUT_WEIGHT", 5),
  unitsPerRequest: num("ASSISTANT_UNITS_PER_REQUEST", 5000), // для «~N запросов»
  trialUnits: num("ASSISTANT_TRIAL_UNITS", 100_000),
  tierDays: num("ASSISTANT_TIER_DAYS", 30),
  hardCapUnits: num("ASSISTANT_HARD_CAP_UNITS", 3_000_000),
  dailyBudgetUsd: num("ASSISTANT_DAILY_BUDGET_USD", 1),
  minIntervalMs: num("ASSISTANT_MIN_INTERVAL_MS", 2000),
  maxMessageChars: num("ASSISTANT_MAX_MESSAGE_CHARS", 2000),
  historyMessages: num("ASSISTANT_HISTORY_MESSAGES", 15),
  timeoutMs: num("ASSISTANT_TIMEOUT_MS", 60_000),
  bucket: str("ASSISTANT_IMAGES_BUCKET", "assistant-images"),
};

/** Уровни по возрастанию. Дневной лимит — в единицах. */
const TIERS = {
  pro: { rank: 1, label: "Профи", dailyUnits: num("ASSISTANT_DAILY_UNITS_PRO", 200_000) },
  mega: { rank: 2, label: "Мега", dailyUnits: num("ASSISTANT_DAILY_UNITS_MEGA", 400_000) },
  ultra: { rank: 3, label: "Ультра", dailyUnits: num("ASSISTANT_DAILY_UNITS_ULTRA", 800_000) },
};

/** Флаг читается на каждом запросе: рубильник без правок кода. */
const enforceLimit = () => str("ASSISTANT_ENFORCE_LIMIT", "true") !== "false";

const ASPECT_TO_SIZE = {
  "1:1": "1024x1024",
  "3:4": "1024x1536",
  "9:16": "1024x1536",
  "4:3": "1536x1024",
  "16:9": "1536x1024",
};

const TOOLS = [
  {
    type: "function",
    function: {
      name: "generate_image",
      description:
        "Сгенерировать изображение по готовому промту. Вызывать только когда запрос юзера понятен и уточнять больше нечего. Стоит юзеру 1 генерацию.",
      parameters: {
        type: "object",
        properties: {
          prompt: { type: "string", description: "Детальный промт на английском" },
          aspect_ratio: { type: "string", enum: Object.keys(ASPECT_TO_SIZE) },
          reference_image_url: {
            type: "string",
            description: "URL фото юзера, если он его прикрепил",
          },
        },
        required: ["prompt"],
      },
    },
  },
];

/* ---------- Время по Москве ---------- */

const mskToday = (date = new Date()) =>
  date.toLocaleDateString("en-CA", { timeZone: "Europe/Moscow" }); // YYYY-MM-DD

const mskDayStartIso = () => `${mskToday()}T00:00:00+03:00`;

/* ---------- Уровни и лимиты ---------- */

function activeTier(user, now = Date.now()) {
  const tier = user?.assistant_tier;
  const until = Date.parse(user?.assistant_tier_until || "");
  return TIERS[tier] && Number.isFinite(until) && until > now ? tier : null;
}

/**
 * Поля для update user_settings при оплате пакета. Уровень не понижаем:
 * Профи поверх активной Меги оставляет Мегу, но продлевает на 30 дней.
 */
export function assistantTierGrant(user, planTier) {
  if (!TIERS[planTier]) return {};
  const current = activeTier(user);
  const tier =
    current && TIERS[current].rank > TIERS[planTier].rank ? current : planTier;
  return {
    assistant_tier: tier,
    assistant_tier_until: new Date(
      Date.now() + CFG.tierDays * 24 * 60 * 60 * 1000
    ).toISOString(),
  };
}

/** Строка про ассистента для карточки пакета. */
export function assistantPlanText(planTier) {
  const approx = (units) => Math.round(units / CFG.unitsPerRequest);
  if (!TIERS[planTier]) {
    return `ИИ-ассистент: пробный доступ (~${approx(CFG.trialUnits)} запросов разово)`;
  }
  return `ИИ-ассистент на ${CFG.tierDays} дней: ~${approx(
    TIERS[planTier].dailyUnits
  )} запросов в день`;
}

/** Что видит фронт: только проценты, без токенов и единиц. */
function computeState(user) {
  const today = mskToday();
  const usedToday =
    user?.assistant_usage_date === today ? Number(user?.assistant_usage_units) || 0 : 0;
  const tier = activeTier(user);
  const limit = tier ? TIERS[tier].dailyUnits : CFG.trialUnits;
  const used = tier ? usedToday : Number(user?.assistant_trial_units_used) || 0;
  const exhausted = used >= limit;
  const hardCapped = usedToday >= CFG.hardCapUnits;

  let blockReason = null;
  if (hardCapped) blockReason = "hard_cap";
  else if (enforceLimit() && exhausted) blockReason = tier ? "daily" : "trial";

  return {
    mode: tier ? "tier" : "trial",
    tier,
    tier_label: tier ? TIERS[tier].label : "Базовый",
    tier_until: tier ? user.assistant_tier_until : null,
    percent: Math.min(100, Math.round((used / Math.max(1, limit)) * 100)),
    blocked: Boolean(blockReason),
    block_reason: blockReason,
    resets_at: tier ? "00:00 МСК" : null,
  };
}

/* ---------- Дневной бюджет в $ на всех ---------- */

const budget = { day: "", spent: 0, checkedAt: 0 };

async function spentTodayUsd(supabase) {
  const day = mskToday();
  if (budget.day === day && Date.now() - budget.checkedAt < 30_000) {
    return budget.spent;
  }
  const { data, error } = await supabase
    .from("assistant_messages")
    .select("cost_usd")
    .gte("created_at", mskDayStartIso())
    .gt("cost_usd", 0);
  if (error) throw error;
  budget.day = day;
  budget.spent = (data || []).reduce((sum, row) => sum + Number(row.cost_usd || 0), 0);
  budget.checkedAt = Date.now();
  return budget.spent;
}

/* ---------- Модель ---------- */

/**
 * Один вызов модели со стримом. onText — каждый кусок текста.
 * Возвращает { text, toolCalls, usage, finishReason }.
 */
async function streamCompletion({ apiKey, messages, signal, onText }) {
  const response = await fetch(CFG.apiUrl, {
    method: "POST",
    signal,
    headers: {
      "Content-Type": "application/json",
      Authorization: `Bearer ${apiKey}`,
    },
    body: JSON.stringify({
      model: CFG.model,
      messages,
      tools: TOOLS,
      max_tokens: CFG.maxTokens,
      stream: true,
      stream_options: { include_usage: true },
    }),
  });

  if (!response.ok || !response.body) {
    const preview = await response.text().catch(() => "");
    const err = new Error(`assistant upstream ${response.status}`);
    err.status = response.status;
    err.preview = preview.slice(0, 600);
    throw err;
  }

  const decoder = new TextDecoder();
  const reader = response.body.getReader();
  let buffer = "";
  let text = "";
  let usage = null;
  let finishReason = null;
  /** @type {{ id: string, name: string, arguments: string }[]} */
  const toolCalls = [];

  const handleLine = (line) => {
    const trimmed = line.trim();
    if (!trimmed.startsWith("data:")) return;
    const data = trimmed.slice(5).trim();
    if (!data || data === "[DONE]") return;
    let chunk;
    try {
      chunk = JSON.parse(data);
    } catch {
      return;
    }
    if (chunk.usage) usage = chunk.usage;
    const choice = chunk.choices?.[0];
    if (!choice) return;
    if (choice.finish_reason) finishReason = choice.finish_reason;
    const delta = choice.delta || {};
    if (typeof delta.content === "string" && delta.content) {
      text += delta.content;
      onText(delta.content);
    }
    for (const call of delta.tool_calls || []) {
      const i = Number.isInteger(call.index) ? call.index : toolCalls.length;
      toolCalls[i] ||= { id: "", name: "", arguments: "" };
      if (call.id) toolCalls[i].id = call.id;
      if (call.function?.name) toolCalls[i].name += call.function.name;
      if (call.function?.arguments) toolCalls[i].arguments += call.function.arguments;
    }
  };

  for (;;) {
    const { value, done } = await reader.read();
    if (done) break;
    buffer += decoder.decode(value, { stream: true });
    const lines = buffer.split("\n");
    buffer = lines.pop() ?? "";
    lines.forEach(handleLine);
  }
  if (buffer) handleLine(buffer);

  return { text, toolCalls: toolCalls.filter(Boolean), usage, finishReason };
}

/** Если провайдер не прислал usage в стриме — грубая оценка по символам. */
const estimateTokens = (value) =>
  Math.ceil(String(typeof value === "string" ? value : JSON.stringify(value)).length / 3);

/* ---------- Роуты ---------- */

/**
 * deps — то, что уже есть в server.js: supabase, auth, юзер, пайплайн генерации.
 */
export function registerAssistantRoutes(app, deps) {
  const {
    supabase,
    requireChatId,
    apiKey,
    usersTable,
    idColumn,
    balanceColumn,
    getUserByChatId,
    createUserIfMissing,
    autoCreateUser,
    runImageGeneration,
    refundBalance,
    imageModelName,
  } = deps;

  const needDb = (_req, res, next) =>
    supabase ? next() : res.status(500).json({ error: "Supabase не настроен" });

  const lastRequestAt = new Map(); // chatId → ms
  const inFlight = new Set(); // chatId, пока идёт ответ

  const loadUser = async (chatId) => {
    let user = await getUserByChatId(chatId);
    if (!user && autoCreateUser) user = await createUserIfMissing(chatId);
    return user;
  };

  const balanceOf = (user) => {
    const raw = Number(user?.[balanceColumn]);
    return Number.isFinite(raw) ? raw : 0;
  };

  const publicPrefix = () =>
    supabase.storage.from(CFG.bucket).getPublicUrl("x").data.publicUrl.replace(/x$/, "");

  async function uploadImage(chatId, base64, mimeType) {
    const clean = String(base64 || "").replace(/^data:.*?;base64,/i, "");
    const buffer = Buffer.from(clean, "base64");
    const ext = /png/i.test(mimeType) ? "png" : /webp/i.test(mimeType) ? "webp" : "jpg";
    const path = `${encodeURIComponent(chatId)}/${Date.now()}-${Math.random()
      .toString(36)
      .slice(2, 8)}.${ext}`;
    const upload = () =>
      supabase.storage
        .from(CFG.bucket)
        .upload(path, buffer, { contentType: mimeType || "image/png", upsert: false });

    let { error } = await upload();
    // Бакета ещё нет — создаём публичный и пробуем снова (как у видео)
    if (error && /bucket not found/i.test(String(error.message))) {
      const created = await supabase.storage.createBucket(CFG.bucket, { public: true });
      if (created.error) {
        console.error("assistant createBucket error", created.error);
        return null;
      }
      ({ error } = await upload());
    }
    if (error) {
      console.error("assistant upload error", error);
      return null;
    }
    return supabase.storage.from(CFG.bucket).getPublicUrl(path).data.publicUrl;
  }

  /** Фото юзера берём только из своего бакета — никаких чужих URL на сервере. */
  async function downloadReference(url) {
    if (typeof url !== "string" || !url.startsWith(publicPrefix())) return null;
    const r = await fetch(url);
    if (!r.ok) return null;
    const mimeType = r.headers.get("content-type") || "image/jpeg";
    const data = Buffer.from(await r.arrayBuffer()).toString("base64");
    return { data, mimeType };
  }

  async function logLimitHit(chatId, reason) {
    const { error } = await supabase
      .from("assistant_limit_hits")
      .insert({ user_id: String(chatId), reason });
    if (error) console.error("assistant limit hit log error", error);
  }

  /** История для модели: системный промт + последние N сообщений диалога. */
  async function buildModelMessages(conversationId) {
    const system = await readFile(SYSTEM_PROMPT_PATH, "utf8");
    const { data, error } = await supabase
      .from("assistant_messages")
      .select("id, role, content, image_url, tool_name")
      .eq("conversation_id", conversationId)
      .order("created_at", { ascending: false })
      .order("id", { ascending: false })
      .limit(CFG.historyMessages);
    if (error) throw error;

    const messages = [{ role: "system", content: system }];
    for (const row of (data || []).reverse()) {
      if (row.role === "user") {
        messages.push({
          role: "user",
          content: row.image_url
            ? `${row.content}\n\n[Юзер прикрепил фото: ${row.image_url}]`
            : row.content,
        });
      } else if (row.role === "assistant") {
        if (row.content) messages.push({ role: "assistant", content: row.content });
      } else if (row.role === "tool") {
        // Восстанавливаем пару «вызов инструмента → результат»
        const callId = `call_${row.id}`;
        messages.push({
          role: "assistant",
          content: null,
          tool_calls: [
            {
              id: callId,
              type: "function",
              function: { name: row.tool_name || "generate_image", arguments: row.content || "{}" },
            },
          ],
        });
        messages.push({
          role: "tool",
          tool_call_id: callId,
          content: JSON.stringify(
            row.image_url ? { ok: true, image_url: row.image_url } : { ok: false }
          ),
        });
      }
    }
    return messages;
  }

  /** generate_image: баланс → пайплайн → картинка в бакет. */
  async function runGenerateImageTool({ chatId, conversationId, rawArgs, send }) {
    let args = {};
    try {
      args = JSON.parse(rawArgs || "{}");
    } catch {
      return { error: "invalid_arguments" };
    }
    const prompt = String(args.prompt || "").trim();
    if (!prompt) return { error: "empty_prompt" };
    const aspect = ASPECT_TO_SIZE[args.aspect_ratio] ? args.aspect_ratio : "1:1";

    const user = await getUserByChatId(chatId);
    if (balanceOf(user) < 1) {
      send("tool_error", { code: "insufficient_balance", balance: balanceOf(user) });
      return {
        error: "insufficient_balance",
        message: "У юзера 0 генераций. Ничего не списано. Предложи пополнить баланс.",
      };
    }

    send("tool_start", { prompt, aspect_ratio: aspect });

    const reqBody = { prompt, size: ASPECT_TO_SIZE[aspect], aspectRatio: aspect };
    if (args.reference_image_url) {
      const ref = await downloadReference(args.reference_image_url);
      if (ref) reqBody.image = ref;
    }

    const { status, body } = await runImageGeneration(chatId, reqBody);
    if (status !== 200 || !body?.images?.length) {
      const code = status === 402 ? "insufficient_balance" : body?.code || "generation_failed";
      send("tool_error", { code, message: body?.error, balance: body?.balance });
      return { error: code, message: body?.error || "Генерация не удалась, ничего не списано" };
    }

    const first = body.images[0];
    const imageUrl = await uploadImage(chatId, first.data, first.mimeType);
    if (!imageUrl) {
      // Картинка есть, но сохранить некуда — возвращаем генерацию
      const refunded = await refundBalance(chatId, balanceColumn, body.charged || 1);
      send("tool_error", { code: "storage_failed", balance: refunded ?? body.balance });
      return { error: "storage_failed", message: "Не удалось сохранить картинку, генерация возвращена" };
    }

    const model = imageModelName(body.fallbackTier);
    await supabase.from("assistant_messages").insert({
      conversation_id: conversationId,
      role: "tool",
      tool_name: "generate_image",
      content: JSON.stringify({ prompt, aspect_ratio: aspect }),
      image_url: imageUrl,
    });

    send("image", { url: imageUrl, prompt, aspect_ratio: aspect, model, balance: body.balance });
    return { ok: true, image_url: imageUrl, balance_left: body.balance };
  }

  /* --- Состояние для плашки и шапки --- */
  app.get("/api/assistant/state", requireChatId, needDb, async (req, res) => {
    try {
      const user = await loadUser(req.chatId);
      if (!user) return res.status(401).json({ error: "Пользователь не найден" });
      return res.json({
        state: computeState(user),
        balance: balanceOf(user),
        model_label: CFG.modelLabel,
      });
    } catch (error) {
      console.error("assistant state error", error);
      return res.status(500).json({ error: "Ошибка сервера" });
    }
  });

  /* --- Список диалогов --- */
  app.get("/api/assistant/conversations", requireChatId, needDb, async (req, res) => {
    try {
      const { data, error } = await supabase
        .from("assistant_conversations")
        .select("id, title, updated_at")
        .eq("user_id", req.chatId)
        .order("updated_at", { ascending: false })
        .limit(50);
      if (error) throw error;
      return res.json({ conversations: data || [] });
    } catch (error) {
      console.error("assistant conversations error", error);
      return res.status(500).json({ error: "Ошибка сервера" });
    }
  });

  /* --- Сообщения диалога --- */
  app.get("/api/assistant/conversations/:id/messages", requireChatId, needDb, async (req, res) => {
    try {
      const { data: conv, error: convError } = await supabase
        .from("assistant_conversations")
        .select("id, title")
        .eq("id", req.params.id)
        .eq("user_id", req.chatId)
        .maybeSingle();
      if (convError) throw convError;
      if (!conv) return res.status(404).json({ error: "Диалог не найден" });

      const { data, error } = await supabase
        .from("assistant_messages")
        .select("id, role, content, image_url, created_at")
        .eq("conversation_id", conv.id)
        .order("created_at", { ascending: true })
        .order("id", { ascending: true });
      if (error) throw error;

      const messages = (data || [])
        .map((row) => {
          if (row.role === "tool") {
            let args = {};
            try {
              args = JSON.parse(row.content || "{}");
            } catch {}
            return row.image_url
              ? { role: "image", url: row.image_url, prompt: args.prompt || "", aspect_ratio: args.aspect_ratio }
              : null;
          }
          if (row.role === "assistant" && !row.content) return null;
          return { role: row.role, content: row.content, image_url: row.image_url };
        })
        .filter(Boolean);

      return res.json({ conversation: conv, messages });
    } catch (error) {
      console.error("assistant messages error", error);
      return res.status(500).json({ error: "Ошибка сервера" });
    }
  });

  /* --- Скрепка: фото юзера в бакет --- */
  app.post("/api/assistant/upload", requireChatId, needDb, async (req, res) => {
    try {
      const mimeType = String(req.body?.mimeType || "");
      const data = String(req.body?.data || "");
      if (!/^image\/(png|jpe?g|webp)$/i.test(mimeType) || !data) {
        return res.status(400).json({ error: "Нужна картинка PNG, JPG или WEBP" });
      }
      if (data.length > 14_000_000) {
        return res.status(413).json({ error: "Фото больше 10 МБ" });
      }
      const url = await uploadImage(req.chatId, data, mimeType);
      if (!url) return res.status(500).json({ error: "Не удалось загрузить фото" });
      return res.json({ url });
    } catch (error) {
      console.error("assistant upload route error", error);
      return res.status(500).json({ error: "Ошибка сервера" });
    }
  });

  /* --- Чат: ответ стримом (SSE) --- */
  app.post("/api/assistant/chat", requireChatId, needDb, async (req, res) => {
    const chatId = req.chatId;
    const message = String(req.body?.message || "").trim();
    const imageUrl = typeof req.body?.image_url === "string" ? req.body.image_url : null;

    if (!message) return res.status(400).json({ error: "Пустое сообщение", code: "EMPTY" });
    if (message.length > CFG.maxMessageChars) {
      return res.status(400).json({
        error: `Сообщение длиннее ${CFG.maxMessageChars} символов`,
        code: "TOO_LONG",
      });
    }
    if (imageUrl && !imageUrl.startsWith(publicPrefix())) {
      return res.status(400).json({ error: "Фото не найдено", code: "BAD_IMAGE" });
    }
    if (!apiKey) return res.status(500).json({ error: "LAOZHANG_API_KEY не настроен" });

    if (inFlight.has(chatId)) {
      return res.status(429).json({ error: "Дождись ответа на прошлое сообщение", code: "BUSY" });
    }
    const last = lastRequestAt.get(chatId) || 0;
    if (Date.now() - last < CFG.minIntervalMs) {
      return res.status(429).json({ error: "Слишком часто, подожди пару секунд", code: "RATE_LIMIT" });
    }
    lastRequestAt.set(chatId, Date.now());
    inFlight.add(chatId);

    let streamOpen = false;
    const send = (event, data) => {
      if (!streamOpen || res.writableEnded) return;
      res.write(`event: ${event}\ndata: ${JSON.stringify(data)}\n\n`);
    };

    try {
      if ((await spentTodayUsd(supabase)) >= CFG.dailyBudgetUsd) {
        return res.status(503).json({
          error: "Ассистент временно недоступен. Генерация на сайте и в боте работает.",
          code: "ASSISTANT_UNAVAILABLE",
        });
      }

      const user = await loadUser(chatId);
      if (!user) return res.status(401).json({ error: "Пользователь не найден" });

      const state = computeState(user);
      if (state.blocked) {
        void logLimitHit(chatId, state.block_reason);
        return res.status(403).json({
          error: state.mode === "trial" ? "Пробный доступ закончился" : "Лимит на сегодня исчерпан",
          code: "LIMIT_REACHED",
          state,
        });
      }

      // Диалог: свой или новый
      let conversationId = Number(req.body?.conversation_id) || null;
      let title = null;
      if (conversationId) {
        const { data: conv, error } = await supabase
          .from("assistant_conversations")
          .select("id, title")
          .eq("id", conversationId)
          .eq("user_id", chatId)
          .maybeSingle();
        if (error) throw error;
        if (!conv) return res.status(404).json({ error: "Диалог не найден" });
        title = conv.title;
      } else {
        title = message.slice(0, 40);
        const { data: conv, error } = await supabase
          .from("assistant_conversations")
          .insert({ user_id: chatId, title })
          .select("id")
          .single();
        if (error) throw error;
        conversationId = conv.id;
      }

      const { error: userMsgError } = await supabase.from("assistant_messages").insert({
        conversation_id: conversationId,
        role: "user",
        content: message,
        image_url: imageUrl,
      });
      if (userMsgError) throw userMsgError;

      res.status(200);
      res.setHeader("Content-Type", "text/event-stream; charset=utf-8");
      res.setHeader("Cache-Control", "no-cache, no-transform");
      res.setHeader("Connection", "keep-alive");
      res.setHeader("X-Accel-Buffering", "no");
      res.flushHeaders();
      streamOpen = true;
      send("meta", { conversation_id: conversationId, title });

      const controller = new AbortController();
      const timeout = setTimeout(() => controller.abort(), CFG.timeoutMs);
      res.on("close", () => {
        if (!res.writableFinished) controller.abort();
      });

      const messages = await buildModelMessages(conversationId);
      let fullText = "";
      let tokensIn = 0;
      let tokensOut = 0;
      let upstreamFailed = false;

      try {
        // Модель может вызвать инструмент, потом дописать ответ — не больше 3 кругов
        for (let round = 0; round < 3; round++) {
          const result = await streamCompletion({
            apiKey,
            messages,
            signal: controller.signal,
            onText: (chunk) => send("delta", { text: chunk }),
          });

          fullText += result.text;
          if (result.usage) {
            tokensIn += Number(result.usage.prompt_tokens) || 0;
            tokensOut += Number(result.usage.completion_tokens) || 0;
          } else {
            tokensIn += estimateTokens(messages);
            tokensOut += estimateTokens(result.text + result.toolCalls.map((c) => c.arguments).join(""));
          }

          if (!result.toolCalls.length) break;

          messages.push({
            role: "assistant",
            content: result.text || null,
            tool_calls: result.toolCalls.map((call, i) => ({
              id: call.id || `call_${round}_${i}`,
              type: "function",
              function: { name: call.name, arguments: call.arguments },
            })),
          });

          // Одна картинка за ход: лишние вызовы отклоняем
          for (const [i, call] of result.toolCalls.entries()) {
            const output =
              i === 0 && call.name === "generate_image"
                ? await runGenerateImageTool({ chatId, conversationId, rawArgs: call.arguments, send })
                : { error: "one_image_per_turn" };
            messages.push({
              role: "tool",
              tool_call_id: call.id || `call_${round}_${i}`,
              content: JSON.stringify(output),
            });
          }
          if (fullText && !fullText.endsWith("\n")) {
            fullText += "\n\n";
            send("delta", { text: "\n\n" });
          }
        }
      } catch (error) {
        upstreamFailed = true;
        if (error?.name !== "AbortError") {
          console.error("assistant upstream error", {
            message: error?.message,
            status: error?.status,
            preview: error?.preview,
          });
        }
        send("error", {
          code: "UPSTREAM",
          message: "Ассистент сейчас не отвечает. Попробуй ещё раз через минуту.",
        });
      } finally {
        clearTimeout(timeout);
      }

      // Учёт: единицы и стоимость, даже если ответ оборвался
      const units = tokensIn + tokensOut * CFG.outWeight;
      const costUsd = (tokensIn * CFG.priceIn) / 1e6 + (tokensOut * CFG.priceOut) / 1e6;

      if (units > 0 || fullText) {
        await supabase.from("assistant_messages").insert({
          conversation_id: conversationId,
          role: "assistant",
          content: fullText.trim(),
          tokens_in: tokensIn,
          tokens_out: tokensOut,
          units,
          cost_usd: Number(costUsd.toFixed(6)),
        });
        if (budget.day === mskToday()) budget.spent += costUsd;
      }

      // Перечитываем юзера: баланс мог измениться после генерации
      const fresh = (await getUserByChatId(chatId)) || user;
      const today = mskToday();
      const usageToday =
        fresh.assistant_usage_date === today ? Number(fresh.assistant_usage_units) || 0 : 0;
      const usageUpdate = {
        assistant_usage_units: usageToday + units,
        assistant_usage_date: today,
      };
      // Пока уровень активен, пробный не тратится
      if (state.mode === "trial") {
        usageUpdate.assistant_trial_units_used =
          (Number(fresh.assistant_trial_units_used) || 0) + units;
      }
      if (units > 0) {
        const { error } = await supabase
          .from(usersTable)
          .update(usageUpdate)
          .eq(idColumn, chatId);
        if (error) console.error("assistant usage update error", error);
      }
      await supabase
        .from("assistant_conversations")
        .update({ updated_at: new Date().toISOString() })
        .eq("id", conversationId);

      const nextState = computeState({ ...fresh, ...usageUpdate });
      if (nextState.blocked && !state.blocked) void logLimitHit(chatId, nextState.block_reason);

      send("done", {
        conversation_id: conversationId,
        title,
        state: nextState,
        balance: balanceOf(fresh),
        failed: upstreamFailed,
      });
      res.end();
    } catch (error) {
      console.error("assistant chat error", error);
      if (streamOpen) {
        send("error", { code: "SERVER", message: "Внутренняя ошибка, попробуй ещё раз" });
        res.end();
      } else if (!res.headersSent) {
        res.status(500).json({ error: "Внутренняя ошибка сервера" });
      }
    } finally {
      inFlight.delete(chatId);
    }
  });
}

// Для локальных проверок без сети
export { streamCompletion as _streamCompletion, computeState as _computeState };
