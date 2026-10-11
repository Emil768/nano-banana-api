// ИИ-ассистент (/assistant): чат с моделью через laozhang (OpenAI-compatible, SSE)
// и один инструмент generate_image поверх общего пайплайна генерации.
//
// Юзер видит только процент использования. Внутри — «единицы»:
//   units = tokens_in + tokens_out * ASSISTANT_OUT_WEIGHT
// Все лимиты и цены — в env, см. README.

import { readFile } from "node:fs/promises";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { createImageStore } from "./assistant-images.js";
import { createFileStore } from "./assistant-files.js";

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
  maxTokens: num("ASSISTANT_MAX_TOKENS", 2500), // хватает на подробное описание фото и код
  // gpt-6-luna в Chat Completions умеет tools только при reasoning_effort=none
  reasoningEffort: str("ASSISTANT_REASONING_EFFORT", "none"),
  outWeight: num("ASSISTANT_OUT_WEIGHT", 5),
  unitsPerRequest: num("ASSISTANT_UNITS_PER_REQUEST", 5000), // для «~N запросов»
  trialUnits: num("ASSISTANT_TRIAL_UNITS", 100_000),
  tierDays: num("ASSISTANT_TIER_DAYS", 30),
  // Окно лимита уровня (как у Claude): открывается первым запросом, живёт N часов
  windowHours: num("ASSISTANT_WINDOW_HOURS", 5),
  hardCapUnits: num("ASSISTANT_HARD_CAP_UNITS", 3_000_000),
  dailyBudgetUsd: num("ASSISTANT_DAILY_BUDGET_USD", 1),
  minIntervalMs: num("ASSISTANT_MIN_INTERVAL_MS", 2000),
  maxMessageChars: num("ASSISTANT_MAX_MESSAGE_CHARS", 2000),
  historyMessages: num("ASSISTANT_HISTORY_MESSAGES", 15),
  timeoutMs: num("ASSISTANT_TIMEOUT_MS", 60_000),
  bucket: str("ASSISTANT_IMAGES_BUCKET", "assistant-images"),
  imageTtlDays: num("ASSISTANT_IMAGE_TTL_DAYS", 5), // потом файлы удаляются, текст остаётся
  docMaxChars: num("ASSISTANT_DOC_MAX_CHARS", 20_000), // текста из одного файла в модель
  filesBucket: str("ASSISTANT_FILES_BUCKET", "assistant-files"),
  // Отдавать модели прикреплённые фото картинками (vision). false — только пути текстом.
  vision: str("ASSISTANT_VISION", "true") !== "false",
};

/** Уровни по возрастанию. Лимит — единиц за окно ASSISTANT_WINDOW_HOURS. */
const TIERS = {
  pro: { rank: 1, label: "Профи", windowUnits: num("ASSISTANT_WINDOW_UNITS_PRO", 75_000) },
  mega: { rank: 2, label: "Мега", windowUnits: num("ASSISTANT_WINDOW_UNITS_MEGA", 150_000) },
  ultra: { rank: 3, label: "Ультра", windowUnits: num("ASSISTANT_WINDOW_UNITS_ULTRA", 300_000) },
};

/** Флаг читается на каждом запросе: рубильник без правок кода. */
const enforceLimit = () => str("ASSISTANT_ENFORCE_LIMIT", "true") !== "false";

/** Сколько фото юзер может прикрепить к сообщению (как на обычной генерации). */
const MAX_IMAGES = 4;
/** И сколько документов / файлов с кодом. */
const MAX_FILES = 3;

// assistant_messages.image_url: path в бакете (не ссылка). У сообщений юзера — до 4 path
// через перевод строки. Ссылки наружу — только подписанные, см. assistant-images.js.

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
          reference_images: {
            type: "array",
            items: { type: "string" },
            maxItems: 4,
            description:
              "Пути фото (до 4): из пометки [Юзер прикрепил фото: …] или image_path прошлой генерации, если юзер хочет её доработать",
          },
        },
        required: ["prompt"],
      },
    },
  },
];

/**
 * Технические правила поверх prompts/assistant-system.md — чтобы правка промта
 * не сломала поведение инструмента. Дописываются в конец системного промта.
 */
const TOOL_RULES = `
Правила работы с generate_image (обязательны):
- Ты обычный чат-собеседник. Отвечай на вопросы и болтай как обычно, картинку генерируй только когда юзер явно попросил картинку.
- Если в запросе не хватает деталей (что изображено, стиль, формат) — сначала задай уточняющие вопросы и дождись ответа. Не вызывай generate_image в том же ответе, где задаёшь вопрос.
- Не додумывай запрос за юзера и не генерируй «пример», если он не просил.
- Картинка показывается юзеру автоматически: не вставляй в текст ссылки, пути и markdown-картинки.
- Фото юзера и прошлые генерации передавай в reference_images их путями (из пометки о фото или image_path результата). Если файл удалён по сроку — попроси прислать фото заново.
- Если generate_image вернул ошибку — коротко и по-человечески объясни, что случилось и что делать дальше.`;

/** Объяснение ошибки за модель, если она промолчала после неудачного generate_image. */
function toolFallbackText(output) {
  switch (output?.error) {
    case "insufficient_balance":
      return "Не хватает генераций на балансе, картинку не сделал и ничего не списал. Пополни баланс — и продолжим.";
    case "storage_failed":
      return "Картинка получилась, но не удалось её сохранить. Генерацию вернул на баланс, попробуй ещё раз.";
    case "GENERATION_SAFETY":
    case "TRANSPARENT_SAFETY":
      return "Модерация нейросети не пропустила этот запрос. Генерация не списана — давай переформулируем.";
    default:
      return `Картинка не получилась${
        output?.message ? `: ${output.message}` : ""
      }. Генерация не списана, попробуй ещё раз.`;
  }
}

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
    return `ИИ-ассистент — пробный · ~${approx(CFG.trialUnits)} запросов разово`;
  }
  return `ИИ-ассистент на ${CFG.tierDays} дней · ~${approx(
    TIERS[planTier].windowUnits
  )} запросов каждые ${CFG.windowHours} часов`;
}

/** Ник для приветствия и промта: username из профиля (как у бота), иначе имя. */
const usernameOf = (user) =>
  String(user?.display_name || user?.first_name || user?.username || user?.name || "")
    .trim()
    .replace(/^@+/, "");

const windowMs = () => CFG.windowHours * 60 * 60 * 1000;

/** Активное окно юзера: { start, units } или null, если окна нет / истекло. */
function activeWindow(user, now = Date.now()) {
  const start = Date.parse(user?.assistant_window_start || "");
  if (!Number.isFinite(start) || now >= start + windowMs()) return null;
  return { start, units: Number(user?.assistant_window_units) || 0 };
}

/** Расход за сутки МСК — только для скрытого потолка. */
const dayUnitsOf = (user) =>
  user?.assistant_day_date === mskToday() ? Number(user?.assistant_day_units) || 0 : 0;

/** Что видит фронт: только проценты, без токенов и единиц. */
function computeState(user) {
  const tier = activeTier(user);
  const win = activeWindow(user);
  const limit = tier ? TIERS[tier].windowUnits : CFG.trialUnits;
  const used = tier ? win?.units || 0 : Number(user?.assistant_trial_units_used) || 0;
  const exhausted = used >= limit;
  const hardCapped = dayUnitsOf(user) >= CFG.hardCapUnits;

  let blockReason = null;
  if (hardCapped) blockReason = "hard_cap";
  else if (enforceLimit() && exhausted) blockReason = tier ? "window" : "trial";

  return {
    mode: tier ? "tier" : "trial",
    tier,
    tier_label: tier ? TIERS[tier].label : "Базовый",
    tier_until: tier ? user.assistant_tier_until : null,
    percent: Math.min(100, Math.round((used / Math.max(1, limit)) * 100)),
    // Когда лимит окна снова полный. null — окно не открыто, лимит полный.
    window_resets_at: tier && win ? new Date(win.start + windowMs()).toISOString() : null,
    blocked: Boolean(blockReason),
    block_reason: blockReason,
  };
}

/**
 * Поля user_settings после ответа на units единиц. Окно открывается первым
 * запросом, когда активного нет (startedAt — момент запроса). Пока уровень
 * активен, пробный не тратится.
 */
function usageUpdateFor(user, mode, units, startedAt) {
  const update = {
    assistant_day_units: dayUnitsOf(user) + units,
    assistant_day_date: mskToday(),
  };
  if (mode === "tier") {
    const win = activeWindow(user, startedAt);
    update.assistant_window_start = new Date(win ? win.start : startedAt).toISOString();
    update.assistant_window_units = (win?.units || 0) + units;
  } else {
    update.assistant_trial_units_used = (Number(user?.assistant_trial_units_used) || 0) + units;
  }
  return update;
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
      max_completion_tokens: CFG.maxTokens,
      reasoning_effort: CFG.reasoningEffort,
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
    getPricingPlans,
    mapPlanForFrontend,
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

  const files = supabase
    ? createFileStore({ supabase, bucket: CFG.filesBucket, maxChars: CFG.docMaxChars })
    : null;
  const filePathsOf = (row) =>
    (Array.isArray(row?.files) ? row.files : []).map((f) => f?.path).filter(Boolean);
  const images = supabase
    ? createImageStore({
        supabase,
        bucket: CFG.bucket,
        ttlDays: CFG.imageTtlDays,
        // Документы удаляются в тот же срок; текст в files_text остаётся
        onPurge: (rows) => files.removePaths(rows.flatMap(filePathsOf)),
      })
    : null;
  images?.startPurgeTimer();

  async function logLimitHit(chatId, reason) {
    const { error } = await supabase
      .from("assistant_limit_hits")
      .insert({ user_id: String(chatId), reason });
    if (error) console.error("assistant limit hit log error", error);
  }

  /** {{tariffs}}: пакеты из user_price — цены в промте всегда как на витрине. Кэш 5 минут. */
  const tariffsCache = { text: "", at: 0 };
  async function tariffsText() {
    if (tariffsCache.text && Date.now() - tariffsCache.at < 5 * 60 * 1000) return tariffsCache.text;
    try {
      const plans = (await getPricingPlans()).map(mapPlanForFrontend);
      const lines = plans
        .sort((a, b) => a.price_rub - b.price_rub)
        .map((p) => `- ${p.name} — ${p.price_rub} ₽: ${p.generations} генераций; ${p.assistant_text}.`);
      if (plans.some((p) => p.assistant_tier)) {
        lines.push(
          `Лимит ассистента в пакетах обновляется через ${CFG.windowHours} часов после первого запроса. ` +
            `Повторная покупка продлевает ассистента на ${CFG.tierDays} дней от даты покупки, генерации складываются.`
        );
      }
      lines.push("Переписка с тобой бесплатна в пределах лимита, картинка — 1 генерация.");
      tariffsCache.text = lines.join("\n");
      tariffsCache.at = Date.now();
    } catch (error) {
      console.error("assistant tariffs for prompt error", error);
    }
    return tariffsCache.text || "Цены — в разделе «Тарифы» на сайте: https://nanobananaa.ru/#pricing";
  }

  /**
   * Системный промт: статичная часть (файл до «# Актуальные тарифы» + TOOL_RULES)
   * идёт первой и не меняется между запросами — так работает кэш провайдера.
   * Тарифы ({{tariffs}}) и ник ({{username}}) — в самом конце.
   */
  async function buildSystemPrompt(username) {
    const file = await readFile(SYSTEM_PROMPT_PATH, "utf8");
    const at = file.search(/^# (Актуальные тарифы|Пользователь)/m);
    const head = (at >= 0 ? file.slice(0, at) : file).trim();
    let tail = at >= 0 ? file.slice(at) : "";
    tail = tail
      .split("\n")
      .filter((line) => !/^\(.*\)$/.test(line.trim())) // пометки для разработчика
      .join("\n")
      .replace(/\{\{username\}\}/g, username || "");
    if (tail.includes("{{tariffs}}")) tail = tail.replace(/\{\{tariffs\}\}/g, await tariffsText());
    return [head, TOOL_RULES.trim(), tail.trim()].filter(Boolean).join("\n\n");
  }

  /** История для модели: системный промт + последние N сообщений диалога. */
  async function buildModelMessages(conversationId, username = "") {
    const system = await buildSystemPrompt(username);
    const { data, error } = await supabase
      .from("assistant_messages")
      .select("id, role, content, image_url, tool_name, images_deleted_at, files_text")
      .eq("conversation_id", conversationId)
      .order("created_at", { ascending: false })
      .order("id", { ascending: false })
      .limit(CFG.historyMessages);
    if (error) throw error;

    const rows = (data || []).reverse();
    // Модель видит фото юзера. Последнее сообщение с фото — оригинал в высоком качестве
    // (чтобы подробно описать и разглядеть детали), старые — превью 1024px, detail=low.
    const lastPhotoRowId = [...rows]
      .reverse()
      .find((row) => row.role === "user" && row.image_url && !row.images_deleted_at)?.id;
    const livePhotoPaths = rows
      .filter((row) => row.role === "user" && row.image_url && !row.images_deleted_at)
      .flatMap((row) => images.splitPaths(row.image_url));
    const signed = CFG.vision && livePhotoPaths.length ? await images.signPaths(livePhotoPaths) : new Map();

    const messages = [{ role: "system", content: system }];
    for (const row of rows) {
      if (row.role === "user") {
        // Текст прикреплённых документов — прямо в сообщении (хранится в БД, файлы могут быть уже удалены)
        const body = row.files_text ? `${row.content}\n\n${row.files_text}` : row.content;
        if (!row.image_url) {
          messages.push({ role: "user", content: body });
        } else if (row.images_deleted_at) {
          messages.push({
            role: "user",
            content: `${body}\n\n[Юзер прикреплял фото, но они удалены через ${CFG.imageTtlDays} дней — попроси прислать заново]`,
          });
        } else {
          const paths = images.splitPaths(row.image_url);
          const text = `${body}\n\n[Юзер прикрепил фото: ${paths.join(" , ")}]`;
          const hi = row.id === lastPhotoRowId;
          const parts = paths
            .map((p) => (hi ? signed.get(p)?.url : signed.get(p)?.preview))
            .filter(Boolean)
            .map((url) => ({ type: "image_url", image_url: { url, detail: hi ? "high" : "low" } }));
          messages.push({
            role: "user",
            content: parts.length ? [{ type: "text", text }, ...parts] : text,
          });
        }
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
            !row.image_url
              ? { ok: false }
              : row.images_deleted_at
                ? { ok: true, image_deleted: true }
                : { ok: true, image_path: images.toPath(row.image_url) }
          ),
        });
      }
    }
    return messages;
  }

  const expiresAtOf = (createdAt) =>
    new Date(Date.parse(createdAt || Date.now()) + CFG.imageTtlDays * 24 * 60 * 60 * 1000).toISOString();

  /**
   * Генерация + сохранение в бакет + строка tool в истории. Общая для инструмента
   * модели и кнопки «Сгенерировать снова». Возвращает { ok, image } или { error, message }.
   */
  async function generateAndStore({ chatId, conversationId, prompt, aspect, refPaths = [] }) {
    const user = await getUserByChatId(chatId);
    if (balanceOf(user) < 1) {
      return {
        error: "insufficient_balance",
        balance: balanceOf(user),
        message: "У юзера 0 генераций. Ничего не списано. Предложи пополнить баланс.",
      };
    }

    const reqBody = { prompt, size: ASPECT_TO_SIZE[aspect], aspectRatio: aspect };
    const refs = (await Promise.all(refPaths.map(images.downloadAsJpeg))).filter(Boolean);
    if (refs.length === 1) reqBody.image = refs[0];
    else if (refs.length > 1) reqBody.images = refs;

    const { status, body } = await runImageGeneration(chatId, reqBody);
    if (status !== 200 || !body?.images?.length) {
      const code = status === 402 ? "insufficient_balance" : body?.code || "generation_failed";
      return { error: code, balance: body?.balance, message: body?.error || "Генерация не удалась, ничего не списано" };
    }

    const imagePath = await images.saveImage(chatId, body.images[0].data);
    const signed = imagePath ? (await images.signPaths([imagePath])).get(imagePath) : null;
    if (!signed) {
      // Картинка есть, но сохранить некуда — возвращаем генерацию
      const refunded = await refundBalance(chatId, balanceColumn, body.charged || 1);
      return {
        error: "storage_failed",
        balance: refunded ?? body.balance,
        message: "Не удалось сохранить картинку, генерация возвращена",
      };
    }

    const now = new Date().toISOString();
    const { data: row } = await supabase
      .from("assistant_messages")
      .insert({
        conversation_id: conversationId,
        role: "tool",
        tool_name: "generate_image",
        content: JSON.stringify({ prompt, aspect_ratio: aspect }),
        image_url: imagePath,
        last_viewed_at: now, // показали сразу после генерации
      })
      .select("id, created_at")
      .single();

    return {
      ok: true,
      imagePath,
      balance: body.balance,
      image: {
        id: row?.id ?? null,
        url: signed.url,
        preview_url: signed.preview,
        prompt,
        aspect_ratio: aspect,
        model: imageModelName(body.fallbackTier),
        expires_at: expiresAtOf(row?.created_at || now),
        balance: body.balance,
      },
    };
  }

  /** generate_image от модели: разбор аргументов → generateAndStore → события в стрим. */
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
    // До 4 фото, как на обычной генерации. Только из папки этого юзера.
    const refPaths = [
      ...(Array.isArray(args.reference_images) ? args.reference_images : []),
      ...(Array.isArray(args.reference_image_urls) ? args.reference_image_urls : []),
    ]
      .map(images.toPath)
      .filter((p) => images.ownsPath(chatId, p))
      .slice(0, MAX_IMAGES);

    send("tool_start", { prompt, aspect_ratio: aspect });
    const result = await generateAndStore({ chatId, conversationId, prompt, aspect, refPaths });
    if (!result.ok) {
      send("tool_error", { code: result.error, message: result.message, balance: result.balance });
      return { error: result.error, message: result.message };
    }
    send("image", result.image);
    return { ok: true, image_path: result.imagePath, balance_left: result.balance };
  }

  /** Сообщение-картинка юзера: { row, conv } или null, если чужое. */
  async function ownedToolMessage(chatId, messageId) {
    const { data: row } = await supabase
      .from("assistant_messages")
      .select("id, conversation_id, role, content, image_url")
      .eq("id", messageId)
      .maybeSingle();
    if (!row || row.role !== "tool") return null;
    const { data: conv } = await supabase
      .from("assistant_conversations")
      .select("id")
      .eq("id", row.conversation_id)
      .eq("user_id", chatId)
      .maybeSingle();
    return conv ? { row, conv } : null;
  }

  /* --- «Сгенерировать снова» по сохранённому промту: без модели, −1 генерация --- */
  app.post("/api/assistant/messages/:id/regenerate", requireChatId, needDb, async (req, res) => {
    const chatId = req.chatId;
    if (inFlight.has(chatId)) {
      return res.status(429).json({ error: "Дождись окончания прошлого запроса", code: "BUSY" });
    }
    inFlight.add(chatId);
    try {
      const owned = await ownedToolMessage(chatId, req.params.id);
      if (!owned) return res.status(404).json({ error: "Картинка не найдена" });
      let args = {};
      try {
        args = JSON.parse(owned.row.content || "{}");
      } catch {}
      const prompt = String(args.prompt || "").trim();
      if (!prompt) return res.status(400).json({ error: "У картинки нет промта" });
      const aspect = ASPECT_TO_SIZE[args.aspect_ratio] ? args.aspect_ratio : "1:1";

      const result = await generateAndStore({ chatId, conversationId: owned.conv.id, prompt, aspect });
      if (!result.ok) {
        const status = result.error === "insufficient_balance" ? 402 : 502;
        return res.status(status).json({ error: result.message, code: result.error, balance: result.balance });
      }
      await supabase
        .from("assistant_conversations")
        .update({ updated_at: new Date().toISOString() })
        .eq("id", owned.conv.id);
      return res.json({ image: result.image, balance: result.balance });
    } catch (error) {
      console.error("assistant regenerate error", error);
      return res.status(500).json({ error: "Ошибка сервера" });
    } finally {
      inFlight.delete(chatId);
    }
  });

  /* --- «Попробовать снова» после неудачной генерации: тот же промт напрямую, без модели --- */
  app.post("/api/assistant/generate", requireChatId, needDb, async (req, res) => {
    const chatId = req.chatId;
    const prompt = String(req.body?.prompt || "").trim().slice(0, 4000);
    const aspect = ASPECT_TO_SIZE[req.body?.aspect_ratio] ? req.body.aspect_ratio : "1:1";
    if (!prompt) return res.status(400).json({ error: "Нет промта" });
    if (inFlight.has(chatId)) {
      return res.status(429).json({ error: "Дождись окончания прошлого запроса", code: "BUSY" });
    }
    inFlight.add(chatId);
    try {
      const { data: conv } = await supabase
        .from("assistant_conversations")
        .select("id")
        .eq("id", req.body?.conversation_id)
        .eq("user_id", chatId)
        .maybeSingle();
      if (!conv) return res.status(404).json({ error: "Диалог не найден" });

      const result = await generateAndStore({ chatId, conversationId: conv.id, prompt, aspect });
      if (!result.ok) {
        const status = result.error === "insufficient_balance" ? 402 : 502;
        return res.status(status).json({ error: result.message, code: result.error, balance: result.balance });
      }
      await supabase
        .from("assistant_conversations")
        .update({ updated_at: new Date().toISOString() })
        .eq("id", conv.id);
      return res.json({ image: result.image, balance: result.balance });
    } catch (error) {
      console.error("assistant generate error", error);
      return res.status(500).json({ error: "Ошибка сервера" });
    } finally {
      inFlight.delete(chatId);
    }
  });

  /* --- Статистика: картинку открыли на весь экран или скачали --- */
  app.post("/api/assistant/messages/:id/viewed", requireChatId, needDb, async (req, res) => {
    try {
      const owned = await ownedToolMessage(req.chatId, req.params.id);
      if (!owned) return res.status(404).json({ error: "Не найдено" });
      await supabase
        .from("assistant_messages")
        .update({ last_viewed_at: new Date().toISOString() })
        .eq("id", owned.row.id);
      return res.json({ ok: true });
    } catch (error) {
      console.error("assistant viewed error", error);
      return res.status(500).json({ error: "Ошибка сервера" });
    }
  });

  /* --- Состояние для плашки и шапки --- */
  app.get("/api/assistant/state", requireChatId, needDb, async (req, res) => {
    try {
      const user = await loadUser(req.chatId);
      if (!user) return res.status(401).json({ error: "Пользователь не найден" });
      return res.json({
        state: computeState(user),
        balance: balanceOf(user),
        model_label: CFG.modelLabel,
        username: usernameOf(user), // для приветствия в новом чате
        image_ttl_days: CFG.imageTtlDays,
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

  /* --- Удалить переписку: файлы картинок из бакета + диалог (сообщения уйдут каскадом) --- */
  app.delete("/api/assistant/conversations/:id", requireChatId, needDb, async (req, res) => {
    try {
      const { data: conv, error: convError } = await supabase
        .from("assistant_conversations")
        .select("id")
        .eq("id", req.params.id)
        .eq("user_id", req.chatId)
        .maybeSingle();
      if (convError) throw convError;
      if (!conv) return res.status(404).json({ error: "Диалог не найден" });

      const { data: rows, error } = await supabase
        .from("assistant_messages")
        .select("image_url, files")
        .eq("conversation_id", conv.id)
        .or("image_url.not.is.null,files.not.is.null")
        .is("images_deleted_at", null);
      if (error) throw error;
      await Promise.all([
        images.removePaths((rows || []).flatMap((row) => images.splitPaths(row.image_url))),
        files.removePaths((rows || []).flatMap(filePathsOf)),
      ]);

      const { error: deleteError } = await supabase
        .from("assistant_conversations")
        .delete()
        .eq("id", conv.id);
      if (deleteError) throw deleteError;
      return res.json({ ok: true });
    } catch (error) {
      console.error("assistant delete conversation error", error);
      return res.status(500).json({ error: "Не удалось удалить переписку" });
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
        .select("id, role, content, image_url, images_deleted_at, files, created_at")
        .eq("conversation_id", conv.id)
        .order("created_at", { ascending: true })
        .order("id", { ascending: true });
      if (error) throw error;

      // Подписанные ссылки на все живые картинки диалога — одним запросом
      const rows = data || [];
      const live = (row) => row.image_url && !row.images_deleted_at;
      const signed = await images.signPaths(rows.filter(live).flatMap((row) => images.splitPaths(row.image_url)));

      const messages = rows
        .map((row) => {
          if (row.role === "tool") {
            let args = {};
            try {
              args = JSON.parse(row.content || "{}");
            } catch {}
            if (!row.image_url) return null;
            const link = live(row) ? signed.get(images.toPath(row.image_url)) : null;
            return {
              role: "image",
              id: row.id,
              url: link?.url || null,
              preview_url: link?.preview || null,
              expired: !link, // удалена по сроку (или файла нет) — на фронте заглушка
              expires_at: expiresAtOf(row.created_at),
              prompt: args.prompt || "",
              aspect_ratio: args.aspect_ratio,
            };
          }
          if (row.role === "assistant" && !row.content) return null;
          const paths = row.role === "user" && row.image_url ? images.splitPaths(row.image_url) : [];
          const photos = live(row) ? paths.map((p) => signed.get(p)).filter(Boolean) : [];
          return {
            role: row.role,
            content: row.content,
            images: photos.map((l) => ({ url: l.url, preview_url: l.preview })),
            images_expired: paths.length - photos.length,
            files: (Array.isArray(row.files) ? row.files : []).map((f) => ({
              name: f.name,
              size: f.size,
              kind: f.kind,
              truncated: f.truncated,
            })),
          };
        })
        .filter(Boolean);

      // Статистика возвратов: открыл чат и увидел живые картинки
      const now = new Date().toISOString();
      const shownIds = rows.filter((row) => row.role === "tool" && live(row)).map((row) => row.id);
      void Promise.all([
        supabase.from("assistant_conversations").update({ last_opened_at: now }).eq("id", conv.id),
        shownIds.length
          ? supabase.from("assistant_messages").update({ last_viewed_at: now }).in("id", shownIds)
          : null,
      ]).catch((e) => console.error("assistant opened stats error", e));

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
      const path = await images.saveImage(req.chatId, data);
      if (!path) return res.status(500).json({ error: "Не удалось загрузить фото" });
      // Фронту — path (его шлём в чат) и подписанное превью
      const link = (await images.signPaths([path])).get(path);
      return res.json({ path, preview_url: link?.preview || null });
    } catch (error) {
      console.error("assistant upload route error", error);
      return res.status(500).json({ error: "Ошибка сервера" });
    }
  });

  /* --- Скрепка: документ или файл с кодом → текст для модели --- */
  app.post("/api/assistant/upload-file", requireChatId, needDb, async (req, res) => {
    try {
      const name = String(req.body?.name || "").trim();
      const data = String(req.body?.data || "").replace(/^data:.*?;base64,/i, "");
      if (!name || !data) return res.status(400).json({ error: "Нет файла" });
      if (data.length > 14_000_000) return res.status(413).json({ error: "Файл больше 10 МБ" });
      const result = await files.saveFile(req.chatId, name, Buffer.from(data, "base64"));
      if (!result.ok) return res.status(422).json({ error: result.error });
      return res.json({ file: result.file });
    } catch (error) {
      console.error("assistant upload-file error", error);
      return res.status(500).json({ error: "Ошибка сервера" });
    }
  });

  /* --- Чат: ответ стримом (SSE) --- */
  app.post("/api/assistant/chat", requireChatId, needDb, async (req, res) => {
    const chatId = req.chatId;
    const startedAt = Date.now();
    const message = String(req.body?.message || "").trim();
    const imagePaths = (Array.isArray(req.body?.image_paths) ? req.body.image_paths : [])
      .filter((p) => typeof p === "string" && p)
      .map(images.toPath);
    const filePaths = (Array.isArray(req.body?.file_paths) ? req.body.file_paths : []).filter(
      (p) => typeof p === "string" && p
    );

    if (!message) return res.status(400).json({ error: "Пустое сообщение", code: "EMPTY" });
    if (message.length > CFG.maxMessageChars) {
      return res.status(400).json({
        error: `Сообщение длиннее ${CFG.maxMessageChars} символов`,
        code: "TOO_LONG",
      });
    }
    if (imagePaths.length > MAX_IMAGES) {
      return res.status(400).json({ error: `Не больше ${MAX_IMAGES} фото`, code: "TOO_MANY_IMAGES" });
    }
    if (filePaths.length > MAX_FILES) {
      return res.status(400).json({ error: `Не больше ${MAX_FILES} файлов`, code: "TOO_MANY_FILES" });
    }
    if ([...imagePaths, ...filePaths].some((p) => !images.ownsPath(chatId, p))) {
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
          error: state.mode === "trial" ? "Пробный доступ закончился" : "Лимит исчерпан",
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

      // Документы: текст уже извлечён при загрузке — берём его и пишем в сообщение
      const loaded = (await Promise.all(filePaths.map(files.loadFile))).filter(Boolean);
      const { data: userMsg, error: userMsgError } = await supabase
        .from("assistant_messages")
        .insert({
          conversation_id: conversationId,
          role: "user",
          content: message,
          image_url: imagePaths.length ? imagePaths.join("\n") : null,
          files: loaded.length
            ? loaded.map(({ path, name, size, kind, truncated, chars }) => ({ path, name, size, kind, truncated, chars }))
            : null,
          files_text: loaded.length ? loaded.map(files.blockFor).join("\n\n") : null,
        })
        .select("id")
        .single();
      if (userMsgError) throw userMsgError;

      res.status(200);
      res.setHeader("Content-Type", "text/event-stream; charset=utf-8");
      res.setHeader("Cache-Control", "no-cache, no-transform");
      res.setHeader("Connection", "keep-alive");
      res.setHeader("X-Accel-Buffering", "no");
      res.flushHeaders();
      streamOpen = true;
      send("meta", { conversation_id: conversationId, title });

      // Юзер закрыл вкладку — обрываем запрос к модели. Таймаут — на каждый вызов
      // модели отдельно: генерация картинки между ними может идти минуты.
      const controller = new AbortController();
      res.on("close", () => {
        if (!res.writableFinished) controller.abort();
      });

      const messages = await buildModelMessages(conversationId, usernameOf(user));
      let fullText = "";
      let tokensIn = 0;
      let tokensOut = 0;
      let upstreamFailed = false;
      let imageMade = false;
      let lastToolOutput = null; // результат последнего generate_image
      let textAfterTool = ""; // что модель написала после него

      try {
        // Модель может вызвать инструмент, потом дописать ответ — не больше 3 кругов
        for (let round = 0; round < 3; round++) {
          const result = await streamCompletion({
            apiKey,
            messages,
            signal: AbortSignal.any([controller.signal, AbortSignal.timeout(CFG.timeoutMs)]),
            onText: (chunk) => send("delta", { text: chunk }),
          });

          fullText += result.text;
          textAfterTool += result.text;
          if (result.usage) {
            tokensIn += Number(result.usage.prompt_tokens) || 0;
            tokensOut += Number(result.usage.completion_tokens) || 0;
          } else {
            tokensIn += estimateTokens(messages);
            tokensOut += estimateTokens(result.text + result.toolCalls.map((c) => c.arguments).join(""));
          }

          if (!result.toolCalls.length) break;

          // Модель задала вопрос и тут же полезла генерить — не даём: ждём ответа юзера,
          // иначе спишем генерацию за картинку, которую никто не просил
          if (result.text.includes("?")) {
            console.warn("assistant: tool call with a question in the same turn — skipped");
            break;
          }

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
            if (output?.ok) imageMade = true;
            if (i === 0) {
              lastToolOutput = output;
              textAfterTool = "";
            }
            messages.push({
              role: "tool",
              tool_call_id: call.id || `call_${round}_${i}`,
              content: JSON.stringify(output),
            });
          }
          // Картинка готова — модель второй раз не зовём: карточка говорит сама за себя,
          // токены не тратим. Ошибка — даём модели объяснить юзеру, что случилось.
          if (imageMade) break;

          if (fullText && !fullText.endsWith("\n")) {
            fullText += "\n\n";
            send("delta", { text: "\n\n" });
          }
        }
      } catch (error) {
        upstreamFailed = true;
        console.error("assistant upstream error", {
          name: error?.name,
          message: error?.message,
          status: error?.status,
          preview: error?.preview,
        });
        // Картинка уже в чате — упало только продолжение текста, юзера не пугаем
        if (!imageMade) {
          send("error", {
            code: "UPSTREAM",
            message: "Ассистент сейчас не отвечает. Попробуй ещё раз через минуту.",
          });
        }
      }

      // После генерации всегда должен быть ответ текстом. Модель не дописала
      // (оборвалась, пусто, кончились круги) — пишем сами по результату инструмента.
      if (lastToolOutput && !lastToolOutput.ok && !textAfterTool.trim()) {
        const fallback = toolFallbackText(lastToolOutput);
        const glue = fullText && !fullText.endsWith("\n") ? "\n\n" : "";
        fullText += glue + fallback;
        send("delta", { text: glue + fallback });
      }

      // Ответа нет совсем — убираем вопрос юзера из истории, чтобы модель
      // потом не «доделывала» его в следующем сообщении
      if (upstreamFailed && !fullText.trim() && !imageMade && userMsg?.id) {
        await supabase.from("assistant_messages").delete().eq("id", userMsg.id);
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
      const usageUpdate = units > 0 ? usageUpdateFor(fresh, state.mode, units, startedAt) : {};
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
export { streamCompletion as _streamCompletion, computeState as _computeState, usageUpdateFor as _usageUpdateFor };
