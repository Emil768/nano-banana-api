// «Промт по фото»: POST /api/describe-image — vision-модель описывает картинку
// и возвращает промт на английском и русском. Бесплатно и без дневного лимита
// для вошедших; от скриптов — невидимый потолок запросов в минуту (в памяти).
//
// Картинку не храним: она живёт только в памяти на время запроса, в логи
// base64 не пишем. Ключ laozhang — тот же, что для генерации, только на бэке.

const SYSTEM_PROMPT = `You are an expert prompt writer for AI image models (GPT Image, Nano Banana / Gemini, Midjourney, Flux).
You receive one image. Write a detailed, ready-to-use prompt that lets a model reproduce the result as closely as possible.
Be specific and concrete: exact colors, materials, textures, positions (left/right/foreground/background), sizes, counts. No vague words like "beautiful" or "nice".

FORMAT: several short paragraphs separated by an empty line ("\\n\\n" inside the JSON string). Each paragraph covers one aspect.
Do not use headings, labels, bullet points or markdown — just the paragraphs of the prompt itself.

Describe the whole image so a model can generate a very similar picture from scratch. 150–250 words, paragraphs in this order:
1) Main subject(s): who or what, approximate age, build, face and hair, expression, clothing with colors, fabrics and details, accessories.
2) Action and pose: what they are doing, body position, gaze direction, hands.
3) Setting and background: location, objects around, what is in the foreground and background, weather or time of day.
4) Composition and camera: shot type (close-up, medium, wide), camera angle and height, framing and placement in the frame, lens feel (e.g. 35mm, 85mm), depth of field, aspect ratio (portrait, square, landscape).
5) Lighting: light sources, direction, hardness or softness, color temperature, shadows and highlights.
6) Color palette, mood and style: main colors, contrast, atmosphere, and the medium (photo, film photo, 3D render, digital illustration, anime, oil painting, etc.), plus quality cues (sharp focus, natural skin texture, realistic details).

Rules:
- Never name real people, celebrities or characters; describe them generically ("a young man with short dark hair").
- Never mention brand names or logos; describe objects generically.
- If the image has prominent text, include it in double quotes as it appears.
- Do not start with "The image shows" or "This is". Write the prompt itself, in imperative/descriptive form.
- The Russian version must be a natural, equally detailed translation with the same paragraphs.
- If the image contains nudity, sexual content, a minor in any suggestive context, graphic violence or gore,
  return exactly {"error":"unsafe"} and nothing else.

Return ONLY valid JSON, no markdown:
{"prompt_en": "<prompt in English, paragraphs separated by \\n\\n>", "prompt_ru": "<the same prompt in natural Russian, same paragraphs>", "tags_ru": ["3-5 short Russian tags: subject, style, light, mood"]}`;

const ALLOWED_MIME = new Set(["image/jpeg", "image/png", "image/webp"]);
const MAX_IMAGE_BYTES = 2 * 1024 * 1024; // после сжатия на фронте (1024 px, JPEG 0.85)
const MODEL_TIMEOUT_MS = 30_000;

/** data:image/...;base64,... → { mime, base64, bytes } или null */
function parseDataUrl(value) {
  const m = /^data:([^;,]+);base64,([A-Za-z0-9+/=\s]+)$/i.exec(String(value || ""));
  if (!m) return null;
  const mime = m[1].toLowerCase();
  const base64 = m[2].replace(/\s/g, "");
  const bytes = Math.floor((base64.length * 3) / 4) - (base64.endsWith("==") ? 2 : base64.endsWith("=") ? 1 : 0);
  return { mime, base64, bytes };
}

/** JSON из ответа модели: целиком или от первой { до последней } (если обёрнут в текст/markdown). */
function extractJson(text) {
  const raw = String(text || "").trim();
  try {
    return JSON.parse(raw);
  } catch {
    const a = raw.indexOf("{");
    const b = raw.lastIndexOf("}");
    if (a === -1 || b <= a) return null;
    try {
      return JSON.parse(raw.slice(a, b + 1));
    } catch {
      return null;
    }
  }
}

/** Проверяем форму ответа; unsafe — отдельным флагом. */
function normalizeResult(json) {
  if (!json || typeof json !== "object") return null;
  if (json.error === "unsafe") return { unsafe: true };
  const prompt_en = String(json.prompt_en || "").trim();
  const prompt_ru = String(json.prompt_ru || "").trim();
  if (!prompt_en || !prompt_ru) return null;
  const tags_ru = (Array.isArray(json.tags_ru) ? json.tags_ru : [])
    .map((t) => String(t || "").trim())
    .filter(Boolean)
    .slice(0, 5);
  return { prompt_en, prompt_ru, tags_ru };
}

export function registerDescribeRoutes(app, deps) {
  const {
    requireChatId,
    buildLaozhangRequest,
    apiKey,
    apiHost, // хост laozhang из LAOZHANG_URL, например api.laozhang.ai
    normalizeEnv,
  } = deps;

  // Защита от скриптов: живой человек столько не нажмёт. Env DESCRIBE_PER_MINUTE.
  const PER_MINUTE = Math.max(1, Number(process.env.DESCRIBE_PER_MINUTE || 10));
  const VISION_MODEL = normalizeEnv(process.env.VISION_MODEL, "gemini-3-flash-preview");
  const VISION_MODEL_FALLBACK = normalizeEnv(process.env.VISION_MODEL_FALLBACK, "gpt-4.1-mini");
  // Gemini через laozhang можно звать нативным API (inline_data), если image_url
  // в chat/completions для него не заработает. По умолчанию — OpenAI-формат.
  const GEMINI_NATIVE = String(process.env.VISION_GEMINI_NATIVE || "false") === "true";

  const chatUrl = apiHost ? `https://${apiHost}/v1/chat/completions` : "";

  /* ---------- Потолок запросов в минуту (в памяти, без базы) ---------- */

  /** @type {Map<string, number[]>} chatId → время последних запросов */
  const recentByChatId = new Map();

  function tooManyRequests(chatId) {
    const now = Date.now();
    const recent = (recentByChatId.get(chatId) || []).filter((t) => now - t < 60_000);
    if (recent.length >= PER_MINUTE) {
      recentByChatId.set(chatId, recent);
      return true;
    }
    recent.push(now);
    recentByChatId.set(chatId, recent);
    return false;
  }

  // Раз в 10 минут выкидываем тех, кто давно не заходил, чтобы Map не рос
  setInterval(() => {
    const now = Date.now();
    for (const [chatId, times] of recentByChatId) {
      if (!times.some((t) => now - t < 60_000)) recentByChatId.delete(chatId);
    }
  }, 10 * 60_000).unref();

  /* ---------- Запрос к модели ---------- */

  async function fetchWithTimeout(url, init) {
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), MODEL_TIMEOUT_MS);
    try {
      return await fetch(url, { ...init, signal: controller.signal });
    } finally {
      clearTimeout(timer);
    }
  }

  /** OpenAI-совместимый chat/completions; картинка — image_url с data URL. */
  async function callChat(model, image, temperature, jsonMode) {
    const body = {
      model,
      temperature,
      messages: [
        { role: "system", content: SYSTEM_PROMPT },
        {
          role: "user",
          content: [
            { type: "text", text: "Write the prompt for this image." },
            { type: "image_url", image_url: { url: `data:${image.mime};base64,${image.base64}` } },
          ],
        },
      ],
    };
    if (jsonMode) body.response_format = { type: "json_object" };

    const { requestUrl, headers } = buildLaozhangRequest(chatUrl, { apiKey });
    const res = await fetchWithTimeout(requestUrl, {
      method: "POST",
      headers,
      body: JSON.stringify(body),
    });
    const raw = await res.json().catch(() => ({}));
    if (!res.ok) {
      const err = new Error(String(raw?.error?.message || `HTTP ${res.status}`));
      err.status = res.status;
      err.code = raw?.error?.code;
      throw err;
    }
    return String(raw?.choices?.[0]?.message?.content || "");
  }

  /** Нативный Gemini generateContent с inline_data (если VISION_GEMINI_NATIVE=true). */
  async function callGeminiNative(model, image, temperature) {
    const url = `https://${apiHost}/v1beta/models/${encodeURIComponent(model)}:generateContent`;
    const body = {
      systemInstruction: { parts: [{ text: SYSTEM_PROMPT }] },
      contents: [
        {
          role: "user",
          parts: [
            { text: "Write the prompt for this image." },
            { inline_data: { mime_type: image.mime, data: image.base64 } },
          ],
        },
      ],
      generationConfig: { temperature, responseMimeType: "application/json" },
    };
    const { requestUrl, headers } = buildLaozhangRequest(url, { apiKey });
    const res = await fetchWithTimeout(requestUrl, {
      method: "POST",
      headers,
      body: JSON.stringify(body),
    });
    const raw = await res.json().catch(() => ({}));
    if (!res.ok) {
      const err = new Error(String(raw?.error?.message || `HTTP ${res.status}`));
      err.status = res.status;
      throw err;
    }
    return (raw?.candidates?.[0]?.content?.parts || [])
      .map((p) => p?.text || "")
      .join("");
  }

  /**
   * Одна модель: запрос → JSON. Если модель отвергла response_format — повтор без него.
   * Невалидный JSON — ещё одна попытка, потом ошибка.
   */
  async function describeWithModel(model, image, temperature) {
    const native = GEMINI_NATIVE && /^gemini/i.test(model);
    let jsonMode = !native;

    for (let attempt = 0; attempt < 2; attempt++) {
      let text;
      try {
        text = native
          ? await callGeminiNative(model, image, temperature)
          : await callChat(model, image, temperature, jsonMode);
      } catch (error) {
        if (jsonMode && error.status === 400 && /response_format|json/i.test(error.message)) {
          jsonMode = false;
          attempt -= 1; // это не попытка, а смена формата
          continue;
        }
        throw error;
      }
      const result = normalizeResult(extractJson(text));
      if (result) return result;
      console.warn("describe-image: invalid JSON from model", { model, attempt: attempt + 1 });
    }
    const err = new Error("invalid JSON");
    err.status = 502;
    throw err;
  }

  /** Основная модель, при сбое — одна попытка на запасной. */
  async function describe(image, temperature) {
    try {
      return { ...(await describeWithModel(VISION_MODEL, image, temperature)), model: VISION_MODEL };
    } catch (error) {
      console.warn("describe-image: primary model failed", {
        model: VISION_MODEL,
        status: error.status,
        message: String(error.message).slice(0, 200),
      });
      if (!VISION_MODEL_FALLBACK || VISION_MODEL_FALLBACK === VISION_MODEL) throw error;
      return {
        ...(await describeWithModel(VISION_MODEL_FALLBACK, image, temperature)),
        model: VISION_MODEL_FALLBACK,
      };
    }
  }

  /* ---------- Роуты ---------- */

  app.post("/api/describe-image", requireChatId, async (req, res) => {
    if (!chatUrl || !apiKey) {
      return res.status(500).json({ error: "not_configured" });
    }

    const temperature = req.body?.variant === true ? 0.9 : 0.4;

    const image = parseDataUrl(req.body?.image);
    if (!image || !ALLOWED_MIME.has(image.mime)) {
      return res.status(400).json({ error: "bad_image" });
    }
    if (image.bytes > MAX_IMAGE_BYTES) {
      return res.status(413).json({ error: "too_large" });
    }

    if (tooManyRequests(String(req.chatId))) {
      return res.status(429).json({ error: "too_many" });
    }

    let result;
    try {
      result = await describe(image, temperature);
    } catch (error) {
      console.error("describe-image: model failed", {
        status: error.status,
        message: String(error.message).slice(0, 200),
      });
      return res.status(502).json({ error: "model" });
    }

    if (result.unsafe) {
      return res.status(422).json({ error: "unsafe" });
    }

    return res.json({
      prompt_en: result.prompt_en,
      prompt_ru: result.prompt_ru,
      tags_ru: result.tags_ru,
    });
  });
}
