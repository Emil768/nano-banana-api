// Документы и файлы с кодом для ИИ-ассистента.
//
// Модель сама файлы не читает: бэк достаёт из них текст и кладёт в сообщение
// юзера блоком «[Файл: имя]». Оригинал и извлечённый текст (рядом, .json) лежат
// в приватном бакете assistant-files; через ASSISTANT_IMAGE_TTL_DAYS дней файлы
// удаляются вместе с картинками (текст остаётся в assistant_messages.files_text).

import { randomUUID } from "node:crypto";
import { extractText, getDocumentProxy } from "unpdf";
import mammoth from "mammoth";
import ExcelJS from "exceljs";

export const MAX_FILE_BYTES = 10 * 1024 * 1024;
const MAX_SHEET_ROWS = 300; // таблица: первые N строк каждого листа

// Всё, что читается как обычный текст: код, конфиги, разметка, данные
const TEXT_EXT = new Set(
  (
    "txt md markdown csv tsv json jsonl xml yml yaml toml ini cfg conf log env sql " +
    "js mjs cjs jsx ts tsx vue svelte html htm css scss sass less " +
    "py rb php java kt kts swift go rs c h cpp hpp cc cs m mm scala dart lua pl r " +
    "sh bash zsh ps1 bat dockerfile makefile gradle graphql proto tex srt vtt"
  ).split(" ")
);

const extOf = (name) => {
  const base = String(name || "").toLowerCase().split("/").pop();
  if (base === "dockerfile" || base === "makefile") return base;
  const i = base.lastIndexOf(".");
  return i >= 0 ? base.slice(i + 1) : "";
};

/** pdf | docx | xlsx | text | null (не поддерживается) */
export function fileKind(name) {
  const ext = extOf(name);
  if (ext === "pdf") return "pdf";
  if (ext === "docx") return "docx";
  if (ext === "xlsx") return "xlsx";
  if (TEXT_EXT.has(ext)) return "text";
  return null;
}

class FileReadError extends Error {}

async function readPdf(buffer) {
  const pdf = await getDocumentProxy(new Uint8Array(buffer));
  const { text } = await extractText(pdf, { mergePages: true });
  const clean = String(text || "").trim();
  // Нет текстового слоя — это скан
  if (clean.replace(/\s+/g, "").length < 20) {
    throw new FileReadError("Не могу прочитать текст в этом PDF — похоже, это скан. Пришли фото страниц.");
  }
  return clean;
}

async function readDocx(buffer) {
  const { value } = await mammoth.extractRawText({ buffer });
  return String(value || "").trim();
}

async function readXlsx(buffer) {
  const book = new ExcelJS.Workbook();
  await book.xlsx.load(buffer);
  const parts = [];
  book.eachSheet((sheet) => {
    const lines = [];
    sheet.eachRow({ includeEmpty: false }, (row, n) => {
      if (n > MAX_SHEET_ROWS) return;
      const cells = (row.values || []).slice(1).map((v) => {
        if (v == null) return "";
        if (typeof v === "object") return String(v.text ?? v.result ?? v.richText?.map((r) => r.text).join("") ?? "");
        return String(v);
      });
      lines.push(cells.join(" | "));
    });
    const more = sheet.actualRowCount > MAX_SHEET_ROWS ? `\n… ещё ${sheet.actualRowCount - MAX_SHEET_ROWS} строк` : "";
    parts.push(`## Лист: ${sheet.name}\n${lines.join("\n")}${more}`);
  });
  return parts.join("\n\n").trim();
}

function readText(buffer) {
  const text = buffer.toString("utf8").replace(/^﻿/, "");
  // Бинарник с «текстовым» расширением
  if ((text.match(/\u0000/g) || []).length > 5) {
    throw new FileReadError("Это не похоже на текстовый файл.");
  }
  return text;
}

/** Текст файла, обрезанный до maxChars. Бросает FileReadError с понятным юзеру текстом. */
export async function readFileText(buffer, kind, maxChars) {
  let text;
  try {
    if (kind === "pdf") text = await readPdf(buffer);
    else if (kind === "docx") text = await readDocx(buffer);
    else if (kind === "xlsx") text = await readXlsx(buffer);
    else text = readText(buffer);
  } catch (error) {
    if (error instanceof FileReadError) throw error;
    console.error("assistant file read error", { kind, message: error?.message });
    throw new FileReadError("Не получилось прочитать файл. Проверь, что он не повреждён и не защищён паролем.");
  }
  if (!text.trim()) throw new FileReadError("В файле нет текста.");
  const truncated = text.length > maxChars;
  return { text: truncated ? text.slice(0, maxChars) : text, truncated, chars: text.length };
}

export function createFileStore({ supabase, bucket, maxChars }) {
  const storage = () => supabase.storage.from(bucket);
  const metaPathOf = (path) => `${path}.json`;

  async function upload(path, body, contentType) {
    const put = () => storage().upload(path, body, { contentType, upsert: false });
    let { error } = await put();
    if (error && /bucket not found/i.test(String(error.message))) {
      const created = await supabase.storage.createBucket(bucket, { public: false });
      if (created.error) throw created.error;
      ({ error } = await put());
    }
    if (error) throw error;
  }

  /**
   * Разобрать и сохранить файл. Возвращает { ok, file } или { error } с текстом для юзера.
   * file = { path, name, size, kind, truncated, chars }
   */
  async function saveFile(chatId, name, buffer) {
    const kind = fileKind(name);
    if (!kind) {
      return { error: "Такой формат пока не читаю. Подойдут PDF, Word (DOCX), Excel (XLSX), CSV, TXT и файлы с кодом." };
    }
    if (buffer.length > MAX_FILE_BYTES) return { error: "Файл больше 10 МБ" };
    let read;
    try {
      read = await readFileText(buffer, kind, maxChars);
    } catch (error) {
      return { error: error.message };
    }
    const ext = extOf(name) || "txt";
    const path = `${encodeURIComponent(chatId)}/${randomUUID()}.${ext.replace(/[^a-z0-9]/g, "") || "bin"}`;
    const meta = { name: String(name).slice(0, 200), size: buffer.length, kind, truncated: read.truncated, chars: read.chars };
    try {
      await upload(path, buffer, "application/octet-stream");
      await upload(metaPathOf(path), Buffer.from(JSON.stringify({ ...meta, text: read.text })), "application/json");
    } catch (error) {
      console.error("assistant file save error", error);
      return { error: "Не удалось сохранить файл, попробуй ещё раз" };
    }
    return { ok: true, file: { path, ...meta } };
  }

  /** Метаданные + текст ранее загруженного файла. */
  async function loadFile(path) {
    const { data, error } = await storage().download(metaPathOf(path));
    if (error || !data) return null;
    try {
      return { path, ...JSON.parse(await data.text()) };
    } catch {
      return null;
    }
  }

  async function removePaths(paths) {
    const all = [...new Set(paths.filter(Boolean).flatMap((p) => [p, metaPathOf(p)]))];
    for (let i = 0; i < all.length; i += 500) {
      const { error } = await storage().remove(all.slice(i, i + 500));
      if (error) console.error("assistant remove docs error", error);
    }
  }

  /** Блок для модели: «[Файл: имя]» + текст (+ пометка, что прочитана часть). */
  const blockFor = (f) =>
    `[Файл: ${f.name}]\n${f.text}${
      f.truncated ? `\n[Прочитана только часть файла: первые ${maxChars} символов из ${f.chars}. Скажи об этом юзеру.]` : ""
    }`;

  return { saveFile, loadFile, removePaths, blockFor };
}
