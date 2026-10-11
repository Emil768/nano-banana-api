// Картинки ИИ-ассистента в Supabase Storage (приватный бакет).
//
// - Всё (сгенерированное и загруженное юзером) пережимается в WebP ~85 + превью 1024px.
// - Файлы: {userId}/{uuid}.webp и {userId}/{uuid}_thumb.webp. В БД — только path оригинала.
// - Наружу — только подписанные ссылки (createSignedUrls, 1 час), их делает сервер.
// - Через ASSISTANT_IMAGE_TTL_DAYS дней файлы удаляются, текст переписки остаётся
//   (assistant_messages.images_deleted_at).

import { randomUUID } from "node:crypto";
import sharp from "sharp";

const SIGNED_URL_TTL_SECONDS = 60 * 60;
const MAX_SIDE = 2048; // оригинал больше не храним: экономия места без потери на экране
// Превью для ленты: карточка 380px на ретине = 760 реальных пикселей, 512 там мылит
const PREVIEW_SIDE = 1024;
const PURGE_EVERY_MS = 24 * 60 * 60 * 1000; // cron раз в сутки (и через минуту после старта)
const PURGE_BATCH = 200;

/**
 * onPurge(rows) — вызывается перед пометкой строк удалёнными: там чистятся
 * файлы-документы этих сообщений (у них свой бакет).
 */
export function createImageStore({ supabase, bucket, ttlDays, onPurge }) {
  const storage = () => supabase.storage.from(bucket);

  /** Превью есть только у новых WebP-файлов; у старых PNG/JPG показываем оригинал. */
  const previewPathOf = (path) =>
    /\.webp$/i.test(path) && !/_thumb\.webp$/i.test(path)
      ? path.replace(/\.webp$/i, "_thumb.webp")
      : path;

  /** Старые записи хранили полную публичную ссылку — оставляем от неё только path. */
  const toPath = (value) => {
    const raw = String(value || "").trim();
    const marker = `/storage/v1/object/public/${bucket}/`;
    const i = raw.indexOf(marker);
    return decodeURIComponent(i >= 0 ? raw.slice(i + marker.length) : raw);
  };

  /** Файл юзера — только из его папки. Защита от чужих путей (в т.ч. подсунутых модели). */
  const ownsPath = (chatId, path) =>
    typeof path === "string" &&
    path.startsWith(`${encodeURIComponent(chatId)}/`) &&
    !path.includes("..");

  const splitPaths = (value) =>
    String(value || "")
      .split("\n")
      .map(toPath)
      .filter(Boolean);

  async function upload(path, buffer) {
    const put = () =>
      storage().upload(path, buffer, { contentType: "image/webp", upsert: false });
    let { error } = await put();
    // Бакета ещё нет — создаём приватный и пробуем снова
    if (error && /bucket not found/i.test(String(error.message))) {
      const created = await supabase.storage.createBucket(bucket, { public: false });
      if (created.error) throw created.error;
      ({ error } = await put());
    }
    if (error) throw error;
  }

  /** Любая картинка (base64 или Buffer) → WebP + превью в бакет. Возвращает path или null. */
  async function saveImage(chatId, input) {
    try {
      const source = Buffer.isBuffer(input)
        ? input
        : Buffer.from(String(input || "").replace(/^data:.*?;base64,/i, ""), "base64");
      const image = sharp(source, { failOn: "none" }).rotate(); // rotate — по EXIF телефона
      const [full, preview] = await Promise.all([
        image
          .clone()
          .resize(MAX_SIDE, MAX_SIDE, { fit: "inside", withoutEnlargement: true })
          .webp({ quality: 85 })
          .toBuffer(),
        image
          .clone()
          .resize(PREVIEW_SIDE, PREVIEW_SIDE, { fit: "inside", withoutEnlargement: true })
          .webp({ quality: 80 })
          .toBuffer(),
      ]);
      const path = `${encodeURIComponent(chatId)}/${randomUUID()}.webp`;
      await Promise.all([upload(path, full), upload(previewPathOf(path), preview)]);
      return path;
    } catch (error) {
      console.error("assistant image save error", error);
      return null;
    }
  }

  /**
   * Подписанные ссылки пачкой: path → { url, preview }.
   * Чего нет в бакете — просто не попадёт в ответ.
   */
  async function signPaths(paths) {
    const unique = [...new Set(paths.filter(Boolean))];
    const all = [...new Set(unique.flatMap((p) => [p, previewPathOf(p)]))];
    const out = new Map();
    if (!all.length) return out;
    const { data, error } = await storage().createSignedUrls(all, SIGNED_URL_TTL_SECONDS);
    if (error) {
      console.error("assistant sign urls error", error);
      return out;
    }
    const byPath = new Map(
      (data || []).filter((d) => d?.signedUrl && !d.error).map((d) => [d.path, d.signedUrl])
    );
    for (const p of unique) {
      const url = byPath.get(p);
      if (url) out.set(p, { url, preview: byPath.get(previewPathOf(p)) || url });
    }
    return out;
  }

  /** Фото юзера → JPEG base64 для пайплайна генерации (его все модели каскада понимают). */
  async function downloadAsJpeg(path) {
    const { data, error } = await storage().download(path);
    if (error || !data) return null;
    const jpeg = await sharp(Buffer.from(await data.arrayBuffer()), { failOn: "none" })
      .jpeg({ quality: 90 })
      .toBuffer();
    return { data: jpeg.toString("base64"), mimeType: "image/jpeg" };
  }

  /** Удаление файлов старше ttlDays. Текст и промты в БД остаются. */
  async function purgeExpired() {
    const before = new Date(Date.now() - ttlDays * 24 * 60 * 60 * 1000).toISOString();
    for (;;) {
      const { data, error } = await supabase
        .from("assistant_messages")
        .select("id, image_url, files")
        .lt("created_at", before)
        .or("image_url.not.is.null,files.not.is.null")
        .is("images_deleted_at", null)
        .limit(PURGE_BATCH);
      if (error) {
        console.error("assistant purge select error", error);
        return;
      }
      if (!data?.length) return;

      const paths = [
        ...new Set(data.flatMap((row) => splitPaths(row.image_url).flatMap((p) => [p, previewPathOf(p)]))),
      ];
      if (paths.length) {
        const { error: removeError } = await storage().remove(paths);
        if (removeError) {
          console.error("assistant purge remove error", removeError);
          return;
        }
      }
      if (onPurge) await onPurge(data);
      const { error: markError } = await supabase
        .from("assistant_messages")
        .update({ images_deleted_at: new Date().toISOString() })
        .in("id", data.map((row) => row.id));
      if (markError) {
        console.error("assistant purge mark error", markError);
        return;
      }
      console.log(`assistant purge: removed ${paths.length} files from ${data.length} messages`);
      if (data.length < PURGE_BATCH) return;
    }
  }

  /** Удалить файлы (оригинал + превью). Ошибку только логируем: строки в БД всё равно чистим. */
  async function removePaths(paths) {
    const all = [...new Set(paths.filter(Boolean).flatMap((p) => [p, previewPathOf(p)]))];
    for (let i = 0; i < all.length; i += 500) {
      const { error } = await storage().remove(all.slice(i, i + 500));
      if (error) console.error("assistant remove files error", error);
    }
  }

  function startPurgeTimer() {
    const run = () => purgeExpired().catch((e) => console.error("assistant purge error", e));
    setTimeout(run, 60 * 1000).unref();
    setInterval(run, PURGE_EVERY_MS).unref();
  }

  return {
    saveImage,
    signPaths,
    downloadAsJpeg,
    previewPathOf,
    toPath,
    ownsPath,
    splitPaths,
    startPurgeTimer,
    purgeExpired,
    removePaths,
    ttlDays,
  };
}
