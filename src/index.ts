import { encode as encodeAvif } from "@jsquash/avif";
import { encode as encodeWebp } from "@jsquash/webp";

export interface Env {
  HOT: KVNamespace;
  STAGING: R2Bucket;
  ASSETS: Fetcher;

  // (kept in case you still want presign for other things)
  R2_ACCOUNT_ID: string;
  R2_BUCKET: string;
  R2_ACCESS_KEY_ID: string;
  R2_SECRET_ACCESS_KEY: string;
}

const enc = new TextEncoder();

function json(data: unknown, status = 200) {
  return new Response(JSON.stringify(data), {
    status,
    headers: { "content-type": "application/json; charset=utf-8" },
  });
}

async function sha256HexBytes(buf: ArrayBuffer) {
  const digest = await crypto.subtle.digest("SHA-256", buf);
  return [...new Uint8Array(digest)]
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("");
}

type HotAsset = {
  assetId: string;
  r2Key: string;
  mime: string;
  bytes: number;
  createdAt: number;
};

const HOT_TTL_SECONDS = 12 * 60 * 60; // 12 hours

function isApiRoute(pathname: string) {
  return (
    pathname === "/upload" ||
    pathname === "/commit" ||
    pathname.startsWith("/a/") ||
    pathname === "/api"
  );
}

async function persistToDrive(_env: Env, _hot: HotAsset) {}

type OutputFormat = "avif" | "webp";

function pickFormat(req: Request): OutputFormat {
  // Prefer explicit query param, else default to avif
  const url = new URL(req.url);
  const f = (url.searchParams.get("format") || "").toLowerCase();
  if (f === "webp") return "webp";
  return "avif";
}

function sanitizeUserId(userId?: string) {
  return (userId || "anon").replace(/[^a-zA-Z0-9._-]/g, "_");
}

/**
 * Decode → encode requires pixels. We can’t reliably decode all formats ourselves in Workers
 * without pulling in a decoder. The simplest practical approach is:
 * - If the input is already a browser-decodable image type, use createImageBitmap()
 * - Then draw to OffscreenCanvas to get raw RGBA
 *
 * Works well for PNG/JPEG/WebP (and sometimes GIF first frame).
 */
async function fileToRgba(file: File): Promise<{
  rgba: Uint8ClampedArray;
  width: number;
  height: number;
}> {
  const ab = await file.arrayBuffer();
  const blob = new Blob([ab], {
    type: file.type || "application/octet-stream",
  });

  let bmp: ImageBitmap;
  try {
    bmp = await createImageBitmap(blob);
  } catch {
    throw new Error(
      `Unsupported input type for server-side compression: ${file.type || "unknown"}. ` +
        `Try uploading JPEG/PNG/WebP.`,
    );
  }

  const width = bmp.width;
  const height = bmp.height;

  const canvas = new OffscreenCanvas(width, height);
  const ctx = canvas.getContext("2d");
  if (!ctx) throw new Error("Failed to get 2d context");

  ctx.drawImage(bmp, 0, 0);
  bmp.close();

  const imageData = ctx.getImageData(0, 0, width, height);
  return { rgba: imageData.data, width, height };
}

async function fileToImageData(file: File): Promise<ImageData> {
  const ab = await file.arrayBuffer();
  const blob = new Blob([ab], {
    type: file.type || "application/octet-stream",
  });

  let bmp: ImageBitmap;
  try {
    bmp = await createImageBitmap(blob);
  } catch {
    throw new Error(
      `Unsupported input type for server-side compression: ${file.type || "unknown"}. ` +
        `Try JPEG/PNG/WebP.`,
    );
  }

  const canvas = new OffscreenCanvas(bmp.width, bmp.height);
  const ctx = canvas.getContext("2d");
  if (!ctx) throw new Error("Failed to get 2d context");

  ctx.drawImage(bmp, 0, 0);
  bmp.close();

  return ctx.getImageData(0, 0, canvas.width, canvas.height);
}

async function compressToFormat(
  file: File,
  format: OutputFormat,
): Promise<{ bytes: Uint8Array; mime: string; ext: string }> {
  const imageData = await fileToImageData(file);

  if (format === "webp") {
    const ab = await encodeWebp(imageData, {
      quality: 80, // 0-100
    });
    return { bytes: new Uint8Array(ab), mime: "image/webp", ext: "webp" };
  }

  const ab = await encodeAvif(imageData, {
    quality: 45, // typical range ~20-60
    // speed: 6, // if supported by your version
  } as any);

  return { bytes: new Uint8Array(ab), mime: "image/avif", ext: "avif" };
}

export default {
  async fetch(
    req: Request,
    env: Env,
    ctx: ExecutionContext,
  ): Promise<Response> {
    const url = new URL(req.url);

    if (url.pathname === "/api" && req.method === "GET") {
      return json({
        ok: true,
        routes: [
          "POST /upload?format=avif|webp (multipart/form-data: file, optional userId)",
          "POST /commit (optional legacy)",
          "GET /a/:assetId",
          "Static assets: everything else (via ASSETS binding)",
        ],
      });
    }

    // NEW: server-side upload + compression + put to R2
    if (url.pathname === "/upload" && req.method === "POST") {
      // Expect multipart form-data with:
      // - file: File
      // - userId: string (optional)
      let form: FormData;
      try {
        form = await req.formData();
      } catch {
        return json({ error: "expected multipart/form-data" }, 400);
      }

      const file = form.get("file");
      const userId = (form.get("userId") || "")?.toString() || "anon";

      if (!(file instanceof File)) {
        return json({ error: "missing form field: file" }, 400);
      }
      if (!file.size) return json({ error: "empty file" }, 400);

      const format = pickFormat(req);

      let compressed: { bytes: Uint8Array; mime: string; ext: string };
      try {
        compressed = await compressToFormat(file, format);
      } catch (e) {
        return json(
          { error: e instanceof Error ? e.message : "compression failed" },
          400,
        );
      }

      const assetId = crypto.randomUUID();
      const userPrefix = sanitizeUserId(userId);

      // Use hash of *compressed* bytes so identical outputs dedupe naturally
      const outHash = await sha256HexBytes(
        compressed.bytes.buffer as ArrayBuffer,
      );

      const r2Key = `staging/${userPrefix}/${outHash}.${compressed.ext}`;

      // Put compressed object to R2
      await env.STAGING.put(r2Key, compressed.bytes, {
        httpMetadata: {
          contentType: compressed.mime,
          cacheControl: "public, max-age=31536000, immutable",
        },
      });

      const hot: HotAsset = {
        assetId,
        r2Key,
        mime: compressed.mime,
        bytes: compressed.bytes.byteLength,
        createdAt: Date.now(),
      };

      await env.HOT.put(`asset:${assetId}`, JSON.stringify(hot), {
        expirationTtl: HOT_TTL_SECONDS,
      });

      // Optional async persistence hook
      ctx.waitUntil(
        persistToDrive(env, hot).catch((e) => {
          console.error("persistToDrive failed", e);
        }),
      );

      return json({
        assetId,
        r2Key,
        mime: hot.mime,
        bytes: hot.bytes,
        url: `/a/${assetId}`,
      });
    }

    // Keep your old /commit (optional; can remove if you fully migrate)
    if (url.pathname === "/commit" && req.method === "POST") {
      const body = (await req.json().catch(() => ({}))) as {
        assetId?: string;
        r2Key?: string;
        mime?: string;
        bytes?: number;
      };

      if (!body.assetId || !body.r2Key)
        return json({ error: "missing assetId/r2Key" }, 400);

      const head = await env.STAGING.head(body.r2Key);
      if (!head)
        return json({ error: "object not found in R2 (upload failed?)" }, 404);

      const raw = await env.HOT.get(`asset:${body.assetId}`);
      if (!raw) return json({ error: "assetId not found/expired" }, 404);

      const hot = JSON.parse(raw) as HotAsset;
      hot.mime = body.mime || hot.mime;
      hot.bytes = body.bytes ?? hot.bytes ?? head.size ?? 0;

      await env.HOT.put(`asset:${body.assetId}`, JSON.stringify(hot), {
        expirationTtl: HOT_TTL_SECONDS,
      });

      ctx.waitUntil(
        persistToDrive(env, hot).catch((e) => {
          console.error("persistToDrive failed", e);
        }),
      );

      return json({ ok: true, persisted: "scheduled" });
    }

    // Serve stored assets
    {
      const m = url.pathname.match(/^\/a\/(.+)$/);
      if (m && req.method === "GET") {
        const assetId = m[1];
        const raw = await env.HOT.get(`asset:${assetId}`);
        if (!raw) return new Response("Not found (expired)", { status: 404 });

        const hot = JSON.parse(raw) as HotAsset;
        const obj = await env.STAGING.get(hot.r2Key);
        if (!obj) return new Response("Not found in staging", { status: 404 });

        const headers = new Headers();
        headers.set("content-type", hot.mime);
        headers.set("cache-control", "public, max-age=3600");
        return new Response(obj.body, {
          headers,
          cf: { cacheEverything: true, cacheTtl: 3600 } as any,
        });
      }
    }

    // Static assets fallback
    if (!isApiRoute(url.pathname)) {
      return env.ASSETS.fetch(req);
    }

    return new Response("Not found", { status: 404 });
  },
};
