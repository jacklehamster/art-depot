/**
 * Worker: Presigned PUT upload to R2 + server-side convert on /commit (AVIF/WEBP),
 * while keeping the original client flow:
 *   1) POST /upload-url  -> {assetId, r2Key, putUrl}
 *   2) PUT  putUrl       -> upload original bytes to R2
 *   3) POST /commit      -> server converts + updates KV to point at converted object
 *   4) GET  /a/:assetId  -> serves converted object
 */

import { encode as avifEncode } from "@jsquash/avif";
import { encode as webpEncode, decode as webpDecode } from "@jsquash/webp";
import { decode as jpegDecode } from "@jsquash/jpeg";
import { decode as pngDecode } from "@jsquash/png";

export interface Env {
  // Storage
  HOT: KVNamespace;
  STAGING: R2Bucket;

  // Static assets binding (Workers Static Assets)
  ASSETS: Fetcher;

  // R2 presign config
  R2_ACCOUNT_ID: string;
  R2_BUCKET: string;
  R2_ACCESS_KEY_ID: string;
  R2_SECRET_ACCESS_KEY: string;
}

type OutputFormat = "avif" | "webp";

type HotAsset = {
  assetId: string;
  r2Key: string;
  mime: string;
  bytes: number;
  createdAt: number;
};

const enc = new TextEncoder();

const HOT_TTL_SECONDS = 12 * 60 * 60; // 12 hours
const PUT_URL_EXPIRES_SECONDS = 5 * 60;

// -----------------------------
// Small utilities
// -----------------------------
function json(data: unknown, status = 200) {
  return new Response(JSON.stringify(data), {
    status,
    headers: { "content-type": "application/json; charset=utf-8" },
  });
}

function isApiRoute(pathname: string) {
  return (
    pathname === "/upload-url" ||
    pathname === "/commit" ||
    pathname.startsWith("/a/") ||
    pathname === "/api"
  );
}

function awsDates(d = new Date()) {
  const pad = (n: number) => String(n).padStart(2, "0");
  const y = d.getUTCFullYear();
  const m = pad(d.getUTCMonth() + 1);
  const day = pad(d.getUTCDate());
  const hh = pad(d.getUTCHours());
  const mm = pad(d.getUTCMinutes());
  const ss = pad(d.getUTCSeconds());
  const dateStamp = `${y}${m}${day}`;
  const amzDate = `${dateStamp}T${hh}${mm}${ss}Z`;
  return { dateStamp, amzDate };
}

async function hmacSha256(key: ArrayBuffer, msg: string) {
  const cryptoKey = await crypto.subtle.importKey(
    "raw",
    key,
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["sign"],
  );
  const sig = await crypto.subtle.sign("HMAC", cryptoKey, enc.encode(msg));
  return new Uint8Array(sig);
}

async function sha256Hex(s: string) {
  const digest = await crypto.subtle.digest("SHA-256", enc.encode(s));
  return [...new Uint8Array(digest)]
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("");
}

async function sha256HexBytes(buf: ArrayBuffer) {
  const digest = await crypto.subtle.digest("SHA-256", buf);
  return [...new Uint8Array(digest)]
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("");
}

/**
 * Presigned PUT URL for R2 (S3 SigV4).
 * Signs only `host`, uses UNSIGNED-PAYLOAD (browser can set Content-Type freely).
 */
async function presignR2Put(env: Env, key: string, expiresSeconds: number) {
  const { dateStamp, amzDate } = awsDates();
  const region = "auto";
  const service = "s3";
  const host = `${env.R2_ACCOUNT_ID}.r2.cloudflarestorage.com`;

  const canonicalUri = `/${env.R2_BUCKET}/${encodeURIComponent(key).replace(/%2F/g, "/")}`;
  const algorithm = "AWS4-HMAC-SHA256";
  const credentialScope = `${dateStamp}/${region}/${service}/aws4_request`;
  const credential = `${env.R2_ACCESS_KEY_ID}/${credentialScope}`;
  const signedHeaders = "host";

  const params: Record<string, string> = {
    "X-Amz-Algorithm": algorithm,
    "X-Amz-Credential": encodeURIComponent(credential),
    "X-Amz-Date": amzDate,
    "X-Amz-Expires": String(expiresSeconds),
    "X-Amz-SignedHeaders": signedHeaders,
  };

  const canonicalQuery = Object.keys(params)
    .sort()
    .map((k) => `${k}=${params[k]}`)
    .join("&");

  const canonicalHeaders = `host:${host}\n`;
  const payloadHash = "UNSIGNED-PAYLOAD";

  const canonicalRequest = [
    "PUT",
    canonicalUri,
    canonicalQuery,
    canonicalHeaders,
    signedHeaders,
    payloadHash,
  ].join("\n");

  const stringToSign = [
    algorithm,
    amzDate,
    credentialScope,
    await sha256Hex(canonicalRequest),
  ].join("\n");

  // SigV4 key derivation
  const kSecret = enc.encode(`AWS4${env.R2_SECRET_ACCESS_KEY}`).buffer;
  const kDate = (await hmacSha256(kSecret, dateStamp)).buffer;
  const kRegion = (await hmacSha256(kDate, region)).buffer;
  const kService = (await hmacSha256(kRegion, service)).buffer;
  const kSigning = (await hmacSha256(kService, "aws4_request")).buffer;

  const sigBytes = await hmacSha256(kSigning, stringToSign);
  const signature = [...sigBytes]
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("");

  return `https://${host}${canonicalUri}?${canonicalQuery}&X-Amz-Signature=${signature}`;
}

// -----------------------------
// Decode: R2 object -> ImageData
// Prefer jSquash WASM decoders (reliable in Workers) over createImageBitmap.
// -----------------------------
async function r2ObjectToImageData(obj: R2ObjectBody): Promise<ImageData> {
  const ab = await obj.arrayBuffer();

  // Prefer R2 httpMetadata.contentType; fall back to headers if needed.
  const contentType =
    obj.httpMetadata?.contentType ||
    (obj as any).headers?.get?.("content-type") ||
    "application/octet-stream";

  const ct = contentType.toLowerCase();

  try {
    if (ct.includes("image/jpeg") || ct.includes("image/jpg")) {
      return await jpegDecode(ab);
    }
    if (ct.includes("image/png")) {
      return await pngDecode(ab);
    }
    if (ct.includes("image/webp")) {
      return await webpDecode(ab);
    }
  } catch (e) {
    // Fall through to createImageBitmap fallback below with the real error captured.
    const msg = e instanceof Error ? e.message : String(e);
    console.warn("WASM decode failed, falling back to createImageBitmap:", msg);
  }

  // Fallback: Canvas decode (may be unsupported in some Workers configs)
  try {
    const blob = new Blob([ab], { type: contentType });
    const bmp = await createImageBitmap(blob);

    const canvas = new OffscreenCanvas(bmp.width, bmp.height);
    const ctx = canvas.getContext("2d");
    if (!ctx) throw new Error("Failed to get 2d context");
    ctx.drawImage(bmp, 0, 0);
    bmp.close();

    return ctx.getImageData(0, 0, canvas.width, canvas.height);
  } catch (e) {
    const msg = e instanceof Error ? e.message : String(e);
    throw new Error(`Decode failed for content-type "${contentType}": ${msg}`);
  }
}

// -----------------------------
// Encode: ImageData -> AVIF/WEBP
// -----------------------------
async function encodeImage(
  imageData: ImageData,
  format: OutputFormat,
): Promise<{ bytes: Uint8Array; mime: string; ext: string }> {
  if (format === "webp") {
    const ab = await webpEncode(imageData, { quality: 80 } as any);
    return { bytes: new Uint8Array(ab), mime: "image/webp", ext: "webp" };
  }

  const ab = await avifEncode(imageData, { quality: 45 } as any);
  return { bytes: new Uint8Array(ab), mime: "image/avif", ext: "avif" };
}

// -----------------------------
// Placeholder hook
// -----------------------------
async function persistToDrive(_env: Env, _hot: HotAsset) {}

// -----------------------------
// Worker
// -----------------------------
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
          "POST /upload-url",
          "POST /commit (optionally include format: avif|webp)",
          "GET /a/:assetId",
          "Static assets: everything else (via ASSETS binding)",
        ],
      });
    }

    // 1) Presign URL for browser PUT to R2 (original bytes)
    if (url.pathname === "/upload-url" && req.method === "POST") {
      const body = (await req.json().catch(() => ({}))) as {
        userId?: string;
        sha256?: string;
        mime?: string;
        bytes?: number;
      };

      const assetId = crypto.randomUUID();
      const mime = body.mime || "application/octet-stream";
      const bytes = body.bytes || 0;

      const userPrefix = (body.userId || "anon").replace(
        /[^a-zA-Z0-9._-]/g,
        "_",
      );
      const sha = (body.sha256 ?? "").trim();

      // original upload key
      const fileKey = sha
        ? `staging/original/${userPrefix}/${sha}`
        : `staging/original/${userPrefix}/${assetId}`;

      const putUrl = await presignR2Put(env, fileKey, PUT_URL_EXPIRES_SECONDS);

      const hot: HotAsset = {
        assetId,
        r2Key: fileKey,
        mime,
        bytes,
        createdAt: Date.now(),
      };

      await env.HOT.put(`asset:${assetId}`, JSON.stringify(hot), {
        expirationTtl: HOT_TTL_SECONDS,
      });

      return json({
        assetId,
        r2Key: fileKey,
        putUrl,
        expiresIn: PUT_URL_EXPIRES_SECONDS,
      });
    }

    // 2) Commit uploaded file; server converts to AVIF/WEBP and updates KV to point to converted key
    if (url.pathname === "/commit" && req.method === "POST") {
      const body = (await req.json().catch(() => ({}))) as {
        assetId?: string;
        r2Key?: string;
        mime?: string;
        bytes?: number;
        format?: "avif" | "webp";
      };

      if (!body.assetId || !body.r2Key) {
        return json({ error: "missing assetId/r2Key" }, 400);
      }

      // Verify original exists
      const original = await env.STAGING.get(body.r2Key);
      if (!original) {
        return json({ error: "object not found in R2 (upload failed?)" }, 404);
      }

      // Load HOT record
      const raw = await env.HOT.get(`asset:${body.assetId}`);
      if (!raw) return json({ error: "assetId not found/expired" }, 404);

      const hot = JSON.parse(raw) as HotAsset;

      // Choose output format (default avif)
      const format: OutputFormat = body.format === "webp" ? "webp" : "avif";

      // Convert
      let outBytes: Uint8Array;
      let outMime: string;
      let outExt: string;

      try {
        const imageData = await r2ObjectToImageData(original);
        const encOut = await encodeImage(imageData, format);
        outBytes = encOut.bytes;
        outMime = encOut.mime;
        outExt = encOut.ext;
      } catch (e) {
        return json(
          {
            error: "conversion_failed",
            message: e instanceof Error ? e.message : String(e),
          },
          400,
        );
      }

      // Store converted object (dedupe by hash of encoded bytes)
      const outHash = await sha256HexBytes(outBytes.buffer as ArrayBuffer);
      const convertedKey = `staging/converted/${outHash}.${outExt}`;

      await env.STAGING.put(convertedKey, outBytes, {
        httpMetadata: {
          contentType: outMime,
          cacheControl: "public, max-age=31536000, immutable",
        },
      });

      // Optionally delete original to save space
      ctx.waitUntil(env.STAGING.delete(body.r2Key));

      // Update HOT KV so /a/:assetId serves the converted version
      hot.r2Key = convertedKey;
      hot.mime = outMime;
      hot.bytes = outBytes.byteLength;

      await env.HOT.put(`asset:${body.assetId}`, JSON.stringify(hot), {
        expirationTtl: HOT_TTL_SECONDS,
      });

      // Optional persistence hook
      ctx.waitUntil(
        persistToDrive(env, hot).catch((err) => {
          console.error("persistToDrive failed", err);
        }),
      );

      return json({
        ok: true,
        assetId: body.assetId,
        originalKey: body.r2Key,
        r2Key: convertedKey,
        mime: outMime,
        bytes: outBytes.byteLength,
        format,
      });
    }

    // 3) Serve asset by assetId (serves whatever KV points to — converted after commit)
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

    // ---- Static assets fallback ----
    if (!isApiRoute(url.pathname)) {
      return env.ASSETS.fetch(req);
    }

    return new Response("Not found", { status: 404 });
  },
};
