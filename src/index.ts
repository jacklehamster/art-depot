/* eslint-disable no-console */

/**
 * Worker: Presigned PUT upload to R2 + server-side convert on /commit (AVIF/WEBP),
 * keeping the original client flow:
 *   1) POST /upload-url  -> {assetId, r2Key, putUrl}
 *   2) PUT  putUrl       -> upload original bytes to R2
 *   3) POST /commit      -> server decodes + encodes + updates KV to converted key
 *   4) GET  /a/:assetId  -> serves converted object
 *
 * IMPORTANT:
 * - This uses the NEW jSquash API shape:
 *     init(opts?) -> Promise<void>
 *     default decode(buf) -> Promise<ImageData>
 *     default encode(imageData) -> Promise<ArrayBuffer>
 * - In Workers, WASM must be locatable. We provide locateFile to pull wasm from a CDN.
 * - Set JSQUASH_VERSIONS to match your package.json versions.
 */

import jpegDecode, { init as initJpeg } from "@jsquash/jpeg/decode";
import pngDecode, { init as initPng } from "@jsquash/png/decode";
import webpDecode, { init as initWebpDec } from "@jsquash/webp/decode";

import avifEncode, { init as initAvifEnc } from "@jsquash/avif/encode";
import webpEncode, { init as initWebpEnc } from "@jsquash/webp/encode";

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
// jSquash WASM loading (NEW API)
// -----------------------------
// ⚠️ Set these to match your installed versions in package.json
const JSQUASH_VERSIONS = {
  jpeg: "1.4.0",
  png: "3.0.1",
  webp: "1.5.0",
  avif: "2.1.1",
} as const;

// You can swap unpkg -> cdn.jsdelivr.net if preferred.
const JSQUASH_CDN = "https://unpkg.com";

// Emscripten locateFile callback
function locateFileFor(pkg: string, version: string) {
  return (path: string, prefix: string) => {
    const pfx = (prefix || "").replace(/^\.\//, "");
    const joined = `${pfx}${path}`.replace(/^\.\//, "");
    return `${JSQUASH_CDN}/${pkg}@${version}/${joined}`;
  };
}

let codecsReady: Promise<void> | null = null;

function ensureCodecsReady() {
  codecsReady ??= (async () => {
    // Decoders
    await initJpeg({
      locateFile: locateFileFor("@jsquash/jpeg", JSQUASH_VERSIONS.jpeg),
    } as any);

    await initPng({
      locateFile: locateFileFor("@jsquash/png", JSQUASH_VERSIONS.png),
    } as any);

    await initWebpDec({
      locateFile: locateFileFor("@jsquash/webp", JSQUASH_VERSIONS.webp),
    } as any);

    // Encoders
    await initAvifEnc({
      locateFile: locateFileFor("@jsquash/avif", JSQUASH_VERSIONS.avif),
    } as any);

    await initWebpEnc({
      locateFile: locateFileFor("@jsquash/webp", JSQUASH_VERSIONS.webp),
    } as any);
  })();

  return codecsReady;
}

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
  // Keep static assets clean by reserving these
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

async function sha256HexBytes(buf: ArrayBufferLike) {
  const digest = await crypto.subtle.digest("SHA-256", buf as ArrayBuffer);
  return [...new Uint8Array(digest)]
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("");
}

function sanitizeUserId(userId?: string) {
  return (userId || "anon").replace(/[^a-zA-Z0-9._-]/g, "_");
}

function pickFormat(body: any): OutputFormat {
  return body?.format === "webp" ? "webp" : "avif";
}

// -----------------------------
// Presigned PUT URL for R2 (S3 SigV4)
// -----------------------------
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
// Decode + encode helpers
// -----------------------------
async function r2ObjectToImageData(obj: R2ObjectBody): Promise<ImageData> {
  await ensureCodecsReady();

  const ab = await obj.arrayBuffer();
  const contentType =
    obj.httpMetadata?.contentType || "application/octet-stream";
  const ct = contentType.toLowerCase();

  // Decode based on MIME. (You can add sniffing if needed.)
  if (ct.includes("image/jpeg") || ct.includes("image/jpg"))
    return await jpegDecode(ab);
  if (ct.includes("image/png")) return await pngDecode(ab);
  if (ct.includes("image/webp")) return await webpDecode(ab);

  throw new Error(
    `Unsupported input for conversion: ${contentType}. Try JPEG/PNG/WebP.`,
  );
}

async function encodeImage(
  imageData: ImageData,
  format: OutputFormat,
): Promise<{ bytes: Uint8Array; mime: string; ext: string }> {
  await ensureCodecsReady();

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
          "POST /commit (optional format: avif|webp)",
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

      const userPrefix = sanitizeUserId(body.userId);
      const sha = (body.sha256 ?? "").trim();
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

    // 2) Commit: read uploaded object, decode+encode, store converted key, update KV mapping
    if (url.pathname === "/commit" && req.method === "POST") {
      const body = (await req.json().catch(() => ({}))) as {
        assetId?: string;
        r2Key?: string;
        mime?: string;
        bytes?: number;
        format?: OutputFormat;
      };

      if (!body.assetId || !body.r2Key) {
        return json({ error: "missing assetId/r2Key" }, 400);
      }

      const original = await env.STAGING.get(body.r2Key);
      if (!original) {
        return json({ error: "object not found in R2 (upload failed?)" }, 404);
      }

      const raw = await env.HOT.get(`asset:${body.assetId}`);
      if (!raw) return json({ error: "assetId not found/expired" }, 404);

      const hot = JSON.parse(raw) as HotAsset;

      const format = pickFormat(body);

      let outBytes: Uint8Array;
      let outMime: string;
      let outExt: string;

      try {
        const imageData = await r2ObjectToImageData(original);
        const encoded = await encodeImage(imageData, format);
        outBytes = encoded.bytes;
        outMime = encoded.mime;
        outExt = encoded.ext;
      } catch (e) {
        return json(
          {
            error: "conversion_failed",
            message: e instanceof Error ? e.message : String(e),
          },
          400,
        );
      }

      const outHash = await sha256HexBytes(outBytes.buffer);
      const convertedKey = `staging/converted/${outHash}.${outExt}`;

      await env.STAGING.put(convertedKey, outBytes, {
        httpMetadata: {
          contentType: outMime,
          cacheControl: "public, max-age=31536000, immutable",
        },
      });

      // Optional: delete original upload
      ctx.waitUntil(env.STAGING.delete(body.r2Key));

      hot.r2Key = convertedKey;
      hot.mime = outMime;
      hot.bytes = outBytes.byteLength;

      await env.HOT.put(`asset:${body.assetId}`, JSON.stringify(hot), {
        expirationTtl: HOT_TTL_SECONDS,
      });

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

    // 3) Serve asset by assetId
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
