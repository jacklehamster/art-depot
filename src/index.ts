/* eslint-disable no-console */

import jpegDecode, { init as initJpeg } from "@jsquash/jpeg/decode";
import pngDecode, { init as initPng } from "@jsquash/png/decode";
import webpDecode, { init as initWebpDec } from "@jsquash/webp/decode";

import avifEncode, { init as initAvifEnc } from "@jsquash/avif/encode";
import webpEncode, { init as initWebpEnc } from "@jsquash/webp/encode";

export interface Env {
  HOT: KVNamespace;
  STAGING: R2Bucket;
  ASSETS: Fetcher;

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
const HOT_TTL_SECONDS = 12 * 60 * 60;
const PUT_URL_EXPIRES_SECONDS = 5 * 60;

// -----------------------------
// Serve your own wasm files under /wasm/*
// -----------------------------
// Put these in public/wasm/ (see instructions above)
const WASM_FILES = {
  jpeg_dec: "mozjpeg_dec.wasm",
  png: "squoosh_png_bg.wasm",
  webp_dec: "webp_dec.wasm",
  webp_enc: "webp_enc.wasm",
  avif_enc: "avif_enc.wasm",
} as const;

let codecsReady: Promise<void> | null = null;

/**
 * jSquash's init() uses Emscripten Module options.
 * We provide locateFile so that when it asks for *.wasm, it fetches from our own origin: /wasm/<file>.
 *
 * IMPORTANT:
 * Different codecs may request different filenames. To be robust, we:
 * - If the requested path already ends with ".wasm", we return /wasm/<that filename>
 * - Else we fall back to /wasm/<path>
 */
function makeLocateFile(baseUrl: string) {
  return (path: string, _prefix: string) => {
    // Some builds pass things like "mozjpeg_dec.wasm" or "./mozjpeg_dec.wasm"
    const file = path.split("/").pop() || path;
    const clean = file.replace(/^\.\//, "");
    return new URL(`/wasm/${clean}`, baseUrl).toString();
  };
}

function ensureCodecsReady(baseUrl: string) {
  codecsReady ??= (async () => {
    const locateFile = makeLocateFile(baseUrl);

    // NOTE: New API shape: init(opts?) -> Promise<void>
    await initJpeg({ locateFile } as any);
    await initPng({ locateFile } as any);
    await initWebpDec({ locateFile } as any);

    await initWebpEnc({ locateFile } as any);
    await initAvifEnc({ locateFile } as any);
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

async function persistToDrive(_env: Env, _hot: HotAsset) {}

function sanitizeUserId(userId?: string): string {
  if (!userId) return "anonymous";
  return userId.replace(/[^a-zA-Z0-9_-]/g, "_").slice(0, 64);
}

function pickFormat(body: any): OutputFormat {
  return body?.format === "webp" ? "webp" : "avif";
}

// -----------------------------
// Decode + encode
// -----------------------------
async function r2ObjectToImageData(
  obj: R2ObjectBody,
  baseUrl: string,
): Promise<ImageData> {
  await ensureCodecsReady(baseUrl);

  const ab = await obj.arrayBuffer();
  const contentType =
    obj.httpMetadata?.contentType || "application/octet-stream";
  const ct = contentType.toLowerCase();

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
  baseUrl: string,
): Promise<{ bytes: Uint8Array; mime: string; ext: string }> {
  await ensureCodecsReady(baseUrl);

  if (format === "webp") {
    const ab = await webpEncode(imageData, { quality: 80 } as any);
    return { bytes: new Uint8Array(ab), mime: "image/webp", ext: "webp" };
  }

  const ab = await avifEncode(imageData, { quality: 45 } as any);
  return { bytes: new Uint8Array(ab), mime: "image/avif", ext: "avif" };
}

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
    const baseUrl = `${url.protocol}//${url.host}`;

    if (url.pathname === "/api" && req.method === "GET") {
      return json({
        ok: true,
        routes: [
          "POST /upload-url",
          "POST /commit (optional format: avif|webp)",
          "GET /a/:assetId",
          "GET /wasm/<file>.wasm (served by ASSETS)",
        ],
        wasmExpectedAt: Object.values(WASM_FILES).map((f) => `/wasm/${f}`),
      });
    }

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

      try {
        const imageData = await r2ObjectToImageData(original, baseUrl);
        const encoded = await encodeImage(imageData, format, baseUrl);

        const outHash = await sha256HexBytes(encoded.bytes.buffer);
        const convertedKey = `staging/converted/${outHash}.${encoded.ext}`;

        await env.STAGING.put(convertedKey, encoded.bytes, {
          httpMetadata: {
            contentType: encoded.mime,
            cacheControl: "public, max-age=31536000, immutable",
          },
        });

        // delete original to save space (optional)
        ctx.waitUntil(env.STAGING.delete(body.r2Key));

        hot.r2Key = convertedKey;
        hot.mime = encoded.mime;
        hot.bytes = encoded.bytes.byteLength;

        await env.HOT.put(`asset:${body.assetId}`, JSON.stringify(hot), {
          expirationTtl: HOT_TTL_SECONDS,
        });

        ctx.waitUntil(
          persistToDrive(env, hot).catch((err) => console.error(err)),
        );

        return json({
          ok: true,
          assetId: body.assetId,
          r2Key: convertedKey,
          mime: encoded.mime,
          bytes: encoded.bytes.byteLength,
          format,
        });
      } catch (e) {
        return json(
          {
            error: "conversion_failed",
            message: e instanceof Error ? e.message : String(e),
          },
          400,
        );
      }
    }

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

    // Static assets fallback (includes /wasm/*.wasm)
    if (!isApiRoute(url.pathname)) {
      return env.ASSETS.fetch(req);
    }

    return new Response("Not found", { status: 404 });
  },
};
