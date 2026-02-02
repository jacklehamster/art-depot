/* eslint-disable no-console */

import { init as initAvifEncode } from "@jsquash/avif/encode";
import avifEncode from "@jsquash/avif/encode";
import { init as initWebpEncode } from "@jsquash/webp/encode";
import webpEncode from "@jsquash/webp/encode";

import jpegDecode, { init as initJpegDecode } from "@jsquash/jpeg/decode";
import pngDecode, { init as initPngDecode } from "@jsquash/png/decode";
import webpDecode, { init as initWebpDecode } from "@jsquash/webp/decode";

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

const HOT_TTL_SECONDS = 12 * 60 * 60; // 12 hours
const PUT_URL_EXPIRES_SECONDS = 5 * 60;

// ---- helpers ----
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

function sanitizeUserId(userId?: string) {
  return (userId || "anon").replace(/[^a-zA-Z0-9._-]/g, "_");
}

function pickFormat(req: Request, body?: any): OutputFormat {
  if (body?.format === "webp") return "webp";
  const url = new URL(req.url);
  const f = (url.searchParams.get("format") || "").toLowerCase();
  return f === "webp" ? "webp" : "avif";
}

// ---- presign ----
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

// ---- jSquash wasm boot ----
// We load wasm BYTES from static assets using env.ASSETS.fetch,
// then pass wasmBinary into init(). This avoids Emscripten doing fetch() itself.
const WASM_CANDIDATES = {
  jpeg_dec: ["mozjpeg_dec_simd.wasm", "mozjpeg_dec.wasm"],
  png: ["squoosh_png_bg.wasm"],
  webp_dec: ["webp_dec_simd.wasm", "webp_dec.wasm"],
  webp_enc: ["webp_enc_simd.wasm", "webp_enc.wasm"],
  avif_enc: ["avif_enc_simd.wasm", "avif_enc.wasm"],
} as const;

async function loadWasmFromAssets(env: Env, candidates: readonly string[]) {
  for (const name of candidates) {
    const req = new Request(`https://assets.local/wasm/${name}`);
    const res = await env.ASSETS.fetch(req);
    if (res.ok) return await res.arrayBuffer();
  }
  throw new Error(
    `Missing wasm in assets. Tried: ${candidates.join(", ")} (expected under /public/wasm/)`,
  );
}

let codecsInitPromise: Promise<void> | null = null;

async function ensureCodecsReady(env: Env) {
  codecsInitPromise ??= (async () => {
    const jpegDec = await loadWasmFromAssets(env, WASM_CANDIDATES.jpeg_dec);
    const png = await loadWasmFromAssets(env, WASM_CANDIDATES.png);
    const webpDec = await loadWasmFromAssets(env, WASM_CANDIDATES.webp_dec);
    const webpEnc = await loadWasmFromAssets(env, WASM_CANDIDATES.webp_enc);
    const avifEnc = await loadWasmFromAssets(env, WASM_CANDIDATES.avif_enc);

    await initJpegDecode({ wasmBinary: jpegDec } as any);
    await initPngDecode({ wasmBinary: png } as any);
    await initWebpDecode({ wasmBinary: webpDec } as any);

    await initWebpEncode({ wasmBinary: webpEnc } as any);
    await initAvifEncode({ wasmBinary: avifEnc } as any);
  })();

  return codecsInitPromise;
}

// ---- decode/encode pipeline ----
async function r2ObjectToImageData(
  env: Env,
  obj: R2ObjectBody,
): Promise<ImageData> {
  await ensureCodecsReady(env);

  const ab = await obj.arrayBuffer();
  const ct =
    obj.httpMetadata?.contentType ||
    (obj as any).headers?.get?.("content-type") ||
    "application/octet-stream";

  const m = ct.toLowerCase();

  // Prefer decode based on mime, but fall back to sniffing attempts if mime missing/wrong.
  try {
    if (m.includes("image/jpeg") || m.includes("image/jpg"))
      return await jpegDecode(ab);
    if (m.includes("image/png")) return await pngDecode(ab);
    if (m.includes("image/webp")) return await webpDecode(ab);
  } catch (e) {
    const msg = e instanceof Error ? e.message : String(e);
    throw new Error(`Decode failed (${ct}): ${msg}`);
  }

  // Mime might be application/octet-stream; try common decoders.
  try {
    return await jpegDecode(ab);
  } catch {}
  try {
    return await pngDecode(ab);
  } catch {}
  try {
    return await webpDecode(ab);
  } catch {}

  throw new Error(
    `Unsupported input for conversion: ${ct}. Try JPEG/PNG/WebP.`,
  );
}

async function encodeImage(
  env: Env,
  imageData: ImageData,
  format: OutputFormat,
): Promise<{ bytes: Uint8Array; mime: string; ext: string }> {
  await ensureCodecsReady(env);

  if (format === "webp") {
    const ab = await webpEncode(imageData, { quality: 80 } as any);
    return { bytes: new Uint8Array(ab), mime: "image/webp", ext: "webp" };
  }

  const ab = await avifEncode(imageData, { quality: 45 } as any);
  return { bytes: new Uint8Array(ab), mime: "image/avif", ext: "avif" };
}

async function persistToDrive(_env: Env, _hot: HotAsset) {}

// ---- worker ----
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
          "POST /commit (optional format=avif|webp via query or JSON body)",
          "GET /a/:assetId",
          "Static assets: everything else (via ASSETS binding)",
        ],
        wasmExpectedSomewhere: "/wasm/*.wasm (served from static assets)",
        wasmCandidates: WASM_CANDIDATES,
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
        ? `staging/${userPrefix}/${sha}`
        : `staging/${userPrefix}/${assetId}`;

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

      if (!body.assetId || !body.r2Key)
        return json({ error: "missing assetId/r2Key" }, 400);

      const original = await env.STAGING.get(body.r2Key);
      if (!original)
        return json({ error: "object not found in R2 (upload failed?)" }, 404);

      const raw = await env.HOT.get(`asset:${body.assetId}`);
      if (!raw) return json({ error: "assetId not found/expired" }, 404);

      const hot = JSON.parse(raw) as HotAsset;

      const format = pickFormat(req, body);

      try {
        const imageData = await r2ObjectToImageData(env, original);
        const out = await encodeImage(env, imageData, format);

        const outHash = await sha256HexBytes(out.bytes.buffer);
        const convertedKey = `staging/converted/${outHash}.${out.ext}`;

        await env.STAGING.put(convertedKey, out.bytes, {
          httpMetadata: {
            contentType: out.mime,
            cacheControl: "public, max-age=31536000, immutable",
          },
        });

        // Delete original to save space (optional)
        ctx.waitUntil(env.STAGING.delete(body.r2Key));

        hot.r2Key = convertedKey;
        hot.mime = out.mime;
        hot.bytes = out.bytes.byteLength;

        await env.HOT.put(`asset:${body.assetId}`, JSON.stringify(hot), {
          expirationTtl: HOT_TTL_SECONDS,
        });

        ctx.waitUntil(
          persistToDrive(env, hot).catch((e) =>
            console.error("persistToDrive failed", e),
          ),
        );

        return json({
          ok: true,
          assetId: body.assetId,
          r2Key: convertedKey,
          mime: out.mime,
          bytes: out.bytes.byteLength,
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

    // Serve assets by assetId
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
