/* eslint-disable no-console */

import avifEncode, { init as initAvifEncode } from "@jsquash/avif/encode";
import webpEncode, { init as initWebpEncode } from "@jsquash/webp/encode";

import jpegDecode, { init as initJpegDecode } from "@jsquash/jpeg/decode";
import pngDecode, { init as initPngDecode } from "@jsquash/png/decode";
import webpDecode, { init as initWebpDecode } from "@jsquash/webp/decode";

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

const HOT_TTL_SECONDS = 12 * 60 * 60; // 12 hours
const PUT_URL_EXPIRES_SECONDS = 5 * 60;

const enc = new TextEncoder();

function json(data: unknown, status = 200) {
  return new Response(JSON.stringify(data), {
    status,
    headers: { "content-type": "application/json; charset=utf-8" },
  });
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

function isApiRoute(pathname: string) {
  // Keep static assets clean by reserving these
  return (
    pathname === "/upload-url" ||
    pathname === "/commit" ||
    pathname.startsWith("/a/") ||
    pathname === "/api"
  );
}

async function persistToDrive(_env: Env, _hot: HotAsset) {}

function pickFormatFromBody(body: any): OutputFormat {
  return body?.format === "webp" ? "webp" : "avif";
}

/**
 * --- jSquash WASM loading ---
 * We avoid deep-importing *.wasm from node_modules (often breaks with TS/package exports),
 * and instead initialize codecs with locateFile so they can fetch their own WASM.
 *
 * This keeps your server API stable, and fixes JPEG decode failures in Workers.
 */
const JSQUASH_VERSIONS = {
  avif: "2.1.1",
  webp: "1.5.0",
  jpeg: "1.4.0",
  png: "3.0.1",
} as const;

// You can swap unpkg -> cdn.jsdelivr.net if you prefer.
const CDN = "https://unpkg.com";

function locateFileFor(pkgName: string, version: string) {
  return (path: string, prefix: string) => {
    const p = (prefix || "").replace(/^\//, "");
    const joined = p ? `${p}${path}` : path;
    return `${CDN}/${pkgName}@${version}/${joined}`;
  };
}

let codecsInitPromise: Promise<void> | null = null;

async function ensureCodecsInit() {
  if (codecsInitPromise) return codecsInitPromise;

  codecsInitPromise = (async () => {
    // decode
    await Promise.resolve(
      initJpegDecode({
        locateFile: locateFileFor("@jsquash/jpeg", JSQUASH_VERSIONS.jpeg),
      }),
    );

    await Promise.resolve(
      initPngDecode({
        locateFile: locateFileFor("@jsquash/png", JSQUASH_VERSIONS.png),
      }),
    );

    await Promise.resolve(
      initWebpDecode({
        locateFile: locateFileFor("@jsquash/webp", JSQUASH_VERSIONS.webp),
      }),
    );

    // encode
    await Promise.resolve(
      initAvifEncode({
        locateFile: locateFileFor("@jsquash/avif", JSQUASH_VERSIONS.avif),
      }),
    );

    await Promise.resolve(
      initWebpEncode({
        locateFile: locateFileFor("@jsquash/webp", JSQUASH_VERSIONS.webp),
      }),
    );
  })();

  return codecsInitPromise;
}

async function decodeToImageData(
  ab: ArrayBuffer,
  mime: string,
): Promise<ImageData> {
  await ensureCodecsInit();

  const m = (mime || "").toLowerCase();
  if (m === "image/jpeg" || m === "image/jpg")
    return (await jpegDecode(ab)) as any;
  if (m === "image/png") return (await pngDecode(ab)) as any;
  if (m === "image/webp") return (await webpDecode(ab)) as any;

  throw new Error(
    `Unsupported input for conversion: ${mime || "unknown"}. Try JPEG/PNG/WebP.`,
  );
}

async function r2ObjectToImageData(obj: R2ObjectBody): Promise<ImageData> {
  const ab = await obj.arrayBuffer();
  const contentType =
    obj.httpMetadata?.contentType || "application/octet-stream";

  // Try fast path first (if Worker runtime supports decoding that mime)
  try {
    const blob = new Blob([ab], { type: contentType });
    const bmp = await createImageBitmap(blob);

    const canvas = new OffscreenCanvas(bmp.width, bmp.height);
    const ctx = canvas.getContext("2d");
    if (!ctx) throw new Error("Failed to get 2d context");
    ctx.drawImage(bmp, 0, 0);
    bmp.close();

    return ctx.getImageData(0, 0, canvas.width, canvas.height);
  } catch {
    // Fallback: wasm decoders (fixes JPEG failures in Workers)
    return decodeToImageData(ab, contentType);
  }
}

async function encodeImage(
  imageData: ImageData,
  format: OutputFormat,
): Promise<{ bytes: Uint8Array; mime: string; ext: string }> {
  await ensureCodecsInit();

  if (format === "webp") {
    const ab = await webpEncode(imageData, { quality: 80 } as any);
    return { bytes: new Uint8Array(ab), mime: "image/webp", ext: "webp" };
  }

  const ab = await avifEncode(imageData, { quality: 45 } as any);
  return { bytes: new Uint8Array(ab), mime: "image/avif", ext: "avif" };
}

export default {
  async fetch(
    req: Request,
    env: Env,
    ctx: ExecutionContext,
  ): Promise<Response> {
    const url = new URL(req.url);

    // Serve a simple API descriptor
    if (url.pathname === "/api" && req.method === "GET") {
      return json({
        ok: true,
        routes: [
          "POST /upload-url",
          "POST /commit",
          "GET /a/:assetId",
          "Static assets: everything else (via ASSETS binding)",
        ],
        note: "Flow unchanged: presigned PUT upload, then /commit converts+stores AVIF/WebP",
      });
    }

    // ---- API routes ----
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

    /**
     * Commit: convert what was uploaded to R2 into AVIF or WebP and update HOT mapping
     * (flow preserved; conversion happens server-side *before storing final key*).
     */
    if (url.pathname === "/commit" && req.method === "POST") {
      const body = (await req.json().catch(() => ({}))) as {
        assetId?: string;
        r2Key?: string;
        mime?: string;
        bytes?: number;
        format?: OutputFormat; // NEW optional: "avif" | "webp" (default avif)
      };

      if (!body.assetId || !body.r2Key)
        return json({ error: "missing assetId/r2Key" }, 400);

      // Verify object exists
      const original = await env.STAGING.get(body.r2Key);
      if (!original)
        return json({ error: "object not found in R2 (upload failed?)" }, 404);

      // Load HOT record
      const raw = await env.HOT.get(`asset:${body.assetId}`);
      if (!raw) return json({ error: "assetId not found/expired" }, 404);

      const hot = JSON.parse(raw) as HotAsset;

      // Convert
      let outBytes: Uint8Array;
      let outMime: string;
      let outExt: string;

      try {
        const format = pickFormatFromBody(body);
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

      // Store converted object (hash by converted bytes for dedupe)
      const outHash = await sha256HexBytes(outBytes.buffer);
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

      // Fire-and-forget persistence (no paid features)
      ctx.waitUntil(
        persistToDrive(env, hot).catch((err) => {
          console.error("persistToDrive failed", err);
        }),
      );

      return json({
        ok: true,
        assetId: body.assetId,
        r2Key: convertedKey,
        mime: outMime,
        bytes: outBytes.byteLength,
      });
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
        // Cache reads for 1 hour at edge
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
