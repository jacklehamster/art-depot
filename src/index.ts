/* eslint-disable no-console */

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
  r2Key: string; // points to ORIGINAL after upload-url; points to CONVERTED after commit
  mime: string;
  bytes: number;
  createdAt: number;

  // Keep original around so commit can always re-run if needed
  originalKey?: string;
  originalMime?: string;
  originalBytes?: number;
};

const enc = new TextEncoder();

const HOT_TTL_SECONDS = 12 * 60 * 60; // 12 hours
const PUT_URL_EXPIRES_SECONDS = 5 * 60;

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
  return (
    pathname === "/upload-url" ||
    pathname === "/commit" ||
    pathname.startsWith("/a/") || // serve (converted) asset
    pathname.startsWith("/o/") || // serve original asset (for cf image resizing fetch)
    pathname === "/api"
  );
}

async function persistToDrive(_env: Env, _hot: HotAsset) {}

function pickFormat(req: Request, body?: any): OutputFormat {
  if (body?.format === "webp") return "webp";
  const url = new URL(req.url);
  const f = (url.searchParams.get("format") || "").toLowerCase();
  return f === "webp" ? "webp" : "avif";
}

function extAndMime(format: OutputFormat) {
  return format === "webp"
    ? { ext: "webp", mime: "image/webp" }
    : { ext: "avif", mime: "image/avif" };
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
          "POST /commit?format=avif|webp  (converts using Cloudflare Image Resizing, then stores to R2)",
          "GET /a/:assetId  (serves converted if committed; otherwise original)",
          "GET /o/:assetId  (serves original; used internally by /commit)",
          "Static assets: everything else (via ASSETS binding)",
        ],
        note: "This version requires Cloudflare Image Resizing enabled on the zone. No WASM.",
      });
    }

    // ---- API: upload-url (unchanged) ----
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

      // store originals under original/
      const originalKey = sha
        ? `staging/original/${userPrefix}/${sha}`
        : `staging/original/${userPrefix}/${assetId}`;

      const putUrl = await presignR2Put(
        env,
        originalKey,
        PUT_URL_EXPIRES_SECONDS,
      );

      const hot: HotAsset = {
        assetId,
        r2Key: originalKey, // until commit happens
        mime,
        bytes,
        createdAt: Date.now(),
        originalKey,
        originalMime: mime,
        originalBytes: bytes,
      };

      await env.HOT.put(`asset:${assetId}`, JSON.stringify(hot), {
        expirationTtl: HOT_TTL_SECONDS,
      });

      return json({
        assetId,
        r2Key: originalKey,
        putUrl,
        expiresIn: PUT_URL_EXPIRES_SECONDS,
      });
    }

    // ---- API: serve original by assetId (internal for resize fetch, but also useful) ----
    {
      const m = url.pathname.match(/^\/o\/(.+)$/);
      if (m && req.method === "GET") {
        const assetId = m[1];
        const raw = await env.HOT.get(`asset:${assetId}`);
        if (!raw) return new Response("Not found (expired)", { status: 404 });

        const hot = JSON.parse(raw) as HotAsset;
        const originalKey = hot.originalKey || hot.r2Key;

        const obj = await env.STAGING.get(originalKey);
        if (!obj) return new Response("Not found in staging", { status: 404 });

        const headers = new Headers();
        headers.set(
          "content-type",
          hot.originalMime ||
            obj.httpMetadata?.contentType ||
            "application/octet-stream",
        );
        headers.set("cache-control", "private, max-age=0, no-store");

        return new Response(obj.body, { headers });
      }
    }

    // ---- API: commit (convert + store) ----
    if (url.pathname === "/commit" && req.method === "POST") {
      const body = (await req.json().catch(() => ({}))) as {
        assetId?: string;
        r2Key?: string; // original key (client sends it)
        mime?: string;
        bytes?: number;
        format?: OutputFormat;
      };

      if (!body.assetId || !body.r2Key)
        return json({ error: "missing assetId/r2Key" }, 400);

      // Verify original exists
      const head = await env.STAGING.head(body.r2Key);
      if (!head)
        return json({ error: "object not found in R2 (upload failed?)" }, 404);

      // Load HOT record
      const raw = await env.HOT.get(`asset:${body.assetId}`);
      if (!raw) return json({ error: "assetId not found/expired" }, 404);

      const hot = JSON.parse(raw) as HotAsset;

      // Keep original pointers stable
      hot.originalKey = hot.originalKey || body.r2Key;
      hot.originalMime = hot.originalMime || body.mime || hot.mime;
      hot.originalBytes =
        hot.originalBytes || body.bytes || hot.bytes || head.size || 0;

      const format = pickFormat(req, body);
      const { ext, mime: outMime } = extAndMime(format);

      // Fetch the original THROUGH our own endpoint and ask Cloudflare Image Resizing to transcode it.
      // This is the key: no WASM, no decoding in JS.
      const originalUrl = new URL(
        `/o/${encodeURIComponent(body.assetId)}`,
        url.origin,
      ).toString();

      let resized: Response;
      try {
        resized = await fetch(originalUrl, {
          cf: {
            image: {
              format,
              quality: format === "avif" ? 45 : 80,
              // keep original dimensions; no resize unless you add width/height
              // width: ..., height: ...,
            },
            // don't cache the transform at edge; we store it ourselves in R2
            cacheTtl: 0,
          } as any,
        });
      } catch (e) {
        return json(
          {
            error: "resize_fetch_failed",
            message: e instanceof Error ? e.message : String(e),
            hint: "If this is a Cloudflare zone, ensure Image Resizing is enabled.",
          },
          400,
        );
      }

      if (!resized.ok) {
        const txt = await resized.text().catch(() => "");
        return json(
          {
            error: "resize_failed",
            status: resized.status,
            body: txt.slice(0, 500),
            hint: "Cloudflare Image Resizing might not be enabled on this zone, or the input image type is unsupported.",
          },
          400,
        );
      }

      const outAb = await resized.arrayBuffer();
      const outBytes = new Uint8Array(outAb);

      // Dedup by converted bytes
      const outHash = await sha256HexBytes(outBytes.buffer);
      const convertedKey = `staging/converted/${outHash}.${ext}`;

      await env.STAGING.put(convertedKey, outBytes, {
        httpMetadata: {
          contentType: outMime,
          cacheControl: "public, max-age=31536000, immutable",
        },
      });

      // Optionally delete original to save space:
      // ctx.waitUntil(env.STAGING.delete(body.r2Key));

      // Update HOT to serve converted version via /a/:assetId
      hot.r2Key = convertedKey;
      hot.mime = outMime;
      hot.bytes = outBytes.byteLength;

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
        mime: outMime,
        bytes: outBytes.byteLength,
        format,
      });
    }

    // ---- Serve stored assets by assetId (converted if committed; else original) ----
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
        headers.set(
          "content-type",
          hot.mime ||
            obj.httpMetadata?.contentType ||
            "application/octet-stream",
        );
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
