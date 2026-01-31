// 1) Ask for upload URL
const init = await fetch("/upload-url", {
  method: "POST",
  headers: { "content-type": "application/json" },
  body: JSON.stringify({ userId, sha256, mime: file.type, bytes: file.size }),
});
const { assetId, r2Key, putUrl } = await init.json();

// 2) Upload directly to R2
const put = await fetch(putUrl, {
  method: "PUT",
  headers: { "content-type": file.type || "application/octet-stream" },
  body: file,
});
if (!put.ok) throw new Error(`R2 upload failed: ${put.status}`);

// 3) Commit
await fetch("/commit", {
  method: "POST",
  headers: { "content-type": "application/json" },
  body: JSON.stringify({ assetId, r2Key, mime: file.type, bytes: file.size }),
});
