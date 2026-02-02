import { mkdir, copyFile } from "node:fs/promises";
import { dirname, join } from "node:path";

const outDir = join(process.cwd(), "public", "wasm");

const files = [
  // JPEG decoder
  {
    from: "node_modules/@jsquash/jpeg/codec/dec/mozjpeg_dec.wasm",
    to: "mozjpeg_dec.wasm",
  },
  // PNG codec
  {
    from: "node_modules/@jsquash/png/codec/pkg/squoosh_png_bg.wasm",
    to: "squoosh_png_bg.wasm",
  },
  // WebP decoder/encoder
  {
    from: "node_modules/@jsquash/webp/codec/dec/webp_dec.wasm",
    to: "webp_dec.wasm",
  },
  {
    from: "node_modules/@jsquash/webp/codec/enc/webp_enc.wasm",
    to: "webp_enc.wasm",
  },
  // AVIF encoder
  {
    from: "node_modules/@jsquash/avif/codec/enc/avif_enc.wasm",
    to: "avif_enc.wasm",
  },
];

await mkdir(outDir, { recursive: true });

for (const f of files) {
  const dest = join(outDir, f.to);
  await mkdir(dirname(dest), { recursive: true });
  await copyFile(join(process.cwd(), f.from), dest);
  console.log(`copied ${f.from} -> public/wasm/${f.to}`);
}
