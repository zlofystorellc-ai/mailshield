/*
 * Generates extension/icons/icon{16,32,48,128}.png (a blue shield with a white check mark)
 * with no image dependencies: shapes are rasterized with 4x4 supersampling and written as PNG via zlib.
 * Usage: node scripts/make-icons.js
 */
const fs = require('fs');
const path = require('path');
const zlib = require('zlib');

const OUT = path.resolve(__dirname, '../extension/icons');
const SIZES = [16, 32, 48, 128];
const BLUE = [26, 115, 232];
const DARK = [13, 71, 161];
const WHITE = [255, 255, 255];

// Shield outline in a 0..1 box: flat top with rounded corners, sides curving to a point at the bottom.
function inShield(x, y) {
  if (y < 0.06 || y > 0.96) return false;
  const half = y < 0.5 ? 0.40 : 0.40 * Math.sqrt(Math.max(0, 1 - ((y - 0.5) / 0.46) ** 2));
  if (Math.abs(x - 0.5) > half) return false;
  if (y < 0.16) { // rounded top corners
    const cx = x < 0.5 ? 0.20 : 0.80;
    if (Math.abs(x - 0.5) > 0.30 && (x - cx) ** 2 + (y - 0.16) ** 2 > 0.10 ** 2) return false;
  }
  return true;
}

function distToSegment(px, py, ax, ay, bx, by) {
  const dx = bx - ax; const dy = by - ay;
  const t = Math.max(0, Math.min(1, ((px - ax) * dx + (py - ay) * dy) / (dx * dx + dy * dy)));
  return Math.hypot(px - (ax + t * dx), py - (ay + t * dy));
}

function inCheck(x, y) {
  const w = 0.075;
  return distToSegment(x, y, 0.30, 0.50, 0.44, 0.64) < w || distToSegment(x, y, 0.44, 0.64, 0.71, 0.36) < w;
}

function render(size) {
  const px = Buffer.alloc(size * size * 4);
  const S = 4;
  for (let j = 0; j < size; j++) {
    for (let i = 0; i < size; i++) {
      let r = 0; let g = 0; let b = 0; let a = 0;
      for (let sy = 0; sy < S; sy++) {
        for (let sx = 0; sx < S; sx++) {
          const x = (i + (sx + 0.5) / S) / size;
          const y = (j + (sy + 0.5) / S) / size;
          if (!inShield(x, y)) continue;
          const c = inCheck(x, y) ? WHITE : (x > 0.5 ? DARK : BLUE); // two-tone body
          r += c[0]; g += c[1]; b += c[2]; a += 1;
        }
      }
      const o = (j * size + i) * 4;
      if (a) { px[o] = r / a; px[o + 1] = g / a; px[o + 2] = b / a; }
      px[o + 3] = Math.round((255 * a) / (S * S));
    }
  }
  return px;
}

const CRC = (() => {
  const t = new Uint32Array(256);
  for (let n = 0; n < 256; n++) { let c = n; for (let k = 0; k < 8; k++) c = c & 1 ? 0xedb88320 ^ (c >>> 1) : c >>> 1; t[n] = c >>> 0; }
  return (buf) => { let c = 0xffffffff; for (const byte of buf) c = t[(c ^ byte) & 0xff] ^ (c >>> 8); return (c ^ 0xffffffff) >>> 0; };
})();

function chunk(type, data) {
  const len = Buffer.alloc(4); len.writeUInt32BE(data.length);
  const td = Buffer.concat([Buffer.from(type), data]);
  const crc = Buffer.alloc(4); crc.writeUInt32BE(CRC(td));
  return Buffer.concat([len, td, crc]);
}

function png(size, rgba) {
  const ihdr = Buffer.alloc(13);
  ihdr.writeUInt32BE(size, 0); ihdr.writeUInt32BE(size, 4);
  ihdr[8] = 8; ihdr[9] = 6; // 8-bit RGBA
  const raw = Buffer.alloc((size * 4 + 1) * size);
  for (let y = 0; y < size; y++) rgba.copy(raw, y * (size * 4 + 1) + 1, y * size * 4, (y + 1) * size * 4);
  return Buffer.concat([
    Buffer.from([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a]),
    chunk('IHDR', ihdr), chunk('IDAT', zlib.deflateSync(raw)), chunk('IEND', Buffer.alloc(0)),
  ]);
}

fs.mkdirSync(OUT, { recursive: true });
for (const s of SIZES) fs.writeFileSync(path.join(OUT, `icon${s}.png`), png(s, render(s)));
console.log(`[icons] wrote ${SIZES.map((s) => `icon${s}.png`).join(', ')} to extension/icons`);
