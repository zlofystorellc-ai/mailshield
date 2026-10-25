/*
 * The heuristic engine, normalizer, SimHash, redaction and harm mapping are written ONCE in
 * /extension/lib (classic scripts for the browser). This copies them into server/src/shared so the
 * server (and its Docker image, which doesn't include /extension) uses byte-identical logic.
 */
const fs = require('fs');
const path = require('path');

const src = path.resolve(__dirname, '../../extension/lib');
const dst = path.resolve(__dirname, '../src/shared');
const FILES = ['brands.js', 'redact.js', 'normalize.js', 'simhash.js', 'harms.js', 'signatures.js', 'heuristics.js'];

if (!fs.existsSync(src)) {
  console.log('[sync-shared] extension/lib not found; keeping existing server/src/shared copy');
  process.exit(0);
}
fs.mkdirSync(dst, { recursive: true });
for (const f of FILES) {
  const body = fs.readFileSync(path.join(src, f), 'utf8');
  fs.writeFileSync(path.join(dst, f), '/* AUTO-COPIED from extension/lib by scripts/sync-shared.js — edit the original. */\n' + body);
}
console.log(`[sync-shared] copied ${FILES.length} files to src/shared`);
