/*
 * Builds a shareable extension package pointed at a public backend.
 *   node scripts/build-extension.js https://mailshield-api.onrender.com
 * Output: dist/mailshield-extension/ (load unpacked) and dist/mailshield-extension.zip (to share / upload).
 * The source extension/ folder is not modified, so local development keeps using localhost.
 */
const fs = require('fs');
const path = require('path');
const { execFileSync } = require('child_process');

const backend = (process.argv[2] || '').replace(/\/+$/, '');
if (!/^https:\/\/[a-z0-9.-]+(:\d+)?$/i.test(backend)) {
  console.error('Usage: node scripts/build-extension.js https://your-api.onrender.com   (HTTPS origin, no path)');
  process.exit(1);
}

const ROOT = path.resolve(__dirname, '..');
const SRC = path.join(ROOT, 'extension');
const DIST = path.join(ROOT, 'dist');
const OUT = path.join(DIST, 'mailshield-extension');

fs.rmSync(OUT, { recursive: true, force: true });
fs.mkdirSync(DIST, { recursive: true });
fs.cpSync(SRC, OUT, { recursive: true });

// config.js -> public backend
const cfgPath = path.join(OUT, 'config.js');
let cfg = fs.readFileSync(cfgPath, 'utf8');
cfg = cfg.replace(/BACKEND_URL:\s*'[^']*'/, `BACKEND_URL: '${backend}'`).replace(/PRIVACY_URL:\s*'[^']*'/, `PRIVACY_URL: '${backend}/privacy'`);
fs.writeFileSync(cfgPath, cfg);

// manifest -> only Gmail + the public backend
const manPath = path.join(OUT, 'manifest.json');
const manifest = JSON.parse(fs.readFileSync(manPath, 'utf8'));
manifest.host_permissions = ['https://mail.google.com/*', `${backend}/*`];
fs.writeFileSync(manPath, JSON.stringify(manifest, null, 2) + '\n');

// zip (macOS/Linux `zip`), excluding Finder junk
const zipPath = path.join(DIST, 'mailshield-extension.zip');
fs.rmSync(zipPath, { force: true });
execFileSync('zip', ['-rq', zipPath, '.', '-x', '*.DS_Store'], { cwd: OUT });

console.log(`[build] backend:  ${backend}`);
console.log(`[build] folder:   ${OUT}`);
console.log(`[build] zip:      ${zipPath} (${(fs.statSync(zipPath).size / 1024).toFixed(0)} KB)`);
