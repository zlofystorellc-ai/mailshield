# MailShield

A Chrome (Manifest V3) extension that protects Gmail users from phishing, UPI/bank fraud, OTP scams and malicious links/attachments, backed by a Node.js + MongoDB service that **learns from user reports**. When users report a scam that was missed, similar reports are clustered into a signature, and once enough distinct users agree, similar future emails are flagged for everyone.

- **SAFE** (0–29): small green badge.
- **WARNING** (30–69): yellow banner with the reasons in plain language. Clicking a link asks for confirmation first.
- **BLOCK** (70–100): red banner. Link clicks open a full-page interstitial with the reasons, "what harm can happen", **Go back**, and a two-step **open anyway** (checkbox, then click). The override is logged.
- Every email gets **This is safe (false alarm)**, **Correctly flagged** and **Report as scam** buttons, plus an optional comment.
- UI in **English and Hinglish** (switch it in the popup).

```
.
├── extension/                 Chrome MV3 extension (load unpacked)
│   ├── manifest.json
│   ├── config.js              BACKEND_URL etc. (no secrets, ever)
│   ├── background.js          service worker: auth, API calls, 24h verdict cache, 6h signature sync, offline queue
│   ├── lib/                   SHARED ENGINE (also copied into the server and used by the Jest tests)
│   │   ├── brands.js          brand → legit domains, free-mail, shorteners, suspicious TLDs, verified senders
│   │   ├── heuristics.js      local rule engine: {id, weight, reason, reasonHi, harmType}
│   │   ├── normalize.js       normalization for matching (amounts/dates/names/numbers → placeholders)
│   │   ├── simhash.js         64-bit SimHash, Hamming distance, local embedding
│   │   ├── signatures.js      build/match scam signatures
│   │   ├── redact.js          client-side PII redaction
│   │   ├── harms.js           threatType → harm text (EN + Hinglish)
│   │   └── i18n.js            UI strings (EN + Hinglish)
│   ├── content/
│   │   ├── selectors.js       ← ALL Gmail DOM selectors (see GMAIL_SELECTORS.md)
│   │   ├── extract.js         sender / subject / body / links / attachments
│   │   ├── ui.js              Shadow-DOM banners, dialogs, interstitial, report dialog
│   │   └── main.js            MutationObserver, scan flow, link-click interception
│   ├── popup/                 toggle, language, cloud consent, allow/block lists, stats, delete data
│   └── onboarding/            first-run consent page
├── server/                    Node.js + Express + Mongoose API
│   ├── src/
│   │   ├── models/index.js    all collections + indexes (spec §7)
│   │   ├── services/          reputation (SB/VT/URLhaus/RDAP), embeddings, llm, scoring,
│   │   │                      scanService (pipeline), clustering, signatureService, trust, verified
│   │   ├── routes/            api.js (extension), admin.js (role-protected), schemas.js (zod)
│   │   ├── middleware/        JWT auth, zod validation, per-install rate limits, timeouts
│   │   ├── workers/           analysisWorker.js (report → cluster → signature)
│   │   └── shared/            auto-copied from extension/lib (`npm run sync-shared`)
│   ├── atlas/                 Atlas Vector Search index definitions
│   ├── scripts/               sync-shared.js, seed.js
│   └── tests/                 Jest tests + fixtures
├── admin/                     admin panel (plain HTML/JS, served at /admin)
├── docker-compose.yml         server + MongoDB for local dev
├── .env.example
├── privacy-policy.md
└── GMAIL_SELECTORS.md
```

## Architecture

```
Gmail tab ──content script (local heuristics, instant)──► background service worker ──HTTPS/JWT──► Express API ──► MongoDB (Atlas)
                                                                                                    │
                                     Safe Browsing · VirusTotal · URLhaus · RDAP · embeddings · LLM ◄┘
```

- The extension holds **no** database credentials or third-party API keys. It authenticates with an anonymous install ID → JWT (`POST /api/auth/register`).
- The local engine always runs first and alone if the backend or any third-party API is down. The backend wraps every external call in a timeout and degrades to "unknown". The content script wraps everything in try/catch, so Gmail never breaks.
- **No data leaves the browser until the user consents** on the onboarding page. Before that, MailShield runs in local-only mode.

### Scan pipeline (`POST /api/scan`)

1. user allowlist/blocklist (domains, exact free-mail addresses, and templates the user reported) → 2. global blocklist → 3. `url_reputation` cache (24h TTL) → 4. Google Safe Browsing v4, VirusTotal, URLhaus → 5. RDAP domain age (<30 days = risk) → 6. scam-signature matching → 7. optional LLM (only for opted-in users, only in the uncertain 15–69 band) → 8. weighted combination with the local score. Verified senders are capped at 20 unless there's hard evidence (Safe Browsing/URLhaus/blocklist). Only features and hashes are stored; the body is never stored.

### Learning loop (report → analyze → auto-warn)

1. **Report as scam** → dialog with category, comment, **redacted preview**, and an explicit consent checkbox. PII is redacted in the browser (account/card → `<ACCOUNT>`, phone → `<PHONE>`, email → `<EMAIL>`, UPI → `<UPI>`, OTP-like codes → `<CODE>`, PAN/Aadhaar → `<ID>`, the user's own name/email → `<USER>`) and again on the server.
2. `POST /api/report` stores the report and **immediately** adds the sender to that user's personal blocklist (the exact address for free-mail senders, otherwise the domain). Reports about verified senders are held for an admin.
3. The worker normalizes the text, computes a 64-bit SimHash and an embedding, and finds neighbors using Hamming ≤ 6, cosine ≥ 0.85 (Atlas `$vectorSearch` when enabled), token/concept overlap, or a match against an existing cluster's template/signature. It also stores a personal *template* block, so the reporter is warned about look-alikes straight away.
4. A cluster reported by ≥ `REPORT_THRESHOLD` distinct, trusted users becomes a `pending_review` signature. At ≥ `AUTO_ACTIVATE_THRESHOLD` it auto-activates. Admins can approve or reject at any time. An optional LLM writes the EN/Hinglish reason text.
5. Each activation or change bumps a global version. Extensions pull `GET /api/signatures?sinceVersion=X` every 6 hours and match locally, so this also works offline. A match adds **+40** with a minimum of WARNING: *"Similar to a fake payment / 'sent by mistake' scam reported by N users"*.

**Why not SimHash alone?** Re-worded variants of the same scam (different amounts, names, English vs. Hinglish) are typically 16–25 bits apart, so Hamming ≤ 6 only catches near-copies. MailShield also collapses synonyms to concepts (`credited/sent/bheja → money_in`, `mistake/galti/error → mistake`, …) and matches on the cluster's shared concept keywords. The tests show all 5 fake-credit variants (including a Hinglish one) landing in one cluster and matching one signature, while genuine bank alerts and normal mail don't match.

**Abuse protection:** at least 2 distinct users are always required, so one user can never create or activate a signature alone. Reports are rate-limited per install (default 20/day). Reporters carry a `trustScore`: admin-confirmed reports raise it (+0.2), rejected ones lower it (−0.3), and reporters below 0.3 don't count. Verified senders (built-in bank/government/brand list plus the admin-managed `verified_senders`) are never auto-blocked or turned into signatures. "False alarm" feedback lowers a signature's confidence, and enough of it sends the signature back to `pending_review`.

## Setup

### 1. Backend (local, Docker)

```bash
cp .env.example .env
```

Set `JWT_SECRET` and `ADMIN_SECRET` in `.env` (for example with `openssl rand -hex 32`), then:

```bash
docker compose up --build
```

The API runs at http://localhost:3000 (`/healthz`), and the admin panel at http://localhost:3000/admin.

### 1b. Backend (without Docker)

```bash
cd server && npm install && npm run seed && npm run dev
```

You need MongoDB at `MONGODB_URI`. `npm run seed` loads the built-in verified senders and syncs the indexes.

### 2. Load the extension

1. Open `chrome://extensions` and turn on **Developer mode**.
2. Click **Load unpacked** and pick the `extension/` folder.
3. The onboarding page opens. Choose **Enable cloud protection** (or stay local-only).
4. Open Gmail and open an email.

The backend URL is `BACKEND_URL` in `extension/config.js`, and it must also appear in `host_permissions` in `manifest.json`. For production, replace `https://api.mailshield.example.com/*` with your API origin and remove the localhost entry. Then set `EXTENSION_ORIGIN=chrome-extension://<your-extension-id>` on the server so CORS only accepts your extension. Icons aren't included: add `icons` (16/48/128 px) to the manifest before publishing.

### 3. Run the tests

```bash
cd server && npm test
```

`pretest` copies `extension/lib` into `server/src/shared` first, so the tests always exercise the exact code that ships in the extension. The suite covers the heuristic engine, scoring, PII redaction, normalization, clustering and signature matching (106 tests).

## API keys (all optional)

| Key | Where to get it | Notes |
|---|---|---|
| `SAFE_BROWSING_KEY` | Google Cloud Console → enable **Safe Browsing API** → Credentials → API key | Free. Check Google's terms for commercial use; the Web Risk API is the commercial option. |
| `VIRUSTOTAL_KEY` | virustotal.com → sign up → API key | The free tier is 4 requests/min, so MailShield checks at most 5 URLs per scan and caches results for 24h. |
| `URLHAUS_KEY` | auth.abuse.ch → sign in → Auth-Key | Free. Required by the URLhaus API. |
| `EMBEDDING_API_KEY` | e.g. OpenAI (`EMBEDDING_PROVIDER=openai`) | Without it, the built-in local embedding is used. |
| `LLM_API_KEY` | Anthropic (`LLM_PROVIDER=anthropic`) or OpenAI | Optional. Only used for users who enable "AI analysis" in the popup, and for cluster summaries. Only normalized, redacted text is sent. |

RDAP (domain age) needs no key.

## Atlas Vector Search indexes

Vector search is optional: with `ATLAS_VECTOR_SEARCH=false` (the default), clustering and matching use SimHash, keywords and in-process cosine. To enable it on MongoDB Atlas:

1. Atlas UI → your cluster → **Atlas Search** → **Create Search Index** → **Atlas Vector Search – JSON editor**.
2. Create `reported_messages_embedding` on collection `reported_messages` using `server/atlas/reported_messages_embedding.json`.
3. Create `scam_signatures_embedding` on collection `scam_signatures` using `server/atlas/scam_signatures_embedding.json`.
4. Set `numDimensions` to your `EMBEDDING_DIM`: 256 for `local`, 1536 for OpenAI `text-embedding-3-small`. Don't mix providers in one database.
5. Set `ATLAS_VECTOR_SEARCH=true`.

Atlas reports cosine as `(1 + cos) / 2`, and the code converts that back before comparing it with `COSINE_THRESHOLD`.

## Deploying (Render or Railway + MongoDB Atlas)

1. **Atlas:** create a cluster (M0 works to start), a database user, and a network-access rule. Copy the `mongodb+srv://…` URI.
2. **Render:** New → **Web Service** → connect the repo → Environment **Docker** → Dockerfile path `server/Dockerfile`, root/context = repo root. **Railway:** New project → Deploy from repo → set the `RAILWAY_DOCKERFILE_PATH=server/Dockerfile` variable.
3. Add the environment variables from `.env.example`: `NODE_ENV=production`, `MONGODB_URI`, `JWT_SECRET`, `ADMIN_SECRET`, `EXTENSION_ORIGIN`, plus any API keys.
4. Health check path: `/healthz`.
5. Run the seed once from your machine with the production URI: `cd server && MONGODB_URI=... npm run seed`.
6. Put the service URL into `extension/config.js` (`BACKEND_URL`, `PRIVACY_URL`) and `manifest.json` (`host_permissions`), then pack or publish the extension.
7. Scaling: set `RUN_WORKER=false` on web instances and run one or more `npm run worker` processes. Claims are atomic, so several workers are safe.

## Admin panel

Open `/admin` and sign in with `ADMIN_SECRET`. The admin JWT lasts 8 hours and is kept in sessionStorage.

- **Dashboard:** scans, warnings, blocks, overrides, reports and false alarms per day.
- **Clusters:** redacted samples, report count, distinct users, suggested category and keywords. You can re-evaluate, approve or reject from here.
- **Signatures:** approve, reject, or edit the EN/Hinglish reason text. Edits bump the version so extensions pick them up.
- **False alarms:** review feedback, and optionally mark a sender as verified.
- **Blocklist:** domains reported by ≥ 2 users can be promoted to the global blocklist. Verified domains are refused.
- **Held reports** (about verified senders) and **Verified senders** management.

## Security notes

- helmet with a strict CSP; CORS limited to the extension origin; zod validation on every input; per-install rate limits; JWTs; constant-time admin secret check; request and external-call timeouts.
- All injected UI uses closed Shadow DOM, and email-derived strings are only ever set via `textContent`. The admin panel follows the same rule for reported content.
- **Limitation:** the extension sees what Gmail renders. It can't verify SPF/DKIM itself, so a forged `From:` on a verified domain would look verified. Gmail's own authentication warnings still apply, and Safe Browsing/URLhaus hits override the verified cap.

## Gmail selectors

All Gmail DOM selectors are in **`extension/content/selectors.js`**. See [GMAIL_SELECTORS.md](GMAIL_SELECTORS.md) for how to update them when Gmail changes its markup.
