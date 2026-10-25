const path = require('path');
const dotenv = require('dotenv');

// Root .env (used by docker-compose) first, then server/.env; neither overrides real env vars.
dotenv.config({ path: path.resolve(__dirname, '../../.env') });
dotenv.config({ path: path.resolve(__dirname, '../.env') });

const int = (v, d) => (v === undefined || v === '' ? d : parseInt(v, 10));
const float = (v, d) => (v === undefined || v === '' ? d : parseFloat(v));
const bool = (v, d) => (v === undefined || v === '' ? d : /^(1|true|yes)$/i.test(v));

const env = process.env.NODE_ENV || 'development';

const config = {
  env,
  port: int(process.env.PORT, 3000),
  mongoUri: process.env.MONGODB_URI || 'mongodb://localhost:27017/mailshield',
  jwtSecret: process.env.JWT_SECRET || (env === 'production' ? null : 'dev-only-insecure-secret'),
  jwtExpiresIn: process.env.JWT_EXPIRES_IN || '180d',
  adminSecret: process.env.ADMIN_SECRET || '',
  // e.g. chrome-extension://abcdefghijklmnopabcdefghijklmnop (comma-separated allowed)
  extensionOrigins: (process.env.EXTENSION_ORIGIN || '').split(',').map((s) => s.trim()).filter(Boolean),
  // Unpacked installs get a different extension ID on every machine; allow any chrome-extension:// origin
  // until the Web Store ID is fixed (requests still need a valid install JWT).
  allowAnyExtensionOrigin: bool(process.env.ALLOW_ANY_EXTENSION_ORIGIN, false),
  runWorker: bool(process.env.RUN_WORKER, true),
  requestTimeoutMs: int(process.env.REQUEST_TIMEOUT_MS, 10000),
  externalTimeoutMs: int(process.env.EXTERNAL_TIMEOUT_MS, 3500),

  keys: {
    safeBrowsing: process.env.SAFE_BROWSING_KEY || '',
    virusTotal: process.env.VIRUSTOTAL_KEY || '',
    urlhaus: process.env.URLHAUS_KEY || '',
  },
  embedding: {
    provider: process.env.EMBEDDING_PROVIDER || 'local', // local | openai
    apiKey: process.env.EMBEDDING_API_KEY || '',
    model: process.env.EMBEDDING_MODEL || 'text-embedding-3-small',
    dim: int(process.env.EMBEDDING_DIM, process.env.EMBEDDING_PROVIDER === 'openai' ? 1536 : 256),
  },
  llm: {
    provider: process.env.LLM_PROVIDER || 'none', // none | anthropic | openai
    apiKey: process.env.LLM_API_KEY || '',
    model: process.env.LLM_MODEL || (process.env.LLM_PROVIDER === 'openai' ? 'gpt-4o-mini' : 'claude-haiku-5-5'),
  },
  atlasVectorSearch: bool(process.env.ATLAS_VECTOR_SEARCH, false),

  learning: {
    reportThreshold: int(process.env.REPORT_THRESHOLD, 3),
    autoActivateThreshold: int(process.env.AUTO_ACTIVATE_THRESHOLD, 10),
    simhashDistance: int(process.env.SIMHASH_DISTANCE, 6),
    cosine: float(process.env.COSINE_THRESHOLD, 0.85),
    minTrust: float(process.env.MIN_REPORTER_TRUST, 0.3),
    falseAlarmMin: int(process.env.FALSE_ALARM_MIN, 3),
    falseAlarmRatio: float(process.env.FALSE_ALARM_RATIO, 0.3),
    reportsPerDay: int(process.env.REPORTS_PER_DAY, 20),
    signatureMatchBoost: 40,
  },
};

if (!config.jwtSecret) throw new Error('JWT_SECRET must be set in production');

module.exports = config;
