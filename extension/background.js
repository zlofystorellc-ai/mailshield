/*
 * MailShield background service worker (MV3).
 * - Owns all network calls (content scripts never talk to the backend directly).
 * - Anonymous install ID + JWT auth, 24h verdict cache, 6-hourly signature sync, offline queue.
 * - Nothing is sent to the backend until the user consents on the onboarding page.
 */
importScripts('config.js');

const CFG = self.MAILSHIELD_CONFIG;
const DEFAULT_SETTINGS = { enabled: true, language: 'en', aiEnabled: false, consented: false };
const DEFAULT_STATS = { scanned: 0, warnings: 0, blocked: 0, reports: 0 };
const MAX_CACHE = 500;
const MAX_QUEUE = 50;

const store = {
  get: (keys) => chrome.storage.local.get(keys),
  set: (obj) => chrome.storage.local.set(obj),
};

async function init(reason) {
  const s = await store.get(['installId', 'settings', 'stats', 'allowlist', 'blocklist', 'signatures']);
  await store.set({
    installId: s.installId || crypto.randomUUID(),
    settings: { ...DEFAULT_SETTINGS, ...(s.settings || {}) },
    stats: { ...DEFAULT_STATS, ...(s.stats || {}) },
    allowlist: s.allowlist || [],
    blocklist: s.blocklist || [],
    signatures: s.signatures || { version: 0, items: {} },
  });
  chrome.alarms.create('sync', { periodInMinutes: CFG.SIGNATURE_SYNC_MINUTES, delayInMinutes: 1 });
  if (reason === 'install' || reason === 'update') await store.set({ verdicts: {} }); // new rules -> drop cached verdicts
  if (reason === 'install') chrome.tabs.create({ url: chrome.runtime.getURL('onboarding/onboarding.html') });
}

chrome.runtime.onInstalled.addListener(({ reason }) => init(reason));
chrome.runtime.onStartup.addListener(() => init('startup'));
chrome.alarms.onAlarm.addListener((a) => { if (a.name === 'sync') syncAll().catch(() => {}); });

// ---------------- backend client ----------------
class ApiError extends Error {
  constructor(message, status) { super(message); this.status = status; }
}

async function register() {
  const { installId } = await store.get('installId');
  const res = await timedFetch(`${CFG.BACKEND_URL}/api/auth/register`, {
    method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ installId }),
  });
  if (!res.ok) throw new ApiError('register_failed', res.status);
  const { token } = await res.json();
  await store.set({ token });
  return token;
}

async function timedFetch(url, opts) {
  const ctrl = new AbortController();
  const timer = setTimeout(() => ctrl.abort(), CFG.REQUEST_TIMEOUT_MS);
  try {
    return await fetch(url, { ...opts, signal: ctrl.signal });
  } catch (e) {
    throw new ApiError('network', 0); // offline / timeout / server down
  } finally {
    clearTimeout(timer);
  }
}

async function api(path, { method = 'GET', body, retry = true } = {}) {
  const { token: saved, settings } = await store.get(['token', 'settings']);
  if (!settings || !settings.consented) throw new ApiError('no_consent', -1);
  const token = saved || await register();
  const res = await timedFetch(`${CFG.BACKEND_URL}/api${path}`, {
    method,
    headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${token}` },
    body: body ? JSON.stringify(body) : undefined,
  });
  if (res.status === 401 && retry) {
    await store.set({ token: null });
    return api(path, { method, body, retry: false });
  }
  const data = await res.json().catch(() => ({}));
  if (!res.ok) throw new ApiError(data.error || `http_${res.status}`, res.status);
  return data;
}

/** For fire-and-forget writes: queue when offline, flush on next sync. */
async function apiOrQueue(path, body) {
  try {
    await api(path, { method: 'POST', body });
    return { ok: true };
  } catch (e) {
    if (e.status === 0 || e.status >= 500) {
      const { queue = [] } = await store.get('queue');
      queue.push({ path, body, at: Date.now() });
      await store.set({ queue: queue.slice(-MAX_QUEUE) });
      return { ok: true, queued: true };
    }
    return { ok: false, error: e.message, status: e.status };
  }
}

async function flushQueue() {
  const { queue = [] } = await store.get('queue');
  if (!queue.length) return;
  const remaining = [];
  for (const item of queue) {
    try { await api(item.path, { method: 'POST', body: item.body }); } catch (e) {
      if (e.status === 0 || e.status >= 500) remaining.push(item); // retry later; drop 4xx
    }
  }
  await store.set({ queue: remaining });
}

// ---------------- sync ----------------
async function syncSignatures() {
  const { signatures = { version: 0, items: {} } } = await store.get('signatures');
  let data = await api(`/signatures?sinceVersion=${signatures.version}`);
  let items = { ...signatures.items };
  if (data.version < signatures.version) { // server was reset -> full resync
    data = await api('/signatures?sinceVersion=0');
    items = {};
  }
  data.signatures.forEach((s) => { items[s.signatureId] = s; });
  data.removed.forEach((id) => { delete items[id]; });
  await store.set({ signatures: { version: data.version, items, syncedAt: Date.now() } });
}

async function syncLists() {
  const [allow, block] = await Promise.all([api('/allowlist'), api('/blocklist')]);
  await store.set({ allowlist: allow.items.map((i) => i.domain), blocklist: block.items.map((i) => i.domain) });
}

async function syncAll() {
  const { settings } = await store.get('settings');
  if (!settings || !settings.consented) return;
  await flushQueue().catch(() => {});
  await Promise.allSettled([syncSignatures(), syncLists()]);
}

// ---------------- verdict cache ----------------
async function cacheGet(key) {
  const { verdicts = {} } = await store.get('verdicts');
  const hit = verdicts[key];
  return hit && Date.now() - hit.ts < CFG.VERDICT_CACHE_MS ? hit.v : null;
}

async function cachePut(key, v) {
  const { verdicts = {} } = await store.get('verdicts');
  verdicts[key] = { v, ts: Date.now() };
  const entries = Object.entries(verdicts).filter(([, e]) => Date.now() - e.ts < CFG.VERDICT_CACHE_MS)
    .sort((a, b) => b[1].ts - a[1].ts).slice(0, MAX_CACHE);
  await store.set({ verdicts: Object.fromEntries(entries) });
}

// ---------------- message handlers ----------------
const handlers = {
  async GET_STATE() {
    const s = await store.get(['settings', 'allowlist', 'blocklist', 'signatures', 'stats']);
    return {
      settings: { ...DEFAULT_SETTINGS, ...(s.settings || {}) },
      allowlist: s.allowlist || [],
      blocklist: s.blocklist || [],
      signatures: Object.values((s.signatures && s.signatures.items) || {}),
      signatureVersion: (s.signatures && s.signatures.version) || 0,
      stats: { ...DEFAULT_STATS, ...(s.stats || {}) },
    };
  },

  async SCAN({ key, payload }) {
    const cached = await cacheGet(key);
    if (cached) return { ok: true, verdict: cached, cached: true };
    try {
      const verdict = await api('/scan', { method: 'POST', body: payload });
      await cachePut(key, verdict);
      return { ok: true, verdict };
    } catch (e) {
      return { ok: false, error: e.message }; // content script keeps the local verdict
    }
  },

  FEEDBACK: ({ scanId, feedbackType, comment }) => apiOrQueue('/feedback', { scanId, type: feedbackType, comment }),
  OVERRIDE: ({ scanId, url, score }) => apiOrQueue('/override', { scanId, url, score }),

  async REPORT({ payload }) {
    const r = await apiOrQueue('/report', payload);
    if (r.ok) await bump('reports');
    return r;
  },

  async STAT({ field }) { await bump(field); return { ok: true }; },

  async SET_SETTINGS({ patch }) {
    const { settings } = await store.get('settings');
    const next = { ...DEFAULT_SETTINGS, ...settings, ...patch };
    await store.set({ settings: next });
    if (next.consented) {
      if (!settings.consented) syncAll().catch(() => {});
      if ('language' in patch || 'aiEnabled' in patch) {
        api('/me/settings', { method: 'PUT', body: { language: next.language, aiEnabled: next.aiEnabled } }).catch(() => {});
      }
    }
    return { ok: true, settings: next };
  },

  async LIST_ADD({ listType: type, domain }) {
    domain = String(domain || '').trim().toLowerCase().replace(/^https?:\/\//, '').replace(/\/.*$/, '').replace(/^www\./, '');
    if (!/^([a-z0-9-]+\.)+[a-z]{2,}$/.test(domain)) return { ok: false, error: 'invalid_domain' };
    const key = type === 'allow' ? 'allowlist' : 'blocklist';
    const other = type === 'allow' ? 'blocklist' : 'allowlist';
    const s = await store.get([key, other, 'settings']);
    if (s.settings.consented) {
      try { await api(`/${type}list`, { method: 'POST', body: { domain } }); } catch (e) {
        if (e.status >= 400 && e.status < 500) return { ok: false, error: e.message };
      }
    }
    await store.set({ [key]: [...new Set([domain, ...(s[key] || [])])], [other]: (s[other] || []).filter((d) => d !== domain) });
    await store.set({ verdicts: {} }); // lists changed -> cached verdicts are stale
    return { ok: true };
  },

  async LIST_REMOVE({ listType: type, domain }) {
    const key = type === 'allow' ? 'allowlist' : 'blocklist';
    const s = await store.get([key, 'settings']);
    await store.set({ [key]: (s[key] || []).filter((d) => d !== domain), verdicts: {} });
    if (s.settings.consented) api(`/${type}list/${encodeURIComponent(domain)}`, { method: 'DELETE' }).catch(() => {});
    return { ok: true };
  },

  async DELETE_DATA() {
    let remote = 'skipped';
    try { await api('/me', { method: 'DELETE' }); remote = 'deleted'; } catch (e) { remote = e.status === -1 ? 'skipped' : 'failed'; }
    if (remote === 'failed') return { ok: false, error: 'server_unreachable' };
    await chrome.storage.local.clear();
    await init('reset');
    return { ok: true, remote };
  },

  async SYNC_NOW() { await syncAll(); return { ok: true }; },
};

async function bump(field) {
  if (!(field in DEFAULT_STATS)) return;
  const { stats } = await store.get('stats');
  const next = { ...DEFAULT_STATS, ...(stats || {}) };
  next[field] += 1;
  await store.set({ stats: next });
}

chrome.runtime.onMessage.addListener((msg, sender, sendResponse) => {
  // Only accept messages from our own extension (content scripts / pages).
  if (sender.id !== chrome.runtime.id || !msg || !handlers[msg.type]) return false;
  Promise.resolve(handlers[msg.type](msg))
    .then(sendResponse)
    .catch((e) => sendResponse({ ok: false, error: String(e && e.message) }));
  return true; // async response
});
