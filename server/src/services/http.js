const config = require('../config');

/**
 * fetch with a hard timeout. Never throws: returns {ok, status, data} or {ok:false, error}.
 * Every third-party call goes through here so an outage degrades to "unknown", never to a 500.
 */
async function fetchJson(url, opts = {}, timeoutMs = config.externalTimeoutMs) {
  const ctrl = new AbortController();
  const t = setTimeout(() => ctrl.abort(), timeoutMs);
  try {
    const res = await fetch(url, { ...opts, signal: ctrl.signal });
    const text = await res.text();
    let data = null;
    try { data = text ? JSON.parse(text) : null; } catch (e) { data = text; }
    return { ok: res.ok, status: res.status, data };
  } catch (error) {
    return { ok: false, status: 0, error: error.name === 'AbortError' ? 'timeout' : error.message };
  } finally {
    clearTimeout(t);
  }
}

module.exports = { fetchJson };
