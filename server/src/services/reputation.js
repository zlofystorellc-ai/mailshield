/*
 * URL reputation: url_reputation cache -> Google Safe Browsing v4, VirusTotal, URLhaus, RDAP domain age.
 * All lookups are optional (key-gated), time-boxed, and cached for 24h.
 */
const crypto = require('crypto');
const config = require('../config');
const { fetchJson } = require('./http');
const { UrlReputation } = require('../models');
const MS = require('../shared');

const MAX_URLS_PER_SCAN = 5; // protects free-tier API quotas (VirusTotal: 4 req/min)

const sha256 = (s) => crypto.createHash('sha256').update(String(s)).digest('hex');

async function safeBrowsingBatch(urls) {
  if (!config.keys.safeBrowsing || !urls.length) return null;
  const r = await fetchJson(`https://safebrowsing.googleapis.com/v4/threatMatches:find?key=${encodeURIComponent(config.keys.safeBrowsing)}`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      client: { clientId: 'mailshield', clientVersion: '1.0.0' },
      threatInfo: {
        threatTypes: ['MALWARE', 'SOCIAL_ENGINEERING', 'UNWANTED_SOFTWARE', 'POTENTIALLY_HARMFUL_APPLICATION'],
        platformTypes: ['ANY_PLATFORM'],
        threatEntryTypes: ['URL'],
        threatEntries: urls.map((url) => ({ url })),
      },
    }),
  });
  if (!r.ok) return null;
  const out = {};
  urls.forEach((u) => { out[u] = { checked: true, threat: null }; });
  ((r.data && r.data.matches) || []).forEach((m) => {
    if (m.threat && out[m.threat.url]) out[m.threat.url].threat = m.threatType;
  });
  return out;
}

async function virusTotal(url) {
  if (!config.keys.virusTotal) return null;
  const id = Buffer.from(url).toString('base64url').replace(/=+$/, '');
  const r = await fetchJson(`https://www.virustotal.com/api/v3/urls/${id}`, { headers: { 'x-apikey': config.keys.virusTotal } });
  if (r.status === 404) return { checked: true, malicious: 0, suspicious: 0, seen: false };
  if (!r.ok || !r.data || !r.data.data) return null;
  const s = r.data.data.attributes.last_analysis_stats || {};
  return { checked: true, malicious: s.malicious || 0, suspicious: s.suspicious || 0, seen: true };
}

async function urlhaus(url) {
  const headers = { 'Content-Type': 'application/x-www-form-urlencoded' };
  if (config.keys.urlhaus) headers['Auth-Key'] = config.keys.urlhaus;
  else return null; // URLhaus now requires a (free) Auth-Key
  const r = await fetchJson('https://urlhaus-api.abuse.ch/v1/url/', { method: 'POST', headers, body: new URLSearchParams({ url }).toString() });
  if (!r.ok || !r.data) return null;
  const listed = r.data.query_status === 'ok';
  return { checked: true, listed, status: listed ? r.data.url_status : null, threat: listed ? r.data.threat : null };
}

/** Domain age in days via RDAP (public, no key). */
async function domainAgeDays(domain) {
  const r = await fetchJson(`https://rdap.org/domain/${encodeURIComponent(domain)}`, { headers: { Accept: 'application/rdap+json' } });
  if (!r.ok || !r.data || !Array.isArray(r.data.events)) return null;
  const reg = r.data.events.find((e) => e.eventAction === 'registration');
  if (!reg || !reg.eventDate) return null;
  return Math.floor((Date.now() - new Date(reg.eventDate).getTime()) / 86400000);
}

function verdictOf(doc) {
  const { safeBrowsing: sb, virusTotal: vt, urlhaus: uh } = doc.sources;
  if ((sb && sb.threat) || (uh && uh.listed && uh.status !== 'offline') || (vt && vt.malicious >= 3)) return 'malicious';
  if ((vt && (vt.malicious >= 1 || vt.suspicious >= 3)) || (doc.domainAgeDays != null && doc.domainAgeDays < 30)) return 'suspicious';
  if (sb || vt || uh) return 'clean';
  return 'unknown';
}

/**
 * @param {string[]} urls
 * @returns {Promise<Array<{url, domain, verdict, sources, domainAgeDays}>>}
 */
async function checkUrls(urls) {
  const unique = [...new Set(urls)].filter((u) => /^https?:\/\//i.test(u)).slice(0, MAX_URLS_PER_SCAN);
  const results = [];
  const toFetch = [];

  for (const url of unique) {
    let domain;
    try { domain = MS.brands.registrable(new URL(url).hostname); } catch (e) { continue; }
    if (MS.brands.isVerifiedDomain(domain)) { // well-known legit domains: skip paid lookups
      results.push({ url, domain, verdict: 'clean', sources: {}, domainAgeDays: null, trusted: true });
      continue;
    }
    const cached = await UrlReputation.findOne({ urlHash: sha256(url) }).lean().catch(() => null);
    if (cached) results.push({ url, domain, verdict: cached.verdict, sources: cached.sources || {}, domainAgeDays: cached.domainAgeDays });
    else toFetch.push({ url, domain });
  }
  if (!toFetch.length) return results;

  const domains = [...new Set(toFetch.map((x) => x.domain))];
  const [sb, ages, vts, uhs] = await Promise.all([
    safeBrowsingBatch(toFetch.map((x) => x.url)),
    Promise.all(domains.map(domainAgeDays)),
    Promise.all(toFetch.map((x) => virusTotal(x.url))),
    Promise.all(toFetch.map((x) => urlhaus(x.url))),
  ]);
  const ageByDomain = Object.fromEntries(domains.map((d, i) => [d, ages[i]]));

  for (let i = 0; i < toFetch.length; i++) {
    const { url, domain } = toFetch[i];
    const doc = {
      urlHash: sha256(url), domain,
      sources: { safeBrowsing: sb ? sb[url] : null, virusTotal: vts[i], urlhaus: uhs[i] },
      domainAgeDays: ageByDomain[domain],
      checkedAt: new Date(),
    };
    doc.verdict = verdictOf(doc);
    UrlReputation.updateOne({ urlHash: doc.urlHash }, { $set: doc }, { upsert: true }).catch(() => {});
    results.push({ url, domain, verdict: doc.verdict, sources: doc.sources, domainAgeDays: doc.domainAgeDays });
  }
  return results;
}

module.exports = { checkUrls, sha256, verdictOf, domainAgeDays };
