/* AUTO-COPIED from extension/lib by scripts/sync-shared.js — edit the original. */
/*
 * Scam-signature building and matching (shared by extension + server).
 * A signature = cluster centroid SimHash + discriminative concept keywords (+ optional embedding).
 * Depends on: normalize.js, simhash.js, brands.js
 */
(function (g) {
  'use strict';
  const MS = (g.MailShield = g.MailShield || {});

  const DEFAULTS = {
    simhashDistance: 6,
    cosine: 0.85,
    keywordRatio: 0.6,
    keywordMinHits: 4,
    maxKeywords: 14,
    keywordMinDf: 0.6,
  };

  /** Concept keywords present in >= minDf of the documents. */
  function extractKeywords(normalizedList, opts) {
    opts = Object.assign({}, DEFAULTS, opts);
    const df = new Map();
    normalizedList.forEach((n) => {
      new Set(MS.normalize.conceptTokens(n)).forEach((t) => df.set(t, (df.get(t) || 0) + 1));
    });
    const minCount = Math.max(2, Math.ceil(opts.keywordMinDf * normalizedList.length));
    return [...df.entries()]
      .filter(([t, c]) => c >= minCount && t.length > 2)
      .sort((a, b) => b[1] - a[1] || b[0].length - a[0].length)
      .slice(0, opts.maxKeywords)
      .map(([t]) => t);
  }

  /** Domains that appear for >= 2 distinct reporters and are not free-mail / shorteners / verified. */
  function sharedDomains(reports, field) {
    const byDomain = new Map();
    reports.forEach((r) => {
      [].concat(r[field] || []).forEach((d) => {
        if (!d) return;
        const reg = MS.brands.registrable(d);
        if (MS.brands.FREE_MAIL.has(reg) || MS.brands.SHORTENERS.has(reg) || MS.brands.isVerifiedDomain(reg)) return;
        if (!byDomain.has(reg)) byDomain.set(reg, new Set());
        byDomain.get(reg).add(String(r.userId || Math.random()));
      });
    });
    return [...byDomain.entries()].filter(([, users]) => users.size >= 2).map(([d]) => d);
  }

  /**
   * @param {Array<{normalizedText:string, simhash?:string, embedding?:number[], senderDomain?:string, urlDomains?:string[], userId?:string}>} reports
   */
  function buildSignature(reports, opts) {
    const norms = reports.map((r) => r.normalizedText);
    const hashes = reports.map((r) => r.simhash || MS.simhash.simhash(r.normalizedText));
    const embs = reports.map((r) => r.embedding).filter((e) => Array.isArray(e) && e.length);
    let centroid = null;
    if (embs.length) {
      centroid = new Array(embs[0].length).fill(0);
      embs.forEach((e) => e.forEach((x, i) => { centroid[i] += x / embs.length; }));
      centroid = MS.simhash.l2normalize(centroid);
    }
    return {
      simhash: MS.simhash.majority(hashes),
      keywords: extractKeywords(norms, opts),
      senderDomains: sharedDomains(reports, 'senderDomain'),
      urlDomains: sharedDomains(reports, 'urlDomains'),
      centroidEmbedding: centroid,
    };
  }

  /**
   * Compare one message against one signature.
   * @param {{normalized:string, simhash?:string, embedding?:number[], senderDomain?:string, urlDomains?:string[]}} msg
   */
  function similarity(msg, sig, opts) {
    opts = Object.assign({}, DEFAULTS, opts);
    const sh = msg.simhash || MS.simhash.simhash(msg.normalized);
    const dist = MS.simhash.hamming(sh, sig.simhash);
    if (dist <= opts.simhashDistance) return { match: true, method: 'simhash', score: 1 - dist / 64, distance: dist };

    if (msg.embedding && sig.centroidEmbedding && msg.embedding.length === sig.centroidEmbedding.length) {
      const cos = MS.simhash.cosine(msg.embedding, sig.centroidEmbedding);
      if (cos >= opts.cosine) return { match: true, method: 'embedding', score: cos };
    }

    const kws = sig.keywords || [];
    let hits = 0;
    if (kws.length) {
      const toks = new Set(MS.normalize.conceptTokens(msg.normalized));
      hits = kws.filter((k) => toks.has(k)).length;
      const ratio = hits / kws.length;
      if (hits >= Math.min(opts.keywordMinHits, kws.length) && ratio >= opts.keywordRatio) {
        return { match: true, method: 'keywords', score: ratio, hits };
      }
    }

    const sd = msg.senderDomain ? MS.brands.registrable(msg.senderDomain) : '';
    const domainHit = (sd && (sig.senderDomains || []).includes(sd)) ||
      (msg.urlDomains || []).some((d) => (sig.urlDomains || []).includes(MS.brands.registrable(d)));
    if (domainHit && hits >= 2) return { match: true, method: 'domain', score: 0.7 };

    return { match: false, score: 0, distance: dist };
  }

  /** Best matching active signature, or null. */
  function matchAll(msg, signatures, opts) {
    let best = null;
    (signatures || []).forEach((sig) => {
      if (sig.status && sig.status !== 'active') return;
      if (typeof sig.confidence === 'number' && sig.confidence < 0.3) return;
      const r = similarity(msg, sig, opts);
      if (r.match && (!best || r.score > best.result.score)) best = { signature: sig, result: r };
    });
    return best;
  }

  MS.signatures = { buildSignature, extractKeywords, similarity, matchAll, DEFAULTS };
  if (typeof module !== 'undefined' && module.exports) module.exports = MS.signatures;
})(typeof globalThis !== 'undefined' ? globalThis : self);
