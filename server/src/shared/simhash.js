/* AUTO-COPIED from extension/lib by scripts/sync-shared.js — edit the original. */
/*
 * 64-bit SimHash (as two 32-bit halves, hex encoded) + a local hashed-bag-of-concepts embedding.
 * Depends on: normalize.js
 */
(function (g) {
  'use strict';
  const MS = (g.MailShield = g.MailShield || {});

  // FNV-1a with a murmur3 finalizer for good bit dispersion.
  function hash32(str, seed) {
    let h = seed >>> 0;
    for (let i = 0; i < str.length; i++) {
      h ^= str.charCodeAt(i);
      h = Math.imul(h, 16777619);
    }
    h ^= h >>> 16; h = Math.imul(h, 0x85ebca6b);
    h ^= h >>> 13; h = Math.imul(h, 0xc2b2ae35);
    h ^= h >>> 16;
    return h >>> 0;
  }

  function features(normalized) {
    const toks = MS.normalize.conceptTokens(normalized);
    const feats = toks.slice();
    for (let i = 0; i + 1 < toks.length; i++) feats.push(toks[i] + '_' + toks[i + 1]);
    return feats;
  }

  /** @returns {string} 16 hex chars */
  function simhash(normalized) {
    const v = new Array(64).fill(0);
    const feats = features(normalized);
    if (!feats.length) return '0000000000000000';
    feats.forEach((f) => {
      const lo = hash32(f, 0x811c9dc5);
      const hi = hash32(f, 0x9747b28c);
      for (let i = 0; i < 32; i++) {
        v[i] += (lo >>> i) & 1 ? 1 : -1;
        v[32 + i] += (hi >>> i) & 1 ? 1 : -1;
      }
    });
    return bitsToHex(v.map((x) => x > 0));
  }

  function bitsToHex(bits) {
    let lo = 0; let hi = 0;
    for (let i = 0; i < 32; i++) {
      if (bits[i]) lo |= 1 << i;
      if (bits[32 + i]) hi |= 1 << i;
    }
    return (hi >>> 0).toString(16).padStart(8, '0') + (lo >>> 0).toString(16).padStart(8, '0');
  }

  function popcount(x) {
    x -= (x >>> 1) & 0x55555555;
    x = (x & 0x33333333) + ((x >>> 2) & 0x33333333);
    return (Math.imul((x + (x >>> 4)) & 0x0f0f0f0f, 0x01010101) >>> 24);
  }

  function hamming(a, b) {
    if (!a || !b || a.length !== 16 || b.length !== 16) return 64;
    const ah = parseInt(a.slice(0, 8), 16); const al = parseInt(a.slice(8), 16);
    const bh = parseInt(b.slice(0, 8), 16); const bl = parseInt(b.slice(8), 16);
    return popcount((ah ^ bh) >>> 0) + popcount((al ^ bl) >>> 0);
  }

  /** Per-bit majority vote: a cluster "centroid" simhash. */
  function majority(hexList) {
    const votes = new Array(64).fill(0);
    hexList.forEach((hex) => {
      const hi = parseInt(hex.slice(0, 8), 16); const lo = parseInt(hex.slice(8), 16);
      for (let i = 0; i < 32; i++) {
        votes[i] += (lo >>> i) & 1 ? 1 : -1;
        votes[32 + i] += (hi >>> i) & 1 ? 1 : -1;
      }
    });
    return bitsToHex(votes.map((x) => x > 0));
  }

  /** Local embedding (feature hashing). Used when no external embedding provider is configured. */
  function localEmbedding(normalized, dim) {
    dim = dim || 256;
    const vec = new Array(dim).fill(0);
    features(normalized).forEach((f) => {
      const h = hash32(f, 0x1234567);
      const w = f.includes('_') ? 0.5 : 1;
      vec[h % dim] += (h & 0x80000000 ? -1 : 1) * w;
    });
    return l2normalize(vec);
  }

  function l2normalize(vec) {
    const n = Math.sqrt(vec.reduce((s, x) => s + x * x, 0)) || 1;
    return vec.map((x) => x / n);
  }

  function cosine(a, b) {
    if (!a || !b || a.length !== b.length || !a.length) return 0;
    let dot = 0; let na = 0; let nb = 0;
    for (let i = 0; i < a.length; i++) { dot += a[i] * b[i]; na += a[i] * a[i]; nb += b[i] * b[i]; }
    return na && nb ? dot / Math.sqrt(na * nb) : 0;
  }

  MS.simhash = { simhash, hamming, majority, hash32, localEmbedding, l2normalize, cosine };
  if (typeof module !== 'undefined' && module.exports) module.exports = MS.simhash;
})(typeof globalThis !== 'undefined' ? globalThis : self);
