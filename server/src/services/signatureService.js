/*
 * Scam signature lifecycle: global version counter, active-signature cache, matching at scan time,
 * activation/deactivation, false-alarm handling.
 */
const config = require('../config');
const { ScamSignature, Meta } = require('../models');
const MS = require('../shared');

const VERSION_KEY = 'signatureVersion';
let activeCache = { at: 0, version: -1, list: [] };

async function currentVersion() {
  const m = await Meta.findOne({ key: VERSION_KEY }).lean();
  return m ? m.value : 0;
}

/** Increments the global version; extensions pull everything with version > their last seen. */
async function bumpVersion() {
  const m = await Meta.findOneAndUpdate({ key: VERSION_KEY }, { $inc: { value: 1 } }, { upsert: true, new: true });
  activeCache.at = 0;
  return m.value;
}

async function activeSignatures() {
  if (Date.now() - activeCache.at < 60 * 1000) return activeCache.list;
  const list = await ScamSignature.find({ status: 'active' }).lean();
  activeCache = { at: Date.now(), list };
  return list;
}

/**
 * Find the best active signature for a scanned message.
 * Uses SimHash + keywords + domains (always) and Atlas $vectorSearch on centroids (when enabled).
 */
async function match({ normalized, simhash, embedding, senderDomain, urlDomains }) {
  const opts = { simhashDistance: config.learning.simhashDistance, cosine: config.learning.cosine };
  const sigs = await activeSignatures();
  let best = MS.signatures.matchAll({ normalized, simhash, embedding, senderDomain, urlDomains }, sigs, opts);

  if (!best && embedding && config.atlasVectorSearch) {
    try {
      const hits = await ScamSignature.aggregate([
        { $vectorSearch: { index: 'scam_signatures_embedding', path: 'centroidEmbedding', queryVector: embedding, numCandidates: 50, limit: 3, filter: { status: 'active' } } },
        { $project: { centroidEmbedding: 0, score: { $meta: 'vectorSearchScore' } } },
      ]);
      // Atlas cosine score is (1 + cos) / 2.
      const top = hits.find((h) => 2 * h.score - 1 >= opts.cosine && h.confidence >= 0.3);
      if (top) best = { signature: top, result: { match: true, method: 'vector', score: 2 * top.score - 1 } };
    } catch (e) {
      /* Vector search not available (local Mongo) -> SimHash/keyword fallback already applied. */
    }
  }
  return best;
}

/** Public payload for extensions (no embeddings — keeps the sync small). */
function toPublic(sig) {
  return {
    signatureId: sig.signatureId,
    category: sig.category,
    threatType: sig.threatType,
    simhash: sig.simhash,
    keywords: sig.keywords,
    senderDomains: sig.senderDomains,
    urlDomains: sig.urlDomains,
    reportCount: sig.reportCount,
    distinctUsers: sig.distinctUsers,
    confidence: sig.confidence,
    reasonText: sig.reasonText,
    status: sig.status,
    version: sig.version,
  };
}

async function setStatus(signatureId, status, { admin = false } = {}) {
  const sig = await ScamSignature.findOne({ signatureId });
  if (!sig) return null;
  const wasActive = sig.status === 'active';
  sig.status = status;
  if (admin) sig.adminLocked = true;
  if (wasActive || status === 'active') sig.version = await bumpVersion();
  await sig.save();
  return sig;
}

/** "False alarm" feedback on a signature match. */
async function registerFalseAlarm(signatureId) {
  const sig = await ScamSignature.findOne({ signatureId });
  if (!sig) return null;
  sig.falseAlarmCount += 1;
  sig.confidence = Math.max(0, +(sig.confidence - 0.1).toFixed(3));
  const { falseAlarmMin, falseAlarmRatio } = config.learning;
  const tooMany = sig.falseAlarmCount >= falseAlarmMin && sig.falseAlarmCount >= falseAlarmRatio * Math.max(1, sig.distinctUsers);
  if (sig.status === 'active' && (tooMany || sig.confidence < 0.3)) {
    sig.status = 'pending_review';
    sig.adminLocked = false;
    sig.version = await bumpVersion();
  }
  await sig.save();
  return sig;
}

async function registerConfirmation(signatureId) {
  await ScamSignature.updateOne({ signatureId }, [{ $set: { confidence: { $min: [1, { $add: ['$confidence', 0.02] }] } } }]);
}

module.exports = { currentVersion, bumpVersion, activeSignatures, match, toPublic, setStatus, registerFalseAlarm, registerConfirmation };
