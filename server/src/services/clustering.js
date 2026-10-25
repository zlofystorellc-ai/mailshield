/*
 * Report analysis (spec §6): normalize -> SimHash -> embedding -> cluster -> signature.
 * Called by the analysis worker for each new reported_messages document.
 */
const crypto = require('crypto');
const config = require('../config');
const { ReportedMessage, ScamSignature, UserList } = require('../models');
const MS = require('../shared');
const { embed } = require('./embeddings');
const llm = require('./llm');
const trust = require('./trust');
const verified = require('./verified');
const signatureService = require('./signatureService');

const CANDIDATE_WINDOW_DAYS = 180;
const MAX_CANDIDATES = 5000;
const JACCARD_FALLBACK = 0.5; // concept-token overlap; catches re-worded variants SimHash misses

function jaccard(a, b) {
  const A = new Set(MS.normalize.conceptTokens(a));
  const B = new Set(MS.normalize.conceptTokens(b));
  if (!A.size || !B.size) return 0;
  let inter = 0;
  A.forEach((t) => { if (B.has(t)) inter += 1; });
  return inter / (A.size + B.size - inter);
}

const CONCEPT_NAMES = new Set(Object.values(MS.normalize.CONCEPTS));
const CONCEPT_JACCARD = 0.6;
const CONCEPT_MIN_SHARED = 4;

/** Overlap of scam *concepts* only (money_in, mistake, refund, <upi>…): robust to rewording and Hinglish. */
function conceptOverlap(a, b) {
  const pick = (n) => new Set(MS.normalize.conceptTokens(n).filter((t) => CONCEPT_NAMES.has(t) || t[0] === '<'));
  const A = pick(a); const B = pick(b);
  let shared = 0;
  A.forEach((t) => { if (B.has(t)) shared += 1; });
  const union = A.size + B.size - shared;
  return { shared, ratio: union ? shared / union : 0 };
}

/** Pure neighbor test, exported for tests. */
function isNeighbor(a, b, opts = config.learning) {
  if (MS.simhash.hamming(a.simhash, b.simhash) <= opts.simhashDistance) return true;
  if (a.embedding && b.embedding && a.embedding.length === b.embedding.length &&
      MS.simhash.cosine(a.embedding, b.embedding) >= opts.cosine) return true;
  if (jaccard(a.normalizedText, b.normalizedText) >= JACCARD_FALLBACK) return true;
  const c = conceptOverlap(a.normalizedText, b.normalizedText);
  return c.shared >= CONCEPT_MIN_SHARED && c.ratio >= CONCEPT_JACCARD;
}

const asMsg = (r) => ({ normalized: r.normalizedText, simhash: r.simhash, embedding: r.embedding, senderDomain: r.senderDomain, urlDomains: r.urlDomains });

/** A report also joins a cluster when it matches the template built from that cluster's members. */
function matchesClusterTemplate(report, members, opts = config.learning) {
  if (members.length < 2) return false;
  const sig = MS.signatures.buildSignature(members);
  return MS.signatures.similarity(asMsg(report), sig, opts).match;
}

/** In-memory clustering of a list of reports (same rules as the worker). Used by tests and offline tooling. */
function clusterOffline(reports, opts = config.learning) {
  const clusters = [];
  for (const r of reports) {
    const target = clusters.find((c) => c.some((m) => isNeighbor(r, m, opts)) || matchesClusterTemplate(r, c, opts));
    if (target) target.push(r); else clusters.push([r]);
  }
  return clusters;
}

async function vectorNeighbors(report) {
  if (!config.atlasVectorSearch || !report.embedding) return [];
  try {
    const hits = await ReportedMessage.aggregate([
      { $vectorSearch: { index: 'reported_messages_embedding', path: 'embedding', queryVector: report.embedding, numCandidates: 200, limit: 25 } },
      { $project: { clusterId: 1, userId: 1, status: 1, score: { $meta: 'vectorSearchScore' } } },
    ]);
    return hits.filter((h) => String(h._id) !== String(report._id) && h.clusterId &&
      ['clustered', 'confirmed'].includes(h.status) && 2 * h.score - 1 >= config.learning.cosine);
  } catch (e) {
    return []; // not on Atlas -> local comparison below
  }
}

async function findNeighbors(report) {
  const since = new Date(Date.now() - CANDIDATE_WINDOW_DAYS * 86400000);
  const candidates = await ReportedMessage.find({
    _id: { $ne: report._id }, status: { $in: ['clustered', 'confirmed'] }, heldForAdmin: false, createdAt: { $gte: since },
  }).select('simhash embedding normalizedText clusterId userId senderDomain urlDomains').sort({ createdAt: -1 }).limit(MAX_CANDIDATES).lean();

  const local = candidates.filter((c) => c.clusterId && isNeighbor(report, c));

  // Template match: existing signatures, or clusters of >= 2 members that don't have one yet.
  const opts = config.learning;
  const sigs = await ScamSignature.find({ status: { $ne: 'rejected' }, clusterId: { $ne: null } })
    .select('clusterId simhash keywords senderDomains urlDomains centroidEmbedding').lean();
  const viaSignature = sigs.filter((s) => MS.signatures.similarity(asMsg(report), s, opts).match).map((s) => ({ clusterId: s.clusterId }));
  const withSig = new Set(sigs.map((s) => s.clusterId));
  const byCluster = new Map();
  candidates.forEach((c) => { if (c.clusterId && !withSig.has(c.clusterId)) byCluster.set(c.clusterId, [...(byCluster.get(c.clusterId) || []), c]); });
  const viaTemplate = [...byCluster.entries()].filter(([, members]) => matchesClusterTemplate(report, members, opts)).map(([clusterId]) => ({ clusterId }));

  return [...local, ...viaSignature, ...viaTemplate, ...(await vectorNeighbors(report))];
}

async function assignCluster(report, neighbors) {
  const ids = [...new Set(neighbors.map((n) => n.clusterId).filter(Boolean))].sort();
  if (!ids.length) return 'cl_' + crypto.randomUUID().replace(/-/g, '').slice(0, 16);
  const target = ids[0];
  const others = ids.slice(1);
  if (others.length) { // merge clusters that this report bridges
    await ReportedMessage.updateMany({ clusterId: { $in: others } }, { $set: { clusterId: target } });
    const hasSig = await ScamSignature.exists({ clusterId: target });
    if (!hasSig) await ScamSignature.updateOne({ clusterId: { $in: others } }, { $set: { clusterId: target } });
  }
  return target;
}

function mode(values) {
  const c = new Map();
  values.forEach((v) => c.set(v, (c.get(v) || 0) + 1));
  return [...c.entries()].sort((a, b) => b[1] - a[1])[0][0];
}

/** Create/update the signature for a cluster once enough distinct, trusted users reported it. */
async function evaluateCluster(clusterId) {
  const { reportThreshold, autoActivateThreshold, minTrust } = config.learning;
  const reports = await ReportedMessage.find({ clusterId, status: { $in: ['clustered', 'confirmed'] } }).lean();
  if (!reports.length) return null;

  const userIds = [...new Set(reports.map((r) => String(r.userId)))];
  const trustMap = await trust.getTrustMap(userIds);
  const distinctUsers = userIds.filter((u) => trustMap.get(u) >= minTrust).length;

  let sig = await ScamSignature.findOne({ clusterId });
  // A single user can never create or activate a global signature.
  if (!sig && distinctUsers < Math.max(2, reportThreshold)) return null;

  const built = MS.signatures.buildSignature(reports.map((r) => ({
    normalizedText: r.normalizedText, simhash: r.simhash, embedding: r.embedding,
    senderDomain: r.senderDomain, urlDomains: r.urlDomains, userId: String(r.userId),
  })));
  const senderDomains = [];
  for (const d of built.senderDomains) if (!(await verified.isVerified(d))) senderDomains.push(d);
  const urlDomains = [];
  for (const d of built.urlDomains) if (!(await verified.isVerified(d))) urlDomains.push(d);

  const isNew = !sig;
  if (isNew) sig = new ScamSignature({ signatureId: 'sig_' + crypto.randomUUID().replace(/-/g, '').slice(0, 12), clusterId });

  const category = mode(reports.map((r) => r.category));
  Object.assign(sig, {
    category: sig.adminLocked && sig.category ? sig.category : category,
    threatType: sig.adminLocked && sig.threatType ? sig.threatType : MS.harms.CATEGORY_TO_THREAT[category] || 'other',
    simhash: built.simhash,
    keywords: built.keywords,
    senderDomains,
    urlDomains,
    centroidEmbedding: built.centroidEmbedding || undefined,
    reportCount: reports.length,
    distinctUsers,
  });
  if (isNew) sig.confidence = Math.min(0.9, 0.5 + distinctUsers * 0.04);

  if (isNew || !sig.reasonText || !sig.reasonText.en) {
    const summary = await llm.summarizeCluster(reports.map((r) => r.normalizedText), distinctUsers).catch(() => null);
    const label = MS.harms.CATEGORIES[sig.category] || MS.harms.CATEGORIES.other;
    sig.reasonText = summary ? summary.reasonText : {
      en: `Similar to a ${label.en} scam reported by multiple MailShield users.`,
      hinglish: `Kai MailShield users ne aise hi ${label.hi} scam ki report ki hai.`,
    };
    if (summary) sig.suggestedKeywords = summary.suggestedKeywords;
  }

  const wasActive = sig.status === 'active';
  if (!sig.adminLocked && sig.status === 'pending_review' && distinctUsers >= Math.max(2, autoActivateThreshold) && sig.confidence >= 0.3) {
    sig.status = 'active';
  }
  if (sig.status === 'active' || wasActive) sig.version = await signatureService.bumpVersion();
  await sig.save();
  return sig;
}

async function processReport(report) {
  report.normalizedText = MS.normalize.normalizeForMatch(report.redactedSubject, report.redactedBody);
  report.simhash = MS.simhash.simhash(report.normalizedText);
  const emb = await embed(report.normalizedText);
  report.embedding = emb || undefined;

  // Personal template block: this user is warned about look-alikes immediately, before any global decision.
  await UserList.updateOne(
    { userId: report.userId, type: 'block', simhash: report.simhash },
    { $setOnInsert: { userId: report.userId, type: 'block', simhash: report.simhash, createdAt: new Date() } },
    { upsert: true },
  );

  const neighbors = await findNeighbors(report);
  report.clusterId = await assignCluster(report, neighbors);
  report.status = 'clustered';
  report.lockedAt = undefined;
  await report.save();
  return evaluateCluster(report.clusterId);
}

module.exports = { processReport, evaluateCluster, isNeighbor, jaccard, conceptOverlap, matchesClusterTemplate, clusterOffline };
