/*
 * Admin API (role-protected). Used by /admin (static panel served by this server).
 */
const crypto = require('crypto');
const express = require('express');
const config = require('../config');
const S = require('./schemas');
const M = require('../models');
const MS = require('../shared');
const { ah, signAdminToken, requireAdmin, validate, adminLoginLimiter } = require('../middleware');
const signatureService = require('../services/signatureService');
const trust = require('../services/trust');
const verified = require('../services/verified');
const clustering = require('../services/clustering');

const router = express.Router();
const { z } = S;

router.post('/login', adminLoginLimiter, validate(z.object({ secret: z.string().min(1).max(500) })), (req, res) => {
  const a = Buffer.from(String(config.adminSecret));
  const b = Buffer.from(req.body.secret);
  if (!config.adminSecret || config.adminSecret.length < 16 || a.length !== b.length || !crypto.timingSafeEqual(a, b)) {
    return res.status(401).json({ error: 'bad_secret' });
  }
  res.json({ token: signAdminToken() });
});

router.use(requireAdmin);

// ---------- dashboard ----------
router.get('/stats', ah(async (req, res) => {
  const days = Math.min(90, Math.max(1, parseInt(req.query.days, 10) || 14));
  const since = new Date(Date.now() - days * 86400000);
  const byDay = (Model, extraGroup = {}) => Model.aggregate([
    { $match: { createdAt: { $gte: since } } },
    { $group: { _id: { $dateToString: { format: '%Y-%m-%d', date: '$createdAt' } }, n: { $sum: 1 }, ...extraGroup } },
  ]);
  const [scans, reports, overrides, fps] = await Promise.all([
    byDay(M.Scan, {
      warnings: { $sum: { $cond: [{ $eq: ['$level', 'warning'] }, 1, 0] } },
      blocks: { $sum: { $cond: [{ $eq: ['$level', 'block'] }, 1, 0] } },
    }),
    byDay(M.ReportedMessage), byDay(M.Override),
    M.Feedback.aggregate([{ $match: { createdAt: { $gte: since }, type: 'false_positive' } },
      { $group: { _id: { $dateToString: { format: '%Y-%m-%d', date: '$createdAt' } }, n: { $sum: 1 } } }]),
  ]);
  const map = (arr) => Object.fromEntries(arr.map((x) => [x._id, x]));
  const [sm, rm, om, fm] = [map(scans), map(reports), map(overrides), map(fps)];
  const out = [];
  for (let i = days - 1; i >= 0; i--) {
    const d = new Date(Date.now() - i * 86400000).toISOString().slice(0, 10);
    out.push({
      date: d, scans: sm[d] ? sm[d].n : 0, warnings: sm[d] ? sm[d].warnings : 0, blocks: sm[d] ? sm[d].blocks : 0,
      overrides: om[d] ? om[d].n : 0, reports: rm[d] ? rm[d].n : 0, falseAlarms: fm[d] ? fm[d].n : 0,
    });
  }
  const [users, activeSigs, pendingSigs, version] = await Promise.all([
    M.User.estimatedDocumentCount(), M.ScamSignature.countDocuments({ status: 'active' }),
    M.ScamSignature.countDocuments({ status: 'pending_review' }), signatureService.currentVersion(),
  ]);
  res.json({ days: out, totals: { users, activeSigs, pendingSigs, signatureVersion: version } });
}));

// ---------- clusters ----------
router.get('/clusters', ah(async (req, res) => {
  const clusters = await M.ReportedMessage.aggregate([
    { $match: { clusterId: { $ne: null }, status: { $ne: 'rejected' } } },
    { $sort: { createdAt: -1 } },
    { $group: {
      _id: '$clusterId', reportCount: { $sum: 1 }, users: { $addToSet: '$userId' }, categories: { $push: '$category' },
      last: { $first: '$createdAt' }, samples: { $push: { subject: '$redactedSubject', body: { $substrCP: ['$redactedBody', 0, 500] }, senderDomain: '$senderDomain' } },
    } },
    { $project: { reportCount: 1, distinctUsers: { $size: '$users' }, categories: 1, last: 1, samples: { $slice: ['$samples', 3] } } },
    { $sort: { distinctUsers: -1, last: -1 } }, { $limit: 100 },
  ]);
  const sigs = await M.ScamSignature.find({ clusterId: { $in: clusters.map((c) => c._id) } }).select('-centroidEmbedding').lean();
  const sigBy = Object.fromEntries(sigs.map((s) => [s.clusterId, s]));
  res.json({
    clusters: clusters.map((c) => {
      const counts = {};
      c.categories.forEach((x) => { counts[x] = (counts[x] || 0) + 1; });
      return {
        clusterId: c._id, reportCount: c.reportCount, distinctUsers: c.distinctUsers, last: c.last, samples: c.samples,
        suggestedCategory: Object.entries(counts).sort((a, b) => b[1] - a[1])[0][0],
        signature: sigBy[c._id] || null,
      };
    }),
  });
}));

router.post('/clusters/:id/evaluate', ah(async (req, res) => {
  const sig = await clustering.evaluateCluster(req.params.id);
  res.json({ signature: sig });
}));

// ---------- signatures ----------
router.get('/signatures', ah(async (req, res) => {
  const q = req.query.status ? { status: String(req.query.status) } : {};
  res.json({ signatures: await M.ScamSignature.find(q).select('-centroidEmbedding').sort({ updatedAt: -1 }).limit(200).lean() });
}));

async function decide(signatureId, approve) {
  const sig = await signatureService.setStatus(signatureId, approve ? 'active' : 'rejected', { admin: true });
  if (!sig) return null;
  const reports = await M.ReportedMessage.find({ clusterId: sig.clusterId, status: 'clustered' }).select('userId').lean();
  await M.ReportedMessage.updateMany({ _id: { $in: reports.map((r) => r._id) } }, { $set: { status: approve ? 'confirmed' : 'rejected' } });
  for (const u of new Set(reports.map((r) => String(r.userId)))) await trust.adjust(u, approve);
  return sig;
}

router.post('/signatures/:id/approve', ah(async (req, res) => {
  const sig = await decide(req.params.id, true);
  return sig ? res.json({ signature: sig }) : res.status(404).json({ error: 'not_found' });
}));

router.post('/signatures/:id/reject', ah(async (req, res) => {
  const sig = await decide(req.params.id, false);
  return sig ? res.json({ signature: sig }) : res.status(404).json({ error: 'not_found' });
}));

router.patch('/signatures/:id', validate(z.object({
  reasonText: z.object({ en: z.string().max(400), hinglish: z.string().max(400) }).optional(),
  category: z.enum(S.CATEGORIES).optional(),
  threatType: z.string().max(64).optional(),
  keywords: z.array(z.string().max(40)).max(20).optional(),
})), ah(async (req, res) => {
  const sig = await M.ScamSignature.findOne({ signatureId: req.params.id });
  if (!sig) return res.status(404).json({ error: 'not_found' });
  Object.assign(sig, req.body, { adminLocked: true });
  if (sig.status === 'active') sig.version = await signatureService.bumpVersion();
  await sig.save();
  res.json({ signature: sig });
}));

// ---------- false-alarm feedback ----------
router.get('/feedback', ah(async (req, res) => {
  const q = { reviewed: req.query.reviewed === 'true' };
  if (req.query.type) q.type = String(req.query.type);
  const items = await M.Feedback.find(q).sort({ createdAt: -1 }).limit(200).populate('scanId', 'senderDomain score level reasons threatType matchedSignatureId').lean();
  res.json({ items });
}));

router.post('/feedback/:id/review', ah(async (req, res) => {
  await M.Feedback.updateOne({ _id: req.params.id }, { $set: { reviewed: true } });
  res.json({ ok: true });
}));

// ---------- global blocklist ----------
router.get('/blocklist', ah(async (req, res) => {
  res.json({ items: await M.GlobalBlocklist.find().sort({ createdAt: -1 }).lean() });
}));

router.get('/blocklist/candidates', ah(async (req, res) => {
  const rows = await M.ReportedMessage.aggregate([
    { $match: { status: { $ne: 'rejected' }, heldForAdmin: false } },
    { $project: { userId: 1, d: { $setUnion: [[{ $ifNull: ['$senderDomain', ''] }], { $ifNull: ['$urlDomains', []] }] } } },
    { $unwind: '$d' },
    { $group: { _id: '$d', users: { $addToSet: '$userId' }, reports: { $sum: 1 } } },
    { $project: { domain: '$_id', reports: 1, distinctUsers: { $size: '$users' } } },
    { $match: { distinctUsers: { $gte: 2 }, domain: { $ne: '' } } },
    { $sort: { distinctUsers: -1 } }, { $limit: 200 },
  ]);
  const existing = new Set((await M.GlobalBlocklist.find().select('domain').lean()).map((g) => g.domain));
  const out = [];
  for (const r of rows) {
    if (existing.has(r.domain) || MS.brands.FREE_MAIL.has(r.domain) || MS.brands.SHORTENERS.has(r.domain)) continue;
    if (await verified.isVerified(r.domain)) continue; // verified senders can never be candidates
    out.push({ domain: r.domain, reports: r.reports, distinctUsers: r.distinctUsers });
  }
  res.json({ items: out });
}));

router.post('/blocklist', validate(z.object({ domain: S.domain, reportCount: z.number().int().min(0).optional() })), ah(async (req, res) => {
  const domain = MS.brands.registrable(req.body.domain);
  if (await verified.isVerified(domain)) return res.status(400).json({ error: 'verified_sender', message: 'Remove it from verified senders first.' });
  if (MS.brands.FREE_MAIL.has(domain)) return res.status(400).json({ error: 'free_mail_domain' });
  await M.GlobalBlocklist.updateOne({ domain }, { $set: { approvedBy: 'admin', reportCount: req.body.reportCount || 0 }, $setOnInsert: { createdAt: new Date() } }, { upsert: true });
  res.json({ ok: true, domain });
}));

router.delete('/blocklist/:domain', ah(async (req, res) => {
  await M.GlobalBlocklist.deleteOne({ domain: String(req.params.domain).toLowerCase() });
  res.json({ ok: true });
}));

// ---------- reports held for admin (verified senders) ----------
router.get('/reports/held', ah(async (req, res) => {
  res.json({ items: await M.ReportedMessage.find({ heldForAdmin: true, status: 'new' }).select('-embedding').sort({ createdAt: -1 }).limit(100).lean() });
}));

router.post('/reports/:id/:action(release|reject)', ah(async (req, res) => {
  const update = req.params.action === 'release' ? { heldForAdmin: false } : { status: 'rejected' };
  await M.ReportedMessage.updateOne({ _id: req.params.id }, { $set: update });
  res.json({ ok: true });
}));

// ---------- verified senders ----------
router.get('/verified-senders', ah(async (req, res) => {
  res.json({ items: await M.VerifiedSender.find().sort({ domain: 1 }).lean(), builtIn: [...MS.brands.VERIFIED_DOMAINS].sort() });
}));

router.post('/verified-senders', validate(z.object({ domain: S.domain, organization: z.string().max(200).optional() })), ah(async (req, res) => {
  const domain = MS.brands.registrable(req.body.domain);
  await M.VerifiedSender.updateOne({ domain }, { $set: { organization: req.body.organization || '', addedBy: 'admin' } }, { upsert: true });
  await M.GlobalBlocklist.deleteOne({ domain });
  verified.invalidate();
  res.json({ ok: true, domain });
}));

router.delete('/verified-senders/:domain', ah(async (req, res) => {
  await M.VerifiedSender.deleteOne({ domain: String(req.params.domain).toLowerCase() });
  verified.invalidate();
  res.json({ ok: true });
}));

module.exports = router;
