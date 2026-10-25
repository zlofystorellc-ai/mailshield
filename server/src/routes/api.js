/*
 * Extension-facing REST API. Every route except /auth/register requires the install JWT.
 */
const express = require('express');
const config = require('../config');
const S = require('./schemas');
const M = require('../models');
const MS = require('../shared');
const { ah, signUserToken, requireUser, validate, perInstall, registerLimiter } = require('../middleware');
const scanService = require('../services/scanService');
const signatureService = require('../services/signatureService');
const verified = require('../services/verified');
const clustering = require('../services/clustering');

const router = express.Router();
const HOUR = 60 * 60 * 1000;

// ---------- auth ----------
router.post('/auth/register', registerLimiter, validate(S.register), ah(async (req, res) => {
  const { installId } = req.body;
  const user = await M.User.findOneAndUpdate(
    { installId }, { $setOnInsert: { installId, createdAt: new Date() } }, { upsert: true, new: true },
  );
  res.json({ token: signUserToken(user), userId: String(user._id) });
}));

router.use(requireUser);

// ---------- scan ----------
router.post('/scan', perInstall(HOUR, 600), validate(S.scan), ah(async (req, res) => {
  res.json(await scanService.scan(req.user, req.body));
}));

// ---------- feedback ----------
router.post('/feedback', perInstall(HOUR, 200), validate(S.feedback), ah(async (req, res) => {
  const scan = await M.Scan.findOne({ _id: req.body.scanId, userId: req.user._id }).lean();
  if (!scan) return res.status(404).json({ error: 'scan_not_found' });

  const prev = await M.Feedback.findOne({ scanId: scan._id, userId: req.user._id });
  const changed = !prev || prev.type !== req.body.type;
  const fb = prev || new M.Feedback({ scanId: scan._id, userId: req.user._id, signatureId: scan.matchedSignatureId });
  fb.type = req.body.type;
  fb.comment = req.body.comment;
  fb.reviewed = false;
  await fb.save();

  // Signature confidence only moves once per user per scan.
  if (changed && scan.matchedSignatureId) {
    if (req.body.type === 'false_positive') await signatureService.registerFalseAlarm(scan.matchedSignatureId);
    else await signatureService.registerConfirmation(scan.matchedSignatureId);
  }
  res.json({ ok: true });
}));

// ---------- report a missed scam ----------
router.post('/report', perInstall(24 * HOUR, config.learning.reportsPerDay), validate(S.report), ah(async (req, res) => {
  const b = req.body;
  const senderEmail = b.senderEmail.toLowerCase();
  const senderDomain = MS.brands.registrable(MS.brands.domainOfEmail(senderEmail));
  const isVerified = await verified.isVerified(senderDomain);
  const urlDomains = [...new Set(b.urls.map((u) => { try { return MS.brands.registrable(new URL(u).hostname); } catch (e) { return null; } }).filter(Boolean))];

  // Defence in depth: redact again server-side (idempotent).
  const report = await M.ReportedMessage.create({
    userId: req.user._id,
    category: b.category,
    comment: MS.redact.redact(b.comment),
    senderDomain,
    senderName: MS.redact.redact(b.senderName).slice(0, 200),
    redactedSubject: MS.redact.redact(b.subject),
    redactedBody: MS.redact.redact(b.body),
    urls: b.urls,
    urlDomains,
    attachmentNames: b.attachmentNames,
    heldForAdmin: isVerified, // verified senders can only be acted on by an admin
  });

  // Immediately protect THIS user: block the sender (exact address for free-mail, else the domain).
  let entry = null;
  if (!isVerified && senderDomain) {
    entry = MS.brands.FREE_MAIL.has(senderDomain) ? { email: senderEmail } : { domain: senderDomain };
    await M.UserList.updateOne({ userId: req.user._id, type: 'block', ...entry },
      { $setOnInsert: { userId: req.user._id, type: 'block', ...entry, createdAt: new Date() } }, { upsert: true });
  }
  if (b.scanId) {
    await M.Feedback.updateOne({ scanId: b.scanId, userId: req.user._id },
      { $set: { type: 'false_positive', comment: 'reported as missed scam', reviewed: false } }).catch(() => {});
  }
  res.status(202).json({ reportId: String(report._id), queued: !isVerified, blocked: entry ? entry.email || entry.domain : null });
}));

// ---------- "open anyway" ----------
router.post('/override', perInstall(HOUR, 200), validate(S.override), ah(async (req, res) => {
  let urlDomain = '';
  try { urlDomain = MS.brands.registrable(new URL(req.body.url).hostname); } catch (e) { /* invalid url */ }
  await M.Override.create({ scanId: req.body.scanId, userId: req.user._id, urlDomain, score: req.body.score });
  res.json({ ok: true });
}));

// ---------- personal allow / block lists ----------
for (const type of ['allow', 'block']) {
  const path = `/${type}list`;
  router.get(path, ah(async (req, res) => {
    const items = await M.UserList.find({ userId: req.user._id, type, $or: [{ domain: { $ne: null } }, { email: { $ne: null } }] })
      .select('domain email createdAt').sort({ createdAt: -1 }).lean();
    res.json({ items: items.map((i) => ({ domain: i.domain || i.email, createdAt: i.createdAt })) });
  }));
  router.post(path, perInstall(HOUR, 120), validate(S.listEntry), ah(async (req, res) => {
    const domain = MS.brands.registrable(req.body.domain);
    if (type === 'allow' && MS.brands.FREE_MAIL.has(domain)) {
      return res.status(400).json({ error: 'cannot_allowlist_free_mail', message: 'Allowlisting a free-mail provider would disable protection for all its senders.' });
    }
    await M.UserList.deleteMany({ userId: req.user._id, domain, type: type === 'allow' ? 'block' : 'allow' });
    await M.UserList.updateOne({ userId: req.user._id, type, domain }, { $setOnInsert: { createdAt: new Date() } }, { upsert: true });
    res.json({ ok: true, domain });
  }));
  router.delete(`${path}/:domain`, ah(async (req, res) => {
    const v = String(req.params.domain).toLowerCase();
    await M.UserList.deleteMany({ userId: req.user._id, type, $or: [{ domain: v }, { email: v }] });
    res.json({ ok: true });
  }));
}

// ---------- signatures sync ----------
router.get('/signatures', validate(S.sigQuery, 'query'), ah(async (req, res) => {
  const since = req.validQuery.sinceVersion;
  const [version, changed] = await Promise.all([
    signatureService.currentVersion(),
    M.ScamSignature.find({ version: { $gt: since } }).select('-centroidEmbedding').lean(),
  ]);
  res.json({
    version,
    signatures: changed.filter((s) => s.status === 'active').map(signatureService.toPublic),
    removed: changed.filter((s) => s.status !== 'active').map((s) => s.signatureId),
  });
}));

// ---------- account / privacy ----------
router.get('/me', ah(async (req, res) => {
  res.json({ userId: String(req.user._id), settings: req.user.settings, createdAt: req.user.createdAt });
}));

router.put('/me/settings', validate(S.settings), ah(async (req, res) => {
  Object.assign(req.user.settings, req.body);
  await req.user.save();
  res.json({ settings: req.user.settings });
}));

router.delete('/me', ah(async (req, res) => {
  const userId = req.user._id;
  const clusters = await M.ReportedMessage.distinct('clusterId', { userId });
  await Promise.all([
    M.Scan.deleteMany({ userId }), M.Feedback.deleteMany({ userId }), M.Override.deleteMany({ userId }),
    M.UserList.deleteMany({ userId }), M.ReportedMessage.deleteMany({ userId }), M.ReporterTrust.deleteMany({ userId }),
  ]);
  await M.User.deleteOne({ _id: userId });
  // Recompute affected clusters without this user's reports (async, best effort).
  clusters.filter(Boolean).forEach((c) => clustering.evaluateCluster(c).catch(() => {}));
  res.json({ ok: true, deleted: true });
}));

module.exports = router;
