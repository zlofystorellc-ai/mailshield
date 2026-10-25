/*
 * Signature learning: build a signature from a few user reports, then verify that every
 * variant of the same scam matches it — and unrelated / genuine mail does not.
 */
const MS = require('../src/shared');
const F = require('./fixtures/emails');
const { isNeighbor, clusterOffline } = require('../src/services/clustering');

const OPTS = { simhashDistance: 6, cosine: 0.85 };

const toReport = (e, i) => {
  // Simulate the real report path: client-side redaction, then server normalization.
  const subject = MS.redact.redact(e.subject);
  const body = MS.redact.redact(e.body);
  const normalizedText = MS.normalize.normalizeForMatch(subject, body);
  return {
    normalizedText,
    simhash: MS.simhash.simhash(normalizedText),
    embedding: MS.simhash.localEmbedding(normalizedText),
    senderDomain: MS.brands.registrable(MS.brands.domainOfEmail(e.senderEmail)),
    urlDomains: [],
    userId: 'user' + i,
  };
};

const msgOf = (e) => {
  const normalized = MS.normalize.normalizeForMatch(e.subject, e.body);
  return { normalized, senderDomain: MS.brands.registrable(MS.brands.domainOfEmail(e.senderEmail)), urlDomains: [] };
};

describe('SimHash', () => {
  test('64-bit hex, deterministic', () => {
    const a = MS.simhash.simhash('hello world');
    expect(a).toMatch(/^[0-9a-f]{16}$/);
    expect(MS.simhash.simhash('hello world')).toBe(a);
  });
  test('hamming distance', () => {
    expect(MS.simhash.hamming('0000000000000000', '0000000000000000')).toBe(0);
    expect(MS.simhash.hamming('0000000000000000', 'ffffffffffffffff')).toBe(64);
    expect(MS.simhash.hamming('000000000000000f', '0000000000000000')).toBe(4);
  });
  test('near-duplicates are close, unrelated texts are far', () => {
    const a = MS.normalize.normalizeText('Rs 25,000 credited to your account by mistake please refund immediately to my upi');
    const b = MS.normalize.normalizeText('Rs 9,999 credited to your account by mistake please refund immediately to my upi');
    const c = MS.normalize.normalizeText('Team lunch is moved to Friday, please bring your laptop for the demo');
    expect(MS.simhash.hamming(MS.simhash.simhash(a), MS.simhash.simhash(b))).toBeLessThanOrEqual(6);
    expect(MS.simhash.hamming(MS.simhash.simhash(a), MS.simhash.simhash(c))).toBeGreaterThan(6);
  });
});

describe('report clustering', () => {
  test('all 5 fake-credit variants (incl. Hinglish) end up in ONE cluster', () => {
    const clusters = clusterOffline(F.fakeCreditVariants.map(toReport), OPTS);
    expect(clusters).toHaveLength(1);
    expect(clusters[0]).toHaveLength(5);
  });

  test('mixed reports separate into their own clusters', () => {
    const reports = [
      ...F.fakeCreditVariants.map(toReport),
      ...Object.values(F.otherScams).map((e, i) => toReport(e, 100 + i)),
      ...F.genuineBankAlerts.map((e, i) => toReport(e, 200 + i)),
    ];
    const clusters = clusterOffline(reports, OPTS);
    const fc = clusters.find((c) => c.includes(reports[0]));
    expect(fc).toHaveLength(5); // nothing else got pulled into the fake-credit cluster
  });

  test('a fake-credit report is not a neighbor of a job scam, a bank alert or a normal email', () => {
    const fc = toReport(F.fakeCreditVariants[0], 0);
    expect(isNeighbor(fc, toReport(F.otherScams.fakeJob, 9), OPTS)).toBe(false);
    expect(isNeighbor(fc, toReport(F.genuineBankAlerts[0], 7), OPTS)).toBe(false);
    expect(isNeighbor(fc, toReport(F.normalEmails[0], 8), OPTS)).toBe(false);
  });
});

describe('signature matching', () => {
  // Built from only the first 3 reports (REPORT_THRESHOLD = 3 distinct users).
  const sig = {
    signatureId: 'sig_test', category: 'fake_payment_credit', threatType: 'fake_payment_credit',
    status: 'active', confidence: 0.7, distinctUsers: 3,
    ...MS.signatures.buildSignature(F.fakeCreditVariants.slice(0, 3).map(toReport)),
  };

  test('signature has keywords and a centroid', () => {
    expect(sig.keywords.length).toBeGreaterThanOrEqual(4);
    expect(sig.keywords).toEqual(expect.arrayContaining(['mistake', 'refund']));
    expect(sig.simhash).toMatch(/^[0-9a-f]{16}$/);
  });

  test.each(F.fakeCreditVariants.map((e, i) => [i + 1, e]))('variant %i matches the same signature', (i, e) => {
    const best = MS.signatures.matchAll(msgOf(e), [sig]);
    expect(best).not.toBeNull();
    expect(best.signature.signatureId).toBe('sig_test');
  });

  test.each([
    ...Object.entries(F.otherScams),
    ...F.genuineBankAlerts.map((e) => [e.senderEmail, e]),
    ...F.normalEmails.map((e) => [e.subject, e]),
  ])('%s does not match the fake-credit signature', (_, e) => {
    expect(MS.signatures.matchAll(msgOf(e), [sig])).toBeNull();
  });

  test('inactive or low-confidence signatures never match', () => {
    const e = msgOf(F.fakeCreditVariants[0]);
    expect(MS.signatures.matchAll(e, [{ ...sig, status: 'pending_review' }])).toBeNull();
    expect(MS.signatures.matchAll(e, [{ ...sig, confidence: 0.1 }])).toBeNull();
  });

  test('heuristic engine adds signature_match (+40, min WARNING) for a re-worded variant', () => {
    const variant = {
      senderName: 'Kiran', senderEmail: 'kiran.p@rediffmail.com', subject: 'Amount credited by mistake',
      body: 'Hello Meena, I credited ₹7,200 to your account by mistake. Please refund it to my UPI kiran@okhdfc. Thanks, Kiran',
    };
    const r = MS.heuristics.analyze({ ...variant, links: [], attachments: [] }, { signatures: [sig] });
    expect(r.reasons.map((x) => x.id)).toContain('signature_match');
    expect(r.matchedSignatureId).toBe('sig_test');
    expect(r.score).toBeGreaterThanOrEqual(30);
  });

  test('verified senders are never matched against signatures', () => {
    const r = MS.heuristics.analyze({ ...F.genuineBankAlerts[0] }, { signatures: [sig] });
    expect(r.reasons.map((x) => x.id)).not.toContain('signature_match');
  });
});
