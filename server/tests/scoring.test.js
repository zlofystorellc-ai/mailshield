const { combine } = require('../src/services/scoring');
const { reputationFindings } = require('../src/services/scanService');

const f = (id, weight, extra = {}) => ({ id, weight, reason: id, reasonHi: id, harmType: 'credential_phishing', ...extra });

describe('scoring.combine', () => {
  test('levels: 0-29 safe, 30-69 warning, 70-100 block', () => {
    expect(combine({ localScore: 29 }).level).toBe('safe');
    expect(combine({ localScore: 30 }).level).toBe('warning');
    expect(combine({ localScore: 69 }).level).toBe('warning');
    expect(combine({ localScore: 70 }).level).toBe('block');
  });

  test('adds server findings and caps at 100', () => {
    const r = combine({ localScore: 50, localReasons: [f('urgency', 50)], serverFindings: [f('safe_browsing', 60, { hard: true })] });
    expect(r.score).toBe(100);
    expect(r.reasons.map((x) => x.id)).toEqual(['safe_browsing', 'urgency']);
  });

  test('signature match forces at least WARNING', () => {
    const r = combine({ localScore: 0, serverFindings: [], signatureMatched: true });
    expect(r.level).toBe('warning');
    expect(r.score).toBe(30);
  });

  test('does not double count a signature already matched locally', () => {
    const r = combine({ localScore: 40, localReasons: [f('signature_match', 40)], serverFindings: [f('signature_match', 40)], signatureMatched: true });
    expect(r.score).toBe(40);
  });

  test('verified sender is capped unless there is hard evidence', () => {
    expect(combine({ localScore: 10, serverFindings: [f('new_domain', 30)], verifiedSender: true }).score).toBeLessThanOrEqual(20);
    expect(combine({ localScore: 10, serverFindings: [f('safe_browsing', 60, { hard: true })], verifiedSender: true }).level).toBe('block');
  });

  test('harms are attached for non-safe verdicts', () => {
    const r = combine({ localScore: 45, localReasons: [f('otp_request', 45, { harmType: 'otp_scam' })] });
    expect(r.harms[0].type).toBe('otp_scam');
    expect(r.harms[0].en).toMatch(/OTP/);
    expect(r.harms[0].hi).toBeTruthy();
    expect(r.threatType).toBe('otp_scam');
  });
});

describe('reputation findings', () => {
  test('Safe Browsing + young domain', () => {
    const out = reputationFindings([{ domain: 'evil.xyz', domainAgeDays: 3, sources: { safeBrowsing: { threat: 'SOCIAL_ENGINEERING' } } }]);
    const ids = out.map((x) => x.id);
    expect(ids).toEqual(expect.arrayContaining(['safe_browsing', 'new_domain']));
    expect(out.find((x) => x.id === 'safe_browsing').hard).toBe(true);
    expect(out.find((x) => x.id === 'new_domain').weight).toBe(30);
  });
  test('clean results produce nothing', () => {
    expect(reputationFindings([{ domain: 'ok.com', domainAgeDays: 4000, sources: { virusTotal: { malicious: 0, suspicious: 0 } } }])).toEqual([]);
  });
});
