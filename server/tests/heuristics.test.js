const MS = require('../src/shared');
const F = require('./fixtures/emails');

const analyze = (e, ctx) => MS.heuristics.analyze({ links: [], attachments: [], ...e }, ctx);
const ids = (r) => r.reasons.map((x) => x.id);

describe('heuristic engine: scams are flagged', () => {
  test.each(F.fakeCreditVariants.map((e, i) => [i + 1, e]))('fake credit variant %i -> at least WARNING', (i, e) => {
    const r = analyze(e);
    expect(r.score).toBeGreaterThanOrEqual(30);
    expect(ids(r)).toContain('fake_payment_credit');
    expect(r.threatType).toBe('fake_payment_credit');
  });

  test('KYC phishing with mismatched link text and lookalike domain -> BLOCK', () => {
    const r = analyze(F.otherScams.kyc);
    expect(r.level).toBe('block');
    expect(ids(r)).toEqual(expect.arrayContaining(['kyc_bank_update', 'link_text_mismatch', 'lookalike_domain', 'suspicious_tld', 'insecure_login_link']));
    expect(r.harms.length).toBeGreaterThan(0);
  });

  test('Hinglish KYC scam from free mail claiming to be a bank', () => {
    const r = analyze(F.otherScams.kycHinglish);
    expect(r.level).toBe('block');
    expect(ids(r)).toEqual(expect.arrayContaining(['brand_sender_mismatch', 'kyc_bank_update', 'lookalike_domain', 'suspicious_tld', 'urgency']));
  });

  test.each([
    ['lottery', 'lottery_prize'],
    ['fakeJob', 'fake_job'],
    ['delivery', 'delivery_scam'],
    ['otp', 'otp_request'],
    ['otpHinglish', 'otp_request'],
  ])('%s scam -> flagged with %s', (key, rule) => {
    const r = analyze(F.otherScams[key]);
    expect(r.score).toBeGreaterThanOrEqual(30);
    expect(ids(r)).toContain(rule);
  });

  test('double-extension attachment -> malware', () => {
    const r = analyze(F.otherScams.malwareAttachment);
    expect(ids(r)).toContain('double_extension');
    expect(r.threatType).toBe('malware');
    expect(r.score).toBeGreaterThanOrEqual(30);
  });

  test('loan-recovery pressure from a look-alike lender domain with a hidden short link -> flagged', () => {
    const r = analyze(F.otherScams.loanRecovery);
    expect(ids(r)).toEqual(expect.arrayContaining(['lookalike_sender', 'shortener', 'loan_recovery_pressure', 'urgency']));
    expect(r.score).toBeGreaterThanOrEqual(30);
  });

  test('the real lender domain is not treated as a look-alike', () => {
    const r = analyze(F.genuineLenderReminder);
    expect(ids(r)).not.toContain('lookalike_sender');
    expect(ids(r)).not.toContain('lookalike_domain');
    expect(r.level).toBe('safe');
  });

  test.each(['setup.exe', 'report.html', 'macro.docm', 'app.apk', 'disk.iso', 'run.vbs'])('dangerous attachment %s', (name) => {
    expect(ids(analyze({ subject: 'file', body: 'see attached', attachments: [name] }))).toContain('dangerous_attachment');
  });
});

describe('heuristic engine: link rules', () => {
  const linkIds = (href, text = 'click here') => ids(analyze({ subject: 's', body: 'b', links: [{ text, href }] }));

  test('raw IP address', () => expect(linkIds('http://192.168.10.5/login')).toContain('ip_url'));
  test('punycode', () => expect(linkIds('https://xn--pypal-4ve.com/')).toContain('punycode'));
  test('homoglyph digit swap', () => expect(linkIds('https://paypa1.com/signin')).toContain('lookalike_domain'));
  test('edit-distance lookalike', () => expect(linkIds('https://amazom.in/order')).toContain('lookalike_domain'));
  test('brand in subdomain', () => expect(linkIds('https://paypal.com.account-verify.co/')).toContain('lookalike_domain'));
  test('brand with suffix', () => expect(linkIds('https://hdfcbank-secure.com/')).toContain('lookalike_domain'));
  test('shortener', () => expect(linkIds('https://bit.ly/abc')).toContain('shortener'));
  test('suspicious TLD', () => expect(linkIds('https://free-gift.zip/')).toContain('suspicious_tld'));
  test('text shows other domain', () => expect(linkIds('https://evil.example/x', 'www.icicibank.com')).toContain('link_text_mismatch'));
  test('google redirect is unwrapped', () => expect(linkIds('https://www.google.com/url?q=http://203.0.113.9/x')).toContain('ip_url'));

  test.each(['https://www.amazon.in/orders', 'https://accounts.google.com/', 'https://www.onlinesbi.sbi/', 'https://github.com/x'])('real site %s is not a lookalike', (href) => {
    expect(linkIds(href)).not.toContain('lookalike_domain');
  });
});

describe('heuristic engine: legitimate mail is not flagged', () => {
  test.each(F.genuineBankAlerts.map((e) => [e.senderEmail, e]))('verified bank alert from %s -> SAFE', (_, e) => {
    const r = analyze(e);
    expect(r.level).toBe('safe');
    expect(r.verified).toBe(true);
  });

  test.each(F.normalEmails.map((e) => [e.subject, e]))('normal email "%s" -> SAFE', (_, e) => {
    expect(analyze(e).level).toBe('safe');
  });

  test('"never share your OTP" is not an OTP request', () => {
    const r = analyze({ senderEmail: 'a@shop.example', subject: 'Order', body: 'We will never ask you to share your OTP or password. Do not share your PIN.' });
    expect(ids(r)).not.toContain('otp_request');
  });
});

describe('heuristic engine: lists', () => {
  test('allowlisted sender -> score 0', () => {
    const r = analyze(F.otherScams.lottery, { allowlist: ['lucky-prize.click'] });
    expect(r.score).toBe(0);
    expect(r.allowlisted).toBe(true);
  });
  test('blocklisted sender -> BLOCK', () => {
    const r = analyze(F.normalEmails[0], { blocklist: ['sunita.mehta1962@gmail.com'] });
    expect(r.level).toBe('block');
  });
});
