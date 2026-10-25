const MS = require('../src/shared');

const n = (s) => MS.normalize.normalizeText(s);

describe('normalization', () => {
  test('lowercases, strips HTML and collapses whitespace', () => {
    expect(n('<p>The   <b>WORLD</b></p>\n\n')).toBe('the world');
  });
  test('amounts in all currencies -> <amount>', () => {
    expect(n('₹5,000 and Rs. 12000 and INR 8,000.50 and $20 and 300 rupees')).toBe('<amount> and <amount> and <amount> and <amount> and <amount>');
  });
  test('dates and times -> <date>', () => {
    expect(n('on 12/05/2025 at 10:30 am, or 3 Jan 2024')).toBe('on <date> at <date> or <date>');
  });
  test('other numbers -> <num>', () => expect(n('ref 42 step 7')).toBe('ref <num> step <num>'));
  test('greeting names -> <name>', () => {
    expect(n('Dear Rahul Sharma, hello')).toBe('dear <name> hello');
    expect(n('Hi Priya, ok')).toBe('hi <name> ok');
    expect(n('Thanks, Amit Kumar')).toBe('thanks <name>');
    expect(n('money from Mr. Sharma today')).toBe('money from <name> today');
  });
  test('PII placeholders survive', () => {
    expect(n('call 9876543210 or pay rahul@okaxis')).toBe('call <phone> or pay <upi>');
  });
  test('URLs -> <url>', () => expect(n('visit https://evil.xyz/a?b=1 now')).toBe('visit <url> now'));
  test('idempotent (server re-normalizes the extension snippet)', () => {
    const once = n('Dear Rahul, ₹25,000 credited on 12/05/2025. Call +91 98765 43210, OTP 482913.');
    expect(n(once)).toBe(once);
  });
  test('normalizeForMatch caps length without cutting a token', () => {
    const s = MS.normalize.normalizeForMatch('subject', 'word '.repeat(1000));
    expect(s.length).toBeLessThanOrEqual(MS.normalize.MAX_MATCH_CHARS);
    expect(s.endsWith('word')).toBe(true);
  });
  test('two variants with different amounts/names normalize identically', () => {
    const a = n('Dear Rahul, Rs. 25,000 has been credited to your account by mistake.');
    const b = n('Dear Priya, ₹12,500 has been credited to your account by mistake.');
    expect(a).toBe(b);
  });
});
