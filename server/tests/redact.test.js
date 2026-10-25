const MS = require('../src/shared');

const r = (s, o) => MS.redact.redact(s, o);

describe('PII redaction', () => {
  test('emails', () => expect(r('write to john.doe@example.co.in now')).toBe('write to <EMAIL> now'));
  test('UPI IDs', () => expect(r('pay to rahul.k@okaxis today')).toBe('pay to <UPI> today'));
  test('Indian mobile numbers', () => {
    expect(r('call 9876543210')).toBe('call <PHONE>');
    expect(r('call +91 98765 43210')).toBe('call <PHONE>');
    expect(r('call +91-9876543210.')).toBe('call <PHONE>.');
  });
  test('toll-free numbers', () => expect(r('helpline 1800 202 6161')).toBe('helpline <PHONE>'));
  test('PAN', () => expect(r('PAN ABCDE1234F')).toBe('PAN <ID>'));
  test('Aadhaar', () => expect(r('Aadhaar 1234 5678 9012')).toBe('Aadhaar <ID>'));
  test('card numbers', () => expect(r('card 4111 1111 1111 1111 expires')).toBe('card <ACCOUNT> expires'));
  test('account numbers', () => expect(r('a/c 001234567890 credited')).toBe('a/c <ACCOUNT> credited'));
  test('masked accounts', () => expect(r('A/c XXXX4521 debited')).toBe('A/c <ACCOUNT> debited'));
  test('OTP-like codes', () => expect(r('Your OTP is 482913.')).toBe('Your OTP is <CODE>.'));
  test('amounts and years are kept', () => {
    expect(r('Rs 15000 received in 2024')).toBe('Rs 15000 received in 2024');
    expect(r('₹12000 sent')).toBe('₹12000 sent');
    expect(r('5000 rupees only')).toBe('5000 rupees only');
  });
  test("user's own name and email", () => {
    expect(r('Dear Neha Kapoor, neha.k@gmail.com', { userName: 'Neha Kapoor', userEmail: 'neha.k@gmail.com' })).toBe('Dear <USER> <USER>, <USER>');
  });
  test('idempotent', () => {
    const once = r('Call 9876543210 or mail a@b.com, OTP 1234, UPI x@ybl');
    expect(r(once)).toBe(once);
  });
});
