/*
 * Client-side PII redaction. Runs in the extension BEFORE a reported email leaves the browser,
 * and again on the server (idempotent) as a safety net.
 */
(function (g) {
  'use strict';
  const MS = (g.MailShield = g.MailShield || {});

  const EMAIL = /[a-z0-9._%+-]+@[a-z0-9-]+(?:\.[a-z0-9-]+)*\.[a-z]{2,}/gi;
  // UPI handle: name@bank with no dot-TLD after it (emails are removed first).
  const UPI = /\b[\w.-]{2,64}@[a-z][a-z0-9]{1,30}\b(?!\.[a-z])/gi;
  const PAN = /\b[A-Z]{5}[0-9]{4}[A-Z]\b/gi;
  const AADHAAR = /\b\d{4}[\s-]\d{4}[\s-]\d{4}\b/g;
  const CARD = /\b\d(?:[ -]?\d){12,18}\b/g;
  const MASKED = /(?:[xX*•]{2,}[ -]?)+\d{2,6}\b/g;
  const ENDING = /\b(ending|ends)(\s+(?:with|in))?\s+\d{3,6}\b/gi;
  const PHONE_INTL = /\+\d{1,3}[\s-]?\(?\d{2,5}\)?[\s-]?\d{3,5}[\s-]?\d{3,5}\b/g;
  const PHONE_IN = /(?<!\d)(?:(?:\+|00)?91[\s-]?)?[6-9]\d{4}[\s-]?\d{5}(?!\d)/g;
  const TOLL_FREE = /\b1800[\s-]?\d{3}[\s-]?\d{3,4}\b/g;
  const ACCOUNT = /(?<!\d)\d{9,18}(?!\d)/g;
  const CODE = /(?<![\d.,])\b\d{4,8}\b/g;

  function escapeRe(s) {
    return s.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
  }

  // A 4–8 digit number is treated as an OTP-like code unless it is clearly an amount or a year.
  function codeReplacer(m, offset, str) {
    const before = str.slice(Math.max(0, offset - 8), offset);
    const after = str.slice(offset + m.length, offset + m.length + 10);
    if (/(?:₹|\$|rs\.?|inr|usd)\s*$/i.test(before)) return m;
    if (/^\s*(?:\/-|rupees?|rs\b|inr\b|only\b|usd\b|dollars?\b)/i.test(after)) return m;
    if (/^[.,]\d/.test(after)) return m; // decimal / grouped amount
    if (m.length === 4 && /^(19|20)\d\d$/.test(m)) return m; // year
    return '<CODE>';
  }

  /**
   * @param {string} text
   * @param {{userName?:string,userEmail?:string}} [opts]
   */
  function redact(text, opts) {
    opts = opts || {};
    let s = String(text || '');
    if (opts.userEmail) s = s.replace(new RegExp(escapeRe(opts.userEmail), 'gi'), '<USER>');
    if (opts.userName) {
      opts.userName.split(/\s+/).filter((p) => p.length >= 3).forEach((part) => {
        s = s.replace(new RegExp('\\b' + escapeRe(part) + '\\b', 'gi'), '<USER>');
      });
    }
    s = s.replace(EMAIL, '<EMAIL>');
    s = s.replace(UPI, '<UPI>');
    s = s.replace(PAN, '<ID>');
    s = s.replace(PHONE_INTL, '<PHONE>');
    s = s.replace(TOLL_FREE, '<PHONE>');
    s = s.replace(PHONE_IN, '<PHONE>');
    s = s.replace(CARD, '<ACCOUNT>'); // 13–19 digits, before Aadhaar (12) so cards aren't split
    s = s.replace(AADHAAR, '<ID>');
    s = s.replace(MASKED, '<ACCOUNT>');
    s = s.replace(ENDING, (m, w, w2) => w + (w2 || '') + ' <ACCOUNT>');
    s = s.replace(ACCOUNT, '<ACCOUNT>');
    s = s.replace(CODE, codeReplacer);
    return s;
  }

  MS.redact = { redact };
  if (typeof module !== 'undefined' && module.exports) module.exports = MS.redact;
})(typeof globalThis !== 'undefined' ? globalThis : self);
