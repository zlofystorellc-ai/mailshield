/* AUTO-COPIED from extension/lib by scripts/sync-shared.js — edit the original. */
/*
 * Text normalization used for SimHash / signature matching.
 * Goal: two variants of the same scam template ("₹5,000 credited by mistake, Dear Rahul" vs
 * "Rs 12000 sent in error, Hello Priya") normalize to very similar token streams.
 * Depends on: redact.js
 */
(function (g) {
  'use strict';
  const MS = (g.MailShield = g.MailShield || {});

  const MAX_MATCH_CHARS = 1500;

  const HTML_TAG = /<\/?(?:p|div|br|span|a|b|i|u|strong|em|table|tbody|thead|tr|td|th|ul|ol|li|h[1-6]|img|html|body|head|style|script|font|center|hr|meta|link|title)\b[^>]*>/gi;
  const ENTITIES = { '&nbsp;': ' ', '&amp;': '&', '&lt;': ' ', '&gt;': ' ', '&quot;': '"', '&#39;': "'", '&#8377;': '₹', '&#x20b9;': '₹' };
  const URL_RE = /\bhttps?:\/\/\S+|\bwww\.\S+/g;
  const AMOUNT_PREFIX = /(?:₹|\brs\b\.?|\binr\b\.?|\$|\busd\b|\brupees?\b)\s*\d[\d,]*(?:\.\d+)?(?:\s*(?:\/-|lakhs?|crores?|k)\b)?(?:\s*\/-)?/g;
  const AMOUNT_SUFFIX = /\b\d[\d,]*(?:\.\d+)?\s*(?:₹|\brs\b\.?|\binr\b|\brupees?\b|\/-|\bdollars?\b|\busd\b|\blakhs?\b|\bcrores?\b)/g;
  const MONTHS = '(?:jan|feb|mar|apr|may|jun|jul|aug|sep|sept|oct|nov|dec)[a-z]*\\.?';
  const DATE_RES = [
    /\b\d{1,2}[/\-.]\d{1,2}[/\-.]\d{2,4}\b/g,
    /\b\d{4}-\d{2}-\d{2}\b/g,
    new RegExp('\\b\\d{1,2}(?:st|nd|rd|th)?\\s+' + MONTHS + ',?(?:\\s+\\d{4})?\\b', 'g'),
    new RegExp('\\b' + MONTHS + '\\s+\\d{1,2}(?:st|nd|rd|th)?,?(?:\\s+\\d{4})?\\b', 'g'),
    /\b\d{1,2}:\d{2}(?::\d{2})?\s*(?:am|pm)?\b/g,
  ];
  // Name detection runs on ORIGINAL case so we can use capitalization.
  const GREETING = /\b(Dear|dear|DEAR|Hi|hi|Hello|hello|Hey|hey|Namaste|namaste|Respected|respected|Hii|hii)\s+(?:(?:Mr|Mrs|Ms|Miss|Dr|Shri|Smt|Sri)\.?\s+)?[\p{L}]+(?:\s+[A-Z][\p{L}]+)*/gu;
  const HONORIFIC = /\b(?:Mr|Mrs|Ms|Miss|Dr|Shri|Smt|Sri|MR|MRS|MS)\.?\s+[A-Z][\p{L}]+(?:\s+[A-Z][\p{L}]+)*/gu;
  const SIGNOFF = /\b(Regards|regards|Thanks|thanks|Thank you|thank you|Sincerely|sincerely|Cheers|Best|Warm regards|Best regards|Yours sincerely|Yours faithfully|Dhanyavaad|dhanyavaad)[,!.]?\s+(?:[A-Z][\p{L}.]*(?:\s+[A-Z][\p{L}.]*){0,3})/gu;

  // Placeholders from redact() and from a previous normalize() pass (keeps normalizeText idempotent).
  const PLACEHOLDER_IN = /<(account|phone|email|upi|id|code|user|amount|date|num|name|url)>/gi;

  const STOP = new Set((
    'a an the and or but if of to in on at by for with from as is are was were be been being am this that these those it its ' +
    'you your yours we our us they them he she his her i me my mine please kindly will would shall should can could may might ' +
    'do does did have has had not no yes so than then there here also just very any all some such into onto over under about ' +
    'up out off per via what which who whom when where why how our ours been being get got ' +
    'hai hain ho hua hui ka ki ke ko se me mein par pe aur ya yeh ye woh wo aap aapka aapke aapki hum humara kar karo kare ' +
    'kripya ji to bhi na nahi diya di de do ' +
    // greetings / sign-offs carry no signal and would otherwise become signature keywords
    'dear hi hii hello hey namaste respected thanks thank regards sincerely cheers best warm dhanyavaad'
  ).split(/\s+/));

  // Word -> canonical concept. Makes different wordings of the same scam collapse together.
  const CONCEPTS = {};
  function concept(name, words) { words.split(' ').forEach((w) => { CONCEPTS[w] = name; }); }
  concept('money_in', 'credited credit deposited deposit received receive transferred transfer sent paid payment jama aaya aaye bheja bheje bhej transaction txn');
  concept('mistake', 'mistake mistakenly error erroneously wrongly wrong accidentally accident galti galat galati bhul bhool unintentionally');
  concept('refund', 'refund refunded return returned revert repay repayment wapas vapas lauta lautao lautado reverse back');
  concept('urgent', 'immediately urgent urgently asap now today quickly turant jaldi foran fauran soon hurry');
  concept('legal', 'legal police fir court complaint penalty fine lawsuit case cyber');
  concept('account', 'account a/c acct acc khata wallet');
  concept('bank', 'bank banking netbanking');
  concept('upi', 'upi gpay phonepe paytm bhim');
  concept('send', 'send sending transfer');
  concept('blocked', 'blocked block suspended suspend deactivated deactivate closed freeze frozen band terminated');
  concept('verify', 'verify verification validate confirm update updated reactivate');
  concept('kyc', 'kyc pan aadhaar aadhar');
  concept('prize', 'won winner lottery prize reward cashback lucky jackpot congratulations');
  concept('job', 'job jobs hiring vacancy salary earn earning income');
  concept('parcel', 'parcel package shipment courier delivery consignment');
  concept('otp', 'otp pin cvv password passcode mpin');
  concept('call', 'call contact whatsapp dial helpline');
  concept('click', 'click tap link');

  const DROP_PLACEHOLDERS = new Set(['<num>', '<name>', '<date>', '<user>']);

  function decodeEntities(s) {
    return s.replace(/&(?:nbsp|amp|lt|gt|quot|#39|#8377|#x20b9);/gi, (m) => ENTITIES[m.toLowerCase()] || ' ');
  }

  /** Full normalization pipeline (see spec §6 step 1). */
  function normalizeText(raw, opts) {
    opts = opts || {};
    let s = String(raw || '');
    s = s.replace(HTML_TAG, ' ');
    s = decodeEntities(s);
    s = MS.redact.redact(s);
    s = s.replace(PLACEHOLDER_IN, (m, t) => '§' + t.toLowerCase() + '§');
    s = s.replace(GREETING, (m, greet) => greet + ' §name§');
    s = s.replace(HONORIFIC, '§name§');
    s = s.replace(SIGNOFF, (m, word) => word + ' §name§');
    s = s.toLowerCase();
    s = s.replace(URL_RE, ' §url§ ');
    s = s.replace(AMOUNT_PREFIX, ' §amount§ ');
    s = s.replace(AMOUNT_SUFFIX, ' §amount§ ');
    DATE_RES.forEach((re) => { s = s.replace(re, ' §date§ '); });
    s = s.replace(/\d+(?:[.,]\d+)*/g, ' §num§ ');
    s = s.replace(/[^\p{L}\p{N}§\s]/gu, ' ');
    s = s.replace(/§([a-z]+)§/g, ' <$1> ');
    s = s.replace(/\s+/g, ' ').trim();
    if (opts.max && s.length > opts.max) s = s.slice(0, opts.max).replace(/\s+\S*$/, ''); // don't cut mid-token
    return s;
  }

  /** The canonical string compared against signatures: subject + body, capped. */
  function normalizeForMatch(subject, body) {
    return normalizeText(String(subject || '') + '\n' + String(body || ''), { max: MAX_MATCH_CHARS });
  }

  /** Content tokens with stopwords removed and synonyms collapsed to concepts. */
  function conceptTokens(normalized) {
    const out = [];
    String(normalized || '').split(' ').forEach((t) => {
      if (!t || STOP.has(t) || DROP_PLACEHOLDERS.has(t)) return;
      if (t.length < 2 && t[0] !== '<') return;
      out.push(CONCEPTS[t] || t);
    });
    return out;
  }

  MS.normalize = { normalizeText, normalizeForMatch, conceptTokens, STOP, CONCEPTS, MAX_MATCH_CHARS };
  if (typeof module !== 'undefined' && module.exports) module.exports = MS.normalize;
})(typeof globalThis !== 'undefined' ? globalThis : self);
