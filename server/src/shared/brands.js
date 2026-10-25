/* AUTO-COPIED from extension/lib by scripts/sync-shared.js — edit the original. */
/*
 * MailShield shared reference data + domain helpers.
 * Classic script: attaches to globalThis.MailShield so it works in content scripts,
 * the MV3 service worker, the popup, and (via require) in Node/Jest on the server.
 */
(function (g) {
  'use strict';
  const MS = (g.MailShield = g.MailShield || {});

  // Brand key -> aliases that may appear in a display name, plus the registrable
  // domains that legitimately send mail / host pages for that brand.
  // Free-mail domains (gmail.com, outlook.com...) are intentionally NEVER listed here.
  const BRANDS = {
    google: { names: ['google'], domains: ['google.com', 'google.co.in', 'youtube.com'] },
    gpay: { names: ['google pay', 'gpay'], domains: ['google.com'] },
    paypal: { names: ['paypal'], domains: ['paypal.com', 'paypal.in'] },
    amazon: { names: ['amazon'], domains: ['amazon.com', 'amazon.in', 'amazon.co.uk', 'amazon.de', 'amazonpay.in'] },
    microsoft: { names: ['microsoft', 'office 365', 'office365'], domains: ['microsoft.com', 'microsoftonline.com', 'office.com', 'office365.com'] },
    apple: { names: ['apple', 'apple id', 'itunes'], domains: ['apple.com'] },
    netflix: { names: ['netflix'], domains: ['netflix.com'] },
    facebook: { names: ['facebook', 'meta'], domains: ['facebook.com', 'facebookmail.com', 'meta.com', 'fb.com'] },
    instagram: { names: ['instagram'], domains: ['instagram.com'] },
    whatsapp: { names: ['whatsapp'], domains: ['whatsapp.com'] },
    linkedin: { names: ['linkedin'], domains: ['linkedin.com'] },
    sbi: { names: ['sbi', 'state bank of india', 'state bank', 'yono'], domains: ['sbi.co.in', 'onlinesbi.sbi', 'onlinesbi.com', 'sbicard.com', 'sbi.bank.in', 'sbilife.co.in'] },
    hdfc: { names: ['hdfc'], domains: ['hdfcbank.com', 'hdfcbank.net', 'hdfc.com', 'hdfclife.com', 'hdfcergo.com', 'hdfcsec.com'] },
    icici: { names: ['icici'], domains: ['icicibank.com', 'icicidirect.com', 'icicilombard.com', 'iciciprulife.com'] },
    axis: { names: ['axis bank', 'axisbank'], domains: ['axisbank.com', 'axisbank.co.in'] },
    kotak: { names: ['kotak'], domains: ['kotak.com', 'kotakbank.com', 'kotaksecurities.com'] },
    paytm: { names: ['paytm'], domains: ['paytm.com', 'paytmbank.com', 'paytmpayments.com'] },
    phonepe: { names: ['phonepe', 'phone pe'], domains: ['phonepe.com'] },
    flipkart: { names: ['flipkart'], domains: ['flipkart.com'] },
    myntra: { names: ['myntra'], domains: ['myntra.com'] },
    irctc: { names: ['irctc', 'indian railways'], domains: ['irctc.co.in', 'irctc.com'] },
    incometax: { names: ['income tax', 'incometax', 'income-tax', 'itr refund'], domains: ['incometax.gov.in', 'incometaxindia.gov.in'], gov: true },
    uidai: { names: ['uidai', 'aadhaar', 'aadhar'], domains: ['uidai.gov.in'], gov: true },
    epfo: { names: ['epfo', 'provident fund'], domains: ['epfindia.gov.in'], gov: true },
    npci: { names: ['npci', 'bhim', 'upi team'], domains: ['npci.org.in', 'bhimupi.org.in'] },
    rbi: { names: ['rbi', 'reserve bank'], domains: ['rbi.org.in'], gov: true },
    indiapost: { names: ['india post', 'indiapost'], domains: ['indiapost.gov.in'], gov: true },
    dhl: { names: ['dhl'], domains: ['dhl.com', 'dhl.co.in', 'dhl.de'] },
    fedex: { names: ['fedex'], domains: ['fedex.com'] },
    bluedart: { names: ['blue dart', 'bluedart'], domains: ['bluedart.com'] },
    delhivery: { names: ['delhivery'], domains: ['delhivery.com'] },
    // Digital lenders — frequently impersonated in loan-recovery / "credit bureau" scams.
    mpokket: { names: ['mpokket'], domains: ['mpokket.com', 'mpokket.in'] },
    kreditbee: { names: ['kreditbee'], domains: ['kreditbee.in'] },
    moneyview: { names: ['moneyview', 'money view'], domains: ['moneyview.in'] },
    kissht: { names: ['kissht'], domains: ['kissht.com'] },
    lazypay: { names: ['lazypay'], domains: ['lazypay.in'] },
    bajajfinserv: { names: ['bajaj finserv', 'bajajfinserv'], domains: ['bajajfinserv.in', 'bajajfinservmarkets.in'] },
    cibil: { names: ['cibil', 'transunion cibil'], domains: ['cibil.com', 'transunion.com'] },
    jio: { names: ['jio', 'reliance jio'], domains: ['jio.com', 'ril.com'] },
    airtel: { names: ['airtel'], domains: ['airtel.in', 'airtel.com'] },
  };

  const FREE_MAIL = new Set([
    'gmail.com', 'googlemail.com', 'yahoo.com', 'yahoo.co.in', 'ymail.com', 'outlook.com', 'hotmail.com',
    'live.com', 'msn.com', 'rediffmail.com', 'aol.com', 'icloud.com', 'me.com', 'proton.me', 'protonmail.com',
    'mail.com', 'gmx.com', 'yandex.com', 'zoho.com', 'zohomail.in', 'tutanota.com',
  ]);

  const SHORTENERS = new Set([
    'bit.ly', 'tinyurl.com', 'cutt.ly', 'goo.gl', 'ow.ly', 'is.gd', 'buff.ly', 'rebrand.ly', 'shorturl.at',
    'tiny.cc', 'rb.gy', 'bl.ink', 't.ly', 'v.gd', 'shorte.st', 'adf.ly', 'bitly.com', 'tiny.one', 'qr.io', 's.id', 'shrtco.de',
  ]);

  const SUSPICIOUS_TLDS = new Set([
    'zip', 'mov', 'xyz', 'top', 'click', 'tk', 'buzz', 'gq', 'ml', 'cf', 'ga', 'work', 'loan', 'men', 'rest',
    'country', 'kim', 'icu', 'monster', 'cyou', 'cfd', 'sbs', 'bid', 'win', 'review', 'party', 'link', 'live', 'quest', 'su',
  ]);

  // Registry suffixes that take one extra label (minimal PSL substitute).
  const TWO_LEVEL = new Set([
    'co.in', 'org.in', 'net.in', 'gov.in', 'nic.in', 'ac.in', 'res.in', 'edu.in', 'firm.in', 'gen.in', 'ind.in', 'bank.in',
    'co.uk', 'org.uk', 'ac.uk', 'gov.uk', 'com.au', 'net.au', 'co.nz', 'co.za', 'com.br', 'com.sg', 'co.jp', 'com.cn', 'com.mx',
  ]);

  const GOV_SUFFIX = /\.(gov|nic)\.in$/;

  const VERIFIED_DOMAINS = new Set();
  Object.values(BRANDS).forEach((b) => b.domains.forEach((d) => VERIFIED_DOMAINS.add(d)));

  function registrable(host) {
    host = String(host || '').toLowerCase().replace(/\.$/, '');
    if (!host || isIp(host)) return host;
    const p = host.split('.');
    if (p.length <= 2) return host;
    const last2 = p.slice(-2).join('.');
    return TWO_LEVEL.has(last2) ? p.slice(-3).join('.') : last2;
  }

  function isIp(host) {
    return /^\d{1,3}(\.\d{1,3}){3}$/.test(host) || /^\[?[0-9a-f:]+\]?$/i.test(host) && host.includes(':');
  }

  function tld(host) {
    const p = String(host || '').toLowerCase().split('.');
    return p[p.length - 1] || '';
  }

  function domainOfEmail(email) {
    const m = String(email || '').toLowerCase().match(/@([a-z0-9.-]+)/);
    return m ? m[1] : '';
  }

  function isVerifiedDomain(regDomain) {
    return VERIFIED_DOMAINS.has(regDomain) || GOV_SUFFIX.test(regDomain);
  }

  MS.brands = {
    BRANDS, FREE_MAIL, SHORTENERS, SUSPICIOUS_TLDS, VERIFIED_DOMAINS, GOV_SUFFIX,
    registrable, isIp, tld, domainOfEmail, isVerifiedDomain,
  };
  if (typeof module !== 'undefined' && module.exports) module.exports = MS.brands;
})(typeof globalThis !== 'undefined' ? globalThis : self);
