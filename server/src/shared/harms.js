/* AUTO-COPIED from extension/lib by scripts/sync-shared.js — edit the original. */
/*
 * threatType -> plain-language harm explanation (English + Hinglish).
 * Also: scam category labels and category -> threatType mapping.
 */
(function (g) {
  'use strict';
  const MS = (g.MailShield = g.MailShield || {});

  const HARMS = {
    credential_phishing: {
      title: { en: 'Account takeover', hi: 'Account hack ho sakta hai' },
      en: 'Your password can be stolen and your account taken over.',
      hi: 'Aapka password chori hokar account hack ho sakta hai.',
    },
    financial_fraud: {
      title: { en: 'Money theft', hi: 'Paise ki chori' },
      en: 'Money can be withdrawn from your bank or UPI account without your knowledge.',
      hi: 'Aapke bank ya UPI account se bina bataye paise nikale ja sakte hain.',
    },
    fake_payment_credit: {
      title: { en: 'Fake payment / refund trap', hi: 'Nakli payment / refund ka jaal' },
      en: 'No money actually reached you. You may be tricked into "refunding" money you never received, or into approving a UPI collect request that takes money out.',
      hi: 'Aapke account mein asal mein koi paisa nahi aaya. Aapse woh paisa "wapas" karwaya ja sakta hai jo kabhi mila hi nahi, ya UPI collect request approve karwakar paise kaate ja sakte hain.',
    },
    kyc_bank_update: {
      title: { en: 'Bank details theft', hi: 'Bank details ki chori' },
      en: 'Fake "KYC update" pages steal your net-banking login, card details, PAN/Aadhaar and OTPs, then empty your account.',
      hi: 'Nakli "KYC update" page aapka net-banking login, card, PAN/Aadhaar aur OTP chura kar account khaali kar sakte hain.',
    },
    otp_scam: {
      title: { en: 'OTP fraud', hi: 'OTP fraud' },
      en: 'Anyone with your OTP or PIN can approve payments or log into your account. Banks never ask for it.',
      hi: 'Jiske paas aapka OTP ya PIN hai woh payment approve kar sakta hai ya account mein login kar sakta hai. Bank kabhi OTP nahi maangta.',
    },
    malware: {
      title: { en: 'Malware infection', hi: 'Virus / malware' },
      en: 'Opening the file or link can install malware that spies on you, steals passwords or controls your device.',
      hi: 'File ya link kholne se aapke device mein virus aa sakta hai jo passwords chura sakta hai ya device control kar sakta hai.',
    },
    ransomware: {
      title: { en: 'Ransomware', hi: 'Ransomware' },
      en: 'Malicious macros or programs can lock all your files and demand a ransom.',
      hi: 'Kharab macro ya program aapki saari files lock karke paise (phirauti) maang sakte hain.',
    },
    data_theft: {
      title: { en: 'Personal data theft', hi: 'Personal data ki chori' },
      en: 'Your personal details (ID numbers, address, contacts) can be stolen and used for identity fraud or loans in your name.',
      hi: 'Aapki personal details (ID number, pata, contacts) chura kar aapke naam par fraud ya loan liya ja sakta hai.',
    },
    fake_invoice: {
      title: { en: 'Fake bill', hi: 'Nakli bill' },
      en: 'Fake invoices and renewals trick you into paying for nothing or calling a "refund desk" that steals card details.',
      hi: 'Nakli bill ya renewal se aapse bekar mein payment karwaya jaata hai ya "refund desk" par call karwakar card details li jaati hain.',
    },
    lottery_scam: {
      title: { en: 'Prize / lottery scam', hi: 'Inaam / lottery scam' },
      en: 'There is no prize. You will be asked to pay a "processing fee" or tax, or share bank details, and lose that money.',
      hi: 'Koi inaam nahi hai. Aapse "processing fee" ya tax maanga jaayega ya bank details li jaayengi, aur paisa doob jaayega.',
    },
    fake_job: {
      title: { en: 'Fake job / task scam', hi: 'Nakli job / task scam' },
      en: 'Fake jobs ask for a registration fee or "investment" for tasks, then disappear with your money and documents.',
      hi: 'Nakli job wale registration fee ya task ke liye "investment" maangte hain, phir paise aur documents lekar gayab ho jaate hain.',
    },
    delivery_scam: {
      title: { en: 'Fake delivery fee', hi: 'Nakli delivery charge' },
      en: 'Fake courier messages collect a small "fee" to steal your card details and charge much more.',
      hi: 'Nakli courier message chhoti si "fee" ke bahaane card details chura kar zyada paise kaat lete hain.',
    },
    tech_support: {
      title: { en: 'Tech-support scam', hi: 'Nakli tech support' },
      en: 'Fake support agents ask you to install remote-access apps, then take over your device and bank accounts.',
      hi: 'Nakli support wale remote-access app install karwa kar aapka phone/computer aur bank account control kar lete hain.',
    },
    impersonation: {
      title: { en: 'Impersonation', hi: 'Kisi aur ke naam se dhokha' },
      en: 'Scammers pretend to be your boss, a relative or an official to make you send money or gift cards urgently.',
      hi: 'Thag aapke boss, rishtedaar ya officer bankar turant paise ya gift card bhejne ko kehte hain.',
    },
    other: {
      title: { en: 'Scam risk', hi: 'Scam ka khatra' },
      en: 'This message shows signs of a scam and may try to steal money or information.',
      hi: 'Is message mein scam ke sanket hain; yeh paise ya jaankari churane ki koshish kar sakta hai.',
    },
  };

  const CATEGORIES = {
    fake_payment_credit: { en: 'fake payment / "sent by mistake"', hi: 'nakli payment / "galti se bheja"' },
    kyc_bank_update: { en: 'KYC / bank update', hi: 'KYC / bank update' },
    lottery_prize: { en: 'lottery / prize', hi: 'lottery / inaam' },
    fake_job: { en: 'fake job', hi: 'nakli job' },
    otp_request: { en: 'OTP request', hi: 'OTP maangne wala' },
    fake_invoice: { en: 'fake invoice', hi: 'nakli bill' },
    delivery_scam: { en: 'delivery', hi: 'delivery' },
    tech_support: { en: 'tech support / account security', hi: 'tech support / account security' },
    impersonation: { en: 'impersonation', hi: 'impersonation' },
    other: { en: 'scam', hi: 'scam' },
  };

  const CATEGORY_TO_THREAT = {
    fake_payment_credit: 'fake_payment_credit',
    kyc_bank_update: 'kyc_bank_update',
    lottery_prize: 'lottery_scam',
    fake_job: 'fake_job',
    otp_request: 'otp_scam',
    fake_invoice: 'fake_invoice',
    delivery_scam: 'delivery_scam',
    tech_support: 'tech_support',
    impersonation: 'impersonation',
    other: 'other',
  };

  function harmFor(type) {
    const h = HARMS[type] || HARMS.other;
    return { type: HARMS[type] ? type : 'other', title: h.title, en: h.en, hi: h.hi };
  }

  /** Unique harms in order; the generic "other" harm is only used when nothing more specific applies. */
  function harmsFor(types) {
    const seen = new Set();
    const list = (types || []).filter((t) => t && !seen.has(t) && seen.add(t)).map(harmFor);
    const specific = list.filter((x) => x.type !== 'other');
    return specific.length ? specific : list.slice(0, 1);
  }

  MS.harms = { HARMS, CATEGORIES, CATEGORY_TO_THREAT, harmFor, harmsFor };
  if (typeof module !== 'undefined' && module.exports) module.exports = MS.harms;
})(typeof globalThis !== 'undefined' ? globalThis : self);
