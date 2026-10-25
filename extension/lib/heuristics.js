/*
 * Local heuristic engine. Runs instantly in the content script (and in Jest).
 * Every rule produces {id, weight, reason, reasonHi, harmType}.
 * Depends on: brands.js, normalize.js, simhash.js, harms.js, signatures.js
 */
(function (g) {
  'use strict';
  const MS = (g.MailShield = g.MailShield || {});

  const LEVELS = { WARNING: 30, BLOCK: 70 };
  function levelOf(score) {
    return score >= LEVELS.BLOCK ? 'block' : score >= LEVELS.WARNING ? 'warning' : 'safe';
  }

  // ---------- text patterns (English + Hindi/Hinglish) ----------
  const AMOUNT = /(?:₹|\brs\b\.?|\binr\b|\$|\busd\b)\s*\d[\d,]*(?:\.\d+)?|\b\d[\d,]*(?:\.\d+)?\s*(?:rupees?|rs\b|inr\b|\/-|lakhs?|crores?)/i;
  const URGENCY = /\b(immediately|promptly|as soon as possible|urgent(?:ly)?|within\s+\d+\s*(?:hours?|hrs?|minutes?|mins?|days?)|last (?:warning|chance|reminder)|final (?:notice|warning)|act now|expires? (?:today|soon|tonight)|suspended|will be (?:blocked|closed|deactivated|terminated|suspended|frozen)|limited time|right away|asap|turant|jaldi|foran|fauran|band ho (?:jayega|jaayega|jaega)|block ho (?:jayega|jaayega|jaega)|\d+\s*ghante|aaj hi|last mauka)\b/i;
  const CREDENTIAL = /(verify your (?:account|identity|details|email|kyc)|confirm your (?:password|account|identity|details)|update your (?:kyc|pan|aadhaa?r|account|payment|billing|bank)|(?:login|log in|sign in) (?:to|and) (?:verify|confirm|restore|unlock|update)|kyc (?:expired|update|pending|verification|incomplete)|re-?activate your|unlock your account|verify karo|kyc update karo|aadhaa?r (?:link|update) karo|details? update karo)/i;
  const OTP_REQ = /\b(share|send|tell|provide|give|enter|forward|reply with|submit|batao|bata do|bhejo|bhejein|bhej do)\b[^.\n]{0,40}?\b(otp|one[- ]time (?:password|code)|pin|cvv|password|passcode|upi pin|mpin|card number)\b|\b(otp|pin|cvv)\b[^.\n]{0,25}?\b(batao|bata do|bhejo|bhejein|bhej do|share karo|share karein|reply)\b/i;
  const NEGATION = /(\bnever\b|\bdo not\b|\bdon'?t\b|\bnot to\b|\bwon'?t\b|\bwill not\b|\bmat\b|\bna (?:batayein|batao|share|bhejein)\b|\bkisi ko na\b|\bkabhi nahi\b)/i;
  const PHONE = /(\+?\d[\d\s().-]{8,16}\d)/;
  const CALL_NUMBER = /\b(call|contact|whats\s?app|dial|text|ring|helpline|customer (?:care|support)|toll[- ]free|sampark|call karo|phone karo)\b[^.\n]{0,50}?(\+?\d[\d\s().-]{8,16}\d)/i;

  const MONEY_IN = /\b(credited|deposited|received|transferred|sent|paid|jama|aaya|aaye|bheja|bheje|bhej (?:diya|diye|di))\b/i;
  const MISTAKE = /\b(by mistake|mistakenly|in error|by error|wrongly|wrong (?:account|number|upi)|accidentally|galti se|galati se|galat (?:account|number)|bhul se|bhool se)\b/i;
  const REFUND_ASK = /\b(please|kindly|plz|pls|asap|immediately|urgently|turant|jaldi)\b[^.\n]{0,40}?\b(refund|return|send (?:it )?back|give (?:it )?back|revert|repay|wapas|vapas|lauta)|\b(refund|wapas|vapas|lauta)\w*\s+(?:karo|kar do|kijiye|karein|kare)\b/i;
  const KYC = /\b(kyc|pan card|pan number|aadhaa?r)\b[^.\n]{0,60}?\b(update|expire|expired|pending|verify|link|incomplete|blocked|suspend)|\baccount (?:will be|has been|is) (?:blocked|suspended|closed|frozen|deactivated)|\baccount band ho/i;
  const LOTTERY = /\b(you(?:'ve| have)? won|winner|lottery|lucky draw|claim your (?:prize|reward|gift|cashback|winnings)|congratulations[^.\n]{0,40}(?:won|selected|prize|reward)|jackpot|inaam jeeta)\b/i;
  const FAKE_JOB = /\b(work from home|part[- ]time (?:job|work)|task[- ]based|earn\s+\S+\s+(?:per|daily|a day|every day)|registration fee|data entry job|like and earn|youtube (?:like|subscribe) task|telegram (?:group|channel)|ghar baithe (?:kamaye|kamao)|daily payout)\b/i;
  const DELIVERY = /\b(parcel|package|shipment|courier|consignment|delivery)\b[^.\n]{0,80}?\b(held|on hold|failed|pending|customs|redelivery|re-delivery|address (?:incomplete|issue|update)|could not be delivered|rok)\b/i;
  const FEE = /\b(fee|charge|charges|pay|payment|duty)\b/i;
  const TECH = /\b(suspicious (?:login|activity|sign[- ]in|transaction)|unusual (?:sign[- ]in|activity)|virus (?:detected|found)|malware detected|your (?:computer|device|pc) (?:is|has been) (?:infected|hacked|compromised)|technical support|tech support|account (?:compromised|hacked))\b/i;
  const IMPERSONATION = /\b(gift cards?|itunes card|google play (?:card|gift)|amazon pay (?:card|gift)|steam card|wire (?:the )?(?:money|funds)|urgent(?:ly)? (?:transfer|payment|need)|are you available|need a (?:quick )?favou?r|keep (?:this|it) confidential|i am in a meeting|paise bhej do)\b/i;
  const LOAN_PRESSURE = /\b((?:overdue|outstanding|pending|unpaid)\s+(?:loan|emi|dues|payment|amount)s?|credit (?:bureaus?|score|report)|cibil|recovery (?:agent|team|action)|legal (?:action|notice)|(?:loan|emi) (?:default|defaulter)|days past due)\b/i;
  const INVOICE = /\b(invoice|bill|subscription|renewal|auto[- ]?renew(?:al)?|order (?:confirmation|placed))\b[^.\n]{0,80}?\b(charged|will be (?:debited|charged)|has been (?:debited|charged)|to cancel|cancel(?:lation)?|refund|dispute)\b/i;
  const LOGINISH = /(login|log-in|signin|sign-in|verify|secure|account|update|auth|bank|wallet|kyc|password)/i;
  const URLISH_TEXT = /^(?:https?:\/\/)?(?:www\.)?([a-z0-9-]+(?:\.[a-z0-9-]+)+)(?:[/?#]\S*)?$/i;

  const DANGEROUS_EXT = {
    exe: 'malware', scr: 'malware', js: 'malware', jse: 'malware', vbs: 'malware', vbe: 'malware', bat: 'malware', cmd: 'malware',
    com: 'malware', msi: 'malware', jar: 'malware', ps1: 'malware', hta: 'malware', lnk: 'malware', apk: 'malware',
    iso: 'malware', img: 'malware', html: 'credential_phishing', htm: 'credential_phishing', shtml: 'credential_phishing',
    docm: 'ransomware', xlsm: 'ransomware', pptm: 'ransomware', dotm: 'ransomware',
  };
  const DOUBLE_EXT = /\.(pdf|docx?|xlsx?|pptx?|jpe?g|png|txt|csv|zip)\.(exe|scr|js|vbs|bat|cmd|com|jar|msi|apk|html?|lnk|hta)$/i;

  // ---------- helpers ----------
  function levenshtein(a, b) {
    if (a === b) return 0;
    const m = a.length; const n = b.length;
    if (!m) return n; if (!n) return m;
    let prev = Array.from({ length: n + 1 }, (_, i) => i);
    for (let i = 1; i <= m; i++) {
      const cur = [i];
      for (let j = 1; j <= n; j++) {
        cur[j] = Math.min(prev[j] + 1, cur[j - 1] + 1, prev[j - 1] + (a[i - 1] === b[j - 1] ? 0 : 1));
      }
      prev = cur;
    }
    return prev[n];
  }

  // Map common homoglyph tricks to their Latin look-alikes.
  function skeleton(label) {
    return label.toLowerCase()
      .replace(/rn/g, 'm').replace(/vv/g, 'w').replace(/cl/g, 'd')
      .replace(/0/g, 'o').replace(/[1!|]/g, 'l').replace(/3/g, 'e').replace(/4/g, 'a').replace(/5/g, 's').replace(/7/g, 't').replace(/8/g, 'b')
      .replace(/[аɑ]/g, 'a').replace(/[её]/g, 'e').replace(/[оο]/g, 'o').replace(/[рρ]/g, 'p').replace(/[сϲ]/g, 'c').replace(/[іι]/g, 'i').replace(/[ӏ]/g, 'l');
  }

  const BRAND_SUFFIX_OK = /^(?:-?(?:bank|support|secure|security|login|signin|verify|verification|kyc|update|care|help|pay|payment|payments|refund|account|accounts|online|alert|alerts|service|services|official|team|india|in|customer|reward|rewards|offer|offers|net|netbanking|app|id|reporting|report|reports|recovery|collection|collections|loan|loans|credit|legal|notice|notices|finance|dues|repay|repayment))+$/;

  // Custom short-link domains (e.g. mpkt.to): a very short name on a TLD popular for shorteners.
  const SHORT_LINK_TLDS = new Set(['to', 'ly', 'gl', 'me', 'gg', 'cc', 'sh', 'li', 'im', 'is', 'ws', 'su']);
  function looksLikeShortLink(l) {
    const parts = l.reg.split('.');
    return parts.length === 2 && parts[0].length <= 5 && SHORT_LINK_TLDS.has(parts[1]) && l.url.pathname.length > 3;
  }

  /** Returns the brand key a domain imitates, or null. */
  function lookalikeBrand(host) {
    const reg = MS.brands.registrable(host);
    if (MS.brands.isVerifiedDomain(reg)) return null;
    const label = reg.split('.')[0];
    const skel = skeleton(label.replace(/^xn--/, ''));
    const subLabels = host.toLowerCase().split('.').slice(0, -reg.split('.').length);
    for (const [key, b] of Object.entries(MS.brands.BRANDS)) {
      if (b.domains.includes(reg)) return null;
      const len = key.length;
      // Edit distance ≤2 for long brands; shorter brands rely on homoglyph/affix checks to avoid false positives.
      const maxD = len >= 7 ? 2 : len >= 6 ? 1 : 0;
      const plain = skel.replace(/-/g, '');
      if (plain === key && label !== key) return key; // digit/homoglyph swap
      if (maxD && plain.length >= len - 2 && levenshtein(plain, key) <= maxD) return key;
      if (skel.split('-').includes(key)) return key; // sbi-kyc-update.com
      if (len >= 4 && skel.startsWith(key) && BRAND_SUFFIX_OK.test(skel.slice(len))) return key; // hdfcbank-secure.com
      if (len >= 4 && skel.endsWith(key) && BRAND_SUFFIX_OK.test(skel.slice(0, -len))) return key; // securepaypal.com
      if (subLabels.some((s) => s === key || b.domains.some((d) => d.startsWith(s + '.')))) return key; // paypal.com.evil.xyz
    }
    return null;
  }

  function unwrapRedirect(href) {
    try {
      const u = new URL(href);
      if (/(^|\.)google\.[a-z.]+$/.test(u.hostname) && u.pathname === '/url') {
        const q = u.searchParams.get('q') || u.searchParams.get('url');
        if (q && /^https?:/i.test(q)) return q;
      }
    } catch (e) { /* ignore */ }
    return href;
  }

  function parseLink(l) {
    const href = unwrapRedirect(String((l && l.href) || '').trim());
    if (!/^https?:\/\//i.test(href)) return null;
    let u;
    try { u = new URL(href); } catch (e) { return null; }
    const host = u.hostname.toLowerCase();
    return { text: String(l.text || '').trim(), href, url: u, host, reg: MS.brands.registrable(host), https: u.protocol === 'https:' };
  }

  function claimedBrand(displayName) {
    const dn = ' ' + String(displayName || '').toLowerCase().replace(/[^a-z0-9 ]+/g, ' ') + ' ';
    for (const [key, b] of Object.entries(MS.brands.BRANDS)) {
      if (b.names.some((n) => dn.includes(' ' + n + ' '))) return key;
    }
    if (/\b(bank|govt|government|police|cyber cell|income tax|customs)\b/.test(dn)) return 'generic_official';
    return null;
  }

  function otpRequested(text) {
    const re = new RegExp(OTP_REQ.source, 'gi');
    let m;
    while ((m = re.exec(text))) {
      const start = Math.max(text.lastIndexOf('.', m.index), text.lastIndexOf('\n', m.index), text.lastIndexOf('!', m.index)) + 1;
      const endIdx = text.slice(m.index).search(/[.!\n]/);
      const sentence = text.slice(start, endIdx < 0 ? text.length : m.index + endIdx);
      if (!NEGATION.test(sentence)) return true;
    }
    return false;
  }

  // ---------- main ----------
  /**
   * @param {{senderName?:string, senderEmail?:string, replyTo?:string, subject?:string, body?:string,
   *          links?:Array<{text:string,href:string}>, attachments?:string[]}} email
   * @param {{signatures?:object[], allowlist?:string[], blocklist?:string[]}} [ctx]
   */
  function analyze(email, ctx) {
    ctx = ctx || {};
    const reasons = [];
    const add = (id, weight, reason, reasonHi, harmType) => {
      if (!reasons.some((r) => r.id === id)) reasons.push({ id, weight, reason, reasonHi, harmType });
    };

    const senderHost = MS.brands.domainOfEmail(email.senderEmail);
    const senderReg = MS.brands.registrable(senderHost);
    const links = (email.links || []).map(parseLink).filter(Boolean);
    const linkRegs = [...new Set(links.map((l) => l.reg))];
    const subject = String(email.subject || '');
    const body = String(email.body || '');
    const text = subject + '\n' + body;
    const normalizedSnippet = MS.normalize.normalizeForMatch(subject, body);
    const base = { normalizedSnippet, senderDomain: senderReg, urlDomains: linkRegs };

    const allow = new Set((ctx.allowlist || []).map((d) => d.toLowerCase()));
    const block = new Set((ctx.blocklist || []).map((d) => d.toLowerCase()));
    if (senderReg && (allow.has(senderReg) || allow.has(String(email.senderEmail || '').toLowerCase()))) {
      return finalize([], { ...base, allowlisted: true });
    }
    const blockedHit = [senderReg, String(email.senderEmail || '').toLowerCase(), ...linkRegs].find((d) => d && block.has(d));
    if (blockedHit) {
      add('user_blocklist', 100, `You blocked "${blockedHit}" earlier.`, `Aapne "${blockedHit}" ko pehle block kiya tha.`, 'other');
      return finalize(reasons, base);
    }

    const verified = !!senderReg && MS.brands.isVerifiedDomain(senderReg);

    // ---- link rules ----
    for (const l of links) {
      if (allow.has(l.reg)) continue;
      const m = l.text.match(URLISH_TEXT);
      if (m) {
        const shownReg = MS.brands.registrable(m[1]);
        if (shownReg && shownReg !== l.reg && !MS.brands.SHORTENERS.has(l.reg)) {
          add('link_text_mismatch', 35, `A link shows "${shownReg}" but really opens "${l.host}".`,
            `Link par "${shownReg}" likha hai lekin asal mein "${l.host}" khulta hai.`, 'credential_phishing');
        }
      }
      if (MS.brands.isIp(l.host)) {
        add('ip_url', 30, `A link points to a raw IP address (${l.host}) instead of a website name.`,
          `Ek link website naam ki jagah seedha IP address (${l.host}) par jaata hai.`, 'credential_phishing');
      }
      if (/(^|\.)xn--/.test(l.host) || /[^\x00-\x7f]/.test(l.host)) {
        add('punycode', 30, `A link uses disguised international characters (${l.host}) to imitate another site.`,
          `Link mein chhupe hue international characters (${l.host}) hain jo kisi aur site ki nakal karte hain.`, 'credential_phishing');
      }
      const brand = lookalikeBrand(l.host);
      if (brand) {
        add('lookalike_domain', 40, `The link "${l.host}" imitates ${brand.toUpperCase()} but is not its real website.`,
          `Link "${l.host}" ${brand.toUpperCase()} ki nakal hai, asli website nahi hai.`, 'credential_phishing');
      }
      if ((MS.brands.SHORTENERS.has(l.reg) || looksLikeShortLink(l)) && !/\.app\.goo\.gl$/.test(l.host)) { // *.app.goo.gl = Google Photos/Maps shares
        add('shortener', 15, `A link is hidden behind a URL shortener (${l.reg}), so you can't see where it goes.`,
          `Link URL shortener (${l.reg}) ke peeche chhupa hai, asli jagah nahi dikhti.`, 'credential_phishing');
      }
      if (MS.brands.SUSPICIOUS_TLDS.has(MS.brands.tld(l.host))) {
        add('suspicious_tld', 15, `A link uses a domain ending often abused by scammers (.${MS.brands.tld(l.host)}).`,
          `Link ka domain (.${MS.brands.tld(l.host)}) aksar scammers use karte hain.`, 'credential_phishing');
      }
      if (!l.https && (LOGINISH.test(l.href) || LOGINISH.test(l.text))) {
        add('insecure_login_link', 20, 'A login/verification link is not secure (no HTTPS).',
          'Login/verify wala link secure (HTTPS) nahi hai.', 'credential_phishing');
      }
    }

    // ---- sender rules ----
    if (senderHost && !verified) {
      const senderBrand = lookalikeBrand(senderHost);
      if (senderBrand) {
        add('lookalike_sender', 40, `The sender's domain "${senderReg}" imitates ${senderBrand.toUpperCase()}.`,
          `Bhejne wale ka domain "${senderReg}" ${senderBrand.toUpperCase()} ki nakal hai.`, 'credential_phishing');
      }
      const claimed = claimedBrand(email.senderName);
      if (claimed) {
        const b = MS.brands.BRANDS[claimed];
        // Unknown banks/offices on their own domain are fine; we only flag free-mail or abused TLDs for generic claims.
        const legit = b
          ? b.domains.includes(senderReg) || (b.gov && MS.brands.GOV_SUFFIX.test(senderReg))
          : !MS.brands.FREE_MAIL.has(senderReg) && !MS.brands.SUSPICIOUS_TLDS.has(MS.brands.tld(senderReg));
        if (!legit) {
          const isFree = MS.brands.FREE_MAIL.has(senderReg);
          const who = claimed === 'generic_official' ? 'a bank or government office' : claimed.toUpperCase();
          add('brand_sender_mismatch', 35,
            `The sender name claims to be ${who}, but the email comes from ${isFree ? 'a free email account' : 'an unrelated domain'} (${senderReg}).`,
            `Naam ${who} ka hai, lekin email ${isFree ? 'free email account' : 'kisi aur domain'} (${senderReg}) se aaya hai.`, 'credential_phishing');
        }
      }
      if (MS.brands.SUSPICIOUS_TLDS.has(MS.brands.tld(senderHost))) {
        add('suspicious_sender_tld', 10, `The sender uses a domain ending often abused by scammers (.${MS.brands.tld(senderHost)}).`,
          `Sender ka domain (.${MS.brands.tld(senderHost)}) aksar scam mein use hota hai.`, 'other');
      }
    }
    if (email.replyTo) {
      const rt = MS.brands.registrable(MS.brands.domainOfEmail(email.replyTo));
      if (rt && senderReg && rt !== senderReg) {
        add('reply_to_mismatch', 20, `Replies would go to a different address (${rt}) than the sender (${senderReg}).`,
          `Reply kisi aur address (${rt}) par jaayega, sender (${senderReg}) par nahi.`, 'impersonation');
      }
    }

    // ---- attachment rules ----
    for (const name of email.attachments || []) {
      const n = String(name).toLowerCase().trim();
      if (DOUBLE_EXT.test(n)) {
        add('double_extension', 45, `The attachment "${name}" hides a dangerous file type behind a fake extension.`,
          `Attachment "${name}" nakli extension ke peeche khatarnaak file chhupa raha hai.`, 'malware');
        continue;
      }
      const ext = (n.match(/\.([a-z0-9]+)$/) || [])[1];
      if (ext && DANGEROUS_EXT[ext]) {
        add('dangerous_attachment', 40, `The attachment "${name}" is a risky file type (.${ext}).`,
          `Attachment "${name}" khatarnaak file type (.${ext}) hai.`, DANGEROUS_EXT[ext]);
      }
    }

    // ---- text rules (skipped for verified senders: real banks legitimately say "credited", "OTP", etc.) ----
    if (!verified) {
      const hasAmount = AMOUNT.test(text);
      const urgent = URGENCY.test(text);
      const hasPhone = PHONE.test(body) && (body.match(PHONE)[1].replace(/\D/g, '').length >= 10);

      if (MONEY_IN.test(text) && hasAmount && (MISTAKE.test(text) || REFUND_ASK.test(text))) {
        add('fake_payment_credit', 30, 'Claims money was credited/sent "by mistake" and asks you to refund it — a common UPI/bank scam.',
          'Kehta hai paisa "galti se" bheja gaya aur wapas karne ko kehta hai — yeh common UPI/bank scam hai.', 'fake_payment_credit');
      }
      if (KYC.test(text)) {
        add('kyc_bank_update', 30, 'Threatens that your bank account/KYC will be blocked unless you update details.',
          'Dhamki deta hai ki KYC update nahi kiya to account block ho jaayega.', 'kyc_bank_update');
      }
      if (otpRequested(text)) {
        add('otp_request', 35, 'Asks you to share an OTP, PIN or password. No genuine company ever asks for this.',
          'OTP, PIN ya password maang raha hai. Koi bhi asli company yeh kabhi nahi maangti.', 'otp_scam');
      }
      if (LOTTERY.test(text)) {
        add('lottery_prize', 30, 'Says you won a prize, lottery or cashback you never entered for.',
          'Kehta hai aapne inaam/lottery/cashback jeeta hai jiske liye aapne kabhi apply nahi kiya.', 'lottery_scam');
      }
      if (FAKE_JOB.test(text)) {
        add('fake_job', 30, 'Offers easy work-from-home / task-based earnings — typical fake-job scam.',
          'Ghar baithe aasaan kamaai / task ka offer — yeh nakli job scam jaisa hai.', 'fake_job');
      }
      if (DELIVERY.test(text) && FEE.test(text)) {
        add('delivery_scam', 25, 'Says a parcel is held and asks for a fee or details to release it.',
          'Kehta hai parcel ruka hai aur chhudane ke liye fee ya details maangta hai.', 'delivery_scam');
      }
      if (TECH.test(text) && (CALL_NUMBER.test(text) || links.length)) {
        add('tech_support', 25, 'Warns of a "suspicious login" or virus and pushes you to call or click.',
          '"Suspicious login" ya virus ka darr dikha kar call ya click karwana chahta hai.', 'tech_support');
      }
      if (IMPERSONATION.test(text) && (MS.brands.FREE_MAIL.has(senderReg) || reasons.some((r) => r.id === 'reply_to_mismatch') || /confidential|gift card/i.test(text))) {
        add('impersonation', 30, 'Someone asks for urgent money or gift cards, possibly pretending to be your boss or a relative.',
          'Koi turant paise ya gift card maang raha hai, shayad aapka boss ya rishtedaar bankar.', 'impersonation');
      }
      if (LOAN_PRESSURE.test(text) && (links.length || hasPhone)) {
        add('loan_recovery_pressure', 25, 'Pressures you about an overdue loan / credit score and pushes a payment link or phone number.',
          'Overdue loan / credit score ka darr dikhakar payment link ya phone number par bhejta hai.', 'financial_fraud');
      }
      if (INVOICE.test(text)) {
        add('fake_invoice', 20, 'Mentions an unexpected bill, charge or renewal.',
          'Ek anjaan bill, charge ya renewal ki baat karta hai.', 'fake_invoice');
      }
      if (CREDENTIAL.test(text)) {
        add('credential_language', 20, 'Asks you to verify, confirm or update your account or personal details.',
          'Account ya personal details verify/update karne ko kehta hai.', 'credential_phishing');
      }
      if (urgent) {
        add('urgency', 15, 'Uses pressure or urgency ("immediately", "within 24 hours", "turant").',
          'Jaldi ka dabaav banata hai ("turant", "24 ghante mein").', 'other');
      }
      if (hasAmount && urgent && (links.length || hasPhone)) {
        add('amount_urgency_contact', 25, 'Combines money, urgency and a link/phone number — a classic scam pattern.',
          'Paisa, jaldi aur link/phone number ek saath — yeh classic scam pattern hai.', 'financial_fraud');
      }
      if (CALL_NUMBER.test(body)) {
        // "Call me on …" is normal between friends; it only weighs fully alongside other scam signals.
        const otherText = reasons.some((r) => !['link_text_mismatch', 'ip_url', 'punycode', 'lookalike_domain', 'shortener', 'suspicious_tld',
          'insecure_login_link', 'suspicious_sender_tld', 'dangerous_attachment', 'double_extension'].includes(r.id));
        add('call_unknown_number', otherText ? 20 : 10, 'Asks you to call or WhatsApp an unknown phone number.',
          'Anjaan number par call ya WhatsApp karne ko kehta hai.', 'tech_support');
      }
    }

    // ---- local signature match (scams reported by other users) ----
    if (ctx.signatures && ctx.signatures.length && !verified) {
      const best = MS.signatures.matchAll({ normalized: normalizedSnippet, senderDomain: senderReg, urlDomains: linkRegs }, ctx.signatures);
      if (best) {
        const sig = best.signature;
        const cat = MS.harms.CATEGORIES[sig.category] || MS.harms.CATEGORIES.other;
        const n = sig.distinctUsers || sig.reportCount || 'several';
        add('signature_match', 40,
          (sig.reasonText && sig.reasonText.en) || `Similar to a ${cat.en} scam reported by ${n} users.`,
          (sig.reasonText && sig.reasonText.hinglish) || `${n} users ne aise hi ${cat.hi} scam ki report ki hai.`,
          sig.threatType || MS.harms.CATEGORY_TO_THREAT[sig.category] || 'other');
        base.matchedSignatureId = sig.signatureId;
      }
    }

    return finalize(reasons, { ...base, verified });
  }

  function finalize(reasons, extra) {
    reasons.sort((a, b) => b.weight - a.weight);
    let score = Math.min(100, reasons.reduce((s, r) => s + r.weight, 0));
    if (reasons.some((r) => r.id === 'signature_match')) score = Math.max(score, LEVELS.WARNING);
    const typed = reasons.filter((r) => r.harmType && r.harmType !== 'other');
    const threatType = typed.length ? typed[0].harmType : reasons.length ? 'other' : null;
    return Object.assign({
      score,
      level: levelOf(score),
      reasons,
      threatType,
      harms: score >= LEVELS.WARNING ? MS.harms.harmsFor(reasons.map((r) => r.harmType).filter(Boolean)) : [],
    }, extra);
  }

  /** Small feature summary sent to the server instead of the body. */
  function textFeatures(email) {
    const text = String(email.subject || '') + '\n' + String(email.body || '');
    return {
      length: text.length,
      linkCount: (email.links || []).length,
      hasAmount: AMOUNT.test(text),
      urgency: URGENCY.test(text),
      credentialLanguage: CREDENTIAL.test(text),
      otpRequest: otpRequested(text),
      callNumber: CALL_NUMBER.test(text),
    };
  }

  MS.heuristics = { analyze, textFeatures, levelOf, LEVELS, lookalikeBrand, levenshtein, skeleton, unwrapRedirect, parseLink };
  if (typeof module !== 'undefined' && module.exports) module.exports = MS.heuristics;
})(typeof globalThis !== 'undefined' ? globalThis : self);
