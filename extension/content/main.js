/*
 * Content-script controller for mail.google.com.
 * 1. Watches the SPA with a MutationObserver for newly opened message bodies.
 * 2. Runs local heuristics instantly and renders a verdict.
 * 3. Asks the background worker for the server verdict (if the user consented) and re-renders.
 * 4. Intercepts link clicks in flagged emails (capture phase).
 * Any failure here must never break Gmail: everything is wrapped in try/catch.
 */
(function (g) {
  'use strict';
  const MS = g.MailShield;
  const SEL = MS.selectors;

  // Diagnostics only: verdict level/score and errors — never email content.
  const log = (...args) => console.info('[MailShield]', ...args);

  const entries = new WeakMap(); // message body element -> entry
  const live = new Set(); // bodies with an entry (for re-render on language change)
  const counted = new Set(); // email keys already counted in stats this page load
  let state = { settings: { enabled: true, language: 'en', consented: false }, allowlist: [], blocklist: [], signatures: [] };

  // Page marker so tooling (and support) can see the script loaded: "loaded" -> "ready".
  document.documentElement.setAttribute('data-mailshield', 'loaded');
  document.documentElement.setAttribute('data-mailshield-id', chrome.runtime.id); // which install is running

  // Messages to the background never block startup: if the service worker doesn't answer, fall back to local mode.
  const SEND_TIMEOUT_MS = 3000;
  const send = (msg) => new Promise((resolve) => {
    const timer = setTimeout(() => resolve({ ok: false, error: 'bg_timeout' }), msg.type === 'SCAN' ? 15000 : SEND_TIMEOUT_MS);
    try {
      chrome.runtime.sendMessage(msg, (res) => {
        clearTimeout(timer);
        resolve(chrome.runtime.lastError ? { ok: false, error: 'bg_unavailable' } : res);
      });
    } catch (e) {
      clearTimeout(timer);
      resolve({ ok: false, error: 'context_invalidated' }); // extension reloaded while Gmail stayed open
    }
  });

  const THREAT_TO_CATEGORY = {
    fake_payment_credit: 'fake_payment_credit', financial_fraud: 'fake_payment_credit', kyc_bank_update: 'kyc_bank_update',
    credential_phishing: 'kyc_bank_update', lottery_scam: 'lottery_prize', fake_job: 'fake_job', otp_scam: 'otp_request',
    fake_invoice: 'fake_invoice', delivery_scam: 'delivery_scam', tech_support: 'tech_support', impersonation: 'impersonation',
  };

  function localAnalyze(email) {
    return MS.heuristics.analyze(email, { signatures: state.signatures, allowlist: state.allowlist, blocklist: state.blocklist });
  }

  function render(entry) {
    try {
      if (!entry.body.isConnected || !state.settings.enabled) return;
      MS.ui.renderPanel(entry.body, { verdict: entry.verdict, lang: state.settings.language, pending: entry.pending, source: entry.source }, {
        onFeedback: (type, comment) => feedback(entry, type, comment),
        onReport: () => report(entry),
      });
    } catch (e) { console.warn('[MailShield] render failed:', e); /* never break Gmail */ }
  }

  function countStats(entry) {
    if (counted.has(entry.email.key)) return;
    counted.add(entry.email.key);
    send({ type: 'STAT', field: 'scanned' });
    if (entry.verdict.level === 'warning') send({ type: 'STAT', field: 'warnings' });
    if (entry.verdict.level === 'block') send({ type: 'STAT', field: 'blocked' });
  }

  async function handleBody(body) {
    if (entries.has(body) || !state.settings.enabled) return;
    const email = MS.extract.fromBody(body);
    if (!email.body && !email.links.length) return; // not rendered yet; the observer will call again
    const local = localAnalyze(email);
    const entry = { body, email, local, verdict: local, scanId: null, pending: state.settings.consented, source: 'local' };
    entries.set(body, entry);
    live.add(body);
    render(entry);

    if (state.settings.consented) {
      const payload = {
        senderEmail: email.senderEmail,
        senderName: email.senderName,
        subject: email.subject,
        urls: email.links.map((l) => l.href),
        attachmentNames: email.attachments,
        textFeatures: MS.heuristics.textFeatures(email),
        normalizedSnippet: local.normalizedSnippet, // normalized + PII-stripped, never the raw body
        localScore: local.score,
        localReasons: local.reasons.map(({ id, weight, reason, reasonHi, harmType }) => ({ id, weight, reason, reasonHi, harmType })),
      };
      // The cache key includes the local result, so improved local rules never reuse a stale server verdict.
      const cacheKey = `${email.key}:${local.score}:${local.reasons.map((r) => r.id).join(',')}`;
      const res = await send({ type: 'SCAN', key: cacheKey, payload });
      if (res && res.ok && res.verdict) {
        entry.verdict = res.verdict;
        entry.scanId = res.verdict.scanId;
        entry.source = 'server';
      }
      entry.pending = false;
      render(entry);
    }
    log('verdict', entry.verdict.level, entry.verdict.score, `(${entry.source})`);
    countStats(entry);
  }

  function scan() {
    if (!state.settings.enabled) return;
    document.querySelectorAll(SEL.messageBody).forEach((body) => {
      if (body.offsetParent === null) return; // hidden/collapsed
      handleBody(body).catch((e) => console.warn('[MailShield] scan failed:', e)); // logged, never thrown into Gmail
    });
    live.forEach((b) => { if (!b.isConnected) live.delete(b); });
  }

  // ---------------- feedback / report ----------------
  async function feedback(entry, type, comment) {
    const lang = state.settings.language;
    if (!state.settings.consented) return MS.ui.toast(MS.i18n.t(lang, 'needCloud'));
    if (!entry.scanId) return MS.ui.toast(MS.i18n.t(lang, 'queued'));
    const r = await send({ type: 'FEEDBACK', scanId: entry.scanId, feedbackType: type, comment });
    MS.ui.toast(MS.i18n.t(lang, r && r.queued ? 'queued' : 'thanks'));
  }

  async function report(entry) {
    const lang = state.settings.language;
    if (!state.settings.consented) return MS.ui.toast(MS.i18n.t(lang, 'needCloud'));
    const me = MS.extract.currentUser();
    const subject = MS.redact.redact(entry.email.subject, me);
    const body = MS.redact.redact(entry.email.body, me);
    const choice = await MS.ui.showReportDialog({
      lang,
      preview: `${subject}\n\n${body.slice(0, 1200)}${body.length > 1200 ? '…' : ''}`,
      defaultCategory: THREAT_TO_CATEGORY[entry.verdict.threatType] || 'other',
    });
    if (!choice) return;
    const r = await send({
      type: 'REPORT',
      payload: {
        consent: true,
        category: choice.category,
        comment: MS.redact.redact(choice.comment, me),
        senderEmail: entry.email.senderEmail,
        senderName: entry.email.senderName,
        subject,
        body,
        urls: entry.email.links.map((l) => l.href),
        attachmentNames: entry.email.attachments,
        scanId: entry.scanId || undefined,
      },
    });
    if (r && r.ok) {
      MS.ui.toast(MS.i18n.t(lang, r.queued ? 'queued' : 'reported'));
      // Mirror the server's personal blocklist locally so the effect is immediate and offline-proof.
      const domain = MS.brands.registrable(MS.brands.domainOfEmail(entry.email.senderEmail));
      const value = MS.brands.FREE_MAIL.has(domain) ? entry.email.senderEmail : domain;
      if (value && !MS.brands.isVerifiedDomain(domain)) {
        state.blocklist = [...new Set([value, ...state.blocklist])];
        chrome.storage.local.set({ blocklist: state.blocklist, verdicts: {} });
        entry.verdict = localAnalyze(entry.email);
        render(entry);
      }
    } else {
      MS.ui.toast((r && r.error) || 'Error');
    }
  }

  // ---------------- link interception ----------------
  function openUrl(url) {
    window.open(url, '_blank', 'noopener,noreferrer');
  }

  function onLinkActivate(ev) {
    try {
      if (!state.settings.enabled) return;
      if (ev.type === 'auxclick' && ev.button !== 1) return;
      const a = ev.target && ev.target.closest && ev.target.closest('a[href]');
      if (!a) return;
      const body = a.closest(SEL.messageBody);
      const entry = body && entries.get(body);
      if (!entry || entry.verdict.level === 'safe') return;
      const url = MS.heuristics.unwrapRedirect(a.href);
      if (!/^https?:/i.test(url)) return;

      ev.preventDefault();
      ev.stopImmediatePropagation();
      const v = entry.verdict;
      const lang = state.settings.language;
      if (v.level === 'warning') {
        MS.ui.showConfirm({ url, verdict: v, lang }).then((ok) => { if (ok) openUrl(url); });
      } else {
        MS.ui.showInterstitial({ url, verdict: v, lang }).then((ok) => {
          if (!ok) return;
          send({ type: 'OVERRIDE', scanId: entry.scanId || undefined, url, score: v.score });
          openUrl(url);
        });
      }
    } catch (e) { /* never break Gmail */ }
  }

  // ---------------- boot ----------------
  let scheduled = null;
  function schedule() {
    if (scheduled) return;
    scheduled = setTimeout(() => { scheduled = null; scan(); }, 300);
  }

  chrome.storage.onChanged.addListener((changes, area) => {
    if (area !== 'local') return;
    if (changes.settings) state.settings = { ...state.settings, ...changes.settings.newValue };
    if (changes.allowlist) state.allowlist = changes.allowlist.newValue || [];
    if (changes.blocklist) state.blocklist = changes.blocklist.newValue || [];
    if (changes.signatures) state.signatures = Object.values((changes.signatures.newValue || {}).items || {});
    if (changes.settings) live.forEach((b) => { const e = entries.get(b); if (e) render(e); });
  });

  (async () => {
    const s = await send({ type: 'GET_STATE' });
    if (s && s.settings) state = s;
    document.documentElement.setAttribute('data-mailshield', s && s.settings ? 'ready' : `ready-local:${(s && s.error) || 'no_state'}`);
    log(`content script ready — enabled=${state.settings.enabled} cloud=${state.settings.consented} signatures=${state.signatures.length}`);
    window.addEventListener('click', onLinkActivate, true);
    window.addEventListener('auxclick', onLinkActivate, true);
    new MutationObserver(schedule).observe(document.body, { childList: true, subtree: true });
    scan();
  })();
})(typeof globalThis !== 'undefined' ? globalThis : self);
