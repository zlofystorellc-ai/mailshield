/*
 * All injected UI, rendered in closed Shadow DOM so Gmail's CSS can't touch it (and vice versa).
 * Email-derived strings are ALWAYS inserted with textContent — never innerHTML.
 */
(function (g) {
  'use strict';
  const MS = (g.MailShield = g.MailShield || {});
  const t = (lang, k) => MS.i18n.t(lang, k);

  const CSS = `
:host { all: initial; }
* { box-sizing: border-box; font-family: "Google Sans", Roboto, "Segoe UI", Arial, sans-serif; }
.panel { margin: 0 0 12px; border-radius: 10px; font-size: 13px; line-height: 1.45; color: #1f2328; }
.badge { display: inline-flex; align-items: center; gap: 6px; padding: 4px 10px; border-radius: 999px; background: #e6f4ea; color: #137333; font-weight: 500; }
.banner { padding: 12px 14px; border: 1px solid; }
.warning { background: #fef7e0; border-color: #f9ab00; }
.block { background: #fce8e6; border-color: #d93025; }
.title { font-size: 14px; font-weight: 600; display: flex; gap: 8px; align-items: center; }
.score { margin-left: auto; font-size: 12px; font-weight: 500; opacity: .75; white-space: nowrap; }
ul { margin: 6px 0 4px 0; padding-left: 20px; }
li { margin: 2px 0; }
.muted { color: #5f6368; font-size: 12px; }
.row { display: flex; flex-wrap: wrap; gap: 6px; align-items: center; margin-top: 8px; }
button { cursor: pointer; border-radius: 8px; border: 1px solid #dadce0; background: #fff; color: #1f2328; padding: 5px 10px; font-size: 12px; }
button:hover { background: #f1f3f4; }
button:focus-visible, textarea:focus-visible, select:focus-visible, input:focus-visible { outline: 2px solid #1a73e8; outline-offset: 1px; }
button.primary { background: #1a73e8; border-color: #1a73e8; color: #fff; font-weight: 600; }
button.primary:hover { background: #1765cc; }
button.danger { background: #fff; border-color: #d93025; color: #b3261e; }
button[disabled] { opacity: .5; cursor: not-allowed; }
textarea, select { width: 100%; border: 1px solid #dadce0; border-radius: 8px; padding: 6px 8px; font-size: 13px; color: #1f2328; background: #fff; }
textarea { min-height: 56px; resize: vertical; }
.fb-comment { display: none; width: 100%; margin-top: 6px; }
.fb-comment.open { display: block; }
.toast { position: fixed; left: 50%; bottom: 24px; transform: translateX(-50%); background: #202124; color: #fff; padding: 10px 16px; border-radius: 8px; font-size: 13px; z-index: 2147483647; max-width: 90vw; }
.overlay { position: fixed; inset: 0; z-index: 2147483647; display: flex; align-items: center; justify-content: center; background: rgba(32,33,36,.55); padding: 16px; }
.dialog { background: #fff; border-radius: 14px; max-width: 520px; width: 100%; max-height: 90vh; overflow: auto; padding: 20px; box-shadow: 0 12px 40px rgba(0,0,0,.3); color: #1f2328; font-size: 14px; }
.dialog h2 { margin: 0 0 8px; font-size: 18px; }
.url { word-break: break-all; background: #f1f3f4; border-radius: 6px; padding: 6px 8px; font-family: ui-monospace, Menlo, monospace; font-size: 12px; }
.url b { color: #b3261e; }
.inter { position: fixed; inset: 0; z-index: 2147483647; background: #b3261e; color: #fff; overflow: auto; display: flex; justify-content: center; padding: 32px 16px; }
.inter .card { max-width: 680px; width: 100%; }
.inter h1 { font-size: 26px; margin: 8px 0 12px; }
.inter h3 { font-size: 15px; margin: 18px 0 6px; text-transform: uppercase; letter-spacing: .04em; opacity: .9; }
.inter .box { background: rgba(255,255,255,.12); border-radius: 10px; padding: 12px 16px; }
.inter .harm b { display: block; }
.inter .url { background: rgba(0,0,0,.25); color: #fff; }
.inter .url b { color: #ffd7d2; }
.inter button.primary { background: #fff; color: #b3261e; border-color: #fff; font-size: 15px; padding: 10px 18px; }
.inter button.ghost { background: transparent; color: #fff; border-color: rgba(255,255,255,.6); }
.inter label { display: flex; gap: 8px; align-items: flex-start; margin: 10px 0; }
.confirm-area { display: none; margin-top: 12px; }
.confirm-area.open { display: block; }
.preview { white-space: pre-wrap; max-height: 160px; overflow: auto; background: #f1f3f4; border-radius: 8px; padding: 8px; font-size: 12px; color: #3c4043; }
label.consent { display: flex; gap: 8px; align-items: flex-start; margin: 10px 0; font-size: 13px; }
.field { margin: 10px 0; }
.field > span { display: block; font-weight: 500; margin-bottom: 4px; }
/* In-email banners stay light: Gmail's theme is independent of the OS scheme. Overlays follow the OS. */
@media (prefers-color-scheme: dark) {
  .dialog { background: #292a2d; color: #e8eaed; }
  .dialog .muted { color: #9aa0a6; }
  .dialog button { background: #303134; color: #e8eaed; border-color: #5f6368; }
  .dialog button.primary { background: #8ab4f8; border-color: #8ab4f8; color: #202124; }
  .url, .preview { background: #3c4043; color: #e8eaed; }
  textarea, select { background: #303134; color: #e8eaed; border-color: #5f6368; }
}`;

  let sheet = null;
  function adopt(root) {
    try {
      if (!sheet) { sheet = new CSSStyleSheet(); sheet.replaceSync(CSS); }
      root.adoptedStyleSheets = [sheet];
    } catch (e) {
      const s = document.createElement('style'); s.textContent = CSS; root.append(s);
    }
  }

  /** Tiny DOM builder; text children become text nodes (XSS-safe). */
  function h(tag, attrs, ...kids) {
    const el = document.createElement(tag);
    Object.entries(attrs || {}).forEach(([k, v]) => {
      if (v == null || v === false) return;
      if (k === 'class') el.className = v;
      else if (k.startsWith('on')) el.addEventListener(k.slice(2), v);
      else el.setAttribute(k, v === true ? '' : v);
    });
    kids.flat().forEach((c) => { if (c != null && c !== false) el.append(c.nodeType ? c : document.createTextNode(String(c))); });
    return el;
  }

  function shadowHost(attr) {
    const host = document.createElement('div');
    host.setAttribute(attr, '');
    const root = host.attachShadow({ mode: 'closed' });
    adopt(root);
    return { host, root };
  }

  function reasonText(r, lang) {
    return lang === 'hi' ? (r.hi || r.reasonHi || r.en || r.reason) : (r.en || r.reason);
  }

  /** URL with the real registrable domain highlighted. */
  function urlView(url) {
    let host = ''; let reg = '';
    try { host = new URL(url).hostname; reg = MS.brands.registrable(host); } catch (e) { return h('div', { class: 'url' }, url); }
    const i = url.indexOf(host);
    const ri = host.lastIndexOf(reg);
    if (i < 0 || ri < 0) return h('div', { class: 'url' }, url);
    return h('div', { class: 'url' },
      url.slice(0, i + ri), h('b', {}, reg), url.slice(i + ri + reg.length));
  }

  function toast(msg) {
    const { host, root } = shadowHost('data-mailshield-toast');
    root.append(h('div', { class: 'toast', role: 'status' }, msg));
    document.documentElement.append(host);
    setTimeout(() => host.remove(), 4500);
  }

  // -------------------- per-email panel --------------------
  /**
   * @param {HTMLElement} bodyEl  Gmail message body; the panel is inserted just above it
   * @param {{verdict, lang, pending, source}} view
   * @param {{onFeedback:(type,comment)=>void, onReport:()=>void}} handlers
   */
  function renderPanel(bodyEl, view, handlers) {
    let host = bodyEl.previousElementSibling;
    if (!host || !host.hasAttribute('data-mailshield-panel')) {
      const s = shadowHost('data-mailshield-panel');
      host = s.host;
      host._msRoot = s.root;
      bodyEl.parentElement.insertBefore(host, bodyEl);
    }
    const root = host._msRoot;
    [...root.childNodes].forEach((n) => n.remove());

    const { verdict: v, lang } = view;
    const panel = h('div', { class: 'panel', role: v.level === 'safe' ? 'status' : 'alert' });

    if (v.level === 'safe') {
      panel.append(h('span', { class: 'badge' }, '✔ ', view.pending ? t(lang, 'checking') : t(lang, 'safe'),
        view.source === 'local' && !view.pending ? h('span', { class: 'muted' }, ` · ${t(lang, 'localOnly')}`) : null));
    } else {
      const banner = h('div', { class: `banner ${v.level}` },
        h('div', { class: 'title' }, v.level === 'block' ? '⛔' : '⚠️', t(lang, v.level === 'block' ? 'blockTitle' : 'warnTitle'),
          h('span', { class: 'score' }, `${t(lang, 'scoreLabel')}: ${v.score}/100`)),
        h('div', { class: 'muted' }, t(lang, 'why')),
        h('ul', {}, (v.reasons || []).slice(0, 8).map((r) => h('li', {}, reasonText(r, lang)))),
        h('div', { class: 'muted' }, t(lang, v.level === 'block' ? 'linksBlocked' : 'linksGuarded')));
      panel.append(banner);
    }

    // Feedback actions — shown on EVERY email.
    const comment = h('textarea', { class: 'fb-comment', placeholder: t(lang, 'comment'), maxlength: '1000', 'aria-label': t(lang, 'comment') });
    let pendingType = null;
    const sendBtn = h('button', { class: 'primary', style: 'display:none', onclick: () => { handlers.onFeedback(pendingType, comment.value); comment.value = ''; comment.classList.remove('open'); sendBtn.style.display = 'none'; } }, t(lang, 'send'));
    const pick = (type) => () => { pendingType = type; comment.classList.add('open'); sendBtn.style.display = ''; comment.focus(); };
    panel.append(h('div', { class: 'row' },
      h('button', { onclick: pick('false_positive') }, t(lang, 'fp')),
      h('button', { onclick: pick('true_positive') }, t(lang, 'tp')),
      h('button', { class: 'danger', onclick: handlers.onReport }, t(lang, 'report')),
      comment, sendBtn));
    root.append(panel);
  }

  // -------------------- modal helpers --------------------
  function modal(build) {
    return new Promise((resolve) => {
      const { host, root } = shadowHost('data-mailshield-modal');
      const prevFocus = document.activeElement;
      const close = (val) => {
        host.remove();
        document.removeEventListener('keydown', onKey, true);
        if (prevFocus && prevFocus.focus) prevFocus.focus();
        resolve(val);
      };
      const onKey = (e) => { if (e.key === 'Escape') { e.stopPropagation(); close(build.escapeValue); } };
      document.addEventListener('keydown', onKey, true);
      root.append(build(close));
      document.documentElement.append(host);
      const first = root.querySelector('[data-autofocus]');
      if (first) first.focus();
    });
  }

  /** WARNING level: confirm before opening. Resolves true to open. */
  function showConfirm({ url, verdict, lang }) {
    const build = (close) => h('div', { class: 'overlay', onclick: (e) => { if (e.target === e.currentTarget) close(false); } },
      h('div', { class: 'dialog', role: 'dialog', 'aria-modal': 'true', 'aria-label': t(lang, 'confirmTitle') },
        h('h2', {}, '⚠️ ', t(lang, 'confirmTitle')),
        h('p', {}, t(lang, 'confirmBody')),
        h('ul', {}, (verdict.reasons || []).slice(0, 4).map((r) => h('li', {}, reasonText(r, lang)))),
        h('div', { class: 'muted' }, t(lang, 'destination')),
        urlView(url),
        h('div', { class: 'row', style: 'justify-content:flex-end;margin-top:16px' },
          h('button', { class: 'primary', 'data-autofocus': true, onclick: () => close(false) }, t(lang, 'cancel')),
          h('button', { onclick: () => close(true) }, t(lang, 'openLink')))));
    build.escapeValue = false;
    return modal(build);
  }

  /** BLOCK level: full-page red interstitial with two-step override. Resolves true to open. */
  function showInterstitial({ url, verdict, lang }) {
    const build = (close) => {
      const finalBtn = h('button', { class: 'ghost', disabled: true, onclick: () => close(true) }, t(lang, 'openNow'));
      const check = h('input', { type: 'checkbox', onchange: (e) => { finalBtn.disabled = !e.target.checked; } });
      const area = h('div', { class: 'confirm-area' }, h('label', {}, check, h('span', {}, t(lang, 'confirmRisk'))), finalBtn);
      return h('div', { class: 'inter', role: 'alertdialog', 'aria-modal': 'true', 'aria-label': t(lang, 'interTitle') },
        h('div', { class: 'card' },
          h('div', { style: 'font-size:44px' }, '⛔'),
          h('h1', {}, t(lang, 'interTitle')),
          urlView(url),
          h('h3', {}, t(lang, 'why')),
          h('div', { class: 'box' }, h('ul', {}, (verdict.reasons || []).map((r) => h('li', {}, reasonText(r, lang))))),
          h('h3', {}, t(lang, 'harmTitle')),
          h('div', { class: 'box' }, (verdict.harms && verdict.harms.length ? verdict.harms : [MS.harms.harmFor(verdict.threatType)]).map((hm) =>
            h('p', { class: 'harm' }, h('b', {}, lang === 'hi' ? hm.title.hi : hm.title.en), lang === 'hi' ? hm.hi : hm.en))),
          h('div', { class: 'row', style: 'margin-top:20px' },
            h('button', { class: 'primary', 'data-autofocus': true, onclick: () => close(false) }, t(lang, 'goBack')),
            h('button', { class: 'ghost', onclick: () => area.classList.add('open') }, t(lang, 'openAnyway'))),
          area));
    };
    build.escapeValue = false;
    return modal(build);
  }

  /** Report dialog with category, comment, redacted preview and explicit consent. */
  function showReportDialog({ lang, preview, defaultCategory }) {
    const build = (close) => {
      const select = h('select', { 'aria-label': t(lang, 'category') },
        Object.entries(MS.harms.CATEGORIES).map(([k, label]) => h('option', { value: k, selected: k === defaultCategory }, lang === 'hi' ? label.hi : label.en)));
      const comment = h('textarea', { maxlength: '1000', placeholder: t(lang, 'comment') });
      const submit = h('button', { class: 'primary', disabled: true, onclick: () => close({ category: select.value, comment: comment.value }) }, t(lang, 'submitReport'));
      const consent = h('input', { type: 'checkbox', onchange: (e) => { submit.disabled = !e.target.checked; } });
      return h('div', { class: 'overlay', onclick: (e) => { if (e.target === e.currentTarget) close(null); } },
        h('div', { class: 'dialog', role: 'dialog', 'aria-modal': 'true', 'aria-label': t(lang, 'reportTitle') },
          h('h2', {}, t(lang, 'reportTitle')),
          h('p', { class: 'muted' }, t(lang, 'reportIntro')),
          h('label', { class: 'field' }, h('span', {}, t(lang, 'category')), select),
          h('label', { class: 'field' }, h('span', {}, t(lang, 'comment')), comment),
          h('div', { class: 'field' }, h('span', {}, t(lang, 'preview')), h('div', { class: 'preview' }, preview)),
          h('label', { class: 'consent' }, consent, h('span', {}, t(lang, 'consent'))),
          h('div', { class: 'row', style: 'justify-content:flex-end' },
            h('button', { 'data-autofocus': true, onclick: () => close(null) }, t(lang, 'cancel')), submit)));
    };
    build.escapeValue = null;
    return modal(build);
  }

  MS.ui = { renderPanel, showConfirm, showInterstitial, showReportDialog, toast };
})(typeof globalThis !== 'undefined' ? globalThis : self);
