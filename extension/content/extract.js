/*
 * Extracts sender, subject, body text, links (visible text + real href) and attachment names
 * from an opened Gmail message. Uses only MS.selectors for DOM lookups.
 */
(function (g) {
  'use strict';
  const MS = (g.MailShield = g.MailShield || {});
  const SEL = MS.selectors;
  const PAT = MS.selectorPatterns;

  const MAX_BODY = 20000;
  const MAX_LINKS = 50;

  function containerOf(body) {
    return body.closest(SEL.messageContainer) || body.parentElement || document.body;
  }

  function sender(container) {
    const el = container.querySelector(SEL.sender) || container.querySelector(SEL.senderFallback);
    if (!el) return { senderEmail: '', senderName: '' };
    return { senderEmail: (el.getAttribute('email') || '').toLowerCase(), senderName: el.getAttribute('name') || el.textContent.trim() };
  }

  function replyTo(container) {
    for (const row of container.querySelectorAll(SEL.headerDetailsRow)) {
      const cells = row.querySelectorAll('td');
      if (cells.length >= 2 && PAT.replyToLabel.test(cells[0].textContent)) {
        const withAttr = cells[1].querySelector('[email]');
        if (withAttr) return withAttr.getAttribute('email');
        const m = cells[1].textContent.match(PAT.emailInText);
        if (m) return m[0];
      }
    }
    return '';
  }

  function attachments(container) {
    const names = new Set();
    container.querySelectorAll(SEL.attachmentName).forEach((el) => { const t = el.textContent.trim(); if (t) names.add(t); });
    container.querySelectorAll(SEL.attachmentDownload).forEach((el) => {
      const parts = (el.getAttribute('download_url') || '').split(':'); // mime:filename:url
      if (parts.length > 2 && parts[1]) names.add(parts[1]);
    });
    return [...names].slice(0, 30);
  }

  function links(body) {
    const out = [];
    body.querySelectorAll('a[href]').forEach((a) => {
      if (out.length >= MAX_LINKS) return;
      const href = MS.heuristics.unwrapRedirect(a.href);
      if (!/^https?:/i.test(href)) return; // skip mailto:, tel:, javascript:
      out.push({ text: (a.innerText || a.getAttribute('aria-label') || '').trim().slice(0, 300), href });
    });
    return out;
  }

  /** The signed-in user's identity, used only to redact it from reports. */
  function currentUser() {
    const btn = document.querySelector(SEL.accountButton);
    const m = btn && (btn.getAttribute('aria-label') || '').match(PAT.accountAria);
    if (m) return { userName: m[1], userEmail: m[2] };
    const t = document.title.match(PAT.emailInText);
    return { userName: '', userEmail: t ? t[0] : '' };
  }

  function fromBody(body) {
    const container = containerOf(body);
    const subjectEl = document.querySelector(SEL.subject);
    const email = {
      ...sender(container),
      replyTo: replyTo(container),
      subject: subjectEl ? subjectEl.textContent.trim() : '',
      body: (body.innerText || '').slice(0, MAX_BODY),
      links: links(body),
      attachments: attachments(container),
    };
    email.key = MS.simhash.hash32(
      [email.senderEmail, email.subject, email.body.slice(0, 2000), email.links.map((l) => l.href).join('|')].join('\n'), 7,
    ).toString(16);
    return email;
  }

  MS.extract = { fromBody, currentUser, containerOf };
})(typeof globalThis !== 'undefined' ? globalThis : self);
