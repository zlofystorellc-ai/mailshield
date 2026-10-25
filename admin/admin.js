/*
 * MailShield admin panel. Plain JS, no build step.
 * Reported content is attacker-controlled: it is ONLY ever inserted via textContent.
 */
(function () {
  'use strict';
  const TOKEN_KEY = 'ms_admin_token';
  let token = sessionStorage.getItem(TOKEN_KEY);

  // ---------- helpers ----------
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

  async function api(path, opts = {}) {
    const res = await fetch('/api/admin' + path, {
      method: opts.method || 'GET',
      headers: { 'Content-Type': 'application/json', ...(token ? { Authorization: 'Bearer ' + token } : {}) },
      body: opts.body ? JSON.stringify(opts.body) : undefined,
    });
    if (res.status === 401 && path !== '/login') { logout(); throw new Error('Session expired'); }
    const data = await res.json().catch(() => ({}));
    if (!res.ok) throw new Error(data.message || data.error || 'HTTP ' + res.status);
    return data;
  }

  const view = () => document.getElementById('view');
  const fmtDate = (d) => (d ? new Date(d).toLocaleString() : '');

  function show(...nodes) { view().replaceChildren(...nodes); }
  function errorBox(e) { return h('p', { class: 'error', role: 'alert' }, e.message || String(e)); }

  async function act(fn, rerender) {
    try { await fn(); await rerender(); } catch (e) { alert(e.message); }
  }

  // ---------- auth ----------
  function logout() {
    token = null; sessionStorage.removeItem(TOKEN_KEY);
    document.getElementById('app').hidden = true;
    document.getElementById('login').hidden = false;
  }

  document.getElementById('login-form').addEventListener('submit', async (e) => {
    e.preventDefault();
    try {
      const { token: tk } = await api('/login', { method: 'POST', body: { secret: document.getElementById('secret').value } });
      token = tk; sessionStorage.setItem(TOKEN_KEY, tk);
      document.getElementById('secret').value = '';
      start();
    } catch (err) {
      document.getElementById('login-error').textContent = 'Sign-in failed: ' + err.message;
    }
  });
  document.getElementById('logout').addEventListener('click', logout);

  // ---------- views ----------
  const views = {
    async dashboard() {
      const { days, totals } = await api('/stats?days=14');
      const sum = (k) => days.reduce((s, d) => s + d[k], 0);
      const max = Math.max(1, ...days.map((d) => d.scans));
      const kpi = (label, value) => h('div', { class: 'card kpi' }, h('b', {}, value), h('span', {}, label));
      const bar = (cls, n) => { const b = h('div', { class: 'bar ' + cls, title: String(n) }); b.style.width = (100 * n / max) + '%'; return b; };
      show(
        h('h2', {}, 'Last 14 days'),
        h('div', { class: 'kpis' },
          kpi('Scans', sum('scans')), kpi('Warnings', sum('warnings')), kpi('Blocks', sum('blocks')),
          kpi('Overrides ("open anyway")', sum('overrides')), kpi('Reports', sum('reports')), kpi('False alarms', sum('falseAlarms')),
          kpi('Installs', totals.users), kpi('Active signatures', totals.activeSigs), kpi('Pending review', totals.pendingSigs),
          kpi('Signature version', totals.signatureVersion)),
        h('div', { class: 'legend' }, h('span', {}, h('i', { class: 'bar scans' }), 'scans'), h('span', {}, h('i', { class: 'bar warn' }), 'warnings'), h('span', {}, h('i', { class: 'bar block' }), 'blocks')),
        h('table', {},
          h('thead', {}, h('tr', {}, ['Date', 'Scans', 'Warnings', 'Blocks', 'Overrides', 'Reports', 'False alarms', ''].map((c) => h('th', {}, c)))),
          h('tbody', {}, days.slice().reverse().map((d) => h('tr', {},
            h('td', {}, d.date), h('td', { class: 'num' }, d.scans), h('td', { class: 'num' }, d.warnings), h('td', { class: 'num' }, d.blocks),
            h('td', { class: 'num' }, d.overrides), h('td', { class: 'num' }, d.reports), h('td', { class: 'num' }, d.falseAlarms),
            h('td', {}, h('div', { class: 'bars' }, bar('scans', d.scans), bar('warn', d.warnings), bar('block', d.blocks))))))));
    },

    async clusters() {
      const { clusters } = await api('/clusters');
      show(h('h2', {}, 'Report clusters'),
        h('p', { class: 'meta' }, 'Similar user reports grouped by SimHash / embedding similarity. Samples are already PII-redacted.'),
        clusters.length ? h('div', { class: 'list' }, clusters.map((c) => h('div', { class: 'card item' },
          h('h3', {}, c.suggestedCategory, h('span', { class: 'meta' }, `${c.distinctUsers} users · ${c.reportCount} reports · last ${fmtDate(c.last)}`),
            c.signature ? h('span', { class: 'pill ' + c.signature.status }, c.signature.status) : h('span', { class: 'meta' }, 'no signature yet')),
          c.signature && h('div', { class: 'chips' }, (c.signature.keywords || []).map((k) => h('span', { class: 'chip' }, k))),
          c.signature && (c.signature.suggestedKeywords || []).length > 0 &&
            h('div', { class: 'meta' }, 'LLM-suggested keywords: ' + c.signature.suggestedKeywords.join(', ')),
          c.samples.map((s) => h('div', { class: 'sample' }, `From: ${s.senderDomain || '?'}\nSubject: ${s.subject || ''}\n\n${s.body || ''}`)),
          h('div', { class: 'actions' },
            h('button', { onclick: () => act(() => api(`/clusters/${encodeURIComponent(c.clusterId)}/evaluate`, { method: 'POST' }), views.clusters) }, 'Re-evaluate'),
            c.signature && c.signature.status !== 'active' && h('button', { class: 'ok', onclick: () => act(() => api(`/signatures/${c.signature.signatureId}/approve`, { method: 'POST' }), views.clusters) }, 'Approve signature'),
            c.signature && c.signature.status !== 'rejected' && h('button', { class: 'danger', onclick: () => act(() => api(`/signatures/${c.signature.signatureId}/reject`, { method: 'POST' }), views.clusters) }, 'Reject'))))) : h('p', { class: 'empty' }, 'No clusters yet.'));
    },

    async signatures(status = 'pending_review') {
      const { signatures } = await api('/signatures' + (status ? '?status=' + status : ''));
      const filter = h('select', { onchange: (e) => views.signatures(e.target.value).catch((err) => show(errorBox(err))) },
        [['pending_review', 'Pending review'], ['active', 'Active'], ['rejected', 'Rejected'], ['', 'All']].map(([v, l]) => h('option', { value: v, selected: v === status }, l)));
      show(h('h2', {}, 'Scam signatures'), h('div', { class: 'toolbar' }, 'Status:', filter),
        signatures.length ? h('div', { class: 'list' }, signatures.map((s) => {
          const en = h('textarea', { 'aria-label': 'Reason (English)' }); en.value = (s.reasonText && s.reasonText.en) || '';
          const hi = h('textarea', { 'aria-label': 'Reason (Hinglish)' }); hi.value = (s.reasonText && s.reasonText.hinglish) || '';
          const rerender = () => views.signatures(status);
          return h('div', { class: 'card item' },
            h('h3', {}, s.category, h('span', { class: 'pill ' + s.status }, s.status), h('span', { class: 'meta' }, s.signatureId)),
            h('div', { class: 'meta' }, `${s.distinctUsers} users · ${s.reportCount} reports · ${s.falseAlarmCount} false alarms · confidence ${Number(s.confidence).toFixed(2)} · v${s.version} · simhash ${s.simhash}`),
            h('div', { class: 'chips' }, (s.keywords || []).map((k) => h('span', { class: 'chip' }, k))),
            (s.senderDomains || []).length ? h('div', { class: 'meta' }, 'Sender domains: ' + s.senderDomains.join(', ')) : null,
            (s.urlDomains || []).length ? h('div', { class: 'meta' }, 'URL domains: ' + s.urlDomains.join(', ')) : null,
            h('div', { class: 'grid2' }, h('label', {}, 'Reason (English)', en), h('label', {}, 'Reason (Hinglish)', hi)),
            h('div', { class: 'actions' },
              h('button', { onclick: () => act(() => api(`/signatures/${s.signatureId}`, { method: 'PATCH', body: { reasonText: { en: en.value, hinglish: hi.value } } }), rerender) }, 'Save reason text'),
              s.status !== 'active' && h('button', { class: 'ok', onclick: () => act(() => api(`/signatures/${s.signatureId}/approve`, { method: 'POST' }), rerender) }, 'Approve / activate'),
              s.status !== 'rejected' && h('button', { class: 'danger', onclick: () => act(() => api(`/signatures/${s.signatureId}/reject`, { method: 'POST' }), rerender) }, 'Reject')));
        })) : h('p', { class: 'empty' }, 'Nothing here.'));
    },

    async feedback() {
      const { items } = await api('/feedback?reviewed=false&type=false_positive');
      show(h('h2', {}, 'False-alarm feedback (unreviewed)'),
        items.length ? h('table', {},
          h('thead', {}, h('tr', {}, ['When', 'Sender domain', 'Score', 'Reasons', 'Signature', 'Comment', ''].map((c) => h('th', {}, c)))),
          h('tbody', {}, items.map((f) => {
            const s = f.scanId || {};
            return h('tr', {},
              h('td', {}, fmtDate(f.createdAt)), h('td', {}, s.senderDomain || ''), h('td', { class: 'num' }, s.score != null ? s.score : ''),
              h('td', {}, (s.reasons || []).join(', ')), h('td', {}, f.signatureId || ''), h('td', {}, f.comment || ''),
              h('td', {}, h('div', { class: 'actions' },
                h('button', { onclick: () => act(() => api(`/feedback/${f._id}/review`, { method: 'POST' }), views.feedback) }, 'Mark reviewed'),
                s.senderDomain && h('button', { class: 'ok', onclick: () => act(async () => { await api('/verified-senders', { method: 'POST', body: { domain: s.senderDomain } }); await api(`/feedback/${f._id}/review`, { method: 'POST' }); }, views.feedback) }, 'Verify sender'))));
          }))) : h('p', { class: 'empty' }, 'No unreviewed false alarms.'));
    },

    async blocklist() {
      const [{ items: current }, { items: candidates }] = await Promise.all([api('/blocklist'), api('/blocklist/candidates')]);
      const input = h('input', { placeholder: 'scam-domain.xyz', 'aria-label': 'Domain to block' });
      show(h('h2', {}, 'Global blocklist'),
        h('div', { class: 'toolbar' }, input, h('button', { class: 'primary', onclick: () => act(() => api('/blocklist', { method: 'POST', body: { domain: input.value } }), views.blocklist) }, 'Block domain')),
        h('h3', {}, 'Candidates (reported by ≥2 users)'),
        candidates.length ? h('table', {}, h('thead', {}, h('tr', {}, ['Domain', 'Distinct users', 'Reports', ''].map((c) => h('th', {}, c)))),
          h('tbody', {}, candidates.map((c) => h('tr', {}, h('td', {}, c.domain), h('td', { class: 'num' }, c.distinctUsers), h('td', { class: 'num' }, c.reports),
            h('td', {}, h('button', { class: 'danger', onclick: () => act(() => api('/blocklist', { method: 'POST', body: { domain: c.domain, reportCount: c.reports } }), views.blocklist) }, 'Promote to global blocklist')))))) : h('p', { class: 'empty' }, 'No candidates.'),
        h('h3', {}, 'Blocked'),
        current.length ? h('table', {}, h('thead', {}, h('tr', {}, ['Domain', 'Reports', 'Added', ''].map((c) => h('th', {}, c)))),
          h('tbody', {}, current.map((g) => h('tr', {}, h('td', {}, g.domain), h('td', { class: 'num' }, g.reportCount), h('td', {}, fmtDate(g.createdAt)),
            h('td', {}, h('button', { onclick: () => act(() => api('/blocklist/' + encodeURIComponent(g.domain), { method: 'DELETE' }), views.blocklist) }, 'Remove')))))) : h('p', { class: 'empty' }, 'Empty.'));
    },

    async held() {
      const { items } = await api('/reports/held');
      show(h('h2', {}, 'Reports about verified senders'),
        h('p', { class: 'meta' }, 'These are never processed automatically. Release one only if the verified domain is genuinely compromised or misused.'),
        items.length ? h('div', { class: 'list' }, items.map((r) => h('div', { class: 'card item' },
          h('h3', {}, r.category, h('span', { class: 'meta' }, `${r.senderDomain} · ${fmtDate(r.createdAt)}`)),
          h('div', { class: 'sample' }, `Subject: ${r.redactedSubject || ''}\n\n${(r.redactedBody || '').slice(0, 1500)}`),
          r.comment && h('div', { class: 'meta' }, 'Comment: ' + r.comment),
          h('div', { class: 'actions' },
            h('button', { class: 'ok', onclick: () => act(() => api(`/reports/${r._id}/release`, { method: 'POST' }), views.held) }, 'Release for clustering'),
            h('button', { class: 'danger', onclick: () => act(() => api(`/reports/${r._id}/reject`, { method: 'POST' }), views.held) }, 'Reject'))))) : h('p', { class: 'empty' }, 'Nothing held.'));
    },

    async verified() {
      const { items, builtIn } = await api('/verified-senders');
      const domain = h('input', { placeholder: 'bank.example.in', 'aria-label': 'Domain' });
      const org = h('input', { placeholder: 'Organization', 'aria-label': 'Organization' });
      show(h('h2', {}, 'Verified legit senders'),
        h('p', { class: 'meta' }, 'Verified domains can never be auto-blocked or turned into signatures; only admins can act on them.'),
        h('div', { class: 'toolbar' }, domain, org, h('button', { class: 'primary', onclick: () => act(() => api('/verified-senders', { method: 'POST', body: { domain: domain.value, organization: org.value } }), views.verified) }, 'Add')),
        items.length ? h('table', {}, h('thead', {}, h('tr', {}, ['Domain', 'Organization', 'Added by', ''].map((c) => h('th', {}, c)))),
          h('tbody', {}, items.map((v) => h('tr', {}, h('td', {}, v.domain), h('td', {}, v.organization || ''), h('td', {}, v.addedBy || ''),
            h('td', {}, h('button', { onclick: () => act(() => api('/verified-senders/' + encodeURIComponent(v.domain), { method: 'DELETE' }), views.verified) }, 'Remove')))))) : h('p', { class: 'empty' }, 'No custom entries.'),
        h('h3', {}, 'Built-in (from extension/lib/brands.js)'),
        h('div', { class: 'chips' }, builtIn.map((d) => h('span', { class: 'chip' }, d))));
    },
  };

  function select(name) {
    document.querySelectorAll('nav button').forEach((b) => b.classList.toggle('active', b.dataset.view === name));
    show(h('p', { class: 'meta' }, 'Loading…'));
    views[name]().catch((e) => show(errorBox(e)));
  }

  document.querySelectorAll('nav button').forEach((b) => b.addEventListener('click', () => select(b.dataset.view)));

  function start() {
    document.getElementById('login').hidden = true;
    document.getElementById('app').hidden = false;
    select('dashboard');
  }

  if (token) start();
})();
