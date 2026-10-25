/* MailShield popup: protection toggle, language, consent, lists, stats, data deletion. */
(function () {
  'use strict';
  const CFG = self.MAILSHIELD_CONFIG;
  const $ = (id) => document.getElementById(id);

  const POPUP_STRINGS = {
    en: {
      scanned: 'Emails scanned', warnings: 'Warnings', blocked: 'Threats blocked', reports: 'Reports made',
      language: 'Language', cloud: 'Cloud protection', ai: 'AI analysis (optional)', allowlist: 'Allowlist', blocklist: 'Blocklist',
      add: 'Add', privacy: 'Privacy policy', about: 'What data is sent?', delete: 'Delete my data',
      on: 'Protection is <b>ON</b>', off: 'Protection is <b>OFF</b>', cloudOn: 'cloud checks + scam signatures active',
      cloudOff: 'local checks only — enable cloud protection for link reputation and community scam alerts',
      empty: 'No domains yet', confirmDelete: 'Delete all MailShield data stored on our server and in this browser?',
      deleted: 'Your data was deleted.', deleteFailed: 'Could not reach the server. Try again later.', invalid: 'Enter a valid domain like example.com',
      sigs: 'scam signatures',
    },
    hi: {
      scanned: 'Emails scan hue', warnings: 'Warnings', blocked: 'Khatre roke', reports: 'Reports ki',
      language: 'Bhasha', cloud: 'Cloud protection', ai: 'AI analysis (optional)', allowlist: 'Allowlist', blocklist: 'Blocklist',
      add: 'Jodein', privacy: 'Privacy policy', about: 'Kya data bheja jaata hai?', delete: 'Mera data delete karein',
      on: 'Protection <b>ON</b> hai', off: 'Protection <b>OFF</b> hai', cloudOn: 'cloud checks + scam signatures chalu',
      cloudOff: 'sirf local checks — link reputation aur community scam alerts ke liye cloud protection ON karein',
      empty: 'Abhi koi domain nahi', confirmDelete: 'Kya MailShield ka saara data (server aur browser) delete karna hai?',
      deleted: 'Aapka data delete ho gaya.', deleteFailed: 'Server tak nahi pahunch paaye. Baad mein try karein.', invalid: 'Sahi domain likhein, jaise example.com',
      sigs: 'scam signatures',
    },
  };

  let state = null;
  let listType = 'allow';
  const send = (msg) => new Promise((resolve) => chrome.runtime.sendMessage(msg, resolve));
  const tr = (k) => (POPUP_STRINGS[state.settings.language] || POPUP_STRINGS.en)[k] || POPUP_STRINGS.en[k];

  function renderStatus() {
    const s = state.settings;
    const el = $('status');
    el.className = 'status ' + (s.enabled ? 'on' : 'off');
    // Only static, trusted strings go through innerHTML here.
    el.innerHTML = `${tr(s.enabled ? 'on' : 'off')} · ${s.consented ? tr('cloudOn') : tr('cloudOff')}`;
    if (s.consented) el.append(` · ${state.signatures.length} ${tr('sigs')}`);
  }

  function renderList() {
    const items = listType === 'allow' ? state.allowlist : state.blocklist;
    const ul = $('list-items');
    ul.replaceChildren();
    if (!items.length) {
      const li = document.createElement('li'); li.className = 'empty'; li.textContent = tr('empty'); ul.append(li);
    }
    items.forEach((d) => {
      const li = document.createElement('li');
      const span = document.createElement('span'); span.textContent = d;
      const btn = document.createElement('button'); btn.textContent = '×'; btn.setAttribute('aria-label', `Remove ${d}`);
      btn.addEventListener('click', async () => { await send({ type: 'LIST_REMOVE', listType, domain: d }); await refresh(); });
      li.append(span, btn); ul.append(li);
    });
    $('tab-allow').classList.toggle('active', listType === 'allow');
    $('tab-block').classList.toggle('active', listType === 'block');
  }

  function render() {
    const s = state.settings;
    $('enabled').checked = s.enabled;
    $('language').value = s.language;
    $('consented').checked = s.consented;
    $('aiEnabled').checked = s.aiEnabled;
    $('aiEnabled').disabled = !s.consented;
    ['scanned', 'warnings', 'blocked', 'reports'].forEach((k) => { $('s-' + k).textContent = state.stats[k] || 0; });
    document.querySelectorAll('[data-i18n]').forEach((el) => { el.textContent = tr(el.dataset.i18n); });
    document.documentElement.lang = s.language === 'hi' ? 'hi-Latn' : 'en';
    renderStatus();
    renderList();
  }

  async function refresh() {
    state = await send({ type: 'GET_STATE' });
    render();
  }

  const setSetting = async (patch) => { await send({ type: 'SET_SETTINGS', patch }); await refresh(); };

  $('enabled').addEventListener('change', (e) => setSetting({ enabled: e.target.checked }));
  $('language').addEventListener('change', (e) => setSetting({ language: e.target.value }));
  $('aiEnabled').addEventListener('change', (e) => setSetting({ aiEnabled: e.target.checked }));
  $('consented').addEventListener('change', (e) => {
    if (e.target.checked) chrome.tabs.create({ url: chrome.runtime.getURL('onboarding/onboarding.html') }); // consent is given there
    else setSetting({ consented: false, aiEnabled: false });
    e.target.checked = state.settings.consented;
  });
  document.querySelectorAll('.tabs button').forEach((b) => b.addEventListener('click', () => { listType = b.dataset.type; renderList(); }));

  $('list-form').addEventListener('submit', async (e) => {
    e.preventDefault();
    const r = await send({ type: 'LIST_ADD', listType, domain: $('list-input').value });
    $('list-error').textContent = r && r.ok ? '' : (r && r.error === 'invalid_domain' ? tr('invalid') : (r && r.error) || 'Error');
    if (r && r.ok) $('list-input').value = '';
    await refresh();
  });

  $('privacy').addEventListener('click', (e) => { e.preventDefault(); chrome.tabs.create({ url: CFG.PRIVACY_URL }); });
  $('onboarding').addEventListener('click', (e) => { e.preventDefault(); chrome.tabs.create({ url: chrome.runtime.getURL('onboarding/onboarding.html') }); });
  $('delete').addEventListener('click', async () => {
    if (!confirm(tr('confirmDelete'))) return;
    const r = await send({ type: 'DELETE_DATA' });
    alert(r && r.ok ? tr('deleted') : tr('deleteFailed'));
    await refresh();
  });

  refresh();
})();
