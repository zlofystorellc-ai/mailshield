/* First-run consent. Cloud features stay off until the user explicitly agrees here. */
(function () {
  'use strict';
  const $ = (id) => document.getElementById(id);
  const send = (msg) => new Promise((resolve) => chrome.runtime.sendMessage(msg, resolve));

  $('agree').addEventListener('change', (e) => { $('accept').disabled = !e.target.checked; });
  $('accept').addEventListener('click', async () => {
    await send({ type: 'SET_SETTINGS', patch: { consented: true, consentedAt: Date.now() } });
    $('done').textContent = 'Cloud protection is on. You can close this tab and open Gmail.';
  });
  $('local').addEventListener('click', async () => {
    await send({ type: 'SET_SETTINGS', patch: { consented: false, aiEnabled: false } });
    $('done').textContent = 'Local-only mode. You can enable cloud protection later from the MailShield popup.';
  });
  $('privacy').addEventListener('click', (e) => { e.preventDefault(); chrome.tabs.create({ url: self.MAILSHIELD_CONFIG.PRIVACY_URL }); });

  send({ type: 'GET_STATE' }).then((s) => {
    if (s && s.settings && s.settings.consented) $('done').textContent = 'Cloud protection is currently ON.';
  });
})();
