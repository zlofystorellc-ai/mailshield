/*
 * Extension build configuration. Change BACKEND_URL before publishing and add the same origin
 * to "host_permissions" in manifest.json. No secrets or API keys ever belong in this file.
 */
self.MAILSHIELD_CONFIG = {
  BACKEND_URL: 'http://localhost:3000',
  PRIVACY_URL: 'http://localhost:3000/privacy',
  REQUEST_TIMEOUT_MS: 8000,
  VERDICT_CACHE_MS: 24 * 60 * 60 * 1000,
  SIGNATURE_SYNC_MINUTES: 360,
};
