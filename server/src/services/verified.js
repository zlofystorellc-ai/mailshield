// Verified legit senders = built-in brand domains + admin-managed verified_senders collection (cached 5 min).
const { VerifiedSender } = require('../models');
const MS = require('../shared');

let cache = { at: 0, set: new Set() };

async function load() {
  if (Date.now() - cache.at < 5 * 60 * 1000) return cache.set;
  const docs = await VerifiedSender.find({}, { domain: 1 }).lean().catch(() => []);
  cache = { at: Date.now(), set: new Set(docs.map((d) => d.domain)) };
  return cache.set;
}

async function isVerified(domain) {
  if (!domain) return false;
  const reg = MS.brands.registrable(domain);
  if (MS.brands.isVerifiedDomain(reg)) return true;
  return (await load()).has(reg);
}

function invalidate() { cache.at = 0; }

module.exports = { isVerified, invalidate };
