/*
 * Seeds verified_senders with the built-in brand/bank/government domains so admins can see/edit them,
 * and initializes the signature version counter.  Usage: npm run seed
 */
const config = require('../src/config');
const db = require('../src/db');
const M = require('../src/models');
const MS = require('../src/shared');

(async () => {
  await db.connect(config.mongoUri);
  await M.Meta.updateOne({ key: 'signatureVersion' }, { $setOnInsert: { value: 0 } }, { upsert: true });
  let n = 0;
  for (const [org, b] of Object.entries(MS.brands.BRANDS)) {
    for (const domain of b.domains) {
      await M.VerifiedSender.updateOne({ domain }, { $setOnInsert: { domain, organization: org, addedBy: 'seed' } }, { upsert: true });
      n += 1;
    }
  }
  await Promise.all(Object.values(M).filter((x) => x && typeof x.syncIndexes === 'function').map((Model) => Model.syncIndexes()));
  console.log(`[seed] ${n} verified sender domains, indexes synced`);
  await db.mongoose.disconnect();
})().catch((e) => { console.error(e); process.exit(1); });
