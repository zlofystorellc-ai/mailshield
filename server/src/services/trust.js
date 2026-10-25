// Reporter trust: confirmed reports raise trust, rejected ones lower it. Range [0, 2], default 1.
const { ReporterTrust } = require('../models');

const UP = 0.2;
const DOWN = 0.3;

async function getTrustMap(userIds) {
  const docs = await ReporterTrust.find({ userId: { $in: userIds } }).lean();
  const map = new Map(userIds.map((id) => [String(id), 1.0]));
  docs.forEach((d) => map.set(String(d.userId), d.trustScore));
  return map;
}

async function adjust(userId, confirmed) {
  const doc = (await ReporterTrust.findOne({ userId })) || new ReporterTrust({ userId });
  if (confirmed) { doc.confirmedReports += 1; doc.trustScore = Math.min(2, doc.trustScore + UP); }
  else { doc.rejectedReports += 1; doc.trustScore = Math.max(0, doc.trustScore - DOWN); }
  await doc.save();
  return doc;
}

module.exports = { getTrustMap, adjust };
