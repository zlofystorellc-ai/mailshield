/*
 * Report analysis worker (cron-style polling; no Redis needed).
 * Runs in-process when RUN_WORKER=true (default), or standalone: `npm run worker`.
 * Claims one 'new' report at a time with an atomic lock so several workers can run safely.
 */
const config = require('../config');
const { ReportedMessage } = require('../models');
const clustering = require('../services/clustering');

const POLL_MS = 10000;
const LOCK_STALE_MS = 5 * 60 * 1000;
const MAX_PER_TICK = 50;

let timer = null;
let running = false;

async function claimNext() {
  return ReportedMessage.findOneAndUpdate(
    { status: 'new', heldForAdmin: false, $or: [{ lockedAt: null }, { lockedAt: { $lt: new Date(Date.now() - LOCK_STALE_MS) } }] },
    { $set: { lockedAt: new Date() } },
    { sort: { createdAt: 1 }, new: true },
  );
}

async function tick() {
  if (running) return;
  running = true;
  try {
    for (let i = 0; i < MAX_PER_TICK; i++) {
      const report = await claimNext();
      if (!report) break;
      try {
        const sig = await clustering.processReport(report);
        if (sig) console.log(`[worker] cluster ${report.clusterId} -> ${sig.signatureId} (${sig.status}, users=${sig.distinctUsers})`);
      } catch (e) {
        console.error('[worker] failed report', String(report._id), e.message);
        await ReportedMessage.updateOne({ _id: report._id }, { $set: { error: e.message.slice(0, 300) } });
      }
    }
  } finally {
    running = false;
  }
}

function start() {
  if (timer) return;
  console.log('[worker] analysis worker started');
  timer = setInterval(() => tick().catch((e) => console.error('[worker]', e.message)), POLL_MS);
  tick().catch(() => {});
}

function stop() { clearInterval(timer); timer = null; }

module.exports = { start, stop, tick };

if (require.main === module) {
  require('../db').connect(config.mongoUri).then(start).catch((e) => { console.error(e); process.exit(1); });
}
