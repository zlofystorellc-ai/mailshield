const config = require('./config');
const db = require('./db');
const { createApp } = require('./app');
const worker = require('./workers/analysisWorker');

async function main() {
  await db.connect(config.mongoUri);
  const app = createApp();
  const server = app.listen(config.port, () => console.log(`[server] MailShield API on :${config.port} (${config.env})`));
  if (config.runWorker) worker.start();

  const shutdown = () => {
    worker.stop();
    server.close(() => db.mongoose.disconnect().then(() => process.exit(0)));
  };
  process.on('SIGTERM', shutdown);
  process.on('SIGINT', shutdown);
}

main().catch((e) => {
  console.error('[server] failed to start:', e.message);
  process.exit(1);
});
