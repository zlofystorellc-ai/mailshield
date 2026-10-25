const path = require('path');
const express = require('express');
const helmet = require('helmet');
const cors = require('cors');
const config = require('./config');
const { ipLimiter, requestTimeout, errorHandler } = require('./middleware');

function createApp() {
  const app = express();
  app.set('trust proxy', 1); // Render/Railway sit behind one proxy
  app.disable('x-powered-by');

  app.use(helmet({
    contentSecurityPolicy: { directives: { 'default-src': ["'self'"], 'script-src': ["'self'"], 'style-src': ["'self'"], 'img-src': ["'self'", 'data:'] } },
  }));

  // CORS: only the extension origin(s). Same-origin admin panel needs no CORS.
  app.use('/api', cors({
    origin(origin, cb) {
      if (!origin) return cb(null, true); // service worker fetches may omit Origin; JWT still required
      if (config.extensionOrigins.includes(origin)) return cb(null, true);
      if ((config.env !== 'production' || config.allowAnyExtensionOrigin) && origin.startsWith('chrome-extension://')) return cb(null, true);
      return cb(null, false);
    },
    methods: ['GET', 'POST', 'PUT', 'PATCH', 'DELETE'],
    allowedHeaders: ['Content-Type', 'Authorization'],
    maxAge: 600,
  }));

  app.use(express.json({ limit: '100kb' }));
  app.use(ipLimiter);
  app.use(requestTimeout);

  app.get('/healthz', (req, res) => res.json({ ok: true }));
  app.use('/api/admin', require('./routes/admin'));
  app.use('/api', require('./routes/api'));
  app.use('/admin', express.static(path.resolve(__dirname, '../../admin'), { index: 'index.html' }));
  app.get('/privacy', (req, res) => res.sendFile(path.resolve(__dirname, '../../privacy-policy.md'), { headers: { 'Content-Type': 'text/plain; charset=utf-8' } }));

  app.use('/api', (req, res) => res.status(404).json({ error: 'not_found' }));
  app.use(errorHandler);
  return app;
}

module.exports = { createApp };
