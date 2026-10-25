const jwt = require('jsonwebtoken');
const rateLimit = require('express-rate-limit');
const config = require('../config');
const { User } = require('../models');

/** Wrap async route handlers so rejections reach the error handler. */
const ah = (fn) => (req, res, next) => Promise.resolve(fn(req, res, next)).catch(next);

function signUserToken(user) {
  return jwt.sign({ sub: String(user._id), installId: user.installId, role: 'user' }, config.jwtSecret, { expiresIn: config.jwtExpiresIn });
}

function signAdminToken() {
  return jwt.sign({ sub: 'admin', role: 'admin' }, config.jwtSecret, { expiresIn: '8h' });
}

function bearer(req) {
  const h = req.headers.authorization || '';
  return h.startsWith('Bearer ') ? h.slice(7) : null;
}

/** Extension auth: JWT from POST /api/auth/register. Loads req.user. */
const requireUser = ah(async (req, res, next) => {
  const token = bearer(req);
  if (!token) return res.status(401).json({ error: 'missing_token' });
  let payload;
  try { payload = jwt.verify(token, config.jwtSecret); } catch (e) { return res.status(401).json({ error: 'invalid_token' }); }
  if (payload.role !== 'user') return res.status(403).json({ error: 'forbidden' });
  const user = await User.findById(payload.sub);
  if (!user || user.installId !== payload.installId) return res.status(401).json({ error: 'unknown_install' });
  req.user = user;
  next();
});

/** Admin auth: role-protected JWT from POST /api/admin/login. */
function requireAdmin(req, res, next) {
  const token = bearer(req);
  try {
    const payload = jwt.verify(token || '', config.jwtSecret);
    if (payload.role !== 'admin') throw new Error('not admin');
    req.admin = payload;
    next();
  } catch (e) {
    res.status(401).json({ error: 'admin_auth_required' });
  }
}

/** zod validation of req.body (or req.query). Replaces it with the parsed value. */
const validate = (schema, where = 'body') => (req, res, next) => {
  const r = schema.safeParse(req[where]);
  if (!r.success) return res.status(400).json({ error: 'invalid_input', details: r.error.issues.slice(0, 5).map((i) => `${i.path.join('.')}: ${i.message}`) });
  req[where === 'query' ? 'validQuery' : 'body'] = r.data;
  next();
};

const limiterOpts = { standardHeaders: 'draft-7', legacyHeaders: false, message: { error: 'rate_limited' } };

/** Per-install rate limit (falls back to IP before auth). */
const perInstall = (windowMs, limit) => rateLimit({
  ...limiterOpts, windowMs, limit,
  keyGenerator: (req) => (req.user ? `i:${req.user.installId}` : `ip:${req.ip}`),
});

const ipLimiter = rateLimit({ ...limiterOpts, windowMs: 15 * 60 * 1000, limit: 600 });
const registerLimiter = rateLimit({ ...limiterOpts, windowMs: 60 * 60 * 1000, limit: 20 });
const adminLoginLimiter = rateLimit({ ...limiterOpts, windowMs: 15 * 60 * 1000, limit: 10 });

/** Respond 503 rather than hang forever if something downstream stalls. */
function requestTimeout(req, res, next) {
  res.setTimeout(config.requestTimeoutMs + 2000, () => {
    if (!res.headersSent) res.status(503).json({ error: 'timeout', fallback: 'local' });
  });
  next();
}

function errorHandler(err, req, res, next) { // eslint-disable-line no-unused-vars
  console.error('[error]', req.method, req.path, err.message);
  if (res.headersSent) return;
  res.status(err.status || 500).json({ error: err.expose ? err.message : 'server_error' });
}

module.exports = {
  ah, signUserToken, signAdminToken, requireUser, requireAdmin, validate,
  perInstall, ipLimiter, registerLimiter, adminLoginLimiter, requestTimeout, errorHandler,
};
