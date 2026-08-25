// @ts-nocheck -- not part of this session's checkJs rollout yet.
// This file still has genuine `tsc --noEmit` findings (mostly narrow
// `let x = null`-style inference and untyped Express handlers, the same
// patterns already fixed across most of src/) that need real per-file
// JSDoc work to resolve, not a suppression. Tracked as follow-up work;
// see tsconfig.json and docs/development.md. Do not add more files here
// without a similar comment and a plan to remove it.
const crypto = require('node:crypto');
const { promisify } = require('node:util');
const jwt = require('jsonwebtoken');
const { JWT_SECRET, AUTH_RATE_LIMIT_BUCKETS, PUBLIC_ORIGIN } = require('./config');
const { db } = require('./db');

const COOKIE_NAME = 'sham_token';
const TOKEN_TTL_SECONDS = 12 * 60 * 60;
const MFA_TOKEN_TTL_SECONDS = 5 * 60;
const scrypt = promisify(crypto.scrypt);
let lastRevokedSessionSweep = 0;

function normalizeUsername(value) {
  const username = String(value || '').trim();
  if (!/^[a-zA-Z0-9][a-zA-Z0-9._-]{2,39}$/.test(username)) {
    throw new Error('Username must be 3–40 characters and use letters, numbers, dot, underscore, or hyphen.');
  }
  return username;
}

function validatePassword(password) {
  if (typeof password !== 'string' || password.length < 12 || password.length > 200) {
    throw new Error('Password must be between 12 and 200 characters.');
  }
}

async function hashPassword(password, salt = crypto.randomBytes(16).toString('hex')) {
  validatePassword(password);
  const derived = await scrypt(password, salt, 64);
  return { salt, hash: Buffer.from(derived).toString('hex') };
}

async function verifyPassword(password, salt, expectedHex) {
  if (typeof password !== 'string' || password.length > 200) return false;
  try {
    const actual = Buffer.from(await scrypt(password, salt, 64));
    const expected = Buffer.from(expectedHex, 'hex');
    return expected.length === actual.length && crypto.timingSafeEqual(actual, expected);
  } catch {
    return false;
  }
}

function parseCookies(header = '') {
  return header.split(';').reduce((cookies, part) => {
    const separator = part.indexOf('=');
    if (separator < 0) return cookies;
    const key = part.slice(0, separator).trim();
    const value = part.slice(separator + 1).trim();
    if (!key) return cookies;
    try { cookies[key] = decodeURIComponent(value); } catch { cookies[key] = value; }
    return cookies;
  }, {});
}

function issueMfaToken(user) {
  return jwt.sign(
    { sub: String(user.id), username: user.username, purpose: 'mfa' },
    JWT_SECRET,
    { algorithm: 'HS256', expiresIn: MFA_TOKEN_TTL_SECONDS, issuer: 'sham', audience: 'sham-mfa' }
  );
}

function verifyMfaToken(token) {
  try {
    const payload = jwt.verify(String(token || ''), JWT_SECRET, { algorithms: ['HS256'], issuer: 'sham', audience: 'sham-mfa' });
    if (payload.purpose !== 'mfa') return null;
    const user = db.prepare('SELECT * FROM users WHERE id = ?').get(Number(payload.sub));
    return user?.active ? user : null;
  } catch { return null; }
}

function issueToken(user) {
  const sessionVersion = Number(user.session_version ?? db.prepare('SELECT session_version FROM users WHERE id = ?').get(user.id)?.session_version ?? 1);
  return jwt.sign(
    { sub: String(user.id), username: user.username, role: user.role, sv: sessionVersion, sid: crypto.randomUUID() },
    JWT_SECRET,
    { algorithm: 'HS256', expiresIn: TOKEN_TTL_SECONDS, issuer: 'sham', audience: 'sham-dashboard' }
  );
}

function sweepRevokedSessions(now = Date.now()) {
  if (now - lastRevokedSessionSweep < 5 * 60_000) return;
  db.prepare('DELETE FROM revoked_sessions WHERE expires_at <= ?').run(now);
  lastRevokedSessionSweep = now;
}

function revokeCurrentSession(req) {
  if (!req.authSessionId || !req.user?.id || !req.authTokenExpiresAt) return false;
  sweepRevokedSessions();
  db.prepare('INSERT OR REPLACE INTO revoked_sessions (sid, user_id, expires_at) VALUES (?, ?, ?)')
    .run(req.authSessionId, req.user.id, req.authTokenExpiresAt);
  return true;
}

function rotateSessionVersion(userId) {
  db.prepare('UPDATE users SET session_version = session_version + 1 WHERE id = ?').run(Number(userId));
  return db.prepare('SELECT * FROM users WHERE id = ?').get(Number(userId));
}

function setAuthCookie(req, res, token) {
  const parts = [
    `${COOKIE_NAME}=${encodeURIComponent(token)}`,
    'HttpOnly',
    'SameSite=Strict',
    'Path=/',
    `Max-Age=${TOKEN_TTL_SECONDS}`
  ];
  if (req.secure || PUBLIC_ORIGIN.startsWith('https://')) parts.push('Secure');
  res.setHeader('Set-Cookie', parts.join('; '));
}

function clearAuthCookie(req, res) {
  const parts = [`${COOKIE_NAME}=`, 'HttpOnly', 'SameSite=Strict', 'Path=/', 'Max-Age=0'];
  if (req.secure || PUBLIC_ORIGIN.startsWith('https://')) parts.push('Secure');
  res.setHeader('Set-Cookie', parts.join('; '));
}

function tokenHash(token) {
  return crypto.createHash('sha256').update(String(token || '')).digest('hex');
}

function tokenScopes(value) {
  try {
    const scopes = JSON.parse(value || '[]');
    return Array.isArray(scopes) ? scopes.filter((scope) => typeof scope === 'string') : [];
  } catch { return []; }
}

function requiredApiScope(req) {
  const path = String(req.path || req.originalUrl || '');
  if (['GET', 'HEAD', 'OPTIONS'].includes(req.method)) {
    if (/runtime-logs|\/logs(?:\?|$)/.test(path)) return 'logs:read';
    return 'read';
  }
  if (/\/deploy(?:\/|$)|\/releases\/.*\/rollback/.test(path)) return 'deploy';
  if (/\/(?:start|stop|restart)(?:\?|$)/.test(path)) return 'sites:control';
  return '*';
}

function resolveUser(req) {
  req.authType = null;
  req.authScopes = [];
  const authorization = String(req.get?.('authorization') || req.headers?.authorization || '');
  const bearer = /^Bearer\s+(sham_pat_[A-Za-z0-9_-]{32,256})$/i.exec(authorization)?.[1];
  if (bearer) {
    const row = db.prepare(`SELECT tokens.id AS token_id, tokens.scopes_json, tokens.expires_at,
      users.id, users.username, users.role, users.active, users.totp_enabled, users.created_at
      FROM api_tokens AS tokens JOIN users ON users.id = tokens.user_id WHERE tokens.token_hash = ?`).get(tokenHash(bearer));
    if (!row?.active || (row.expires_at && Date.parse(row.expires_at) <= Date.now())) return null;
    req.authType = 'api-token';
    req.authScopes = tokenScopes(row.scopes_json);
    // Keep this write cheap and bounded; precision finer than five minutes is not useful operationally.
    try { db.prepare("UPDATE api_tokens SET last_used_at = CURRENT_TIMESTAMP WHERE id = ? AND (last_used_at IS NULL OR last_used_at < datetime('now', '-5 minutes'))").run(row.token_id); } catch { /* telemetry only */ }
    return { id: row.id, username: row.username, role: row.role, active: row.active, totp_enabled: row.totp_enabled, created_at: row.created_at };
  }

  const token = parseCookies(req.headers.cookie)[COOKIE_NAME];
  if (!token) return null;
  try {
    const payload = jwt.verify(token, JWT_SECRET, {
      algorithms: ['HS256'],
      issuer: 'sham',
      audience: 'sham-dashboard'
    });
    if (!payload.sid || !Number.isSafeInteger(Number(payload.sv))) return null;
    const user = db.prepare('SELECT id, username, role, active, totp_enabled, password_configured, session_version, created_at FROM users WHERE id = ?').get(Number(payload.sub));
    if (!user?.active || Number(payload.sv) !== Number(user.session_version)) return null;
    const now = Date.now();
    sweepRevokedSessions(now);
    if (db.prepare('SELECT 1 FROM revoked_sessions WHERE sid = ? AND expires_at > ?').get(String(payload.sid), now)) return null;
    req.authType = 'session';
    req.authSessionId = String(payload.sid);
    req.authTokenExpiresAt = Number(payload.exp || 0) * 1000;
    return user;
  } catch {
    return null;
  }
}

function optionalAuth(req, _res, next) {
  req.user = resolveUser(req);
  next();
}

function requireAuth(req, res, next) {
  req.user = resolveUser(req);
  if (!req.user) return res.status(401).json({ error: 'Authentication required.' });
  if (req.authType === 'api-token') {
    const required = requiredApiScope(req);
    if (!req.authScopes.includes('*') && !req.authScopes.includes(required)) return res.status(403).json({ error: `API token requires the ${required} scope.` });
  }
  next();
}

function requireAdmin(req, res, next) {
  if (req.user?.role !== 'admin') return res.status(403).json({ error: 'Administrator access required.' });
  next();
}

function sameOriginGuard(req, res, next) {
  if (req.path.startsWith('/api/hooks/deploy/')) return next();
  // Bearer API tokens are not ambient browser credentials, so they are not susceptible to CSRF.
  if (/^Bearer\s+sham_pat_/i.test(String(req.get('authorization') || ''))) return next();
  if (['GET', 'HEAD', 'OPTIONS'].includes(req.method)) return next();

  const fetchSite = req.get('sec-fetch-site');
  if (fetchSite && !['same-origin', 'none'].includes(fetchSite)) {
    return res.status(403).json({ error: 'Cross-site request blocked.' });
  }

  const origin = req.get('origin');
  if (origin) {
    try {
      const supplied = new URL(origin).origin;
      const expected = PUBLIC_ORIGIN || new URL(`${req.protocol}://${req.get('host')}`).origin;
      if (supplied !== expected) return res.status(403).json({ error: 'Origin validation failed.' });
    } catch {
      return res.status(403).json({ error: 'Origin validation failed.' });
    }
  }
  next();
}

function createRateLimiter({ windowMs, max, maxBuckets = AUTH_RATE_LIMIT_BUCKETS }) {
  const buckets = new Map();
  let lastSweep = 0;
  return (req, res, next) => {
    const key = req.ip || req.socket.remoteAddress || 'unknown';
    const now = Date.now();
    if (now - lastSweep >= Math.min(windowMs, 60_000)) {
      for (const [bucketKey, bucket] of buckets) {
        if (now >= bucket.resetAt) buckets.delete(bucketKey);
      }
      lastSweep = now;
    }
    if (!buckets.has(key) && buckets.size >= maxBuckets) {
      const oldestKey = buckets.keys().next().value;
      if (oldestKey !== undefined) buckets.delete(oldestKey);
    }
    const current = buckets.get(key);
    if (!current || now >= current.resetAt) {
      buckets.set(key, { count: 1, resetAt: now + windowMs });
      res.set('RateLimit-Limit', String(max));
      res.set('RateLimit-Remaining', String(Math.max(0, max - 1)));
      res.set('RateLimit-Reset', String(Math.ceil((now + windowMs) / 1000)));
      return next();
    }
    current.count += 1;
    buckets.delete(key);
    buckets.set(key, current);
    res.set('RateLimit-Limit', String(max));
    res.set('RateLimit-Remaining', String(Math.max(0, max - current.count)));
    res.set('RateLimit-Reset', String(Math.ceil(current.resetAt / 1000)));
    if (current.count > max) {
      res.set('Retry-After', String(Math.ceil((current.resetAt - now) / 1000)));
      return res.status(429).json({ error: 'Too many attempts. Try again later.' });
    }
    next();
  };
}

module.exports = {
  normalizeUsername,
  validatePassword,
  hashPassword,
  verifyPassword,
  issueToken,
  issueMfaToken,
  verifyMfaToken,
  setAuthCookie,
  clearAuthCookie,
  optionalAuth,
  requireAuth,
  requireAdmin,
  sameOriginGuard,
  createRateLimiter,
  tokenHash,
  revokeCurrentSession,
  rotateSessionVersion
};
