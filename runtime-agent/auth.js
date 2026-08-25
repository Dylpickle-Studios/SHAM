'use strict';

const fs = require('node:fs');
const path = require('node:path');
const crypto = require('node:crypto');

// Mirrors src/config.js's loadJwtSecret pattern: generate once, persist with
// a restrictive mode, and never accept a value from an environment variable
// that could be echoed into logs or process listings by mistake.
function loadOrCreateToken(tokenPath) {
  fs.mkdirSync(path.dirname(tokenPath), { recursive: true, mode: 0o700 });
  if (fs.existsSync(tokenPath)) {
    const value = fs.readFileSync(tokenPath, 'utf8').trim();
    if (value.length < 32) throw new Error(`${tokenPath} is missing or invalid.`);
    try { fs.chmodSync(tokenPath, 0o600); } catch { /* best effort on non-POSIX storage */ }
    return value;
  }
  const token = crypto.randomBytes(32).toString('base64url');
  fs.writeFileSync(tokenPath, `${token}\n`, { mode: 0o600 });
  return token;
}

function digest(value) { return crypto.createHash('sha256').update(String(value)).digest(); }

// Fixed-size digest comparison avoids both the length-mismatch exception that
// crypto.timingSafeEqual throws on unequal-length buffers and any timing
// signal tied to the presented token's length.
function tokensMatch(expected, presented) {
  if (typeof presented !== 'string' || !presented) return false;
  return crypto.timingSafeEqual(digest(expected), digest(presented));
}

function extractBearerToken(header) {
  const value = String(header || '');
  const match = /^Bearer (.+)$/.exec(value);
  return match ? match[1] : '';
}

module.exports = { loadOrCreateToken, tokensMatch, extractBearerToken };
