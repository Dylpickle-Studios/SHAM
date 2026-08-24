'use strict';

const crypto = require('node:crypto');

const discoveryCache = new Map();
const jwksCache = new Map();

const MAX_OIDC_RESPONSE_BYTES = 2 * 1024 * 1024;
const MAX_ID_TOKEN_BYTES = 128 * 1024;
const MAX_CACHE_ENTRIES = 32;

function cacheSet(cache, key, value) {
  if (!cache.has(key) && cache.size >= MAX_CACHE_ENTRIES) cache.delete(cache.keys().next().value);
  cache.set(key, value);
}

async function responseTextBounded(response, maxBytes = MAX_OIDC_RESPONSE_BYTES) {
  const declared = Number(response.headers.get('content-length') || 0);
  if (Number.isFinite(declared) && declared > maxBytes) throw new Error('OIDC endpoint response is too large.');
  if (!response.body) return '';
  const chunks = [];
  let total = 0;
  for await (const chunk of response.body) {
    const buffer = Buffer.from(chunk);
    total += buffer.length;
    if (total > maxBytes) {
      try { await response.body.cancel?.(); } catch { /* ignore */ }
      throw new Error('OIDC endpoint response is too large.');
    }
    chunks.push(buffer);
  }
  return Buffer.concat(chunks, total).toString('utf8');
}

function b64url(value) { return Buffer.from(value).toString('base64url'); }
function sha256(value) { return crypto.createHash('sha256').update(String(value)).digest(); }
function hashState(value) { return sha256(value).toString('hex'); }

function normalizeIssuer(value) {
  const issuer = String(value || '').trim().replace(/\/$/, '');
  const url = new URL(issuer);
  const hostname = String(url.hostname || '').replace(/^\[|\]$/g, '').toLowerCase();
  if (url.username || url.password || url.search || url.hash) {
    throw new Error('OIDC issuer must not contain credentials, query parameters, or a fragment.');
  }
  if (url.protocol !== 'https:' && !(url.protocol === 'http:' && ['localhost', '127.0.0.1', '::1'].includes(hostname))) {
    throw new Error('OIDC issuer must use HTTPS (HTTP is only allowed for loopback development).');
  }
  return url.href.replace(/\/$/, '');
}

function validateEndpoint(value, label = 'OIDC endpoint') {
  const url = new URL(String(value || ''));
  if (url.username || url.password || url.hash) throw new Error(`${label} must not contain credentials or a fragment.`);
  const hostname = String(url.hostname || '').replace(/^\[|\]$/g, '').toLowerCase();
  const loopback = ['localhost', '127.0.0.1', '::1'].includes(hostname);
  if (url.protocol !== 'https:' && !(url.protocol === 'http:' && loopback)) throw new Error(`${label} must use HTTPS (HTTP is only allowed for loopback development).`);
  return url.href;
}

async function fetchJson(url, options = {}) {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), options.timeoutMs || 10_000);
  timer.unref?.();
  const { timeoutMs: _timeoutMs, ...fetchOptions } = options;
  try {
    const response = await fetch(validateEndpoint(url), { ...fetchOptions, redirect: 'error', cache: 'no-store', signal: controller.signal, headers: { Accept: 'application/json', ...(options.headers || {}) } });
    const text = await responseTextBounded(response);
    let payload;
    try { payload = text ? JSON.parse(text) : {}; } catch { payload = {}; }
    if (!response.ok) throw new Error(payload.error_description || payload.error || `OIDC endpoint returned HTTP ${response.status}.`);
    return payload;
  } finally { clearTimeout(timer); }
}

async function discovery(issuer) {
  const normalized = normalizeIssuer(issuer);
  const cached = discoveryCache.get(normalized);
  if (cached && cached.expiresAt > Date.now()) return cached.value;
  const value = await fetchJson(`${normalized}/.well-known/openid-configuration`);
  if (normalizeIssuer(value.issuer) !== normalized) throw new Error('OIDC discovery issuer does not match the configured issuer.');
  for (const key of ['authorization_endpoint', 'token_endpoint', 'jwks_uri']) {
    if (!value[key]) throw new Error(`OIDC discovery is missing ${key}.`);
    value[key] = validateEndpoint(value[key], `OIDC ${key}`);
  }
  cacheSet(discoveryCache, normalized, { value, expiresAt: Date.now() + 60 * 60_000 });
  return value;
}

function parseJwt(token) {
  const value = String(token || '');
  if (!value || Buffer.byteLength(value) > MAX_ID_TOKEN_BYTES) throw new Error('OIDC provider returned an invalid ID token.');
  const parts = value.split('.');
  if (parts.length !== 3 || parts.some((part) => !part || part.length > MAX_ID_TOKEN_BYTES)) throw new Error('OIDC provider returned an invalid ID token.');
  try {
    const header = JSON.parse(Buffer.from(parts[0], 'base64url').toString('utf8'));
    const payload = JSON.parse(Buffer.from(parts[1], 'base64url').toString('utf8'));
    if (!header || Array.isArray(header) || typeof header !== 'object' || !payload || Array.isArray(payload) || typeof payload !== 'object') throw new Error('invalid claims');
    return {
      header,
      payload,
      signingInput: Buffer.from(`${parts[0]}.${parts[1]}`),
      signature: Buffer.from(parts[2], 'base64url')
    };
  } catch { throw new Error('OIDC provider returned an invalid ID token.'); }
}

async function jwks(uri, force = false) {
  const cached = jwksCache.get(uri);
  if (!force && cached && cached.expiresAt > Date.now()) return cached.value;
  const value = await fetchJson(uri);
  if (!Array.isArray(value.keys) || value.keys.length > 100) throw new Error('OIDC JWKS response is invalid.');
  cacheSet(jwksCache, uri, { value, expiresAt: Date.now() + 60 * 60_000 });
  return value;
}

function verifyWithJwk(parsed, jwk) {
  const algorithm = String(parsed.header.alg || '');
  const allowed = new Set(['RS256', 'RS384', 'RS512', 'PS256', 'PS384', 'PS512', 'ES256', 'ES384', 'ES512']);
  if (!allowed.has(algorithm)) throw new Error(`OIDC ID token uses unsupported signing algorithm ${algorithm || '(none)'}.`);
  const digest = algorithm.slice(-3).replace('256', 'sha256').replace('384', 'sha384').replace('512', 'sha512');
  const key = crypto.createPublicKey({ key: jwk, format: 'jwk' });
  let options = key;
  if (algorithm.startsWith('PS')) options = { key, padding: crypto.constants.RSA_PKCS1_PSS_PADDING, saltLength: crypto.constants.RSA_PSS_SALTLEN_DIGEST };
  else if (algorithm.startsWith('ES')) options = { key, dsaEncoding: 'ieee-p1363' };
  return crypto.verify(digest, parsed.signingInput, options, parsed.signature);
}

async function verifyIdToken(idToken, { issuer, clientId, nonce, discoveryDocument }) {
  const parsed = parseJwt(idToken);
  if (!parsed.header.kid) throw new Error('OIDC ID token is missing a key identifier.');
  let keys = await jwks(discoveryDocument.jwks_uri);
  let key = keys.keys.find((row) => row.kid === parsed.header.kid && (!row.use || row.use === 'sig'));
  if (!key) {
    keys = await jwks(discoveryDocument.jwks_uri, true);
    key = keys.keys.find((row) => row.kid === parsed.header.kid && (!row.use || row.use === 'sig'));
  }
  if (!key) throw new Error('OIDC ID token signing key was not found.');
  if (key.alg && key.alg !== parsed.header.alg) throw new Error('OIDC ID token signing key algorithm does not match the token.');
  if (Array.isArray(discoveryDocument.id_token_signing_alg_values_supported) && !discoveryDocument.id_token_signing_alg_values_supported.includes(parsed.header.alg)) throw new Error('OIDC ID token uses an algorithm not advertised by the provider.');
  if (!verifyWithJwk(parsed, key)) throw new Error('OIDC ID token signature could not be verified.');
  const claims = parsed.payload;
  const now = Math.floor(Date.now() / 1000);
  const normalizedIssuer = normalizeIssuer(issuer);
  if (normalizeIssuer(claims.iss) !== normalizedIssuer) throw new Error('OIDC ID token issuer does not match.');
  const audiences = Array.isArray(claims.aud) ? claims.aud : [claims.aud];
  if (!audiences.includes(clientId)) throw new Error('OIDC ID token audience does not match this SHAM instance.');
  if (audiences.length > 1 && claims.azp !== clientId) throw new Error('OIDC authorized party does not match this SHAM instance.');
  if (!Number.isFinite(Number(claims.exp)) || Number(claims.exp) < now - 60) throw new Error('OIDC ID token is expired.');
  if (claims.nbf && Number(claims.nbf) > now + 60) throw new Error('OIDC ID token is not valid yet.');
  if (claims.iat && Number(claims.iat) > now + 60) throw new Error('OIDC ID token was issued in the future.');
  if (!claims.sub) throw new Error('OIDC ID token is missing the subject claim.');
  if (nonce && claims.nonce !== nonce) throw new Error('OIDC nonce did not match.');
  return claims;
}

async function beginAuthorization({ issuer, clientId, redirectUri, db }) {
  const document = await discovery(issuer);
  const state = crypto.randomBytes(32).toString('base64url');
  const nonce = crypto.randomBytes(32).toString('base64url');
  const verifier = crypto.randomBytes(48).toString('base64url');
  const challenge = b64url(sha256(verifier));
  db.prepare('DELETE FROM oidc_states WHERE expires_at < ?').run(Date.now());
  db.prepare('INSERT INTO oidc_states (state_hash, nonce, verifier, redirect_uri, expires_at) VALUES (?, ?, ?, ?, ?)')
    .run(hashState(state), nonce, verifier, redirectUri, Date.now() + 10 * 60_000);
  const url = new URL(document.authorization_endpoint);
  url.searchParams.set('response_type', 'code');
  url.searchParams.set('client_id', clientId);
  url.searchParams.set('redirect_uri', redirectUri);
  url.searchParams.set('scope', 'openid profile email');
  url.searchParams.set('state', state);
  url.searchParams.set('nonce', nonce);
  url.searchParams.set('code_challenge', challenge);
  url.searchParams.set('code_challenge_method', 'S256');
  return url.href;
}

async function completeAuthorization({ issuer, clientId, clientSecret, state, code, redirectUri, db }) {
  const transaction = db.transaction(() => {
    const row = db.prepare('SELECT * FROM oidc_states WHERE state_hash = ?').get(hashState(state));
    if (row) db.prepare('DELETE FROM oidc_states WHERE state_hash = ?').run(hashState(state));
    return row;
  });
  const stored = transaction();
  if (!stored || Number(stored.expires_at) < Date.now()) throw new Error('OIDC login state expired or did not match.');
  if (stored.redirect_uri !== redirectUri) throw new Error('OIDC redirect URI did not match the login request.');
  const document = await discovery(issuer);
  const body = new URLSearchParams({
    grant_type: 'authorization_code', code: String(code || ''), redirect_uri: redirectUri,
    client_id: clientId, code_verifier: stored.verifier
  });
  const headers = { 'Content-Type': 'application/x-www-form-urlencoded' };
  if (clientSecret) {
    const methods = Array.isArray(document.token_endpoint_auth_methods_supported) ? document.token_endpoint_auth_methods_supported : [];
    if (!methods.length || methods.includes('client_secret_basic')) {
      headers.Authorization = `Basic ${Buffer.from(`${clientId}:${clientSecret}`).toString('base64')}`;
    } else if (methods.includes('client_secret_post')) body.set('client_secret', clientSecret);
    else throw new Error('OIDC provider does not advertise a supported client-secret authentication method.');
  }
  const token = await fetchJson(document.token_endpoint, {
    method: 'POST',
    headers,
    body: body.toString()
  });
  if (!token.id_token) throw new Error('OIDC provider did not return an ID token.');
  return verifyIdToken(token.id_token, { issuer, clientId, nonce: stored.nonce, discoveryDocument: document });
}

module.exports = { normalizeIssuer, validateEndpoint, discovery, beginAuthorization, completeAuthorization, verifyIdToken, verifyWithJwk, hashState };
