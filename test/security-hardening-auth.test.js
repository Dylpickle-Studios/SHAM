'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const net = require('node:net');
const { spawn } = require('node:child_process');
const { once } = require('node:events');

// Point the in-process modules at a throwaway data directory before anything
// under src/ is loaded, so no instance secrets or databases land in the repo.
const UNIT_DATA = fs.mkdtempSync(path.join(os.tmpdir(), 'sham-auth-unit-'));
process.env.SHAM_DATA_PATH = UNIT_DATA;
process.env.SHAM_JWT_SECRET = 'unit-test-secret-at-least-thirty-two-characters-long';
delete process.env.SHAM_SETUP_TOKEN;

const ROOT = path.resolve(__dirname, '..');
const { source: read } = require('./source-tree');
const security = require('../src/security');
const mfa = require('../src/mfa');
const { db } = require('../src/db');

test.after(() => {
  try { db.close(); } catch { /* already closed */ }
  fs.rmSync(UNIT_DATA, { recursive: true, force: true });
});

test('rate-limit buckets group IPv6 clients by /64 and IPv4-mapped clients by address', () => {
  const key = security.rateLimitKey;
  assert.equal(key('203.0.113.9'), '203.0.113.9');
  assert.equal(key('::ffff:203.0.113.9'), '203.0.113.9');
  assert.equal(key('2001:db8:1:2:aaaa:bbbb:cccc:dddd'), key('2001:db8:1:2::1'));
  assert.equal(key('2001:0DB8:0001:0002::1%eth0'), '2001:db8:1:2::/64');
  assert.notEqual(key('2001:db8:1:2::1'), key('2001:db8:1:3::1'));
  assert.equal(key(''), 'unknown');
});

test('API token scopes are bound to exact routes and fail closed', () => {
  const scope = (method, routePath, baseUrl = '') => security.requiredApiScope({ method, baseUrl, path: routePath });
  assert.equal(scope('GET', '/api/sites'), 'read');
  for (const route of ['/api/admin/logs/export', '/api/admin/audit/export', '/api/admin/audit', '/api/runtime-events', '/api/runtime-logs', '/api/runtime-logs/search', '/api/sites/4/deployments/9/logs']) {
    assert.equal(scope('GET', route), 'logs:read', route);
  }
  assert.equal(scope('GET', '/API/Admin/Logs/Export/'), 'logs:read');
  assert.equal(scope('GET', '/api/sites/4/files/content'), '*');
  assert.equal(scope('HEAD', '/api/sites/4/files/content'), '*');
  assert.equal(scope('GET', '/files/content', '/api/sites/4'), '*', 'app.use() mounts must see the full path');
  assert.equal(scope('GET', '/api/sites/4/config/export'), '*');
  assert.equal(scope('GET', '/api/plugins/demo/actions/start'), '*');
  assert.equal(scope('POST', '/api/plugins/demo/actions/restart'), '*');
  assert.equal(scope('POST', '/api/admin/sites/4/cloudflare-tunnel/restart'), '*');
  assert.equal(scope('POST', '/api/admin/pangolin-tunnel/restart'), '*');
  assert.equal(scope('POST', '/api/sites/4/start'), 'sites:control');
  assert.equal(scope('POST', '/api/sites/4/restart/'), 'sites:control');
  assert.equal(scope('POST', '/start', '/api/sites/4'), 'sites:control');
  assert.equal(scope('POST', '/api/sites/4/deploy/git'), 'deploy');
  assert.equal(scope('POST', '/api/sites/4/releases/7/rollback'), 'deploy');
  assert.equal(scope('POST', '/api/sites/4/npm-install'), '*');
  assert.equal(scope('PUT', '/api/sites/4/files/content'), '*');
});

test('per-account failure limiter locks one normalized account name from one source without touching others', () => {
  const limiter = security.createFailureLimiter({ windowMs: 60_000, max: 3, accountMax: 6 });
  const now = Date.now();
  const attacker = '198.51.100.7';
  for (let index = 0; index < 3; index += 1) {
    assert.equal(limiter.retryAfter('Alice', attacker, now), 0);
    limiter.fail(index % 2 ? ' ALICE ' : 'alice', attacker, now);
  }
  assert.ok(limiter.retryAfter('alice', attacker, now) > 0);
  assert.equal(limiter.retryAfter('alice', '203.0.113.9', now), 0, 'a stranger cannot lock the owner out from elsewhere');
  assert.equal(limiter.retryAfter('bob', attacker, now), 0);
  assert.ok(limiter.retryAfter('alice', '2001:db8:1:2::99', now) === 0);
  limiter.fail('alice', '2001:db8:1:2::1', now); limiter.fail('alice', '2001:db8:1:2:ffff::2', now); limiter.fail('alice', '2001:db8:1:2::3', now);
  assert.ok(limiter.retryAfter('alice', '2001:db8:1:2::4', now) > 0, 'one IPv6 /64 is one source');
  assert.ok(limiter.retryAfter('alice', '192.0.2.1', now) > 0, 'distributed failures still reach the account-wide ceiling');
  assert.equal(limiter.retryAfter('alice', attacker, now + 61_000), 0, 'the window expires');
  limiter.fail('carol', attacker, now); limiter.fail('carol', attacker, now); limiter.fail('carol', attacker, now);
  limiter.reset('Carol', attacker);
  assert.equal(limiter.retryAfter('carol', attacker, now), 0);
});

test('MFA tokens carry a jti, burn after five failures and are single-use', () => {
  const user = db.prepare("INSERT INTO users (username, password_hash, password_salt, role) VALUES ('mfa-unit', 'x', 'y', 'admin') RETURNING *").get();
  const token = security.issueMfaToken(user);
  const session = security.readMfaToken(token);
  assert.equal(session.user.id, user.id);
  assert.match(session.jti, /^[0-9a-f-]{36}$/);
  for (let index = 0; index < 4; index += 1) security.recordMfaFailure(session.jti);
  assert.ok(security.readMfaToken(token), 'four failures leave the token usable');
  security.recordMfaFailure(session.jti);
  assert.equal(security.readMfaToken(token), null);

  const second = security.issueMfaToken(user);
  const { jti } = security.readMfaToken(second);
  security.consumeMfaToken(jti);
  assert.equal(security.verifyMfaToken(second), null);

  const jwt = require('jsonwebtoken');
  const legacy = jwt.sign({ sub: String(user.id), purpose: 'mfa' }, process.env.SHAM_JWT_SECRET, { algorithm: 'HS256', expiresIn: 300, issuer: 'sham', audience: 'sham-mfa' });
  assert.equal(security.readMfaToken(legacy), null, 'tokens without a tracked jti are rejected');
});

test('TOTP reports the matched step and rejects replays at or before the last accepted step', () => {
  const secret = mfa.base32Encode(Buffer.alloc(20, 3));
  const now = Date.now();
  const step = Math.floor(now / 30_000);
  assert.equal(mfa.matchTotpStep(secret, mfa.totp(secret, now), { timestamp: now }), step);
  assert.equal(mfa.matchTotpStep(secret, mfa.totp(secret, now), { timestamp: now, afterStep: step }), null);
  assert.equal(mfa.verifyTotp(secret, mfa.totp(secret, now), { timestamp: now }), true);

  const user = db.prepare("INSERT INTO users (username, password_hash, password_salt, role) VALUES ('totp-unit', 'x', 'y', 'admin') RETURNING *").get();
  mfa.enableTotp(db, user.id, secret, [], 0);
  const enrolled = db.prepare('SELECT * FROM users WHERE id = ?').get(user.id);
  const code = mfa.totp(secret, now);
  assert.equal(mfa.consumeTotp(db, enrolled, code, { timestamp: now }), true);
  assert.equal(db.prepare('SELECT totp_last_step FROM users WHERE id = ?').get(user.id).totp_last_step, step);
  assert.equal(mfa.consumeTotp(db, enrolled, code, { timestamp: now }), false, 'the same code cannot be replayed');
  assert.equal(mfa.consumeTotp(db, enrolled, mfa.totp(secret, now - 30_000), { timestamp: now }), false, 'older steps are rejected');
  assert.equal(mfa.consumeTotp(db, enrolled, mfa.totp(secret, now + 30_000), { timestamp: now }), true, 'a later step is still accepted');
});

test('setup token is stored 0600, compared in constant time and removed after use', () => {
  const logs = [];
  const token = security.ensureSetupToken((line) => logs.push(line));
  const file = path.join(UNIT_DATA, '.setup-token');
  assert.equal(fs.statSync(file).mode & 0o777, 0o600);
  assert.equal(fs.readFileSync(file, 'utf8').trim(), token);
  assert.match(logs.join('\n'), new RegExp(`setup token: ${token}`));
  assert.equal(security.ensureSetupToken(() => {}), token, 'restarts reuse the stored token');
  assert.equal(security.verifySetupToken(token), true);
  assert.equal(security.verifySetupToken(`${token}x`), false);
  assert.equal(security.verifySetupToken(''), false);
  security.clearSetupToken();
  assert.equal(fs.existsSync(file), false);
  assert.equal(security.verifySetupToken(token), false);

  process.env.SHAM_SETUP_TOKEN = 'operator-chosen-setup-token';
  try {
    const quiet = [];
    assert.equal(security.ensureSetupToken((line) => quiet.push(line)), 'operator-chosen-setup-token');
    assert.doesNotMatch(quiet.join('\n'), /operator-chosen-setup-token/, 'an operator-supplied token is not echoed');
  } finally {
    delete process.env.SHAM_SETUP_TOKEN;
    security.clearSetupToken();
  }
});

test('site routes gate every code-execution path behind one helper', () => {
  const sites = read('src/routes/sites.js');
  assert.match(sites, /const CODE_RUNTIMES = new Set\(\['node', 'process', 'container', 'compose'\]\)/);
  assert.match(sites, /assertMayConfigureExecution\(req, config\);/);
  assert.match(sites, /assertMayConfigureExecution\(req, config, site\);/);
  for (const route of ["'/api/sites/:id/npm-install'", "'/api/sites/:id/content'", "'/api/sites/:id/files/content', requireAuth, async", "'/api/sites/:id/files/upload'", "app.delete('/api/sites/:id/files'", "'/api/sites/:id/snapshots/:snapshotId/restore'"]) {
    const start = sites.indexOf(route);
    assert.ok(start > 0, route);
    assert.match(sites.slice(start, start + 600), /denyUnlessMayChangeCode\(req, res, site\)/, route);
  }
  const db = read('src/db.js');
  assert.match(db, /ensureColumn\('users', 'totp_last_step', 'INTEGER NOT NULL DEFAULT 0'\)/);
  const operations = read('src/routes/operations.js');
  const update = operations.slice(operations.indexOf("app.post('/api/admin/update'"), operations.indexOf("app.delete('/api/admin/update'"));
  assert.match(update, /stepUpLimiter, multipart/);
  assert.match(update, /verifyPassword\(/);
  const ui = read('public/js/operations.js');
  assert.match(ui.slice(ui.indexOf("$('#update-form')")), /requestAction\(\{ title: 'Stage SHAM update\?'[\s\S]*formData\.append\('password', password\)/);
});

async function freePort() {
  const server = net.createServer();
  await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve));
  const { port } = server.address();
  await new Promise((resolve) => server.close(resolve));
  return port;
}

test('running server enforces setup token, MFA limits, account lockout, scopes, roles and update step-up', { timeout: 60_000 }, async (t) => {
  const dataDir = fs.mkdtempSync(path.join(os.tmpdir(), 'sham-auth-server-'));
  const port = await freePort();
  const base = `http://127.0.0.1:${port}`;
  const child = spawn(process.execPath, ['src/server.js'], {
    cwd: ROOT,
    env: {
      ...process.env,
      NODE_ENV: 'test', SHAM_TEST_MODE: '1', SHAM_DATA_PATH: dataDir,
      SHAM_HOST: '127.0.0.1', SHAM_PORT: String(port), SHAM_EDGE_HOST: '127.0.0.1',
      SHAM_EDGE_HTTP_PORT: String(await freePort()), SHAM_EDGE_HTTPS_PORT: '0',
      SHAM_JWT_SECRET: 'server-test-secret-at-least-thirty-two-characters', SHAM_PUBLIC_ORIGIN: base, SHAM_SETUP_TOKEN: ''
    },
    stdio: ['ignore', 'pipe', 'pipe']
  });
  let output = '';
  child.stdout.on('data', (chunk) => { output += chunk; });
  child.stderr.on('data', (chunk) => { output += chunk; });
  t.after(async () => {
    if (child.exitCode === null) { child.kill('SIGTERM'); await Promise.race([once(child, 'exit'), new Promise((resolve) => setTimeout(resolve, 8000))]); }
    if (child.exitCode === null) child.kill('SIGKILL');
    fs.rmSync(dataDir, { recursive: true, force: true });
  });
  for (let attempt = 0; ; attempt += 1) {
    try { if ((await fetch(`${base}/api/health`)).ok) break; } catch { /* starting */ }
    if (attempt > 150) throw new Error(`SHAM did not start.\n${output}`);
    await new Promise((resolve) => setTimeout(resolve, 100));
  }

  const call = async (endpoint, { method = 'GET', body, cookie = '', bearer = '' } = {}) => {
    const headers = {};
    if (body !== undefined && !(body instanceof FormData)) headers['content-type'] = 'application/json';
    if (cookie) headers.cookie = cookie;
    if (bearer) headers.authorization = `Bearer ${bearer}`;
    const response = await fetch(`${base}${endpoint}`, { method, headers, body: body === undefined || body instanceof FormData ? body : JSON.stringify(body) });
    const text = await response.text();
    let data;
    try { data = text ? JSON.parse(text) : null; } catch { data = text; }
    return { status: response.status, data, cookie: response.headers.get('set-cookie')?.split(';', 1)[0] || '' };
  };
  const password = 'server-test-password-123';

  // First-run registration.
  const tokenFile = path.join(dataDir, '.setup-token');
  assert.equal(fs.statSync(tokenFile).mode & 0o777, 0o600);
  const setupToken = fs.readFileSync(tokenFile, 'utf8').trim();
  assert.match(output, new RegExp(`setup token: ${setupToken}`));
  assert.equal((await call('/api/bootstrap')).data.setupTokenRequired, true);
  assert.equal((await call('/api/auth/register', { method: 'POST', body: { username: 'owner', password } })).status, 401);
  assert.equal((await call('/api/auth/register', { method: 'POST', body: { username: 'owner', password, setupToken: 'wrong-token-value-123' } })).status, 401);
  const registered = await call('/api/auth/register', { method: 'POST', body: { username: 'owner', password, setupToken } });
  assert.equal(registered.status, 201);
  assert.equal(fs.existsSync(tokenFile), false);
  const admin = registered.cookie;

  // TOTP enrolment seeds replay protection; MFA tokens burn after five failures.
  const setup = await call('/api/security/totp/setup', { method: 'POST', cookie: admin, body: { password } });
  const enrolCode = mfa.totp(setup.data.secret);
  assert.equal((await call('/api/security/totp/enable', { method: 'POST', cookie: admin, body: { setupId: setup.data.setupId, code: enrolCode } })).status, 200);
  const first = await call('/api/auth/login', { method: 'POST', body: { username: 'owner', password } });
  assert.equal(first.data.mfaRequired, true);
  assert.equal((await call('/api/auth/login/totp', { method: 'POST', body: { mfaToken: first.data.mfaToken, code: enrolCode } })).status, 401, 'enrolment code cannot be replayed');
  for (let index = 0; index < 4; index += 1) {
    const wrong = await call('/api/auth/login/totp', { method: 'POST', body: { mfaToken: first.data.mfaToken, code: '000000' } });
    assert.equal(wrong.data.error, 'The verification code is not valid.');
  }
  const freshCode = mfa.totp(setup.data.secret, Date.now() + 30_000);
  const burned = await call('/api/auth/login/totp', { method: 'POST', body: { mfaToken: first.data.mfaToken, code: freshCode } });
  assert.equal(burned.status, 401);
  assert.match(burned.data.error, /expired/);
  const second = await call('/api/auth/login', { method: 'POST', body: { username: 'owner', password } });
  const verified = await call('/api/auth/login/totp', { method: 'POST', body: { mfaToken: second.data.mfaToken, code: freshCode } });
  assert.equal(verified.status, 200);
  const reused = await call('/api/auth/login/totp', { method: 'POST', body: { mfaToken: second.data.mfaToken, code: freshCode } });
  assert.match(reused.data.error, /expired/, 'MFA tokens are single-use');

  // Per-account lockout applies to unknown names too, independent of the password.
  for (let index = 0; index < 10; index += 1) assert.equal((await call('/api/auth/login', { method: 'POST', body: { username: 'ghost-user', password: 'not-the-password' } })).status, 401);
  const locked = await call('/api/auth/login', { method: 'POST', body: { username: 'GHOST-USER', password: 'not-the-password' } });
  assert.equal(locked.status, 429);

  // Narrow API token scopes cannot reach exports, file contents or plugin actions.
  const created = await call('/api/security/api-tokens', { method: 'POST', cookie: verified.cookie, body: { password, name: 'reader', scopes: ['read', 'sites:control'] } });
  assert.equal(created.status, 201);
  const reader = created.data.token;
  assert.equal((await call('/api/sites', { bearer: reader })).status, 200);
  for (const endpoint of ['/api/admin/logs/export', '/api/v1/admin/audit/export', '/api/runtime-events', '/api/sites/1/files/content?path=.env', '/api/v1/sites/1/files/content?path=.env']) {
    assert.equal((await call(endpoint, { bearer: reader })).status, 403, endpoint);
  }
  assert.equal((await call('/api/plugins/demo/actions/restart', { method: 'POST', bearer: reader, body: {} })).status, 403);

  // A non-admin cannot choose code that SHAM executes.
  assert.equal((await call('/api/admin/users', { method: 'POST', cookie: verified.cookie, body: { username: 'member', password, role: 'user' } })).status, 201);
  const member = (await call('/api/auth/login', { method: 'POST', body: { username: 'member', password } })).cookie;
  const processSite = await call('/api/sites', { method: 'POST', cookie: member, body: { name: 'shell', runtimeType: 'process', runtimePreset: 'custom', startCommand: 'id > /tmp/pwned', port: String(await freePort()) } });
  assert.equal(processSite.status, 403);
  assert.match(processSite.data.error, /administrator/);
  const staticWithCommand = await call('/api/sites', { method: 'POST', cookie: member, body: { name: 'cmd', runtimeType: 'static', healthCheckType: 'command', healthCheckCommand: 'id', port: String(await freePort()) } });
  assert.equal(staticWithCommand.status, 403);
  const proxy = await call('/api/sites', { method: 'POST', cookie: member, body: { name: 'proxied', runtimeType: 'proxy', proxyTarget: 'http://127.0.0.1:9/', manifestEnabled: true, port: String(await freePort()) } });
  assert.equal(proxy.status, 201, JSON.stringify(proxy.data));
  assert.equal(proxy.data.site.manifest_enabled, false, 'non-admin sites never honour sham.yaml');
  const siteId = proxy.data.site.id;
  const toProcess = await call(`/api/sites/${siteId}`, { method: 'PUT', cookie: member, body: { ...proxy.data.site, runtimeType: 'process', runtimePreset: 'node' } });
  assert.equal(toProcess.status, 403);
  assert.notEqual((await call(`/api/sites/${siteId}/files/content`, { method: 'PUT', cookie: member, body: { path: 'notes.txt', content: 'hello' } })).status, 403);
  const processForm = new FormData();
  for (const [key, value] of Object.entries({ name: 'admin-process', runtimeType: 'process', runtimePreset: 'custom', startCommand: 'sleep 60', port: String(await freePort()) })) processForm.append(key, value);
  processForm.append('relativePaths', JSON.stringify(['server.js']));
  processForm.append('files', new Blob([Buffer.from('console.log(1)\n')]), 'server.js');
  const adminProcess = await call('/api/sites', { method: 'POST', cookie: verified.cookie, body: processForm });
  assert.equal(adminProcess.status, 201, JSON.stringify(adminProcess.data));
  const adminSiteId = adminProcess.data.site.id;
  assert.equal((await call(`/api/sites/${adminSiteId}/files/content`, { method: 'PUT', cookie: member, body: { path: 'server.js', content: 'evil' } })).status, 403);
  assert.equal((await call(`/api/sites/${adminSiteId}/npm-install`, { method: 'POST', cookie: member, body: {} })).status, 403);
  assert.equal((await call(`/api/sites/${adminSiteId}`, { method: 'PUT', cookie: member, body: { ...adminProcess.data.site, name: 'renamed' } })).status, 403);

  // Staging an update needs a fresh password confirmation.
  const form = new FormData();
  form.append('archive', new Blob([Buffer.from('not a zip')]), 'update.zip');
  const unconfirmed = await call('/api/admin/update', { method: 'POST', cookie: verified.cookie, body: form });
  assert.equal(unconfirmed.status, 401);
  assert.match(unconfirmed.data.error, /Password confirmation failed/);
});
