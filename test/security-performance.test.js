const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { spawnSync } = require('node:child_process');

const { root, source: read } = require('./source-tree');
const temporaryData = fs.mkdtempSync(path.join(os.tmpdir(), 'sham-security-performance-'));
process.env.SHAM_DATA_PATH = temporaryData;
process.env.SHAM_JWT_SECRET = 'security-performance-test-secret-at-least-32-characters';
test.after(() => fs.rmSync(temporaryData, { recursive: true, force: true }));

test('TOTP implements the RFC 4226 reference vector', () => {
  const { hotp } = require('../src/mfa');
  assert.equal(hotp('GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ', 0), '755224');
  assert.equal(hotp('GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ', 1), '287082');
});

test('secret encryption authenticates data and keeps generated key material private', () => {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), 'sham-secret-test-'));
  const script = `
    const fs = require('node:fs');
    const store = require(${JSON.stringify(path.join(root, 'src', 'secret-store.js'))});
    const encrypted = store.encrypt('super-secret');
    if (store.decrypt(encrypted) !== 'super-secret') process.exit(2);
    const tampered = encrypted.slice(0, -1) + (encrypted.endsWith('A') ? 'B' : 'A');
    let rejected = false;
    try { store.decrypt(tampered); } catch { rejected = true; }
    if (!rejected) process.exit(3);
    const mode = fs.statSync(store.KEYRING_PATH).mode & 0o777;
    if (process.platform !== 'win32' && mode !== 0o600) process.exit(4);
  `;
  const result = spawnSync(process.execPath, ['-e', script], {
    cwd: root,
    env: { ...process.env, SHAM_DATA_PATH: directory, SHAM_JWT_SECRET: 'x'.repeat(48) },
    encoding: 'utf8'
  });
  fs.rmSync(directory, { recursive: true, force: true });
  assert.equal(result.status, 0, result.stderr || result.stdout);
});

test('JSON plugins only infer data permissions when they declare data actions', () => {
  const { validateManifest } = require('../src/plugin-manager');
  const visual = validateManifest({ id: 'visual-only', name: 'Visual only', type: 'json', ui: { pages: [] } });
  assert.equal(visual.permissions.includes('data:read'), false);
  const reader = validateManifest({ id: 'reader-plugin', name: 'Reader', type: 'json', queries: { total: { sql: 'SELECT COUNT(*) AS total FROM site_stats', mode: 'get' } } });
  assert.equal(reader.permissions.includes('data:read'), true);
});

test('plugin runtime permissions are enforced in both in-process and worker APIs', () => {
  const manager = read('src/plugin-manager.js');
  const worker = read('src/plugin-sandbox-worker.js');
  assert.match(manager, /runtime:\s*\{[\s\S]*requirePermission\('runtime:read'\)[\s\S]*requirePermission\('runtime:manage'\)/);
  assert.match(worker, /runtime:\s*\{[\s\S]*rpc\('runtime\.list'\)[\s\S]*rpc\('runtime\.restart'/);
  assert.match(manager, /workerRuntimeFailed[\s\S]*UPDATE plugins SET enabled = 0/);
  assert.match(manager, /PLUGIN_MAX_PENDING_ACTIONS/);
});

test('public health output is minimal and authenticated telemetry remains separate', () => {
  const server = read('src/server.js');
  const start = server.indexOf("app.get('/api/health'");
  const end = server.indexOf("app.get('/api/bootstrap'", start);
  const route = server.slice(start, end);
  assert.match(route, /res\.json\(\{ ok: true \}\)/);
  assert.doesNotMatch(route, /uptimeSeconds|process\.uptime/);
  assert.doesNotMatch(route, /performanceMonitor|runningSites|edgeProxy/);
  assert.match(server, /app\.get\('\/api\/performance', requireAuth/);
});

test('passkey deletion uses step-up password confirmation and bounded challenges', () => {
  const server = read('src/server.js');
  assert.match(server, /DELETE FROM webauthn_challenges WHERE user_id = \? AND purpose = \?/);
  const start = server.indexOf("app.delete('/api/security/passkeys/:id'");
  const end = server.indexOf("app.use(['/api/sites/:id'", start);
  const route = server.slice(start, end);
  assert.match(route, /await verifyPassword/);
  assert.match(route, /req\.body\.password/);
  const app = read('public/app.js');
  assert.match(app, /Delete this passkey[\s\S]*inputType: 'password'/);
});

test('Certbot coordinates with the shared port-80 edge proxy without hiding partial success', () => {
  const server = read('src/server.js');
  const issueStart = server.indexOf("app.post('/api/admin/sites/:id/certificate'");
  const renewStart = server.indexOf("app.post('/api/admin/certificates/renew'", issueStart);
  const usersStart = server.indexOf("app.get('/api/admin/users'", renewStart);
  const issue = server.slice(issueStart, renewStart);
  const renew = server.slice(renewStart, usersStart);
  for (const route of [issue, renew]) {
    assert.match(route, /edgeProxy\.pauseHttp\(\)/);
    assert.match(route, /edgeProxy\.resumeHttp\(\)/);
  }
  assert.match(issue, /certificate was installed, but the shared HTTPS proxy could not reload/i);
  assert.match(renew, /Certificates were renewed, but the shared HTTPS proxy could not reload/i);
});

test('performance monitoring includes bounded queues, per-site throughput, latency, and anomaly alerts', () => {
  const monitor = read('src/performance-monitor.js');
  assert.match(monitor, /uploadQueueStats/);
  assert.match(monitor, /requestsPerSecond/);
  assert.match(monitor, /bytesPerSecond/);
  assert.match(monitor, /averageResponseMs/);
  assert.match(monitor, /traffic-spike/);
  assert.match(monitor, /site-error-rate/);
  assert.match(monitor, /previousSiteCounters/);
  const html = read('public/index.html');
  const app = read('public/app.js');
  assert.match(html, /id="perf-traffic"/);
  assert.match(html, /Traffic spike multiplier/);
  assert.match(app, /site\.traffic\?\.requestsPerSecond/);
});

test('compression negotiation honors q=0 and security presets avoid broad HSTS by default', () => {
  const manager = read('src/site-manager.js');
  assert.match(manager, /brotli > 0 && brotli >= gzip/);
  assert.match(manager, /if \(gzip > 0\)/);
  assert.match(manager, /preset === 'strict' \? 'max-age=31536000; includeSubDomains' : 'max-age=31536000'/);
});

test('snapshot cleanup warnings propagate to the dashboard instead of turning success into failure', () => {
  const snapshots = read('src/snapshot-manager.js');
  const server = read('src/server.js');
  const app = read('public/app.js');
  assert.match(snapshots, /Snapshot restored, but the previous project backup could not be removed/);
  assert.match(server, /warning: restoreResult\?\.warning \|\| null/);
  assert.match(app, /Snapshot restored\. \$\{result\.warning\}/);
});

test('all security, service, worker, and browser code is included in the recursive syntax check', () => {
  const pkg = JSON.parse(read('package.json'));
  assert.match(pkg.scripts.check, /scripts\/check-syntax\.js/);
  const checker = read('scripts/check-syntax.js');
  assert.match(checker, /const roots = \[path\.join\(root, 'src'\), path\.join\(root, 'public'\), path\.join\(root, 'runtime-agent'\)\]/);
  assert.match(checker, /if \(entry\.isDirectory\(\)\) collect\(absolute\)/);
});
