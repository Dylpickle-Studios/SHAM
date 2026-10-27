'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const http = require('node:http');
const crypto = require('node:crypto');
const { spawnSync } = require('node:child_process');
const tar = require('tar');
const AdmZip = require('adm-zip');
const Database = require('better-sqlite3');

const temporary = fs.mkdtempSync(path.join(os.tmpdir(), 'sham-hardening-'));
const data = path.join(temporary, 'data');
process.env.SHAM_DATA_PATH = data;
process.env.SHAM_JWT_SECRET = 'hardening-test-secret-at-least-thirty-two-characters';
delete process.env.SHAM_MASTER_KEY;

const root = path.resolve(__dirname, '..');
const { db, setSetting } = require('../src/db');
const { DATA_DIR, BACKUPS_DIR, PLUGINS_DIR, SITES_DIR, TMP_ROOT_DIR } = require('../src/config');
const secretStore = require('../src/secret-store');
const { findUnarchivableEntries, stageBackupRestore, applyPendingRestore } = require('../src/backup-restore');
const { ConfigurationOperations } = require('../src/operations/configuration');
const { UpdateManager, compareVersions, UPDATE_TRUSTED_KEYS_SETTING } = require('../src/update-manager');
const { PluginManager, PluginSqlPolicy, validateManifest, pluginTablePrefix } = require('../src/plugin-manager');
const { canonical } = require('../src/plugin-signing');
const { DependencyScanner } = require('../src/dependency-scanner');

test.after(() => fs.rmSync(temporary, { recursive: true, force: true }));

const read = (name) => fs.readFileSync(path.join(root, name), 'utf8');
const quietLogger = { log() {}, error() {} };

async function archiveMembers(file) {
  const names = [];
  await tar.t({ file, onReadEntry: (entry) => names.push(entry.path.replace(/^\.\//, '').replace(/\/$/, '')) });
  return new Set(names);
}

// ---------------------------------------------------------------------------
// Backups
// ---------------------------------------------------------------------------

function plantHostileLinks() {
  const site = path.join(DATA_DIR, 'site-data', 'demo');
  fs.mkdirSync(path.join(site, 'deep'), { recursive: true });
  fs.writeFileSync(path.join(site, 'ok.txt'), 'kept');
  fs.symlinkSync('ok.txt', path.join(site, 'safe'));
  fs.symlinkSync('../..', path.join(site, 'deep', 'up'));
  fs.symlinkSync('/etc/passwd', path.join(site, 'x'));
  fs.symlinkSync('/etc/passwd', path.join(site, 'wild*card'));
  fs.symlinkSync('/etc/passwd', path.join(site, 'new\nline'));
  // Lexically inside the tree, but resolving through deep/up walks out of it.
  fs.symlinkSync('deep/up/../../..', path.join(site, 'chain'));
  const release = path.join(DATA_DIR, 'releases', '1', 'r1');
  fs.mkdirSync(release, { recursive: true });
  fs.symlinkSync('../../../../..', path.join(release, 'escape'));
}

test('backup preflight finds exactly the links the archive validator would reject', async () => {
  plantHostileLinks();
  const skipped = new Set(await findUnarchivableEntries(DATA_DIR));
  for (const name of ['./site-data/demo/x', './site-data/demo/wild*card', './site-data/demo/new\nline', './site-data/demo/chain', './releases/1/r1/escape']) {
    assert.ok(skipped.has(name), `${JSON.stringify(name)} should be skipped`);
  }
  for (const name of ['./site-data/demo/ok.txt', './site-data/demo/safe', './site-data/demo/deep/up']) assert.ok(!skipped.has(name), `${name} should be archived`);
});

test('backups skip hostile links, exclude key material and app-runtime, and still verify strictly', async () => {
  secretStore.encrypt('ensure-keyring');
  fs.writeFileSync(path.join(DATA_DIR, '.jwt-secret'), 'j'.repeat(64), { mode: 0o600 });
  fs.writeFileSync(path.join(DATA_DIR, '.setup-token'), 'setup-token', { mode: 0o600 });
  fs.writeFileSync(path.join(DATA_DIR, 'app-runtime', 'active.json'), '{"current":true}');
  assert.ok(fs.existsSync(secretStore.KEYRING_PATH));
  const logs = [];
  const operations = new ConfigurationOperations({ db, manager: { log: (_site, level, message) => logs.push({ level, message }) }, snapshotManager: null });
  const backup = await operations.createBackup({ provider: 'local', skipRetention: true });
  assert.equal(backup.verified, true);
  const members = await archiveMembers(path.join(BACKUPS_DIR, backup.filename));
  for (const name of ['sham.db', 'site-data/demo/ok.txt', 'site-data/demo/safe', 'site-data/demo/deep/up']) assert.ok(members.has(name), `${name} missing`);
  for (const name of ['site-data/demo/x', 'site-data/demo/wild*card', 'site-data/demo/new\nline', 'site-data/demo/chain', 'releases/1/r1/escape',
    '.master-keyring.json', '.jwt-secret', '.setup-token', 'app-runtime', 'app-runtime/active.json']) {
    assert.ok(!members.has(name), `${JSON.stringify(name)} must not be archived`);
  }
  assert.ok(![...members].some((name) => name.startsWith('app-runtime') || name.startsWith('.master-keyring')));
  const warning = logs.find((entry) => entry.level === 'warning' && /Backup skipped 5 unsafe/.test(entry.message));
  assert.ok(warning, JSON.stringify(logs));
  assert.match(warning.message, /site-data\/demo\/x/);
});

test('recovery keyring export returns the active and retired keys', () => {
  const exported = secretStore.exportRecoveryKeyring();
  const onDisk = JSON.parse(fs.readFileSync(secretStore.KEYRING_PATH, 'utf8'));
  assert.equal(exported.external, false);
  assert.equal(exported.keyring.active, onDisk.active);
  assert.deepEqual(exported.keyring.previous, onDisk.previous);
  const admin = read('src/routes/admin.js');
  const route = admin.slice(admin.indexOf("'/api/admin/security/recovery-key'"), admin.indexOf("const updateTrustedKeys"));
  assert.match(route, /requireAdmin, stepUpLimiter/);
  assert.match(route, /req\.authType !== 'session'/);
  assert.match(route, /verifyPassword/);
  assert.match(route, /Cache-Control', 'no-store'/);
  assert.match(route, /recordAudit/);
});

// ---------------------------------------------------------------------------
// Updates
// ---------------------------------------------------------------------------

test('update versions use semantic-version precedence', () => {
  const ordered = ['1.0.0-alpha', '1.0.0-alpha.1', '1.0.0-alpha.beta', '1.0.0-beta', '1.0.0-beta.2', '1.0.0-beta.11', '1.0.0-rc.1', '1.0.0', '1.4.0', '1.10.0', '2.0.0'];
  for (let index = 1; index < ordered.length; index += 1) {
    assert.equal(compareVersions(ordered[index - 1], ordered[index]), -1, `${ordered[index - 1]} < ${ordered[index]}`);
    assert.equal(compareVersions(ordered[index], ordered[index - 1]), 1);
  }
  assert.equal(compareVersions('1.0.0+build.1', '1.0.0+build.2'), 0);
  assert.throws(() => compareVersions('1.0', '1.0.0'), /semantic/);
});

function walk(directory, current = directory, files = []) {
  for (const entry of fs.readdirSync(current, { withFileTypes: true }).sort((a, b) => a.name.localeCompare(b.name))) {
    const absolute = path.join(current, entry.name);
    if (entry.isDirectory()) walk(directory, absolute, files);
    else files.push(path.relative(directory, absolute).replaceAll('\\', '/'));
  }
  return files;
}

function buildUpdate(version, signingKey = null, keyId = 'release') {
  const current = JSON.parse(read('package.json'));
  const source = fs.mkdtempSync(path.join(temporary, 'update-src-'));
  const manifest = { name: 'simple-hosting-and-more', version, dependencies: current.dependencies, optionalDependencies: current.optionalDependencies };
  fs.mkdirSync(path.join(source, 'src'));
  fs.writeFileSync(path.join(source, 'package.json'), JSON.stringify(manifest));
  fs.writeFileSync(path.join(source, 'src', 'server.js'), 'module.exports = {};\n');
  fs.writeFileSync(path.join(source, 'src', 'bootstrap.js'), '\n');
  if (signingKey) {
    const hash = crypto.createHash('sha256');
    hash.update('SHAM-UPDATE-SIGNATURE-V1\0');
    hash.update(canonical({ name: manifest.name, version, dependencies: manifest.dependencies || {}, optionalDependencies: manifest.optionalDependencies || {} }));
    for (const relative of walk(source)) {
      hash.update('\0'); hash.update(relative); hash.update('\0');
      hash.update(crypto.createHash('sha256').update(fs.readFileSync(path.join(source, relative))).digest());
    }
    const value = crypto.sign(null, hash.digest(), signingKey).toString('base64url');
    fs.writeFileSync(path.join(source, 'sham-update.json'), JSON.stringify({ format: 'sham-update-signature-v1', algorithm: 'ed25519', version, keyId, value }));
  }
  const zip = new AdmZip();
  zip.addLocalFolder(source);
  const archive = path.join(temporary, `update-${crypto.randomUUID()}.zip`);
  zip.writeZip(archive);
  return archive;
}

test('core updates use their own trust store and reject downgrades without acknowledgement', async () => {
  const { privateKey, publicKey } = crypto.generateKeyPairSync('ed25519');
  const pem = publicKey.export({ type: 'spki', format: 'pem' });
  const manager = new UpdateManager({ db });
  const current = JSON.parse(read('package.json')).version;
  try {
    // A key trusted only for plugins proves nothing about a SHAM release.
    setSetting('plugin_trusted_keys_json', JSON.stringify([{ id: 'release', name: 'Release', publicKey: pem }]));
    setSetting(UPDATE_TRUSTED_KEYS_SETTING, '[]');
    await assert.rejects(() => manager.stage(buildUpdate('99.0.0', privateKey)), /not a trusted update key/);
    const acknowledged = await manager.stage(buildUpdate('99.0.0', privateKey), 'u.zip', { allowUnsigned: true });
    assert.equal(acknowledged.signature.status, 'untrusted');
    assert.match(db.prepare('SELECT detail FROM update_history ORDER BY id DESC LIMIT 1').get().detail, /not a trusted update key/);
    await manager.cancel();

    setSetting('plugin_trusted_keys_json', '[]');
    setSetting(UPDATE_TRUSTED_KEYS_SETTING, JSON.stringify([{ id: 'release', name: 'Release', publicKey: pem }]));
    const verified = await manager.stage(buildUpdate('99.0.0', privateKey));
    assert.equal(verified.signature.status, 'verified');
    await manager.cancel();

    for (const version of [current, `${current}-rc.1`, '0.9.0']) {
      await assert.rejects(() => manager.stage(buildUpdate(version, privateKey)), /not newer than the running version/, version);
    }
    const downgrade = await manager.stage(buildUpdate('0.9.0', privateKey), 'old.zip', { allowDowngrade: true });
    assert.equal(downgrade.downgrade, true);
    assert.match(db.prepare('SELECT detail FROM update_history ORDER BY id DESC LIMIT 1').get().detail, /Downgrade from .* explicitly acknowledged/);
    await manager.cancel();
    await assert.rejects(() => manager.stage(buildUpdate('99.0.0')), /unsigned/);
  } finally {
    await manager.cancel().catch(() => {});
    await manager.shutdown();
    setSetting('plugin_trusted_keys_json', '[]');
  }
  const admin = read('src/routes/admin.js');
  assert.match(admin, /app\.get\('\/api\/admin\/update-trusted-keys', requireAuth, requireAdmin/);
  assert.match(admin, /app\.post\('\/api\/admin\/update-trusted-keys', requireAuth, requireAdmin/);
  assert.match(admin, /app\.delete\('\/api\/admin\/update-trusted-keys\/:id', requireAuth, requireAdmin/);
  assert.doesNotMatch(read('src/update-manager.js'), /plugin_trusted_keys_json/);
});

// ---------------------------------------------------------------------------
// Plugin SQL policy
// ---------------------------------------------------------------------------

function registerPlugin(manifest, directory) {
  const normalized = validateManifest(manifest);
  const directoryName = `plugin-${normalized.id}-${crypto.randomUUID()}`;
  const target = path.join(PLUGINS_DIR, directoryName);
  if (directory) fs.cpSync(directory, target, { recursive: true });
  else fs.mkdirSync(target, { recursive: true });
  db.prepare(`INSERT INTO plugins (id, name, version, type, directory_name, manifest_json, permissions_json, signature_status, isolation, enabled)
    VALUES (?, ?, ?, ?, ?, ?, ?, 'unsigned', ?, 1)`).run(normalized.id, normalized.name, normalized.version, normalized.type, directoryName, JSON.stringify(normalized), JSON.stringify(normalized.permissions), normalized.isolation);
  return target;
}

test('plugin SQL policy is derived from the tables SQLite actually opens', () => {
  registerPlugin({ id: 'policy-demo', name: 'Policy demo', type: 'json' });
  registerPlugin({ id: 'policy-demo-extra', name: 'Policy demo extra', type: 'json' });
  const policy = new PluginSqlPolicy(db);
  const allow = (sql, write = false, params = []) => { const statement = policy.prepare('policy-demo', sql, params, { write }); return statement.reader ? statement.all(...params) : statement.run(...params); };
  const deny = (sql, pattern, write = true, params = []) => assert.throws(() => policy.prepare('policy-demo', sql, params, { write }), pattern, sql);
  assert.equal(pluginTablePrefix('policy-demo'), 'plugin_policy_demo_');

  allow('SELECT COUNT(*) AS count FROM sites');
  allow('SELECT id, name, runtime_type, port, enabled FROM sites WHERE slug = ? ORDER BY name', false, ['x']);
  allow('SELECT site_id, total_requests FROM site_stats');
  allow('CREATE TABLE plugin_policy_demo_notes (id INTEGER PRIMARY KEY AUTOINCREMENT, site_id INTEGER, body TEXT)', true);
  allow('CREATE INDEX plugin_policy_demo_notes_site ON plugin_policy_demo_notes(site_id)', true);
  allow('INSERT INTO plugin_policy_demo_notes (site_id, body) VALUES (?, ?)', true, [1, 'hello']);
  assert.deepEqual(allow('SELECT body FROM plugin_policy_demo_notes'), [{ body: 'hello' }]);
  allow('CREATE TABLE plugin_policy_demo_copy AS SELECT id, name FROM sites', true);
  allow('ALTER TABLE plugin_policy_demo_copy ADD COLUMN note TEXT', true);
  allow('ALTER TABLE plugin_policy_demo_copy RENAME TO plugin_policy_demo_copy2', true);
  allow('DROP TABLE plugin_policy_demo_copy2', true);

  for (const table of ['users', 'settings', 'api_tokens', 'passkeys', 'oidc_states', 'webauthn_challenges', 'revoked_sessions', 'alert_destinations', 'site_env', 'site_cloudflare_tunnels', 'plugin_settings', 'audit_logs', 'database_profiles', 'plugins']) {
    deny(`SELECT * FROM ${table}`, new RegExp(`may not read ${table}`), false);
    deny(`SELECT 1 FROM sites WHERE EXISTS (SELECT 1 FROM ${table})`, new RegExp(`may not read ${table}`), false);
  }
  deny('SELECT * FROM sites', /may not read sites\./, false);
  deny('SELECT git_url FROM sites', /sites\.git_url/, false);
  deny('SELECT id FROM sites WHERE build_command LIKE ?', /sites\.build_command/, false, ['%']);
  deny('WITH secrets AS (SELECT password_hash FROM users) SELECT * FROM secrets', /may not read users/, false);
  deny('SELECT * FROM "users"', /may not read users/, false);
  deny("SELECT * FROM 'settings'", /may not read settings/, false);
  deny('INSERT INTO plugin_policy_demo_notes (body) SELECT value FROM settings', /may not read settings/);
  deny('CREATE TABLE plugin_policy_demo_leak AS SELECT * FROM users', /may not read users/);
  deny('UPDATE sites SET name = ?', /may not modify sites/, true, ['x']);
  deny('DELETE FROM site_stats', /may not modify site_stats/);
  deny('INSERT INTO plugin_policy_demo_notes (body) VALUES (?)', /requires the data:write permission/, false, ['x']);
  deny('CREATE TABLE notes (a)', /plugin_policy_demo_ prefix/);
  deny('CREATE TABLE plugin_policy_demo_extra_steal (a)', /plugin_policy_demo_ prefix/);
  deny('CREATE INDEX plugin_policy_demo_idx ON sites(name)', /prefix/);
  deny('ALTER TABLE plugin_policy_demo_notes RENAME TO users_copy', /prefix/);
  deny('DROP TABLE sites', /prefix/);
  deny('CREATE TEMP TABLE plugin_policy_demo_t (a)', /temporary/);
  deny('CREATE TABLE temp.plugin_policy_demo_t (a)', /main SHAM database/);
  deny('CREATE TEMP TRIGGER plugin_policy_demo_trg AFTER INSERT ON sites BEGIN SELECT 1; END', /temporary/);
  deny('CREATE TRIGGER plugin_policy_demo_trg AFTER INSERT ON plugin_policy_demo_notes BEGIN DELETE FROM users; END', /triggers, views/);
  deny('CREATE VIEW plugin_policy_demo_v AS SELECT * FROM users', /triggers, views/);
  deny('CREATE VIRTUAL TABLE plugin_policy_demo_f USING fts5(body)', /triggers, views/);
  for (const sql of ['PRAGMA table_info(users)', 'ATTACH DATABASE ? AS other', 'DETACH other', 'VACUUM', 'BEGIN', 'SAVEPOINT x', 'ANALYZE', 'REINDEX']) deny(sql, /may not run/);
  deny('SELECT * FROM sqlite_master', /internal tables/, false);
  deny('SELECT * FROM temp.sqlite_schema', /internal tables/, false);
  deny('UPDATE sqlite_sequence SET seq = 0', /internal tables/);
  deny('SELECT * FROM pragma_table_info(?)', /pragma/, false, ['users']);
  deny('SELECT * FROM dbstat', /virtual tables/, false);
  deny('SELECT value FROM json_each(?)', /virtual tables/, false, ['[1]']);
  deny('SELECT load_extension(?)', /load_extension/, false, ['x']);
  deny('SELECT 1; DELETE FROM users', /more than one statement/, true);
});

test('declarative plugins are checked against the SQL policy at install and load time', async () => {
  const manager = new PluginManager(db, quietLogger);
  const staging = fs.mkdtempSync(path.join(temporary, 'declarative-'));
  fs.writeFileSync(path.join(staging, 'plugin.json'), JSON.stringify({ id: 'leaky-json', name: 'Leaky', type: 'json', queries: { tokens: { mode: 'all', sql: 'SELECT token_hash FROM api_tokens' } } }));
  assert.throws(() => manager.validatePreparedPlugin(staging), /tokens.*may not read api_tokens/);
  fs.writeFileSync(path.join(staging, 'plugin.json'), JSON.stringify({ id: 'policy_demo', name: 'Clash', type: 'json' }));
  assert.throws(() => manager.validatePreparedPlugin(staging), /share database table names with installed plugin “policy-demo”/);

  registerPlugin({ id: 'legacy-leak', name: 'Legacy leak', type: 'json', queries: { tokens: { mode: 'all', sql: 'SELECT name, scopes_json FROM api_tokens' } } });
  manager.loadEnabled();
  assert.equal(db.prepare('SELECT enabled FROM plugins WHERE id = ?').get('legacy-leak').enabled, 0);

  const example = JSON.parse(read('examples/plugins/json-welcome/plugin.json'));
  registerPlugin(example);
  manager.load(example.id);
  assert.deepEqual(await manager.handleApi(example.id, 'siteCount', { body: {}, query: {}, user: { role: 'user' }, method: 'GET' }), { count: 0 });
  await manager.shutdown();
});

// ---------------------------------------------------------------------------
// Worker plugin sandbox
// ---------------------------------------------------------------------------

const ESCAPE_PROBE = String.raw`
const findings = [];
const NativeFunction = Function;
function inspect(label, value) {
  if (value === null || (typeof value !== 'object' && typeof value !== 'function')) return;
  let constructor;
  try { constructor = value.constructor; } catch { return; }
  if (constructor === undefined) return;
  let outer;
  try { outer = constructor.constructor; } catch { findings.push(label + ': constructor access threw'); return; }
  if (outer !== NativeFunction) findings.push(label + ': reaches a foreign Function constructor');
  try {
    const escaped = outer('return typeof process === "undefined" ? null : process')();
    if (escaped) findings.push(label + ': escaped to process');
  } catch { /* code generation is disabled inside the sandbox */ }
}
function inspectTree(label, value, depth = 0) {
  inspect(label, value);
  if (depth > 2 || value === null || (typeof value !== 'object' && typeof value !== 'function')) return;
  for (const key of Reflect.ownKeys(value)) {
    let child;
    try { child = value[key]; } catch { continue; }
    inspectTree(label + '.' + String(key), child, depth + 1);
  }
}
inspectTree('module', module);
inspectTree('exports', exports);
inspectTree('require', require);
inspect('this', this);
for (const key of Reflect.ownKeys(globalThis)) { try { inspectTree('global.' + String(key), globalThis[key], 1); } catch {} }
exports.activate = function (context) {
  inspectTree('context', context);
  inspect('activate this', this);
  return { api: {
    async probe(request) {
      inspectTree('request', request);
      const pending = context.data.all('SELECT id, name FROM sites');
      inspect('rpc promise', pending);
      inspectTree('rpc result', await pending);
      try { await context.data.all('SELECT * FROM users'); findings.push('policy allowed users'); } catch (error) { inspectTree('rpc error', error); }
      try { await context.data.run('DELETE FROM sites'); findings.push('data:run allowed'); } catch (error) { inspectTree('permission error', error); }
      try { require('fs'); findings.push('require fs allowed'); } catch (error) { inspectTree('require error', error); }
      try { await fetch('http://127.0.0.1:9/'); findings.push('fetch allowed'); } catch (error) { inspectTree('fetch error', error); }
      inspectTree('crypto', require('crypto'));
      inspectTree('hash', require('crypto').createHash('sha256').update('abc'));
      if (require('crypto').createHash('sha256').update('abc').digest('hex') !== 'ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad') findings.push('hash mismatch');
      await new Promise((resolve) => setTimeout(function (...args) { inspect('timer this', this); inspectTree('timer args', args); resolve(); }, 1, { a: 1 }));
      await new Promise((resolve) => { const id = setInterval(function () { inspect('interval this', this); clearInterval(id); resolve(); }, 1); });
      await new Promise((resolve) => queueMicrotask(resolve));
      const previous = Error.prepareStackTrace;
      Error.prepareStackTrace = (_error, frames) => frames;
      const frames = new Error('probe').stack;
      Error.prepareStackTrace = previous;
      if (Array.isArray(frames)) for (const frame of frames) {
        try { inspect('frame this', frame.getThis()); inspect('frame function', frame.getFunction()); } catch {}
      }
      try { context.settings.get('x'); findings.push('settings:read allowed'); } catch (error) { inspectTree('settings error', error); }
      return findings;
    },
    async boom() { throw new TypeError('plugin failure'); }
  } };
};
`;

test('worker plugins cannot reach host-realm objects through any exposed value', async () => {
  const directory = fs.mkdtempSync(path.join(temporary, 'probe-plugin-'));
  fs.writeFileSync(path.join(directory, 'index.js'), ESCAPE_PROBE);
  registerPlugin({ id: 'escape-probe', name: 'Escape probe', type: 'js', main: 'index.js', isolation: 'worker', permissions: ['data:read'] }, directory);
  const manager = new PluginManager(db, quietLogger);
  try {
    manager.load('escape-probe');
    const findings = await manager.handleApi('escape-probe', 'probe', { body: { nested: { value: 1 } }, query: { q: '1' }, user: { id: 1, role: 'user' }, method: 'GET' });
    assert.deepEqual(findings, []);
    await assert.rejects(() => manager.handleApi('escape-probe', 'boom', { body: {}, query: {}, user: null, method: 'GET' }), /plugin failure/);
  } finally { await manager.shutdown(); }
  assert.doesNotMatch(read('src/plugin-sandbox-worker.js'), /require:\s*sandboxRequire|Buffer, URL, URLSearchParams/);
});

test('an unhandled guest rejection is reported without host formatting of the guest value', async () => {
  const directory = fs.mkdtempSync(path.join(temporary, 'fault-plugin-'));
  // A custom inspector on the rejected value would run if the worker let Node format it.
  fs.writeFileSync(path.join(directory, 'index.js'), `module.exports = { activate(api) {
  const value = { stack: 'guest fault' };
  value[Symbol.for('nodejs.util.inspect.custom')] = () => { api.log('custom inspector ran'); return 'inspected'; };
  setTimeout(() => { Promise.reject(value); }, 5);
  return { api: { ping() { return 'pong'; } } };
} };
`);
  registerPlugin({ id: 'guest-fault', name: 'Guest fault', type: 'js', main: 'index.js', isolation: 'worker', permissions: [] }, directory);
  const lines = [];
  const manager = new PluginManager(db, { log: (line) => lines.push(String(line)), error: (line) => lines.push(String(line)) });
  try {
    manager.load('guest-fault');
    await assert.rejects(async () => {
      for (let attempt = 0; attempt < 50; attempt += 1) {
        await manager.handleApi('guest-fault', 'ping', { body: {}, query: {}, user: null, method: 'GET' });
        await new Promise((resolve) => setTimeout(resolve, 20));
      }
    }, /uncaught exception or unhandled promise rejection|not (?:loaded|enabled|running)|failed/i);
    assert.ok(!lines.some((line) => line.includes('custom inspector ran')), lines.join('\n'));
  } finally { await manager.shutdown(); }
});

test('the example worker plugin still works under the sandbox and SQL policy', async () => {
  const example = JSON.parse(read('examples/plugins/js-site-notes/plugin.json'));
  registerPlugin(example, path.join(root, 'examples/plugins/js-site-notes'));
  db.prepare("INSERT INTO plugin_settings (plugin_id, key, value) VALUES (?, 'heading', ?)").run(example.id, JSON.stringify('Inventory'));
  const manager = new PluginManager(db, quietLogger);
  try {
    manager.load(example.id);
    const summary = await manager.handleApi(example.id, 'summary', { body: {}, query: {}, user: null, method: 'GET' });
    assert.equal(summary.heading, 'Inventory');
    assert.equal(summary.showPorts, true);
    assert.ok(Array.isArray(summary.sites));
  } finally { await manager.shutdown(); }
});

// ---------------------------------------------------------------------------
// Dependency scanner
// ---------------------------------------------------------------------------

test('dependency audits ignore the site .npmrc and use the operator registry or npm config', { skip: spawnSync('npm', ['--version']).status !== 0 && 'npm is not installed' }, async () => {
  const hits = { operator: [], site: [] };
  const server = (name) => http.createServer((request, response) => {
    hits[name].push(`${request.method} ${request.url}`);
    request.resume();
    request.on('end', () => { response.setHeader('content-type', 'application/json'); response.end('{}'); });
  });
  const operator = server('operator');
  const site = server('site');
  await Promise.all([new Promise((resolve) => operator.listen(0, '127.0.0.1', resolve)), new Promise((resolve) => site.listen(0, '127.0.0.1', resolve))]);
  const previous = process.env.NPM_CONFIG_REGISTRY;
  const previousHome = process.env.HOME;
  process.env.NPM_CONFIG_REGISTRY = `http://127.0.0.1:${operator.address().port}/`;
  try {
    const siteRoot = path.join(SITES_DIR, 'npmrc-site');
    fs.mkdirSync(siteRoot, { recursive: true });
    const dependency = { version: '1.3.0', resolved: 'https://registry.npmjs.org/left-pad/-/left-pad-1.3.0.tgz', integrity: 'sha512-XI5MPzVNApjAyhQzphX8BkmKsKUxD4LdyK24iZeQ9X6R0qlZlrAgXHN/CoEHyzT13nyTRKa+ixPAddnqaaHN6Q==' };
    fs.writeFileSync(path.join(siteRoot, 'package.json'), JSON.stringify({ name: 'scan', version: '1.0.0', dependencies: { 'left-pad': '1.3.0' } }));
    fs.writeFileSync(path.join(siteRoot, 'package-lock.json'), JSON.stringify({ name: 'scan', version: '1.0.0', lockfileVersion: 3, requires: true, packages: { '': { name: 'scan', version: '1.0.0', dependencies: { 'left-pad': '1.3.0' } }, 'node_modules/left-pad': dependency } }));
    fs.writeFileSync(path.join(siteRoot, '.npmrc'), `registry=http://127.0.0.1:${site.address().port}/\n//127.0.0.1:${site.address().port}/:_authToken=stolen\n`);
    const scanner = new DependencyScanner({ prepare: () => ({ run() {} }) }, quietLogger);
    const result = await scanner.scan({ id: 1, directory_name: 'npmrc-site', active_release_directory: '' });
    assert.equal(result.registryError, null);
    assert.equal(result.registryAvailable, true);
    assert.ok(hits.operator.some((hit) => hit.startsWith('POST /-/npm/v1/security/')), JSON.stringify(hits));
    assert.deepEqual(hits.site, []);
    assert.deepEqual(fs.readdirSync(TMP_ROOT_DIR).filter((name) => name.startsWith('dependency-audit-')), []);
    // Without an override the operator's own npm config (e.g. a corporate mirror) applies.
    delete process.env.NPM_CONFIG_REGISTRY;
    const operatorHome = fs.mkdtempSync(path.join(temporary, 'operator-home-'));
    fs.writeFileSync(path.join(operatorHome, '.npmrc'), `registry=http://127.0.0.1:${operator.address().port}/\n`);
    process.env.HOME = operatorHome;
    hits.operator.length = 0;
    const mirrored = await scanner.scan({ id: 1, directory_name: 'npmrc-site', active_release_directory: '' });
    assert.equal(mirrored.registryError, null);
    assert.ok(hits.operator.some((hit) => hit.startsWith('POST /-/npm/v1/security/')), JSON.stringify(hits));
    assert.deepEqual(hits.site, []);
  } finally {
    process.env.HOME = previousHome;
    if (previous === undefined) delete process.env.NPM_CONFIG_REGISTRY; else process.env.NPM_CONFIG_REGISTRY = previous;
    operator.close();
    site.close();
  }
});

// ---------------------------------------------------------------------------
// Restore (runs last: it replaces sham.db underneath the open handle)
// ---------------------------------------------------------------------------

test('restore keeps host key material and app-runtime, and merges an older archive keyring', async () => {
  const currentRing = JSON.parse(fs.readFileSync(secretStore.KEYRING_PATH, 'utf8'));
  const currentJwt = fs.readFileSync(path.join(DATA_DIR, '.jwt-secret'), 'utf8');
  const currentActive = fs.readFileSync(path.join(DATA_DIR, 'app-runtime', 'active.json'), 'utf8');
  const oldKey = crypto.randomBytes(32);
  const source = fs.mkdtempSync(path.join(temporary, 'old-archive-'));
  const database = new Database(path.join(source, 'sham.db'));
  database.exec('CREATE TABLE users(id INTEGER); CREATE TABLE settings(key TEXT, value TEXT); CREATE TABLE sites(id INTEGER);');
  database.prepare('INSERT INTO settings VALUES (?, ?)').run('cloudflare_api_token', secretStore.encrypt('token-from-old-host', oldKey));
  database.close();
  fs.writeFileSync(path.join(source, '.master-keyring.json'), JSON.stringify({ active: oldKey.toString('base64url'), previous: [] }));
  fs.writeFileSync(path.join(source, '.jwt-secret'), 'o'.repeat(64));
  fs.mkdirSync(path.join(source, 'app-runtime'));
  fs.writeFileSync(path.join(source, 'app-runtime', 'active.json'), '{"old":true}');
  fs.mkdirSync(path.join(source, 'site-data'));
  fs.writeFileSync(path.join(source, 'site-data', 'restored.txt'), 'restored');
  const archive = path.join(BACKUPS_DIR, `sham-backup-old-${crypto.randomUUID()}.tar.gz`);
  await tar.c({ file: archive, gzip: true, cwd: source }, ['.']);

  await stageBackupRestore(archive);
  const restored = await applyPendingRestore();
  assert.ok(restored);
  assert.equal(fs.readFileSync(path.join(DATA_DIR, 'site-data', 'restored.txt'), 'utf8'), 'restored');
  assert.equal(fs.readFileSync(path.join(DATA_DIR, '.jwt-secret'), 'utf8'), currentJwt);
  assert.equal(fs.readFileSync(path.join(DATA_DIR, 'app-runtime', 'active.json'), 'utf8'), currentActive);
  const ring = JSON.parse(fs.readFileSync(secretStore.KEYRING_PATH, 'utf8'));
  assert.equal(ring.active, currentRing.active);
  assert.ok(ring.previous.includes(oldKey.toString('base64url')));
  const reopened = new Database(path.join(DATA_DIR, 'sham.db'), { readonly: true });
  try {
    const value = reopened.prepare("SELECT value FROM settings WHERE key = 'cloudflare_api_token'").get().value;
    assert.equal(secretStore.decrypt(value), 'token-from-old-host');
  } finally { reopened.close(); }
  assert.equal(secretStore.decrypt(secretStore.encrypt('new')), 'new');
  assert.equal(fs.existsSync(path.join(DATA_DIR, '.restore-work', 'stage', '.master-keyring.json')), false);
});
