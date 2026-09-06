'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const os = require('node:os');
const crypto = require('node:crypto');
const tar = require('tar');
const Database = require('better-sqlite3');

const temporary = fs.mkdtempSync(path.join(os.tmpdir(), 'sham-remediation-'));
const data = path.join(temporary, 'data');
process.env.SHAM_DATA_PATH = data;
process.env.SHAM_JWT_SECRET = 'remediation-only-secret-at-least-thirty-two-characters';
const { verifyBackupArchive, stageBackupRestore, applyPendingRestore, recoverInterruptedRestore } = require('../src/backup-restore');
const { validateComposeProjectPaths, composeRuntimePolicy } = require('../src/sites/runtime');
const { DeliverySiteManager } = require('../src/sites/delivery');
const { OperationsManager } = require('../src/operations/observability');
const { beginAuthorization, completeAuthorization } = require('../src/oidc');
test.after(() => fs.rmSync(temporary, { recursive: true, force: true }));

function databaseAt(filename) {
  const db = new Database(filename);
  db.exec("CREATE TABLE users(id INTEGER); CREATE TABLE settings(key TEXT, value TEXT); CREATE TABLE sites(id INTEGER); INSERT INTO settings VALUES ('marker','backed-up');");
  db.close();
}
async function archiveFrom(build) {
  const source = fs.mkdtempSync(path.join(temporary, 'source-'));
  databaseAt(path.join(source, 'sham.db'));
  await build(source);
  const archive = path.join(data, 'backups', `sham-backup-${crypto.randomUUID()}.tar.gz`);
  await tar.c({ file: archive, gzip: true, cwd: source }, ['.']);
  return archive;
}

test('Compose rejects driver-backed host mounts and unmanaged resource names', () => {
  const config = { name: 'sham-1-test', services: { web: { image: 'node:22', volumes: [{ type: 'volume', source: 'content', target: '/data' }] } }, volumes: { content: {} } };
  validateComposeProjectPaths(config, temporary);
  composeRuntimePolicy(config, 'web');
  for (const definition of [
    { driver: 'local', driver_opts: { type: 'none', o: 'bind', device: '/' } },
    { driver: 'unapproved-plugin' }, { name: 'unmanaged-existing-volume' }, { external: true }
  ]) {
    config.volumes.content = definition;
    assert.throws(() => validateComposeProjectPaths(config, temporary), /driver|project-scoped|external/);
  }
  config.volumes.content = { name: 'sham-1-test_content', driver: 'local' };
  validateComposeProjectPaths(config, temporary);
});

test('hidden assets are denied before every optimization and fallback path', async () => {
  const root = path.join(data, 'sites', 'static-audit');
  fs.mkdirSync(path.join(root, '.private'), { recursive: true });
  fs.writeFileSync(path.join(root, '.private', 'credentials.json'), '{"secret":"dummy"}');
  fs.writeFileSync(path.join(root, '.private', 'app.js'), 'const privateValue = 1;');
  fs.writeFileSync(path.join(root, 'index.html'), '<h1>public</h1>');
  for (const options of [{ compression: false }, { compression: true }, { minify: true }, { obfuscate: true }]) {
    const manager = Object.create(DeliverySiteManager.prototype);
    Object.assign(manager, { minifyCache: new Map(), minifyCacheBytes: 0, log: () => {} });
    const site = { id: 1, directory_name: 'static-audit', entry_file: 'index.html', headers: {}, cache_seconds: 0, spa_fallback: true, ...options };
    const app = manager.createStaticApp(site, root, path.join(root, 'index.html'));
    const server = await new Promise((resolve) => { const value = app.listen(0, '127.0.0.1', () => resolve(value)); });
    try {
      for (const name of ['/.private/credentials.json', '/%2eprivate/app.js', '/.missing.txt']) {
        for (const method of ['GET', 'HEAD']) {
          const response = await fetch(`http://127.0.0.1:${server.address().port}${name}`, { method });
          assert.equal(response.status, 404, `${method} ${name} ${JSON.stringify(options)}`);
          assert.doesNotMatch(await response.text(), /dummy|privateValue/);
        }
      }
    } finally { await new Promise((resolve) => server.close(resolve)); }
  }
});

test('OIDC cannot consume another browser transaction and consumes a valid transaction once', async () => {
  const db = new Database(':memory:');
  db.exec('CREATE TABLE oidc_states (state_hash TEXT PRIMARY KEY, nonce TEXT, verifier TEXT, redirect_uri TEXT, expires_at INTEGER)');
  const originalFetch = global.fetch;
  const issuer = 'https://remediation-idp.invalid';
  const redirectUri = 'https://remediation-app.invalid/api/auth/oidc/callback';
  const browserBinding = crypto.randomBytes(32).toString('base64url');
  const { publicKey, privateKey } = crypto.generateKeyPairSync('rsa', { modulusLength: 2048 });
  const jwk = { ...publicKey.export({ format: 'jwk' }), kid: 'remediation', alg: 'RS256', use: 'sig' };
  let nonce;
  let exchanges = 0;
  global.fetch = async (url) => {
    let payload;
    if (String(url).endsWith('openid-configuration')) payload = { issuer, authorization_endpoint: `${issuer}/authorize`, token_endpoint: `${issuer}/token`, jwks_uri: `${issuer}/jwks` };
    else if (String(url).endsWith('/jwks')) payload = { keys: [jwk] };
    else {
      exchanges += 1;
      const header = Buffer.from(JSON.stringify({ alg: 'RS256', kid: 'remediation' })).toString('base64url');
      const claims = Buffer.from(JSON.stringify({ iss: issuer, aud: 'client', sub: 'correct-account', nonce, exp: Math.floor(Date.now() / 1000) + 600 })).toString('base64url');
      const input = `${header}.${claims}`;
      payload = { id_token: `${input}.${crypto.sign('sha256', Buffer.from(input), privateKey).toString('base64url')}` };
    }
    return new Response(JSON.stringify(payload), { headers: { 'content-type': 'application/json' } });
  };
  try {
    const location = new URL(await beginAuthorization({ issuer, clientId: 'client', redirectUri, db, browserBinding }));
    nonce = location.searchParams.get('nonce');
    const args = { issuer, clientId: 'client', redirectUri, db, state: location.searchParams.get('state'), code: 'one-time-code' };
    await assert.rejects(() => completeAuthorization(args), /browser binding/);
    await assert.rejects(() => completeAuthorization({ ...args, browserBinding: crypto.randomBytes(32).toString('base64url') }), /state expired|did not match/);
    assert.equal(exchanges, 0);
    assert.equal(db.prepare('SELECT COUNT(*) AS n FROM oidc_states').get().n, 1);
    assert.equal((await completeAuthorization({ ...args, browserBinding })).sub, 'correct-account');
    await assert.rejects(() => completeAuthorization({ ...args, browserBinding }), /state expired|did not match/);
    assert.equal(exchanges, 1);
  } finally { global.fetch = originalFetch; db.close(); }
});

test('backup health reflects persisted statuses', async () => {
  for (const [status, expected] of [[null, 'warning'], ['running', 'warning'], ['success', 'healthy'], ['failed', 'error']]) {
    const health = await OperationsManager.prototype.systemHealth.call({
      db: { pragma: () => 'ok', prepare: () => ({ get: () => status ? { status, finishedAt: status === 'success' ? '2026-09-05 12:00:00' : null } : null }) },
      capabilities: () => ({ docker: true })
    });
    const backup = health.checks.find((item) => item.id === 'backup');
    assert.equal(backup.status, expected);
    assert.equal(backup.lastCompletedAt, status === 'success' ? '2026-09-05 12:00:00' : null);
  }
});

test('backup links are checked without following unsafe chains or archive ancestors', async () => {
  for (const [label, build] of [
    ['absolute', (root) => fs.symlinkSync('/etc/passwd', path.join(root, 'escape'))],
    ['relative', (root) => fs.symlinkSync('../escape', path.join(root, 'escape'))],
    ['cycle', (root) => { fs.symlinkSync('b', path.join(root, 'a')); fs.symlinkSync('a', path.join(root, 'b')); }],
    ['chain-parent', (root) => { fs.symlinkSync('.', path.join(root, 'a')); fs.symlinkSync('a/../escape', path.join(root, 'b')); }]
  ]) {
    const archive = await archiveFrom(build);
    await assert.rejects(() => verifyBackupArchive(archive), /unsafe|escapes|cyclic/, label);
  }
});

test('restore preserves the data mount and agent identity, and restores safe dependency links', async () => {
  const archive = await archiveFrom((root) => {
    fs.mkdirSync(path.join(root, 'sites', 'node', 'node_modules', '.bin'), { recursive: true });
    fs.mkdirSync(path.join(root, 'sites', 'node', 'node_modules', 'tool'), { recursive: true });
    fs.writeFileSync(path.join(root, 'sites', 'node', 'node_modules', 'tool', 'cli.js'), 'restored-cli', { mode: 0o755 });
    fs.symlinkSync('../tool/cli.js', path.join(root, 'sites', 'node', 'node_modules', '.bin', 'tool'));
  });
  fs.mkdirSync(path.join(data, 'runtime-agent'), { recursive: true });
  fs.writeFileSync(path.join(data, 'runtime-agent', 'agent.token'), 'keep-current-token');
  fs.writeFileSync(path.join(data, 'obsolete.txt'), 'remove-me');
  const inode = fs.statSync(data).ino;
  await stageBackupRestore(archive);
  await applyPendingRestore();
  assert.equal(fs.statSync(data).ino, inode, 'the mount root must not be renamed');
  assert.equal(fs.readFileSync(path.join(data, 'runtime-agent', 'agent.token'), 'utf8'), 'keep-current-token');
  assert.equal(fs.existsSync(path.join(data, 'obsolete.txt')), false);
  assert.equal(fs.readFileSync(path.join(data, 'sites', 'node', 'node_modules', '.bin', 'tool'), 'utf8'), 'restored-cli');
  assert.ok(fs.statSync(path.join(data, 'sites', 'node', 'node_modules', 'tool', 'cli.js')).mode & 0o100);
  const db = new Database(path.join(data, 'sham.db'), { readonly: true });
  assert.equal(db.prepare("SELECT value FROM settings WHERE key='marker'").get().value, 'backed-up');
  db.close();
  assert.ok(fs.existsSync(archive));
  assert.equal(fs.existsSync(path.join(data, '.restore-work', 'agent-paused')), false);
});

test('interrupted restore recovery restores originals and survives a repeated recovery', async () => {
  const work = path.join(data, '.restore-work');
  const rollback = path.join(work, 'rollback');
  fs.mkdirSync(rollback, { recursive: true });
  fs.writeFileSync(path.join(rollback, 'original.txt'), 'old');
  fs.writeFileSync(path.join(data, 'original.txt'), 'candidate');
  fs.writeFileSync(path.join(data, 'new-only.txt'), 'candidate');
  // Already recovered entries are persisted before their atomic rename.
  fs.writeFileSync(path.join(data, 'already-restored.txt'), 'keep-old');
  fs.writeFileSync(path.join(work, 'journal.json'), JSON.stringify({ phase: 'installing', incoming: ['original.txt', 'new-only.txt', 'already-restored.txt'], restored: ['already-restored.txt'] }));
  await recoverInterruptedRestore();
  await recoverInterruptedRestore();
  assert.equal(fs.readFileSync(path.join(data, 'original.txt'), 'utf8'), 'old');
  assert.equal(fs.readFileSync(path.join(data, 'already-restored.txt'), 'utf8'), 'keep-old');
  assert.equal(fs.existsSync(path.join(data, 'new-only.txt')), false);
});

test('invalid SQLite backup is rejected before live data is replaced', async () => {
  const archive = await archiveFrom((root) => fs.writeFileSync(path.join(root, 'sham.db'), 'not-a-database'.repeat(20)));
  const before = fs.readFileSync(path.join(data, 'sham.db'));
  await stageBackupRestore(archive);
  await assert.rejects(() => applyPendingRestore(), /not a valid SQLite/);
  assert.deepEqual(fs.readFileSync(path.join(data, 'sham.db')), before);
});

test('archive validation rejects duplicate paths, writes through links, and special entries', async () => {
  const { gzipSync } = require('node:zlib');
  for (const entries of [
    [{ path: 'same', type: 'File' }, { path: './same', type: 'File' }],
    [{ path: 'alias', type: 'SymbolicLink', linkpath: 'target' }, { path: 'alias/payload', type: 'File' }],
    [{ path: 'socket-replacement', type: 'FIFO' }],
    [{ path: '../outside', type: 'File' }]
  ]) {
    const blocks = [];
    for (const entry of [{ path: 'sham.db', type: 'File' }, ...entries]) {
      const header = new tar.Header({ ...entry, mode: 0o600, size: 0 });
      header.encode();
      blocks.push(header.block);
    }
    blocks.push(Buffer.alloc(1024));
    const archive = path.join(data, 'backups', `sham-backup-${crypto.randomUUID()}.tar.gz`);
    fs.writeFileSync(archive, gzipSync(Buffer.concat(blocks)));
    await assert.rejects(() => verifyBackupArchive(archive), /repeats|through a link|special|unsafe/);
  }
});

test('recovery of a partially moved tree preserves entries not yet moved', async () => {
  const work = path.join(data, '.restore-work');
  const rollback = path.join(work, 'rollback');
  fs.mkdirSync(rollback, { recursive: true });
  fs.writeFileSync(path.join(rollback, 'moved.txt'), 'original-moved');
  fs.writeFileSync(path.join(data, 'untouched.txt'), 'original-untouched');
  fs.writeFileSync(path.join(work, 'journal.json'), JSON.stringify({ phase: 'moving', incoming: ['moved.txt', 'untouched.txt'], restored: [] }));
  await recoverInterruptedRestore();
  assert.equal(fs.readFileSync(path.join(data, 'moved.txt'), 'utf8'), 'original-moved');
  assert.equal(fs.readFileSync(path.join(data, 'untouched.txt'), 'utf8'), 'original-untouched');
  // An interruption after journal cleanup must not leave the agent permanently paused.
  fs.writeFileSync(path.join(work, 'agent-paused'), 'restore');
  await applyPendingRestore();
  assert.equal(fs.existsSync(path.join(work, 'agent-paused')), false);
});
