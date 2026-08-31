process.env.SHAM_JWT_SECRET ||= 'runtime-platform-test-secret-at-least-32-characters';
const test = require('node:test');
const assert = require('node:assert/strict');
const crypto = require('node:crypto');
const fs = require('node:fs');
const path = require('node:path');
const { PassThrough } = require('node:stream');

const { parseSimpleYaml, resolveRuntimeSpec, executionPolicyHash } = require('../src/runtime-spec');
const { validateSiteInput } = require('../src/validation');
const { safeArchiveEntry } = require('../src/backup-restore');
const { lineLogger, shellCommand, waitForReadiness } = require('../src/runtime-engine');
const { CoreSiteManager } = require('../src/sites/core');
const { requestIdentity } = require('../src/sites/shared');
const { EdgeProxy } = require('../src/edge-proxy');
const { verifyWithJwk } = require('../src/oidc');
const { siteRoot, safeReleaseDirectory } = require('../src/site-paths');
const { RELEASES_DIR, SITES_DIR } = require('../src/config');

test('runtime manifest resolves a generic process and policy hash changes with execution policy', () => {
  const manifest = parseSimpleYaml(`
runtime:
  preset: custom
  driver: process
  command: "python app.py"
  portEnv: APP_PORT
readiness:
  type: http
  path: /ready
  statusMin: 200
  statusMax: 299
shutdown:
  graceSeconds: 12
  drainSeconds: 4
`);
  const site = {
    runtime_type: 'process', runtime_preset: 'custom', start_command: 'ignored', runtime_port_env: 'PORT',
    working_directory: '', container_image: 'node:22-alpine', container_mode: 'image', container_port: 3000,
    dockerfile_path: 'Dockerfile', compose_file: 'compose.yaml', compose_service: 'app', entry_file: 'index.html',
    manifest_enabled: true
  };
  const spec = resolveRuntimeSpec(site, '/tmp/example', { manifestRecord: { filename: 'sham.yaml', manifest, raw: '' } });
  assert.equal(spec.driver, 'process');
  assert.equal(spec.command, 'python app.py');
  assert.equal(spec.portEnv, 'APP_PORT');
  assert.equal(spec.readiness.path, '/ready');
  assert.equal(spec.shutdownGraceMs, 12_000);
  assert.equal(spec.drainMs, 4_000);
  const changed = { ...spec, command: 'python other.py' };
  assert.notEqual(executionPolicyHash(spec), executionPolicyHash(changed));
});

test('runtime manifest parser rejects duplicate execution keys', () => {
  assert.throws(() => parseSimpleYaml('runtime:\n  command: one\n  command: two\n'), /repeats key command/);
});

test('site validation supports new process/container/compose modes and fails closed for command probes', () => {
  const processSite = validateSiteInput({ name: 'Fast API', port: 4300, runtimeType: 'process', runtimePreset: 'fastapi', readinessType: 'http' });
  assert.equal(processSite.runtime_type, 'process');
  assert.equal(processSite.runtime_preset, 'fastapi');
  const container = validateSiteInput({ name: 'Image', port: 4301, runtimeType: 'container', runtimePreset: 'dockerfile', containerMode: 'dockerfile', containerPort: 8080 });
  assert.equal(container.container_mode, 'dockerfile');
  const compose = validateSiteInput({ name: 'Compose', port: 4302, runtimeType: 'compose', runtimePreset: 'compose', composeService: 'web', composeFile: 'compose.yaml' });
  assert.equal(compose.compose_service, 'web');
  assert.throws(() => validateSiteInput({ name: 'No command', port: 4303, runtimeType: 'process', runtimePreset: 'custom' }), /require a start command/);
  assert.throws(() => validateSiteInput({ name: 'No probe', port: 4304, runtimeType: 'process', runtimePreset: 'npm', readinessType: 'command' }), /requires a readiness command/);
  assert.throws(() => validateSiteInput({ name: 'No health command', port: 4305, healthCheckType: 'command' }), /require a health-check command/);
});

test('runtime line logger preserves lines split across stream chunks', async () => {
  const stream = new PassThrough();
  const lines = [];
  lineLogger(stream, (line) => lines.push(line));
  stream.write('first half');
  stream.write(' second\nnext');
  stream.end(' line\n');
  await new Promise((resolve) => stream.once('end', resolve));
  assert.deepEqual(lines, ['first half second', 'next line']);
});

test('runtime output is grouped into bounded workspace log events without mixing sources', () => {
  const manager = Object.create(CoreSiteManager.prototype);
  manager.outputLogBatches = new Map();
  manager.activeDeploymentIds = new Map([[7, 31]]);
  const recorded = [];
  manager.log = (...entry) => recorded.push(entry);

  manager.logOutput(7, 'info', 'node: first output line');
  manager.logOutput(7, 'info', 'node: second output line');
  manager.logOutput(7, 'error', 'node: an error line');
  manager.flushOutputLogs(7);

  assert.equal(recorded.length, 2);
  assert.deepEqual(recorded[0], [7, 'info', 'node: first output line\nnode: second output line', null]);
  assert.deepEqual(recorded[1], [7, 'error', 'node: an error line', null]);
});

test('an enabled local Cloudflare Tunnel preserves visitor identity without trusting remote spoofed headers', () => {
  const localTunnelRequest = {
    headers: { 'cf-connecting-ip': '203.0.113.21', 'cf-ipcountry': 'NL', 'user-agent': 'Mozilla/5.0' },
    socket: { remoteAddress: '127.0.0.1' }
  };
  const localIdentity = requestIdentity({ cloudflare_enabled: false }, localTunnelRequest, { trustLocalCloudflareTunnel: true });
  assert.equal(localIdentity.ip, '203.0.113.21');
  assert.equal(localIdentity.country, 'NL');

  const remoteRequest = {
    headers: { 'cf-connecting-ip': '203.0.113.21', 'cf-ipcountry': 'NL', 'user-agent': 'Mozilla/5.0' },
    socket: { remoteAddress: '198.51.100.9' }
  };
  const remoteIdentity = requestIdentity({ cloudflare_enabled: false }, remoteRequest, { trustLocalCloudflareTunnel: true });
  assert.equal(remoteIdentity.ip, '198.51.100.9');
  assert.equal(remoteIdentity.country, 'ZZ');
});

test('shared-edge identity forwarding is enabled only for configured SHAM tunnel connectors', () => {
  const db = { prepare: () => ({ all: () => [], get: () => null }) };
  const edge = new EdgeProxy({ db, manager: {} });
  edge.setCloudflareTunnels(
    { status: () => ({ enabled: false, tokenConfigured: false }) },
    { status: () => ({ enabled: true, tokenConfigured: true }) }
  );
  assert.equal(edge.acceptsLocalTunnelIdentity({ id: 12 }), true);
  edge.setCloudflareTunnels({ status: () => ({ enabled: false, tokenConfigured: false }) });
  assert.equal(edge.acceptsLocalTunnelIdentity({ id: 12 }), false);
});

test('structured runtime argv preserves argument boundaries and startup spawn errors fail fast', async () => {
  const child = shellCommand([process.execPath, '-e', 'process.stdout.write(process.argv[1])', 'space preserved'], { stdio: ['ignore', 'pipe', 'pipe'] });
  let output = '';
  child.stdout.on('data', (chunk) => { output += chunk.toString(); });
  await new Promise((resolve, reject) => { child.once('error', reject); child.once('exit', (code) => code === 0 ? resolve() : reject(new Error(`exit ${code}`))); });
  assert.equal(output, 'space preserved');
  const missing = shellCommand(['sham-command-that-does-not-exist-xyz'], { stdio: 'ignore' });
  await assert.rejects(() => waitForReadiness({ readiness: { type: 'tcp', timeoutMs: 2000 }, host: '127.0.0.1', internalPort: 9 }, { child: missing, host: '127.0.0.1', port: 9 }), /could not start/);
});

test('backup restore entry validation rejects traversal and absolute paths', () => {
  assert.equal(safeArchiveEntry('./sites/example/index.html'), true);
  assert.equal(safeArchiveEntry('../etc/passwd'), false);
  assert.equal(safeArchiveEntry('/etc/passwd'), false);
  assert.equal(safeArchiveEntry('sites/../../etc/passwd'), false);
});

test('OIDC ES256 verification accepts JOSE/P1363 signatures', () => {
  const { privateKey, publicKey } = crypto.generateKeyPairSync('ec', { namedCurve: 'P-256' });
  const header = Buffer.from(JSON.stringify({ alg: 'ES256', kid: 'test' })).toString('base64url');
  const payload = Buffer.from(JSON.stringify({ sub: '123' })).toString('base64url');
  const signingInput = Buffer.from(`${header}.${payload}`);
  const signature = crypto.sign('sha256', signingInput, { key: privateKey, dsaEncoding: 'ieee-p1363' });
  assert.equal(verifyWithJwk({ header: { alg: 'ES256' }, signingInput, signature }, publicKey.export({ format: 'jwk' })), true);
});


test('active releases resolve through stable retained release paths', () => {
  const legacy = siteRoot({ id: 41, directory_name: 'demo', active_release_directory: '' });
  assert.equal(legacy, path.join(SITES_DIR, 'demo'));
  const active = siteRoot({ id: 41, directory_name: 'demo', active_release_directory: 'release-1234-abcd' });
  assert.equal(active, path.join(RELEASES_DIR, '41', 'release-1234-abcd'));
  assert.equal(safeReleaseDirectory('release-1234-abcd'), 'release-1234-abcd');
  assert.throws(() => safeReleaseDirectory('../release-1234'), /invalid/);
});

test('release activation starts candidates only after placing them at their stable release path', () => {
  const source = fs.readFileSync(path.join(__dirname, '..', 'src', 'operations', 'deployments.js'), 'utf8');
  const section = source.slice(source.indexOf('async activateRelease('), source.indexOf('beginDeployment(', source.indexOf('async activateRelease(')));
  assert.match(section, /await fs\.promises\.rename\(stage, releaseRoot\);/);
  assert.match(section, /prepareCandidate\(site, releaseRoot/);
  assert.doesNotMatch(section, /rename\(stage, root\)/);
  assert.match(section, /active_release_directory = \?/);
});

test('runtime manifest parser preserves quoted hashes while stripping real comments', () => {
  const parsed = parseSimpleYaml('runtime:\n  command: "node app.js #production" # deployment comment\n');
  assert.equal(parsed.runtime.command, 'node app.js #production');
});

test('runtime resolution fails closed for unknown presets and invalid buildpack builders', () => {
  assert.throws(() => resolveRuntimeSpec({ runtime_type: 'process', runtime_preset: 'not-a-runtime', start_command: 'echo nope' }, process.cwd()), /Unknown runtime preset/);
  assert.throws(() => validateSiteInput({
    name: 'Bad builder', port: 4310, runtimeType: 'container', runtimePreset: 'buildpack', containerMode: 'buildpack',
    buildpackBuilder: `builder/${'x'.repeat(300)}`
  }), /Buildpack builder is invalid or too long/);
});

test('runtime line logger bounds newline-free output without dropping the final record', async () => {
  const stream = new PassThrough();
  const lines = [];
  lineLogger(stream, (line) => lines.push(line), { maxLineLength: 16 });
  stream.end('abcdefghijklmnopqrstuvwxyz');
  await new Promise((resolve) => stream.once('end', resolve));
  assert.deepEqual(lines, ['abcdefghijklmnop …[truncated]']);
});

test('runtime none-readiness still rejects a child that fails to spawn', async () => {
  const child = shellCommand(['sham-command-that-does-not-exist-none-xyz'], { stdio: 'ignore' });
  await assert.rejects(() => waitForReadiness({ readiness: { type: 'none', timeoutMs: 2000 } }, { child }), /could not start/);
});

test('runtime UI limits and OIDC requirements match backend validation', () => {
  const html = fs.readFileSync(path.join(__dirname, '..', 'public', 'index.html'), 'utf8');
  const admin = fs.readFileSync(path.join(__dirname, '..', 'public', 'js', 'admin.js'), 'utf8');
  assert.match(html, /id="site-cpu-limit"[^>]*max="256"/);
  assert.match(html, /id="site-pids-limit"[^>]*min="16"/);
  assert.doesNotMatch(html, /Compose is administrator-only/i);
  assert.match(admin, /\$\('#oidc-issuer'\)\.required = enabled/);
  assert.match(admin, /\$\('#oidc-default-role'\)\.disabled = !enabled \|\| !autoProvision/);
});

test('runtime promotion, reconciliation, and container cleanup stay transactional', () => {
  const source = fs.readFileSync(path.join(__dirname, '..', 'src', 'sites', 'runtime.js'), 'utf8');
  assert.match(source, /async promoteCandidate\([\s\S]*?const old = runtime\?\.backend \|\| null[\s\S]*?catch \(error\)[\s\S]*?runtime\.backend = old[\s\S]*?stopBackend\(backend\)/);
  assert.match(source, /async rollbackPromotion\([\s\S]*?if \(!old\)[\s\S]*?DELETE FROM runtime_instances[\s\S]*?stopBackend\(candidate\.backend\)/);
  assert.match(source, /terminateReconciledProcess/);
  assert.match(source, /managedImage[\s\S]*?client\.removeImage/);
  const agentDocker = fs.readFileSync(path.join(__dirname, '..', 'runtime-agent', 'docker.js'), 'utf8');
  assert.match(agentDocker, /image', 'rm', '-f'/);
});

test('Compose runtime validation rejects unmanaged exposure and enforces no-egress overrides', () => {
  const source = fs.readFileSync(path.join(__dirname, '..', 'src', 'sites', 'runtime.js'), 'utf8');
  assert.match(source, /cannot publish host ports; auxiliary services must stay on the Compose network/);
  assert.match(source, /cannot use host bind mounts\. Use named volumes instead/);
  assert.match(source, /cannot be external; SHAM-managed projects must not attach unmanaged Docker resources/);
  assert.match(source, /runtimeOverride\.networks = Object\.fromEntries\([\s\S]*internal: true/);
  // The privileged agent re-runs these same validators (defense in depth) and
  // is the process that actually invokes `docker compose config`.
  const agentDocker = fs.readFileSync(path.join(__dirname, '..', 'runtime-agent', 'docker.js'), 'utf8');
  assert.match(agentDocker, /rejectOutputOverflow: true/);
  assert.match(agentDocker, /validateComposeProjectPaths\(config, root\)/);
  assert.match(agentDocker, /composeRuntimePolicy\(config, service/);
});

test('scheduled jobs target the active runtime instead of stale fixed container names', () => {
  const source = fs.readFileSync(path.join(__dirname, '..', 'src', 'operations', 'configuration.js'), 'utf8');
  assert.doesNotMatch(source, /sham-site-\$\{siteId\}/);
  assert.match(source, /backend\.containerName \|\| backend\.containerId/);
  assert.match(source, /backend\.composeFiles/);
});

test('backup restore validates the full archive and database before swapping live data', () => {
  const source = fs.readFileSync(path.join(__dirname, '..', 'src', 'backup-restore.js'), 'utf8');
  assert.match(source, /inspectTarLines/);
  assert.match(source, /database\.pragma\('quick_check'/);
  assert.match(source, /for \(const table of \['users', 'settings', 'sites'\]\)/);
  assert.match(source, /validateRestoreTree\(stageRoot\)/);
  assert.match(source, /rename\(DATA_DIR, rollbackRoot\)/);
});

test('bulk runtime and tunnel shutdown work is concurrency-bounded', () => {
  const runtime = fs.readFileSync(path.join(__dirname, '..', 'src', 'sites', 'runtime.js'), 'utf8');
  const tunnels = fs.readFileSync(path.join(__dirname, '..', 'src', 'cloudflare-tunnel.js'), 'utf8');
  assert.match(runtime, /runningIds\.slice\(index, index \+ HEALTH_CHECK_CONCURRENCY\)/);
  assert.match(tunnels, /settleInBatches\(rows,[\s\S]*?, 4\)/);
  assert.match(tunnels, /settleInBatches\(managers,[\s\S]*?, 4\)/);
});
