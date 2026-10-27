'use strict';

const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');

const temporary = fs.mkdtempSync(path.join(os.tmpdir(), 'sham-runtime-hardening-'));
process.env.SHAM_DATA_PATH = path.join(temporary, 'data');
process.env.SHAM_JWT_SECRET = 'runtime-hardening-secret-at-least-thirty-two-characters';
process.env.SHAM_MASTER_KEY = '22'.repeat(32);

const test = require('node:test');
const assert = require('node:assert/strict');
const http = require('node:http');
const { spawn } = require('node:child_process');
const { composeRuntimePolicy, validateComposeProjectPaths } = require('../src/sites/runtime');
const {
  COMPOSE_COMPAT_CAPABILITIES, assertNoExternalComposeSources, assertComposeRealPaths, hardenComposeConfig
} = require('../runtime-agent/compose');
const { ValidationError } = require('../runtime-agent/validation');
const workloadNetworks = require('../src/runtime/workload-networks');
const { requestIdentity, sanitizeCloudflareHeaders, setLocalTunnelPeerVerifier, INTERNAL_EDGE_TOKEN } = require('../src/sites/shared');
const { CloudflareTunnelManager, supervisedCloudflaredPids } = require('../src/cloudflare-tunnel');
const { validateProxyTarget } = require('../src/validation');
const { DASHBOARD_PORT } = require('../src/config');

test.after(() => fs.rmSync(temporary, { recursive: true, force: true }));

const project = (services, extra = {}) => ({ name: 'sham-1-run', services, networks: { default: { name: 'sham-1-run_default', ipam: {} } }, ...extra });
const web = (extra = {}) => ({ image: 'busybox:1.37', command: null, entrypoint: null, networks: { default: null }, ...extra });

function policy(config, root = temporary) {
  validateComposeProjectPaths(config, root);
  return composeRuntimePolicy(config, 'web', { containerPort: 3000 });
}

test('Compose policy is an allowlist that names the rejected key', () => {
  policy(project({ web: web({ cap_drop: ['ALL'], security_opt: ['no-new-privileges:true'], privileged: false, cap_add: [], ulimits: { nofile: 1024 }, logging: { driver: 'json-file', options: { 'max-size': '10m' } }, deploy: { resources: { limits: { memory: '256m' } }, placement: {} } }) }, { 'x-meta': 1 }));
  assert.throws(() => policy(project({ web: web({ use_api_socket: true }) })), /unsupported Compose key "use_api_socket"/);
  assert.throws(() => policy(project({ web: web() }, { models: {} })), /unsupported top-level key "models"/);
  assert.throws(() => policy(project({ web: web({ build: { context: temporary, privileged: true } }) })), /cannot build privileged/);
  assert.throws(() => policy(project({ web: web({ build: { context: temporary, frobnicate: 1 } }) })), /build uses unsupported Compose key "frobnicate"/);
});

test('Compose policy rejects host-level service options', () => {
  const cases = [
    [{ device_cgroup_rules: ['c 1:3 mr'] }, /device cgroup/], [{ cgroup_parent: '/x' }, /cgroup parent/], [{ cgroup: 'private' }, /cgroup namespace/],
    [{ runtime: 'runc' }, /container runtime/], [{ isolation: 'process' }, /isolation/], [{ sysctls: { 'net.ipv4.ip_forward': 1 } }, /sysctls/],
    [{ userns_mode: 'host' }, /user namespace/], [{ pid: 'service:db' }, /PID/], [{ pid: 'container:x' }, /PID/], [{ pid: 'host' }, /PID/],
    [{ ipc: 'service:db' }, /IPC/], [{ ipc: 'host' }, /IPC/], [{ uts: 'host' }, /UTS/], [{ privileged: true }, /privileged/],
    [{ cap_add: ['NET_ADMIN'] }, /capabilities/], [{ devices: ['/dev/kmsg'] }, /devices/], [{ oom_kill_disable: true }, /OOM killer/],
    [{ security_opt: ['apparmor=unconfined'] }, /security profiles/], [{ security_opt: ['seccomp=/tmp/x.json'] }, /no-new-privileges/],
    [{ network_mode: 'host' }, /network namespace/], [{ logging: { driver: 'gelf' } }, /logging drivers/], [{ ulimits: { rtprio: 99 } }, /rtprio/],
    [{ deploy: { resources: { reservations: { devices: [{ capabilities: ['gpu'] }] } } } }, /host devices/], [{ oom_score_adj: -500 }, /OOM score/],
    [{ volumes: [{ type: 'bind', source: '/', target: '/host' }] }, /bind mounts/], [{ volumes: [{ type: 'npipe', source: 'x', target: '/x' }] }, /named volumes or tmpfs/],
    [{ extra_hosts: ['gw:host-gateway'] }, /host gateway/], [{ annotations: { a: 'b' } }, /annotations/], [{ external_links: ['db'] }, /outside its project/]
  ];
  for (const [extra, message] of cases) assert.throws(() => policy(project({ web: web(extra), db: web() })), message, JSON.stringify(extra));
});

test('Compose build options cannot retag host images, reach host paths, or use remote contexts', () => {
  const build = (extra) => project({ web: web({ build: { context: temporary, dockerfile: 'Dockerfile', ...extra } }), other: web() });
  for (const [extra, message] of [
    [{ tags: ['postgres:16'] }, /extra image tags/], [{ ssh: ['default'] }, /SSH/], [{ cache_to: ['type=local,dest=/tmp/x'] }, /export build caches/],
    [{ cache_from: ['type=local', 'src=/etc'] }, /host paths/], [{ network: 'host' }, /host networking/], [{ network: 'other_net' }, /default or none/],
    [{ entitlements: ['network.host'] }, /entitlements/], [{ additional_contexts: { x: 'docker-image://alpine' } }, /additional build context x/],
    [{ additional_contexts: { x: 'https://example.com/ctx.tar' } }, /additional build context x/], [{ additional_contexts: { x: 'service:missing' } }, /service in this project/],
    [{ additional_contexts: { x: path.dirname(temporary) } }, /stay inside the site project/], [{ dockerfile: '../../etc/passwd' }, /Dockerfile must stay inside/]
  ]) assert.throws(() => policy(build(extra)), message, JSON.stringify(extra));
  policy(build({ additional_contexts: { x: 'service:other', y: path.join(temporary, 'extra') }, cache_from: ['ghcr.io/example/app:cache'] }));
  assert.throws(() => policy(project({ web: web({ build: { context: 'https://github.com/moby/moby.git' } }) })), /remote build contexts/);
  assert.throws(() => policy(project({ web: web() }, { networks: { default: { driver: 'macvlan' } } })), /bridge driver/);
  assert.throws(() => policy(project({ web: web() }, { secrets: { s: { environment: 'HOME' } } })), /unsupported Compose key "environment"/);
  assert.throws(() => policy(project({ web: web() }, { configs: { c: { file: '/etc/passwd' } } })), /Compose config c must stay inside/);
});

test('raw Compose sources cannot include or extend files the normalized model would hide', () => {
  assertNoExternalComposeSources('services:\n  app:\n    image: x\n  b:\n    extends: app\n  c:\n    extends:\n      service: app\n    command: ["--include-paths"]\n');
  assertNoExternalComposeSources('{"services":{"app":{"image":"x"},"b":{"extends":{"service":"app"}}}}');
  for (const source of [
    'include:\n  - ../other/compose.yaml\nservices: {}\n',
    'services:\n  b:\n    extends: {file: ../other.yaml, service: x}\n',
    'services:\n  b:\n    extends:\n      service: x\n      file: ../other.yaml\n',
    'services:\n  b:\n    "extends":\n      "file": ../other.yaml\n',
    '{"services":{"b":{"extends":{"service":"x","file":"/data/other.yaml"}}}}',
    'services:\n  b:\n    "ext\\x65nds": {service: x}\n',
    '{"services":{"b":{"ext\\u0065nds":{"file":"x"}}}}',
    'services:\n  b:\n    ? extends\n    : {file: x}\n',
    'x: &k extends\nservices:\n  b:\n    *k : {file: x}\n',
    'services:\n  b:\n    extends: *external\n'
  ]) assert.throws(() => assertNoExternalComposeSources(source), ValidationError, source);
});

test('the agent realpath-contains every Compose-referenced path', () => {
  const root = fs.mkdtempSync(path.join(temporary, 'project-'));
  const outside = fs.mkdtempSync(path.join(temporary, 'outside-'));
  fs.mkdirSync(path.join(root, 'app'));
  fs.writeFileSync(path.join(root, 'app', 'Dockerfile'), 'FROM busybox\n');
  fs.writeFileSync(path.join(root, 'ok.env'), 'A=1\n');
  fs.writeFileSync(path.join(outside, 'secret'), 'other-site\n');
  fs.symlinkSync(outside, path.join(root, 'linked-dir'));
  fs.symlinkSync(path.join(outside, 'secret'), path.join(root, 'linked-file'));
  const realRoot = fs.realpathSync(root);
  const resolved = assertComposeRealPaths({ services: { web: { build: { context: path.join(root, 'app'), dockerfile: 'Dockerfile' }, env_file: [{ path: path.join(root, 'ok.env') }, { path: path.join(root, 'missing.env'), required: false }] } } }, realRoot);
  assert.equal(resolved.get(path.join(root, 'app')), path.join(realRoot, 'app'));
  for (const config of [
    { services: { web: { build: { context: path.join(root, 'linked-dir') } } } },
    { services: { web: { build: { context: path.join(root, 'app'), dockerfile: '../linked-file' } } } },
    { services: { web: { build: { context: path.join(root, 'app'), additional_contexts: { x: path.join(root, 'linked-dir') } } } } },
    { services: { web: { env_file: [path.join(root, 'linked-file')] } } },
    { services: { web: {} }, secrets: { s: { file: path.join(root, 'linked-file') } } },
    { services: { web: {} }, configs: { c: { file: path.join(root, 'linked-file') } } },
    { services: { web: { env_file: [{ path: path.join(root, '${EF}'), required: true }] } } }
  ]) assert.throws(() => assertComposeRealPaths(config, realRoot), ValidationError, JSON.stringify(config));
});

test('the hardened model forces capabilities, pins paths, and inlines project files', () => {
  const root = fs.realpathSync(fs.mkdtempSync(path.join(temporary, 'harden-')));
  const secretDir = fs.mkdtempSync(path.join(temporary, 'secret-dir-'));
  fs.mkdirSync(path.join(root, 'app'));
  fs.writeFileSync(path.join(root, 'app', 'Dockerfile'), 'FROM busybox\n');
  fs.writeFileSync(path.join(root, 'cfg'), 'value $HOME\n');
  fs.writeFileSync(path.join(root, 'secret'), 's3cret$x\n');
  const config = project({
    web: web({ build: { context: path.join(root, 'app'), dockerfile: 'Dockerfile', secrets: ['build_only'] }, image: 'ghcr.io/dylpickle-studios/sham:latest', cap_drop: ['net_bind_service'], secrets: [{ source: 'db', target: '/run/secrets/db', mode: 0o400 }], configs: [{ source: 'cfg', target: '/etc/app.cfg' }] }),
    db: web({ image: 'postgres:16', cap_drop: ['ALL'], security_opt: ['no-new-privileges'], develop: { watch: [] } }),
    worker: web({ image: 'ghcr.io/dylpickle-studios/sham:latest' })
  }, { configs: { cfg: { file: path.join(root, 'cfg') } }, secrets: { db: { file: path.join(root, 'secret') }, build_only: { file: path.join(root, 'secret') } } });
  const resolved = assertComposeRealPaths(config, root);
  const hardened = hardenComposeConfig(config, { root, resolved, secretDir });
  assert.deepEqual(hardened.services.web.cap_drop, ['ALL']);
  assert.deepEqual(hardened.services.web.cap_add, COMPOSE_COMPAT_CAPABILITIES.filter((capability) => capability !== 'NET_BIND_SERVICE'));
  assert.deepEqual(hardened.services.db.cap_add, []);
  for (const service of Object.values(hardened.services)) assert.deepEqual(service.security_opt, ['no-new-privileges:true']);
  for (const capability of ['MKNOD', 'NET_RAW', 'SETFCAP', 'SYS_CHROOT', 'AUDIT_WRITE']) assert.ok(!COMPOSE_COMPAT_CAPABILITIES.includes(capability));
  assert.equal(hardened.services.web.image, 'sham-1-run-web', 'a build never keeps a host-wide tag');
  assert.equal(hardened.services.worker.image, 'sham-1-run-web', 'services sharing the built image follow the rename');
  assert.equal(hardened.services.worker.pull_policy, 'never');
  assert.equal(hardened.services.db.image, 'postgres:16');
  assert.equal(hardened.services.db.pull_policy, undefined);
  assert.equal(hardened.services.db.develop, undefined);
  assert.equal(hardened.services.web.build.dockerfile, path.join(root, 'app', 'Dockerfile'));
  assert.equal(hardened.configs.cfg.content, 'value $$HOME\n');
  assert.equal(hardened.configs.cfg.file, undefined);
  assert.equal(hardened.configs['sham-secret-db'].content, 's3cret$$x\n');
  assert.deepEqual(hardened.services.web.configs.at(-1), { source: 'sham-secret-db', target: '/run/secrets/db', mode: 0o400 });
  assert.equal(hardened.services.web.secrets, undefined);
  assert.equal(hardened.secrets.db, undefined);
  assert.equal(path.dirname(hardened.secrets.build_only.file), secretDir);
  assert.equal(fs.statSync(hardened.secrets.build_only.file).mode & 0o777, 0o600);
  assert.equal(config.services.web.cap_drop[0], 'net_bind_service', 'the validated model itself is not mutated');
});

test('workload guard never blocks the host side of a runtime bridge', () => {
  // Under the isolation overlay docker-proxy, host-local clients and IPv6 clients
  // reach the control plane from the runtime network's gateway address.
  workloadNetworks.setWorkloadSubnets(['172.27.0.0/16', 'fd00:5::/64']);
  assert.equal(workloadNetworks.isWorkloadAddress('172.27.0.1'), false);
  assert.equal(workloadNetworks.isWorkloadAddress('::ffff:172.27.0.1'), false);
  assert.equal(workloadNetworks.isWorkloadAddress('fd00:5::1'), false);
  assert.equal(workloadNetworks.isWorkloadAddress('172.27.0.2'), true);
  workloadNetworks.setWorkloadSubnets(['10.9.8.0/24'], ['10.9.8.254']);
  assert.equal(workloadNetworks.isWorkloadAddress('10.9.8.254'), false, 'a reported gateway is the host');
  assert.equal(workloadNetworks.isWorkloadAddress('10.9.8.1'), true, 'without the fallback, .1 can be a workload');
  workloadNetworks.setWorkloadSubnets(['172.30.0.0/16', 'fd00:30::/64'], ['172.30.0.1']);
  assert.equal(workloadNetworks.isWorkloadAddress('fd00:30::1'), false, 'a subnet without a reported gateway keeps the fallback');
  assert.equal(workloadNetworks.isWorkloadAddress('172.30.0.1'), false);
  workloadNetworks.setWorkloadSubnets([]);
});

test('workload subnets block the dashboard and direct listeners, fail-open until known', async (t) => {
  let calls = 0;
  let response = { networks: [{ name: 'sham-runtime-internal', subnets: ['172.30.0.0/16', 'fd00:5::/64'] }] };
  workloadNetworks.configureWorkloadNetworks({ fetch: async () => { calls += 1; if (response instanceof Error) throw response; return response; } });
  t.after(() => workloadNetworks.configureWorkloadNetworks({ fetch: () => Promise.reject(new Error('reset')) }));
  assert.equal(workloadNetworks.isWorkloadAddress('172.30.0.5'), false, 'unknown subnets fail open');
  await workloadNetworks.refreshWorkloadSubnets();
  assert.ok(calls >= 1);
  for (const address of ['172.30.0.5', '::ffff:172.30.9.9', 'fd00:5::12']) assert.equal(workloadNetworks.isWorkloadAddress(address), true, address);
  for (const address of ['127.0.0.1', '::1', '172.31.0.1', '::ffff:10.0.0.1', undefined]) assert.equal(workloadNetworks.isWorkloadAddress(address), false, String(address));
  response = new Error('agent unavailable');
  await workloadNetworks.refreshWorkloadSubnets();
  assert.equal(workloadNetworks.isWorkloadAddress('172.30.0.5'), true, 'a failed refresh keeps the last known subnets');

  const guard = workloadNetworks.workloadNetworkGuard();
  const respond = (remoteAddress) => {
    const result = { status: 200, nextCalled: false };
    const res = { writeHead: (status) => { result.status = status; return res; }, end: () => res };
    guard({ socket: { remoteAddress } }, res, () => { result.nextCalled = true; });
    return result;
  };
  assert.deepEqual(respond('::ffff:172.30.1.2'), { status: 403, nextCalled: false });
  assert.deepEqual(respond('192.0.2.1'), { status: 200, nextCalled: true });
});

test('direct site listeners reject workload-network peers through checkAccess', async (t) => {
  workloadNetworks.configureWorkloadNetworks({ fetch: async () => ({ networks: [{ subnets: ['172.30.0.0/16'] }] }) });
  t.after(() => workloadNetworks.configureWorkloadNetworks({ fetch: () => Promise.reject(new Error('reset')) }));
  await workloadNetworks.refreshWorkloadSubnets();
  const { CoreSiteManager } = require('../src/sites/core');
  const manager = Object.create(CoreSiteManager.prototype);
  const site = { id: 1, firewall: {}, firewall_enabled: false };
  assert.equal(manager.checkAccess(site, { headers: {}, socket: { remoteAddress: '172.30.4.4' } }).status, 403);
  assert.equal(manager.checkAccess(site, { headers: {}, socket: { remoteAddress: '127.0.0.1' } }).allowed, true);
  const runtimeSource = fs.readFileSync(path.join(__dirname, '..', 'src', 'sites', 'runtime.js'), 'utf8');
  assert.equal((runtimeSource.match(/isWorkloadAddress\(req\.socket\.remoteAddress\)/g) || []).length, 2, 'private listener HTTP and upgrade paths are guarded');
});

test('Cloudflare visitor headers are trusted only from a verified tunnel peer and never laundered upstream', (t) => {
  t.after(() => setLocalTunnelPeerVerifier(null));
  const request = (remoteAddress, headers = {}) => ({ headers: { 'cf-connecting-ip': '203.0.113.7', 'cf-ipcountry': 'NL', 'cf-visitor': '{"scheme":"https"}', 'user-agent': 'x', ...headers }, socket: { remoteAddress } });

  setLocalTunnelPeerVerifier(() => false);
  const forged = request('127.0.0.1');
  const forgedIdentity = sanitizeCloudflareHeaders({}, forged, { trustLocalCloudflareTunnel: true });
  assert.equal(forgedIdentity.ip, '127.0.0.1');
  assert.equal(forgedIdentity.country, 'ZZ');
  for (const name of ['cf-connecting-ip', 'cf-ipcountry', 'cf-visitor']) assert.equal(forged.headers[name], undefined, name);

  setLocalTunnelPeerVerifier(() => true);
  const tunnel = request('::ffff:127.0.0.1', { 'cf-connecting-ip': ' 198.51.100.4 ' });
  const tunnelIdentity = sanitizeCloudflareHeaders({}, tunnel, { trustLocalCloudflareTunnel: true });
  assert.equal(tunnelIdentity.ip, '198.51.100.4');
  assert.equal(tunnel.headers['cf-connecting-ip'], '198.51.100.4');
  assert.equal(tunnel.headers['cf-ipcountry'], 'NL');

  setLocalTunnelPeerVerifier(() => null);
  assert.equal(requestIdentity({}, request('127.0.0.1'), { trustLocalCloudflareTunnel: true }).ip, '203.0.113.7', 'without /proc the loopback rule is unchanged');

  const direct = request('192.0.2.50');
  sanitizeCloudflareHeaders({ cloudflare_enabled: false }, direct);
  assert.equal(direct.headers['cf-connecting-ip'], undefined);

  const viaEdge = request('127.0.0.1', { 'x-sham-edge-token': INTERNAL_EDGE_TOKEN, 'x-sham-client-ip': '198.51.100.4', 'cf-connecting-ip': '198.51.100.4' });
  assert.equal(sanitizeCloudflareHeaders({}, viaEdge).ip, '198.51.100.4');
  assert.equal(viaEdge.headers['cf-connecting-ip'], '198.51.100.4', 'the edge already rewrote these headers');

  const sources = ['edge-proxy.js', path.join('sites', 'runtime.js')].map((file) => fs.readFileSync(path.join(__dirname, '..', 'src', file), 'utf8'));
  assert.match(sources[0], /prepareRequest\(site, req\) \{\s*const identity = sanitizeCloudflareHeaders/);
  assert.equal((sources[1].match(/sanitizeCloudflareHeaders\((?:activeSite|runtime\.site), req\);\s*proxy\.(?:web|ws)/g) || []).length, 4);
});

test('the /proc lookup trusts only connections owned by a supervised cloudflared child', { skip: process.platform !== 'linux' || !fs.existsSync('/proc/net/tcp') }, async (t) => {
  setLocalTunnelPeerVerifier(null);
  const identities = [];
  const server = http.createServer((req, res) => {
    identities.push(requestIdentity({}, req, { trustLocalCloudflareTunnel: true }));
    res.end('ok');
  });
  await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve));
  t.after(() => server.close());
  const { port } = /** @type {import('node:net').AddressInfo} */ (server.address());

  // An unsupervised local process forging the header is an ordinary peer.
  await new Promise((resolve, reject) => http.get({ host: '127.0.0.1', port, headers: { 'cf-connecting-ip': '203.0.113.9' } }, (res) => { res.resume(); res.once('end', resolve); }).once('error', reject));
  assert.equal(identities.at(-1).ip, '127.0.0.1');

  const script = `require('node:http').get({ host: '127.0.0.1', port: ${port}, headers: { 'cf-connecting-ip': '203.0.113.10', 'cf-ipcountry': 'DE' } }, (res) => { res.resume(); res.on('end', () => setTimeout(() => {}, 30000)); });`;
  const settings = { status: () => ({ enabled: true, tokenConfigured: true }), token: () => 'eyJ-test-token', save: () => ({}) };
  let child = null;
  const manager = new CloudflareTunnelManager({
    settingsStore: settings, command: process.execPath, commandAvailableCheck: () => true, environment: (extra) => ({ ...extra }),
    spawnProcess: () => { child = spawn(process.execPath, ['-e', script], { stdio: ['ignore', 'pipe', 'pipe'] }); return child; },
    terminateProcess: (running) => new Promise((resolve) => { if (running.exitCode !== null) return resolve(); running.once('exit', resolve); running.kill('SIGKILL'); }),
    originProbe: async () => ({ ok: true }), restartBaseMs: 60_000, stableAfterMs: 60_000
  });
  t.after(() => manager.shutdown());
  await manager.start();
  assert.ok(child?.pid && supervisedCloudflaredPids().includes(child.pid));
  const deadline = Date.now() + 10_000;
  while (identities.length < 2 && Date.now() < deadline) await new Promise((resolve) => setTimeout(resolve, 25));
  assert.equal(identities[1]?.ip, '203.0.113.10');
  assert.equal(identities[1]?.country, 'DE');
});

test('reverse proxy targets cannot reach link-local metadata or the SHAM dashboard', () => {
  for (const target of [
    'http://169.254.169.254/latest/meta-data/', 'http://2852039166/', 'http://[::ffff:169.254.169.254]/', 'http://[fe80::1]/',
    'http://[fd00:ec2::254]/', `http://127.0.0.1:${DASHBOARD_PORT}/`, `http://localhost:${DASHBOARD_PORT}`, `http://[::1]:${DASHBOARD_PORT}/`,
    `http://0.0.0.0:${DASHBOARD_PORT}/`, `http://[::ffff:127.0.0.1]:${DASHBOARD_PORT}/`
  ]) assert.throws(() => validateProxyTarget(target, 'proxy'), /link-local|dashboard/, target);
  assert.equal(validateProxyTarget('http://127.0.0.1:3000', 'proxy'), 'http://127.0.0.1:3000/');
  assert.equal(validateProxyTarget('https://example.com/', 'proxy'), 'https://example.com/');
  const runtime = fs.readFileSync(path.join(__dirname, '..', 'src', 'sites', 'runtime.js'), 'utf8');
  assert.match(runtime, /assertSafeProxyTarget\(target\);/, 'saved targets are re-checked at launch');
});

