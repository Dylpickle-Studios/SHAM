'use strict';

process.env.SHAM_JWT_SECRET = 'cloudflare-tunnel-improvements-test-secret-at-least-32-characters';

const test = require('node:test');
const assert = require('node:assert/strict');
const { EventEmitter } = require('node:events');
const { PassThrough } = require('node:stream');
const fs = require('node:fs');
const path = require('node:path');
const {
  CloudflareTunnelManager,
  SiteCloudflareTunnelRegistry,
  validateOriginService
} = require('../src/cloudflare-tunnel');
const { CloudflareTunnelControlPlane } = require('../src/cloudflare-tunnel-control-plane');

class Child extends EventEmitter {
  constructor() {
    super();
    this.pid = 4242;
    this.exitCode = null;
    this.signalCode = null;
    this.stdout = new PassThrough();
    this.stderr = new PassThrough();
  }

  exit(code = 1, signal = null) {
    this.exitCode = code;
    this.signalCode = signal;
    this.emit('exit', code, signal);
  }
}

class Settings {
  constructor({ enabled = true, token = 'tunnel-token', route = {} } = {}) {
    this.enabled = enabled;
    this.savedToken = token;
    this.route = { tunnelId: '', publicHostname: 'app.example.test', originService: 'http://127.0.0.1:8080', managedRoute: false, tunnelOnly: false, ...route };
  }

  status() { return { enabled: this.enabled, tokenConfigured: Boolean(this.savedToken), ...this.route }; }
  token() { return this.savedToken; }
  save(input) {
    this.enabled = Boolean(input.enabled);
    if (input.token !== undefined) this.savedToken = input.token;
    if (input.clearToken) this.savedToken = '';
    for (const [inputKey, routeKey] of [['tunnelId', 'tunnelId'], ['publicHostname', 'publicHostname'], ['originService', 'originService'], ['managedRoute', 'managedRoute'], ['tunnelOnly', 'tunnelOnly']]) {
      if (input[inputKey] !== undefined) this.route[routeKey] = input[inputKey];
    }
  }
}

function managerHarness(options = {}) {
  const children = [];
  const settings = options.settings || new Settings(options);
  const manager = new CloudflareTunnelManager({
    settingsStore: settings,
    command: '/usr/local/bin/cloudflared',
    commandAvailableCheck: () => options.available ?? true,
    spawnProcess: () => {
      const child = new Child();
      children.push(child);
      return child;
    },
    terminateProcess: async (child) => child.exit(0, 'SIGTERM'),
    environment: (extra) => ({ ...extra }),
    originProbe: options.originProbe || (async () => ({ healthy: true, statusCode: 204, error: '' })),
    originCheckIntervalMs: 100,
    availabilityRecheckMs: 100,
    restartBaseMs: 100,
    restartMaxMs: 200,
    random: () => 0.5
  });
  return { manager, children, settings };
}

const wait = (milliseconds) => new Promise((resolve) => setTimeout(resolve, milliseconds));

test('tunnel origin health is distinct from Cloudflare edge connection state', async () => {
  const probes = [];
  const { manager, children } = managerHarness({ originProbe: async (service, hostname) => {
    probes.push({ service, hostname });
    return { healthy: true, statusCode: 204, error: '' };
  } });
  await manager.start();
  children[0].stderr.write('INF Registered tunnel connection connIndex=0\n');
  await wait(10);
  const status = manager.status();
  assert.equal(status.connected, true);
  assert.equal(status.origin.state, 'healthy');
  assert.equal(status.origin.statusCode, 204);
  assert.deepEqual(probes, [{ service: 'http://127.0.0.1:8080', hostname: 'app.example.test' }]);
  await manager.shutdown();
});

test('authentication failures pause retries while unavailable cloudflared is rechecked', async () => {
  const auth = managerHarness();
  await auth.manager.start();
  auth.children[0].stderr.write('ERR authentication failed: invalid token\n');
  auth.children[0].exit(1);
  await wait(10);
  assert.equal(auth.manager.status().state, 'needs-attention');
  assert.equal(auth.manager.status().failureClass, 'authentication');
  await wait(130);
  assert.equal(auth.children.length, 1);
  await auth.manager.shutdown();

  let available = false;
  const recovered = managerHarness({ available: false });
  recovered.manager.commandAvailableCheck = () => available;
  await recovered.manager.start();
  assert.equal(recovered.manager.status().state, 'unavailable');
  available = true;
  await wait(130);
  assert.equal(recovered.children.length, 1);
  await recovered.manager.shutdown();
});

test('tunnel routes accept only local credential-free HTTP origins', () => {
  assert.equal(validateOriginService('http://[::1]:8080/'), 'http://[::1]:8080');
  assert.throws(() => validateOriginService('https://user:pass@127.0.0.1'), /credential-free/);
  assert.throws(() => validateOriginService('http://10.0.0.8:8080'), /loopback/);
  assert.throws(() => validateOriginService('https://origin.example.test'), /loopback/);
});

test('control-plane reconciliation preserves unrelated ingress routes and uses bearer auth', async () => {
  const requests = [];
  const fetchImpl = async (url, options) => {
    requests.push({ url, options });
    if (options.method === 'GET') return { ok: true, status: 200, json: async () => ({ success: true, result: { config: { ingress: [
      { hostname: 'old.example.test', service: 'http://127.0.0.1:3000' },
      { hostname: 'keep.example.test', service: 'http://127.0.0.1:4000' },
      { service: 'http_status:404' }
    ] } } }) };
    return { ok: true, status: 200, json: async () => ({ success: true, result: { version: 7 } }) };
  };
  const control = new CloudflareTunnelControlPlane({
    accountId: '0123456789abcdef0123456789abcdef',
    apiToken: 'management-token',
    fetchImpl
  });
  const result = await control.reconcileIngress({
    tunnelId: 'f70ff985-a4ef-4643-bbbc-4a0ed4fc8415',
    publicHostname: 'old.example.test',
    originService: 'http://127.0.0.1:8080'
  });
  assert.equal(result.configVersion, 7);
  assert.equal(requests.length, 2);
  assert.equal(requests[0].options.headers.Authorization, 'Bearer management-token');
  assert.equal(requests[0].options.redirect, 'error');
  const submitted = JSON.parse(requests[1].options.body).config.ingress;
  assert.deepEqual(submitted, [
    { hostname: 'keep.example.test', service: 'http://127.0.0.1:4000' },
    { hostname: 'old.example.test', service: 'http://127.0.0.1:8080' },
    { service: 'http_status:404' }
  ]);
});

test('shared-edge routing rejects duplicate active domains and stores managed route fields', () => {
  const routes = fs.readFileSync(path.join(__dirname, '..', 'src', 'routes', 'sites.js'), 'utf8');
  const proxy = fs.readFileSync(path.join(__dirname, '..', 'src', 'edge-proxy.js'), 'utf8');
  const db = fs.readFileSync(path.join(__dirname, '..', 'src', 'db.js'), 'utf8');
  assert.match(routes, /assertEdgeDomainAvailable\(config/);
  assert.match(routes, /assertTunnelOnlyBinding\(config, site\.id\)/);
  assert.match(proxy, /findEdgeSites/);
  assert.match(proxy, /Refused ambiguous shared-edge hostname/);
  assert.match(db, /tunnel_id TEXT NOT NULL DEFAULT ''/);
  assert.match(db, /managed_route INTEGER NOT NULL DEFAULT 0/);
});

test('shared connector sites reuse the instance connector instead of spawning one process per site', async () => {
  const stores = new Map([[1, new Settings({ enabled: false, token: '', route: { connectorMode: 'shared' } })]]);
  const calls = { start: 0, restart: 0 };
  const sharedManager = {
    status: () => ({ enabled: true, tokenConfigured: true, tokenReadable: true, available: true, state: 'connected', running: true, connected: true, restartCount: 2, lastError: '', lastLog: '', route: { tunnelId: 'f70ff985-a4ef-4643-bbbc-4a0ed4fc8415' } }),
    start: async () => { calls.start += 1; },
    restart: async () => { calls.restart += 1; }
  };
  const registry = new SiteCloudflareTunnelRegistry({
    db: {},
    sharedManager,
    settingsStoreFactory: (_db, id) => stores.get(id)
  });
  const result = await registry.configure(1, {
    enabled: true,
    connectorMode: 'shared',
    tunnelId: 'f70ff985-a4ef-4643-bbbc-4a0ed4fc8415',
    publicHostname: 'app.example.test',
    originService: 'http://127.0.0.1:8080',
    managedRoute: true
  });
  assert.equal(result.route.connectorMode, 'shared');
  assert.equal(result.connected, true);
  await registry.start(1);
  await registry.restart(1);
  assert.deepEqual(calls, { start: 1, restart: 1 });
});
