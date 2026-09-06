'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const http = require('node:http');
const { spawn } = require('node:child_process');

const ROOT = path.resolve(__dirname, '..');
const FAKE_DOCKER = path.join(__dirname, 'fixtures', 'fake-docker.js');

function waitFor(predicate, timeoutMs = 5000) {
  const deadline = Date.now() + timeoutMs;
  return new Promise((resolve, reject) => {
    const check = () => {
      if (predicate()) return resolve();
      if (Date.now() > deadline) return reject(new Error('Timed out waiting for condition.'));
      setTimeout(check, 25);
    };
    check();
  });
}

async function startAgent() {
  // Some archive/check-out paths discard executable bits. The runtime agent
  // intentionally executes its configured Docker binary, so make the test
  // fixture's contract explicit instead of relying on checkout metadata.
  fs.chmodSync(FAKE_DOCKER, 0o755);
  const dataDir = fs.mkdtempSync(path.join(os.tmpdir(), 'sham-agent-data-'));
  const stateDir = fs.mkdtempSync(path.join(os.tmpdir(), 'sham-agent-tmp-'));
  const socketPath = path.join(dataDir, 'agent.sock');
  const child = spawn(process.execPath, [path.join(ROOT, 'runtime-agent', 'index.js')], {
    cwd: ROOT,
    env: {
      ...process.env,
      SHAM_DATA_PATH: dataDir,
      SHAM_DOCKER_BIN: FAKE_DOCKER,
      SHAM_RUNTIME_AGENT_SOCKET: socketPath,
      TMPDIR: stateDir,
      TMP: stateDir,
      TEMP: stateDir
    },
    stdio: ['ignore', 'pipe', 'pipe']
  });
  let stdout = '';
  let stderr = '';
  child.stdout.on('data', (chunk) => { stdout += chunk.toString(); });
  child.stderr.on('data', (chunk) => { stderr += chunk.toString(); });
  await waitFor(() => fs.existsSync(socketPath));
  const tokenPath = path.join(dataDir, 'runtime-agent', 'agent.token');
  await waitFor(() => fs.existsSync(tokenPath));
  const token = fs.readFileSync(tokenPath, 'utf8').trim();
  return {
    child, socketPath, token, dataDir, stateDir,
    getStdout: () => stdout,
    getStderr: () => stderr,
    async stop() {
      child.kill('SIGTERM');
      await new Promise((resolve) => child.once('exit', resolve));
      fs.rmSync(dataDir, { recursive: true, force: true });
      fs.rmSync(stateDir, { recursive: true, force: true });
    }
  };
}

function rawRequest(socketPath, { method = 'POST', path: urlPath, token, protocolVersion = '1', body, rawBody, headers = {} } = {}) {
  return new Promise((resolve, reject) => {
    const payload = rawBody !== undefined ? Buffer.from(rawBody) : body !== undefined ? Buffer.from(JSON.stringify(body)) : null;
    const req = http.request({
      socketPath, path: urlPath, method,
      headers: {
        ...(token !== undefined ? { authorization: `Bearer ${token}` } : {}),
        ...(protocolVersion !== undefined ? { 'x-sham-runtime-protocol': protocolVersion } : {}),
        ...(payload ? { 'content-type': 'application/json', 'content-length': payload.length } : {}),
        ...headers
      }
    }, (res) => {
      const chunks = [];
      res.on('data', (chunk) => chunks.push(chunk));
      res.once('end', () => {
        const text = Buffer.concat(chunks).toString('utf8');
        let json = null;
        try { json = text ? JSON.parse(text) : null; } catch { /* streaming NDJSON, leave raw */ }
        resolve({ statusCode: res.statusCode, headers: res.headers, text, json });
      });
    });
    req.once('error', reject);
    if (payload) req.end(payload); else req.end();
  });
}

test('runtime agent: authentication, protocol, and malformed-request handling', async (t) => {
  const agent = await startAgent();
  t.after(() => agent.stop());

  await t.test('unauthenticated /health succeeds with a minimal body', async () => {
    const res = await rawRequest(agent.socketPath, { method: 'GET', path: '/health', token: undefined, protocolVersion: undefined });
    assert.equal(res.statusCode, 200);
    assert.deepEqual(res.json, { status: 'ok' });
  });

  await t.test('missing token is rejected', async () => {
    const res = await rawRequest(agent.socketPath, { path: '/v1/status', method: 'GET', token: undefined });
    assert.equal(res.statusCode, 401);
    assert.equal(res.json.error.code, 'UNAUTHENTICATED');
  });

  await t.test('incorrect token is rejected', async () => {
    const res = await rawRequest(agent.socketPath, { path: '/v1/status', method: 'GET', token: 'wrong-token-value-that-is-long-enough' });
    assert.equal(res.statusCode, 401);
  });

  await t.test('the real token is never present in agent stdout/stderr logs', () => {
    assert.doesNotMatch(agent.getStdout(), new RegExp(agent.token));
    assert.doesNotMatch(agent.getStderr(), new RegExp(agent.token));
  });

  await t.test('protocol version mismatch is rejected with a clear error', async () => {
    const res = await rawRequest(agent.socketPath, { path: '/v1/status', method: 'GET', token: agent.token, protocolVersion: '99' });
    assert.equal(res.statusCode, 426);
    assert.equal(res.json.error.code, 'PROTOCOL_VERSION_MISMATCH');
  });

  await t.test('malformed JSON body is rejected, not crashed on', async () => {
    const res = await rawRequest(agent.socketPath, { path: '/v1/containers/stop', token: agent.token, rawBody: '{not json' });
    assert.equal(res.statusCode, 400);
    assert.equal(res.json.error.code, 'INVALID_REQUEST');
  });

  await t.test('a JSON array body (not an object) is rejected', async () => {
    const res = await rawRequest(agent.socketPath, { path: '/v1/containers/stop', token: agent.token, rawBody: '[1,2,3]' });
    assert.equal(res.statusCode, 400);
  });

  await t.test('an oversized request body is rejected', async () => {
    const res = await rawRequest(agent.socketPath, { path: '/v1/containers/stop', token: agent.token, rawBody: JSON.stringify({ name: 'x'.repeat(300 * 1024) }) });
    assert.equal(res.statusCode, 413);
  });

  await t.test('unknown operations return 404, not a generic passthrough', async () => {
    const res = await rawRequest(agent.socketPath, { path: '/v1/docker', token: agent.token, body: { command: 'rm -rf /' } });
    assert.equal(res.statusCode, 404);
    const res2 = await rawRequest(agent.socketPath, { path: '/exec', token: agent.token, body: { cmd: 'id' } });
    assert.equal(res2.statusCode, 404);
  });
});

test('runtime agent: input validation blocks dangerous or malformed operation targets', async (t) => {
  const agent = await startAgent();
  t.after(() => agent.stop());

  const cases = [
    ['command injection in container name', '/v1/containers/stop', { name: 'sham-site-1; rm -rf /' }],
    ['path traversal in compose files', '/v1/compose/config', { files: ['../../../../etc/passwd'], cwd: agent.dataDir, service: 'app', containerPort: 3000 }],
    ['attempt to reference the Docker socket as a data mount', '/v1/containers/run', { name: 'sham-site-1-a', image: 'node:22', siteId: 1, dataMount: { source: '/var/run/docker.sock', target: '/data' } }],
    ['attempt to mount the filesystem root', '/v1/containers/run', { name: 'sham-site-1-a', image: 'node:22', siteId: 1, dataMount: { source: '/', target: '/data' } }],
    ['non-loopback published port (host network exposure)', '/v1/containers/run', { name: 'sham-site-1-a', image: 'node:22', siteId: 1, ports: [{ hostIp: '0.0.0.0', containerPort: 3000 }] }],
    ['malicious image reference', '/v1/containers/run', { name: 'sham-site-1-a', image: 'node:22; curl evil.example', siteId: 1 }],
    ['image removal outside the SHAM-managed namespace', '/v1/images/remove', { tag: 'ubuntu:latest' }],
    ['unknown/unmanaged network name', '/v1/networks/ensure', { name: 'host', internal: false }],
    ['sidecar name outside the Anubis namespace', '/v1/containers/sidecar-run', { name: 'sham-site-1-a', networkMode: 'host', policyFile: agent.dataDir, port: 8080, targetPort: 80 }]
  ];

  for (const [label, urlPath, body] of cases) {
    await t.test(label, async () => {
      const res = await rawRequest(agent.socketPath, { path: urlPath, token: agent.token, body });
      assert.equal(res.statusCode, 400, `${label} should be rejected with 400, got ${res.statusCode}: ${res.text}`);
      assert.equal(res.json.error.code, 'INVALID_REQUEST');
    });
  }

  await t.test('unexpected privileged Docker fields are rejected before a container is launched', async () => {
    const res = await rawRequest(agent.socketPath, {
      path: '/v1/containers/run',
      token: agent.token,
      body: { name: 'sham-site-1-run', image: 'node:22', siteId: 1, privileged: true, capAdd: ['SYS_ADMIN'], networkMode: 'host' }
    });
    assert.equal(res.statusCode, 400);
    assert.equal(res.json.error.code, 'INVALID_REQUEST');
    assert.match(res.json.error.message, /Unexpected request fields: privileged, capAdd, networkMode/);
  });

  await t.test('every POST operation rejects unknown request fields before operation validation', async () => {
    const { OPERATIONS } = require('../src/runtime/protocol');
    for (const operation of Object.values(OPERATIONS)) {
      if (operation.method !== 'POST') continue;
      const res = await rawRequest(agent.socketPath, { path: operation.path, token: agent.token, body: { unexpected: true } });
      assert.equal(res.statusCode, 400, `${operation.path} must reject an unknown property`);
      assert.equal(res.json.error.code, 'INVALID_REQUEST');
      assert.match(res.json.error.message, /Unexpected request field/);
    }
  });
});

test('runtime agent: resource ownership is enforced for mutating container operations', async (t) => {
  const agent = await startAgent();
  t.after(() => agent.stop());

  // Seed an "imposter" container in the fake Docker state that matches the
  // SHAM naming convention but was never created by SHAM (no managed label).
  const statePath = path.join(agent.stateDir, 'sham-fake-docker-state.json');
  fs.writeFileSync(statePath, JSON.stringify({
    containers: { 'sham-site-9-imposter': { Id: 'cid-imposter', Config: { Labels: {} } } },
    networks: {}
  }));

  await t.test('stopping an unmanaged container is refused', async () => {
    const res = await rawRequest(agent.socketPath, { path: '/v1/containers/stop', token: agent.token, body: { name: 'sham-site-9-imposter' } });
    assert.equal(res.statusCode, 403);
    assert.equal(res.json.error.code, 'RESOURCE_NOT_OWNED');
  });

  await t.test('execing into an unmanaged container is refused', async () => {
    const res = await rawRequest(agent.socketPath, { path: '/v1/containers/exec', token: agent.token, body: { name: 'sham-site-9-imposter', command: 'id' } });
    assert.equal(res.statusCode, 403);
  });

  await t.test('operating on a nonexistent container returns NOT_FOUND, not a crash', async () => {
    const res = await rawRequest(agent.socketPath, { path: '/v1/containers/stop', token: agent.token, body: { name: 'sham-site-9-does-not-exist' } });
    assert.equal(res.statusCode, 404);
    assert.equal(res.json.error.code, 'NOT_FOUND');
  });
});

test('runtime agent: full container lifecycle happy path against the fake Docker CLI', async (t) => {
  const agent = await startAgent();
  t.after(() => agent.stop());

  const name = 'sham-site-42-run';
  const created = await rawRequest(agent.socketPath, { path: '/v1/containers/run', token: agent.token, body: { name, image: 'node:22', siteId: 42, env: { PORT: '3000' } } });
  assert.equal(created.statusCode, 200);
  assert.ok(created.json.containerId);

  const ported = await rawRequest(agent.socketPath, { path: '/v1/containers/port', token: agent.token, body: { name, containerPort: 3000 } });
  assert.equal(ported.statusCode, 200);
  assert.equal(ported.json.port, 34567);

  const stopped = await rawRequest(agent.socketPath, { path: '/v1/containers/stop', token: agent.token, body: { name, timeoutSec: 5 } });
  assert.equal(stopped.statusCode, 200);

  const removed = await rawRequest(agent.socketPath, { path: '/v1/containers/remove', token: agent.token, body: { name } });
  assert.equal(removed.statusCode, 200);

  const afterRemoval = await rawRequest(agent.socketPath, { path: '/v1/containers/stop', token: agent.token, body: { name } });
  assert.equal(afterRemoval.statusCode, 404);
});

test('runtime agent: status reports Docker reachability without leaking internals', async (t) => {
  const agent = await startAgent();
  t.after(() => agent.stop());
  const res = await rawRequest(agent.socketPath, { path: '/v1/status', method: 'GET', token: agent.token });
  assert.equal(res.statusCode, 200);
  assert.equal(res.json.dockerAvailable, true);
  assert.equal(res.json.dockerVersion, '99.0.0');
  assert.equal(Object.prototype.hasOwnProperty.call(res.json, 'token'), false);
});

test('runtime agent: workload environment never configures the CLI or its executable lookup', async (t) => {
  const agent = await startAgent();
  t.after(() => agent.stop());
  const hostilePath = path.join(agent.dataDir, 'caller-bin');
  fs.mkdirSync(hostilePath);
  fs.writeFileSync(path.join(hostilePath, 'node'), '#!/bin/sh\nexit 99\n', { mode: 0o755 });
  const env = {
    PATH: hostilePath, HOME: '/caller-home', NODE_OPTIONS: '--caller-invalid-option',
    DOCKER_HOST: 'unix:///caller/docker.sock', DOCKER_CONFIG: '/caller-config',
    TOKEN: 'dummy-secret-$value', EMPTY: ''
  };
  const response = await rawRequest(agent.socketPath, { path: '/v1/containers/run', token: agent.token,
    body: { name: 'sham-site-55-env', image: 'node:22', siteId: 55, env } });
  assert.equal(response.statusCode, 200, response.text);
  const state = JSON.parse(fs.readFileSync(path.join(agent.stateDir, 'sham-fake-docker-state.json'), 'utf8'));
  assert.deepEqual(state.containers['sham-site-55-env'].Config.Env, Object.entries(env).map(([key, value]) => `${key}=${value}`));
  assert.deepEqual(state.containers['sham-site-55-env'].Config.LeakedEnv, []);
  assert.equal(fs.readdirSync(agent.stateDir).some((name) => name.startsWith('sham-agent-env-')), false);

  const compose = path.join(agent.dataDir, 'compose.yaml');
  fs.writeFileSync(compose, 'services: {}\n');
  for (const key of ['DOCKER_CONFIG', 'COMPOSE_FILE', 'COMPOSE_PROJECT_NAME']) {
    const rejected = await rawRequest(agent.socketPath, { path: '/v1/compose/config', token: agent.token,
      body: { files: [compose], cwd: agent.dataDir, env: { [key]: '/caller' }, service: 'web', containerPort: 3000 } });
    assert.equal(rejected.statusCode, 400, rejected.text);
    assert.match(rejected.json.error.message, /reserved/);
  }
});

test('runtime agent: restore pause blocks workloads until recovery releases the marker', async (t) => {
  const agent = await startAgent();
  t.after(() => agent.stop());
  const statePath = path.join(agent.stateDir, 'sham-fake-docker-state.json');
  fs.writeFileSync(statePath, JSON.stringify({ containers: {
    owned: { Id: 'owned', Config: { Labels: { 'sham.managed': 'true' } } },
    auxiliary: { Id: 'auxiliary', Config: { Labels: { 'com.docker.compose.project': 'sham-56-run' } } },
    unrelated: { Id: 'unrelated', Config: { Labels: {} }, State: { Running: true } }
  }, networks: {} }));
  const work = path.join(agent.dataDir, '.restore-work');
  fs.mkdirSync(work);
  fs.writeFileSync(path.join(work, 'agent-paused'), 'restore');
  const paused = await rawRequest(agent.socketPath, { path: '/v1/restore/quiesce', token: agent.token });
  assert.equal(paused.statusCode, 200, paused.text);
  const stopped = JSON.parse(fs.readFileSync(statePath, 'utf8')).containers;
  assert.equal(stopped.owned.State.Running, false);
  assert.equal(stopped.auxiliary.State.Running, false);
  assert.equal(stopped.unrelated.State.Running, true);
  const body = { name: 'sham-site-56-pause', image: 'node:22', siteId: 56 };
  const blocked = await rawRequest(agent.socketPath, { path: '/v1/containers/run', token: agent.token, body });
  assert.equal(blocked.statusCode, 503);
  fs.unlinkSync(path.join(work, 'agent-paused'));
  const resumed = await rawRequest(agent.socketPath, { path: '/v1/containers/run', token: agent.token, body });
  assert.equal(resumed.statusCode, 200, resumed.text);
});

test('runtime agent: named data volumes cannot attach unmanaged or host-bound volumes', async (t) => {
  const agent = await startAgent();
  t.after(() => agent.stop());
  const statePath = path.join(agent.stateDir, 'sham-fake-docker-state.json');
  fs.writeFileSync(statePath, JSON.stringify({ containers: {}, networks: {}, volumes: {
    'sham-site-57-data': { Name: 'sham-site-57-data', Driver: 'local', Options: { type: 'none', o: 'bind', device: '/' } }
  } }));
  const body = { name: 'sham-site-57-volume', image: 'node:22', siteId: 57 };
  for (const namedVolume of ['unmanaged-volume', 'sham-site-57-data']) {
    const response = await rawRequest(agent.socketPath, { path: '/v1/containers/run', token: agent.token, body: { ...body, namedVolume } });
    assert.equal(response.statusCode, 400, response.text);
  }
  const state = JSON.parse(fs.readFileSync(statePath, 'utf8'));
  assert.deepEqual(state.containers, {});
  state.volumes = {};
  fs.writeFileSync(statePath, JSON.stringify(state));
  const safe = await rawRequest(agent.socketPath, { path: '/v1/containers/run', token: agent.token, body: { ...body, namedVolume: 'sham-site-57-data' } });
  assert.equal(safe.statusCode, 200, safe.text);
});
