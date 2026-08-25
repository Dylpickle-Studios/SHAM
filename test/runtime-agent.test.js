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

  await t.test('unexpected extra fields (e.g. attempting to smuggle a privileged flag) are ignored, not honored', async () => {
    const res = await rawRequest(agent.socketPath, {
      path: '/v1/containers/run',
      token: agent.token,
      body: { name: 'sham-site-1-run', image: 'node:22', siteId: 1, privileged: true, capAdd: ['SYS_ADMIN'], networkMode: 'host' }
    });
    assert.equal(res.statusCode, 200);
    assert.ok(res.json.containerId);
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
