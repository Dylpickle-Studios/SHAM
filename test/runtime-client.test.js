'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { spawn } = require('node:child_process');
const { RuntimeClient } = require('../src/runtime/client');
const { RuntimeAgentUnavailableError, RuntimeAgentError } = require('../src/runtime/errors');

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
  // Keep this fake CLI executable even when the checkout mechanism strips
  // tracked executable bits (for example, an extracted source archive).
  fs.chmodSync(FAKE_DOCKER, 0o755);
  const dataDir = fs.mkdtempSync(path.join(os.tmpdir(), 'sham-client-data-'));
  const stateDir = fs.mkdtempSync(path.join(os.tmpdir(), 'sham-client-tmp-'));
  const socketPath = path.join(dataDir, 'agent.sock');
  const child = spawn(process.execPath, [path.join(ROOT, 'runtime-agent', 'index.js')], {
    cwd: ROOT,
    env: { ...process.env, SHAM_DATA_PATH: dataDir, SHAM_DOCKER_BIN: FAKE_DOCKER, SHAM_RUNTIME_AGENT_SOCKET: socketPath, TMPDIR: stateDir, TMP: stateDir, TEMP: stateDir },
    stdio: ['ignore', 'pipe', 'pipe']
  });
  await waitFor(() => fs.existsSync(socketPath));
  const tokenPath = path.join(dataDir, 'runtime-agent', 'agent.token');
  await waitFor(() => fs.existsSync(tokenPath));
  return {
    socketPath, tokenPath, dataDir,
    client: new RuntimeClient({ socketPath, tokenPath, requestTimeoutMs: 5000 }),
    async stop() {
      child.kill('SIGTERM');
      await new Promise((resolve) => child.once('exit', resolve));
      fs.rmSync(dataDir, { recursive: true, force: true });
      fs.rmSync(stateDir, { recursive: true, force: true });
    }
  };
}

test('RuntimeClient: reports unavailable, not a crash, when the agent is unreachable', async () => {
  const client = new RuntimeClient({ socketPath: '/tmp/does-not-exist-sham-agent.sock', tokenPath: '/tmp/does-not-exist-sham-agent.token' });
  // status() intentionally never throws — it degrades into a cached "unreachable" snapshot.
  const status = await client.status();
  assert.equal(status.agentReachable, false);
  assert.equal(status.dockerAvailable, false);
  assert.equal(client.getCachedStatus().agentReachable, false);

  await assert.rejects(() => client.runContainer({ name: 'sham-site-1-a', image: 'node:22', siteId: 1 }), (error) => {
    assert.ok(error instanceof RuntimeAgentUnavailableError);
    assert.match(error.message, /Docker runtime unavailable/);
    return true;
  });
});

test('RuntimeClient: full lifecycle through the real client against a real (fake-Docker-backed) agent', async (t) => {
  const agent = await startAgent();
  t.after(() => agent.stop());

  const status = await agent.client.status();
  assert.equal(status.agentReachable, true);
  assert.equal(status.agentAuthenticated, true);
  assert.equal(status.dockerAvailable, true);

  const name = 'sham-site-7-run';
  const { containerId } = await agent.client.runContainer({ name, image: 'node:22', siteId: 7, env: { PORT: '4000' } });
  assert.ok(containerId);

  const port = await agent.client.containerPort({ name, containerPort: 4000 });
  assert.equal(port, 34567);

  const lines = [];
  const logHandle = await agent.client.streamContainerLogs({ name, onLine: (level, line) => lines.push([level, line]) });
  await new Promise((resolve) => setTimeout(resolve, 200));
  logHandle.stop();
  assert.ok(lines.some(([, line]) => line.includes('log line')));

  await agent.client.stopContainer({ name, timeoutSec: 1 });
  await agent.client.removeContainer({ name });
});

test('RuntimeClient: agent-side errors surface as typed RuntimeAgentError with the original code, not a generic crash', async (t) => {
  const agent = await startAgent();
  t.after(() => agent.stop());

  await assert.rejects(() => agent.client.containerPort({ name: 'sham-site-1-missing', containerPort: 3000 }), (error) => {
    assert.ok(error instanceof RuntimeAgentError);
    assert.equal(error.code, 'NOT_FOUND');
    return true;
  });

  await assert.rejects(() => agent.client.removeImage({ tag: 'ubuntu:latest' }), (error) => {
    assert.equal(error.code, 'INVALID_REQUEST');
    return true;
  });
});

test('RuntimeClient: build streaming forwards log lines and resolves the built tag', async (t) => {
  const agent = await startAgent();
  t.after(() => agent.stop());

  const lines = [];
  const result = await agent.client.buildImage({
    tag: 'sham/site-7:build1', contextPath: agent.dataDir, mode: 'dockerfile', dockerfilePath: agent.dataDir,
    onLine: (level, line) => lines.push([level, line])
  });
  assert.equal(result.tag, 'sham/site-7:build1');
  assert.ok(lines.length > 0);
});
