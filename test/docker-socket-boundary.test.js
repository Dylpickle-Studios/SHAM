'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const { source: read } = require('./source-tree');

test('the main SHAM control-plane service never mounts the Docker socket', () => {
  const base = read('docker-compose.yml');
  const overlay = read('docker-compose.isolation.yml');
  assert.doesNotMatch(base, /docker\.sock/);

  const shamService = overlay.slice(overlay.indexOf('  sham:'), overlay.indexOf('  sham-runtime-agent:'));
  assert.doesNotMatch(shamService, /docker\.sock/);
  assert.doesNotMatch(shamService, /group_add/);

  const agentService = overlay.slice(overlay.indexOf('  sham-runtime-agent:'), overlay.indexOf('\nnetworks:\n'));
  assert.match(agentService, /\/var\/run\/docker\.sock:\/var\/run\/docker\.sock/);
  assert.match(agentService, /command: \["node", "runtime-agent\/index\.js"\]/);
});

test('the runtime agent container does not bind to a public port or the default network', () => {
  const overlay = read('docker-compose.isolation.yml');
  const agentService = overlay.slice(overlay.indexOf('  sham-runtime-agent:'), overlay.indexOf('\nnetworks:\n'));
  assert.doesNotMatch(agentService, /ports:/);
  assert.doesNotMatch(agentService, /0\.0\.0\.0/);
  assert.match(agentService, /network_mode: "none"/);
});

test('the runtime agent server binds a Unix socket, not a TCP host/port', () => {
  const server = read('runtime-agent/index.js');
  assert.match(server, /server\.listen\(socketPath/);
  assert.doesNotMatch(server, /\.listen\(\s*\d/);
  assert.doesNotMatch(server, /0\.0\.0\.0/);
});

test('the runtime agent exposes only allowlisted operations, never a generic command/exec passthrough', () => {
  const protocol = read('src/runtime/protocol.js');
  const server = read('runtime-agent/server.js');
  assert.doesNotMatch(protocol, /\/v1\/docker['"]/);
  assert.doesNotMatch(protocol, /\/v1\/exec['"]/);
  assert.doesNotMatch(server, /req\.body\.command\)/);
  for (const op of ['IMAGES_BUILD', 'CONTAINERS_RUN', 'CONTAINERS_STOP', 'CONTAINERS_REMOVE', 'COMPOSE_UP', 'COMPOSE_DOWN', 'NETWORKS_ENSURE']) {
    assert.match(protocol, new RegExp(op));
  }
});

test('Docker CLI invocations only occur inside the privileged runtime agent', () => {
  const disallowed = [
    'src/sites/runtime.js', 'src/sites/shared.js', 'src/operations/deployments.js',
    'src/operations/configuration.js', 'src/operations/observability.js', 'src/performance-monitor.js', 'src/runtime-engine.js'
  ];
  for (const file of disallowed) {
    const source = read(file);
    assert.doesNotMatch(source, /spawn\(DOCKER_BIN/, `${file} must not spawn Docker directly`);
    assert.doesNotMatch(source, /execFile(Async)?\(DOCKER_BIN/, `${file} must not exec Docker directly`);
  }
  const agent = read('runtime-agent/docker.js');
  assert.match(agent, /spawn\(bin, args/);
});
