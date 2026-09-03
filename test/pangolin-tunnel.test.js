'use strict';

process.env.SHAM_JWT_SECRET = 'pangolin-tunnel-test-secret-at-least-32-characters';

const test = require('node:test');
const assert = require('node:assert/strict');
const { EventEmitter } = require('node:events');
const { PassThrough } = require('node:stream');
const { PangolinTunnelManager, validateEndpoint } = require('../src/pangolin-tunnel');

class Settings {
  constructor() { this.value = { enabled: false, endpoint: '', newtId: '', secretConfigured: false }; this.savedSecret = ''; }
  status() { return { ...this.value }; }
  secret() { return this.savedSecret; }
  save({ enabled, endpoint, newtId, secret, clearSecret }) {
    if (secret !== undefined) this.savedSecret = secret;
    else if (clearSecret) this.savedSecret = '';
    this.value = { enabled, endpoint, newtId, secretConfigured: Boolean(this.savedSecret) };
  }
}

class Child extends EventEmitter {
  constructor() { super(); this.pid = 42; this.exitCode = null; this.signalCode = null; this.stdout = new PassThrough(); this.stderr = new PassThrough(); }
  exit(code = 0, signal = null) { this.exitCode = code; this.signalCode = signal; this.emit('exit', code, signal); }
}

function harness() {
  const settings = new Settings(); const spawns = []; const children = [];
  const manager = new PangolinTunnelManager({
    settingsStore: settings, command: '/usr/local/bin/newt', availabilityCheck: () => true,
    spawnProcess: (command, args, options) => { const child = new Child(); children.push(child); spawns.push({ command, args, options }); return child; },
    environment: (extra) => ({ PATH: '/usr/local/bin', ...extra }),
    terminateProcess: async (child) => { if (child.exitCode === null) child.exit(0, 'SIGTERM'); }, restartBaseMs: 100
  });
  return { manager, settings, spawns, children };
}

test('Pangolin endpoint validation requires HTTPS except for loopback testing', () => {
  assert.equal(validateEndpoint('https://pangolin.example.com/'), 'https://pangolin.example.com');
  assert.equal(validateEndpoint('http://127.0.0.1:3000'), 'http://127.0.0.1:3000');
  assert.throws(() => validateEndpoint('http://pangolin.example.com'), /HTTPS/);
  assert.throws(() => validateEndpoint('https://user:pass@pangolin.example.com'), /credential-free/);
});

test('Newt credentials are encrypted-store inputs and reach Newt only through its environment', async () => {
  const { manager, spawns, children } = harness();
  await manager.configure({ enabled: true, endpoint: 'https://pangolin.example.com', newtId: 'site-id', secret: 'site-secret' });
  assert.equal(spawns.length, 1);
  assert.deepEqual(spawns[0].args, []);
  assert.equal(spawns[0].options.env.PANGOLIN_ENDPOINT, 'https://pangolin.example.com');
  assert.equal(spawns[0].options.env.NEWT_ID, 'site-id');
  assert.equal(spawns[0].options.env.NEWT_SECRET, 'site-secret');
  assert.doesNotMatch(spawns[0].args.join(' '), /site-secret/);
  children[0].stdout.write('Tunnel connection to server established successfully! site-secret');
  await new Promise((resolve) => setImmediate(resolve));
  assert.equal(manager.status().connected, true);
  assert.doesNotMatch(manager.status().lastLog, /site-secret/);
  await manager.shutdown();
});

test('Pangolin cannot be enabled with incomplete credentials', async () => {
  const { manager } = harness();
  await assert.rejects(manager.configure({ enabled: true, endpoint: 'https://pangolin.example.com', newtId: 'site-id' }), /secret/);
  assert.equal(manager.status().running, false);
  await manager.configure({ enabled: false, endpoint: '', newtId: '', clearSecret: true });
  assert.equal(manager.status().state, 'disabled');
});
