'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const crypto = require('node:crypto');
const { root, source: read } = require('./source-tree');
const { dashboardCertificateHosts } = require('../src/dashboard-tls');
const { verifyRegistration } = require('../src/webauthn');

function cborLength(major, length) {
  if (length < 24) return Buffer.from([(major << 5) | length]);
  if (length <= 0xff) return Buffer.from([(major << 5) | 24, length]);
  if (length <= 0xffff) return Buffer.from([(major << 5) | 25, length >> 8, length & 0xff]);
  throw new Error('test CBOR value too large');
}

function cbor(value) {
  if (Buffer.isBuffer(value)) return Buffer.concat([cborLength(2, value.length), value]);
  if (typeof value === 'string') {
    const bytes = Buffer.from(value);
    return Buffer.concat([cborLength(3, bytes.length), bytes]);
  }
  if (typeof value === 'number') {
    if (value >= 0) return cborLength(0, value);
    return cborLength(1, -1 - value);
  }
  if (value === true) return Buffer.from([0xf5]);
  if (value === false) return Buffer.from([0xf4]);
  if (value instanceof Map) {
    const parts = [cborLength(5, value.size)];
    for (const [key, item] of value) parts.push(cbor(key), cbor(item));
    return Buffer.concat(parts);
  }
  throw new Error(`unsupported test CBOR value: ${typeof value}`);
}

function b64url(value) { return Buffer.from(value).toString('base64url'); }

test('passkey registration accepts authenticator extension data after the credential public key', () => {
  const rpId = 'sham.test';
  const origin = 'https://sham.test';
  const challenge = b64url(Buffer.from('registration-challenge'));
  const credentialId = Buffer.from('credential-id');
  const cose = new Map([
    [1, 2],
    [3, -7],
    [-1, 1],
    [-2, Buffer.alloc(32, 1)],
    [-3, Buffer.alloc(32, 2)]
  ]);
  const extensions = new Map([['credProps', new Map([['rk', true]])]]);
  const authData = Buffer.concat([
    crypto.createHash('sha256').update(rpId).digest(),
    Buffer.from([0xc5]), // UP + UV + AT + ED
    Buffer.alloc(4),
    Buffer.alloc(16),
    Buffer.from([credentialId.length >> 8, credentialId.length & 0xff]),
    credentialId,
    cbor(cose),
    cbor(extensions)
  ]);
  const attestationObject = cbor(new Map([
    ['fmt', 'none'],
    ['authData', authData]
  ]));
  const clientDataJSON = Buffer.from(JSON.stringify({ type: 'webauthn.create', challenge, origin }));

  const result = verifyRegistration({
    response: {
      type: 'public-key',
      response: {
        clientDataJSON: b64url(clientDataJSON),
        attestationObject: b64url(attestationObject),
        transports: ['internal']
      }
    },
    challenge,
    rpId,
    origins: [origin]
  });

  assert.equal(result.credentialId, b64url(credentialId));
  assert.equal(result.publicKeyJwk.alg, 'ES256');
  assert.deepEqual(result.transports, ['internal']);
});

test('local dashboard certificate host discovery includes LAN addresses and explicit bind names', () => {
  const interfaces = {
    lo: [{ address: '127.0.0.1', internal: true }],
    eth0: [{ address: '192.168.50.12', internal: false }],
    wlan0: [{ address: 'fe80::1234%wlan0', internal: false }]
  };
  const wildcard = dashboardCertificateHosts('0.0.0.0', interfaces);
  assert.ok(wildcard.dns.includes('localhost'));
  assert.ok(wildcard.ips.includes('192.168.50.12'));
  assert.ok(wildcard.ips.includes('fe80::1234'));
  const named = dashboardCertificateHosts('sham.local', {});
  assert.ok(named.dns.includes('sham.local'));
});

test('direct HTTPS configuration and secure-context passkey guidance are wired through the dashboard', () => {
  const config = read('src/config.js');
  const server = read('src/server.js');
  const app = read('public/app.js');
  const env = read('.env.example');
  assert.match(config, /SHAM_SELF_SIGNED_HTTPS/);
  assert.match(config, /SHAM_OPENSSL_BIN/);
  assert.match(server, /dashboardTlsOptions/);
  assert.match(server, /https\.createServer/);
  assert.match(app, /window\.isSecureContext/);
  assert.match(app, /SHAM_SELF_SIGNED_HTTPS/);
  assert.match(env, /SHAM_SELF_SIGNED_HTTPS=false/);
});

test('password request dialogs are hardened for password-manager recognition', () => {
  const app = read('public/app.js');
  assert.match(app, /passwordInput = inputType === 'password'/);
  assert.match(app, /\/password\/i\.test\(inputLabel\)/);
  assert.match(app, /actionInput\.type = passwordInput \? 'password' : inputType/);
  assert.match(app, /actionInput\.name = passwordInput \? 'password'/);
  assert.match(app, /actionInput\.autocomplete = passwordInput && autocomplete === 'off' \? 'current-password'/);
});

test('site creation hides unsupported Docker, buildpack, Nixpacks, Git, and Anubis choices', () => {
  const html = read('public/index.html');
  const app = read('public/app.js');
  const operations = read('src/operations-manager.js');
  for (const capability of ['docker', 'git', 'buildpacks', 'nixpacks', 'anubis']) {
    assert.match(html, new RegExp(`data-requires-capability="${capability}"`));
  }
  assert.match(app, /function applyRuntimeCapabilities\(\)/);
  assert.match(app, /const roleAllowed = !element\.classList\.contains\('admin-only'\) \|\| state\.user\?\.role === 'admin'/);
  assert.match(app, /element\.hidden = !available/);
  assert.match(app, /element\.disabled = !available/);
  assert.match(operations, /capabilities\(\)/);
  assert.match(operations, /buildpacks: docker && Boolean\(agentStatus\.buildpacksAvailable\)/);
  assert.match(operations, /nixpacks: docker && Boolean\(agentStatus\.nixpacksAvailable\)/);
});

test('documentation and license live in the sidebar and license opens in a modal', () => {
  const html = read('public/index.html');
  const app = read('public/app.js');
  const css = read('public/styles.css');
  assert.match(html, /class="nav-item" data-section="documentation"/);
  assert.match(html, /id="license-button" class="nav-item"/);
  assert.match(html, /id="license-dialog"/);
  assert.doesNotMatch(html, /id="help-button"/);
  assert.doesNotMatch(html, /class="icon-button license-link"/);
  assert.match(app, /async function openLicenseDialog\(\)/);
  assert.match(app, /fetch\('\/LICENSE'/);
  assert.match(css, /\.sidebar-logout \{[\s\S]*grid-column: 1 \/ -1; width: 100%/);
  assert.match(css, /\.license-content/);
});

test('Docker documentation defaults to the published GHCR image', () => {
  const image = 'ghcr.io/dylpickle-studios/sham:latest';
  for (const file of ['README.md', 'docs/getting-started.md', 'docs/troubleshooting.md', 'docker-compose.yml']) {
    const body = fs.readFileSync(path.join(root, file), 'utf8');
    assert.match(body, new RegExp(image.replaceAll('.', '\\.')));
  }
  assert.doesNotMatch(read('docker-compose.yml'), /SHAM_IMAGE:-sham:1\.0\.0/);
  assert.doesNotMatch(read('README.md'), /docker build -t sham/);
  assert.doesNotMatch(read('docs/getting-started.md'), /docker compose up -d --build/);
});


test('requested dashboard UI fixes stay wired to dedicated themed surfaces', () => {
  const html = read('public/index.html');
  const app = read('public/app.js');
  const css = read('public/styles.css');
  assert.match(html, /id="command-button" class="nav-item"/);
  assert.match(html, /id="operations-tab-appearance"/);
  assert.match(html, /id="operations-appearance"/);
  assert.doesNotMatch(html, /id="theme-dialog"/);
  assert.doesNotMatch(html, /data-site-template="proxy"/);
  assert.match(html, /id="performance-rule-dialog"/);
  assert.match(html, /id="performance-alert-rules" class="performance-rule-list"/);
  assert.match(app, /templatePicker\?\.classList\.toggle\('is-disabled', proxySelected\)/);
  assert.match(app, /button\.disabled = proxySelected/);
  assert.match(app, /const currentSource = \$\('#site-source'\)\.value \|\| 'upload'/);
  assert.doesNotMatch(app, /const source = preset\.source === 'git'/);
  assert.match(css, /\.license-modal \.license-content/);
  assert.match(css, /#environment-form[\s\S]*margin-bottom: 1rem/);
  assert.match(css, /\.git-provider-row \{[\s\S]*180px/);
  assert.match(css, /\.performance-rule-card/);
  assert.match(css, /\.performance-chart \.chart-lane/);
});

test('passkey relying-party id is derived from the same canonical origin as the challenge', () => {
  const server = read('src/server.js');
  assert.match(server, /function requestRpId\(req\) \{[\s\S]*new URL\(requestOrigin\(req\)\)\.hostname/);
  assert.doesNotMatch(server, /function requestRpId\(req\) \{[\s\S]{0,160}req\.hostname/);
});

test('password credential fields expose password-manager semantics', () => {
  const html = read('public/index.html');
  const app = read('public/app.js');
  assert.match(html, /id="auth-username" name="username" autocomplete="username"/);
  assert.match(html, /id="auth-password" name="password" type="password" autocomplete="current-password"/);
  assert.match(html, /id="action-username"[^>]*name="username"[^>]*autocomplete="username"/);
  assert.match(app, /actionInput\.type = passwordInput \? 'password' : inputType/);
  assert.match(app, /actionInput\.autocomplete = passwordInput && autocomplete === 'off' \? 'current-password' : autocomplete/);
  assert.match(app, /actionInput\.name = passwordInput \? 'password' : 'action-input'/);
  assert.match(app, /Confirm passkey enrollment[\s\S]*inputType: 'password'[\s\S]*autocomplete: 'current-password'/);
});
