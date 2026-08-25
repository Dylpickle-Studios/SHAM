'use strict';

process.env.SHAM_JWT_SECRET = 'next-additions-test-secret-at-least-32-characters';

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const { providerCommitUrl } = require('../src/git-providers');
const { validateProxyHostHeader } = require('../src/validation');

const root = path.resolve(__dirname, '..');
const read = (file) => fs.readFileSync(path.join(root, file), 'utf8');

test('deployment provider links point to GitHub and GitLab commits', () => {
  assert.equal(
    providerCommitUrl('https://github.com/acme/example.git', '0123456789abcdef'),
    'https://github.com/acme/example/commit/0123456789abcdef'
  );
  assert.equal(
    providerCommitUrl('https://gitlab.com/acme/platform/example.git', 'abcdef0123456789'),
    'https://gitlab.com/acme/platform/example/-/commit/abcdef0123456789'
  );
  assert.equal(providerCommitUrl('https://example.com/acme/example.git', '0123456789abcdef'), '');
  assert.equal(providerCommitUrl('https://github.com/acme/example.git', 'not-a-sha'), '');
});

test('reverse proxy host overrides are normalized and reject request smuggling input', () => {
  assert.equal(validateProxyHostHeader('origin.internal'), 'origin.internal');
  assert.equal(validateProxyHostHeader('origin.internal:8443'), 'origin.internal:8443');
  assert.equal(validateProxyHostHeader(''), '');
  assert.throws(() => validateProxyHostHeader('origin.internal/path'), /Proxy host-header override is invalid/);
  assert.throws(() => validateProxyHostHeader('origin.internal\r\nX-Test: injected'), /Proxy host-header override is invalid/);
});

test('deployment lifecycle, attached logs, active release restoration, and secret reveal are wired', () => {
  const db = read('src/db.js');
  const core = read('src/sites/core.js');
  const deployments = read('src/operations/deployments.js');
  const operationsRoutes = read('src/routes/operations.js');
  assert.match(db, /ensureColumn\('runtime_logs', 'deployment_id', 'INTEGER'\)/);
  assert.match(db, /idx_runtime_logs_deployment/);
  assert.match(core, /site_deployments WHERE status IN \('running', 'deployed-with-warning'\)/);
  assert.match(core, /deploymentId/);
  for (const status of ['queued', 'building', 'running', 'failed', 'rolled-back', 'superseded']) assert.match(deployments, new RegExp(`['"]${status}['"]`));
  assert.match(deployments, /deploymentLogs\(siteId, deploymentId/);
  assert.match(deployments, /providerCommitUrl/);
  assert.match(operationsRoutes, /environment\/:key\/reveal/);
  assert.match(operationsRoutes, /verifyPassword/);
  assert.match(operationsRoutes, /Cache-Control', 'no-store/);
});

test('Hugo, site pinning, and reverse proxy controls are exposed through the product UI', () => {
  const html = read('public/index.html');
  const sites = read('public/js/sites.js');
  const workspace = read('public/js/site-workspace.js');
  const routes = read('src/routes/sites.js');
  const runtime = read('src/sites/runtime.js');
  assert.match(html, /data-site-template="hugo"/);
  assert.match(sites, /build: 'hugo --minify'/);
  assert.match(sites, /data-action="pin"/);
  assert.match(routes, /\/api\/sites\/:id\/pin/);
  assert.match(runtime, /proxy_host_header/);
  assert.match(runtime, /proxy_timeout_ms/);
  assert.match(workspace, /selectWorkspaceTab\('logs', \{ load: false \}\)/);
});
