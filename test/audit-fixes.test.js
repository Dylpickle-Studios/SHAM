const test = require('node:test');
const assert = require('node:assert/strict');

const { source } = require('./source-tree');

test('runtime helpers are imported from their implementation modules', () => {
  assert.match(source('src/edge-proxy.js'), /require\('\.\/sites\/shared'\)/);
  assert.match(source('src/dependency-scanner.js'), /require\('\.\/sites\/shared'\)/);
  assert.match(source('src/snapshot-manager.js'), /require\('\.\/sites\/shared'\)/);
  assert.match(source('src/sites/core.js'), /require\('\.\.\/config'\)/);
  assert.doesNotMatch(source('src/edge-proxy.js'), /require\('\.\/site-manager'\)/);
  assert.doesNotMatch(source('src/dependency-scanner.js'), /require\('\.\/site-manager'\)/);
  assert.doesNotMatch(source('src/snapshot-manager.js'), /require\('\.\/site-manager'\)/);
  assert.doesNotMatch(source('src/sites/core.js'), /require\('\.\/config'\)/);
});

test('exited runtimes close their gateway and clean the backend before restart', () => {
  const runtime = source('src/sites/runtime.js');
  const section = runtime.slice(runtime.indexOf('  handleBackendExit('), runtime.indexOf('  bindBackendExit(site'));
  assert.match(section, /backend\.active = false/);
  assert.match(section, /const gatewayClosed = closeServer\(runtime\.server\)/);
  assert.match(section, /const backendCleaned = this\.stopBackend\(backend\)/);
  assert.match(section, /cleanup\.then\(\(\) => this\.scheduleRestart\(site, message\)\)/);
});

test('compressed static responses use representation-specific ETags', () => {
  const delivery = source('src/sites/delivery.js');
  assert.match(delivery, /const etag = encoded\.encoding \? `\$\{entry\.etag\.slice\(0, -1\)\}-\$\{encoded\.encoding\}/);
  assert.match(delivery, /precompressedFile\(root, absolute, encoding\)/);
  assert.match(delivery, /realFileInsideAsync\(root, candidate\)/);
});

test('scheduled-job status is escaped before dashboard insertion', () => {
  const operations = source('public/js/operations.js');
  assert.match(operations, /escapeHtml\(job\.last_status \|\| 'never run'\)/);
});

test('OIDC issuer validation rejects ambiguous URLs and supports IPv6 loopback development', () => {
  const { normalizeIssuer, validateEndpoint } = require('../src/oidc');
  assert.equal(normalizeIssuer('http://[::1]/issuer/'), 'http://[::1]/issuer');
  assert.equal(validateEndpoint('http://[::1]:9000/.well-known'), 'http://[::1]:9000/.well-known');
  assert.throws(() => normalizeIssuer('https://user:pass@example.com'), /credentials/);
  assert.throws(() => normalizeIssuer('https://example.com?tenant=one'), /query/);
  assert.throws(() => normalizeIssuer('https://example.com/#fragment'), /fragment/);
});

test('all persisted credential tables participate in secret migration and rotation', () => {
  const secrets = source('src/secret-store.js');
  assert.match(secrets, /SELECT id, connection_value FROM database_profiles/);
  assert.match(secrets, /SELECT site_id, key, value FROM site_env WHERE secret = 1/);
  assert.match(secrets, /SELECT id, config_encrypted FROM alert_destinations/);
  assert.match(secrets, /UPDATE database_profiles SET connection_value/);
  assert.match(secrets, /UPDATE site_env SET value/);
  assert.match(secrets, /UPDATE alert_destinations SET config_encrypted/);
  assert.match(source('src/operations/configuration.js'), /isEncrypted\(existing\.connection_value\)/);
});

test('release retention does not count roots outside the release directory', () => {
  const updates = source('src/update-manager.js');
  assert.match(updates, /const releaseRoots = new Set\(entries\.filter\(\(entry\) => entry\.isDirectory\(\)\)/);
  assert.match(updates, /filter\(\(value\) => releaseRoots\.has\(value\)\)/);
});
