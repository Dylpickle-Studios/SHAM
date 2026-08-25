const test = require('node:test');
const assert = require('node:assert/strict');

const { source: projectSource } = require('./source-tree');

test('certificate issuance acquires its operation lock exactly once', () => {
  const source = projectSource('src/server.js');
  const routeStart = source.indexOf("app.post('/api/admin/sites/:id/certificate'");
  const routeEnd = source.indexOf("app.post('/api/admin/certificates/renew'", routeStart);
  assert.ok(routeStart >= 0 && routeEnd > routeStart);
  const route = source.slice(routeStart, routeEnd);
  assert.equal((route.match(/acquireCertificateOperation\(res\)/g) || []).length, 1);
  assert.match(route, /finally\s*\{[\s\S]*releaseCertificateOperation\(\);/);
});

test('dashboard startup imports its configured data path', () => {
  const source = projectSource('src/server.js');
  assert.match(source, /\bDATA_DIR\b/);
  assert.match(source, /SHAM data path: \$\{DATA_DIR\}/);
});


test('static, Node, and reverse-proxy listeners share the configured request timeout', () => {
  const source = projectSource('src/site-manager.js');
  assert.equal((source.match(/server\.requestTimeout = HTTP_REQUEST_TIMEOUT_MS/g) || []).length, 3);
  assert.doesNotMatch(source, /server\.requestTimeout = 30_000/);
});

test('content replacement restores a previously running site', () => {
  const source = projectSource('src/server.js');
  const routeStart = source.indexOf("app.put('/api/sites/:id/content'");
  const routeEnd = source.indexOf("app.get('/api/sites/:id/files'", routeStart);
  assert.ok(routeStart >= 0 && routeEnd > routeStart);
  assert.match(source.slice(routeStart, routeEnd), /if \(wasRunning \|\| site\.enabled\)/);
});


test('Node reverse proxy applies outgoing and incoming request timeouts', () => {
  const source = projectSource('src/site-manager.js');
  assert.match(source, /timeout: HTTP_REQUEST_TIMEOUT_MS/);
  assert.match(source, /proxyTimeout: HTTP_REQUEST_TIMEOUT_MS/);
});

test('site restart compensates when enabled-state persistence fails', () => {
  const source = projectSource('src/server.js');
  const routeStart = source.indexOf("app.post('/api/sites/:id/restart'");
  const routeEnd = source.indexOf("app.post('/api/sites/:id/npm-install'", routeStart);
  assert.ok(routeStart >= 0 && routeEnd > routeStart);
  const route = source.slice(routeStart, routeEnd);
  assert.match(route, /if \(!wasRunning\) await manager\.stop\(site\.id\)/);
  assert.match(route, /could not persist its enabled state/);
});


test('API body parser failures return useful client errors', () => {
  const source = projectSource('src/server.js');
  assert.match(source, /error\?\.type === 'entity\.too\.large'/);
  assert.match(source, /Request body contains invalid JSON/);
  assert.match(source, /if \(res\.headersSent\) return next\(error\)/);
});

test('Cloudflare sync warns about unsupported visitor-facing ports', () => {
  const source = projectSource('src/server.js');
  assert.match(source, /CLOUDFLARE_HTTP_PORTS/);
  assert.match(source, /CLOUDFLARE_HTTPS_PORTS/);
  assert.match(source, /warning: cloudflarePortWarning\(site\)/);
});

test('changing a site domain invalidates the stored Cloudflare synchronization state', () => {
  const source = projectSource('src/server.js');
  const routeStart = source.indexOf("app.put('/api/sites/:id'");
  const routeEnd = source.indexOf("app.patch('/api/sites/:id/toggle'", routeStart);
  assert.ok(routeStart >= 0 && routeEnd > routeStart);
  const route = source.slice(routeStart, routeEnd);
  assert.match(route, /const domainChanged = config\.domain !== site\.domain/);
  assert.match(route, /if \(domainChanged\) config\.cloudflare_enabled = false/);
  assert.match(route, /marked Cloudflare DNS as unsynchronized/);
});

test('site creation INSERT has one value expression per listed column', () => {
  const source = projectSource('src/server.js');
  const routeStart = source.indexOf("app.post('/api/sites'");
  const routeEnd = source.indexOf("app.put('/api/sites/:id'", routeStart);
  assert.ok(routeStart >= 0 && routeEnd > routeStart);
  const route = source.slice(routeStart, routeEnd);
  const insert = route.match(/INSERT INTO sites \(\s*([\s\S]*?)\s*\) VALUES \(\s*([\s\S]*?)\s*\)/);
  assert.ok(insert, 'site creation INSERT statement not found');
  const columns = insert[1].split(',').map((value) => value.trim()).filter(Boolean);
  const values = insert[2].split(',').map((value) => value.trim()).filter(Boolean);
  assert.equal(values.length, columns.length);
});
