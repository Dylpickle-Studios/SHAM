const test = require('node:test');
const assert = require('node:assert/strict');

const { source: read } = require('./source-tree');

function routeSource(server, start, end) {
  const from = server.indexOf(start);
  const to = server.indexOf(end, from + start.length);
  assert.notEqual(from, -1, `Missing route marker: ${start}`);
  assert.notEqual(to, -1, `Missing route marker: ${end}`);
  return server.slice(from, to);
}

test('public status page uses the shared theme without violating CSP', () => {
  const server = read('src/server.js');
  const route = routeSource(server, "app.get('/status'", "app.get('/metrics'");
  const css = read('public/styles.css');
  assert.match(route, /class="status-document"/);
  assert.match(route, /src="\/theme-init\.js"/);
  assert.match(route, /href="\/styles\.css"/);
  assert.match(route, /Cache-Control', 'no-store'/);
  assert.doesNotMatch(route, /<style>/);
  assert.match(css, /html\.status-document/);
  assert.match(css, /body\.status-page/);
  assert.match(css, /\.status-indicator\.online, \.status-indicator\.healthy/);
});

test('Prometheus metrics fail closed unless a token is configured', () => {
  const server = read('src/server.js');
  const route = routeSource(server, "app.get('/metrics'", "app.post('/api/auth/register'");
  assert.match(route, /if \(!expected\) return res\.status\(503\)/);
  assert.match(route, /WWW-Authenticate/);
  assert.match(route, /suppliedBuffer\.length !== expectedBuffer\.length/);
  assert.match(route, /crypto\.timingSafeEqual\(suppliedBuffer, expectedBuffer\)/);
});

test('operations settings validate first and save atomically', () => {
  const server = read('src/server.js');
  const route = routeSource(server, "app.put('/api/admin/operations/settings'", "app.post('/api/admin/backups/run'");
  const tokenValidation = route.indexOf('if (prometheusEnabled && !nextPrometheusToken)');
  const transaction = route.indexOf('db.transaction(() =>');
  assert.ok(tokenValidation >= 0 && tokenValidation < transaction);
  assert.match(route, /OpenTelemetry headers must be a JSON object/);
  assert.match(route, /Locale must be English, Dutch, or German/);
  assert.match(route, /Update channel is invalid/);
  assert.match(route, /db\.transaction\(\(\) => \{[\s\S]*operationsManager\.saveBackupSettings[\s\S]*setSecretSetting/);
});

test('observability and site tools expose coherent accessible controls', () => {
  const html = read('public/index.html');
  const app = read('public/app.js');
  assert.match(html, /id="prometheus-token-status"/);
  assert.match(html, /id="clear-prometheus-token"/);
  assert.match(html, /id="otel-headers-status"/);
  assert.match(html, /id="clear-otel-headers"/);
  assert.match(html, /role="tab" aria-selected="true" aria-controls="site-tools-snapshots"/);
  assert.match(html, /role="tabpanel" aria-labelledby="site-tools-tab-dependencies"/);
  assert.match(app, /button\.setAttribute\('aria-selected', String\(active\)\)/);
  assert.match(app, /\['ArrowLeft', 'ArrowRight', 'Home', 'End'\]/);
});

test('stale client responses cannot overwrite newer admin or site-tool state', () => {
  const app = read('public/app.js');
  const adminStart = app.indexOf('async function loadAdmin()');
  const adminEnd = app.indexOf('function renderUsers', adminStart);
  const admin = app.slice(adminStart, adminEnd);
  assert.ok(admin.indexOf('if (requestId !== state.adminRequest) return;') < admin.indexOf('renderUsers(users.users)'));
  assert.match(app, /function siteToolsRequestIsCurrent/);
  assert.match(app, /state\.siteToolsRequest \+= 1;[\s\S]*toolsSite = null/);
  assert.match(app, /siteToolsRequestIsCurrent\(site, sessionId\)/);
  assert.match(app, /requestId === state\.siteToolsSnapshotRequest/);
  assert.match(app, /requestId !== state\.siteToolsDependencyRequest/);
});

test('plugin refreshes are serialized and action rows remain responsive', () => {
  const app = read('public/app.js');
  const css = read('public/styles.css');
  assert.match(app, /let pluginLoadPromise = null/);
  assert.match(app, /while \(pluginLoadPending && state\.user\)/);
  assert.match(app, /pluginScriptReloadPending \|\|= reloadScripts/);
  assert.match(app, /event-item actionable/);
  assert.match(css, /\.event-item\.actionable \{ grid-template-columns: auto minmax\(0, 1fr\) auto; \}/);
  assert.match(css, /\.event-item\.actionable > \.button, \.event-item\.actionable > \.inline-actions \{ grid-column: 2; grid-row: 2/);
});

test('ZIP dependency and upload diagnostics cover the reported failure modes', () => {
  const pkg = JSON.parse(read('package.json'));
  const upload = read('src/upload-utils.js');
  const app = read('public/app.js');
  assert.equal(pkg.dependencies['adm-zip'], '0.6.0');
  assert.match(upload, /server-side temporary file disappeared before processing/);
  assert.match(upload, /valid, non-encrypted ZIP file/);
  assert.match(app, /function validatedArchive/);
  assert.match(app, /folderContainsEntry/);
});

test('high-impact settings include theme-aware accessible help', () => {
  const html = read('public/index.html');
  const css = read('public/styles.css');
  assert.match(html, /class="help-tip" tabindex="0" role="note"/);
  assert.match(html, /class="upload-guidance"/);
  assert.match(css, /\.help-tip::after/);
  assert.match(css, /\.help-tip:focus-visible/);
  assert.match(css, /background: var\(--panel-solid\)/);
});
