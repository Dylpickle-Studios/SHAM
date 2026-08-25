const test = require('node:test');
const assert = require('node:assert/strict');

const { source: read } = require('./source-tree');

function routeLines(server) {
  return server.split('\n').filter((line) => /app\.(?:get|post|put|patch|delete|all)\('\/?/.test(line));
}

function routePaths(server) {
  return [...server.matchAll(/app\.(?:get|post|put|patch|delete|all)\(['"]([^'"]+)/g)].map((match) => match[1]);
}

function pathMatches(client, route) {
  const left = client.replace(/\?.*$/, '').replace(/^\/+|\/+$/g, '').split('/');
  const right = route.replace(/^\/+|\/+$/g, '').split('/');
  return left.length === right.length && left.every((part, index) => part.startsWith(':') || right[index].startsWith(':') || part === right[index]);
}

test('every operational API route is authenticated and every admin API is administrator-only', () => {
  const server = read('src/server.js');
  const publicApi = [
    '/api/health', '/api/bootstrap', '/api/public/status',
    '/api/auth/register', '/api/auth/login', '/api/auth/login/totp',
    '/api/auth/login/passkey/options', '/api/auth/login/passkey/verify', '/api/auth/logout',
    '/api/hooks/deploy/:id'
  ];
  const lines = routeLines(server).filter((line) => line.includes("'/api/"));
  assert.ok(lines.length >= 90, `expected broad route coverage, found ${lines.length}`);
  for (const line of lines) {
    const route = line.match(/app\.(?:get|post|put|patch|delete|all)\('([^']+)'/)?.[1];
    if (!route || publicApi.includes(route)) continue;
    assert.match(line, /requireAuth/, `route lacks authentication: ${line.trim()}`);
    if (route.startsWith('/api/admin/')) assert.match(line, /requireAdmin/, `admin route lacks role enforcement: ${line.trim()}`);
  }
  assert.match(server, /app\.use\('\/api\/sites\/:id', requireAuth, serializeSiteMutation\)/);
  assert.match(server, /app\.use\('\/api\/admin\/sites\/:id', requireAuth, requireAdmin, serializeSiteMutation\)/);
  assert.match(server, /app\.use\('\/api\/admin\/plugins', requireAuth, requireAdmin, serializePluginMutation\)/);
});

test('public status and deployment webhooks expose only intentionally public information', () => {
  const server = read('src/server.js');
  const publicStatus = server.slice(server.indexOf('function publicStatusSnapshot'), server.indexOf("app.get('/metrics'"));
  const publicApi = server.slice(server.indexOf("app.get('/api/public/status'"), server.indexOf("app.get('/status'"));
  const publicPage = server.slice(server.indexOf("app.get('/status'"), server.indexOf("app.get('/metrics'"));
  assert.match(publicStatus, /SELECT id, name FROM sites/);
  assert.match(publicApi, /publicStatusSnapshot\(\)/);
  assert.match(publicPage, /publicStatusSnapshot\(\)/);
  assert.doesNotMatch(publicStatus, /site\.domain|SELECT[^\n]*domain/);
  const webhook = server.slice(server.indexOf('function authenticateDeployWebhook'), server.indexOf("app.get('/api/sites/:id/operations'"));
  assert.match(webhook, /DEPLOY_WEBHOOK_DUMMY_SECRET/);
  assert.match(webhook, /Webhook authentication failed/);
  assert.match(webhook, /webhookLimiter, authenticateDeployWebhook, serializeSiteMutation/);
  assert.doesNotMatch(webhook, /Site not found|not configured/);
  assert.match(webhook, /Webhook deployment failed\. Review the authenticated runtime logs/);
  assert.doesNotMatch(webhook, /res\.status\(400\)\.json\(\{ error: error\.message \}\)/);
});

test('API serializers do not return encrypted credentials or stored secret values', () => {
  const operations = read('src/operations-manager.js');
  const server = read('src/server.js');
  assert.match(operations, /value: row\.secret \? '' : row\.value/);
  assert.match(operations, /SELECT id, name, type, env_key AS envKey, updated_at AS updatedAt FROM database_profiles/);
  assert.match(operations, /SELECT id, name, kind, enabled, updated_at AS updatedAt FROM alert_destinations/);
  assert.match(operations, /const sensitive = new Set\(\['password', 'accessKey', 'secretKey', 'sessionToken', 'privateKey', 'passphrase'\]\)/);
  const exported = server.slice(server.indexOf("app.get('/api/sites/:id/config/export'"), server.indexOf("app.post('/api/sites/:id/config/import'"));
  assert.match(exported, /value: item\.secret \? null : operationsManager\.siteEnvironment/);
  assert.doesNotMatch(exported, /connection_value|config_encrypted|DEPLOY_WEBHOOK_SECRET/);
});

test('SQLite access is hardened, indexed, parameterized, and protected on disk', () => {
  const database = read('src/db.js');
  const operations = read('src/operations-manager.js');
  const config = read('src/config.js');
  assert.match(database, /journal_mode = WAL/);
  assert.match(database, /foreign_keys = ON/);
  assert.match(database, /busy_timeout = 5000/);
  assert.match(database, /idx_site_visitor_stats_recent_global/);
  assert.match(database, /idx_site_visitor_stats_ip/);
  assert.match(database, /chmodSync\(filename, 0o600\)/);
  assert.match(operations, /key NOT IN \(\$\{keep\.map\(\(\) => '\?'\)\.join\(','\)\}\)/);
  assert.match(operations, /\.run\(siteId, \.\.\.keep\)/);
  assert.match(config, /\[CERTBOT_DIR, SNAPSHOTS_DIR, BACKUPS_DIR, UPDATES_DIR, APP_RUNTIME_DIR, SITE_DATA_DIR, TMP_ROOT_DIR\]/);
  assert.match(config, /chmodSync\(directory, 0o700\)/);
});

test('backups, snapshots, uploads, and temporary credentials remain owner-only', () => {
  const operations = read('src/operations-manager.js');
  const snapshot = read('src/snapshot-worker.js');
  const upload = read('src/upload-storage.js');
  assert.match(operations, /writeFile\(localPath, '', \{ flag: 'wx', mode: 0o600 \}\)/);
  assert.match(operations, /chmod\(localPath, 0o600\)/);
  assert.match(operations, /chmod\(target, 0o600\)/);
  assert.match(operations, /rm\(localPath, \{ force: true \}\)/);
  assert.match(snapshot, /zip\.toBuffer\(\), \{ flag: 'wx', mode: 0o600 \}/);
  assert.match(upload, /createWriteStream\(temporaryPath, \{ flags: 'wx', mode: 0o600 \}\)/);
  assert.match(operations, /writeFile\(keyPath, .*\{ mode: 0o600 \}\)/);
});

test('outbound integrations reject redirects before sending credentials or telemetry', () => {
  const operations = read('src/operations-manager.js');
  const integrations = read('src/integrations.js');
  const alert = operations.slice(operations.indexOf('async sendAlert'), operations.indexOf('async testAlertDestination'));
  const otel = operations.slice(operations.indexOf('async exportTelemetry'), operations.indexOf('async tick()'));
  assert.match(alert, /redirect: 'error'/);
  assert.match(otel, /redirect: 'error'/);
  assert.match(integrations, /redirect: 'error'/);
  assert.match(alert, /AbortSignal\.timeout\(15_000\)/);
  assert.match(otel, /AbortSignal\.timeout\(15_000\)/);
});

test('Git deployment metadata cannot contain embedded credentials or local file paths', () => {
  const operations = read('src/operations-manager.js');
  const validator = operations.slice(operations.indexOf('function validateGitUrl'), operations.indexOf('function validateBranch'));
  assert.match(validator, /Local file:\/\/ repositories are not allowed/);
  assert.match(validator, /Git credentials must not be embedded/);
  assert.match(validator, /parsed\.password/);
  assert.doesNotMatch(validator, /file:\\\/\\\//);
  assert.match(validator, /^function validateGitUrl[\s\S]*\^git@/);
});

test('all static UI references are reachable and ARIA relationships resolve', () => {
  const html = read('public/index.html');
  const app = read('public/app.js');
  const ids = [...(html + app).matchAll(/\bid=["']([^"']+)/g)].map((match) => match[1]);
  const htmlIds = [...html.matchAll(/\bid="([^"]+)"/g)].map((match) => match[1]);
  assert.equal(new Set(htmlIds).size, htmlIds.length, 'duplicate HTML IDs detected');
  const known = new Set(ids);
  for (const match of app.matchAll(/\$\(['"]#([A-Za-z0-9_-]+)['"]\)/g)) assert.ok(known.has(match[1]), `unreachable UI selector #${match[1]}`);
  for (const match of html.matchAll(/\bfor="([^"]+)"/g)) assert.ok(known.has(match[1]), `label targets missing ID ${match[1]}`);
  for (const attribute of ['aria-controls', 'aria-labelledby', 'aria-describedby']) {
    for (const match of html.matchAll(new RegExp(`${attribute}="([^"]+)"`, 'g'))) {
      for (const id of match[1].split(/\s+/)) assert.ok(known.has(id), `${attribute} targets missing ID ${id}`);
    }
  }
  const nav = new Set([...html.matchAll(/class="nav-item[^"\n]*"[^>]*data-section="([^"]+)"/g)].map((match) => match[1]));
  const panels = new Set([...html.matchAll(/id="section-([^"]+)"/g)].map((match) => match[1]));
  for (const section of nav) assert.ok(panels.has(section), `nav section ${section} has no panel`);
  for (const section of ['admin', 'documentation', 'performance', 'site-workspace']) {
    assert.ok(panels.has(section), `programmatic section ${section} is missing`);
  }
});

test('dashboard themes, panels, overlays, and responsive controls share coherent layout rules', () => {
  const html = read('public/index.html');
  const css = read('public/styles.css');
  const combined = `${html}\n${css}`;
  const used = new Set([...combined.matchAll(/var\(--([A-Za-z0-9_-]+)/g)].map((match) => match[1]));
  const defined = new Set([...combined.matchAll(/--([A-Za-z0-9_-]+)\s*:/g)].map((match) => match[1]));
  assert.deepEqual([...used].filter((name) => !defined.has(name)), []);
  assert.doesNotMatch(html, /\sstyle=/);
  assert.match(css, /\.site-action-menu[\s\S]*max-width: min\(320px, calc\(100vw - 20px\)\)/);
  assert.match(css, /\.modal-card[\s\S]*overflow: auto[\s\S]*max-height: 92dvh/);
  assert.match(css, /\.toast-region[\s\S]*max-width: min\(360px, calc\(100vw - 2rem\)\)/);
  assert.match(css, /\.inline-actions \{ display: flex; flex-wrap: wrap/);
  assert.match(css, /\.operations-tabs \{ overflow-x: auto; flex-wrap: nowrap/);
  assert.ok((html.match(/data-tooltip=/g) || []).length >= 18, 'consequential controls lack sufficient contextual help');
});

test('every literal client API call maps to a server route', () => {
  const app = read('public/app.js');
  const routes = routePaths(read('src/server.js'));
  const clients = [...app.matchAll(/\bapi\(\s*([`'"])(.*?)\1/gs)]
    .map((match) => match[2])
    .filter((value) => value.startsWith('/api/'))
    .map((value) => value.replace(/\?.*$/, '').replace(/\$\{[^}]+\}/g, ':param'));
  assert.ok(new Set(clients).size >= 65, 'feature endpoint inventory unexpectedly shrank');
  for (const client of clients) assert.ok(routes.some((route) => pathMatches(client, route)), `client endpoint has no server route: ${client}`);
});
