'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const { root, source } = require('./source-tree');

const read = (name) => fs.readFileSync(path.join(root, name), 'utf8');

test('site mutation serialization advances the middleware chain exactly once', () => {
  const server = read('src/server.js');
  const start = server.indexOf('async function serializeSiteMutation');
  const end = server.indexOf('\nfunction publicUser', start);
  const body = server.slice(start, end);
  assert.equal((body.match(/\bnext\(\)/g) || []).length, 3, 'expected the two early returns and one final next() only');
  assert.match(server, /app\.use\('\/api\/admin\/sites\/:id', requireAuth, requireAdmin, serializeSiteMutation\)/);
});

test('fresh database migrations create runtime log and release tables before altering or indexing them', () => {
  const db = read('src/db.js');
  const runtimeCreate = db.indexOf('CREATE TABLE IF NOT EXISTS runtime_logs');
  const runtimeEnsure = db.indexOf("ensureColumn('runtime_logs', 'deployment_id'");
  const runtimeIndex = db.indexOf('idx_runtime_logs_deployment');
  const releaseCreate = db.indexOf('CREATE TABLE IF NOT EXISTS site_releases');
  const releaseEnsure = db.indexOf("ensureColumn('site_releases', 'deployment_id'");
  assert.ok(runtimeCreate >= 0 && runtimeCreate < runtimeEnsure && runtimeEnsure < runtimeIndex);
  assert.ok(releaseCreate >= 0 && releaseCreate < releaseEnsure);
});

test('nested site resources are site scoped and step-up password checks are throttled', () => {
  const operations = read('src/routes/operations.js');
  const configuration = read('src/operations/configuration.js');
  const deployments = read('src/operations/deployments.js');
  const server = read('src/server.js');
  const admin = read('src/routes/admin.js');
  assert.match(configuration, /runJob\(jobId, trigger = 'manual', expectedSiteId = null\)/);
  assert.match(configuration, /WHERE id = \? AND site_id = \?/);
  assert.match(deployments, /deletePreview\(id, expectedSiteId = null\)/);
  assert.match(operations, /runJob\(Number\(req\.params\.jobId\), 'manual', site\.id\)/);
  assert.match(operations, /deletePreview\(Number\(req\.params\.previewId\), site\.id\)/);
  assert.match(server, /const stepUpLimiter = createRateLimiter/);
  for (const route of ['totp/setup', 'totp/disable', 'recovery-codes/regenerate', 'passkeys/options']) {
    assert.match(server, new RegExp(`app\\.post\\('/api/security/${route.replace('/', '\\/')}'.*stepUpLimiter`));
  }
  assert.match(server, /app\.delete\('\/api\/security\/passkeys\/:id', requireAuth, stepUpLimiter/);
  assert.match(operations, /environment\/:key\/reveal', requireAuth, requireAdmin, stepUpLimiter/);
  assert.match(admin, /rotate-master-key', requireAuth, requireAdmin, stepUpLimiter/);
});

test('successful deployments and rollbacks report metadata bookkeeping failures as warnings', () => {
  const deployments = read('src/operations/deployments.js');
  const sites = read('src/routes/sites.js');
  const operations = read('src/routes/operations.js');
  assert.match(deployments, /Release activated, but SHAM could not finalize all deployment metadata/);
  assert.match(deployments, /Release rollback is active, but SHAM could not finalize deployment history/);
  assert.match(deployments, /status IN \('running', 'deployed-with-warning'\)/);
  assert.match(sites, /Content is deployed, but SHAM could not record deployment history/);
  assert.match(operations, /warning: Boolean\(result\.warning\)/);
});

test('firewall changes hot-apply and WebSocket requests use the same access policy as HTTP', () => {
  const sites = source('src/site-manager.js');
  const routes = read('src/routes/sites.js');
  assert.match(sites, /refreshLiveFirewall\(siteId\)/);
  assert.match(sites, /runtime\.site\.firewall_enabled/);
  assert.match(routes, /firewall\/ban-ip[\s\S]*manager\.refreshLiveFirewall\(site\.id\)/);
  assert.match(sites, /guardWebSocket\(site, req, socket\)/);
  assert.match(sites, /const access = this\.checkAccess\(site, req\)/);
  assert.equal((sites.match(/if \(!this\.guardWebSocket\(site, req, socket\)\) return;/g) || []).length, 2);
});

test('edge routing keeps integrations across HTTP pauses and bounds hot-path caches', () => {
  const edge = read('src/edge-proxy.js');
  const pauseStart = edge.indexOf('async pauseHttp()');
  const pauseEnd = edge.indexOf('\n  async start()', pauseStart);
  assert.doesNotMatch(edge.slice(pauseStart, pauseEnd), /this\.operations = null/);
  assert.match(edge, /this\.siteCache = new Map\(\)/);
  assert.match(edge, /this\.tlsContextCache = new Map\(\)/);
  assert.match(edge, /if \(this\.siteCache\.size > 1024\)/);
  assert.match(edge, /if \(this\.tlsContextCache\.size > 256\)/);
  assert.match(edge, /invalidateSiteCache\(\) \{ this\.siteCache\.clear\(\); this\.tlsDomainCache\.clear\(\); this\.ambiguousDomains\.clear\(\); \}/);
  assert.match(edge, /for \(const socket of server\._shamSockets \|\| \[\]\) socket\.destroy\(\)/);
});

test('cron parsing is done once per next-run scan and accepts 7 as Sunday', () => {
  const shared = read('src/operations/shared.js');
  const nextStart = shared.indexOf('function nextCronDate');
  const nextEnd = shared.indexOf('\nfunction safeName', nextStart);
  const next = shared.slice(nextStart, nextEnd);
  assert.match(next, /const schedule = parseCron\(expression\)/);
  assert.doesNotMatch(next, /cronMatches\(expression, candidate\)/);
  assert.match(shared, /const weekdays = parseField\(parts\[4\], 0, 7\)/);
  assert.match(shared, /if \(weekdays\.delete\(7\)\) weekdays\.add\(0\)/);
});

test('dashboard tab sets use consistent ARIA relationships and roving tab stops', () => {
  const html = read('public/index.html');
  const app = source('public/app.js');
  const activeTabs = [...html.matchAll(/<button[^>]+role="tab"[^>]+aria-selected="true"[^>]*>/g)];
  assert.ok(activeTabs.length >= 4);
  for (const [tag] of activeTabs) assert.match(tag, /tabindex="0"/);
  for (const match of html.matchAll(/aria-controls="([^"]+)"/g)) assert.match(html, new RegExp(`id="${match[1]}"`));
  assert.match(app, /button\.tabIndex = active \? 0 : -1/);
  assert.match(app, /ArrowRight|ArrowLeft/);
});

test('restart recovery closes transient operations and restores warning deployments as active', () => {
  const configuration = read('src/operations/configuration.js');
  const core = read('src/sites/core.js');
  assert.match(configuration, /this\.recoverInterruptedRuns\(\)/);
  assert.match(configuration, /status IN \('queued', 'building'\).*finished_at IS NULL/s);
  assert.match(configuration, /UPDATE job_runs[\s\S]*status = 'failed'[\s\S]*WHERE status = 'running' AND finished_at IS NULL/);
  assert.match(configuration, /UPDATE backup_runs[\s\S]*status = 'failed'[\s\S]*WHERE status = 'running' AND finished_at IS NULL/);
  assert.match(core, /site_deployments WHERE status IN \('running', 'deployed-with-warning'\) ORDER BY id/);
});

test('operations subprocesses are tracked and terminated during shutdown', () => {
  const shared = read('src/operations/shared.js');
  const configuration = read('src/operations/configuration.js');
  const deployments = read('src/operations/deployments.js');
  const observability = read('src/operations/observability.js');
  assert.match(shared, /onSpawn = \(\) => \{\}/);
  assert.match(shared, /onSpawn\(child\)/);
  assert.match(configuration, /this\.operationProcesses = new Set\(\)/);
  assert.match(configuration, /trackedProcessOptions\(options = \{\}\)/);
  assert.match(configuration, /runProcess\(TAR_BIN,[\s\S]*this\.trackedProcessOptions/);
  assert.match(deployments, /runProcess\(GIT_BIN,[\s\S]*this\.trackedProcessOptions/);
  assert.match(observability, /this\.operationProcesses[\s\S]*terminateAndWait\(child, 2000\)/);
});

test('firewall compilation avoids serializing ban lists on every request', () => {
  const core = read('src/sites/core.js');
  const start = core.indexOf('compiledFirewall(site)');
  const end = core.indexOf('\n  matchingRedirect', start);
  const body = core.slice(start, end);
  assert.match(body, /cached\?\.source === source/);
  assert.doesNotMatch(body, /JSON\.stringify/);
});

test('visitor intelligence keeps crawler classes distinct and privacy masking handles compressed IPv6', () => {
  const db = read('src/db.js');
  const core = read('src/sites/core.js');
  const routes = read('src/routes/sites.js');
  const dashboard = read('public/js/dashboard.js');
  const { maskIp, classifyClient } = require('../src/visitor-intelligence');
  assert.equal(maskIp('192.0.2.123'), '192.0.2.0/24');
  assert.equal(maskIp('2001:db8::1234'), '2001:db8::/48');
  assert.equal(maskIp('2001:db8:abcd:1::1'), '2001:db8:abcd::/48');
  assert.equal(classifyClient('GPTBot/1.0').type, 'llm');
  assert.equal(classifyClient('python-requests/2.31').type, 'crawler');
  assert.match(db, /PRIMARY KEY \(site_id, ip, country, client_type\)/);
  assert.match(db, /site_visitor_stats_legacy/);
  assert.match(core, /ON CONFLICT\(site_id, ip, country, client_type\)/);
  assert.match(core, /\['llm', 'search', 'crawler'\]\.includes\(identity\.clientType\)/);
  assert.match(routes, /actionable: net\.isIP/);
  assert.match(dashboard, /const actionable = Boolean\(visitor\.actionable\)/);
});

test('visitor retention is global and privacy setting changes update the live cache immediately', () => {
  const core = read('src/sites/core.js');
  const admin = read('src/routes/admin.js');
  const server = read('src/server.js');
  assert.match(core, /pruneExpiredVisitorStats/);
  assert.match(core, /DELETE FROM site_visitor_stats WHERE last_request_at < datetime\('now', \?\)/);
  assert.match(core, /pruneVisitorHistory\(\)[\s\S]*this\.pruneExpiredVisitorStats\.run\(retention\)/);
  assert.match(core, /setPrivacyMode\(mode\)/);
  assert.match(admin, /manager\.setPrivacyMode\(privacy\)/);
  assert.match(server, /visitorPrivacyMode: getSetting\('visitor_privacy_mode', 'none'\)/);
});

test('proxy failures do not append synthetic error pages after response headers are sent', () => {
  const runtime = read('src/sites/runtime.js');
  const edge = read('src/edge-proxy.js');
  assert.equal((runtime.match(/if \(responseOrSocket\.headersSent\) return responseOrSocket\.destroy\?\.\(error\);/g) || []).length, 2);
  assert.match(edge, /if \(target\.headersSent\) return target\.destroy\?\.\(\)/);
  assert.match(runtime, /Reverse proxy target points back to this site listener/);
});

test('alert delivery retries failed destinations without redelivering successful destinations', () => {
  const observability = read('src/operations/observability.js');
  const operationsUi = read('public/js/operations.js');
  const html = read('public/index.html');
  assert.match(observability, /this\.deliveredAlerts\.get\(`\$\{row\.id\}:\$\{alert\.fingerprint\}`\)/);
  assert.match(observability, /this\.deliveredAlerts\.set\(`\$\{row\.id\}:\$\{alert\.fingerprint\}`, stamp\)/);
  assert.match(observability, /validateAlertDestinationConfig\(kind, input\)/);
  assert.match(observability, /invalid or unsafe HTTP header/);
  assert.match(operationsUi, /alert-destination-form/);
  assert.doesNotMatch(operationsUi, /JSON configuration/);
  assert.match(html, /id="alert-destination-dialog"/);
  assert.match(html, /id="alert-header-rows"/);
});

test('edge proxy prepares hot-path statements once and bounds TLS hostname caching', () => {
  const edge = read('src/edge-proxy.js');
  assert.match(edge, /this\.findEdgeSites = db\.prepare/);
  assert.match(edge, /this\.findTlsSites = db\.prepare/);
  assert.match(edge, /this\.findDefaultTlsDomain = db\.prepare/);
  assert.match(edge, /this\.tlsDomainCache = new Map\(\)/);
  assert.match(edge, /if \(this\.tlsDomainCache\.size > 512\)/);
});

test('OpenTelemetry settings reject credential-bearing endpoints and unsafe headers', () => {
  const routes = read('src/routes/operations.js');
  const observability = read('src/operations/observability.js');
  assert.match(routes, /parsedEndpoint\.username \|\| parsedEndpoint\.password \|\| parsedEndpoint\.search \|\| parsedEndpoint\.hash/);
  assert.match(routes, /OpenTelemetry contains an invalid or unsafe header/);
  assert.match(observability, /OpenTelemetry endpoint is unsafe/);
  assert.equal((observability.match(/response\.body\?\.cancel\(\)\.catch/g) || []).length, 2);
});

test('extracted route modules receive every declared dependency from server wiring', () => {
  const server = read('src/server.js');
  const specs = [
    ['src/routes/sites.js', 'registerSiteRoutes', 'routeContext'],
    ['src/routes/admin.js', 'registerAdminRoutes', 'adminRouteContext'],
    ['src/routes/operations.js', 'registerOperationsRoutes', 'operationsRouteContext']
  ];

  for (const [file, registerName, contextName] of specs) {
    const routeSource = read(file);
    const registerStart = routeSource.indexOf(`function ${registerName}`);
    assert.ok(registerStart >= 0, `${registerName} is missing`);
    const destructure = routeSource.slice(registerStart).match(/const\s*\{([\s\S]*?)\}\s*=\s*ctx;/);
    assert.ok(destructure, `${registerName} must destructure its route context`);
    const required = destructure[1].split(',').map((value) => value.trim()).filter(Boolean);

    const context = server.match(new RegExp(`const ${contextName} = \\{([\\s\\S]*?)\\n\\};`));
    assert.ok(context, `${contextName} is missing`);
    const provided = context[1]
      .split(',')
      .map((value) => value.trim())
      .filter(Boolean)
      .map((value) => value.includes(':') ? value.split(':')[0].trim() : value);

    assert.deepEqual(required.filter((name) => !provided.includes(name)), [], `${contextName} is missing route dependencies`);
  }

  const sites = read('src/routes/sites.js');
  assert.match(sites, /edgeProxy, getSetting, siteRows, getSiteOr404/);
  assert.match(server, /rotateMasterKey, verifyPassword, hashPassword, rotateSessionVersion, stepUpLimiter, writeCloudflareCredentials/);
});

test('bootstrap prints startup stacks so Docker smoke failures identify the bad route', () => {
  assert.match(read('src/bootstrap.js'), /console\.error\(error\.stack \|\| error\.message\)/);
});
