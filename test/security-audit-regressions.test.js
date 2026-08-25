const test = require('node:test');
const assert = require('node:assert/strict');

const { source: read } = require('./source-tree');

test('compressed response cache counts variants and deduplicates first-hit work', () => {
  const source = read('src/site-manager.js');
  assert.match(source, /function cacheEntryBytes\(entry\)[\s\S]*entry\?\.encoded/);
  assert.match(source, /entry\.cacheBytes = cacheEntryBytes\(entry\)/);
  assert.match(source, /entry\.encodedPending\[encoding\]/);
  assert.match(source, /this\.minifyCacheBytes \+= entry\.cacheBytes - previousBytes/);
  assert.match(source, /this\.trimMinifyCache\(key\)/);
});

test('static compression and transformations have independent bounded queues', () => {
  const source = read('src/site-manager.js');
  const config = read('src/config.js');
  const env = read('.env.example');
  const performance = read('src/performance-monitor.js');
  assert.match(source, /runCompression\(work\)[\s\S]*COMPRESSION_QUEUE_LIMIT/);
  assert.match(source, /runMinifier\(task\)[\s\S]*MINIFY_QUEUE_LIMIT/);
  assert.match(source, /Static compression stopped during shutdown/);
  assert.match(config, /SHAM_COMPRESSION_WORKERS/);
  assert.match(config, /SHAM_COMPRESSION_QUEUE_LIMIT/);
  assert.match(env, /SHAM_COMPRESSION_WORKERS=4/);
  assert.match(performance, /compressions:/);
});

test('health checks distinguish client configuration problems from restart-worthy failures', () => {
  const source = read('src/site-manager.js');
  assert.match(source, /ok: statusCode >= 200 && statusCode < 400/);
  assert.match(source, /degraded: statusCode >= 400 && statusCode < 500/);
  assert.match(source, /!result\.degraded && current\.failures === 3/);
});

test('edge listeners receive the same timeout and malformed-client hardening', () => {
  const source = read('src/edge-proxy.js');
  assert.match(source, /function hardenServer\(server\)/);
  assert.match(source, /server\.requestTimeout = HTTP_REQUEST_TIMEOUT_MS/);
  assert.match(source, /server\.headersTimeout/);
  assert.match(source, /server\.keepAliveTimeout/);
  assert.match(source, /server\.on\('clientError'/);
  assert.equal((source.match(/hardenServer\(https\.createServer/g) || []).length, 2);
});

test('MFA enrollment requires password step-up and password prompts preserve whitespace', () => {
  const server = read('src/server.js');
  const app = read('public/app.js');
  const totpStart = server.indexOf("app.post('/api/security/totp/setup'");
  const totpEnd = server.indexOf("app.post('/api/security/totp/enable'", totpStart);
  const passkeyStart = server.indexOf("app.post('/api/security/passkeys/options'");
  const passkeyEnd = server.indexOf("app.post('/api/security/passkeys/register'", passkeyStart);
  assert.match(server.slice(totpStart, totpEnd), /await verifyPassword/);
  assert.match(server.slice(passkeyStart, passkeyEnd), /await verifyPassword/);
  assert.match(app, /Set up TOTP[\s\S]*inputType: 'password'/);
  assert.match(app, /Confirm passkey enrollment[\s\S]*inputType: 'password'/);
  assert.match(app, /actionInput\.type === 'password' \? actionInput\.value : actionInput\.value\.trim\(\)/);
});

test('precompressed sidecars support validators and safe stream failures', () => {
  const source = read('src/site-manager.js');
  assert.match(source, /const etag = `W\/"\$\{Math\.floor\(sidecar\.stat\.mtimeMs\)/);
  assert.match(source, /res\.setHeader\('ETag', etag\)/);
  assert.match(source, /if \(req\.fresh\) \{ res\.status\(304\)\.end\(\)/);
  assert.match(source, /createReadStream\(sidecar\.path\)\.on\('error'/);
});

test('dependency fingerprints and site deletion avoid synchronous request-path disk work', () => {
  const manager = read('src/site-manager.js');
  const server = read('src/server.js');
  assert.match(manager, /async dependencyFingerprint\(root\)/);
  assert.match(manager, /await fs\.promises\.readFile\(absolute\)/);
  assert.match(manager, /async dependenciesAreCurrent\(root\)/);
  const deletionStart = server.indexOf("app.delete('/api/sites/:id'");
  const deletionEnd = server.indexOf("app.get('/api/sites/:id/dependency-scan'", deletionStart);
  const deletion = server.slice(deletionStart, deletionEnd);
  assert.match(deletion, /await fs\.promises\.rename\(root, trash\)/);
  assert.doesNotMatch(deletion, /renameSync|existsSync/);
});

test('performance polling does not overlap and theme surfaces use semantic tokens', () => {
  const app = read('public/app.js');
  const css = read('public/styles.css');
  assert.match(app, /let performanceRequest = null/);
  assert.match(app, /if \(performanceRequest && !force\) return performanceRequest/);
  assert.match(app, /performanceController\?\.abort\(\)/);
  assert.match(css, /--surface-hover:/);
  assert.match(css, /--overlay-backdrop:/);
  assert.match(css, /--card-shadow:/);
  assert.match(css, /\.subgrid[\s\S]*background: var\(--surface-subtle\)/);
  assert.match(css, /\.file-item:hover \{ background: var\(--surface-hover\)/);
  assert.match(css, /\.modal::backdrop \{ background: var\(--overlay-backdrop\)/);
});

test('runtime log batching survives circular context and deleted site foreign keys', () => {
  const manager = read('src/site-manager.js');
  const server = read('src/server.js');
  assert.match(manager, /try \{ contextJson = JSON\.stringify\(context\); \}/);
  assert.match(manager, /serializationError: error\.message/);
  assert.match(manager, /SQLITE_CONSTRAINT_FOREIGNKEY/);
  assert.match(manager, /this\.writeRuntimeLog\.run\(null, row\.level/);
  assert.match(manager, /for \(const row of this\.pendingRuntimeLogs\).*row\.siteId = null/);
  const deletion = server.slice(server.indexOf("app.delete('/api/sites/:id'"), server.indexOf("app.get('/api/sites/:id/dependency-scan'"));
  assert.match(deletion, /manager\.flushRuntimeLogs\(\)/);
  assert.match(deletion, /manager\.log\(null, 'error', `Could not remove deleted site data/);
});

test('shutdown waits for active static compression work', () => {
  const manager = read('src/site-manager.js');
  assert.match(manager, /this\.compressionOperations = new Set\(\)/);
  assert.match(manager, /this\.compressionOperations\.add\(operation\)/);
  assert.match(manager, /this\.compressionOperations\.delete\(operation\)/);
  assert.match(manager, /await Promise\.allSettled\(\[\.\.\.this\.compressionOperations\]\)/);
});

test('plugin archive hashing and signature verification stay off the dashboard thread', () => {
  const manager = read('src/plugin-manager.js');
  const worker = read('src/plugin-archive-worker.js');
  assert.match(manager, /workerData: \{ source, destination: staging, trustedKeys \}/);
  assert.match(manager, /validatePreparedPlugin\(staging, message\)/);
  assert.match(worker, /verifyPluginSignature/);
  assert.match(worker, /rawManifest/);
  assert.match(worker, /parentPort\.postMessage\(\{ ok: true, rawManifest, signature \}\)/);
});

test('dialog overlays and card shadows remain coherent in light and custom themes', () => {
  const css = read('public/styles.css');
  const theme = read('public/theme-init.js');
  assert.match(css, /--overlay-backdrop: rgba\(3, 1, 8, 0\.72\)/);
  assert.match(css, /html\[data-mode="light"\][\s\S]*--overlay-backdrop: rgba\(36, 23, 51, 0\.48\)/);
  assert.match(css, /html\[data-mode="light"\][\s\S]*--card-shadow: 0 14px 38px rgba\(54, 31, 77, 0\.12\)/);
  assert.match(theme, /'--overlay-backdrop': light \? alpha\(text, 0\.46\) : 'rgba\(0, 0, 0, 0\.72\)'/);
  assert.match(theme, /'--card-shadow': `0 14px 38px/);
});

test('health monitoring deduplicates cycles, awaits shutdown, and reports rejected checks', () => {
  const manager = read('src/site-manager.js');
  assert.match(manager, /if \(this\.healthCheckPromise\) return this\.healthCheckPromise/);
  assert.match(manager, /const failures = results\.filter\(\(result\) => result\.status === 'rejected'\)/);
  assert.match(manager, /Health monitor could not check/);
  assert.match(manager, /await this\.healthCheckPromise\?\.catch/);
});

test('runtime log batches are bounded and cannot reschedule after shutdown begins', () => {
  const manager = read('src/site-manager.js');
  assert.match(manager, /if \(this\.runtimeLogStopping \|\| this\.runtimeLogFlushImmediate\) return/);
  assert.match(manager, /const bounded = Math\.min\(Math\.max\(Number\(maxRows\) \|\| 500, 1\), 10_000\)/);
  assert.match(manager, /if \(this\.pendingRuntimeLogs\.length > 10_000\)/);
  assert.match(manager, /this\.runtimeLogStopping = true/);
});

test('snapshot recovery and asynchronous plugin lifecycle avoid synchronous request-path tree work', () => {
  const snapshots = read('src/snapshot-manager.js');
  const plugins = read('src/plugin-manager.js');
  const restore = snapshots.slice(snapshots.indexOf('  async restore('), snapshots.indexOf('  async delete(', snapshots.indexOf('  async restore(')));
  const installAsync = plugins.slice(plugins.indexOf('  async installAsync('), plugins.indexOf('  async toggle(', plugins.indexOf('  async installAsync(')));
  const deletion = plugins.slice(plugins.indexOf('  async delete('), plugins.indexOf('  clientScript(', plugins.indexOf('  async delete(')));
  assert.match(restore, /await pathExistsAsync\(backup\)/);
  assert.doesNotMatch(restore, /existsSync/);
  assert.match(installAsync, /await fs\.promises\.mkdir/);
  assert.match(installAsync, /commitPreparedPluginAsync/);
  assert.doesNotMatch(installAsync, /rmSync|mkdirSync|renameSync/);
  assert.match(deletion, /await fs\.promises\.rename\(root, trash\)/);
  assert.match(deletion, /fs\.promises\.rm/);
  assert.doesNotMatch(deletion, /existsSync|renameSync|rmSync/);
});

test('switches and plugin file inputs cannot widen mobile dialogs or pages', () => {
  const css = read('public/styles.css');
  assert.match(css, /\.switch-row input \{[\s\S]*width: 1px;[\s\S]*clip-path: inset\(50%\)/);
  assert.match(css, /\.upload-box \{[\s\S]*min-width: 0;[\s\S]*overflow: hidden/);
  assert.match(css, /\.upload-box input\[type="file"\] \{[\s\S]*max-width: 100%/);
  assert.match(css, /@media \(max-width: 620px\)[\s\S]*\.checkbox-line \{[\s\S]*display: grid/);
});

test('performance sampling bounds per-site process reads and avoids one query per running site', () => {
  const monitor = read('src/performance-monitor.js');
  const config = read('src/config.js');
  const env = read('.env.example');
  assert.match(monitor, /async function mapWithConcurrency/);
  assert.match(monitor, /mapWithConcurrency\(running, PERFORMANCE_SITE_CONCURRENCY/);
  assert.match(monitor, /this\.readSiteMetadata\.all\(\)/);
  assert.doesNotMatch(monitor.slice(monitor.indexOf('async sampleSites'), monitor.indexOf('async sample()', monitor.indexOf('async sampleSites'))), /manager\.getSite/);
  assert.match(config, /SHAM_PERFORMANCE_SITE_CONCURRENCY/);
  assert.match(env, /SHAM_PERFORMANCE_SITE_CONCURRENCY=8/);
});

test('plugin client scripts are loaded asynchronously and cached', () => {
  const manager = read('src/plugin-manager.js');
  const server = read('src/server.js');
  const client = manager.slice(manager.indexOf('  async clientScript('), manager.indexOf('  async handleApi('));
  assert.match(client, /await fs\.promises\.stat\(clientPath\)/);
  assert.match(client, /await fs\.promises\.readFile\(clientPath, 'utf8'\)/);
  assert.doesNotMatch(client, /readFileSync|statSync/);
  assert.match(server, /send\(await pluginManager\.clientScript\(req\.params\.id\)\)/);
});

test('plugin shutdown rejects new work and waits for active installs and actions', () => {
  const manager = read('src/plugin-manager.js');
  assert.match(manager, /this\.installOperations = new Set\(\)/);
  assert.match(manager, /this\.activeActions = new Map\(\)/);
  assert.match(manager, /if \(this\.stopping\) throw new Error\('Plugin manager is shutting down\.'/);
  assert.match(manager, /this\.installOperations\.add\(operation\)/);
  assert.match(manager, /this\.activeActions\.set\(rawOperation, pluginId\)/);
  assert.match(manager, /await Promise\.allSettled\(\[\.\.\.this\.installOperations\]\)/);
  assert.match(manager, /Promise\.allSettled\(\[\.\.\.this\.activeActions\.keys\(\)\]\)/);
});

test('in-process plugin actions retain lifecycle tracking after response timeouts', () => {
  const manager = read('src/plugin-manager.js');
  const handle = manager.slice(manager.indexOf('  async handleApi('), manager.indexOf('  async shutdown()', manager.indexOf('  async handleApi(')));
  const unload = manager.slice(manager.indexOf('  async unload('), manager.indexOf('  list()', manager.indexOf('  async unload(')));
  assert.match(handle, /if \(this\.activeActions\.size >= PLUGIN_MAX_PENDING_ACTIONS\)/);
  assert.match(handle, /rawOperation = Promise\.resolve\(\)\.then/);
  assert.match(handle, /responseOperation = withTimeout\([\s\S]*rawOperation/);
  assert.match(handle, /this\.activeActions\.set\(rawOperation, pluginId\)/);
  assert.match(unload, /Promise\.allSettled\(actions\)/);
});

test('password verification rejects oversized values before invoking scrypt', () => {
  const security = read('src/security.js');
  const start = security.indexOf('async function verifyPassword');
  const end = security.indexOf('\n}', start) + 2;
  const body = security.slice(start, end);
  assert.match(body, /typeof password !== 'string' \|\| password\.length > 200/);
  assert.ok(body.indexOf('password.length > 200') < body.indexOf('await scrypt'));
});

test('authentication challenges can only be consumed by their matching user and purpose', () => {
  const server = read('src/server.js');
  const start = server.indexOf('function consumeChallenge');
  const end = server.indexOf('\n}', start) + 2;
  const body = server.slice(start, end);
  assert.match(body, /DELETE FROM webauthn_challenges WHERE id = \? AND user_id = \? AND purpose = \?/);
});
