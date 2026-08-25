const test = require('node:test');
const assert = require('node:assert/strict');

const { source } = require('./source-tree');

test('site mutations are serialized and large file routes use async helpers', () => {
  const server = source('src/server.js');
  assert.match(server, /serializeSiteMutation/);
  assert.match(server, /app\.use\('\/api\/sites\/:id', requireAuth, serializeSiteMutation\)/);
  assert.match(server, /app\.use\('\/api\/admin\/sites\/:id', requireAuth, requireAdmin, serializeSiteMutation\)/);
  for (const helper of ['listSiteFilesAsync', 'readTextFileAsync', 'writeTextFileAsync', 'replaceSingleFileFromPathAsync', 'deleteSingleFileAsync', 'stageSingleFileDeletionAsync']) {
    assert.match(server, new RegExp(`\\b${helper}\\b`));
  }
});

test('cross-origin writes are rejected before request bodies are parsed', () => {
  const server = source('src/server.js');
  assert.ok(server.indexOf('app.use(sameOriginGuard)') < server.indexOf('app.use(express.json'));
});

test('Cloudflare identity headers do not trust private networks by default', () => {
  const manager = source('src/site-manager.js');
  const rangeBlock = manager.slice(manager.indexOf('const TRUSTED_EDGE_RANGES'), manager.indexOf('const trustedEdgePeers'));
  for (const range of ['10.0.0.0/8', '172.16.0.0/12', '192.168.0.0/16', '127.0.0.0/8', 'fc00::/7']) {
    assert.doesNotMatch(rangeBlock, new RegExp(range.replaceAll('.', '\\.').replace('/', '\\/')));
  }
  assert.match(rangeBlock, /\.\.\.TRUSTED_EDGE_PROXIES/);
  assert.match(source('src/config.js'), /SHAM_TRUSTED_EDGE_PROXIES/);
});

test('obfuscation preserves script globals and transformed ETags use content hashes', () => {
  const manager = source('src/site-manager.js');
  const worker = source('src/minify-worker.js');
  assert.match(worker, /minifyJS: obfuscate[\s\S]*javascriptOptions/);
  assert.match(worker, /toplevel: false/);
  assert.match(worker, /keep_fnames: Boolean\(obfuscate\)/);
  assert.match(worker, /keep_classnames: Boolean\(obfuscate\)/);
  assert.doesNotMatch(worker, /toplevel: extension === '\.mjs'/);
  assert.match(manager, /createHash\('sha256'\)\.update\(data\)/);
  assert.doesNotMatch(manager, /etag: `W\//);
});

test('rate-limit maps and visitor analytics have bounded retention', () => {
  const manager = source('src/site-manager.js');
  const security = source('src/security.js');
  const database = source('src/db.js');
  assert.match(manager, /FIREWALL_RATE_LIMIT_BUCKETS/);
  assert.match(security, /AUTH_RATE_LIMIT_BUCKETS/);
  assert.match(manager, /VISITOR_RETENTION_DAYS/);
  assert.match(database, /site_id, last_request_at DESC/);
});

test('theme and interaction regressions are guarded in the dashboard', () => {
  const app = source('public/app.js');
  const theme = source('public/theme-init.js');
  const css = source('public/styles.css');
  const html = source('public/index.html');
  assert.match(app, /MAX_BROWSER_UPLOAD_FILES = 2000/);
  assert.match(app, /fileListRequest/);
  assert.match(app, /fileContentRequest/);
  assert.match(app, /siteMenuTrigger[\s\S]*handleSiteAction\(site, button\.dataset\.action, trigger \|\| button\)/);
  assert.match(app, /ArrowLeft[\s\S]*ArrowRight[\s\S]*Home[\s\S]*End/);
  assert.match(theme, /validateCustom/);
  assert.match(theme, /contrastRatio/);
  assert.match(css, /input:focus-visible \+ \.switch/);
  assert.match(css, /--danger-text/);
  assert.match(html, /id="theme-form-error"/);
  assert.doesNotMatch(html, /id="drop-zone"[^>]*tabindex/);
  assert.doesNotMatch(html, /aggressive variable mangling/);
});


test('declarative plugins cannot bypass secrets or runtime lifecycle handling', () => {
  const manager = source('src/plugin-manager.js');
  assert.match(manager, /DECLARATIVE_PRIVATE_TABLES/);
  assert.match(manager, /DECLARATIVE_LIFECYCLE_TABLES/);
  assert.match(manager, /DECLARATIVE_DANGEROUS_FUNCTIONS/);
  assert.match(manager, /pragma_/);
});

test('certificate renewal only interrupts port 80 for standalone renewals', () => {
  const integrations = source('src/integrations.js');
  const server = source('src/server.js');
  assert.match(integrations, /function renewalNeedsPort80/);
  assert.match(integrations, /authenticator\s*\\s\*=\\s\*standalone/);
  assert.match(server, /if \(renewalNeedsPort80\(\)\)/);
});

test('dashboard refresh and file errors ignore stale responses', () => {
  const app = source('public/app.js');
  assert.match(app, /siteListRequest: 0/);
  assert.match(app, /requestId !== state\.siteListRequest/);
  assert.match(app, /requestId === state\.fileListRequest/);
  assert.match(app, /requestId === state\.fileContentRequest/);
  assert.match(app, /Object\.hasOwn\(button\.dataset, 'originalLabel'\)/);
  assert.match(app, /function refreshSiteActionMenuPosition/);
  assert.doesNotMatch(app, /workspace'\)\.addEventListener\('scroll', \(\) => closeSiteActionMenu/);
});

test('trusted edge proxy configuration is validated and documented', () => {
  const config = source('src/config.js');
  const env = source('.env.example');
  const readme = source('README.md');
  assert.match(config, /function cidrListEnv/);
  assert.match(config, /net\.isIP/);
  assert.match(env, /SHAM_TRUSTED_EDGE_PROXIES=/);
  assert.match(readme, /SHAM_TRUSTED_EDGE_PROXIES/);
});


test('a Node process that exits during startup is cleaned up after runtime registration', () => {
  const manager = source('src/site-manager.js');
  const start = manager.slice(manager.indexOf('async _start(site)'), manager.indexOf('async stop(id)'));
  const setIndex = start.indexOf('this.running.set(site.id, runtime)');
  const exitIndex = start.indexOf('if (runtime.exited');
  assert.ok(setIndex >= 0 && exitIndex > setIndex);
  assert.match(start.slice(exitIndex), /runtime\.proxy\?\.close\(\)/);
  assert.match(start.slice(exitIndex), /await closeServer\(runtime\.server\)/);
});


test('plugin archive extraction runs outside the dashboard event loop and client code is cached', () => {
  const manager = source('src/plugin-manager.js');
  const server = source('src/server.js');
  assert.match(manager, /installAsync\(source(?:,\s*\{[^)]*\}\s*=\s*\{\})?\)/);
  assert.match(manager, /new Worker\(path\.join\(__dirname, 'plugin-archive-worker\.js'\)/);
  assert.match(server, /await pluginManager\.installAsync\(req\.file\.path(?:,|\))/);
  assert.match(manager, /clientSource: null/);
  assert.match(manager, /active\.clientSource =/);
});


test('same-origin validation canonicalizes default ports and rejects malformed origins', () => {
  const security = source('src/security.js');
  assert.match(security, /new URL\(origin\)\.origin/);
  assert.match(security, /new URL\(`\$\{req\.protocol\}:\/\/\$\{req\.get\('host'\)\}`\)\.origin/);
  assert.match(security, /catch \{[\s\S]*Origin validation failed/);
});

test('shutdown terminates active npm and Certbot processes before closing storage', () => {
  const manager = source('src/site-manager.js');
  const config = source('src/config.js');
  const integrations = source('src/integrations.js');
  const server = source('src/server.js');
  assert.match(manager, /this\.installProcesses = new Map\(\)/);
  assert.match(manager, /this\.installQueue = \[\]/);
  assert.match(manager, /this\.installActive < NPM_INSTALL_WORKERS/);
  assert.match(manager, /this\.installQueue\.length >= NPM_INSTALL_QUEUE_LIMIT/);
  assert.match(config, /SHAM_NPM_INSTALL_WORKERS/);
  assert.match(config, /SHAM_NPM_INSTALL_QUEUE_LIMIT/);
  assert.match(manager, /this\.installProcesses\.set\(site\.id, child\)/);
  assert.match(manager, /terminateAndWait\(child, 2000\)/);
  assert.match(integrations, /const activeProcesses = new Set\(\)/);
  assert.match(integrations, /async function stopIntegrationProcesses/);
  assert.match(server, /dashboardServer\.close\([\s\S]*await stopIntegrationProcesses\(\)[\s\S]*await manager\.stopAll\(\)/);
  assert.ok(server.indexOf('dashboardServer.close(() =>') < server.indexOf('await stopIntegrationProcesses()'));
  assert.ok(server.indexOf('await manager.stopAll()') < server.indexOf('db.close()'));
});

test('static transformations use a bounded worker pool and entry files are revalidated per request', () => {
  const manager = source('src/site-manager.js');
  const config = source('src/config.js');
  assert.match(manager, /new Worker\(path\.join\(__dirname, '\.\.', 'minify-worker\.js'\)/);
  assert.match(manager, /this\.minifyWorkers\.size \+ this\.minifyQueue\.length >= MINIFY_QUEUE_LIMIT/);
  assert.match(manager, /await realFileInsideAsync\(root, entry\)/);
  assert.match(config, /SHAM_MINIFY_WORKERS/);
  assert.match(config, /SHAM_MINIFY_QUEUE_LIMIT/);
});

test('statistics flushing is scheduled and visitor cardinality is bounded', () => {
  const manager = source('src/site-manager.js');
  const security = source('src/security.js');
  assert.match(manager, /scheduleStatsFlush\(\)/);
  assert.match(manager, /VISITOR_PENDING_BUCKETS/);
  assert.doesNotMatch(manager, /pendingVisitors\.size >= 500\) this\.flushStats\(\)/);
  assert.match(security, /Math\.min\(windowMs, 60_000\)/);
  assert.match(security, /buckets\.delete\(key\);\s*buckets\.set\(key, current\)/);
});

test('all background workers are terminated during graceful shutdown', () => {
  const upload = source('src/upload-utils.js');
  const plugins = source('src/plugin-manager.js');
  const server = source('src/server.js');
  const config = source('src/config.js');
  assert.match(upload, /async function stopUploadWorkers/);
  assert.match(upload, /activeWorkers\.size < UPLOAD_WORKERS/);
  assert.match(upload, /activeWorkers\.size \+ uploadQueue\.length >= UPLOAD_QUEUE_LIMIT/);
  assert.match(config, /SHAM_UPLOAD_WORKERS/);
  assert.match(config, /SHAM_UPLOAD_QUEUE_LIMIT/);
  assert.match(plugins, /this\.installWorkers = new Set\(\)/);
  assert.match(plugins, /worker\.terminate\(\)/);
  assert.match(server, /await stopUploadWorkers\(\)/);
});

test('plugin mutations are serialized to avoid lifecycle races', () => {
  const server = source('src/server.js');
  assert.match(server, /async function serializePluginMutation/);
  assert.match(server, /app\.use\('\/api\/admin\/plugins', requireAuth, requireAdmin, serializePluginMutation\)/);
});

test('file scans tolerate concurrent removal and minifier startup fails safely', () => {
  const files = source('src/file-utils.js');
  const manager = source('src/site-manager.js');
  assert.match(files, /fs\.promises\.lstat\(absolute\)/);
  assert.match(files, /error\.code === 'ENOENT' \|\| error\.code === 'ENOTDIR'/);
  assert.match(manager, /try \{\s*worker = new Worker\(/);
  assert.match(manager, /job\.reject\(error\);\s*continue;/);
  assert.match(manager, /Asset transformation failed for/);
});

test('theme runtime keeps custom state coherent and semantic colors tokenized', () => {
  const theme = source('public/theme-init.js');
  const css = source('public/styles.css');
  assert.match(theme, /let current = safeTheme\(\)/);
  assert.match(theme, /get: \(\) => \(\{ name: current\.name/);
  assert.match(theme, /theme\.name === 'custom' && !validateCustom\(theme\.custom\)\.valid/);
  assert.match(css, /--danger-soft:/);
  assert.match(css, /--warning-soft:/);
  assert.match(css, /--success-soft:/);
  assert.match(css, /var\(--danger-soft\)/);
});
