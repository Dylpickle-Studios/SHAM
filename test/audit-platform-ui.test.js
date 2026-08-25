const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');

const ROOT = path.join(__dirname, '..');
const read = (file) => fs.readFileSync(path.join(ROOT, file), 'utf8');

test('dashboard attention quick views are interactive drilldowns', () => {
  const html = read('public/index.html');
  const dashboard = read('public/js/dashboard.js');
  const cards = [...html.matchAll(/<button class="attention-card"[^>]*data-attention-view="([^"]+)"/g)].map((match) => match[1]);
  assert.deepEqual(cards, ['health', 'deployments', 'alerts', 'automation']);
  assert.match(html, /id="attention-dialog"/);
  assert.match(dashboard, /function openAttentionDetail\(kind\)/);
  assert.match(dashboard, /attentionDetails/);
});

test('primary navigation exposes Performance and command palette indexes deep destinations', () => {
  const html = read('public/index.html');
  const core = read('public/js/core.js');
  assert.match(html, /class="nav-item" data-section="performance"/);
  for (const phrase of ['Settings: ${label}', 'Files for ${site.name}', 'Logs for ${site.name}', 'Settings for ${site.name}', "label: 'Performance'"]) {
    assert.ok(core.includes(phrase), `command palette must include ${phrase}`);
  }
  assert.match(core, /p50 p95/);
});

test('settings and security layout fixes have explicit responsive spacing', () => {
  const html = read('public/index.html');
  const css = read('public/styles.css');
  assert.match(html, /security-grid security-secondary-grid/);
  assert.match(html, /class="filter-row env-copy-row"/);
  assert.match(html, /class="panel git-provider-panel"/);
  assert.match(css, /\.performance-grid, \.security-grid \{[^}]*gap:\s*1rem/);
  assert.match(css, /\.env-copy-row[^}]*grid-template-columns: minmax\(0, 1fr\) auto/);
  assert.match(css, /\.git-provider-row[^}]*grid-template-columns:/);
  assert.match(css, /@media \(max-width: 760px\)[\s\S]*\.env-copy-row[\s\S]*grid-template-columns: 1fr/);
});

test('administration is a settings category and appearance separates mode from palette', () => {
  const html = read('public/index.html');
  const core = read('public/js/core.js');
  const theme = read('public/theme-init.js');
  assert.match(html, /id="operations-administration"/);
  assert.match(core, /settings-category-header/);
  assert.match(core, /Accounts, Cloudflare, Certbot, identity, users, and persistent instance policy/);
  for (const mode of ['system', 'light', 'dark']) assert.match(html, new RegExp(`data-theme-mode="${mode}"`));
  for (const preset of ['purple', 'midnight', 'emerald', 'custom']) assert.match(html, new RegExp(`data-theme-preset="${preset}"`));
  assert.match(theme, /mode: 'system'/);
});

test('tooltips and toasts use the active top layer instead of stale stacking contexts', () => {
  const core = read('public/js/core.js');
  const css = read('public/styles.css');
  assert.match(core, /function topLayerHost\(\)/);
  assert.match(core, /toast-region top-layer-toast-region/);
  assert.match(core, /trigger\.closest\('dialog\[open\]'\)/);
  assert.match(css, /\.floating-tooltip[^}]*z-index:\s*2147483647/);
  assert.match(css, /\.modal\s*\{[^}]*overflow:\s*visible/);
});

test('source and runtime UI includes Docker image, Dockerfile and Compose modes', () => {
  const html = read('public/index.html');
  const sites = read('public/js/sites.js');
  assert.match(html, /Docker image/);
  assert.match(html, /data-site-template="dockerfile"/);
  assert.match(html, /data-site-template="compose"/);
  assert.match(html, /id="site-runtime-container-image"/);
  assert.match(sites, /source === 'image'/);
  assert.match(sites, /containerMode/);
});

test('Git integrations include GitHub, GitLab, Bitbucket Cloud, Gitea and Forgejo', () => {
  const providers = read('src/git-providers.js');
  const html = read('public/index.html');
  for (const provider of ['github', 'gitlab', 'bitbucket', 'gitea', 'forgejo']) {
    assert.match(providers, new RegExp(`\\b${provider}: \\{`));
    assert.match(html, new RegExp(`data-git-provider-row="${provider}"`));
  }
  assert.match(providers, /repository URLs would be ambiguous/);
  assert.match(providers, /Never guess between providers configured for the same origin\/path/);
});

test('hosted Compose policy blocks common project-boundary escapes', () => {
  const runtime = read('src/sites/runtime.js');
  for (const phrase of [
    'cannot use host bind mounts',
    'cannot mount the Docker socket',
    'cannot publish host ports',
    'cannot map the Docker host gateway',
    'cannot disable container security profiles',
    'must not attach unmanaged Docker resources'
  ]) assert.match(runtime, new RegExp(phrase));
  assert.match(runtime, /assertComposePathInside\(root, dockerfile/);
  assert.match(runtime, /internal: true/);
});

test('plugin playground validates with the production manifest validator and isolates preview code', () => {
  const html = read('public/index.html');
  const admin = read('src/routes/admin.js');
  const client = read('public/js/plugins.js');
  assert.match(html, /id="plugin-playground-dialog"/);
  assert.match(html, /sandbox="allow-scripts"/);
  assert.match(admin, /plugins\/playground\/validate/);
  assert.match(admin, /validateManifest\(manifest\)/);
  assert.match(admin, /128 \* 1024/);
  assert.match(client, /connect-src 'none'/);
});

test('site folder multipart limit has bounded headroom for the expanded wizard', () => {
  const server = read('src/server.js');
  const value = Number(server.match(/const SITE_FORM_FIELD_LIMIT = (\d+);/)?.[1] || 0);
  assert.ok(value >= 128 && value <= 256);
  assert.match(server, /fields: SITE_FORM_FIELD_LIMIT/);
  assert.match(server, /parts: MAX_FILES \+ SITE_FORM_FIELD_LIMIT/);
});

test('CLI runtime-control commands map to explicit idempotent HTTP endpoints', () => {
  const routes = read('src/routes/sites.js');
  const cli = read('bin/sham.js');
  for (const action of ['start', 'stop', 'restart']) {
    assert.match(routes, new RegExp(`app\\.post\\('/api/sites/:id/${action}'`));
    assert.ok(cli.includes(`['start', 'stop', 'restart']`));
  }
  assert.match(routes, /async function setSiteEnabled\(site, enabled\)/);
  assert.match(cli, /AbortSignal\.timeout\(timeoutMs\)/);
  assert.match(cli, /timeoutMs: 30 \* 60_000/);
  assert.match(cli, /timeoutMs: 10 \* 60_000/);
});

test('license and categorized documentation are included in the source release and in-app updates', () => {
  const server = read('src/server.js');
  const readme = read('README.md');
  const html = read('public/index.html');
  const core = read('public/js/core.js');
  const updater = read('src/update-manager.js');
  assert.match(server, /app\.get\('\/LICENSE'/);
  assert.match(read('LICENSE'), /GNU AFFERO GENERAL PUBLIC LICENSE/);
  const docs = [
    'getting-started.md', 'dashboard-and-ui.md', 'runtimes-and-docker.md', 'git-and-cicd.md',
    'api-and-cli.md', 'api-reference.md', 'operations-and-security.md', 'configuration-reference.md',
    'plugin-development.md', 'troubleshooting.md'
  ];
  for (const doc of docs) {
    assert.ok(fs.existsSync(path.join(ROOT, 'docs', doc)), `${doc} must ship`);
    assert.match(readme, new RegExp(doc.replace('.', '\\.')));
  }
  for (const tab of ['usage', 'dashboard', 'runtimes', 'git', 'api', 'config', 'operations', 'development', 'troubleshooting']) {
    assert.match(html, new RegExp(`data-doc-tab="${tab}"`));
    assert.match(html, new RegExp(`data-doc-panel="${tab}"`));
  }
  assert.match(core, /\['Dashboard & UI', 'dashboard'\]/);
  assert.match(core, /\['Configuration', 'config'\]/);
  assert.match(core, /\['Troubleshooting', 'troubleshooting'\]/);
  assert.match(updater, /'bin', 'runtime-agent', 'docs'/);
});

test('dashboard HTML has unique IDs and label targets resolve', () => {
  const html = read('public/index.html');
  const ids = [...html.matchAll(/\bid="([^"]+)"/g)].map((match) => match[1]);
  assert.equal(new Set(ids).size, ids.length);
  const set = new Set(ids);
  for (const match of html.matchAll(/<label[^>]*\bfor="([^"]+)"/g)) assert.ok(set.has(match[1]), `label target ${match[1]} must exist`);
});

test('tests do not leave generated JWT instance secrets in the repository', () => {
  assert.equal(fs.existsSync(path.join(ROOT, 'data', '.jwt-secret')), false);
});
