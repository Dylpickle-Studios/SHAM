const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const os = require('node:os');
const { execFileSync } = require('node:child_process');

const { root, source: read } = require('./source-tree');

test('release is AGPL-3.0-or-later and exposes the license from the interface', () => {
  const pkg = JSON.parse(read('package.json'));
  const license = read('LICENSE');
  const html = read('public/index.html');
  const server = read('src/server.js');
  assert.equal(pkg.license, 'AGPL-3.0-or-later');
  assert.match(license, /GNU AFFERO GENERAL PUBLIC LICENSE[\s\S]*Version 3, 19 November 2007/);
  assert.doesNotMatch(license, /^MIT License/m);
  assert.match(html, /id="license-button"[\s\S]*>License<\/button>/);
  assert.match(html, /id="license-dialog"[\s\S]*AGPL-3\.0-or-later/);
  assert.match(html, /SHAM is licensed under <strong>AGPL-3\.0-or-later<\/strong>/);
  assert.match(server, /app\.get\('\/LICENSE',[\s\S]*ROOT_DIR, 'LICENSE'/);
});

test('multipart parsers pin the patched Multer release and disable field nesting', () => {
  const pkg = JSON.parse(read('package.json'));
  const server = read('src/server.js');
  assert.equal(pkg.dependencies.multer, '2.2.0');
  assert.equal((server.match(/fieldNestingDepth:\s*0/g) || []).length, 3);
  const fieldLimit = Number(server.match(/const SITE_FORM_FIELD_LIMIT = (\d+);/)?.[1] || 0);
  assert.ok(fieldLimit >= 128 && fieldLimit <= 256, `site form field limit ${fieldLimit} must leave headroom without being unbounded`);
  assert.match(server, /fields:\s*SITE_FORM_FIELD_LIMIT[\s\S]*parts:\s*MAX_FILES \+ SITE_FORM_FIELD_LIMIT/);
  assert.match(server, /fieldNameSize:\s*100/);
});


test('JWT dependency uses the patched JWS dependency line', () => {
  const pkg = JSON.parse(read('package.json'));
  assert.equal(pkg.dependencies.jsonwebtoken, '9.0.3');
  assert.match(read('README.md'), /jsonwebtoken` 9\.0\.3/);
});

test('production image fails its build on high-severity dependency advisories', () => {
  const pkg = JSON.parse(read('package.json'));
  const dockerfile = read('Dockerfile');
  assert.equal(pkg.scripts.security, 'npm audit --omit=dev --audit-level=high');
  assert.match(dockerfile, /COPY package\*\.json/);
  assert.match(dockerfile, /npm ci --omit=dev --no-fund/);
  assert.match(dockerfile, /npm audit --omit=dev --audit-level=high/);
  assert.doesNotMatch(dockerfile, /npm install[^\n]*--no-audit/);
});

test('Docker build context excludes runtime data, secrets, dependencies, and release archives', () => {
  const ignore = read('.dockerignore');
  for (const pattern of ['node_modules', '.env', 'data/*', 'sham-data', '*.zip', 'package.json.bak']) {
    assert.match(ignore, new RegExp(`(?:^|\\n)${pattern.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')}(?:\\n|$)`));
  }
  assert.match(ignore, /!data\/sites\/\.gitkeep/);
  assert.match(ignore, /!data\/plugins\/\.gitkeep/);
});

test('performance refresh requests a new sample and always restores the button', () => {
  const app = read('public/app.js');
  const server = read('src/server.js');
  const monitor = read('src/performance-monitor.js');
  assert.match(app, /force \? '\/api\/performance\?refresh=1' : '\/api\/performance'/);
  assert.match(app, /performanceController\?\.abort\(\)/);
  assert.match(app, /button\.disabled = true/);
  assert.match(app, /finally[\s\S]*button\.disabled = false/);
  assert.match(server, /if \(bool\(req\.query\.refresh, false\)\) await performanceMonitor\.runSample\(\)/);
  assert.match(monitor, /const tracked = Promise\.resolve\(\)\.then\(\(\) => this\.sample\(\)\)/);
  assert.match(monitor, /if \(this\.currentSamplePromise\) return this\.currentSamplePromise/);
});

test('performance surfaces retain visible spacing and collapse cleanly on narrow screens', () => {
  const css = read('public/styles.css');
  assert.match(css, /#section-performance \{[^}]*display:\s*grid;[^}]*gap:\s*1\.15rem/);
  assert.match(css, /\.performance-stats \{[^}]*margin-bottom:\s*1rem/);
  assert.match(css, /\.performance-grid, \.security-grid \{[^}]*gap:\s*1rem;[^}]*margin-bottom:\s*1rem/);
  assert.match(css, /\.performance-grid > \.panel, #section-performance > \.panel \{[^}]*min-width:\s*0/);
  assert.match(css, /@media \(max-width: 620px\)[\s\S]*\.performance-grid, \.security-grid \{ grid-template-columns: 1fr; \}/);
  assert.match(css, /@media \(max-width: 620px\)[\s\S]*\.performance-stats \{ grid-template-columns: 1fr; \}/);
});

test('application updates persist beneath SHAM_DATA_PATH and bootstrap active releases after recreation', () => {
  const config = read('src/config.js');
  const updates = read('src/update-manager.js');
  const bootstrap = read('src/bootstrap.js');
  const compose = read('docker-compose.yml');
  assert.match(config, /APP_RUNTIME_DIR = path\.join\(DATA_DIR, 'app-runtime'\)/);
  assert.match(config, /ACTIVE_APP_PATH = path\.join\(APP_RUNTIME_DIR, 'active\.json'\)/);
  assert.match(updates, /await writeJsonAtomic\(ACTIVE_APP_PATH, active\)/);
  assert.match(updates, /resolveActiveAppRoot\(\)/);
  assert.match(bootstrap, /const activeRoot = updateRuntime\.resolveActiveAppRoot\(\)/);
  assert.match(bootstrap, /NODE_PATH/);
  assert.match(bootstrap, /await server\.ready/);
  assert.match(compose, /SHAM_DATA_PATH:\s*\/data/);
  assert.match(compose, /\.\/sham-data:\/data/);
});

test('hosted and helper processes receive purpose-specific environment allowlists', () => {
  const env = require('../src/process-env');
  process.env.SHAM_JWT_SECRET = 'do-not-forward';
  process.env.SHAM_MASTER_KEY = 'do-not-forward';
  process.env.NPM_CONFIG_REGISTRY = 'https://registry.example.invalid';
  assert.equal(env.runtimeEnvironment().SHAM_JWT_SECRET, undefined);
  assert.equal(env.runtimeEnvironment().SHAM_MASTER_KEY, undefined);
  assert.equal(env.buildEnvironment().NPM_CONFIG_REGISTRY, 'https://registry.example.invalid');
  const sites = read('src/site-manager.js');
  const operations = read('src/operations-manager.js');
  const integrations = read('src/integrations.js');
  const scanner = read('src/dependency-scanner.js');
  assert.match(sites, /runtimeEnvironment\(/);
  assert.match(operations, /environmentMode === 'runtime' \? runtimeEnvironment/);
  // Docker itself is only ever invoked by the privileged Runtime Agent, which
  // still spawns it with the same sanitized environment.
  const agentDocker = read('runtime-agent/docker.js');
  assert.match(agentDocker, /spawn\(bin, args,[\s\S]*env: \{ \.\.\.operatorEnvironment\(\)/);
  assert.match(integrations, /env:\s*operatorEnvironment\(\)/);
  assert.match(scanner, /env:\s*buildEnvironment\(\{ NODE_ENV: 'production' \}\)/);
  assert.doesNotMatch(integrations, /env:\s*process\.env/);
  assert.doesNotMatch(scanner, /env:\s*\{ \.\.\.process\.env/);
});

test('deployment webhook replay protection is persistent and bounded', () => {
  const db = read('src/db.js');
  const operations = read('src/routes/operations.js');
  assert.match(db, /CREATE TABLE IF NOT EXISTS deploy_webhook_deliveries/);
  assert.match(db, /PRIMARY KEY \(site_id, delivery_id\)/);
  for (const header of ['x-github-delivery', 'x-gitlab-event-uuid', 'x-gitea-delivery', 'x-forgejo-delivery', 'x-sham-delivery']) {
    assert.match(operations, new RegExp(header));
  }
  assert.match(operations, /DELETE FROM deploy_webhook_deliveries WHERE received_at < datetime\('now', '-14 days'\)/);
  assert.match(operations, /This webhook delivery was already processed/);
});

test('backup generation uses a consistent database snapshot and rejects unsafe destinations', () => {
  const operations = read('src/operations-manager.js');
  assert.match(operations, /await this\.db\.backup\(path\.join\(databaseSnapshotDirectory, 'sham\.db'\)\)/);
  assert.match(operations, /pathInside\(dataRoot, externalLocalDirectory\)/);
  assert.match(operations, /'--exclude=\.\/tmp', '--exclude=\.\/backups', '--exclude=\.\/updates'/);
  assert.doesNotMatch(operations, /'--exclude=tmp', '--exclude=backups', '--exclude=updates'/);
  assert.match(operations, /outside SHAM_DATA_PATH/);
  assert.match(operations, /function sftpQuote/);
  assert.match(operations, /Backup provider must be local, restic, s3, or sftp/);
});

test('cron day-of-month and weekday matching follows standard OR semantics', () => {
  const operations = read('src/operations-manager.js');
  assert.match(operations, /const calendarMatches = schedule\.dayWildcard && schedule\.weekdayWildcard[\s\S]*: schedule\.dayWildcard[\s\S]*: schedule\.weekdayWildcard[\s\S]*: dayMatches \|\| weekdayMatches/);
});



test('update staging cleanup never removes the shared updates directory', () => {
  const temp = fs.mkdtempSync(path.join(os.tmpdir(), 'sham-update-cleanup-'));
  const modulePath = path.join(root, 'src', 'update-manager.js');
  const script = `
    const fs = require('node:fs');
    const path = require('node:path');
    process.env.SHAM_DATA_PATH = ${JSON.stringify('${DATA_PATH}')};
    const manager = require(${JSON.stringify('${MODULE_PATH}')});
    const updates = path.join(process.env.SHAM_DATA_PATH, 'updates');
    const stage = path.join(updates, 'stage-root-package');
    fs.mkdirSync(path.join(stage, 'src'), { recursive: true });
    fs.writeFileSync(path.join(stage, 'package.json'), '{}');
    fs.writeFileSync(path.join(updates, 'update-state.json'), '{"status":"healthy"}');
    fs.writeFileSync(path.join(updates, 'keep-me'), 'safe');
    manager.removeStagedRoot(stage).then(() => {
      if (fs.existsSync(stage)) throw new Error('stage still exists');
      if (!fs.existsSync(path.join(updates, 'update-state.json'))) throw new Error('state was deleted');
      if (!fs.existsSync(path.join(updates, 'keep-me'))) throw new Error('sibling was deleted');
    }).catch((error) => { console.error(error); process.exitCode = 1; });
  `.replace('${DATA_PATH}', temp.replaceAll('\\', '\\\\')).replace('${MODULE_PATH}', modulePath.replaceAll('\\', '\\\\'));
  try {
    execFileSync(process.execPath, ['-e', script], { stdio: 'pipe', env: { ...process.env, SHAM_JWT_SECRET: 'x'.repeat(64) } });
  } finally {
    fs.rmSync(temp, { recursive: true, force: true });
  }
  const updates = read('src/update-manager.js');
  assert.match(updates, /const stageName = relative\.split\(path\.sep\)\[0\]/);
  assert.match(updates, /runMutation\(callback\)[\s\S]*if \(this\.mutationActive\) throw new Error\('Another update operation is already running\.'\)/);
  assert.match(updates, /this\.operations\.add\(operation\)[\s\S]*this\.operations\.delete\(operation\)/);
  assert.match(updates, /An update is already staged/);
});
