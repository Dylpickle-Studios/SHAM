const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const vm = require('node:vm');

const { source } = require('./source-tree');

const { validateSiteInput } = require('../src/validation');
const { validatePluginArchiveFile } = require('../src/plugin-archive');

test('obfuscation requires explicit risk acknowledgement', () => {
  assert.throws(
    () => validateSiteInput({ name: 'Risky', port: 4400, obfuscate: true }),
    /Confirm that JavaScript obfuscation can change runtime behavior/
  );
  const site = validateSiteInput({
    name: 'Acknowledged',
    port: 4401,
    obfuscate: true,
    obfuscationRiskAcknowledged: true
  });
  assert.equal(site.obfuscate, true);
  assert.equal(site.obfuscation_risk_acknowledged, true);
});

test('obfuscation uses compatibility-oriented options and a runtime warning path', () => {
  const worker = source('src/minify-worker.js');
  const server = source('src/server.js');
  const manager = source('src/site-manager.js');
  assert.match(worker, /toplevel: false/);
  assert.match(worker, /keep_fnames: Boolean\(obfuscate\)/);
  assert.match(worker, /keep_classnames: Boolean\(obfuscate\)/);
  assert.match(worker, /unsafe: false/);
  assert.doesNotMatch(worker, /properties:\s*\{/);
  assert.match(manager, /Asset transformation failed[\s\S]*serving the original file/);
  assert.match(server, /safeObfuscationWarning/);
  assert.match(server, /obfuscation-report/);
});

test('dashboard wires reliable refresh and plugin install controls', () => {
  const app = source('public/app.js');
  const html = source('public/index.html');
  assert.match(app, /event\.target\.closest\('#refresh-overview'\)/);
  assert.match(app, /loadOverview\(\{ force: true \}\)/);
  assert.match(app, /overviewController\?\.abort\(\)/);
  assert.match(app, /button\.disabled = false/);
  assert.match(app, /event\.target\.closest\('#install-plugin-button'\)/);
  assert.match(app, /function openPluginInstaller\(\)/);
  assert.match(html, /id="plugin-file-status"/);
  assert.match(html, /id="site-obfuscation-ack"/);
  assert.match(html, /id="site-obfuscation-scan"/);
});

test('traffic map uses real country geometry instead of hand-drawn land blobs', () => {
  const html = source('public/index.html');
  const app = source('public/app.js');
  const mapSource = source('public/world-map.js');
  assert.match(html, /<script src="world-map\.js"><\/script>/);
  assert.match(app, /window\.SHAM_WORLD_MAP/);
  assert.match(app, /map-country level-/);
  assert.doesNotMatch(app, /COUNTRY_POINTS/);

  const context = { window: {} };
  vm.runInNewContext(mapSource, context);
  assert.equal(context.window.SHAM_WORLD_MAP.viewBox, '0 0 1000 500');
  assert.ok(context.window.SHAM_WORLD_MAP.countries.length >= 170);
  assert.ok(context.window.SHAM_WORLD_MAP.countries.every((item) => /^[A-Z]{2}$/.test(item.code) && /^M/.test(item.path)));
});

test('compatibility scanner is bounded and rejects symlink races', () => {
  const audit = source('src/obfuscation-audit.js');
  assert.match(audit, /MAX_SCAN_FILES = 750/);
  assert.match(audit, /MAX_SCAN_TOTAL_BYTES = 20 \* 1024 \* 1024/);
  assert.match(audit, /MAX_WARNINGS = 200/);
  assert.match(audit, /resolveSitePathAsync/);
  assert.match(audit, /stat\.isSymbolicLink\(\)/);
  assert.match(audit, /lineStarts/);
});

test('package syntax check recursively covers source and browser modules', () => {
  const pkg = JSON.parse(source('package.json'));
  assert.match(pkg.scripts.check, /scripts\/check-syntax\.js/);
  const checker = source('scripts/check-syntax.js');
  assert.match(checker, /path\.join\(root, 'src'\)/);
  assert.match(checker, /path\.join\(root, 'public'\)/);
  assert.match(checker, /entry\.name\.endsWith\('\.js'\)/);
});

test('plugin uploads are validated on both client and server before extraction', async () => {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), 'sham-plugin-signature-'));
  const valid = path.join(directory, 'valid.zip');
  const invalid = path.join(directory, 'invalid.zip');
  fs.writeFileSync(valid, Buffer.from([0x50, 0x4b, 0x03, 0x04, 0, 0]));
  fs.writeFileSync(invalid, 'not a zip');
  await validatePluginArchiveFile(valid, 'plugin.zip');
  await assert.rejects(validatePluginArchiveFile(valid, 'plugin.txt'), /\.zip file extension/);
  await assert.rejects(validatePluginArchiveFile(invalid, 'plugin.zip'), /not a valid ZIP archive/);
  fs.rmSync(directory, { recursive: true, force: true });

  const server = source('src/server.js');
  const app = source('public/app.js');
  assert.match(server, /await validatePluginArchiveFile\(req\.file\.path, req\.file\.originalname\)/);
  assert.match(app, /Plugin archives may not exceed 20 MB/);
  assert.match(app, /data\.append\('plugin', file, file\.name\)/);
});

test('traffic map reports data coverage and uses accessible interactive country geometry', () => {
  const app = source('public/app.js');
  const html = source('public/index.html');
  assert.match(app, /Math\.log1p\(value\) \/ Math\.log1p\(maximum\)/);
  assert.match(app, /class="map-tooltip" role="status"/);
  assert.match(app, /map\.onfocusin/);
  assert.match(app, /trusted country data/);
  assert.match(html, /id="traffic-map-status"/);
});
