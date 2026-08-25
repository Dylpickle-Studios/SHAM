'use strict';

const fs = require('node:fs');
const path = require('node:path');

const root = path.resolve(__dirname, '..');
const read = (name) => fs.readFileSync(path.join(root, name), 'utf8');
const exists = (name) => fs.existsSync(path.join(root, name));
const failures = [];
const requireCondition = (condition, message) => { if (!condition) failures.push(message); };

const pkg = JSON.parse(read('package.json'));
const escapedVersion = pkg.version.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
requireCondition(/^\d+\.\d+\.\d+$/.test(pkg.version), 'package.json version must be a stable semantic version.');
requireCondition(pkg.license === 'AGPL-3.0-or-later', 'package.json must declare AGPL-3.0-or-later.');
requireCondition(pkg.private === true, 'The application package should remain private to prevent accidental npm publication.');

for (const filename of [
  'LICENSE', 'README.md', 'CHANGELOG.md', 'CONTRIBUTING.md', 'RELEASING.md', 'SECURITY.md',
  '.github/workflows/ci.yml', '.github/workflows/docker-publish.yml', '.github/workflows/release.yml',
  '.github/dependabot.yml', 'Dockerfile', 'docker-compose.yml', '.env.example'
]) requireCondition(exists(filename), `Required release file is missing: ${filename}`);

requireCondition(/GNU AFFERO GENERAL PUBLIC LICENSE[\s\S]*Version 3, 19 November 2007/.test(read('LICENSE')), 'LICENSE must contain GNU Affero GPL version 3.');
if (exists('package-lock.json')) {
  const lock = JSON.parse(read('package-lock.json'));
  requireCondition(lock.version === pkg.version, 'package-lock.json version must match package.json.');
  requireCondition(lock.packages?.['']?.version === pkg.version, 'package-lock.json root package version must match package.json.');
}

requireCondition(new RegExp(`Current release: ${escapedVersion}`).test(read('README.md')), `README must identify release ${pkg.version}.`);
requireCondition(new RegExp(`## \\[${escapedVersion}\\] — \\d{4}-\\d{2}-\\d{2}`).test(read('CHANGELOG.md')), `CHANGELOG must contain a dated ${pkg.version} release entry.`);
requireCondition(new RegExp(`^ARG VERSION=${escapedVersion}$`, 'm').test(read('Dockerfile')), `Dockerfile default VERSION must match ${pkg.version}.`);
requireCondition(new RegExp(`VERSION: ${escapedVersion}`).test(read('docker-compose.yml')), `docker-compose.yml build VERSION must match ${pkg.version}.`);
requireCondition(new RegExp(`VERSION=${escapedVersion}`).test(read('.github/workflows/ci.yml')), `CI Docker smoke build VERSION must match ${pkg.version}.`);
requireCondition(new RegExp(`ghcr\\.io/<owner>/<repository>:${escapedVersion}`).test(read('RELEASING.md')), `RELEASING.md must use the ${pkg.version} image tag.`);
requireCondition(/ghcr\.io\/<owner>\/<repository>/.test(read('RELEASING.md')), 'RELEASING.md must explain GHCR image names.');
requireCondition(/packages:\s*write/.test(read('.github/workflows/docker-publish.yml')), 'Docker workflow must request package write permission.');
requireCondition(/npm audit --omit=dev --audit-level=high/.test(read('.github/workflows/ci.yml')), 'CI must fail on high-severity production dependency advisories.');

for (const [forbidden, message] of [
  ['.env', 'A real .env file must not be committed.'],
  ['data/.jwt-secret', 'A generated JWT secret must not be included in the source tree.'],
  ['data/sham.db', 'The runtime database must not be included in the source tree.'],
  ['data/sham.db-wal', 'The SQLite WAL file must not be included in the source tree.'],
  ['data/sham.db-shm', 'The SQLite shared-memory file must not be included in the source tree.'],
  ['data/master-key.json', 'The encrypted-secret master key must not be included in the source tree.'],
  ['data/runtime-agent', 'The generated runtime agent token/socket directory must not be included in the source tree.'],
  ['sham-data', 'The Docker runtime-data directory must not be included in the source tree.']
]) requireCondition(!exists(forbidden), message);

const releaseWorkflow = read('.github/workflows/release.yml');
requireCondition(/--exclude 'data\/'/.test(releaseWorkflow), 'Tagged release archives must exclude the runtime data directory.');
requireCondition(/data\/sites\/\.gitkeep/.test(releaseWorkflow) && /data\/plugins\/\.gitkeep/.test(releaseWorkflow), 'Tagged release archives must recreate only safe data placeholders.');

if (!exists('package-lock.json')) {
  console.warn('Release warning: package-lock.json is not committed. Tagged GitHub workflows will refuse to publish until the Prepare lockfile pull request is merged.');
}

if (failures.length) {
  for (const failure of failures) console.error(`- ${failure}`);
  process.exit(1);
}

console.log(`SHAM ${pkg.version} release metadata and repository files are coherent.`);
