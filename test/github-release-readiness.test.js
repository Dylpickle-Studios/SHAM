const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');

const { root, source: read } = require('./source-tree');

test('public release metadata is coherent with package version', () => {
  const pkg = JSON.parse(read('package.json'));
  const lock = JSON.parse(read('package-lock.json'));
  const escapedVersion = pkg.version.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');

  assert.match(pkg.version, /^\d+\.\d+\.\d+$/);
  assert.equal(lock.version, pkg.version);
  assert.equal(lock.packages[''].version, pkg.version);
  assert.equal(pkg.license, 'AGPL-3.0-or-later');
  assert.equal(pkg.private, true);
  assert.match(read('README.md'), new RegExp(`Current release: ${escapedVersion}`));
  assert.match(read('CHANGELOG.md'), new RegExp(`## \\[${escapedVersion}\\] — \\d{4}-\\d{2}-\\d{2}`));
  assert.match(read('Dockerfile'), new RegExp(`^ARG VERSION=${escapedVersion}$`, 'm'));
  assert.match(read('docker-compose.yml'), new RegExp(`VERSION: ${escapedVersion}`));
  assert.match(read('.github/workflows/ci.yml'), new RegExp(`VERSION=${escapedVersion}`));
  assert.match(read('RELEASING.md'), new RegExp(`ghcr\\.io/<owner>/<repository>:${escapedVersion}`));
  assert.match(read('docs/README.md'), new RegExp(`current SHAM ${escapedVersion} feature set`));
  assert.match(read('docs/api-reference.md'), new RegExp(`SHAM ${escapedVersion}`));
  assert.doesNotMatch(read('README.md'), /3\.1\.1|3\.1\.0/);
  assert.doesNotMatch(read('public/index.html'), /3\.1\.1|3\.1\.0/);
});

test('GitHub CI and GHCR release workflows enforce validation and narrow permissions', () => {
  const ci = read('.github/workflows/ci.yml');
  const docker = read('.github/workflows/docker-publish.yml');
  const release = read('.github/workflows/release.yml');
  assert.match(ci, /permissions:\n {2}contents: read/);
  assert.match(ci, /npm run release:check/);
  assert.match(ci, /npm audit --omit=dev --audit-level=high/);
  assert.match(ci, /Docker smoke build/);
  assert.match(docker, /REGISTRY: ghcr\.io/);
  assert.match(docker, /packages: write/);
  assert.match(docker, /platforms: linux\/amd64,linux\/arm64/);
  assert.match(docker, /sbom: true/);
  assert.match(docker, /provenance: mode=max/);
  assert.match(release, /Tag \$GITHUB_REF_NAME does not match package\.json version/);
  assert.match(release, /gh release create/);
  assert.match(release, /sha256sum/);
  assert.match(release, /--exclude 'data\/'/);
  assert.match(release, /data\/sites\/\.gitkeep/);
  assert.match(release, /data\/plugins\/\.gitkeep/);
});

test('release documentation and repository policy files are present', () => {
  for (const filename of [
    'LICENSE', 'SECURITY.md', 'CONTRIBUTING.md', 'RELEASING.md', 'CHANGELOG.md',
    '.github/dependabot.yml', '.github/pull_request_template.md',
    '.github/ISSUE_TEMPLATE/bug_report.yml', '.github/ISSUE_TEMPLATE/feature_request.yml'
  ]) assert.equal(fs.existsSync(path.join(root, filename)), true, filename);
  assert.match(read('RELEASING.md'), /ghcr\.io\/<owner>\/<repository>:/);
  assert.match(read('SECURITY.md'), /private vulnerability reporting/);
});
