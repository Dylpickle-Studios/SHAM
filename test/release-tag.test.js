'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const path = require('node:path');
const { spawnSync } = require('node:child_process');
const { version } = require('../package.json');

test('release validation accepts the matching tag and rejects mismatched or prerelease tags', () => {
  const root = path.resolve(__dirname, '..');
  for (const [ref, accepted] of [
    [`refs/tags/v${version}`, true],
    ['refs/tags/v0.0.0', false],
    [`refs/tags/v${version}-rc.1`, false],
    ['refs/heads/main', true],
  ]) {
    const result = spawnSync(process.execPath, ['scripts/release-check.js'], {
      cwd: root,
      env: { ...process.env, GITHUB_REF: ref },
      encoding: 'utf8',
    });
    assert.ifError(result.error);
    assert.equal(result.status, accepted ? 0 : 1, `${ref}: ${result.stdout}${result.stderr}`);
    if (!accepted) assert.match(result.stderr, /Release tag must match/);
  }
});
