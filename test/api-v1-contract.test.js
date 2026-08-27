'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const { ShamHarness } = require('./integration/harness');

test('the documented /api/v1 contract preserves legacy API behavior and uses structured errors', { timeout: 30_000 }, async (t) => {
  const sham = await new ShamHarness().start();
  t.after(() => sham.close());

  const spec = JSON.parse(fs.readFileSync(path.join(__dirname, '..', 'docs', 'openapi.json'), 'utf8'));
  assert.equal(spec.openapi, '3.1.0');
  assert.equal(spec.info.version, require('../package.json').version, 'OpenAPI release metadata must follow package.json');
  for (const endpoint of ['/health', '/auth/login', '/sites', '/sites/{siteId}/deploy/git', '/sites/{siteId}/releases/{releaseId}/rollback', '/runtime-logs', '/performance', '/admin/backups/run']) {
    assert.ok(spec.paths[endpoint], `OpenAPI must document ${endpoint}`);
  }

  const legacyHealth = await sham.request('/api/health');
  const versionedHealth = await sham.request('/api/v1/health');
  assert.deepEqual(versionedHealth, legacyHealth);

  const legacySites = await sham.request('/api/sites');
  const versionedSites = await sham.request('/api/v1/sites');
  assert.deepEqual(versionedSites.sites, legacySites.sites);

  const missing = await fetch(`${sham.baseUrl}/api/v1/sites/999999`, { headers: { cookie: sham.cookie } });
  assert.equal(missing.status, 404);
  assert.equal(missing.headers.get('api-version'), '1');
  const body = await missing.json();
  assert.equal(body.error.code, 'NOT_FOUND');
  assert.equal(typeof body.error.message, 'string');
});
