'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const { ShamHarness } = require('./harness');

const enabled = process.env.SHAM_RUN_INTEGRATION === '1';

test('Git deployment switches traffic, preserves a failed candidate, rolls back, and reconciles after restart', { skip: !enabled, timeout: 90_000 }, async (t) => {
  const sham = await new ShamHarness().start();
  t.after(() => sham.close());
  try {
    const site = await sham.createNodeSite();
    await sham.waitForEdge(site.domain, 'SHAM_TEST_VERSION_1');

    await sham.publishFixture('node-v2', 'version 2');
    await sham.deployGit(site);
    await sham.waitForEdge(site.domain, 'SHAM_TEST_VERSION_2');

    await sham.publishFixture('node-broken', 'broken candidate');
    await assert.rejects(() => sham.deployGit(site), /did not become ready|Runtime exited|timed out/i);
    await sham.waitForEdge(site.domain, 'SHAM_TEST_VERSION_2');

    const deployments = await sham.request(`/api/sites/${site.id}/deployments`);
    assert.equal(deployments.deployments[0].status, 'failed');
    const rollback = deployments.deployments.find((deployment) => deployment.releaseId && !deployment.activeRelease);
    assert.ok(rollback, 'the version-1 release should be retained for rollback');
    await sham.request(`/api/sites/${site.id}/releases/${rollback.releaseId}/rollback`, { method: 'POST', body: {} });
    await sham.waitForEdge(site.domain, 'SHAM_TEST_VERSION_1');

    await sham.restartSham();
    const afterRestart = await sham.request('/api/sites');
    assert.ok(afterRestart.sites.some((candidate) => candidate.id === site.id));
    await sham.waitForEdge(site.domain, 'SHAM_TEST_VERSION_1');

    await sham.request(`/api/sites/${site.id}/stop`, { method: 'POST', body: {} });
    const stopped = await sham.edgeText(site.domain);
    assert.notEqual(stopped.status, 200, 'stopped site must not keep serving through the edge');
    await sham.request(`/api/sites/${site.id}/start`, { method: 'POST', body: {} });
    await sham.waitForEdge(site.domain, 'SHAM_TEST_VERSION_1');
    await sham.request(`/api/sites/${site.id}/restart`, { method: 'POST', body: {} });
    await sham.waitForEdge(site.domain, 'SHAM_TEST_VERSION_1');

    const logs = await sham.request(`/api/runtime-logs?siteId=${site.id}&limit=200`);
    assert.ok(logs.logs.some((entry) => entry.message.includes('SHAM_TEST_VERSION_1')), 'fixture runtime logs should be available through the API');
  } catch (error) {
    error.message += `\nIntegration diagnostics:\n${await sham.diagnostics()}`;
    throw error;
  }
});
