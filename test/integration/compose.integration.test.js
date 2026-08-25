'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const { execFile } = require('node:child_process');
const { promisify } = require('node:util');
const { ShamHarness } = require('./harness');

const execFileAsync = promisify(execFile);
const enabled = process.env.SHAM_RUN_INTEGRATION === '1';

async function dockerAvailable() {
  try { await execFileAsync('docker', ['info'], { timeout: 10_000 }); return true; }
  catch { return false; }
}

test('Compose deployment routes only the selected web service and survives SHAM reconciliation', { skip: !enabled, timeout: 180_000 }, async (t) => {
  if (!(await dockerAvailable())) return t.skip('Docker daemon is unavailable');
  const sham = await new ShamHarness().start({ docker: true });
  t.after(() => sham.close());
  try {
    await sham.publishFixture('compose-basic', 'compose fixture');
    const site = await sham.createComposeSite();
    await sham.waitForEdge(site.domain, 'SHAM_TEST_COMPOSE_OK');
    await sham.restartSham();
    await sham.waitForEdge(site.domain, 'SHAM_TEST_COMPOSE_OK');
    await sham.request(`/api/sites/${site.id}`, { method: 'DELETE', body: {} });
    const sites = await sham.request('/api/sites');
    assert.ok(!sites.sites.some((candidate) => candidate.id === site.id));
  } catch (error) {
    error.message += `\nCompose diagnostics:\n${await sham.diagnostics()}`;
    throw error;
  }
});

test('Compose deployment rejects prohibited host-level capabilities before launch', { skip: !enabled, timeout: 120_000 }, async (t) => {
  if (!(await dockerAvailable())) return t.skip('Docker daemon is unavailable');
  const sham = await new ShamHarness().start({ docker: true });
  t.after(() => sham.close());
  await sham.publishFixture('compose-invalid', 'unsafe compose fixture');
  await assert.rejects(
    () => sham.createComposeSite({ name: 'unsafe-compose', domain: 'unsafe.integration.test' }),
    /privileged|network_mode|pid|ipc|docker socket|host root|SYS_ADMIN/i
  );
});
