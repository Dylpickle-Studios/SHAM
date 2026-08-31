'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs/promises');
const os = require('node:os');
const path = require('node:path');
const Database = require('better-sqlite3');
const { ShamHarness, ROOT, run, waitFor } = require('./harness');

const enabled = process.env.SHAM_RUN_INTEGRATION === '1';
// v1.1.2 is the stable predecessor to v1.2.0. Keeping the baseline explicit
// makes this a repeatable compatibility contract rather than an accidental
// choice based on tag ordering. Set SHAM_UPGRADE_FROM when preparing a future
// release line.
const DEFAULT_UPGRADE_FROM = 'v1.1.2';

async function supportedReleaseCheckout() {
  const checkout = await fs.mkdtemp(path.join(os.tmpdir(), 'sham-upgrade-baseline-'));
  const archive = path.join(checkout, 'baseline.tar');
  const requested = String(process.env.SHAM_UPGRADE_FROM || '').trim();
  const tag = requested || DEFAULT_UPGRADE_FROM;
  try { await run('git', ['rev-parse', '--verify', `${tag}^{commit}`], { cwd: ROOT }); }
  catch (error) {
    await fs.rm(checkout, { recursive: true, force: true });
    if (!requested && process.env.SHAM_REQUIRE_UPGRADE_BASELINE !== '1') return null;
    throw new Error(`SHAM_UPGRADE_FROM=${tag} is not an available stable release tag. Fetch tags or set SHAM_UPGRADE_FROM to a supported tag.`);
  }
  const ref = (await run('git', ['rev-parse', `${tag}^{commit}`], { cwd: ROOT })).stdout.trim();
  await run('git', ['archive', '--format=tar', '-o', archive, ref], { cwd: ROOT });
  await run('tar', ['-xf', archive, '-C', checkout]);
  await fs.rm(archive, { force: true });
  // Install the release's own locked dependency graph. Sharing current
  // node_modules can hide a genuine upgrade compatibility problem.
  await run('npm', ['ci', '--no-fund', '--no-audit'], { cwd: checkout, env: { ...process.env, npm_config_update_notifier: 'false' } });
  return { checkout, ref, tag };
}

function sqliteQuickCheck(dataDir) {
  const database = new Database(path.join(dataDir, 'sham.db'), { readonly: true, fileMustExist: true });
  try { return database.pragma('quick_check', { simple: true }); }
  finally { database.close(); }
}

async function verifyArchive(dataDir, filename) {
  const script = `require('./src/backup-restore').verifyBackupArchive(process.argv[1]).then((value) => process.stdout.write(JSON.stringify(value))).catch((error) => { console.error(error.message); process.exitCode = 1; });`;
  const result = await run(process.execPath, ['-e', script, path.join(dataDir, 'backups', filename)], {
    cwd: ROOT, env: { ...process.env, SHAM_DATA_PATH: dataDir }
  });
  return JSON.parse(result.stdout);
}

test('upgrade from the last supported stable release preserves releases, secrets, and running traffic', { skip: !enabled, timeout: 180_000 }, async (t) => {
  const legacy = await supportedReleaseCheckout();
  if (!legacy) {
    if (process.env.SHAM_REQUIRE_UPGRADE_BASELINE === '1') throw new Error('No supported stable release tag is available. CI must fetch tags or set SHAM_UPGRADE_FROM.');
    t.skip('No supported stable release tag is present in this checkout; set SHAM_UPGRADE_FROM to run the release-upgrade drill.');
    return;
  }
  const sham = new ShamHarness({ appRoot: legacy.checkout });
  try {
    await sham.start();
    await sham.useSmartGitHttp();
    const site = await sham.createNodeSite({ name: 'upgrade-site', domain: 'upgrade.integration.test' });
    await sham.waitForEdge(site.domain, 'SHAM_TEST_VERSION_1');
    await sham.request(`/api/sites/${site.id}/environment`, {
      method: 'PUT', body: { variables: [{ key: 'RECOVERY_SECRET', value: 'upgrade-secret-value', secret: true, scope: 'runtime' }] }
    });
    await sham.publishFixture('node-v2', 'upgrade version 2');
    await sham.deployGit(site);
    await sham.waitForSite(site.port, 'SHAM_TEST_VERSION_2');
    const before = await sham.request(`/api/sites/${site.id}/deployments?limit=20`);
    assert.ok(before.deployments.length >= 2, 'baseline must create deployment history');
    await assert.rejects(fs.access(path.join(sham.dataDir, 'runtime-agent', 'agent.token')));

    sham.appRoot = ROOT;
    await sham.restartSham();
    await sham.startRuntimeAgent();
    await fs.access(path.join(sham.dataDir, 'runtime-agent', 'agent.token'));
    await sham.waitForEdge(site.domain, 'SHAM_TEST_VERSION_2');
    await sham.loginAdmin();
    const revealed = await sham.request(`/api/sites/${site.id}/environment/RECOVERY_SECRET/reveal`, {
      method: 'POST', body: { password: 'integration-password-123!' }
    });
    assert.equal(revealed.value, 'upgrade-secret-value');
    const releases = await sham.request(`/api/sites/${site.id}/deployments?limit=20`);
    const versionOne = releases.deployments.find((item) => item.releaseId && item.id !== releases.deployments[0].id);
    assert.ok(versionOne?.releaseId, 'upgraded installation must retain the earlier release');
    await sham.request(`/api/sites/${site.id}/releases/${versionOne.releaseId}/rollback`, { method: 'POST', body: {} });
    await sham.waitForEdge(site.domain, 'SHAM_TEST_VERSION_1');
  } catch (error) {
    error.message = `${error.message}\nUpgrade diagnostics:\n${await sham.diagnostics()}`;
    throw error;
  } finally {
    await sham.close();
    await fs.rm(legacy.checkout, { recursive: true, force: true });
  }
});

test('backup restore drill validates archive, database, releases, secrets, and restarted traffic', { skip: !enabled }, async () => {
  const sham = new ShamHarness();
  try {
    await sham.start();
    const site = await sham.createNodeSite({ name: 'recovery-site', domain: 'recovery.integration.test' });
    await sham.waitForEdge(site.domain, 'SHAM_TEST_VERSION_1');
    await sham.request(`/api/sites/${site.id}/environment`, {
      method: 'PUT', body: { variables: [{ key: 'RECOVERY_SECRET', value: 'restore-secret-value', secret: true, scope: 'runtime' }] }
    });
    await sham.publishFixture('node-v2', 'recovery version 2');
    await sham.deployGit(site);
    await sham.waitForEdge(site.domain, 'SHAM_TEST_VERSION_2');

    const backup = (await sham.request('/api/admin/backups/run', { method: 'POST', body: { provider: 'local' } })).backup;
    assert.equal(backup.verified, true);
    const archive = await verifyArchive(sham.dataDir, backup.filename);
    assert.ok(archive.entries > 0);

    await sham.request(`/api/sites/${site.id}`, { method: 'DELETE', body: {} });
    assert.equal((await sham.request('/api/sites')).sites.some((item) => item.id === site.id), false);
    await sham.request(`/api/admin/backups/${backup.id}/restore`, {
      method: 'POST', body: { password: 'integration-password-123!' }
    });
    await sham.restartSham();
    await waitFor(() => sqliteQuickCheck(sham.dataDir) === 'ok', { message: 'Restored SQLite database did not pass quick_check.' });
    const restored = (await sham.request('/api/sites')).sites.find((item) => item.id === site.id);
    assert.ok(restored, 'restore must recover deleted site configuration');
    await fs.access(path.join(sham.dataDir, 'releases', String(restored.id), restored.active_release_directory, 'server.js'));
    const revealed = await sham.request(`/api/sites/${site.id}/environment/RECOVERY_SECRET/reveal`, {
      method: 'POST', body: { password: 'integration-password-123!' }
    });
    assert.equal(revealed.value, 'restore-secret-value');
    await sham.waitForEdge(site.domain, 'SHAM_TEST_VERSION_2');
    const deployments = await sham.request(`/api/sites/${site.id}/deployments?limit=20`);
    const versionOne = deployments.deployments.find((item) => item.releaseId && item.id !== deployments.deployments[0].id);
    assert.ok(versionOne?.releaseId, 'restore must retain release history');
    await sham.request(`/api/sites/${site.id}/releases/${versionOne.releaseId}/rollback`, { method: 'POST', body: {} });
    await sham.waitForEdge(site.domain, 'SHAM_TEST_VERSION_1');
  } catch (error) {
    error.message = `${error.message}\nRestore-drill diagnostics:\n${await sham.diagnostics()}`;
    throw error;
  } finally { await sham.close(); }
});
