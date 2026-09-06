'use strict';

// Executed through stdin inside CI's disposable, unprivileged SHAM container.
const fs = require('node:fs/promises');
const path = require('node:path');
const assert = require('node:assert/strict');

const origin = `http://127.0.0.1:${process.env.SHAM_PORT || '8080'}`;
const marker = path.join(process.env.SHAM_DATA_PATH || '/data', 'restore-smoke.txt');
const expected = 'Recovered from the container data volume.';
const password = 'ci-restore-only-password-123!';

async function main() {
  if (process.argv[2] === 'stage') {
    const registered = await fetch(`${origin}/api/auth/register`, {
      method: 'POST', headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ username: 'ci-restore-admin', password })
    });
    assert.equal(registered.status, 201);
    const cookie = String(registered.headers.get('set-cookie') || '').split(';')[0];
    const post = async (route, body) => {
      const response = await fetch(`${origin}${route}`, {
        method: 'POST', headers: { 'content-type': 'application/json', cookie }, body: JSON.stringify(body)
      });
      const result = /** @type {{ error?: string, backup?: { id: number, verified: boolean } }} */ (await response.json());
      assert.ok(response.ok, result.error || `HTTP ${response.status}`);
      return result;
    };
    await fs.writeFile(marker, expected);
    const { backup } = await post('/api/admin/backups/run', { provider: 'local' });
    assert.ok(backup);
    assert.equal(backup.verified, true);
    await fs.unlink(marker);
    await post(`/api/admin/backups/${backup.id}/restore`, { password });
    console.log('Container backup restore staged.');
    return;
  }
  assert.equal(process.argv[2], 'verify');
  for (let attempt = 0; attempt < 30; attempt += 1) {
    if (await fetch(`${origin}/api/health`).then((response) => response.ok).catch(() => false)) {
      assert.equal(await fs.readFile(marker, 'utf8'), expected);
      console.log('Container backup restore verified with the data mount intact.');
      return;
    }
    await new Promise((resolve) => setTimeout(resolve, 1000));
  }
  throw new Error('Container did not become healthy after restore.');
}

main().catch((error) => { console.error(error.message); process.exitCode = 1; });
