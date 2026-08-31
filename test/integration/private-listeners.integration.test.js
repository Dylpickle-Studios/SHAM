'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const { ShamHarness } = require('./harness');

const enabled = process.env.SHAM_RUN_INTEGRATION === '1';

test('Node process private listeners stay off the edge and recover with the site runtime', { skip: !enabled }, async () => {
  const sham = new ShamHarness({ fixture: 'node-multi' });
  try {
    await sham.start();
    const privatePort = 43117;
    const site = await sham.createNodeSite({
      name: 'multi-listener-node',
      domain: 'multi-listener.integration.test',
      additionalListeners: [{ name: 'admin', port: privatePort, bindHost: '127.0.0.1', portEnv: 'ADMIN_PORT' }]
    });
    assert.deepEqual(site.additional_listeners, [{ name: 'admin', port: privatePort, bindHost: '127.0.0.1', portEnv: 'ADMIN_PORT' }]);
    await sham.waitForEdge(site.domain, 'SHAM_MULTI_PUBLIC');
    await sham.waitForSite(privatePort, 'SHAM_MULTI_PRIVATE_ADMIN');
    const edge = await sham.edgeText(site.domain);
    assert.equal(edge.body, 'SHAM_MULTI_PUBLIC', 'Cloudflare/shared-edge traffic must use only the public listener');
    const tunnelResponse = await fetch(`${sham.baseUrl}/api/admin/sites/${site.id}/cloudflare-tunnel`, {
      method: 'PUT',
      headers: { 'content-type': 'application/json', cookie: sham.cookie },
      body: JSON.stringify({ originService: `http://127.0.0.1:${privatePort}` })
    });
    assert.equal(tunnelResponse.status, 400);
    assert.match(await tunnelResponse.text(), /private process listener/i);
    await sham.request(`/api/sites/${site.id}/restart`, { method: 'POST', body: {} });
    await sham.waitForEdge(site.domain, 'SHAM_MULTI_PUBLIC');
    await sham.waitForSite(privatePort, 'SHAM_MULTI_PRIVATE_ADMIN');
  } finally {
    await sham.close();
  }
});
