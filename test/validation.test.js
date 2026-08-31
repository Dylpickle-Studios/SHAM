const test = require('node:test');
const assert = require('node:assert/strict');
const { safeRelativePath, validateHeaders, validateIpOrCidr, validateSiteInput } = require('../src/validation');

test('safeRelativePath rejects traversal and absolute paths', () => {
  for (const value of ['../index.html', '/etc/passwd', 'C:/Windows/file', '.', '']) {
    assert.throws(() => safeRelativePath(value));
  }
  assert.equal(safeRelativePath('./assets/app.js'), 'assets/app.js');
});

test('custom headers reject hop-by-hop and newline values', () => {
  assert.throws(() => validateHeaders({ Connection: 'close' }));
  assert.throws(() => validateHeaders({ 'X-Test': 'one\r\ntwo' }));
  assert.deepEqual(validateHeaders('{"X-Robots-Tag":"noindex"}'), { 'X-Robots-Tag': 'noindex' });
});

test('site input normalizes supported values', () => {
  const result = validateSiteInput({
    name: 'Docs App',
    port: '4100',
    bindHost: '0.0.0.0',
    entryFile: './index.html',
    spaFallback: 'true',
    cacheSeconds: '60',
    headers: '{}'
  });
  assert.equal(result.slug, 'docs-app');
  assert.equal(result.port, 4100);
  assert.equal(result.spa_fallback, true);
  assert.equal(result.cache_seconds, 60);
});

test('firewall CIDR parsing rejects extra path separators', () => {
  assert.throws(() => validateIpOrCidr('192.0.2.1/24/extra'), /not a valid IP address or CIDR range/);
  assert.throws(() => validateIpOrCidr('2001:db8::1/64/extra'), /not a valid IP address or CIDR range/);
});

test('site input supports Node.js runtime and minification settings', () => {
  const nodeSite = validateSiteInput({
    name: 'API',
    port: 4200,
    runtimeType: 'node',
    nodeEntry: './server.js',
    installDependencies: true,
    domain: 'api.example.com'
  });
  assert.equal(nodeSite.runtime_type, 'node');
  assert.equal(nodeSite.node_entry, 'server.js');
  assert.equal(nodeSite.install_dependencies, true);
  assert.equal(nodeSite.domain, 'api.example.com');

  const staticSite = validateSiteInput({
    name: 'Static',
    port: 4201,
    runtimeType: 'static',
    minify: 'true'
  });
  assert.equal(staticSite.minify, true);
  assert.throws(() => validateSiteInput({ name: 'Bad', port: 4202, domain: 'not-a-domain' }));
});

test('private process listeners are explicit, private, and limited to managed processes', () => {
  const site = validateSiteInput({
    name: 'Private API', port: 4203, runtimeType: 'node', runtimeIsolation: 'process',
    additionalListeners: [{ name: 'admin', port: 4204, bindHost: '10.8.0.1', portEnv: 'ADMIN_PORT' }]
  });
  assert.deepEqual(site.additional_listeners, [{ name: 'admin', port: 4204, bindHost: '10.8.0.1', portEnv: 'ADMIN_PORT' }]);
  assert.throws(() => validateSiteInput({ name: 'Public private port', port: 4205, runtimeType: 'node', additionalListeners: [{ name: 'admin', port: 4206, bindHost: '0.0.0.0', portEnv: 'ADMIN_PORT' }] }), /public bind addresses/);
  assert.throws(() => validateSiteInput({ name: 'Container listener', port: 4207, runtimeType: 'container', additionalListeners: [{ name: 'admin', port: 4208, bindHost: '127.0.0.1', portEnv: 'ADMIN_PORT' }] }), /supported only/);
  assert.throws(() => validateSiteInput({ name: 'Reserved listener environment', port: 4209, runtimeType: 'node', additionalListeners: [{ name: 'admin', port: 4210, bindHost: '127.0.0.1', portEnv: 'PORT' }] }), /reserved/);
});


test('site input rejects partially numeric port and cache values', () => {
  assert.throws(() => validateSiteInput({ name: 'Bad port', port: '4100abc' }), /Port must be an integer/);
  assert.throws(() => validateSiteInput({ name: 'Bad cache', port: 4100, cacheSeconds: '60seconds' }), /Cache duration must be an integer/);
});
