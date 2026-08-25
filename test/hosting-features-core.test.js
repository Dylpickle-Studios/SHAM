const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const os = require('node:os');

const temporaryData = fs.mkdtempSync(path.join(os.tmpdir(), 'sham-hosting-features-'));
process.env.SHAM_DATA_PATH = temporaryData;
process.env.SHAM_JWT_SECRET = 'hosting-features-test-secret-at-least-32-characters';
test.after(() => fs.rmSync(temporaryData, { recursive: true, force: true }));

const { validateSiteInput } = require('../src/validation');
const { buildCloudflareFirewallExpression } = require('../src/integrations');

const { root, source: projectSource } = require('./source-tree');

test('site input supports obfuscation, domain-only access, and firewall settings', () => {
  const site = validateSiteInput({
    name: 'Protected app',
    port: 4300,
    domain: 'APP.Example.com.',
    obfuscate: true,
    obfuscationRiskAcknowledged: true,
    domainOnly: true,
    firewallEnabled: true,
    cloudflareEnabled: true,
    firewallMode: 'both',
    firewallCloudflareAction: 'managed_challenge',
    firewallRateLimit: '120',
    firewallMaxBodyKb: '512',
    firewallBlockedIps: '198.51.100.0/24\n2001:db8::/32',
    firewallAllowedCountries: 'NL, BE',
    firewallBlockBots: true
  });
  assert.equal(site.domain, 'app.example.com');
  assert.equal(site.obfuscate, true);
  assert.equal(site.obfuscation_risk_acknowledged, true);
  assert.equal(site.domain_only, true);
  assert.equal(site.firewall_enabled, true);
  assert.deepEqual(site.firewall.blockedIps, ['198.51.100.0/24', '2001:db8::/32']);
  assert.deepEqual(site.firewall.allowedCountries, ['NL', 'BE']);
  assert.equal(site.firewall.rateLimitPerMinute, 120);
  assert.equal(site.firewall.maxBodyKb, 512);
  assert.equal(site.firewall.blockBots, true);
});

test('domain-only access requires a configured domain and firewall lists are validated', () => {
  assert.throws(() => validateSiteInput({ name: 'No domain', port: 4301, domainOnly: true }), /Configure a domain/);
  assert.throws(() => validateSiteInput({ name: 'Bad CIDR', port: 4302, firewallBlockedIps: '198.51.100.0/99' }), /invalid CIDR prefix/);
  assert.throws(() => validateSiteInput({ name: 'Bad country', port: 4303, firewallBlockedCountries: 'NLD' }), /two-letter country codes/);
  assert.throws(() => validateSiteInput({ name: 'Untrusted country', port: 4304, firewallEnabled: true, firewallMode: 'local', firewallAllowedCountries: 'NL' }), /require a synchronized Cloudflare proxy/);
  assert.deepEqual(validateSiteInput({ name: 'Tor rule', port: 4305, firewallBlockedCountries: 'T1' }).firewall.blockedCountries, ['T1']);
});

test('Cloudflare firewall expressions stay scoped to the site hostname', () => {
  const expression = buildCloudflareFirewallExpression('app.example.com', {
    blockedIps: ['198.51.100.0/24'],
    allowedIps: [],
    blockedCountries: ['RU'],
    allowedCountries: ['NL', 'BE']
  });
  assert.match(expression, /^\(http\.host eq "app\.example\.com"\) and /);
  assert.match(expression, /ip\.src in \{198\.51\.100\.0\/24\}/);
  assert.match(expression, /ip\.src\.country in \{"RU"\}/);
  assert.match(expression, /not ip\.src\.country in \{"NL" "BE"\}/);
});

test('dashboard exposes the requested controls, analytics, and theme surfaces', () => {
  const html = fs.readFileSync(path.join(root, 'public', 'index.html'), 'utf8');
  const app = projectSource('public/app.js');
  const css = fs.readFileSync(path.join(root, 'public', 'styles.css'), 'utf8');
  for (const id of [
    'site-obfuscate', 'site-domain-only', 'site-firewall-enabled', 'traffic-map',
    'visitor-table', 'operations-tab-appearance', 'operations-appearance', 'theme-form', 'custom-theme-fields'
  ]) assert.match(html, new RegExp(`id="${id}"`));
  assert.match(app, /cloudflare-firewall/);
  assert.match(app, /renderTrafficOrigins/);
  assert.match(app, /SHAM_THEME\.save/);
  assert.match(css, /body \{ position: fixed; inset: 0;/);
  assert.match(html, /id="site-action-menu"[^>]*popover="auto"/);
  assert.match(app, /showPopover/);
  assert.match(css, /\.site-action-menu \{/);
  assert.match(css, /--primary: #a970ff/);
});

test('Cloudflare headers are accepted only from trusted edge peers', () => {
  const source = projectSource('src/site-manager.js');
  assert.match(source, /TRUSTED_EDGE_RANGES/);
  assert.match(source, /site\.cloudflare_enabled && trustedEdgePeer\(peerIp\)/);
  assert.match(source, /Chunked request bodies are not accepted/);
  assert.match(source, /site\.minify \|\| site\.obfuscate/);
  assert.match(fs.readFileSync(path.join(root, 'src/minify-worker.js'), 'utf8'), /minifyJS: obfuscate/);
});
