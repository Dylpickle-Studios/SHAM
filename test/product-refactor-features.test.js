'use strict';

process.env.SHAM_JWT_SECRET = 'product-refactor-test-secret-at-least-32-characters';

const test = require('node:test');
const assert = require('node:assert/strict');

const { classifyClient, actionableIp } = require('../src/visitor-intelligence');
const { validateProxyTarget, validateBuildCommand, validateBuildOutput } = require('../src/validation');
const { providerForRepositoryUrl, applyGitProviderCredentials, normalizeWebhookBaseUrl, ensureProviderWebhook } = require('../src/git-providers');
const { source } = require('./source-tree');

test('visitor intelligence separates LLM crawlers, search crawlers, generic automation, and browsers', () => {
  assert.deepEqual(classifyClient('Mozilla/5.0 compatible; GPTBot/1.2').type, 'llm');
  assert.equal(classifyClient('ClaudeBot/1.0').type, 'llm');
  assert.equal(classifyClient('Mozilla/5.0 (compatible; Googlebot/2.1)').type, 'search');
  assert.equal(classifyClient('python-requests/2.32').type, 'crawler');
  assert.equal(classifyClient('Mozilla/5.0 AppleWebKit/537.36 Chrome/140 Safari/537.36').type, 'browser');
  assert.equal(actionableIp('203.0.113.42'), true);
  assert.equal(actionableIp('2001:db8::42'), true);
  assert.equal(actionableIp('203.0.113.x'), false);
});

test('reverse-proxy and build configuration validates URLs, commands, and contained output paths', () => {
  assert.equal(validateProxyTarget('http://127.0.0.1:3000', 'proxy'), 'http://127.0.0.1:3000/');
  assert.throws(() => validateProxyTarget('file:///etc/passwd', 'proxy'), /HTTP or HTTPS/);
  assert.throws(() => validateProxyTarget('https://user:pass@example.com', 'proxy'), /must not embed credentials/);
  assert.equal(validateBuildCommand('npm run build', 'Build command'), 'npm run build');
  assert.throws(() => validateBuildCommand('npm ci\nnpm run build', 'Build command'), /single command/);
  assert.equal(validateBuildOutput('./dist'), 'dist');
  assert.throws(() => validateBuildOutput('../outside'), /not safe|must stay inside/);
});

test('connected Git providers are recognized and inject clone credentials through Git environment config', () => {
  assert.equal(providerForRepositoryUrl('https://github.com/example/private.git'), 'github');
  assert.equal(providerForRepositoryUrl('https://gitlab.com/example/private.git'), 'gitlab');
  assert.equal(providerForRepositoryUrl('git@github.com:example/private.git'), null);
  const db = {
    prepare() {
      return { get(key) { return key === 'git_provider_github_token' ? { value: 'example-secret-token' } : null; } };
    }
  };
  const environment = {};
  assert.equal(applyGitProviderCredentials(db, 'https://github.com/example/private.git', environment), 'github');
  assert.equal(environment.GIT_TERMINAL_PROMPT, '0');
  assert.equal(environment.GIT_CONFIG_KEY_0, 'http.https://github.com/.extraHeader');
  assert.match(environment.GIT_CONFIG_VALUE_0, /^Authorization: Basic /);
  assert.doesNotMatch(environment.GIT_CONFIG_VALUE_0, /example-secret-token/);
  assert.match(source('src/operations/deployments.js'), /applyGitProviderCredentials\(this\.db, repository, environment\)/);
});

test('connected Git providers can synchronize push webhooks without exposing provider tokens', async () => {
  assert.equal(normalizeWebhookBaseUrl('https://sham.example.com/'), 'https://sham.example.com');
  assert.throws(() => normalizeWebhookBaseUrl('https://sham.example.com/control-plane'), /origin/);
  const db = {
    prepare() {
      return { get(key) { return key === 'git_provider_github_token' ? { value: 'provider-token' } : null; } };
    }
  };
  const calls = [];
  const originalFetch = global.fetch;
  global.fetch = async (url, options = {}) => {
    calls.push({ url: String(url), options });
    if ((options.method || 'GET') === 'GET') return { ok: true, status: 200, json: async () => [] };
    return { ok: true, status: 201, json: async () => ({ id: 42 }) };
  };
  try {
    const result = await ensureProviderWebhook(db, 'https://github.com/example/private.git', 'https://sham.example.com/api/hooks/deploy/7', 'webhook-secret');
    assert.equal(result.provider, 'github');
    assert.equal(result.action, 'created');
    assert.equal(calls.length, 2);
    assert.match(calls[1].options.body, /api\/hooks\/deploy\/7/);
    assert.doesNotMatch(calls[1].options.body, /provider-token/);
    assert.equal(calls[1].options.headers.Authorization, 'Bearer provider-token');
  } finally { global.fetch = originalFetch; }
  const operationsRoutes = source('src/routes/operations.js');
  assert.match(operationsRoutes, /x-gitlab-token/);
  assert.match(operationsRoutes, /x-gitlab-event-uuid/);
});

test('site creation keeps ports and risky asset transforms out of the normal wizard path', () => {
  const html = source('public/index.html');
  const css = source('public/styles.css');
  assert.match(html, /class="advanced-only"[^>]*><span class="field-label">(?:Listener )?port/i);
  assert.match(html, /id="asset-transform-options"/);
  assert.match(html, /data-site-template="next">Next\.js/);
  assert.match(css, /data-wizard-step="2"[^\n]*\.advanced-only/);
});
