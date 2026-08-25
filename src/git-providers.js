// @ts-nocheck -- not part of this session's checkJs rollout yet.
// This file still has genuine `tsc --noEmit` findings (mostly narrow
// `let x = null`-style inference and untyped Express handlers, the same
// patterns already fixed across most of src/) that need real per-file
// JSDoc work to resolve, not a suppression. Tracked as follow-up work;
// see tsconfig.json and docs/development.md. Do not add more files here
// without a similar comment and a plan to remove it.
'use strict';

const { getSecretSetting, setSecretSetting } = require('./secret-store');

const PROVIDERS = Object.freeze({
  github: {
    label: 'GitHub',
    tokenKey: 'git_provider_github_token',
    baseUrl: 'https://github.com',
    apiBaseUrl: 'https://api.github.com',
    configurableBaseUrl: false,
    headers(token) {
      return {
        Accept: 'application/vnd.github+json',
        Authorization: `Bearer ${token}`,
        'User-Agent': 'SHAM/1.0',
        'X-GitHub-Api-Version': '2022-11-28'
      };
    },
    repositoriesPath: '/user/repos?per_page=100&sort=updated&affiliation=owner,collaborator,organization_member',
    repositories(payload) { return payload; },
    map(repository) {
      return {
        id: String(repository.id), name: String(repository.name || ''), fullName: String(repository.full_name || repository.name || ''),
        url: String(repository.clone_url || ''), defaultBranch: String(repository.default_branch || 'main'), private: Boolean(repository.private), updatedAt: String(repository.updated_at || '')
      };
    },
    gitAuthorization(token) { return `Basic ${Buffer.from(`x-access-token:${token}`).toString('base64')}`; }
  },
  gitlab: {
    label: 'GitLab',
    tokenKey: 'git_provider_gitlab_token',
    baseUrl: 'https://gitlab.com',
    apiBaseUrl: 'https://gitlab.com/api/v4',
    configurableBaseUrl: false,
    headers(token) { return { 'PRIVATE-TOKEN': token, 'User-Agent': 'SHAM/1.0' }; },
    repositoriesPath: '/projects?membership=true&simple=true&per_page=100&order_by=last_activity_at&sort=desc',
    repositories(payload) { return payload; },
    map(repository) {
      return {
        id: String(repository.id), name: String(repository.name || ''), fullName: String(repository.path_with_namespace || repository.name || ''),
        url: String(repository.http_url_to_repo || ''), defaultBranch: String(repository.default_branch || 'main'),
        private: String(repository.visibility || '').toLowerCase() !== 'public', updatedAt: String(repository.last_activity_at || '')
      };
    },
    gitAuthorization(token) { return `Basic ${Buffer.from(`oauth2:${token}`).toString('base64')}`; }
  },
  bitbucket: {
    label: 'Bitbucket Cloud',
    tokenKey: 'git_provider_bitbucket_token',
    baseUrl: 'https://bitbucket.org',
    apiBaseUrl: 'https://api.bitbucket.org/2.0',
    configurableBaseUrl: false,
    headers(token) { return { Authorization: `Bearer ${token}`, Accept: 'application/json', 'User-Agent': 'SHAM/1.0' }; },
    repositoriesPath: '/repositories?role=member&pagelen=100&sort=-updated_on',
    repositories(payload) { return Array.isArray(payload?.values) ? payload.values : null; },
    map(repository) {
      const httpsLink = Array.isArray(repository?.links?.clone) ? repository.links.clone.find((link) => String(link?.name || '').toLowerCase() === 'https') : null;
      return {
        id: String(repository.uuid || repository.full_name || ''), name: String(repository.name || ''), fullName: String(repository.full_name || repository.name || ''),
        url: String(httpsLink?.href || ''), defaultBranch: String(repository.mainbranch?.name || 'main'),
        private: Boolean(repository.is_private), updatedAt: String(repository.updated_on || '')
      };
    },
    gitAuthorization(token) { return `Basic ${Buffer.from(`x-token-auth:${token}`).toString('base64')}`; }
  },
  gitea: {
    label: 'Gitea',
    tokenKey: 'git_provider_gitea_token',
    baseUrlKey: 'git_provider_gitea_base_url',
    baseUrl: 'https://gitea.com',
    configurableBaseUrl: true,
    headers(token) { return { Authorization: `token ${token}`, Accept: 'application/json', 'User-Agent': 'SHAM/1.0' }; },
    repositoriesPath: '/user/repos?limit=100&page=1&sort=updated',
    repositories(payload) { return payload; },
    map(repository) {
      return {
        id: String(repository.id), name: String(repository.name || ''), fullName: String(repository.full_name || repository.name || ''),
        url: String(repository.clone_url || ''), defaultBranch: String(repository.default_branch || 'main'), private: Boolean(repository.private), updatedAt: String(repository.updated_at || '')
      };
    },
    gitAuthorization(token) { return `token ${token}`; }
  },
  forgejo: {
    label: 'Forgejo',
    tokenKey: 'git_provider_forgejo_token',
    baseUrlKey: 'git_provider_forgejo_base_url',
    baseUrl: 'https://codeberg.org',
    configurableBaseUrl: true,
    headers(token) { return { Authorization: `token ${token}`, Accept: 'application/json', 'User-Agent': 'SHAM/1.0' }; },
    repositoriesPath: '/user/repos?limit=100&page=1&sort=updated',
    repositories(payload) { return payload; },
    map(repository) {
      return {
        id: String(repository.id), name: String(repository.name || ''), fullName: String(repository.full_name || repository.name || ''),
        url: String(repository.clone_url || ''), defaultBranch: String(repository.default_branch || 'main'), private: Boolean(repository.private), updatedAt: String(repository.updated_at || '')
      };
    },
    gitAuthorization(token) { return `token ${token}`; }
  }
});

function getPlainSetting(db, key, fallback = '') {
  if (!key) return fallback;
  return db.prepare('SELECT value FROM settings WHERE key = ?').get(key)?.value ?? fallback;
}

function setPlainSetting(db, key, value) {
  if (!key) return;
  db.prepare(`INSERT INTO settings (key, value) VALUES (?, ?) ON CONFLICT(key) DO UPDATE SET value = excluded.value`).run(key, String(value || ''));
}

function normalizeProviderBaseUrl(value, fallback = '') {
  const input = String(value || fallback || '').trim();
  if (!input || input.length > 2048 || /[\0\r\n]/.test(input)) throw new Error('Git provider base URL is invalid.');
  let parsed;
  try { parsed = new URL(input); } catch { throw new Error('Git provider base URL must be a valid HTTP or HTTPS URL.'); }
  if (!['http:', 'https:'].includes(parsed.protocol) || parsed.username || parsed.password || parsed.search || parsed.hash) {
    throw new Error('Git provider base URL must be HTTP or HTTPS without credentials, query parameters, or fragments.');
  }
  const pathname = parsed.pathname.replace(/\/+$/, '');
  return `${parsed.origin}${pathname === '/' ? '' : pathname}`;
}

function providerDefinition(provider, db = null) {
  const key = String(provider || '').trim().toLowerCase();
  const template = PROVIDERS[key];
  if (!template) throw new Error('Git provider must be GitHub, GitLab, Bitbucket Cloud, Gitea, or Forgejo.');
  const baseUrl = template.configurableBaseUrl && db
    ? normalizeProviderBaseUrl(getPlainSetting(db, template.baseUrlKey, template.baseUrl), template.baseUrl)
    : normalizeProviderBaseUrl(template.baseUrl, template.baseUrl);
  const apiBaseUrl = template.apiBaseUrl || `${baseUrl}/api/v1`;
  return { key, ...template, baseUrl, apiBaseUrl };
}

function providerStatuses(db) {
  return Object.keys(PROVIDERS).map((provider) => {
    const definition = providerDefinition(provider, db);
    return {
      provider, label: definition.label, configured: Boolean(getSecretSetting(db, definition.tokenKey, '')),
      baseUrl: definition.baseUrl, configurableBaseUrl: Boolean(definition.configurableBaseUrl), insecureBaseUrl: definition.baseUrl.startsWith('http:')
    };
  });
}

/**
 * @param {import('better-sqlite3').Database} db
 * @param {string} provider
 * @param {{ token?: string | null, clearToken?: boolean, baseUrl?: string }} [options]
 */
function saveProviderToken(db, provider, { token, clearToken = false, baseUrl } = {}) {
  const definition = providerDefinition(provider, db);
  const incoming = token === undefined || token === null ? '' : String(token).trim();
  if (incoming && (incoming.length > 8192 || /[\s\0]/.test(incoming))) throw new Error(`${definition.label} token must be a single value no longer than 8192 characters.`);
  if (incoming && clearToken) throw new Error('Choose either a replacement token or disconnect the provider.');
  if (definition.configurableBaseUrl && baseUrl !== undefined) {
    const proposed = normalizeProviderBaseUrl(baseUrl, definition.baseUrl);
    const willBeConnected = !clearToken && Boolean(incoming || getSecretSetting(db, definition.tokenKey, ''));
    if (willBeConnected) {
      for (const otherProvider of Object.keys(PROVIDERS)) {
        if (otherProvider === definition.key) continue;
        const other = providerDefinition(otherProvider, db);
        if (other.baseUrl === proposed && getSecretSetting(db, other.tokenKey, '')) {
          throw new Error(`${definition.label} and ${other.label} cannot both use ${proposed}; repository URLs would be ambiguous.`);
        }
      }
    }
    setPlainSetting(db, definition.baseUrlKey, proposed);
  }
  if (incoming || clearToken) setSecretSetting(db, definition.tokenKey, clearToken ? '' : incoming);
  if (!incoming && !clearToken && baseUrl === undefined) throw new Error(`Enter a ${definition.label} access token, update its base URL, or choose disconnect.`);
  return providerStatuses(db);
}

function apiUrl(definition, pathname) {
  return new URL(String(pathname || '').replace(/^\/+/, ''), `${definition.apiBaseUrl.replace(/\/+$/, '')}/`).toString();
}

async function listProviderRepositories(db, provider) {
  const definition = providerDefinition(provider, db);
  const token = getSecretSetting(db, definition.tokenKey, '');
  if (!token) throw new Error(`${definition.label} is not connected. Connect it from Settings → Administration first.`);
  const response = await fetch(apiUrl(definition, definition.repositoriesPath), {
    method: 'GET', headers: definition.headers(token), redirect: 'error', signal: AbortSignal.timeout(15_000)
  });
  if (!response.ok) {
    await response.body?.cancel().catch(() => {});
    const retry = response.status === 401 || response.status === 403 ? ' Check the saved token and its repository-read permissions.' : '';
    throw new Error(`${definition.label} repository lookup failed with HTTP ${response.status}.${retry}`);
  }
  const payload = await response.json();
  const repositories = definition.repositories(payload);
  if (!Array.isArray(repositories)) throw new Error(`${definition.label} returned an unexpected repository response.`);
  return repositories.map(definition.map).filter((repository) => repository.fullName && /^https?:\/\//i.test(repository.url)).slice(0, 100);
}

function repositoryOriginMatches(parsed, definition) {
  const base = new URL(definition.baseUrl);
  if (parsed.origin.toLowerCase() !== base.origin.toLowerCase()) return false;
  const basePath = base.pathname.replace(/\/+$/, '');
  return !basePath || basePath === '/' || parsed.pathname === basePath || parsed.pathname.startsWith(`${basePath}/`);
}

function providerForRepositoryUrl(repositoryUrl, db = null) {
  let parsed;
  try { parsed = new URL(String(repositoryUrl || '')); } catch { return null; }
  if (!['http:', 'https:'].includes(parsed.protocol) || parsed.username || parsed.password) return null;
  const matches = Object.keys(PROVIDERS)
    .map((provider) => ({ provider, definition: providerDefinition(provider, db) }))
    .filter(({ definition }) => repositoryOriginMatches(parsed, definition))
    .map((match) => ({ ...match, specificity: new URL(match.definition.baseUrl).pathname.replace(/\/+$/, '').length }))
    .sort((left, right) => right.specificity - left.specificity);
  if (!matches.length) return null;
  const mostSpecific = matches.filter((match) => match.specificity === matches[0].specificity);
  if (mostSpecific.length === 1) return mostSpecific[0].provider;
  if (db) {
    const connected = mostSpecific.filter(({ definition }) => Boolean(getSecretSetting(db, definition.tokenKey, '')));
    if (connected.length === 1) return connected[0].provider;
  }
  // Never guess between providers configured for the same origin/path. Supplying
  // credentials for the wrong provider is worse than requiring an unambiguous setup.
  return null;
}

function repositoryPath(repositoryUrl, provider, db = null) {
  const definition = providerDefinition(provider, db);
  let parsed;
  try { parsed = new URL(String(repositoryUrl || '')); } catch { throw new Error('Repository URL is invalid.'); }
  if (!repositoryOriginMatches(parsed, definition)) throw new Error(`Repository URL is not hosted on ${definition.label}.`);
  let decodedPath;
  try { decodedPath = decodeURIComponent(parsed.pathname); }
  catch { throw new Error(`${definition.label} repository path contains invalid URL encoding.`); }
  const basePath = new URL(definition.baseUrl).pathname.replace(/^\/+|\/+$/g, '');
  let pathname = decodedPath.replace(/^\/+|\/+$/g, '').replace(/\.git$/i, '');
  if (basePath && (pathname === basePath || pathname.startsWith(`${basePath}/`))) pathname = pathname.slice(basePath.length).replace(/^\/+/, '');
  if (!pathname || pathname.split('/').some((part) => !part || part === '.' || part === '..')) throw new Error(`${definition.label} repository path is invalid.`);
  return pathname;
}

function providerCommitUrl(repositoryUrl, commitSha, db = null) {
  const provider = providerForRepositoryUrl(repositoryUrl, db);
  const sha = String(commitSha || '').trim();
  if (!provider || !/^[0-9a-f]{7,64}$/i.test(sha)) return '';
  let pathname;
  try { pathname = repositoryPath(repositoryUrl, provider, db).split('/').map(encodeURIComponent).join('/'); }
  catch { return ''; }
  const baseUrl = providerDefinition(provider, db).baseUrl;
  if (provider === 'gitlab') return `${baseUrl}/${pathname}/-/commit/${encodeURIComponent(sha)}`;
  if (provider === 'bitbucket') return `${baseUrl}/${pathname}/commits/${encodeURIComponent(sha)}`;
  return `${baseUrl}/${pathname}/commit/${encodeURIComponent(sha)}`;
}

function normalizeWebhookBaseUrl(value) {
  const input = String(value || '').trim();
  if (!input) return '';
  if (input.length > 2048 || /[\0\r\n]/.test(input)) throw new Error('Public SHAM URL is too long or invalid.');
  let parsed;
  try { parsed = new URL(input); } catch { throw new Error('Public SHAM URL must be a valid HTTP or HTTPS origin.'); }
  if (!['http:', 'https:'].includes(parsed.protocol) || parsed.username || parsed.password || parsed.search || parsed.hash) throw new Error('Public SHAM URL must be a valid HTTP or HTTPS origin without credentials, query parameters, or fragments.');
  if (parsed.pathname && parsed.pathname !== '/') throw new Error('Public SHAM URL must be an origin without an additional path.');
  return parsed.origin;
}

async function providerRequest(definition, token, url, options = {}) {
  const response = await fetch(url, {
    method: options.method || 'GET',
    headers: { ...definition.headers(token), ...(options.body ? { 'Content-Type': 'application/json' } : {}) },
    body: options.body ? JSON.stringify(options.body) : undefined,
    redirect: 'error', signal: AbortSignal.timeout(15_000)
  });
  if (!response.ok) {
    await response.body?.cancel().catch(() => {});
    const permission = [401, 403, 404].includes(response.status) ? ` Check the saved ${definition.label} token and its repository/webhook permissions.` : '';
    throw new Error(`${definition.label} webhook configuration failed with HTTP ${response.status}.${permission}`);
  }
  if (response.status === 204) {
    await response.body?.cancel().catch(() => {});
    return null;
  }
  return response.json().catch(() => null);
}

function encodedRepositoryPath(repoPath) {
  return repoPath.split('/').map(encodeURIComponent).join('/');
}

async function ensureProviderWebhook(db, repositoryUrl, callbackUrl, secret) {
  const provider = providerForRepositoryUrl(repositoryUrl, db);
  if (!provider) throw new Error('Automatic webhooks require a connected supported Git provider repository.');
  const definition = providerDefinition(provider, db);
  const token = getSecretSetting(db, definition.tokenKey, '');
  if (!token) throw new Error(`${definition.label} is not connected. Connect it from Settings → Administration first.`);
  const repoPath = repositoryPath(repositoryUrl, provider, db);
  const target = new URL(callbackUrl);
  if (!['http:', 'https:'].includes(target.protocol) || target.username || target.password) throw new Error('Webhook callback URL is invalid.');
  const webhookSecret = String(secret || '');
  if (!webhookSecret || webhookSecret.length > 8192 || /[\0\r\n]/.test(webhookSecret)) throw new Error('Webhook secret is invalid.');

  if (provider === 'github') {
    const base = `${definition.apiBaseUrl}/repos/${encodedRepositoryPath(repoPath)}/hooks`;
    const hooks = await providerRequest(definition, token, `${base}?per_page=100`);
    const existing = Array.isArray(hooks) ? hooks.find((hook) => String(hook?.config?.url || '') === target.toString()) : null;
    const body = { name: 'web', active: true, events: ['push'], config: { url: target.toString(), content_type: 'json', secret: webhookSecret, insecure_ssl: '0' } };
    const hook = existing ? await providerRequest(definition, token, `${base}/${encodeURIComponent(existing.id)}`, { method: 'PATCH', body }) : await providerRequest(definition, token, base, { method: 'POST', body });
    return { provider, action: existing ? 'updated' : 'created', id: String(hook?.id || existing?.id || ''), url: target.toString() };
  }

  if (provider === 'gitlab') {
    const project = encodeURIComponent(repoPath);
    const base = `${definition.apiBaseUrl}/projects/${project}/hooks`;
    const hooks = await providerRequest(definition, token, base);
    const existing = Array.isArray(hooks) ? hooks.find((hook) => String(hook?.url || '') === target.toString()) : null;
    const body = { url: target.toString(), token: webhookSecret, push_events: true, enable_ssl_verification: target.protocol === 'https:' };
    const hook = existing ? await providerRequest(definition, token, `${base}/${encodeURIComponent(existing.id)}`, { method: 'PUT', body }) : await providerRequest(definition, token, base, { method: 'POST', body });
    return { provider, action: existing ? 'updated' : 'created', id: String(hook?.id || existing?.id || ''), url: target.toString() };
  }

  if (provider === 'bitbucket') {
    const base = `${definition.apiBaseUrl}/repositories/${encodedRepositoryPath(repoPath)}/hooks`;
    const payload = await providerRequest(definition, token, `${base}?pagelen=100`);
    const hooks = Array.isArray(payload?.values) ? payload.values : [];
    const existing = hooks.find((hook) => String(hook?.url || '') === target.toString());
    const body = { description: 'SHAM deployment', url: target.toString(), active: true, events: ['repo:push'], secret: webhookSecret };
    const hook = existing ? await providerRequest(definition, token, `${base}/${encodeURIComponent(existing.uuid)}`, { method: 'PUT', body }) : await providerRequest(definition, token, base, { method: 'POST', body });
    return { provider, action: existing ? 'updated' : 'created', id: String(hook?.uuid || existing?.uuid || ''), url: target.toString() };
  }

  const base = `${definition.apiBaseUrl}/repos/${encodedRepositoryPath(repoPath)}/hooks`;
  const hooks = await providerRequest(definition, token, `${base}?limit=100`);
  const existing = Array.isArray(hooks) ? hooks.find((hook) => String(hook?.config?.url || hook?.config?.URL || '') === target.toString()) : null;
  const body = { type: 'gitea', active: true, events: ['push'], config: { url: target.toString(), content_type: 'json', secret: webhookSecret } };
  const hook = existing ? await providerRequest(definition, token, `${base}/${encodeURIComponent(existing.id)}`, { method: 'PATCH', body }) : await providerRequest(definition, token, base, { method: 'POST', body });
  return { provider, action: existing ? 'updated' : 'created', id: String(hook?.id || existing?.id || ''), url: target.toString() };
}

function applyGitProviderCredentials(db, repositoryUrl, environment) {
  const provider = providerForRepositoryUrl(repositoryUrl, db);
  if (!provider) return null;
  const definition = providerDefinition(provider, db);
  const token = getSecretSetting(db, definition.tokenKey, '');
  if (!token) return null;
  environment.GIT_TERMINAL_PROMPT = '0';
  environment.GIT_CONFIG_COUNT = '1';
  environment.GIT_CONFIG_KEY_0 = `http.${definition.baseUrl}/.extraHeader`;
  environment.GIT_CONFIG_VALUE_0 = `Authorization: ${definition.gitAuthorization(token)}`;
  return provider;
}

module.exports = {
  PROVIDERS, providerDefinition, providerStatuses, saveProviderToken, listProviderRepositories, providerForRepositoryUrl,
  providerCommitUrl, applyGitProviderCredentials, normalizeWebhookBaseUrl, ensureProviderWebhook, normalizeProviderBaseUrl
};
