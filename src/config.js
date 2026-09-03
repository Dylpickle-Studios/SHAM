const fs = require('node:fs');
const path = require('node:path');
const crypto = require('node:crypto');
const net = require('node:net');
const { isMainThread } = require('node:worker_threads');

const ROOT_DIR = path.resolve(__dirname, '..');
const DATA_DIR = path.resolve(process.env.SHAM_DATA_PATH || path.join(ROOT_DIR, 'data'));
const SITES_DIR = path.join(DATA_DIR, 'sites');
const PLUGINS_DIR = path.join(DATA_DIR, 'plugins');
const CERTBOT_DIR = path.join(DATA_DIR, 'certbot');
const SNAPSHOTS_DIR = path.join(DATA_DIR, 'snapshots');
const RELEASES_DIR = path.join(DATA_DIR, 'releases');
const PREVIEWS_DIR = path.join(DATA_DIR, 'previews');
const BACKUPS_DIR = path.join(DATA_DIR, 'backups');
const UPDATES_DIR = path.join(DATA_DIR, 'updates');
const APP_RUNTIME_DIR = path.join(DATA_DIR, 'app-runtime');
const APP_RELEASES_DIR = path.join(APP_RUNTIME_DIR, 'releases');
const ACTIVE_APP_PATH = path.join(APP_RUNTIME_DIR, 'active.json');
const SITE_DATA_DIR = path.join(DATA_DIR, 'site-data');
const TMP_ROOT_DIR = path.join(DATA_DIR, 'tmp');
const UPLOAD_TMP_DIR = path.join(TMP_ROOT_DIR, `process-${process.pid}`);

for (const directory of [DATA_DIR, SITES_DIR, PLUGINS_DIR, CERTBOT_DIR, SNAPSHOTS_DIR, RELEASES_DIR, PREVIEWS_DIR, BACKUPS_DIR, UPDATES_DIR, APP_RUNTIME_DIR, APP_RELEASES_DIR, SITE_DATA_DIR, TMP_ROOT_DIR]) {
  fs.mkdirSync(directory, { recursive: true });
}
for (const directory of [CERTBOT_DIR, SNAPSHOTS_DIR, BACKUPS_DIR, UPDATES_DIR, APP_RUNTIME_DIR, SITE_DATA_DIR, TMP_ROOT_DIR]) {
  try { fs.chmodSync(directory, 0o700); }
  catch { /* Read-only or non-POSIX storage may prevent tightening directory modes. */ }
}
if (isMainThread) {
  for (const entry of fs.readdirSync(TMP_ROOT_DIR, { withFileTypes: true })) {
    const match = entry.isDirectory() && /^process-(\d+)$/.exec(entry.name);
    if (!match) continue;
    const ownerPid = Number(match[1]);
    if (ownerPid !== process.pid) {
      try {
        process.kill(ownerPid, 0);
        continue;
      } catch (error) {
        if (error.code === 'EPERM') continue;
      }
    }
    const temporaryDirectory = path.join(TMP_ROOT_DIR, entry.name);
    try { fs.rmSync(temporaryDirectory, { recursive: true, force: true }); }
    catch { /* A concurrent process may own or remove this directory. */ }
  }
  fs.rmSync(UPLOAD_TMP_DIR, { recursive: true, force: true });
}
fs.mkdirSync(UPLOAD_TMP_DIR, { recursive: true, mode: 0o700 });
try { fs.chmodSync(UPLOAD_TMP_DIR, 0o700); } catch { /* Best effort on non-POSIX storage. */ }

function integerEnv(name, fallback, min, max) {
  const raw = process.env[name];
  if (raw === undefined || raw === '') return fallback;
  const normalized = String(raw).trim();
  if (!/^\d+$/.test(normalized)) {
    throw new Error(`${name} must be an integer between ${min} and ${max}.`);
  }
  const value = Number(normalized);
  if (!Number.isSafeInteger(value) || value < min || value > max) {
    throw new Error(`${name} must be an integer between ${min} and ${max}.`);
  }
  return value;
}

function booleanEnv(name, fallback = false) {
  const raw = process.env[name];
  if (raw === undefined || raw === '') return fallback;
  const normalized = String(raw).trim().toLowerCase();
  if (['1', 'true', 'yes', 'on'].includes(normalized)) return true;
  if (['0', 'false', 'no', 'off'].includes(normalized)) return false;
  throw new Error(`${name} must be true/false, yes/no, on/off, or 1/0.`);
}

function trustProxyEnv() {
  const raw = String(process.env.SHAM_TRUST_PROXY || 'loopback').trim();
  if (raw.toLowerCase() === 'true') return true;
  if (raw.toLowerCase() === 'false') return false;
  if (/^\d+$/.test(raw)) return Number(raw);
  return raw;
}

function publicOriginEnv() {
  const raw = String(process.env.SHAM_PUBLIC_ORIGIN || '').trim();
  if (!raw) return '';
  let parsed;
  try { parsed = new URL(raw); }
  catch { throw new Error('SHAM_PUBLIC_ORIGIN must be an absolute http:// or https:// URL.'); }
  if (!['http:', 'https:'].includes(parsed.protocol) || parsed.username || parsed.password || parsed.search || parsed.hash) {
    throw new Error('SHAM_PUBLIC_ORIGIN must be an absolute http:// or https:// URL without credentials, query, or fragment.');
  }
  if (parsed.pathname && parsed.pathname !== '/') {
    throw new Error('SHAM_PUBLIC_ORIGIN must not include a path.');
  }
  return parsed.origin;
}

function listEnv(name) {
  return String(process.env[name] || '')
    .split(/[\s,;]+/)
    .map((value) => value.trim())
    .filter(Boolean);
}

function cidrListEnv(name) {
  return listEnv(name).map((entry) => {
    const parts = entry.split('/');
    if (parts.length > 2 || !net.isIP(parts[0])) {
      throw new Error(`${name} contains an invalid IP address or CIDR range: ${entry}`);
    }
    if (parts.length === 2) {
      const max = net.isIP(parts[0]) === 4 ? 32 : 128;
      if (!/^\d+$/.test(parts[1]) || Number(parts[1]) < 0 || Number(parts[1]) > max) {
        throw new Error(`${name} contains an invalid CIDR prefix: ${entry}`);
      }
    }
    return entry;
  });
}

function loadJwtSecret() {
  if (process.env.SHAM_JWT_SECRET?.trim()) {
    const configured = process.env.SHAM_JWT_SECRET.trim();
    if (configured.length < 32) throw new Error('SHAM_JWT_SECRET must contain at least 32 characters.');
    return configured;
  }

  const secretPath = path.join(DATA_DIR, '.jwt-secret');
  if (fs.existsSync(secretPath)) {
    const stored = fs.readFileSync(secretPath, 'utf8').trim();
    if (stored.length < 32) throw new Error(`${secretPath} is missing or invalid.`);
    try { fs.chmodSync(secretPath, 0o600); }
    catch { /* Read-only storage may prevent tightening an existing file mode. */ }
    return stored;
  }

  const secret = crypto.randomBytes(48).toString('base64url');
  fs.writeFileSync(secretPath, `${secret}\n`, { mode: 0o600 });
  return secret;
}

module.exports = {
  ROOT_DIR,
  DATA_DIR,
  SITES_DIR,
  PLUGINS_DIR,
  CERTBOT_DIR,
  SNAPSHOTS_DIR,
  RELEASES_DIR,
  PREVIEWS_DIR,
  BACKUPS_DIR,
  UPDATES_DIR,
  APP_RUNTIME_DIR,
  APP_RELEASES_DIR,
  ACTIVE_APP_PATH,
  SITE_DATA_DIR,
  TMP_ROOT_DIR,
  UPLOAD_TMP_DIR,
  DB_PATH: path.join(DATA_DIR, 'sham.db'),
  DASHBOARD_HOST: process.env.SHAM_HOST || '127.0.0.1',
  DASHBOARD_PORT: integerEnv('SHAM_PORT', 8080, 1, 65535),
  DASHBOARD_SELF_SIGNED_HTTPS: booleanEnv('SHAM_SELF_SIGNED_HTTPS', false),
  OPENSSL_BIN: process.env.SHAM_OPENSSL_BIN || 'openssl',
  UPLOAD_LIMIT_BYTES: integerEnv('SHAM_UPLOAD_LIMIT_MB', 100, 1, 2048) * 1024 * 1024,
  UPLOAD_WORKERS: integerEnv('SHAM_UPLOAD_WORKERS', 2, 1, 16),
  UPLOAD_QUEUE_LIMIT: integerEnv('SHAM_UPLOAD_QUEUE_LIMIT', 16, 1, 256),
  EDITOR_LIMIT_BYTES: integerEnv('SHAM_EDITOR_LIMIT_MB', 2, 1, 32) * 1024 * 1024,
  NODE_START_TIMEOUT_MS: integerEnv('SHAM_NODE_START_TIMEOUT_SECONDS', 30, 5, 300) * 1000,
  NPM_INSTALL_TIMEOUT_MS: integerEnv('SHAM_NPM_INSTALL_TIMEOUT_SECONDS', 600, 30, 3600) * 1000,
  NPM_INSTALL_WORKERS: integerEnv('SHAM_NPM_INSTALL_WORKERS', 2, 1, 16),
  NPM_INSTALL_QUEUE_LIMIT: integerEnv('SHAM_NPM_INSTALL_QUEUE_LIMIT', 32, 1, 1000),
  HTTP_REQUEST_TIMEOUT_MS: integerEnv('SHAM_REQUEST_TIMEOUT_SECONDS', 300, 30, 3600) * 1000,
  STATS_FLUSH_INTERVAL_MS: integerEnv('SHAM_STATS_FLUSH_SECONDS', 2, 1, 60) * 1000,
  VISITOR_RETENTION_DAYS: integerEnv('SHAM_VISITOR_RETENTION_DAYS', 90, 1, 3650),
  MINIFY_MAX_BYTES: integerEnv('SHAM_MINIFY_MAX_MB', 5, 1, 64) * 1024 * 1024,
  MINIFY_CACHE_BYTES: integerEnv('SHAM_MINIFY_CACHE_MB', 32, 4, 512) * 1024 * 1024,
  MINIFY_WORKERS: integerEnv('SHAM_MINIFY_WORKERS', 2, 1, 16),
  MINIFY_QUEUE_LIMIT: integerEnv('SHAM_MINIFY_QUEUE_LIMIT', 64, 1, 1000),
  COMPRESSION_WORKERS: integerEnv('SHAM_COMPRESSION_WORKERS', 4, 1, 32),
  COMPRESSION_QUEUE_LIMIT: integerEnv('SHAM_COMPRESSION_QUEUE_LIMIT', 128, 1, 2000),
  VISITOR_PENDING_BUCKETS: integerEnv('SHAM_VISITOR_PENDING_BUCKETS', 50_000, 500, 2_000_000),
  AUTH_RATE_LIMIT_BUCKETS: integerEnv('SHAM_AUTH_RATE_LIMIT_BUCKETS', 10_000, 100, 1_000_000),
  FIREWALL_RATE_LIMIT_BUCKETS: integerEnv('SHAM_FIREWALL_RATE_LIMIT_BUCKETS', 50_000, 100, 2_000_000),
  INTEGRATION_TIMEOUT_MS: integerEnv('SHAM_INTEGRATION_TIMEOUT_SECONDS', 20, 5, 120) * 1000,
  PERFORMANCE_INTERVAL_MS: integerEnv('SHAM_PERFORMANCE_INTERVAL_SECONDS', 5, 1, 60) * 1000,
  PERFORMANCE_HISTORY_SAMPLES: integerEnv('SHAM_PERFORMANCE_HISTORY_SAMPLES', 720, 60, 10000),
  PERFORMANCE_SITE_CONCURRENCY: integerEnv('SHAM_PERFORMANCE_SITE_CONCURRENCY', 8, 1, 64),
  HEALTH_CHECK_CONCURRENCY: integerEnv('SHAM_HEALTH_CHECK_CONCURRENCY', 8, 1, 64),
  DEPENDENCY_SCAN_TIMEOUT_MS: integerEnv('SHAM_DEPENDENCY_SCAN_TIMEOUT_SECONDS', 120, 15, 1800) * 1000,
  DEPENDENCY_SCAN_WORKERS: integerEnv('SHAM_DEPENDENCY_SCAN_WORKERS', 1, 1, 8),
  DEPENDENCY_SCAN_QUEUE_LIMIT: integerEnv('SHAM_DEPENDENCY_SCAN_QUEUE_LIMIT', 16, 1, 256),
  SNAPSHOT_RETENTION: integerEnv('SHAM_SNAPSHOT_RETENTION', 10, 1, 100),
  SNAPSHOT_WORKERS: integerEnv('SHAM_SNAPSHOT_WORKERS', 1, 1, 8),
  SNAPSHOT_QUEUE_LIMIT: integerEnv('SHAM_SNAPSHOT_QUEUE_LIMIT', 8, 1, 128),
  PLUGIN_ACTION_TIMEOUT_MS: integerEnv('SHAM_PLUGIN_ACTION_TIMEOUT_SECONDS', 15, 1, 300) * 1000,
  PLUGIN_MAX_PENDING_ACTIONS: integerEnv('SHAM_PLUGIN_MAX_PENDING_ACTIONS', 32, 1, 10000),
  EDGE_HOST: process.env.SHAM_EDGE_HOST || '0.0.0.0',
  EDGE_HTTP_PORT: integerEnv('SHAM_EDGE_HTTP_PORT', 0, 0, 65535),
  EDGE_HTTPS_PORT: integerEnv('SHAM_EDGE_HTTPS_PORT', 0, 0, 65535),
  CERTBOT_BIN: process.env.SHAM_CERTBOT_BIN || 'certbot',
  CLOUDFLARED_BIN: process.env.SHAM_CLOUDFLARED_BIN || 'cloudflared',
  NEWT_BIN: process.env.SHAM_NEWT_BIN || 'newt',
  DOCKER_BIN: process.env.SHAM_DOCKER_BIN || 'docker',
  PACK_BIN: process.env.SHAM_PACK_BIN || 'pack',
  NIXPACKS_BIN: process.env.SHAM_NIXPACKS_BIN || 'nixpacks',
  DOCKER_INTERNAL_NETWORK: process.env.SHAM_DOCKER_INTERNAL_NETWORK || 'sham-internal',
  DOCKER_EGRESS_NETWORK: process.env.SHAM_DOCKER_EGRESS_NETWORK || '',
  // The Runtime Agent owns the Docker socket; the control plane only ever
  // talks to it over this local Unix socket with a shared, generated token.
  RUNTIME_AGENT_SOCKET_PATH: process.env.SHAM_RUNTIME_AGENT_SOCKET || path.join(DATA_DIR, 'runtime-agent', 'agent.sock'),
  RUNTIME_AGENT_TOKEN_PATH: process.env.SHAM_RUNTIME_AGENT_TOKEN_PATH || path.join(DATA_DIR, 'runtime-agent', 'agent.token'),
  RUNTIME_AGENT_REQUEST_TIMEOUT_MS: integerEnv('SHAM_RUNTIME_AGENT_TIMEOUT_SECONDS', 120, 5, 3600) * 1000,
  GIT_BIN: process.env.SHAM_GIT_BIN || 'git',
  TAR_BIN: process.env.SHAM_TAR_BIN || 'tar',
  RESTIC_BIN: process.env.SHAM_RESTIC_BIN || 'restic',
  AWS_BIN: process.env.SHAM_AWS_BIN || 'aws',
  SFTP_BIN: process.env.SHAM_SFTP_BIN || 'sftp',
  ANUBIS_IMAGE: process.env.SHAM_ANUBIS_IMAGE || 'ghcr.io/techarohq/anubis:v1.26.2',
  JOB_POLL_INTERVAL_MS: integerEnv('SHAM_JOB_POLL_SECONDS', 15, 5, 300) * 1000,
  JOB_TIMEOUT_MS: integerEnv('SHAM_JOB_TIMEOUT_SECONDS', 900, 5, 86400) * 1000,
  BACKUP_TIMEOUT_MS: integerEnv('SHAM_BACKUP_TIMEOUT_SECONDS', 3600, 30, 86400) * 1000,
  GIT_TIMEOUT_MS: integerEnv('SHAM_GIT_TIMEOUT_SECONDS', 600, 30, 3600) * 1000,
  PREVIEW_TTL_HOURS: integerEnv('SHAM_PREVIEW_TTL_HOURS', 24, 1, 720),
  JWT_SECRET: loadJwtSecret(),
  PUBLIC_ORIGIN: publicOriginEnv(),
  TRUST_PROXY: trustProxyEnv(),
  TRUSTED_EDGE_PROXIES: cidrListEnv('SHAM_TRUSTED_EDGE_PROXIES')
};
