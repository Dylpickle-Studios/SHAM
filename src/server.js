// @ts-nocheck -- not part of this session's checkJs rollout yet.
// This file still has genuine `tsc --noEmit` findings (mostly narrow
// `let x = null`-style inference and untyped Express handlers, the same
// patterns already fixed across most of src/) that need real per-file
// JSDoc work to resolve, not a suppression. Tracked as follow-up work;
// see tsconfig.json and docs/development.md. Do not add more files here
// without a similar comment and a plan to remove it.
require('./env');

const fs = require('node:fs');
const path = require('node:path');
const crypto = require('node:crypto');
const net = require('node:net');
const http = require('node:http');
const https = require('node:https');
const express = require('express');
const multer = require('multer');

const {
  ROOT_DIR,
  DATA_DIR,
  SITES_DIR,
  UPLOAD_TMP_DIR,
  DASHBOARD_HOST,
  DASHBOARD_PORT,
  DASHBOARD_SELF_SIGNED_HTTPS,
  OPENSSL_BIN,
  UPLOAD_LIMIT_BYTES,
  EDITOR_LIMIT_BYTES,
  HTTP_REQUEST_TIMEOUT_MS,
  TRUST_PROXY,
  EDGE_HTTP_PORT,
  EDGE_HTTPS_PORT,
  PUBLIC_ORIGIN
} = require('./config');
const { db, getSetting, setSetting, audit: writeAudit } = require('./db');
const {
  normalizeUsername,
  hashPassword,
  verifyPassword,
  issueToken,
  issueMfaToken,
  verifyMfaToken,
  setAuthCookie,
  clearAuthCookie,
  optionalAuth,
  requireAuth,
  requireAdmin,
  sameOriginGuard,
  createRateLimiter,
  tokenHash,
  revokeCurrentSession,
  rotateSessionVersion
} = require('./security');
const { bool, validateSiteInput, safeRelativePath } = require('./validation');
const { auditObfuscationCompatibility } = require('./obfuscation-audit');
const { installUploadAsync, stopUploadWorkers, MAX_FILES } = require('./upload-utils');
const SITE_FORM_FIELD_LIMIT = 192;
const { CappedDiskStorage, cleanupUploadedFiles } = require('./upload-storage');
const {
  listSiteFilesAsync,
  readTextFileAsync,
  writeTextFileAsync,
  replaceSingleFileFromPathAsync,
  deleteSingleFileAsync,
  stageSingleFileDeletionAsync
} = require('./file-utils');
const { SiteManager, hydrateSite, realFileInside } = require('./site-manager');
const {
  syncCloudflareRecord,
  syncCloudflareFirewall,
  issueCertificate,
  renewalNeedsPort80,
  renewCertificates,
  hasCertificate,
  writeCloudflareCredentials,
  stopIntegrationProcesses
} = require('./integrations');
const { PluginManager } = require('./plugin-manager');
const { getSecretSetting, setSecretSetting, rotateMasterKey } = require('./secret-store');
const { generateTotpSetup, generateRecoveryCodes, verifyTotp, consumeRecoveryCode, enableTotp, disableTotp, userTotpSecret } = require('./mfa');
const { registrationOptions, verifyRegistration, assertionOptions, verifyAssertion } = require('./webauthn');
const { dashboardTlsOptions } = require('./dashboard-tls');
const { SnapshotManager } = require('./snapshot-manager');
const { DependencyScanner } = require('./dependency-scanner');
const { PerformanceMonitor } = require('./performance-monitor');
const { EdgeProxy } = require('./edge-proxy');
const { validatePluginArchiveFile } = require('./plugin-archive');
const { OperationsManager } = require('./operations-manager');
const { UpdateManager } = require('./update-manager');
const { CloudflareTunnelManager, DatabaseTunnelSettingsStore, SiteCloudflareTunnelRegistry } = require('./cloudflare-tunnel');
const { CloudflareTunnelControlPlane } = require('./cloudflare-tunnel-control-plane');
const { registerSiteRoutes } = require('./routes/sites');
const { registerAdminRoutes } = require('./routes/admin');
const { registerOperationsRoutes } = require('./routes/operations');
const { normalizeIssuer: normalizeOidcIssuer, beginAuthorization, completeAuthorization } = require('./oidc');
const { CloudflareReconciler } = require('./cloudflare-reconciler');

const app = express();
const DEPLOY_WEBHOOK_DUMMY_SECRET = crypto.randomBytes(32);
const manager = new SiteManager(db);
const pluginManager = new PluginManager(db, console, manager);
const snapshotManager = new SnapshotManager(db);
const dependencyScanner = new DependencyScanner(db);
const performanceMonitor = new PerformanceMonitor({ db, manager, snapshotManager, dependencyScanner });
const edgeProxy = new EdgeProxy({ db, manager });
const operationsManager = new OperationsManager({ db, manager, snapshotManager, edgeProxy });
const updateManager = new UpdateManager({ db });
const legacyCloudflareTunnel = new CloudflareTunnelManager({
  settingsStore: new DatabaseTunnelSettingsStore(db),
  log: (level, message) => manager.log(null, level, `[Legacy tunnel] ${message}`)
});
const cloudflareTunnels = new SiteCloudflareTunnelRegistry({
  db,
  sharedManager: legacyCloudflareTunnel,
  log: (siteId, level, message) => manager.log(siteId, level, message)
});
const cloudflareReconciler = new CloudflareReconciler({ db, manager, getSetting });
manager.setOperations(operationsManager);
edgeProxy.setOperations(operationsManager);
const publicDir = path.join(ROOT_DIR, 'public');
pluginManager.loadEnabled();

app.set('trust proxy', TRUST_PROXY);
app.disable('x-powered-by');
app.use((req, res, next) => {
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('X-Frame-Options', 'DENY');
  res.setHeader('Referrer-Policy', 'no-referrer');
  res.setHeader('Permissions-Policy', 'camera=(), microphone=(), geolocation=()');
  res.setHeader(
    'Content-Security-Policy',
    "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; connect-src 'self'; object-src 'none'; base-uri 'none'; frame-ancestors 'none'; form-action 'self'"
  );
  if (req.path.startsWith('/api/')) res.setHeader('Cache-Control', 'no-store');
  next();
});
app.use(sameOriginGuard);
app.use(express.json({
  limit: `${Math.max(EDITOR_LIMIT_BYTES + 1024 * 1024, 3 * 1024 * 1024)}b`,
  verify: (req, _res, buffer) => { if (req.path.startsWith('/api/hooks/deploy/')) req.rawBody = Buffer.from(buffer); }
}));
app.use(express.urlencoded({ extended: false, limit: '2mb' }));

// Version 1 is a compatibility-preserving alias of the established /api
// surface. Keep the original URLs for existing scripts, but normalize v1
// errors to the documented structured shape without changing legacy bodies.
function apiV1Compatibility(req, res, next) {
  if (!req.url.startsWith('/api/v1/') && req.url !== '/api/v1') return next();
  const suffix = req.url.slice('/api/v1'.length) || '/';
  req.url = `/api${suffix}`;
  res.setHeader('API-Version', '1');
  const json = res.json.bind(res);
  res.json = (body) => {
    if (!body || typeof body !== 'object' || typeof body.error !== 'string') return json(body);
    const status = res.statusCode;
    const code = status === 401 ? 'UNAUTHENTICATED'
      : status === 403 ? 'FORBIDDEN'
        : status === 404 ? 'NOT_FOUND'
          : status === 409 ? 'CONFLICT'
            : status === 413 ? 'PAYLOAD_TOO_LARGE'
              : status === 429 ? 'RATE_LIMITED'
                : 'INVALID_REQUEST';
    return json({ ...body, error: { code, message: body.error } });
  };
  return next();
}
app.use(apiV1Compatibility);

const authLimiter = createRateLimiter({ windowMs: 15 * 60 * 1000, max: 30 });
const stepUpLimiter = createRateLimiter({ windowMs: 15 * 60 * 1000, max: 20 });
const webhookLimiter = createRateLimiter({ windowMs: 15 * 60 * 1000, max: 120 });
const upload = multer({
  storage: new CappedDiskStorage(UPLOAD_TMP_DIR, UPLOAD_LIMIT_BYTES),
  limits: {
    fileSize: UPLOAD_LIMIT_BYTES,
    files: MAX_FILES,
    // The site wizard carries runtime, deployment, security, and monitoring
    // configuration alongside uploaded files. Keep this bounded, but leave
    // enough headroom for future settings so folder uploads do not trip
    // Multer's field-count guard before file handling begins.
    fields: SITE_FORM_FIELD_LIMIT,
    parts: MAX_FILES + SITE_FORM_FIELD_LIMIT,
    fieldNameSize: 100,
    fieldNestingDepth: 0,
    fieldSize: Math.max(EDITOR_LIMIT_BYTES, 2 * 1024 * 1024)
  }
});
const updateUpload = multer({
  storage: new CappedDiskStorage(UPLOAD_TMP_DIR, 512 * 1024 * 1024),
  limits: { fileSize: 512 * 1024 * 1024, files: 1, fields: 4, parts: 5, fieldNameSize: 100, fieldNestingDepth: 0, fieldSize: 64 * 1024 }
});
const pluginUpload = multer({
  storage: new CappedDiskStorage(UPLOAD_TMP_DIR, 20 * 1024 * 1024),
  limits: { fileSize: 20 * 1024 * 1024, files: 1, fields: 8, parts: 9, fieldNameSize: 100, fieldNestingDepth: 0, fieldSize: 64 * 1024 }
});

const receiveWebsite = upload.fields([
  { name: 'archive', maxCount: 1 },
  { name: 'files', maxCount: MAX_FILES }
]);
const receiveSingleFile = upload.single('file');

function uploadSizeGuard(req, res, next) {
  const contentLength = Number(req.get('content-length') || 0);
  const multipartAllowance = 10 * 1024 * 1024;
  if (contentLength && contentLength > UPLOAD_LIMIT_BYTES + multipartAllowance) {
    return res.status(413).json({ error: 'Upload exceeds the configured size limit.' });
  }
  next();
}

function multipart(handler) {
  return (req, res, next) => {
    let cleaned = false;
    const cleanup = () => {
      if (cleaned) return;
      cleaned = true;
      cleanupUploadedFiles(req);
    };
    res.once('finish', cleanup);
    res.once('close', cleanup);
    handler(req, res, (error) => {
      if (!error) return next();
      cleanup();
      const message = error instanceof multer.MulterError ? `Upload rejected: ${error.message}` : error.message;
      res.status(error?.code === 'LIMIT_FILE_SIZE' ? 413 : 400).json({ error: message });
    });
  };
}

function recordAudit(userId, action, detail = null) {
  try {
    writeAudit(userId, action, detail);
  } catch (error) {
    manager.log(null, 'error', `Could not write audit event “${action}”: ${error.message}`);
  }
}

let certificateOperationActive = false;
function acquireCertificateOperation(res) {
  if (certificateOperationActive) {
    res.status(409).json({ error: 'Another certificate operation is already running.' });
    return false;
  }
  certificateOperationActive = true;
  return true;
}
function releaseCertificateOperation() { certificateOperationActive = false; }

let pluginMutationTail = Promise.resolve();
async function serializePluginMutation(req, res, next) {
  if (['GET', 'HEAD', 'OPTIONS'].includes(req.method)) return next();
  const previous = pluginMutationTail;
  let release;
  const gate = new Promise((resolve) => { release = resolve; });
  pluginMutationTail = previous.catch(() => {}).then(() => gate);
  await previous.catch(() => {});
  let released = false;
  const finish = () => {
    if (released) return;
    released = true;
    release();
  };
  res.once('finish', finish);
  res.once('close', finish);
  next();
}

const siteMutationTails = new Map();
async function serializeSiteMutation(req, res, next) {
  if (['GET', 'HEAD', 'OPTIONS'].includes(req.method)) return next();
  const siteId = Number(req.params.id);
  if (!Number.isSafeInteger(siteId) || siteId < 1) return next();

  const previous = siteMutationTails.get(siteId) || Promise.resolve();
  let release;
  const gate = new Promise((resolve) => { release = resolve; });
  const tail = previous.catch(() => {}).then(() => gate);
  siteMutationTails.set(siteId, tail);
  await previous.catch(() => {});

  let released = false;
  const finish = () => {
    if (released) return;
    released = true;
    release();
    if (siteMutationTails.get(siteId) === tail) siteMutationTails.delete(siteId);
  };
  res.once('finish', finish);
  res.once('close', finish);
  next();
}

function publicUser(user) {
  return user ? {
    id: user.id,
    username: user.username,
    role: user.role,
    active: Boolean(user.active),
    totpEnabled: Boolean(user.totp_enabled),
    passkeyCount: Number(user.passkey_count || 0),
    hasLocalPassword: user.password_configured !== undefined ? Boolean(user.password_configured) : true,
    createdAt: user.created_at
  } : null;
}

function userCount() {
  return db.prepare('SELECT COUNT(*) AS count FROM users').get().count;
}

function registrationEnabled() {
  return userCount() === 0;
}

function securityUser(id) {
  return db.prepare(`SELECT users.*, (SELECT COUNT(*) FROM passkeys WHERE user_id = users.id) AS passkey_count FROM users WHERE users.id = ?`).get(id);
}

function requestOrigin(req) {
  return PUBLIC_ORIGIN || new URL(`${req.protocol}://${req.get('host')}`).origin;
}

function requestRpId(req) {
  const host = String(new URL(requestOrigin(req)).hostname || '').trim().toLowerCase();
  if (!host) throw new Error('The dashboard hostname is unavailable for passkey verification.');
  return host;
}

function createChallenge(userId, purpose, challenge, rpId, origin, ttlMs = 5 * 60_000) {
  db.prepare("DELETE FROM webauthn_challenges WHERE expires_at < ?").run(Date.now());
  db.prepare('DELETE FROM webauthn_challenges WHERE user_id = ? AND purpose = ?').run(userId, purpose);
  const id = crypto.randomUUID();
  db.prepare('INSERT INTO webauthn_challenges (id, user_id, purpose, challenge, rp_id, origin, expires_at) VALUES (?, ?, ?, ?, ?, ?, ?)')
    .run(id, userId, purpose, challenge, rpId, origin, Date.now() + ttlMs);
  return id;
}

function consumeChallenge(id, userId, purpose) {
  const row = db.prepare('SELECT * FROM webauthn_challenges WHERE id = ? AND user_id = ? AND purpose = ?').get(String(id || ''), userId, purpose);
  db.prepare('DELETE FROM webauthn_challenges WHERE id = ? AND user_id = ? AND purpose = ?').run(String(id || ''), userId, purpose);
  if (!row || row.expires_at < Date.now()) throw new Error('The authentication challenge expired. Start again.');
  return row;
}

function uniqueSlug(base, excludedId = null) {
  let candidate = base;
  let suffix = 2;
  const query = excludedId
    ? db.prepare('SELECT 1 FROM sites WHERE slug = ? AND id != ?')
    : db.prepare('SELECT 1 FROM sites WHERE slug = ?');
  while (excludedId ? query.get(candidate, excludedId) : query.get(candidate)) {
    candidate = `${base.slice(0, 54)}-${suffix++}`;
  }
  return candidate;
}

function checkPort(port, excludedId = null) {
  if (port === DASHBOARD_PORT) throw new Error(`Port ${port} is reserved by the SHAM dashboard.`);
  if ([EDGE_HTTP_PORT, EDGE_HTTPS_PORT].includes(port) && port > 0) throw new Error(`Port ${port} is reserved by the SHAM shared edge proxy.`);
  const row = excludedId
    ? db.prepare('SELECT id, name FROM sites WHERE port = ? AND id != ?').get(port, excludedId)
    : db.prepare('SELECT id, name FROM sites WHERE port = ?').get(port);
  if (row) throw new Error(`Port ${port} is already assigned to “${row.name}”.`);
  const sites = excludedId
    ? db.prepare('SELECT name, additional_listeners_json FROM sites WHERE id != ?').all(excludedId)
    : db.prepare('SELECT name, additional_listeners_json FROM sites').all();
  for (const site of sites) {
    let listeners = [];
    try { listeners = JSON.parse(site.additional_listeners_json || '[]'); } catch { /* Ignore malformed legacy JSON. */ }
    if (Array.isArray(listeners) && listeners.some((listener) => Number(listener?.port) === Number(port))) {
      throw new Error(`Port ${port} is already assigned to private listener on “${site.name}”.`);
    }
  }
}

function checkAdditionalListenerPorts(listeners, excludedId = null) {
  for (const listener of listeners || []) checkPort(Number(listener.port), excludedId);
}

function nextAvailableSitePort() {
  const used = new Set();
  for (const row of db.prepare('SELECT port, additional_listeners_json FROM sites').all()) {
    used.add(Number(row.port));
    try { for (const listener of JSON.parse(row.additional_listeners_json || '[]')) used.add(Number(listener?.port)); } catch { /* Ignore malformed legacy JSON. */ }
  }
  for (let port = 4100; port <= 65535; port += 1) {
    if (port === DASHBOARD_PORT || port === EDGE_HTTP_PORT || port === EDGE_HTTPS_PORT || used.has(port)) continue;
    return port;
  }
  throw new Error('No free site port is available.');
}

function writeSiteConfig(id, config) {
  db.prepare(`
    UPDATE sites SET
      name = ?, slug = ?, bind_host = ?, port = ?, runtime_type = ?, runtime_preset = ?, start_command = ?, runtime_port_env = ?, additional_listeners_json = ?, working_directory = ?, proxy_target = ?, proxy_host_header = ?, proxy_timeout_ms = ?, install_command = ?, build_command = ?, build_output_dir = ?, entry_file = ?,
      node_entry = ?, install_dependencies = ?, minify = ?, obfuscate = ?, obfuscation_risk_acknowledged = ?, domain_only = ?, spa_fallback = ?,
      cache_seconds = ?, headers_json = ?, domain = ?, ssl_enabled = ?,
      cloudflare_enabled = ?, firewall_enabled = ?, firewall_json = ?, compression = ?, security_preset = ?, csp = ?,
      health_check_path = ?, health_check_interval = ?, health_check_type = ?, health_check_command = ?, health_check_status_min = ?, health_check_status_max = ?, restart_policy = ?, max_restarts = ?, memory_limit_mb = ?,
      max_connections = ?, edge_enabled = ?, runtime_isolation = ?, container_image = ?, container_mode = ?, container_port = ?, dockerfile_path = ?, compose_file = ?, compose_service = ?, buildpack_builder = ?, readiness_type = ?, readiness_path = ?, readiness_command = ?, readiness_status_min = ?, readiness_status_max = ?, startup_timeout_seconds = ?, shutdown_grace_seconds = ?, blue_green_drain_seconds = ?, manifest_enabled = ?, cloudflare_auto_sync = ?, cpu_limit = ?, pids_limit = ?,
      outbound_network = ?, anubis_enabled = ?, anubis_preset = ?, anubis_difficulty = ?, anubis_policy = ?,
      maintenance_enabled = ?, maintenance_html = ?, redirects_json = ?, error_pages_json = ?, cache_rules_json = ?,
      release_mode = ?, git_url = ?, git_branch = ?, preview_domain = ?, updated_at = CURRENT_TIMESTAMP
    WHERE id = ?
  `).run(
    config.name,
    config.slug,
    config.bind_host,
    config.port,
    config.runtime_type,
    config.runtime_preset,
    config.start_command,
    config.runtime_port_env,
    JSON.stringify(config.additional_listeners || []),
    config.working_directory,
    config.proxy_target,
    config.proxy_host_header,
    config.proxy_timeout_ms,
    config.install_command,
    config.build_command,
    config.build_output_dir,
    config.entry_file,
    config.node_entry,
    Number(config.install_dependencies),
    Number(config.minify),
    Number(config.obfuscate),
    Number(config.obfuscation_risk_acknowledged),
    Number(config.domain_only),
    Number(config.spa_fallback),
    config.cache_seconds,
    JSON.stringify(config.headers || {}),
    config.domain,
    Number(config.ssl_enabled),
    Number(config.cloudflare_enabled),
    Number(config.firewall_enabled),
    JSON.stringify(config.firewall || {}),
    Number(config.compression),
    config.security_preset,
    config.csp,
    config.health_check_path,
    config.health_check_interval,
    config.health_check_type,
    config.health_check_command,
    config.health_check_status_min,
    config.health_check_status_max,
    config.restart_policy,
    config.max_restarts,
    config.memory_limit_mb,
    config.max_connections,
    Number(config.edge_enabled),
    config.runtime_isolation,
    config.container_image,
    config.container_mode,
    config.container_port,
    config.dockerfile_path,
    config.compose_file,
    config.compose_service,
    config.buildpack_builder,
    config.readiness_type,
    config.readiness_path,
    config.readiness_command,
    config.readiness_status_min,
    config.readiness_status_max,
    config.startup_timeout_seconds,
    config.shutdown_grace_seconds,
    config.blue_green_drain_seconds,
    Number(config.manifest_enabled),
    Number(config.cloudflare_auto_sync),
    config.cpu_limit,
    config.pids_limit,
    Number(config.outbound_network),
    Number(config.anubis_enabled),
    config.anubis_preset,
    config.anubis_difficulty,
    config.anubis_policy,
    Number(config.maintenance_enabled),
    config.maintenance_html,
    JSON.stringify(config.redirects || []),
    JSON.stringify(config.error_pages || {}),
    JSON.stringify(config.cache_rules || []),
    Number(config.release_mode),
    config.git_url,
    config.git_branch,
    config.preview_domain,
    id
  );
}

function requiredSiteFile(config) {
  if (config.runtime_type === 'proxy') return null;
  if (config.runtime_type === 'node' && !config.start_command) return config.node_entry;
  if (config.runtime_type === 'static') return config.entry_file;
  return null;
}

function obfuscationWarning(report) {
  if (!report) return 'JavaScript obfuscation is enabled. Test the deployed site because static analysis cannot prove runtime compatibility.';
  if (report.warningCount || report.skippedFiles?.length) {
    return `JavaScript obfuscation is enabled. The compatibility report found ${report.warningCount} warning${report.warningCount === 1 ? '' : 's'}${report.skippedFiles?.length ? ` and skipped ${report.skippedFiles.length} file(s)` : ''}. Review the report and test the deployed site.`;
  }
  return 'JavaScript obfuscation is enabled. No known risky patterns were found, but runtime compatibility still cannot be guaranteed; test the deployed site.';
}

async function safeObfuscationWarning(site) {
  try { return obfuscationWarning(await auditObfuscationCompatibility(site)); }
  catch (error) { return `JavaScript obfuscation is enabled, but SHAM could not complete the compatibility report: ${error.message}. Test the deployed site.`; }
}

function uploadParts(req) {
  const archive = req.files?.archive?.[0] || null;
  const files = req.files?.files || [];
  let relativePaths = [];
  if (req.body.relativePaths) {
    try { relativePaths = JSON.parse(req.body.relativePaths); }
    catch { throw new Error('Upload path manifest is not valid JSON.'); }
  }
  return { archive, files, relativePaths };
}

function siteRows() {
  return db.prepare(`
    SELECT sites.*, users.username AS created_by_username
    FROM sites
    LEFT JOIN users ON users.id = sites.created_by
    ORDER BY sites.pinned DESC, sites.created_at DESC, sites.id DESC
  `).all().map((row) => manager.decorate(hydrateSite(row)));
}

function getSiteOr404(req, res) {
  const site = manager.getSite(Number(req.params.id));
  if (!site) {
    res.status(404).json({ error: 'Site not found.' });
    return null;
  }
  return site;
}

function activeAdminCount() {
  return db.prepare("SELECT COUNT(*) AS count FROM users WHERE role = 'admin' AND active = 1").get().count;
}

function oidcSettings() {
  return {
    enabled: getSetting('oidc_enabled', '0') === '1',
    issuer: getSetting('oidc_issuer', ''),
    clientId: getSetting('oidc_client_id', ''),
    clientSecretConfigured: Boolean(getSecretSetting(db, 'oidc_client_secret', '')),
    autoProvision: getSetting('oidc_auto_provision', '0') === '1',
    defaultRole: getSetting('oidc_default_role', 'user') === 'admin' ? 'admin' : 'user'
  };
}

function integrationSettings() {
  return {
    cloudflareTokenConfigured: Boolean(getSecretSetting(db, 'cloudflare_api_token', '')),
    cloudflareZoneId: getSetting('cloudflare_zone_id', ''),
    cloudflareTargetIp: getSetting('cloudflare_target_ip', ''),
    certbotEmail: getSetting('certbot_email', ''),
    cloudflareReconcileEnabled: getSetting('cloudflare_reconcile_enabled', '0') === '1',
    cloudflareReconcileMinutes: Number(getSetting('cloudflare_reconcile_minutes', '15')) || 15,
    cloudflareTunnelAccountId: getSetting('cloudflare_tunnel_account_id', ''),
    cloudflareTunnelApiTokenConfigured: Boolean(getSecretSetting(db, 'cloudflare_tunnel_api_token', ''))
  };
}

function cloudflareTunnelControlPlane() {
  const accountId = getSetting('cloudflare_tunnel_account_id', '');
  const apiToken = getSecretSetting(db, 'cloudflare_tunnel_api_token', '');
  if (!accountId || !apiToken) throw new Error('Configure a dedicated Cloudflare Tunnel account ID and management API token first.');
  return new CloudflareTunnelControlPlane({ accountId, apiToken });
}

function securitySettings() {
  let trustedKeys;
  try { trustedKeys = JSON.parse(getSetting('plugin_trusted_keys_json', '[]')); } catch { trustedKeys = []; }
  return {
    allowUnsignedPlugins: getSetting('allow_unsigned_plugins', '0') === '1',
    pluginTrustedKeys: Array.isArray(trustedKeys) ? trustedKeys : [],
    logRetentionDays: Number(getSetting('log_retention_days', '30')) || 30,
    visitorPrivacyMode: getSetting('visitor_privacy_mode', 'none'),
    alertCpuPercent: Number(getSetting('alert_cpu_percent', '90')) || 90,
    alertEventLoopMs: Number(getSetting('alert_event_loop_ms', '250')) || 250,
    alertDiskPercent: Number(getSetting('alert_disk_percent', '90')) || 90,
    alertTrafficMultiplier: Number(getSetting('alert_traffic_multiplier', '5')) || 5,
    alertErrorPercent: Number(getSetting('alert_error_percent', '25')) || 25,
    masterKeyExternal: Boolean(process.env.SHAM_MASTER_KEY),
    edge: edgeProxy.status()
  };
}

function integerSetting(value, name, minimum, maximum) {
  const number = Number(value);
  if (!Number.isInteger(number) || number < minimum || number > maximum) throw new Error(`${name} must be between ${minimum} and ${maximum}.`);
  return number;
}

function snapshotLabel(value, fallback = '') {
  return String(value || fallback).trim().slice(0, 120);
}

async function stopRunningSitesOnPort(port) {
  const stopped = [];
  for (const row of db.prepare('SELECT id FROM sites WHERE port = ?').all(port)) {
    if (!manager.statusFor(row.id).running) continue;
    await manager.stop(row.id);
    stopped.push(row.id);
  }
  return stopped;
}

async function restoreEnabledSites(ids) {
  const warnings = [];
  for (const id of [...new Set(ids)]) {
    const site = manager.getSite(id);
    if (!site?.enabled || manager.statusFor(id, site).running) continue;
    try { await manager.start(id); }
    catch (error) {
      const warning = `Site ${id} could not be restored after the certificate operation: ${error.message}`;
      warnings.push(warning);
      manager.log(id, 'error', warning);
    }
  }
  return warnings;
}

const CLOUDFLARE_HTTP_PORTS = new Set([80, 8080, 8880, 2052, 2082, 2086, 2095]);
const CLOUDFLARE_HTTPS_PORTS = new Set([443, 2053, 2083, 2087, 2096, 8443]);

function cloudflarePortWarning(site) {
  if (site.edge_enabled && ((site.ssl_enabled && EDGE_HTTPS_PORT > 0) || (!site.ssl_enabled && EDGE_HTTP_PORT > 0))) return null;
  const supported = site.ssl_enabled ? CLOUDFLARE_HTTPS_PORTS : CLOUDFLARE_HTTP_PORTS;
  if (supported.has(Number(site.port))) return null;
  const protocol = site.ssl_enabled ? 'HTTPS' : 'HTTP';
  return `The DNS record is proxied, but port ${site.port} is not a standard Cloudflare ${protocol} proxy port. Use a supported port or place a reverse proxy on 80/443 before relying on proxied traffic.`;
}

const routeContext = {
  app, requireAuth, requireAdmin, db, manager, cloudflareTunnels, net, recordAudit, performanceMonitor,
  uploadSizeGuard, multipart, receiveWebsite, receiveSingleFile, nextAvailableSitePort, validateSiteInput, uniqueSlug,
  checkPort, checkAdditionalListenerPorts, installUploadAsync, SITES_DIR, fs, path, operationsManager, bool, writeSiteConfig, requiredSiteFile,
  safeObfuscationWarning, uploadParts, auditObfuscationCompatibility, safeRelativePath, listSiteFilesAsync,
  readTextFileAsync, writeTextFileAsync, replaceSingleFileFromPathAsync, deleteSingleFileAsync, stageSingleFileDeletionAsync,
  snapshotManager, dependencyScanner, edgeProxy, getSetting, siteRows, getSiteOr404,
  hasCertificate, realFileInside, cloudflarePortWarning, snapshotLabel
};

const adminRouteContext = {
  app, requireAuth, requireAdmin, pluginManager, publicUser, multipart, pluginUpload, validatePluginArchiveFile, bool,
  cleanupUploadedFiles, serializePluginMutation, integrationSettings, securitySettings, oidcSettings, normalizeOidcIssuer, normalizeUsername, getSetting, setSetting, setSecretSetting,
  getSecretSetting, rotateMasterKey, verifyPassword, hashPassword, rotateSessionVersion, stepUpLimiter, writeCloudflareCredentials, recordAudit, manager, siteRows, getSiteOr404,
  syncCloudflareRecord, cloudflarePortWarning, syncCloudflareFirewall, acquireCertificateOperation, releaseCertificateOperation,
  stopRunningSitesOnPort, renewalNeedsPort80, issueCertificate, hasCertificate, restoreEnabledSites, renewCertificates, db,
  activeAdminCount, registrationEnabled, integerSetting, net, crypto, edgeProxy, EDGE_HTTP_PORT, DASHBOARD_PORT
};

const operationsRouteContext = {
  app, requireAuth, requireAdmin, webhookLimiter, serializeSiteMutation, db, crypto, DEPLOY_WEBHOOK_DUMMY_SECRET,
  operationsManager, manager, recordAudit, getSiteOr404, bool, validateSiteInput, uniqueSlug, writeSiteConfig,
  getSecretSetting, setSecretSetting, getSetting, setSetting, cloudflareTunnels, legacyCloudflareTunnel, cloudflareTunnelControlPlane, updateManager, verifyPassword, stepUpLimiter,
  multipart, updateUpload, cleanupUploadedFiles
};

app.get('/api/health', (_req, res) => {
  res.json({ ok: true });
});

app.get('/api/bootstrap', optionalAuth, (req, res) => {
  const count = userCount();
  res.json({
    needsSetup: count === 0,
    registrationEnabled: count === 0 || registrationEnabled(),
    authenticated: Boolean(req.user),
    user: publicUser(req.user ? securityUser(req.user.id) : null),
    locale: getSetting('instance_locale', 'en'),
    setupCompleted: req.user?.role !== 'admin' || getSetting('setup_completed', '0') === '1',
    oidcEnabled: getSetting('oidc_enabled', '0') === '1' && Boolean(getSetting('oidc_issuer', '')) && Boolean(getSetting('oidc_client_id', '')),
    capabilities: req.user ? operationsManager.capabilities() : undefined,
    secureContext: req.secure || PUBLIC_ORIGIN.startsWith('https://')
  });
});

function publicStatusSnapshot() {
  const allowedStatuses = new Set(['healthy', 'online', 'degraded', 'starting', 'offline']);
  const sites = db.prepare("SELECT id, name FROM sites WHERE enabled = 1 ORDER BY name COLLATE NOCASE").all().map((site) => {
    const runtime = manager.statusFor(site.id, site);
    const candidate = runtime.running && runtime.health?.status !== 'unhealthy' ? runtime.health?.status || 'online' : 'offline';
    return { name: site.name, status: allowedStatuses.has(candidate) ? candidate : 'offline' };
  });
  const available = sites.filter((site) => ['healthy', 'online'].includes(site.status)).length;
  const offline = sites.filter((site) => site.status === 'offline').length;
  const overall = !sites.length ? 'empty' : available === sites.length ? 'operational' : offline === sites.length ? 'outage' : 'degraded';
  return {
    title: getSetting('public_status_title', 'SHAM service status'),
    generatedAt: new Date().toISOString(),
    overall,
    summary: { services: sites.length, available, offline },
    sites
  };
}

app.get('/api/public/status', (_req, res) => {
  if (getSetting('public_status_enabled', '0') !== '1') return res.status(404).json({ error: 'Public status page is disabled.' });
  res.json(publicStatusSnapshot());
});

app.get('/status', (_req, res) => {
  if (getSetting('public_status_enabled', '0') !== '1') return res.status(404).type('text/plain').send('Status page is disabled.');
  const snapshot = publicStatusSnapshot();
  const escapeStatusHtml = (value) => String(value).replace(/[&<>"']/g, (character) => ({
    '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;'
  }[character]));
  const safeTitle = escapeStatusHtml(snapshot.title);
  const generatedDate = new Date(snapshot.generatedAt);
  const generatedLabel = new Intl.DateTimeFormat('en', {
    year: 'numeric', month: 'short', day: 'numeric', hour: '2-digit', minute: '2-digit',
    timeZone: 'UTC', timeZoneName: 'short'
  }).format(generatedDate);
  const statusLabels = { healthy: 'Healthy', online: 'Online', degraded: 'Degraded', starting: 'Starting', offline: 'Offline' };
  const overallLabels = { operational: 'All systems operational', degraded: 'Some services need attention', outage: 'Services unavailable', empty: 'No public services' };
  const serviceSummary = snapshot.summary.services
    ? `${snapshot.summary.available} of ${snapshot.summary.services} service${snapshot.summary.services === 1 ? '' : 's'} available`
    : 'No enabled services are currently published';
  const sites = snapshot.sites.map((site) => `<article class="status-card"><span class="status-indicator ${site.status}" aria-hidden="true"></span><div><strong>${escapeStatusHtml(site.name)}</strong><small>${statusLabels[site.status]}</small></div></article>`).join('');
  res.setHeader('Cache-Control', 'no-store');
  res.type('html').send(`<!doctype html><html lang="en" class="status-document"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1"><meta name="theme-color" content="#0c0717"><meta http-equiv="refresh" content="30"><title>${safeTitle}</title><script src="/theme-init.js"></script><link rel="stylesheet" href="/styles.css"></head><body class="status-page"><main class="status-shell"><header class="status-header"><p class="eyebrow">SHAM public status</p><h1>${safeTitle}</h1><p class="muted">Updated <time datetime="${snapshot.generatedAt}">${generatedLabel}</time> · refreshes every 30 seconds</p></header><section class="status-overview" aria-label="Overall service status"><div><strong>${overallLabels[snapshot.overall]}</strong><small>${serviceSummary}</small></div><span class="status-overview-badge ${snapshot.overall}">${snapshot.overall === 'operational' ? 'Operational' : snapshot.overall === 'outage' ? 'Outage' : snapshot.overall === 'empty' ? 'No services' : 'Degraded'}</span></section><section class="status-list" aria-label="Service status">${sites || '<article class="status-card empty"><div><strong>No public services</strong><small>No enabled sites are currently listed.</small></div></article>'}</section></main></body></html>`);
});

app.get('/metrics', (req, res) => {
  res.setHeader('Cache-Control', 'no-store');
  if (getSetting('prometheus_enabled', '0') !== '1') return res.status(404).type('text/plain').send('Metrics are disabled.');
  const expected = getSecretSetting(db, 'prometheus_token', '');
  if (!expected) return res.status(503).type('text/plain').send('Metrics token is not configured.');
  const supplied = String(req.get('authorization') || '').replace(/^Bearer\s+/i, '');
  const suppliedBuffer = Buffer.from(supplied);
  const expectedBuffer = Buffer.from(expected);
  if (suppliedBuffer.length !== expectedBuffer.length || !crypto.timingSafeEqual(suppliedBuffer, expectedBuffer)) {
    res.setHeader('WWW-Authenticate', 'Bearer realm="SHAM metrics"');
    return res.status(401).type('text/plain').send('Unauthorized');
  }
  res.type('text/plain; version=0.0.4').send(operationsManager.metricsText(performanceMonitor.payload()));
});

const OIDC_START_PATH = '/api/auth/oidc/start';
const OIDC_CALLBACK_PATH = '/api/auth/oidc/callback';

app.get(OIDC_START_PATH, authLimiter, async (req, res) => {
  try {
    if (getSetting('oidc_enabled', '0') !== '1') return res.status(404).type('text/plain').send('OIDC login is disabled.');
    const issuer = getSetting('oidc_issuer', '');
    const clientId = getSetting('oidc_client_id', '');
    if (!issuer || !clientId) throw new Error('OIDC login is not fully configured.');
    const redirectUri = `${requestOrigin(req)}/api/auth/oidc/callback`;
    const location = await beginAuthorization({ issuer, clientId, redirectUri, db });
    res.redirect(302, location);
  } catch (error) { res.status(400).type('text/plain').send(`OIDC login could not start: ${error.message}`); }
});

app.get(OIDC_CALLBACK_PATH, authLimiter, async (req, res) => {
  const fail = (message) => res.redirect(302, `/?oidc_error=${encodeURIComponent(String(message || 'OIDC login failed.').slice(0, 300))}`);
  try {
    if (req.query.error) return fail(req.query.error_description || req.query.error);
    if (getSetting('oidc_enabled', '0') !== '1') return fail('OIDC login is disabled.');
    const issuer = getSetting('oidc_issuer', '');
    const clientId = getSetting('oidc_client_id', '');
    const redirectUri = `${requestOrigin(req)}/api/auth/oidc/callback`;
    const claims = await completeAuthorization({
      issuer,
      clientId,
      clientSecret: getSecretSetting(db, 'oidc_client_secret', ''),
      state: String(req.query.state || ''),
      code: String(req.query.code || ''),
      redirectUri,
      db
    });
    const normalizedIssuer = normalizeOidcIssuer(issuer);
    const identity = db.prepare('SELECT * FROM oidc_identities WHERE issuer = ? AND subject = ?').get(normalizedIssuer, String(claims.sub));
    let user = identity ? securityUser(identity.user_id) : null;
    if (!user) {
      if (identity) throw new Error('The account linked to this OIDC identity no longer exists.');
      if (getSetting('oidc_auto_provision', '0') !== '1') throw new Error('This OIDC identity has not been provisioned in SHAM.');
      const rawName = String(claims.preferred_username || claims.email?.split('@')[0] || claims.name || `oidc-${String(claims.sub).slice(0, 12)}`);
      let base = rawName.replace(/[^a-zA-Z0-9._-]+/g, '-').replace(/^[^a-zA-Z0-9]+/, '').slice(0, 32);
      if (base.length < 3) base = `oidc-${crypto.randomBytes(4).toString('hex')}`;
      let username = base;
      for (let index = 2; db.prepare('SELECT 1 FROM users WHERE username = ? COLLATE NOCASE').get(username); index += 1) username = `${base.slice(0, 35 - String(index).length)}-${index}`;
      const password = await hashPassword(crypto.randomBytes(48).toString('base64url'));
      const role = getSetting('oidc_default_role', 'user') === 'admin' ? 'admin' : 'user';
      const created = db.transaction(() => {
        const result = db.prepare('INSERT INTO users (username, password_hash, password_salt, role, active, password_configured) VALUES (?, ?, ?, ?, 1, 0)').run(username, password.hash, password.salt, role);
        db.prepare('INSERT INTO oidc_identities (issuer, subject, user_id, email, last_login_at) VALUES (?, ?, ?, ?, CURRENT_TIMESTAMP)')
          .run(normalizedIssuer, String(claims.sub), Number(result.lastInsertRowid), String(claims.email || '').slice(0, 320));
        return Number(result.lastInsertRowid);
      })();
      user = securityUser(created);
      recordAudit(user.id, 'auth.oidc.provision', { issuer: normalizedIssuer, role });
    } else {
      db.prepare('UPDATE oidc_identities SET email = ?, last_login_at = CURRENT_TIMESTAMP WHERE issuer = ? AND subject = ?')
        .run(String(claims.email || identity.email || '').slice(0, 320), normalizedIssuer, String(claims.sub));
    }
    if (!user?.active) throw new Error('This SHAM account is disabled.');
    setAuthCookie(req, res, issueToken(user));
    recordAudit(user.id, 'auth.oidc.login', { issuer: normalizedIssuer });
    res.redirect(302, '/');
  } catch (error) { fail(error.message); }
});

app.post('/api/auth/register', authLimiter, async (req, res) => {
  try {
    if (userCount() > 0) return res.status(403).json({ error: 'Public registration is disabled. Ask an administrator to create your account.' });
    const username = normalizeUsername(req.body.username);
    const { salt, hash } = await hashPassword(req.body.password);
    const createUser = db.transaction(() => {
      const count = userCount();
      if (count > 0) throw new Error('Public registration is disabled. Ask an administrator to create your account.');
      const result = db.prepare(`
        INSERT INTO users (username, password_hash, password_salt, role)
        VALUES (?, ?, ?, 'admin')
      `).run(username, hash, salt);
      setSetting('registration_enabled', '0');
      return db.prepare('SELECT * FROM users WHERE id = ?').get(result.lastInsertRowid);
    });
    const user = createUser();
    setAuthCookie(req, res, issueToken(user));
    recordAudit(user.id, 'auth.register', { role: user.role });
    res.status(201).json({ user: publicUser(user) });
  } catch (error) {
    const duplicate = String(error.code || '').includes('SQLITE_CONSTRAINT_UNIQUE');
    res.status(duplicate ? 409 : 400).json({ error: duplicate ? 'That username is already in use.' : error.message });
  }
});

app.post('/api/auth/login', authLimiter, async (req, res) => {
  const username = String(req.body.username || '').trim();
  const user = db.prepare(`SELECT users.*, (SELECT COUNT(*) FROM passkeys WHERE user_id = users.id) AS passkey_count FROM users WHERE username = ? COLLATE NOCASE`).get(username);
  const suppliedPassword = typeof req.body.password === 'string' && req.body.password.length <= 200 ? req.body.password : '';
  const valid = await verifyPassword(
    suppliedPassword,
    user?.password_salt || '00000000000000000000000000000000',
    user?.password_hash || '00'.repeat(64)
  );
  if (!user || !user.active || !valid) return res.status(401).json({ error: 'Invalid username or password.' });
  const methods = [];
  if (user.totp_enabled) methods.push('totp', 'recovery');
  if (user.passkey_count > 0) methods.push('passkey');
  if (methods.length) {
    recordAudit(user.id, 'auth.password.accepted', { mfa: true });
    return res.json({ mfaRequired: true, mfaToken: issueMfaToken(user), methods, username: user.username });
  }
  setAuthCookie(req, res, issueToken(user));
  recordAudit(user.id, 'auth.login');
  res.json({ user: publicUser(user) });
});

app.post('/api/auth/login/totp', authLimiter, (req, res) => {
  const user = verifyMfaToken(req.body.mfaToken);
  if (!user || !user.totp_enabled) return res.status(401).json({ error: 'The multi-factor login session expired.' });
  const code = String(req.body.code || '');
  const valid = verifyTotp(userTotpSecret(user), code) || consumeRecoveryCode(db, user.id, code);
  if (!valid) return res.status(401).json({ error: 'The verification code is not valid.' });
  const hydrated = securityUser(user.id);
  setAuthCookie(req, res, issueToken(hydrated));
  recordAudit(user.id, 'auth.mfa.totp');
  res.json({ user: publicUser(hydrated) });
});

app.post('/api/auth/login/passkey/options', authLimiter, (req, res) => {
  const user = verifyMfaToken(req.body.mfaToken);
  if (!user) return res.status(401).json({ error: 'The multi-factor login session expired.' });
  const credentials = db.prepare('SELECT * FROM passkeys WHERE user_id = ? ORDER BY id').all(user.id);
  if (!credentials.length) return res.status(400).json({ error: 'No passkey is registered for this account.' });
  const options = assertionOptions({ credentials });
  options.rpId = requestRpId(req);
  const challengeId = createChallenge(user.id, 'login', options.challenge, options.rpId, requestOrigin(req));
  res.json({ challengeId, options });
});

app.post('/api/auth/login/passkey/verify', authLimiter, (req, res) => {
  try {
    const user = verifyMfaToken(req.body.mfaToken);
    if (!user) return res.status(401).json({ error: 'The multi-factor login session expired.' });
    const challenge = consumeChallenge(req.body.challengeId, user.id, 'login');
    const credential = db.prepare('SELECT * FROM passkeys WHERE user_id = ? AND credential_id = ?').get(user.id, String(req.body.credential?.id || ''));
    if (!credential) throw new Error('Passkey is not registered for this account.');
    const result = verifyAssertion({ response: req.body.credential, credential, challenge: challenge.challenge, rpId: challenge.rp_id, origins: [challenge.origin] });
    db.prepare('UPDATE passkeys SET sign_count = ?, last_used_at = CURRENT_TIMESTAMP WHERE id = ?').run(result.signCount, credential.id);
    const hydrated = securityUser(user.id);
    setAuthCookie(req, res, issueToken(hydrated));
    recordAudit(user.id, 'auth.mfa.passkey', { passkeyId: credential.id });
    res.json({ user: publicUser(hydrated) });
  } catch (error) { res.status(400).json({ error: error.message }); }
});

app.post('/api/auth/logout', optionalAuth, (req, res) => {
  if (req.user) {
    revokeCurrentSession(req);
    recordAudit(req.user.id, 'auth.logout');
  }
  clearAuthCookie(req, res);
  res.status(204).end();
});

app.get('/api/auth/me', requireAuth, (req, res) => res.json({ user: publicUser(securityUser(req.user.id)) }));


app.put('/api/security/password', requireAuth, stepUpLimiter, async (req, res) => {
  if (req.authType !== 'session') return res.status(403).json({ error: 'Change your password from an authenticated browser session.' });
  try {
    const user = db.prepare('SELECT * FROM users WHERE id = ?').get(req.user.id);
    const hasLocalPassword = Boolean(user.password_configured);
    if (hasLocalPassword) {
      const currentPassword = typeof req.body.currentPassword === 'string' && req.body.currentPassword.length <= 200 ? req.body.currentPassword : '';
      if (!(await verifyPassword(currentPassword, user.password_salt, user.password_hash))) return res.status(401).json({ error: 'Current password confirmation failed.' });
    } else if (!db.prepare('SELECT 1 FROM oidc_identities WHERE user_id = ? LIMIT 1').get(req.user.id)) {
      return res.status(400).json({ error: 'This account cannot bootstrap a local password from the current sign-in method.' });
    }
    const next = await hashPassword(req.body.newPassword);
    db.prepare('UPDATE users SET password_hash = ?, password_salt = ?, password_configured = 1, session_version = session_version + 1 WHERE id = ?')
      .run(next.hash, next.salt, req.user.id);
    const updated = securityUser(req.user.id);
    setAuthCookie(req, res, issueToken(updated));
    recordAudit(req.user.id, hasLocalPassword ? 'security.password.change' : 'security.password.bootstrap');
    res.json({ user: publicUser(updated), sessionsRevoked: true });
  } catch (error) { res.status(400).json({ error: error.message }); }
});

app.post('/api/security/sessions/revoke-others', requireAuth, stepUpLimiter, async (req, res) => {
  if (req.authType !== 'session') return res.status(403).json({ error: 'Revoke browser sessions from an authenticated browser session.' });
  const user = db.prepare('SELECT * FROM users WHERE id = ?').get(req.user.id);
  if (user.password_configured) {
    const password = typeof req.body.password === 'string' && req.body.password.length <= 200 ? req.body.password : '';
    if (!(await verifyPassword(password, user.password_salt, user.password_hash))) return res.status(401).json({ error: 'Password confirmation failed.' });
  } else if (!db.prepare('SELECT 1 FROM oidc_identities WHERE user_id = ? LIMIT 1').get(req.user.id)) {
    return res.status(400).json({ error: 'This account does not have a step-up authentication method configured.' });
  }
  const updated = rotateSessionVersion(req.user.id);
  setAuthCookie(req, res, issueToken(updated));
  recordAudit(req.user.id, 'security.sessions.revoke-others');
  res.json({ user: publicUser(securityUser(req.user.id)) });
});

app.get('/api/security', requireAuth, (req, res) => {
  const user = securityUser(req.user.id);
  const passkeys = db.prepare('SELECT id, name, transports_json, created_at, last_used_at FROM passkeys WHERE user_id = ? ORDER BY id').all(req.user.id).map((row) => ({
    id: row.id, name: row.name, transports: (() => { try { return JSON.parse(row.transports_json); } catch { return []; } })(), createdAt: row.created_at, lastUsedAt: row.last_used_at
  }));
  const apiTokens = db.prepare('SELECT id, name, scopes_json, last_used_at AS lastUsedAt, expires_at AS expiresAt, created_at AS createdAt FROM api_tokens WHERE user_id = ? ORDER BY id DESC').all(req.user.id).map((row) => ({
    ...row, scopes: (() => { try { return JSON.parse(row.scopes_json || '[]'); } catch { return []; } })(), scopes_json: undefined
  }));
  res.json({ user: publicUser(user), passkeys, apiTokens, recoveryCodesRemaining: (() => { try { return JSON.parse(user.recovery_codes_json || '[]').length; } catch { return 0; } })(), webauthnAvailable: true });
});

app.post('/api/security/api-tokens', requireAuth, stepUpLimiter, async (req, res) => {
  if (req.authType !== 'session') return res.status(403).json({ error: 'Create API tokens from an authenticated browser session.' });
  const user = db.prepare('SELECT * FROM users WHERE id = ?').get(req.user.id);
  if (!(await verifyPassword(String(req.body.password || ''), user.password_salt, user.password_hash))) return res.status(401).json({ error: 'Password confirmation failed.' });
  const name = String(req.body.name || '').trim().slice(0, 100);
  if (!name) return res.status(400).json({ error: 'Token name is required.' });
  const allowed = new Set(['read', 'logs:read', 'deploy', 'sites:control', '*']);
  const scopes = [...new Set((Array.isArray(req.body.scopes) ? req.body.scopes : []).map(String).filter((scope) => allowed.has(scope)))];
  if (!scopes.length) return res.status(400).json({ error: 'Select at least one API token scope.' });
  if (scopes.includes('*') && scopes.length > 1) scopes.splice(0, scopes.length, '*');
  const expiresDays = Number(req.body.expiresDays || 0);
  if (!Number.isSafeInteger(expiresDays) || expiresDays < 0 || expiresDays > 3650) return res.status(400).json({ error: 'Token expiry must be between 0 and 3650 days.' });
  const token = `sham_pat_${crypto.randomBytes(32).toString('base64url')}`;
  const expiresAt = expiresDays > 0 ? new Date(Date.now() + expiresDays * 86400_000).toISOString() : null;
  const result = db.prepare('INSERT INTO api_tokens (user_id, name, token_hash, scopes_json, expires_at) VALUES (?, ?, ?, ?, ?)').run(req.user.id, name, tokenHash(token), JSON.stringify(scopes), expiresAt);
  recordAudit(req.user.id, 'security.api-token.create', { id: Number(result.lastInsertRowid), name, scopes, expiresAt });
  res.setHeader('Cache-Control', 'no-store');
  res.status(201).json({ token, apiToken: { id: Number(result.lastInsertRowid), name, scopes, expiresAt, createdAt: new Date().toISOString() } });
});

app.delete('/api/security/api-tokens/:id', requireAuth, stepUpLimiter, async (req, res) => {
  if (req.authType !== 'session') return res.status(403).json({ error: 'Revoke API tokens from an authenticated browser session.' });
  const user = db.prepare('SELECT * FROM users WHERE id = ?').get(req.user.id);
  if (!(await verifyPassword(String(req.body.password || ''), user.password_salt, user.password_hash))) return res.status(401).json({ error: 'Password confirmation failed.' });
  const result = db.prepare('DELETE FROM api_tokens WHERE id = ? AND user_id = ?').run(Number(req.params.id), req.user.id);
  if (!result.changes) return res.status(404).json({ error: 'API token not found.' });
  recordAudit(req.user.id, 'security.api-token.delete', { id: Number(req.params.id) });
  res.status(204).end();
});

app.post('/api/security/totp/setup', requireAuth, stepUpLimiter, async (req, res) => {
  const user = db.prepare('SELECT * FROM users WHERE id = ?').get(req.user.id);
  const suppliedPassword = typeof req.body.password === 'string' && req.body.password.length <= 200 ? req.body.password : '';
  if (!(await verifyPassword(suppliedPassword, user.password_salt, user.password_hash))) {
    return res.status(401).json({ error: 'Password confirmation failed.' });
  }
  const setup = generateTotpSetup(req.user.username);
  const id = createChallenge(req.user.id, 'totp-setup', require('./secret-store').encrypt(setup.secret), '-', requestOrigin(req), 10 * 60_000);
  res.json({ setupId: id, secret: setup.secret, otpauthUrl: setup.url });
});

app.post('/api/security/totp/enable', requireAuth, (req, res) => {
  try {
    const challenge = consumeChallenge(req.body.setupId, req.user.id, 'totp-setup');
    const secret = require('./secret-store').decrypt(challenge.challenge);
    if (!verifyTotp(secret, req.body.code)) throw new Error('The authenticator code did not match. Check the device clock and try again.');
    const recoveryCodes = generateRecoveryCodes();
    enableTotp(db, req.user.id, secret, recoveryCodes);
    recordAudit(req.user.id, 'security.totp.enable');
    res.json({ user: publicUser(securityUser(req.user.id)), recoveryCodes });
  } catch (error) { res.status(400).json({ error: error.message }); }
});

app.post('/api/security/totp/disable', requireAuth, stepUpLimiter, async (req, res) => {
  const user = db.prepare('SELECT * FROM users WHERE id = ?').get(req.user.id);
  if (!(await verifyPassword(String(req.body.password || ''), user.password_salt, user.password_hash))) return res.status(401).json({ error: 'Password confirmation failed.' });
  disableTotp(db, req.user.id);
  recordAudit(req.user.id, 'security.totp.disable');
  res.json({ user: publicUser(securityUser(req.user.id)) });
});

app.post('/api/security/recovery-codes/regenerate', requireAuth, stepUpLimiter, async (req, res) => {
  const user = db.prepare('SELECT * FROM users WHERE id = ?').get(req.user.id);
  if (!(await verifyPassword(String(req.body.password || ''), user.password_salt, user.password_hash))) return res.status(401).json({ error: 'Password confirmation failed.' });
  if (!user.totp_enabled) return res.status(400).json({ error: 'Enable TOTP before generating recovery codes.' });
  const codes = generateRecoveryCodes();
  db.prepare('UPDATE users SET recovery_codes_json = ? WHERE id = ?').run(JSON.stringify(codes.map(require('./mfa').hashRecoveryCode)), req.user.id);
  recordAudit(req.user.id, 'security.recovery.regenerate');
  res.json({ recoveryCodes: codes });
});

app.post('/api/security/passkeys/options', requireAuth, stepUpLimiter, async (req, res) => {
  const user = db.prepare('SELECT * FROM users WHERE id = ?').get(req.user.id);
  const suppliedPassword = typeof req.body.password === 'string' && req.body.password.length <= 200 ? req.body.password : '';
  if (!(await verifyPassword(suppliedPassword, user.password_salt, user.password_hash))) {
    return res.status(401).json({ error: 'Password confirmation failed.' });
  }
  const existing = db.prepare('SELECT credential_id FROM passkeys WHERE user_id = ?').all(req.user.id).map((row) => row.credential_id);
  const rpId = requestRpId(req);
  const options = registrationOptions({ user: req.user, rpId, existing });
  const challengeId = createChallenge(req.user.id, 'register', options.challenge, rpId, requestOrigin(req));
  res.json({ challengeId, options });
});

app.post('/api/security/passkeys/register', requireAuth, (req, res) => {
  try {
    const challenge = consumeChallenge(req.body.challengeId, req.user.id, 'register');
    const result = verifyRegistration({ response: req.body.credential, challenge: challenge.challenge, rpId: challenge.rp_id, origins: [challenge.origin] });
    const name = String(req.body.name || 'Passkey').trim().slice(0, 100) || 'Passkey';
    db.prepare('INSERT INTO passkeys (user_id, credential_id, public_key_jwk, algorithm, sign_count, transports_json, name) VALUES (?, ?, ?, ?, ?, ?, ?)')
      .run(req.user.id, result.credentialId, JSON.stringify(result.publicKeyJwk), result.publicKeyJwk.alg, result.signCount, JSON.stringify(result.transports), name);
    recordAudit(req.user.id, 'security.passkey.add', { name });
    res.status(201).json({ passkeys: db.prepare('SELECT id, name, created_at AS createdAt, last_used_at AS lastUsedAt FROM passkeys WHERE user_id = ? ORDER BY id').all(req.user.id) });
  } catch (error) {
    const duplicate = String(error.code || '').includes('SQLITE_CONSTRAINT_UNIQUE');
    res.status(duplicate ? 409 : 400).json({ error: duplicate ? 'That passkey is already registered.' : error.message });
  }
});

app.delete('/api/security/passkeys/:id', requireAuth, stepUpLimiter, async (req, res) => {
  const user = db.prepare('SELECT * FROM users WHERE id = ?').get(req.user.id);
  if (!(await verifyPassword(String(req.body.password || ''), user.password_salt, user.password_hash))) return res.status(401).json({ error: 'Password confirmation failed.' });
  const result = db.prepare('DELETE FROM passkeys WHERE id = ? AND user_id = ?').run(Number(req.params.id), req.user.id);
  if (!result.changes) return res.status(404).json({ error: 'Passkey not found.' });
  recordAudit(req.user.id, 'security.passkey.delete', { id: Number(req.params.id) });
  res.status(204).end();
});

app.use('/api/sites/:id', requireAuth, serializeSiteMutation);
app.use('/api/admin/sites/:id', requireAuth, requireAdmin, serializeSiteMutation);

registerSiteRoutes(routeContext);

app.get('/api/runtime-events', requireAuth, (req, res) => {
  res.json({ events: manager.listEvents(Number(req.query.limit) || 100) });
});

app.use('/api/admin/plugins', requireAuth, requireAdmin, serializePluginMutation);

registerAdminRoutes(adminRouteContext);

registerOperationsRoutes(operationsRouteContext);

app.get('/LICENSE', (_req, res) => {
  res.type('text/plain').sendFile(path.join(ROOT_DIR, 'LICENSE'), (error) => {
    if (!error || res.headersSent) return;
    res.status(error.statusCode === 404 ? 404 : 500).type('text/plain').send('SHAM license file is unavailable in this installation.');
  });
});

app.use('/api', (_req, res) => res.status(404).json({ error: 'API route not found.' }));
app.use(express.static(publicDir, { index: 'index.html', maxAge: 0 }));
app.use((req, res) => {
  if (!['GET', 'HEAD'].includes(req.method)) return res.status(404).type('text/plain').send('Not found');
  res.sendFile(path.join(publicDir, 'index.html'));
});

app.use((error, _req, res, next) => {
  console.error(error);
  if (res.headersSent) return next(error);
  if (error?.type === 'entity.too.large' || error?.status === 413) {
    return res.status(413).json({ error: 'Request body exceeds the configured size limit.' });
  }
  if (error instanceof SyntaxError && error?.status === 400 && Object.hasOwn(error, 'body')) {
    return res.status(400).json({ error: 'Request body contains invalid JSON.' });
  }
  res.status(500).json({ error: 'Internal server error.' });
});

let resolveDashboardReady;
let rejectDashboardReady;
let dashboardStartupSettled = false;
const ready = new Promise((resolve, reject) => {
  resolveDashboardReady = resolve;
  rejectDashboardReady = reject;
});

const dashboardTls = DASHBOARD_SELF_SIGNED_HTTPS
  ? dashboardTlsOptions({ dataDir: DATA_DIR, bindHost: DASHBOARD_HOST, opensslBin: OPENSSL_BIN })
  : null;
const dashboardServer = dashboardTls ? https.createServer({ key: dashboardTls.key, cert: dashboardTls.cert }, app) : http.createServer(app);
dashboardServer.listen(DASHBOARD_PORT, DASHBOARD_HOST, async () => {
  const dashboardUrlHost = net.isIP(DASHBOARD_HOST) === 6 ? `[${DASHBOARD_HOST}]` : DASHBOARD_HOST;
  const dashboardProtocol = dashboardTls ? 'https' : 'http';
  console.log(`SHAM dashboard listening on ${dashboardProtocol}://${dashboardUrlHost}:${DASHBOARD_PORT}`);
  if (dashboardTls) console.log(`Local self-signed dashboard certificate covers: ${[...dashboardTls.hosts.dns, ...dashboardTls.hosts.ips].join(', ')}`);
  console.log(`SHAM data path: ${DATA_DIR}`);
  try {
    await manager.reconcileRuntimes();
    await manager.startEnabledSites();
    await edgeProxy.start();
  } catch (error) {
    console.error(`Could not restore enabled sites during startup: ${error.message}`);
  }
  try {
    await Promise.all([cloudflareTunnels.startEnabled(), legacyCloudflareTunnel.start()]);
    await cloudflareReconciler.tick();
  } catch (error) {
    console.error(`Could not start configured Cloudflare Tunnels: ${error.message}`);
  } finally {
    dashboardStartupSettled = true;
    resolveDashboardReady({ host: DASHBOARD_HOST, port: DASHBOARD_PORT });
  }
});

dashboardServer.requestTimeout = HTTP_REQUEST_TIMEOUT_MS;
dashboardServer.headersTimeout = Math.min(60_000, HTTP_REQUEST_TIMEOUT_MS);
dashboardServer.keepAliveTimeout = 5_000;

dashboardServer.on('error', (error) => {
  console.error(`Dashboard failed: ${error.message}`);
  if (!dashboardStartupSettled) {
    dashboardStartupSettled = true;
    rejectDashboardReady(error);
  }
  process.exitCode = 1;
});

let shuttingDown = false;
async function shutdown(signal) {
  if (shuttingDown) return;
  shuttingDown = true;
  console.log(`Received ${signal}; stopping SHAM...`);

  let serverClosed = false;
  let resolveServerClosed;
  const serverClosedPromise = new Promise((resolve) => { resolveServerClosed = resolve; });
  dashboardServer.close(() => {
    serverClosed = true;
    resolveServerClosed();
  });
  dashboardServer.closeIdleConnections?.();

  await cloudflareReconciler.stop();
  await stopIntegrationProcesses();
  await Promise.allSettled([performanceMonitor.stop(), dependencyScanner.shutdown(), snapshotManager.shutdown(), operationsManager.shutdown(), updateManager.shutdown(), cloudflareTunnels.shutdown(), legacyCloudflareTunnel.shutdown(), edgeProxy.stop()]);
  await stopUploadWorkers();
  await pluginManager.shutdown();
  await manager.stopAll();

  if (!serverClosed) {
    const forceTimer = setTimeout(() => {
      dashboardServer.closeAllConnections?.();
      resolveServerClosed();
    }, 5_000);
    forceTimer.unref?.();
    await serverClosedPromise;
    clearTimeout(forceTimer);
  }

  try { await fs.promises.rm(UPLOAD_TMP_DIR, { recursive: true, force: true }); } catch { /* Temporary files are best-effort cleanup. */ }
  db.close();
  process.exit(0);
}

process.on('SIGINT', () => shutdown('SIGINT'));
process.on('SIGTERM', () => shutdown('SIGTERM'));

module.exports = { app, dashboardServer, ready, shutdown };
