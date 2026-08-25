const fs = require('node:fs');
const Database = require('better-sqlite3');
const { DB_PATH } = require('./config');

const db = new Database(DB_PATH);
db.pragma('journal_mode = WAL');
db.pragma('foreign_keys = ON');
db.pragma('busy_timeout = 5000');

db.exec(`
  CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT NOT NULL UNIQUE COLLATE NOCASE,
    password_hash TEXT NOT NULL,
    password_salt TEXT NOT NULL,
    role TEXT NOT NULL CHECK (role IN ('admin', 'user')) DEFAULT 'user',
    active INTEGER NOT NULL DEFAULT 1 CHECK (active IN (0, 1)),
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
  );

  CREATE TABLE IF NOT EXISTS settings (
    key TEXT PRIMARY KEY,
    value TEXT NOT NULL,
    updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
  );

  CREATE TABLE IF NOT EXISTS sites (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL,
    slug TEXT NOT NULL UNIQUE,
    directory_name TEXT NOT NULL UNIQUE,
    bind_host TEXT NOT NULL DEFAULT '127.0.0.1',
    port INTEGER NOT NULL UNIQUE,
    entry_file TEXT NOT NULL DEFAULT 'index.html',
    spa_fallback INTEGER NOT NULL DEFAULT 0 CHECK (spa_fallback IN (0, 1)),
    cache_seconds INTEGER NOT NULL DEFAULT 0,
    headers_json TEXT NOT NULL DEFAULT '{}',
    enabled INTEGER NOT NULL DEFAULT 0 CHECK (enabled IN (0, 1)),
    created_by INTEGER,
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (created_by) REFERENCES users(id) ON DELETE SET NULL
  );

  CREATE TABLE IF NOT EXISTS audit_logs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER,
    action TEXT NOT NULL,
    detail TEXT,
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE SET NULL
  );

  CREATE TABLE IF NOT EXISTS site_stats (
    site_id INTEGER PRIMARY KEY,
    total_requests INTEGER NOT NULL DEFAULT 0,
    total_bytes INTEGER NOT NULL DEFAULT 0,
    total_errors INTEGER NOT NULL DEFAULT 0,
    total_response_ms INTEGER NOT NULL DEFAULT 0,
    last_request_at TEXT,
    FOREIGN KEY (site_id) REFERENCES sites(id) ON DELETE CASCADE
  );

  CREATE TABLE IF NOT EXISTS site_daily_stats (
    site_id INTEGER NOT NULL,
    day TEXT NOT NULL,
    requests INTEGER NOT NULL DEFAULT 0,
    bytes INTEGER NOT NULL DEFAULT 0,
    errors INTEGER NOT NULL DEFAULT 0,
    response_ms INTEGER NOT NULL DEFAULT 0,
    PRIMARY KEY (site_id, day),
    FOREIGN KEY (site_id) REFERENCES sites(id) ON DELETE CASCADE
  );

  CREATE TABLE IF NOT EXISTS plugins (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    version TEXT NOT NULL,
    type TEXT NOT NULL CHECK (type IN ('json', 'js')),
    directory_name TEXT NOT NULL UNIQUE,
    enabled INTEGER NOT NULL DEFAULT 0 CHECK (enabled IN (0, 1)),
    manifest_json TEXT NOT NULL,
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
  );

  CREATE TABLE IF NOT EXISTS plugin_settings (
    plugin_id TEXT NOT NULL,
    key TEXT NOT NULL,
    value TEXT NOT NULL,
    updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (plugin_id, key),
    FOREIGN KEY (plugin_id) REFERENCES plugins(id) ON DELETE CASCADE
  );
`);

/** @typedef {{ cid: number, name: string, type: string, notnull: number, dflt_value: unknown, pk: number }} PragmaColumnRow */

function columnsFor(table) {
  const rows = /** @type {PragmaColumnRow[]} */ (db.prepare(`PRAGMA table_info(${table})`).all());
  return new Set(rows.map((row) => row.name));
}

function ensureColumn(table, name, definition) {
  if (!columnsFor(table).has(name)) db.exec(`ALTER TABLE ${table} ADD COLUMN ${name} ${definition}`);
}

ensureColumn('sites', 'runtime_type', "TEXT NOT NULL DEFAULT 'static'");
ensureColumn('sites', 'node_entry', "TEXT NOT NULL DEFAULT 'server.js'");
ensureColumn('sites', 'install_dependencies', 'INTEGER NOT NULL DEFAULT 0');
ensureColumn('sites', 'minify', 'INTEGER NOT NULL DEFAULT 0');
ensureColumn('sites', 'obfuscate', 'INTEGER NOT NULL DEFAULT 0');
ensureColumn('sites', 'obfuscation_risk_acknowledged', 'INTEGER NOT NULL DEFAULT 0');
ensureColumn('sites', 'domain_only', 'INTEGER NOT NULL DEFAULT 0');
ensureColumn('sites', 'firewall_enabled', 'INTEGER NOT NULL DEFAULT 0');
ensureColumn('sites', 'firewall_json', "TEXT NOT NULL DEFAULT '{}'");
ensureColumn('sites', 'domain', "TEXT NOT NULL DEFAULT ''");
ensureColumn('sites', 'ssl_enabled', 'INTEGER NOT NULL DEFAULT 0');
ensureColumn('sites', 'cloudflare_enabled', 'INTEGER NOT NULL DEFAULT 0');
ensureColumn('sites', 'compression', 'INTEGER NOT NULL DEFAULT 1');
ensureColumn('sites', 'security_preset', "TEXT NOT NULL DEFAULT 'balanced'");
ensureColumn('sites', 'csp', "TEXT NOT NULL DEFAULT ''");
ensureColumn('sites', 'health_check_path', "TEXT NOT NULL DEFAULT '/'");
ensureColumn('sites', 'health_check_interval', 'INTEGER NOT NULL DEFAULT 30');
ensureColumn('sites', 'restart_policy', "TEXT NOT NULL DEFAULT 'on-failure'");
ensureColumn('sites', 'max_restarts', 'INTEGER NOT NULL DEFAULT 5');
ensureColumn('sites', 'memory_limit_mb', 'INTEGER NOT NULL DEFAULT 0');
ensureColumn('sites', 'max_connections', 'INTEGER NOT NULL DEFAULT 0');
ensureColumn('sites', 'edge_enabled', 'INTEGER NOT NULL DEFAULT 0');
ensureColumn('sites', 'runtime_isolation', "TEXT NOT NULL DEFAULT 'process'");
ensureColumn('sites', 'container_image', "TEXT NOT NULL DEFAULT 'node:22-alpine'");
ensureColumn('sites', 'cpu_limit', 'REAL NOT NULL DEFAULT 0');
ensureColumn('sites', 'pids_limit', 'INTEGER NOT NULL DEFAULT 128');
ensureColumn('sites', 'outbound_network', 'INTEGER NOT NULL DEFAULT 1');
ensureColumn('sites', 'anubis_enabled', 'INTEGER NOT NULL DEFAULT 0');
ensureColumn('sites', 'anubis_preset', "TEXT NOT NULL DEFAULT 'balanced'");
ensureColumn('sites', 'anubis_difficulty', 'INTEGER NOT NULL DEFAULT 4');
ensureColumn('sites', 'anubis_policy', "TEXT NOT NULL DEFAULT ''");
ensureColumn('sites', 'maintenance_enabled', 'INTEGER NOT NULL DEFAULT 0');
ensureColumn('sites', 'maintenance_html', "TEXT NOT NULL DEFAULT ''");
ensureColumn('sites', 'redirects_json', "TEXT NOT NULL DEFAULT '[]'");
ensureColumn('sites', 'error_pages_json', "TEXT NOT NULL DEFAULT '{}'");
ensureColumn('sites', 'cache_rules_json', "TEXT NOT NULL DEFAULT '[]'");
ensureColumn('sites', 'release_mode', 'INTEGER NOT NULL DEFAULT 0');
ensureColumn('sites', 'active_release_directory', "TEXT NOT NULL DEFAULT ''");
ensureColumn('sites', 'git_url', "TEXT NOT NULL DEFAULT ''");
ensureColumn('sites', 'git_branch', "TEXT NOT NULL DEFAULT 'main'");
ensureColumn('sites', 'preview_domain', "TEXT NOT NULL DEFAULT ''");
ensureColumn('sites', 'proxy_target', "TEXT NOT NULL DEFAULT ''");
ensureColumn('sites', 'proxy_host_header', "TEXT NOT NULL DEFAULT ''");
ensureColumn('sites', 'proxy_timeout_ms', 'INTEGER NOT NULL DEFAULT 30000');
ensureColumn('sites', 'pinned', 'INTEGER NOT NULL DEFAULT 0');
ensureColumn('sites', 'install_command', "TEXT NOT NULL DEFAULT ''");
ensureColumn('sites', 'build_command', "TEXT NOT NULL DEFAULT ''");
ensureColumn('sites', 'build_output_dir', "TEXT NOT NULL DEFAULT ''");
ensureColumn('sites', 'runtime_preset', "TEXT NOT NULL DEFAULT ''");
ensureColumn('sites', 'start_command', "TEXT NOT NULL DEFAULT ''");
ensureColumn('sites', 'runtime_port_env', "TEXT NOT NULL DEFAULT 'PORT'");
ensureColumn('sites', 'working_directory', "TEXT NOT NULL DEFAULT ''");
ensureColumn('sites', 'readiness_type', "TEXT NOT NULL DEFAULT 'tcp'");
ensureColumn('sites', 'readiness_path', "TEXT NOT NULL DEFAULT '/'");
ensureColumn('sites', 'readiness_command', "TEXT NOT NULL DEFAULT ''");
ensureColumn('sites', 'readiness_status_min', 'INTEGER NOT NULL DEFAULT 200');
ensureColumn('sites', 'readiness_status_max', 'INTEGER NOT NULL DEFAULT 399');
ensureColumn('sites', 'startup_timeout_seconds', 'INTEGER NOT NULL DEFAULT 30');
ensureColumn('sites', 'shutdown_grace_seconds', 'INTEGER NOT NULL DEFAULT 10');
ensureColumn('sites', 'container_mode', "TEXT NOT NULL DEFAULT 'image'");
ensureColumn('sites', 'container_port', 'INTEGER NOT NULL DEFAULT 3000');
ensureColumn('sites', 'dockerfile_path', "TEXT NOT NULL DEFAULT 'Dockerfile'");
ensureColumn('sites', 'compose_file', "TEXT NOT NULL DEFAULT 'compose.yaml'");
ensureColumn('sites', 'compose_service', "TEXT NOT NULL DEFAULT 'app'");
ensureColumn('sites', 'buildpack_builder', "TEXT NOT NULL DEFAULT ''");
ensureColumn('sites', 'runtime_manifest_hash', "TEXT NOT NULL DEFAULT ''");
ensureColumn('sites', 'runtime_manifest_approved_hash', "TEXT NOT NULL DEFAULT ''");
ensureColumn('sites', 'health_check_type', "TEXT NOT NULL DEFAULT 'http'");
ensureColumn('sites', 'health_check_command', "TEXT NOT NULL DEFAULT ''");
ensureColumn('sites', 'health_check_status_min', 'INTEGER NOT NULL DEFAULT 200');
ensureColumn('sites', 'health_check_status_max', 'INTEGER NOT NULL DEFAULT 499');

ensureColumn('sites', 'blue_green_drain_seconds', 'INTEGER NOT NULL DEFAULT 5');
ensureColumn('sites', 'manifest_enabled', 'INTEGER NOT NULL DEFAULT 1');
ensureColumn('sites', 'cloudflare_auto_sync', 'INTEGER NOT NULL DEFAULT 0');


ensureColumn('users', 'totp_secret', "TEXT NOT NULL DEFAULT ''");
ensureColumn('users', 'totp_enabled', 'INTEGER NOT NULL DEFAULT 0');
ensureColumn('users', 'recovery_codes_json', "TEXT NOT NULL DEFAULT '[]'");
ensureColumn('users', 'password_configured', 'INTEGER NOT NULL DEFAULT 1');
ensureColumn('users', 'session_version', 'INTEGER NOT NULL DEFAULT 1');
ensureColumn('plugins', 'permissions_json', "TEXT NOT NULL DEFAULT '[]'");
ensureColumn('plugins', 'signature_status', "TEXT NOT NULL DEFAULT 'unsigned'");
ensureColumn('plugins', 'isolation', "TEXT NOT NULL DEFAULT 'in-process'");
db.exec(`
  CREATE TABLE IF NOT EXISTS api_tokens (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL,
    name TEXT NOT NULL,
    token_hash TEXT NOT NULL UNIQUE,
    scopes_json TEXT NOT NULL DEFAULT '[]',
    expires_at TEXT,
    last_used_at TEXT,
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
  );

  CREATE INDEX IF NOT EXISTS idx_api_tokens_user ON api_tokens(user_id, created_at DESC);

  CREATE TABLE IF NOT EXISTS revoked_sessions (
    sid TEXT PRIMARY KEY,
    user_id INTEGER NOT NULL,
    expires_at INTEGER NOT NULL,
    revoked_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
  );

  CREATE INDEX IF NOT EXISTS idx_revoked_sessions_expiry ON revoked_sessions(expires_at);

  CREATE TABLE IF NOT EXISTS oidc_identities (
    issuer TEXT NOT NULL,
    subject TEXT NOT NULL,
    user_id INTEGER NOT NULL,
    email TEXT NOT NULL DEFAULT '',
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    last_login_at TEXT,
    PRIMARY KEY (issuer, subject),
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
  );

  CREATE TABLE IF NOT EXISTS oidc_states (
    state_hash TEXT PRIMARY KEY,
    nonce TEXT NOT NULL,
    verifier TEXT NOT NULL,
    redirect_uri TEXT NOT NULL,
    expires_at INTEGER NOT NULL
  );

  CREATE TABLE IF NOT EXISTS runtime_instances (
    site_id INTEGER PRIMARY KEY,
    driver TEXT NOT NULL,
    external_id TEXT NOT NULL DEFAULT '',
    internal_host TEXT NOT NULL DEFAULT '',
    internal_port INTEGER NOT NULL DEFAULT 0,
    root_path TEXT NOT NULL DEFAULT '',
    observed_state TEXT NOT NULL DEFAULT 'stopped',
    updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (site_id) REFERENCES sites(id) ON DELETE CASCADE
  );

  CREATE TABLE IF NOT EXISTS site_performance_samples (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    site_id INTEGER NOT NULL,
    sampled_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    cpu_percent REAL NOT NULL DEFAULT 0,
    rss_bytes INTEGER NOT NULL DEFAULT 0,
    request_rate REAL NOT NULL DEFAULT 0,
    error_rate REAL NOT NULL DEFAULT 0,
    avg_response_ms REAL NOT NULL DEFAULT 0,
    p95_response_ms REAL NOT NULL DEFAULT 0,
    connections INTEGER NOT NULL DEFAULT 0,
    FOREIGN KEY (site_id) REFERENCES sites(id) ON DELETE CASCADE
  );

  CREATE INDEX IF NOT EXISTS idx_site_performance_samples_time ON site_performance_samples(site_id, sampled_at DESC);

  CREATE TABLE IF NOT EXISTS alert_rules (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    site_id INTEGER,
    kind TEXT NOT NULL,
    threshold REAL NOT NULL,
    severity TEXT NOT NULL DEFAULT 'warning',
    enabled INTEGER NOT NULL DEFAULT 1 CHECK (enabled IN (0, 1)),
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (site_id) REFERENCES sites(id) ON DELETE CASCADE
  );

  CREATE INDEX IF NOT EXISTS idx_alert_rules_site ON alert_rules(site_id, enabled);

  CREATE TABLE IF NOT EXISTS site_visitor_stats (
    site_id INTEGER NOT NULL,
    ip TEXT NOT NULL,
    country TEXT NOT NULL DEFAULT 'ZZ',
    client_type TEXT NOT NULL DEFAULT 'unknown',
    user_agent TEXT NOT NULL DEFAULT '',
    requests INTEGER NOT NULL DEFAULT 0,
    bytes INTEGER NOT NULL DEFAULT 0,
    errors INTEGER NOT NULL DEFAULT 0,
    last_request_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (site_id, ip, country, client_type),
    FOREIGN KEY (site_id) REFERENCES sites(id) ON DELETE CASCADE
  );

  CREATE INDEX IF NOT EXISTS idx_site_daily_stats_day ON site_daily_stats(day);
  CREATE INDEX IF NOT EXISTS idx_site_visitor_stats_recent ON site_visitor_stats(site_id, last_request_at DESC);
  CREATE INDEX IF NOT EXISTS idx_site_visitor_stats_recent_global ON site_visitor_stats(last_request_at DESC);
  CREATE INDEX IF NOT EXISTS idx_site_visitor_stats_ip ON site_visitor_stats(ip);
  CREATE INDEX IF NOT EXISTS idx_site_visitor_stats_country ON site_visitor_stats(country);
  CREATE TABLE IF NOT EXISTS passkeys (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL,
    credential_id TEXT NOT NULL UNIQUE,
    public_key_jwk TEXT NOT NULL,
    algorithm TEXT NOT NULL,
    sign_count INTEGER NOT NULL DEFAULT 0,
    transports_json TEXT NOT NULL DEFAULT '[]',
    name TEXT NOT NULL DEFAULT 'Passkey',
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    last_used_at TEXT,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
  );

  CREATE TABLE IF NOT EXISTS webauthn_challenges (
    id TEXT PRIMARY KEY,
    user_id INTEGER NOT NULL,
    purpose TEXT NOT NULL,
    challenge TEXT NOT NULL,
    rp_id TEXT NOT NULL,
    origin TEXT NOT NULL,
    expires_at INTEGER NOT NULL,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
  );

  CREATE TABLE IF NOT EXISTS site_snapshots (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    site_id INTEGER NOT NULL,
    label TEXT NOT NULL DEFAULT '',
    filename TEXT NOT NULL UNIQUE,
    bytes INTEGER NOT NULL DEFAULT 0,
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (site_id) REFERENCES sites(id) ON DELETE CASCADE
  );

  CREATE TABLE IF NOT EXISTS dependency_scans (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    site_id INTEGER NOT NULL,
    result_json TEXT NOT NULL,
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (site_id) REFERENCES sites(id) ON DELETE CASCADE
  );

  CREATE TABLE IF NOT EXISTS runtime_logs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    site_id INTEGER,
    level TEXT NOT NULL,
    message TEXT NOT NULL,
    context_json TEXT,
    deployment_id INTEGER,
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (site_id) REFERENCES sites(id) ON DELETE CASCADE
  );

  CREATE TABLE IF NOT EXISTS performance_samples (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    sampled_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    cpu_percent REAL NOT NULL DEFAULT 0,
    rss_bytes INTEGER NOT NULL DEFAULT 0,
    heap_bytes INTEGER NOT NULL DEFAULT 0,
    event_loop_ms REAL NOT NULL DEFAULT 0,
    disk_percent REAL NOT NULL DEFAULT 0,
    load_1m REAL NOT NULL DEFAULT 0,
    running_sites INTEGER NOT NULL DEFAULT 0
  );

  CREATE TABLE IF NOT EXISTS alerts (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    kind TEXT NOT NULL,
    severity TEXT NOT NULL,
    title TEXT NOT NULL,
    detail TEXT NOT NULL,
    site_id INTEGER,
    fingerprint TEXT NOT NULL,
    acknowledged INTEGER NOT NULL DEFAULT 0 CHECK (acknowledged IN (0, 1)),
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    last_seen_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    acknowledged_at TEXT,
    FOREIGN KEY (site_id) REFERENCES sites(id) ON DELETE CASCADE,
    UNIQUE(fingerprint, acknowledged)
  );


  CREATE TABLE IF NOT EXISTS site_cloudflare_tunnels (
    site_id INTEGER PRIMARY KEY,
    enabled INTEGER NOT NULL DEFAULT 0 CHECK (enabled IN (0, 1)),
    token TEXT NOT NULL DEFAULT '',
    tunnel_id TEXT NOT NULL DEFAULT '',
    public_hostname TEXT NOT NULL DEFAULT '',
    origin_service TEXT NOT NULL DEFAULT '',
    managed_route INTEGER NOT NULL DEFAULT 0 CHECK (managed_route IN (0, 1)),
    tunnel_only INTEGER NOT NULL DEFAULT 0 CHECK (tunnel_only IN (0, 1)),
    connector_mode TEXT NOT NULL DEFAULT 'dedicated' CHECK (connector_mode IN ('dedicated', 'shared')),
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (site_id) REFERENCES sites(id) ON DELETE CASCADE
  );

  CREATE TABLE IF NOT EXISTS site_env (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    site_id INTEGER NOT NULL,
    key TEXT NOT NULL,
    value TEXT NOT NULL DEFAULT '',
    secret INTEGER NOT NULL DEFAULT 0 CHECK (secret IN (0, 1)),
    scope TEXT NOT NULL DEFAULT 'runtime' CHECK (scope IN ('runtime', 'build', 'both')),
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    UNIQUE(site_id, key),
    FOREIGN KEY (site_id) REFERENCES sites(id) ON DELETE CASCADE
  );

  CREATE TABLE IF NOT EXISTS database_profiles (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL UNIQUE COLLATE NOCASE,
    type TEXT NOT NULL,
    env_key TEXT NOT NULL,
    connection_value TEXT NOT NULL,
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
  );

  CREATE TABLE IF NOT EXISTS site_database_profiles (
    site_id INTEGER NOT NULL,
    profile_id INTEGER NOT NULL,
    PRIMARY KEY (site_id, profile_id),
    FOREIGN KEY (site_id) REFERENCES sites(id) ON DELETE CASCADE,
    FOREIGN KEY (profile_id) REFERENCES database_profiles(id) ON DELETE CASCADE
  );

  CREATE TABLE IF NOT EXISTS site_jobs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    site_id INTEGER NOT NULL,
    name TEXT NOT NULL,
    schedule TEXT NOT NULL,
    command TEXT NOT NULL,
    enabled INTEGER NOT NULL DEFAULT 1 CHECK (enabled IN (0, 1)),
    timeout_seconds INTEGER NOT NULL DEFAULT 900,
    allow_overlap INTEGER NOT NULL DEFAULT 0 CHECK (allow_overlap IN (0, 1)),
    last_started_at TEXT,
    next_run_at TEXT,
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (site_id) REFERENCES sites(id) ON DELETE CASCADE
  );

  CREATE TABLE IF NOT EXISTS job_runs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    job_id INTEGER NOT NULL,
    status TEXT NOT NULL,
    output TEXT NOT NULL DEFAULT '',
    started_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    finished_at TEXT,
    duration_ms INTEGER,
    FOREIGN KEY (job_id) REFERENCES site_jobs(id) ON DELETE CASCADE
  );

  CREATE TABLE IF NOT EXISTS site_deployments (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    site_id INTEGER NOT NULL,
    source TEXT NOT NULL DEFAULT 'upload',
    status TEXT NOT NULL DEFAULT 'running',
    ref TEXT NOT NULL DEFAULT '',
    commit_sha TEXT NOT NULL DEFAULT '',
    commit_author TEXT NOT NULL DEFAULT '',
    commit_message TEXT NOT NULL DEFAULT '',
    detail TEXT NOT NULL DEFAULT '',
    started_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    finished_at TEXT,
    duration_ms INTEGER NOT NULL DEFAULT 0,
    FOREIGN KEY (site_id) REFERENCES sites(id) ON DELETE CASCADE
  );

  CREATE INDEX IF NOT EXISTS idx_site_deployments_recent ON site_deployments(site_id, id DESC);
  CREATE INDEX IF NOT EXISTS idx_site_deployments_status_started ON site_deployments(status, started_at DESC);

  CREATE TABLE IF NOT EXISTS site_releases (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    site_id INTEGER NOT NULL,
    version TEXT NOT NULL,
    source TEXT NOT NULL,
    directory_name TEXT NOT NULL,
    commit_sha TEXT,
    deployment_id INTEGER,
    status TEXT NOT NULL DEFAULT 'ready',
    active INTEGER NOT NULL DEFAULT 0 CHECK (active IN (0, 1)),
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (site_id) REFERENCES sites(id) ON DELETE CASCADE
  );

  CREATE TABLE IF NOT EXISTS preview_deployments (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    site_id INTEGER NOT NULL,
    hostname TEXT NOT NULL UNIQUE COLLATE NOCASE,
    port INTEGER NOT NULL UNIQUE,
    directory_name TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'starting',
    expires_at TEXT NOT NULL,
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (site_id) REFERENCES sites(id) ON DELETE CASCADE
  );

  CREATE TABLE IF NOT EXISTS backup_runs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    destination TEXT NOT NULL,
    status TEXT NOT NULL,
    filename TEXT,
    bytes INTEGER NOT NULL DEFAULT 0,
    detail TEXT,
    started_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    finished_at TEXT
  );

  CREATE TABLE IF NOT EXISTS saved_log_filters (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL,
    name TEXT NOT NULL,
    filter_json TEXT NOT NULL,
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    UNIQUE(user_id, name),
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
  );

  CREATE TABLE IF NOT EXISTS alert_destinations (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL,
    kind TEXT NOT NULL CHECK (kind IN ('webhook', 'slack', 'discord', 'email')),
    config_encrypted TEXT NOT NULL,
    enabled INTEGER NOT NULL DEFAULT 1 CHECK (enabled IN (0, 1)),
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
  );

  CREATE TABLE IF NOT EXISTS update_history (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    version TEXT NOT NULL,
    status TEXT NOT NULL,
    detail TEXT,
    archive_name TEXT,
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    applied_at TEXT
  );

  CREATE TABLE IF NOT EXISTS deploy_webhook_deliveries (
    site_id INTEGER NOT NULL,
    delivery_id TEXT NOT NULL,
    received_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (site_id, delivery_id),
    FOREIGN KEY (site_id) REFERENCES sites(id) ON DELETE CASCADE
  );

  CREATE INDEX IF NOT EXISTS idx_site_env_site ON site_env(site_id);
  CREATE INDEX IF NOT EXISTS idx_site_jobs_due ON site_jobs(enabled, next_run_at);
  CREATE INDEX IF NOT EXISTS idx_job_runs_job ON job_runs(job_id, started_at DESC);
  CREATE INDEX IF NOT EXISTS idx_site_releases_site ON site_releases(site_id, created_at DESC);
  CREATE INDEX IF NOT EXISTS idx_preview_expiry ON preview_deployments(expires_at);
  CREATE INDEX IF NOT EXISTS idx_preview_site_recent ON preview_deployments(site_id, id DESC);
  CREATE INDEX IF NOT EXISTS idx_backup_runs_started ON backup_runs(started_at DESC);
  CREATE INDEX IF NOT EXISTS idx_deploy_webhook_received ON deploy_webhook_deliveries(received_at);

  CREATE INDEX IF NOT EXISTS idx_runtime_logs_created ON runtime_logs(created_at DESC);
  CREATE INDEX IF NOT EXISTS idx_runtime_logs_site ON runtime_logs(site_id, created_at DESC);
  CREATE INDEX IF NOT EXISTS idx_dependency_scans_site ON dependency_scans(site_id, created_at DESC);
  CREATE INDEX IF NOT EXISTS idx_snapshots_site ON site_snapshots(site_id, created_at DESC);
  CREATE INDEX IF NOT EXISTS idx_performance_samples_time ON performance_samples(sampled_at DESC);
  CREATE INDEX IF NOT EXISTS idx_passkeys_user ON passkeys(user_id);
  CREATE INDEX IF NOT EXISTS idx_webauthn_challenges_expiry ON webauthn_challenges(expires_at);
  CREATE INDEX IF NOT EXISTS idx_alerts_active ON alerts(acknowledged, last_seen_at DESC);

  DELETE FROM site_daily_stats WHERE day < date('now', '-400 days');
  DELETE FROM deploy_webhook_deliveries WHERE received_at < datetime('now', '-14 days');

  INSERT OR IGNORE INTO settings (key, value) VALUES ('registration_enabled', '0');
  INSERT OR IGNORE INTO settings (key, value) VALUES ('cloudflare_api_token', '');
  INSERT OR IGNORE INTO settings (key, value) VALUES ('cloudflare_zone_id', '');
  INSERT OR IGNORE INTO settings (key, value) VALUES ('cloudflare_target_ip', '');
  INSERT OR IGNORE INTO settings (key, value) VALUES ('cloudflare_tunnel_enabled', '0');
  INSERT OR IGNORE INTO settings (key, value) VALUES ('cloudflare_tunnel_token', '');
  INSERT OR IGNORE INTO settings (key, value) VALUES ('cloudflare_tunnel_id', '');
  INSERT OR IGNORE INTO settings (key, value) VALUES ('cloudflare_tunnel_api_token', '');
  INSERT OR IGNORE INTO settings (key, value) VALUES ('cloudflare_tunnel_account_id', '');
  INSERT OR IGNORE INTO settings (key, value) VALUES ('certbot_email', '');
  INSERT OR IGNORE INTO settings (key, value) VALUES ('plugin_trusted_keys_json', '[]');
  INSERT OR IGNORE INTO settings (key, value) VALUES ('allow_unsigned_plugins', '0');
  INSERT OR IGNORE INTO settings (key, value) VALUES ('log_retention_days', '30');
  INSERT OR IGNORE INTO settings (key, value) VALUES ('visitor_privacy_mode', 'none');
  INSERT OR IGNORE INTO settings (key, value) VALUES ('alert_cpu_percent', '90');
  INSERT OR IGNORE INTO settings (key, value) VALUES ('alert_event_loop_ms', '250');
  INSERT OR IGNORE INTO settings (key, value) VALUES ('alert_disk_percent', '90');
  INSERT OR IGNORE INTO settings (key, value) VALUES ('alert_traffic_multiplier', '5');
  INSERT OR IGNORE INTO settings (key, value) VALUES ('alert_error_percent', '25');

  INSERT OR IGNORE INTO settings (key, value) VALUES ('backup_provider', 'local');
  INSERT OR IGNORE INTO settings (key, value) VALUES ('backup_schedule', '0 3 * * *');
  INSERT OR IGNORE INTO settings (key, value) VALUES ('backup_enabled', '0');
  INSERT OR IGNORE INTO settings (key, value) VALUES ('backup_config', '');
  INSERT OR IGNORE INTO settings (key, value) VALUES ('alert_delivery_config', '');
  INSERT OR IGNORE INTO settings (key, value) VALUES ('prometheus_enabled', '0');
  INSERT OR IGNORE INTO settings (key, value) VALUES ('prometheus_token', '');
  INSERT OR IGNORE INTO settings (key, value) VALUES ('otel_endpoint', '');
  INSERT OR IGNORE INTO settings (key, value) VALUES ('otel_headers', '');
  INSERT OR IGNORE INTO settings (key, value) VALUES ('git_webhook_base_url', '');
  INSERT OR IGNORE INTO settings (key, value) VALUES ('public_status_enabled', '0');
  INSERT OR IGNORE INTO settings (key, value) VALUES ('public_status_title', 'SHAM service status');
  INSERT OR IGNORE INTO settings (key, value) VALUES ('instance_locale', 'en');
  INSERT OR IGNORE INTO settings (key, value) VALUES ('setup_completed', '0');
  INSERT OR IGNORE INTO settings (key, value) VALUES ('update_channel', 'stable');
  INSERT OR IGNORE INTO settings (key, value) VALUES ('oidc_enabled', '0');
  INSERT OR IGNORE INTO settings (key, value) VALUES ('oidc_issuer', '');
  INSERT OR IGNORE INTO settings (key, value) VALUES ('oidc_client_id', '');
  INSERT OR IGNORE INTO settings (key, value) VALUES ('oidc_client_secret', '');
  INSERT OR IGNORE INTO settings (key, value) VALUES ('oidc_auto_provision', '0');
  INSERT OR IGNORE INTO settings (key, value) VALUES ('oidc_default_role', 'user');
  INSERT OR IGNORE INTO settings (key, value) VALUES ('cloudflare_reconcile_enabled', '0');
  INSERT OR IGNORE INTO settings (key, value) VALUES ('cloudflare_reconcile_minutes', '15');

`);

ensureColumn('site_cloudflare_tunnels', 'tunnel_id', "TEXT NOT NULL DEFAULT ''");
ensureColumn('site_cloudflare_tunnels', 'public_hostname', "TEXT NOT NULL DEFAULT ''");
ensureColumn('site_cloudflare_tunnels', 'origin_service', "TEXT NOT NULL DEFAULT ''");
ensureColumn('site_cloudflare_tunnels', 'managed_route', 'INTEGER NOT NULL DEFAULT 0');
ensureColumn('site_cloudflare_tunnels', 'tunnel_only', 'INTEGER NOT NULL DEFAULT 0');
ensureColumn('site_cloudflare_tunnels', "connector_mode", "TEXT NOT NULL DEFAULT 'dedicated'");

/** @typedef {{ value: string }} SettingRow */

const oidcPasswordMigration = /** @type {SettingRow | undefined} */ (db.prepare("SELECT value FROM settings WHERE key = 'oidc_password_config_migrated'").get());
if (oidcPasswordMigration?.value !== '1') {
  db.transaction(() => {
    db.prepare('UPDATE users SET password_configured = 0 WHERE id IN (SELECT DISTINCT user_id FROM oidc_identities)').run();
    db.prepare("INSERT INTO settings (key, value) VALUES ('oidc_password_config_migrated', '1') ON CONFLICT(key) DO UPDATE SET value = excluded.value, updated_at = CURRENT_TIMESTAMP").run();
  })();
}

ensureColumn('site_performance_samples', 'p50_response_ms', 'REAL NOT NULL DEFAULT 0');
ensureColumn('site_performance_samples', 'restarts', 'INTEGER NOT NULL DEFAULT 0');

ensureColumn('site_visitor_stats', 'client_type', "TEXT NOT NULL DEFAULT 'unknown'");
ensureColumn('site_visitor_stats', 'user_agent', "TEXT NOT NULL DEFAULT ''");

function visitorStatsPrimaryKey() {
  const rows = /** @type {PragmaColumnRow[]} */ (db.prepare('PRAGMA table_info(site_visitor_stats)').all());
  return rows
    .filter((row) => Number(row.pk) > 0)
    .sort((a, b) => Number(a.pk) - Number(b.pk))
    .map((row) => row.name);
}

if (visitorStatsPrimaryKey().join(',') !== 'site_id,ip,country,client_type') {
  db.transaction(() => {
    db.exec(`
      DROP INDEX IF EXISTS idx_site_visitor_stats_recent;
      DROP INDEX IF EXISTS idx_site_visitor_stats_recent_global;
      DROP INDEX IF EXISTS idx_site_visitor_stats_ip;
      DROP INDEX IF EXISTS idx_site_visitor_stats_country;
      DROP INDEX IF EXISTS idx_site_visitor_stats_client;
      ALTER TABLE site_visitor_stats RENAME TO site_visitor_stats_legacy;
      CREATE TABLE site_visitor_stats (
        site_id INTEGER NOT NULL,
        ip TEXT NOT NULL,
        country TEXT NOT NULL DEFAULT 'ZZ',
        client_type TEXT NOT NULL DEFAULT 'unknown',
        user_agent TEXT NOT NULL DEFAULT '',
        requests INTEGER NOT NULL DEFAULT 0,
        bytes INTEGER NOT NULL DEFAULT 0,
        errors INTEGER NOT NULL DEFAULT 0,
        last_request_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
        PRIMARY KEY (site_id, ip, country, client_type),
        FOREIGN KEY (site_id) REFERENCES sites(id) ON DELETE CASCADE
      );
      INSERT INTO site_visitor_stats (site_id, ip, country, client_type, user_agent, requests, bytes, errors, last_request_at)
      SELECT site_id, ip, country,
        CASE WHEN client_type IN ('browser', 'search', 'crawler', 'llm', 'unknown') THEN client_type ELSE 'unknown' END,
        MAX(COALESCE(user_agent, '')), SUM(requests), SUM(bytes), SUM(errors), MAX(last_request_at)
      FROM site_visitor_stats_legacy
      GROUP BY site_id, ip, country,
        CASE WHEN client_type IN ('browser', 'search', 'crawler', 'llm', 'unknown') THEN client_type ELSE 'unknown' END;
      DROP TABLE site_visitor_stats_legacy;
    `);
  })();
}

ensureColumn('runtime_logs', 'deployment_id', 'INTEGER');
ensureColumn('site_releases', 'deployment_id', 'INTEGER');
ensureColumn('site_releases', 'manifest_hash', "TEXT NOT NULL DEFAULT ''");
ensureColumn('site_releases', 'runtime_config_json', "TEXT NOT NULL DEFAULT '{}'");
db.exec('CREATE INDEX IF NOT EXISTS idx_runtime_logs_deployment ON runtime_logs(deployment_id, created_at ASC)');
db.exec(`
  CREATE INDEX IF NOT EXISTS idx_site_visitor_stats_recent ON site_visitor_stats(site_id, last_request_at DESC);
  CREATE INDEX IF NOT EXISTS idx_site_visitor_stats_recent_global ON site_visitor_stats(last_request_at DESC);
  CREATE INDEX IF NOT EXISTS idx_site_visitor_stats_ip ON site_visitor_stats(ip);
  CREATE INDEX IF NOT EXISTS idx_site_visitor_stats_country ON site_visitor_stats(country);
  CREATE INDEX IF NOT EXISTS idx_site_visitor_stats_client ON site_visitor_stats(client_type, last_request_at DESC);
`);
db.exec('CREATE INDEX IF NOT EXISTS idx_site_releases_deployment ON site_releases(deployment_id)');

function tightenDatabasePermissions() {
  if (process.platform === 'win32') return;
  for (const filename of [DB_PATH, `${DB_PATH}-wal`, `${DB_PATH}-shm`]) {
    try { if (fs.existsSync(filename)) fs.chmodSync(filename, 0o600); }
    catch { /* Read-only or permission-managed storage may reject chmod. */ }
  }
}
tightenDatabasePermissions();

const { migrateKnownSecrets } = require('./secret-store');
migrateKnownSecrets(db);

/**
 * @param {string} key
 * @param {string | null} [fallback]
 * @returns {string | null}
 */
function getSetting(key, fallback = null) {
  const row = /** @type {SettingRow | undefined} */ (db.prepare('SELECT value FROM settings WHERE key = ?').get(key));
  return row ? row.value : fallback;
}

function setSetting(key, value) {
  db.prepare(`
    INSERT INTO settings (key, value, updated_at)
    VALUES (?, ?, CURRENT_TIMESTAMP)
    ON CONFLICT(key) DO UPDATE SET value = excluded.value, updated_at = CURRENT_TIMESTAMP
  `).run(key, String(value));
}

let auditWrites = 0;
const writeAudit = db.prepare('INSERT INTO audit_logs (user_id, action, detail) VALUES (?, ?, ?)');
const pruneAudit = db.prepare('DELETE FROM audit_logs WHERE id < COALESCE((SELECT id FROM audit_logs ORDER BY id DESC LIMIT 1 OFFSET 9999), 0)');
function audit(userId, action, detail = null) {
  writeAudit.run(userId || null, action, detail ? JSON.stringify(detail) : null);
  auditWrites += 1;
  if (auditWrites % 100 === 0) pruneAudit.run();
}

module.exports = { db, getSetting, setSetting, audit };
