'use strict';

const { isEncrypted } = require('../secret-store');
const { getRuntimeClient } = require('../runtime/client');
const { fs, path, crypto, DATA_DIR, PREVIEWS_DIR, BACKUPS_DIR, TAR_BIN, RESTIC_BIN, AWS_BIN, SFTP_BIN, JOB_POLL_INTERVAL_MS, JOB_TIMEOUT_MS, BACKUP_TIMEOUT_MS, encrypt, decrypt, getSecretSetting, setSecretSetting, appendTail, runProcess, parseCron, cronMatches, nextCronDate, pathInside, sftpQuote, siteRoot } = require('./shared');

/**
 * Base of the OperationsManager mixin chain (ConfigurationOperations ->
 * DeploymentOperations -> OperationsManager). `tick()` is only ever declared
 * on the final OperationsManager subclass, but the scheduler started here in
 * the base constructor calls `this.tick()` — safe in practice because the
 * interval callback only fires after the full subclass has finished
 * constructing, just not something TS's structural typing can see from here.
 */
class ConfigurationOperations {
  constructor({ db, manager, snapshotManager, edgeProxy = null }) {
    this.db = db;
    this.manager = manager;
    this.snapshotManager = snapshotManager;
    this.edgeProxy = edgeProxy;
    this.runningJobs = new Map();
    this.operationProcesses = new Set();
    this.previewRuntimes = new Map();
    this.previewHostnames = new Map();
    this.anubisRuntimes = new Map();
    this.stopping = false;
    this.jobTickPromise = null;
    this.backupPromise = null;
    this.lastBackupMinute = '';
    this.deliveredAlerts = new Map();
    this.lastTelemetryAt = 0;
    this.recoverInterruptedRuns();
    this.ensureJobSchedules();
    this.stalePreviewCleanupPromise = this.clearStalePreviews().catch((error) => this.manager.log(null, 'error', `Could not clean stale previews: ${error.message}`));
    getRuntimeClient().status().catch(() => {});
    this.timer = setInterval(() => (/** @type {{ tick: () => Promise<void> }} */ (/** @type {unknown} */ (this))).tick().catch((error) => this.manager.log(null, 'error', `Operations scheduler failed: ${error.message}`)), JOB_POLL_INTERVAL_MS);
    this.timer.unref?.();
  }

  setEdgeProxy(edgeProxy) { this.edgeProxy = edgeProxy; }

  trackProcess(child) {
    if (!child) return;
    this.operationProcesses.add(child);
    const release = () => this.operationProcesses.delete(child);
    child.once('exit', release);
    child.once('error', release);
  }

  trackedProcessOptions(options = {}) {
    return { ...options, onSpawn: (child) => { this.trackProcess(child); options.onSpawn?.(child); } };
  }

  recoverInterruptedRuns() {
    const transaction = this.db.transaction(() => {
      const deployments = this.db.prepare(`UPDATE site_deployments
        SET status = 'failed', detail = CASE WHEN detail = '' THEN 'Interrupted by SHAM restart.' ELSE substr(detail || '\nInterrupted by SHAM restart.', 1, 4000) END, finished_at = CURRENT_TIMESTAMP
        WHERE status IN ('queued', 'building') AND finished_at IS NULL`).run().changes;
      const jobs = this.db.prepare(`UPDATE job_runs
        SET status = 'failed', output = substr(output || CASE WHEN output = '' THEN '' ELSE '\n' END || '[SHAM] Interrupted by control-plane restart.', 1, 100000),
            finished_at = CURRENT_TIMESTAMP,
            duration_ms = COALESCE(duration_ms, CAST(MAX(0, (julianday(CURRENT_TIMESTAMP) - julianday(started_at)) * 86400000) AS INTEGER))
        WHERE status = 'running' AND finished_at IS NULL`).run().changes;
      const backups = this.db.prepare(`UPDATE backup_runs
        SET status = 'failed', detail = CASE WHEN COALESCE(detail, '') = '' THEN 'Interrupted by SHAM restart.' ELSE substr(detail || '\nInterrupted by SHAM restart.', 1, 4000) END, finished_at = CURRENT_TIMESTAMP
        WHERE status = 'running' AND finished_at IS NULL`).run().changes;
      return { deployments, jobs, backups };
    });
    const recovered = transaction();
    const total = recovered.deployments + recovered.jobs + recovered.backups;
    if (total) this.manager.log(null, 'warning', `Recovered ${total} interrupted operation${total === 1 ? '' : 's'} after restart.`);
  }

  ensureJobSchedules() {
    for (const job of this.db.prepare('SELECT id, schedule FROM site_jobs').all()) {
      try {
        const next = nextCronDate(job.schedule).toISOString();
        this.db.prepare('UPDATE site_jobs SET next_run_at = COALESCE(next_run_at, ?) WHERE id = ?').run(next, job.id);
      } catch (error) {
        this.db.prepare('UPDATE site_jobs SET enabled = 0, next_run_at = NULL WHERE id = ?').run(job.id);
        this.manager.log(null, 'error', `Disabled invalid scheduled job ${job.id}: ${error.message}`);
      }
    }
  }

  async clearStalePreviews() {
    const rows = this.db.prepare('SELECT directory_name FROM preview_deployments').all();
    this.db.prepare('DELETE FROM preview_deployments').run();
    for (let index = 0; index < rows.length; index += 8) {
      await Promise.allSettled(rows.slice(index, index + 8).map((row) => fs.promises.rm(path.join(PREVIEWS_DIR, row.directory_name), { recursive: true, force: true })));
    }
  }

  siteEnvironment(siteId, scope = 'runtime') {
    const result = {};
    for (const row of this.db.prepare("SELECT key, value, secret, scope FROM site_env WHERE site_id = ? AND (scope = ? OR scope = 'both') ORDER BY key").all(siteId, scope)) {
      try { result[row.key] = row.secret ? decrypt(row.value) : row.value; }
      catch (error) { this.manager.log(siteId, 'error', `Could not decrypt environment variable ${row.key}: ${error.message}`); }
    }
    for (const profile of this.db.prepare(`
      SELECT profiles.env_key, profiles.connection_value
      FROM database_profiles AS profiles
      JOIN site_database_profiles AS links ON links.profile_id = profiles.id
      WHERE links.site_id = ?
    `).all(siteId)) {
      try { result[profile.env_key] = decrypt(profile.connection_value); }
      catch (error) { this.manager.log(siteId, 'error', `Could not decrypt database profile ${profile.env_key}: ${error.message}`); }
    }
    return result;
  }

  listEnvironment(siteId) {
    return this.db.prepare('SELECT id, key, value, secret, scope, updated_at AS updatedAt FROM site_env WHERE site_id = ? ORDER BY key').all(siteId)
      .map((row) => ({ ...row, value: row.secret ? '' : row.value, secret: Boolean(row.secret), configured: true }));
  }

  revealEnvironmentSecret(siteId, key) {
    const normalizedKey = String(key || '').trim().toUpperCase();
    if (!/^[A-Z_][A-Z0-9_]{0,127}$/.test(normalizedKey)) throw new Error('Environment variable name is invalid.');
    const row = this.db.prepare('SELECT value, secret FROM site_env WHERE site_id = ? AND key = ?').get(Number(siteId), normalizedKey);
    if (!row) throw new Error('Environment variable not found.');
    if (!row.secret) return { key: normalizedKey, value: String(row.value || ''), secret: false };
    return { key: normalizedKey, value: decrypt(row.value), secret: true };
  }

  saveEnvironment(siteId, variables) {
    if (!Array.isArray(variables) || variables.length > 200) throw new Error('Environment variables must be an array with at most 200 entries.');
    const keep = [];
    const upsert = this.db.prepare(`
      INSERT INTO site_env (site_id, key, value, secret, scope, updated_at)
      VALUES (?, ?, ?, ?, ?, CURRENT_TIMESTAMP)
      ON CONFLICT(site_id, key) DO UPDATE SET value = excluded.value, secret = excluded.secret, scope = excluded.scope, updated_at = CURRENT_TIMESTAMP
    `);
    const transaction = this.db.transaction(() => {
      for (const item of variables) {
        const key = String(item.key || '').trim().toUpperCase();
        if (!/^[A-Z_][A-Z0-9_]{0,127}$/.test(key) || key.startsWith('SHAM_') || ['PORT', 'HOST', 'NODE_ENV'].includes(key)) throw new Error(`Environment variable “${key || '?'}” is invalid or reserved.`);
        const scope = ['runtime', 'build', 'both'].includes(item.scope) ? item.scope : 'runtime';
        const secret = Boolean(item.secret);
        const existing = this.db.prepare('SELECT value, secret FROM site_env WHERE site_id = ? AND key = ?').get(siteId, key);
        let value = item.value === undefined || item.value === null ? '' : String(item.value);
        if (value.length > 64 * 1024 || /\0/.test(value)) throw new Error(`Environment variable ${key} is too large or invalid.`);
        if (secret && !value && existing?.secret && !item.clear) value = existing.value;
        else value = secret ? encrypt(value) : value;
        upsert.run(siteId, key, value, Number(secret), scope);
        keep.push(key);
      }
      if (keep.length) this.db.prepare(`DELETE FROM site_env WHERE site_id = ? AND key NOT IN (${keep.map(() => '?').join(',')})`).run(siteId, ...keep);
      else this.db.prepare('DELETE FROM site_env WHERE site_id = ?').run(siteId);
    });
    transaction();
    return this.listEnvironment(siteId);
  }

  ensureDeployWebhookSecret(siteId) {
    const row = this.db.prepare('SELECT value, secret, scope FROM site_env WHERE site_id = ? AND key = ?').get(Number(siteId), 'DEPLOY_WEBHOOK_SECRET');
    let value = '';
    if (row?.value) {
      try { value = row.secret ? decrypt(row.value) : String(row.value); }
      catch { value = ''; }
    }
    if (!value) value = crypto.randomBytes(32).toString('hex');
    const scope = row?.scope === 'runtime' ? 'both' : row?.scope === 'both' ? 'both' : 'build';
    this.db.prepare(`INSERT INTO site_env (site_id, key, value, secret, scope, updated_at) VALUES (?, 'DEPLOY_WEBHOOK_SECRET', ?, 1, ?, CURRENT_TIMESTAMP)
      ON CONFLICT(site_id, key) DO UPDATE SET value = excluded.value, secret = 1, scope = excluded.scope, updated_at = CURRENT_TIMESTAMP`).run(Number(siteId), encrypt(value), scope);
    return value;
  }

  copyEnvironment(sourceSiteId, targetSiteId) {
    const sourceId = Number(sourceSiteId);
    const targetId = Number(targetSiteId);
    if (!Number.isInteger(sourceId) || sourceId <= 0 || !Number.isInteger(targetId) || targetId <= 0) throw new Error('Source and target site IDs are required.');
    if (sourceId === targetId) return { copied: 0, environment: this.listEnvironment(targetId) };
    const source = this.db.prepare('SELECT id, name FROM sites WHERE id = ?').get(sourceId);
    const target = this.db.prepare('SELECT id, name FROM sites WHERE id = ?').get(targetId);
    if (!source || !target) throw new Error('Source or target site was not found.');
    const variables = this.db.prepare("SELECT key, value, secret, scope FROM site_env WHERE site_id = ? AND key <> 'DEPLOY_WEBHOOK_SECRET' ORDER BY key").all(sourceId);
    const upsert = this.db.prepare(`
      INSERT INTO site_env (site_id, key, value, secret, scope, updated_at)
      VALUES (?, ?, ?, ?, ?, CURRENT_TIMESTAMP)
      ON CONFLICT(site_id, key) DO UPDATE SET value = excluded.value, secret = excluded.secret, scope = excluded.scope, updated_at = CURRENT_TIMESTAMP
    `);
    this.db.transaction(() => {
      for (const variable of variables) upsert.run(targetId, variable.key, variable.value, variable.secret, variable.scope);
    })();
    return { copied: variables.length, source: source.name, target: target.name, environment: this.listEnvironment(targetId) };
  }

  listDatabaseProfiles(siteId = null) {
    const profiles = this.db.prepare('SELECT id, name, type, env_key AS envKey, updated_at AS updatedAt FROM database_profiles ORDER BY name').all();
    if (siteId == null) return profiles;
    const attached = new Set(this.db.prepare('SELECT profile_id FROM site_database_profiles WHERE site_id = ?').all(siteId).map((row) => row.profile_id));
    return profiles.map((profile) => ({ ...profile, attached: attached.has(profile.id) }));
  }

  saveDatabaseProfile(input) {
    const id = Number(input.id || 0);
    const name = String(input.name || '').trim().slice(0, 100);
    const type = String(input.type || 'custom').trim().toLowerCase().slice(0, 40);
    const envKey = String(input.envKey || 'DATABASE_URL').trim().toUpperCase();
    if (!name || !/^[a-z0-9_-]+$/.test(type) || !/^[A-Z_][A-Z0-9_]{0,127}$/.test(envKey)) throw new Error('Database profile name, type, or environment key is invalid.');
    const existing = id ? this.db.prepare('SELECT connection_value FROM database_profiles WHERE id = ?').get(id) : null;
    let connection = String(input.connection || '');
    if (!connection && existing) connection = isEncrypted(existing.connection_value) ? existing.connection_value : encrypt(existing.connection_value);
    else {
      if (!connection || connection.length > 16 * 1024 || /[\r\n\0]/.test(connection)) throw new Error('Connection value is invalid.');
      connection = encrypt(connection);
    }
    if (id) {
      const result = this.db.prepare('UPDATE database_profiles SET name = ?, type = ?, env_key = ?, connection_value = ?, updated_at = CURRENT_TIMESTAMP WHERE id = ?').run(name, type, envKey, connection, id);
      if (!result.changes) throw new Error('Database profile not found.');
      return id;
    }
    return Number(this.db.prepare('INSERT INTO database_profiles (name, type, env_key, connection_value) VALUES (?, ?, ?, ?)').run(name, type, envKey, connection).lastInsertRowid);
  }

  attachDatabaseProfiles(siteId, profileIds) {
    const ids = [...new Set((Array.isArray(profileIds) ? profileIds : []).map(Number).filter((id) => Number.isInteger(id) && id > 0))];
    const transaction = this.db.transaction(() => {
      this.db.prepare('DELETE FROM site_database_profiles WHERE site_id = ?').run(siteId);
      const insert = this.db.prepare('INSERT INTO site_database_profiles (site_id, profile_id) VALUES (?, ?)');
      for (const id of ids) insert.run(siteId, id);
    });
    transaction();
    return this.listDatabaseProfiles(siteId);
  }

  deleteDatabaseProfile(id) {
    const result = this.db.prepare('DELETE FROM database_profiles WHERE id = ?').run(Number(id));
    if (!result.changes) throw new Error('Database profile not found.');
  }

  listJobs(siteId) {
    return this.db.prepare(`SELECT jobs.*, (SELECT status FROM job_runs WHERE job_id = jobs.id ORDER BY id DESC LIMIT 1) AS last_status FROM site_jobs AS jobs WHERE site_id = ? ORDER BY name`).all(siteId)
      .map((row) => ({ ...row, enabled: Boolean(row.enabled), allow_overlap: Boolean(row.allow_overlap), running: Boolean(this.runningJobs.get(row.id)?.size) }));
  }

  saveJob(siteId, input) {
    const id = Number(input.id || 0);
    const name = String(input.name || '').trim().slice(0, 100);
    const schedule = String(input.schedule || '').trim();
    const command = String(input.command || '').trim();
    if (!name || !command || command.length > 4000 || /\0/.test(command)) throw new Error('Job name and command are required.');
    const next = nextCronDate(schedule).toISOString();
    const timeout = Math.min(Math.max(Number(input.timeoutSeconds) || JOB_TIMEOUT_MS / 1000, 5), 86400);
    if (id) {
      const result = this.db.prepare(`UPDATE site_jobs SET name = ?, schedule = ?, command = ?, enabled = ?, timeout_seconds = ?, allow_overlap = ?, next_run_at = ?, updated_at = CURRENT_TIMESTAMP WHERE id = ? AND site_id = ?`)
        .run(name, schedule, command, Number(input.enabled !== false), timeout, Number(Boolean(input.allowOverlap)), next, id, siteId);
      if (!result.changes) throw new Error('Scheduled job not found.');
      return id;
    }
    return Number(this.db.prepare('INSERT INTO site_jobs (site_id, name, schedule, command, enabled, timeout_seconds, allow_overlap, next_run_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?)')
      .run(siteId, name, schedule, command, Number(input.enabled !== false), timeout, Number(Boolean(input.allowOverlap)), next).lastInsertRowid);
  }

  deleteJob(siteId, id) {
    if (this.runningJobs.get(Number(id))?.size) throw new Error('Stop or wait for the running job before deleting it.');
    const result = this.db.prepare('DELETE FROM site_jobs WHERE id = ? AND site_id = ?').run(Number(id), siteId);
    if (!result.changes) throw new Error('Scheduled job not found.');
  }

  async executeSiteCommand(site, command, timeoutMs, onLine) {
    const root = siteRoot(site);
    const backend = this.manager.running.get(Number(site.id))?.backend || null;
    if (backend?.driver === 'container') {
      await getRuntimeClient().containerExec({ name: backend.containerName || backend.containerId, command, timeoutMs, onLine });
      return { ok: true };
    }
    if (backend?.driver === 'compose') {
      await getRuntimeClient().composeExec({ project: backend.composeProject, files: backend.composeFiles || [backend.composeFile], cwd: backend.cwd, env: backend.env, service: backend.composeService, command, timeoutMs, onLine });
      return { ok: true };
    }
    if (site.runtime_type === 'container' || site.runtime_type === 'compose' || (site.runtime_type === 'node' && site.runtime_isolation === 'docker')) {
      throw new Error('The container runtime must be running before a scheduled or manual site command can execute inside it.');
    }
    const shell = process.platform === 'win32' ? process.env.ComSpec || 'cmd.exe' : '/bin/sh';
    const args = process.platform === 'win32' ? ['/d', '/s', '/c', command] : ['-lc', command];
    return runProcess(shell, args, this.trackedProcessOptions({ cwd: root, env: this.siteEnvironment(site.id, 'runtime'), timeoutMs, onLine, environmentMode: 'runtime' }));
  }

  async runJob(jobId, trigger = 'manual', expectedSiteId = null) {
    const numericJobId = Number(jobId);
    const numericSiteId = expectedSiteId == null ? null : Number(expectedSiteId);
    const job = numericSiteId == null
      ? this.db.prepare('SELECT * FROM site_jobs WHERE id = ?').get(numericJobId)
      : this.db.prepare('SELECT * FROM site_jobs WHERE id = ? AND site_id = ?').get(numericJobId, numericSiteId);
    if (!job) throw new Error('Scheduled job not found.');
    const activeRuns = this.runningJobs.get(job.id) || new Set();
    if (activeRuns.size && !job.allow_overlap) throw new Error('This job is already running.');
    const site = this.manager.getSite(job.site_id);
    if (!site) throw new Error('Site not found.');
    const runId = Number(this.db.prepare("INSERT INTO job_runs (job_id, status, output) VALUES (?, 'running', '')").run(job.id).lastInsertRowid);
    const started = Date.now();
    let output = '';
    let operation;
    operation = this.executeSiteCommand(site, job.command, Math.min(job.timeout_seconds * 1000, 86400_000), (level, line) => {
      output = appendTail(output, `[${level}] ${line}\n`);
      this.manager.log(site.id, level, `job ${job.name}: ${line}`);
    }).then(() => {
      this.db.prepare("UPDATE job_runs SET status = 'success', output = ?, finished_at = CURRENT_TIMESTAMP, duration_ms = ? WHERE id = ?").run(output, Date.now() - started, runId);
      this.manager.log(site.id, 'info', `Scheduled job “${job.name}” completed (${trigger}).`);
      return { runId, status: 'success' };
    }, (error) => {
      output = appendTail(output, `\n${error.message}`);
      this.db.prepare("UPDATE job_runs SET status = 'failed', output = ?, finished_at = CURRENT_TIMESTAMP, duration_ms = ? WHERE id = ?").run(output, Date.now() - started, runId);
      this.manager.log(site.id, 'error', `Scheduled job “${job.name}” failed: ${error.message}`);
      throw error;
    }).finally(() => {
      activeRuns.delete(operation);
      if (!activeRuns.size && this.runningJobs.get(job.id) === activeRuns) this.runningJobs.delete(job.id);
    });
    activeRuns.add(operation);
    this.runningJobs.set(job.id, activeRuns);
    return operation;
  }

  async tickJobs(now) {
    const due = this.db.prepare("SELECT id, schedule FROM site_jobs WHERE enabled = 1 AND next_run_at IS NOT NULL AND next_run_at <= ? ORDER BY next_run_at LIMIT 20").all(now.toISOString());
    for (const job of due) {
      const next = nextCronDate(job.schedule, now).toISOString();
      this.db.prepare('UPDATE site_jobs SET last_started_at = CURRENT_TIMESTAMP, next_run_at = ? WHERE id = ?').run(next, job.id);
      this.runJob(job.id, 'schedule').catch(() => {});
    }
  }

  _backupSettings() {
    let config;
    try { config = JSON.parse(getSecretSetting(this.db, 'backup_config', '{}')); } catch { config = {}; }
    return {
      enabled: this.db.prepare("SELECT value FROM settings WHERE key = 'backup_enabled'").get()?.value === '1',
      provider: this.db.prepare("SELECT value FROM settings WHERE key = 'backup_provider'").get()?.value || 'local',
      schedule: this.db.prepare("SELECT value FROM settings WHERE key = 'backup_schedule'").get()?.value || '0 3 * * *',
      configured: Boolean(Object.keys(config).length),
      config
    };
  }

  backupSettings() {
    const settings = this._backupSettings();
    const sensitive = new Set(['password', 'accessKey', 'secretKey', 'sessionToken', 'privateKey', 'passphrase']);
    const config = {};
    const secretFields = [];
    for (const [key, value] of Object.entries(settings.config || {})) {
      if (sensitive.has(key)) {
        if (value !== undefined && value !== null && String(value) !== '') secretFields.push(key);
      } else config[key] = value;
    }
    return { ...settings, config, secretFields };
  }

  saveBackupSettings(input) {
    const provider = String(input.provider || 'local');
    if (!['local', 'restic', 's3', 'sftp'].includes(provider)) throw new Error('Backup provider must be local, restic, s3, or sftp.');
    const schedule = String(input.schedule || '0 3 * * *');
    parseCron(schedule);
    const incoming = input.config && typeof input.config === 'object' && !Array.isArray(input.config) ? input.config : {};
    const existing = this._backupSettings().config || {};
    const sensitive = new Set(['password', 'accessKey', 'secretKey', 'sessionToken', 'privateKey', 'passphrase']);
    const config = { ...existing };
    for (const [key, value] of Object.entries(incoming)) {
      if (!/^[a-zA-Z][a-zA-Z0-9_-]{0,63}$/.test(key)) throw new Error(`Backup option “${key}” is invalid.`);
      if (sensitive.has(key) && (value === '' || value === null || value === undefined)) continue;
      if (value === undefined) continue;
      config[key] = value;
    }
    for (const key of Array.isArray(input.clearSecrets) ? input.clearSecrets : []) {
      if (sensitive.has(String(key))) delete config[String(key)];
    }
    const serialized = JSON.stringify(config);
    if (serialized.length > 128 * 1024 || serialized.includes('\0')) throw new Error('Backup provider configuration is too large or invalid.');
    this.db.prepare("UPDATE settings SET value = ?, updated_at = CURRENT_TIMESTAMP WHERE key = 'backup_enabled'").run(input.enabled ? '1' : '0');
    this.db.prepare("UPDATE settings SET value = ?, updated_at = CURRENT_TIMESTAMP WHERE key = 'backup_provider'").run(provider);
    this.db.prepare("UPDATE settings SET value = ?, updated_at = CURRENT_TIMESTAMP WHERE key = 'backup_schedule'").run(schedule);
    setSecretSetting(this.db, 'backup_config', serialized);
    return this.backupSettings();
  }

  async createBackup({ provider = null, skipRetention = false } = {}) {
    if (this.backupPromise) return this.backupPromise;
    const operation = this._createBackup(provider, { skipRetention }).finally(() => { if (this.backupPromise === operation) this.backupPromise = null; });
    this.backupPromise = operation;
    return operation;
  }

  async _createBackup(providerOverride, { skipRetention = false } = {}) {
    const settings = this._backupSettings();
    const provider = providerOverride || settings.provider;
    if (!['local', 'restic', 's3', 'sftp'].includes(provider)) throw new Error('Backup provider is invalid.');

    const stamp = new Date().toISOString().replace(/[:.]/g, '-');
    const filename = `sham-backup-${stamp}.tar.gz`;
    const localPath = path.join(BACKUPS_DIR, filename);
    const runId = Number(this.db.prepare("INSERT INTO backup_runs (destination, status, filename) VALUES (?, 'running', ?)").run(provider, filename).lastInsertRowid);
    let databaseSnapshotDirectory = '';

    try {
      await fs.promises.writeFile(localPath, '', { flag: 'wx', mode: 0o600 });
      databaseSnapshotDirectory = await fs.promises.mkdtemp(path.join(DATA_DIR, 'tmp', 'backup-db-'));
      await this.db.backup(path.join(databaseSnapshotDirectory, 'sham.db'));
      await runProcess(TAR_BIN, [
        '--exclude=./tmp', '--exclude=./backups', '--exclude=./updates',
        '--exclude=./sham.db', '--exclude=./sham.db-wal', '--exclude=./sham.db-shm',
        '-czf', localPath, '-C', DATA_DIR, '.', '-C', databaseSnapshotDirectory, 'sham.db'
      ], this.trackedProcessOptions({ timeoutMs: BACKUP_TIMEOUT_MS, onLine: (level, line) => this.manager.log(null, level, `backup: ${line}`) }));
      await runProcess(TAR_BIN, ['-tzf', localPath], this.trackedProcessOptions({ timeoutMs: Math.min(BACKUP_TIMEOUT_MS, 10 * 60 * 1000) }));
      await fs.promises.chmod(localPath, 0o600);

      const stat = await fs.promises.stat(localPath);
      const config = settings.config || {};
      let destination = provider;
      /** @type {string | null} */
      let externalLocalDirectory = null;

      if (provider === 'local' && config.destination) {
        if (String(config.destination).includes('\0')) throw new Error('Local backup destination is invalid.');
        await fs.promises.mkdir(path.resolve(String(config.destination)), { recursive: true, mode: 0o700 });
        externalLocalDirectory = await fs.promises.realpath(path.resolve(String(config.destination)));
        const dataRoot = await fs.promises.realpath(DATA_DIR);
        const builtInBackupRoot = await fs.promises.realpath(BACKUPS_DIR);
        if (pathInside(dataRoot, externalLocalDirectory) && externalLocalDirectory !== builtInBackupRoot) {
          throw new Error('External local backups must be stored outside SHAM_DATA_PATH to avoid recursive archives.');
        }
        const target = path.join(externalLocalDirectory, filename);
        if (path.resolve(target) !== path.resolve(localPath)) {
          await fs.promises.copyFile(localPath, target, fs.constants.COPYFILE_EXCL);
          await fs.promises.chmod(target, 0o600);
        }
        destination = target;
      } else if (provider === 'restic') {
        if (!config.repository || !config.password) throw new Error('Restic repository and password are required.');
        await runProcess(RESTIC_BIN, ['backup', localPath, '--tag', 'sham'], this.trackedProcessOptions({
          timeoutMs: BACKUP_TIMEOUT_MS,
          env: { RESTIC_REPOSITORY: config.repository, RESTIC_PASSWORD: config.password }
        }));
        destination = String(config.repository);
      } else if (provider === 's3') {
        const s3Destination = String(config.destination || '');
        if (!/^s3:\/\/[A-Za-z0-9][A-Za-z0-9._-]{1,62}(?:\/[^\r\n\0]*)?$/.test(s3Destination)) {
          throw new Error('S3 destination must be a valid s3:// bucket path.');
        }
        const target = `${s3Destination.replace(/\/$/, '')}/${filename}`;
        const args = ['s3', 'cp', localPath, target];
        if (config.endpoint) args.push('--endpoint-url', String(config.endpoint));
        await runProcess(AWS_BIN, args, this.trackedProcessOptions({
          timeoutMs: BACKUP_TIMEOUT_MS,
          env: {
            AWS_ACCESS_KEY_ID: config.accessKey || '',
            AWS_SECRET_ACCESS_KEY: config.secretKey || '',
            AWS_SESSION_TOKEN: config.sessionToken || '',
            AWS_DEFAULT_REGION: config.region || ''
          }
        }));
        destination = target;
      } else if (provider === 'sftp') {
        if (!config.host || !config.remotePath) throw new Error('SFTP host and remote path are required.');
        const host = String(config.host);
        const user = String(config.user || '');
        if (!/^(?:[A-Za-z0-9.-]+|\[[0-9A-Fa-f:]+\])$/.test(host) || (user && !/^[A-Za-z0-9._-]+$/.test(user))) {
          throw new Error('SFTP host or user is invalid.');
        }
        const target = user ? `${user}@${host}` : host;
        const args = ['-b', '-'];
        let keyPath = '';
        try {
          if (config.privateKey) {
            keyPath = path.join(DATA_DIR, 'tmp', `sftp-key-${crypto.randomUUID()}`);
            await fs.promises.writeFile(keyPath, String(config.privateKey), { mode: 0o600 });
            args.push('-i', keyPath, '-o', 'IdentitiesOnly=yes');
          }
          if (config.port) {
            const sftpPort = Number(config.port);
            if (!Number.isInteger(sftpPort) || sftpPort < 1 || sftpPort > 65535) throw new Error('SFTP port is invalid.');
            args.push('-P', String(sftpPort));
          }
          args.push(target);
          const remote = `${String(config.remotePath).replace(/\/$/, '')}/${filename}`;
          await runProcess(SFTP_BIN, args, this.trackedProcessOptions({
            timeoutMs: BACKUP_TIMEOUT_MS,
            stdin: `put ${sftpQuote(localPath, 'Local backup path')} ${sftpQuote(remote, 'Remote backup path')}\n`
          }));
          destination = `${target}:${remote}`;
        } finally {
          if (keyPath) await fs.promises.rm(keyPath, { force: true }).catch(() => {});
        }
      }

      this.db.prepare("UPDATE backup_runs SET destination = ?, status = 'success', bytes = ?, detail = 'Archive integrity verified', finished_at = CURRENT_TIMESTAMP WHERE id = ?").run(String(destination).slice(0, 2000), stat.size, runId);
      if (!skipRetention) {
        const retention = Math.min(Math.max(Number(config.retention) || 14, 1), 365);
        const localBackups = (await fs.promises.readdir(BACKUPS_DIR)).filter((name) => /^sham-backup-.*\.tar\.gz$/.test(name)).sort().reverse();
        for (const name of localBackups.slice(retention)) await fs.promises.rm(path.join(BACKUPS_DIR, name), { force: true });
        if (externalLocalDirectory) {
          const externalBackups = (await fs.promises.readdir(externalLocalDirectory)).filter((name) => /^sham-backup-.*\.tar\.gz$/.test(name)).sort().reverse();
          for (const name of externalBackups.slice(retention)) await fs.promises.rm(path.join(externalLocalDirectory, name), { force: true });
        }
      }
      this.manager.log(null, 'info', `Backup ${filename} completed using ${provider}; archive integrity was verified.`);
      return { id: runId, filename, bytes: stat.size, provider, destination, verified: true };
    } catch (error) {
      await fs.promises.rm(localPath, { force: true }).catch(() => {});
      this.db.prepare("UPDATE backup_runs SET status = 'failed', detail = ?, finished_at = CURRENT_TIMESTAMP WHERE id = ?").run(error.message.slice(0, 4000), runId);
      throw error;
    } finally {
      if (databaseSnapshotDirectory) await fs.promises.rm(databaseSnapshotDirectory, { recursive: true, force: true }).catch(() => {});
    }
  }

  async tickBackup(now) {
    const settings = this._backupSettings();
    if (!settings.enabled || !cronMatches(settings.schedule, now)) return;
    const minute = now.toISOString().slice(0, 16);
    if (this.lastBackupMinute === minute) return;
    this.lastBackupMinute = minute;
    this.createBackup({}).catch((error) => this.manager.log(null, 'error', `Scheduled backup failed: ${error.message}`));
  }

}

module.exports = { ConfigurationOperations };
