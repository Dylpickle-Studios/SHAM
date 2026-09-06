'use strict';

const { DeploymentOperations } = require('./deployments');
const { getRuntimeClient } = require('../runtime/client');
const { fs, GIT_BIN, ANUBIS_IMAGE, encrypt, decrypt, getSecretSetting, commandAvailable, terminateAndWait, runProcess } = require('./shared');
const { DATA_DIR, DB_PATH } = require('../config');

/** @typedef {{ enabled?: boolean, connected?: boolean, lastError?: string }} ConnectorHealth */

class OperationsManager extends DeploymentOperations {
  /** @param {{ cloudflare?: ConnectorHealth | null, pangolin?: ConnectorHealth | null }} [connectors] */
  async systemHealth({ cloudflare = null, pangolin = null } = {}) {
    const checks = [];
    const add = (id, label, status, detail, metadata = {}) => checks.push({ id, label, status, detail, ...metadata });
    try {
      const result = this.db.pragma('quick_check', { simple: true });
      add('sqlite', 'SQLite integrity', result === 'ok' ? 'healthy' : 'error', result === 'ok' ? 'Integrity check passed.' : String(result));
    } catch (error) { add('sqlite', 'SQLite integrity', 'error', error.message); }
    try {
      const storage = await fs.promises.statfs(DATA_DIR);
      const totalBytes = Number(storage.blocks) * Number(storage.bsize);
      const freeBytes = Number(storage.bavail) * Number(storage.bsize);
      const freePercent = totalBytes ? Math.round((freeBytes / totalBytes) * 1000) / 10 : 0;
      add('storage', 'Persistent storage', freePercent < 5 ? 'error' : freePercent < 15 ? 'warning' : 'healthy', `${freePercent}% free.`, { totalBytes, freeBytes, path: DATA_DIR });
    } catch (error) { add('storage', 'Persistent storage', 'error', error.message); }
    try {
      const wal = await fs.promises.stat(`${DB_PATH}-wal`).catch(() => null);
      add('wal', 'SQLite WAL', wal && wal.size > 256 * 1024 * 1024 ? 'warning' : 'healthy', wal ? `${wal.size} bytes.` : 'No WAL file is currently present.', { bytes: wal?.size || 0 });
    } catch (error) { add('wal', 'SQLite WAL', 'warning', error.message); }
    const capabilities = this.capabilities();
    add('runtime-agent', 'Runtime Agent', capabilities.docker ? 'healthy' : 'warning', capabilities.docker ? 'Authenticated and Docker is reachable.' : capabilities.dockerReason || 'Unavailable.');
    const latestBackup = this.db.prepare('SELECT status, finished_at AS finishedAt, detail FROM backup_runs ORDER BY id DESC LIMIT 1').get();
    add('backup', 'Latest backup', !latestBackup ? 'warning' : latestBackup.status === 'success' ? 'healthy' : latestBackup.status === 'running' ? 'warning' : 'error', !latestBackup ? 'No backup has been recorded.' : `${latestBackup.status}${latestBackup.finishedAt ? ` at ${latestBackup.finishedAt}` : ''}.`, { lastCompletedAt: latestBackup?.status === 'success' ? latestBackup.finishedAt : null });
    for (const { id, label, tunnel } of [{ id: 'cloudflare', label: 'Cloudflare Tunnel', tunnel: cloudflare }, { id: 'pangolin', label: 'Pangolin / Newt', tunnel: pangolin }]) {
      if (!tunnel?.enabled) add(id, label, 'disabled', 'Not enabled.');
      else if (tunnel.connected) add(id, label, 'healthy', 'Connector is connected.');
      else add(id, label, 'warning', tunnel.lastError || 'Connector is enabled but not connected.');
    }
    const rank = { healthy: 0, disabled: 0, warning: 1, error: 2 };
    const overall = checks.reduce((current, check) => rank[check.status] > rank[current] ? check.status : current, 'healthy');
    return { overall, checkedAt: new Date().toISOString(), checks };
  }

  validateAlertDestinationConfig(kind, input) {
    const config = input && typeof input === 'object' && !Array.isArray(input) ? input : {};
    if (kind === 'email') {
      const to = String(config.to || '').trim();
      const from = String(config.from || '').trim();
      const sendmail = String(config.sendmail || '').trim();
      if (!to || to.length > 320 || /[\r\n]/.test(to) || !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(to)) throw new Error('Email destination requires a valid recipient address.');
      if (from && (from.length > 320 || /[\r\n]/.test(from) || !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(from))) throw new Error('Alert sender address is invalid.');
      if (sendmail.length > 512 || /[\0\r\n]/.test(sendmail)) throw new Error('Sendmail executable is invalid.');
      return { to, ...(from ? { from } : {}), ...(sendmail ? { sendmail } : {}) };
    }
    const rawUrl = String(config.url || '').trim();
    if (!rawUrl || rawUrl.length > 2048) throw new Error('Webhook destination requires a URL.');
    let target;
    try { target = new URL(rawUrl); } catch { throw new Error('Webhook destination URL is invalid.'); }
    if (!['http:', 'https:'].includes(target.protocol) || target.username || target.password) throw new Error('Webhook destination URL must use HTTP or HTTPS without embedded credentials.');
    const rawHeaders = config.headers && typeof config.headers === 'object' && !Array.isArray(config.headers) ? config.headers : {};
    const entries = Object.entries(rawHeaders);
    if (entries.length > 50) throw new Error('Alert destination can define at most 50 HTTP headers.');
    const headers = {};
    const seen = new Set();
    for (const [rawName, rawValue] of entries) {
      const name = String(rawName || '').trim();
      const value = String(rawValue ?? '');
      const normalized = name.toLowerCase();
      const forbidden = new Set(['connection', 'content-length', 'host', 'keep-alive', 'proxy-authenticate', 'proxy-authorization', 'te', 'trailer', 'transfer-encoding', 'upgrade']);
      if (!/^[!#$%&'*+.^_`|~0-9A-Za-z-]{1,200}$/.test(name) || /[\0\r\n]/.test(value) || value.length > 4096 || forbidden.has(normalized)) throw new Error('Alert destination contains an invalid or unsafe HTTP header.');
      if (seen.has(normalized)) throw new Error(`Alert destination header “${name}” is duplicated.`);
      seen.add(normalized);
      headers[name] = value;
    }
    return { url: target.toString(), ...(entries.length ? { headers } : {}) };
  }

  listAlertDestinations() {
    return this.db.prepare('SELECT id, name, kind, enabled, updated_at AS updatedAt FROM alert_destinations ORDER BY name').all()
      .map((row) => ({ ...row, enabled: Boolean(row.enabled), configured: true }));
  }

  saveAlertDestination(input) {
    const id = Number(input.id || 0);
    const name = String(input.name || '').trim().slice(0, 100);
    const kind = String(input.kind || '').toLowerCase();
    if (!name || !['webhook', 'slack', 'discord', 'email'].includes(kind)) throw new Error('Alert destination name or type is invalid.');
    const existing = id ? this.db.prepare('SELECT config_encrypted FROM alert_destinations WHERE id = ?').get(id) : null;
    const config = input.config && typeof input.config === 'object' ? this.validateAlertDestinationConfig(kind, input.config) : null;
    let encrypted = existing?.config_encrypted || '';
    if (config && Object.keys(config).length) {
      const serialized = JSON.stringify(config);
      if (serialized.length > 64 * 1024 || /\0/.test(serialized)) throw new Error('Alert destination configuration is invalid.');
      encrypted = encrypt(serialized);
    }
    if (!encrypted) throw new Error('Alert destination configuration is required.');
    if (id) {
      const result = this.db.prepare('UPDATE alert_destinations SET name = ?, kind = ?, config_encrypted = ?, enabled = ?, updated_at = CURRENT_TIMESTAMP WHERE id = ?').run(name, kind, encrypted, Number(input.enabled !== false), id);
      if (!result.changes) throw new Error('Alert destination not found.');
      return id;
    }
    return Number(this.db.prepare('INSERT INTO alert_destinations (name, kind, config_encrypted, enabled) VALUES (?, ?, ?, ?)').run(name, kind, encrypted, Number(input.enabled !== false)).lastInsertRowid);
  }

  deleteAlertDestination(id) {
    const result = this.db.prepare('DELETE FROM alert_destinations WHERE id = ?').run(Number(id));
    if (!result.changes) throw new Error('Alert destination not found.');
  }

  alertConfig(row) {
    try { return JSON.parse(decrypt(row.config_encrypted)); }
    catch { throw new Error(`Alert destination “${row.name}” has unreadable encrypted settings.`); }
  }

  async sendAlert(row, alert) {
    const config = this.alertConfig(row);
    const title = `[SHAM ${String(alert.severity || 'info').toUpperCase()}] ${alert.title}`;
    const detail = `${alert.detail}\n${alert.site_id ? `Site ID: ${alert.site_id}\n` : ''}Seen: ${alert.last_seen_at || alert.created_at}`;
    if (row.kind === 'email') {
      if (!config.to) throw new Error('Email destination requires a recipient.');
      const message = `To: ${String(config.to).replace(/[\r\n]/g, '')}\nFrom: ${String(config.from || 'sham@localhost').replace(/[\r\n]/g, '')}\nSubject: ${title.replace(/[\r\n]/g, '')}\nContent-Type: text/plain; charset=utf-8\n\n${detail}\n`;
      await runProcess(config.sendmail || process.env.SHAM_SENDMAIL_BIN || 'sendmail', ['-t', '-i'], this.trackedProcessOptions({ timeoutMs: 30_000, stdin: message }));
      return;
    }
    const url = String(config.url || '').trim();
    if (!/^https?:\/\//i.test(url)) throw new Error('Webhook destination URL is invalid.');
    /** @type {Record<string, unknown>} */
    let body = { title, detail, severity: alert.severity, siteId: alert.site_id, fingerprint: alert.fingerprint };
    if (row.kind === 'slack') body = { text: `*${title}*\n${detail}` };
    if (row.kind === 'discord') body = { content: `**${title}**\n${detail}`.slice(0, 1900) };
    const response = await fetch(url, {
      method: 'POST', redirect: 'error', signal: AbortSignal.timeout(15_000),
      headers: { 'Content-Type': 'application/json', ...(config.headers || {}) },
      body: JSON.stringify(body)
    });
    const status = response.status;
    await response.body?.cancel().catch(() => {});
    if (!response.ok) throw new Error(`Alert webhook returned HTTP ${status}.`);
  }

  async testAlertDestination(id) {
    const row = this.db.prepare('SELECT * FROM alert_destinations WHERE id = ?').get(Number(id));
    if (!row) throw new Error('Alert destination not found.');
    await this.sendAlert(row, { severity: 'info', title: 'Test notification', detail: 'SHAM successfully reached this alert destination.', site_id: null, fingerprint: 'test', created_at: new Date().toISOString() });
  }

  async deliverAlerts() {
    const destinations = this.db.prepare('SELECT * FROM alert_destinations WHERE enabled = 1 ORDER BY id').all();
    if (!destinations.length) return;
    const alerts = this.db.prepare('SELECT * FROM alerts WHERE acknowledged = 0 ORDER BY last_seen_at DESC LIMIT 50').all();
    for (const alert of alerts) {
      const stamp = String(alert.last_seen_at || alert.created_at);
      const pending = destinations.filter((row) => this.deliveredAlerts.get(`${row.id}:${alert.fingerprint}`) !== stamp);
      if (!pending.length) continue;
      const results = await Promise.allSettled(pending.map((row) => this.sendAlert(row, alert)));
      const failures = [];
      results.forEach((result, index) => {
        const row = pending[index];
        if (result.status === 'fulfilled') this.deliveredAlerts.set(`${row.id}:${alert.fingerprint}`, stamp);
        else failures.push(result);
      });
      if (failures.length) this.manager.log(alert.site_id, 'error', `Could not deliver alert to ${failures.length} destination(s): ${failures[0].reason?.message || failures[0].reason}`);
    }
    if (this.deliveredAlerts.size > 5000) {
      for (const key of [...this.deliveredAlerts.keys()].slice(0, this.deliveredAlerts.size - 5000)) this.deliveredAlerts.delete(key);
    }
  }

  /** @returns {Promise<void>} */
  async exportTelemetry() {
    // this.lastTelemetryAt is initialized in ConfigurationOperations's
    // constructor (configuration.js); checkJs cannot trace assignment
    // across that base-class file, so it looks unassigned from here.
    // @ts-expect-error TS2565 -- see comment above.
    if (Date.now() - this.lastTelemetryAt < 60_000) return;
    this.lastTelemetryAt = Date.now();
    const endpoint = this.db.prepare("SELECT value FROM settings WHERE key = 'otel_endpoint'").get()?.value || '';
    if (!endpoint) return;
    let headers;
    try { headers = JSON.parse(getSecretSetting(this.db, 'otel_headers', '{}')); } catch { headers = {}; }
    const now = String(BigInt(Date.now()) * 1000000n);
    const metrics = [
      { name: 'sham.running_sites', gauge: { dataPoints: [{ asInt: String(this.manager.running.size), timeUnixNano: now }] } },
      { name: 'sham.process.rss', unit: 'By', gauge: { dataPoints: [{ asInt: String(process.memoryUsage().rss), timeUnixNano: now }] } }
    ];
    let target;
    try {
      const parsed = new URL(endpoint);
      if (!['http:', 'https:'].includes(parsed.protocol) || parsed.username || parsed.password || parsed.search || parsed.hash) throw new Error('OpenTelemetry endpoint is unsafe.');
      const normalizedPath = parsed.pathname.replace(/\/+$/, '');
      parsed.pathname = normalizedPath.endsWith('/v1/metrics') ? normalizedPath : `${normalizedPath}/v1/metrics`;
      target = parsed.toString();
    } catch (error) { throw new Error(`OpenTelemetry endpoint is invalid: ${error.message}`); }
    const response = await fetch(target, {
      method: 'POST', redirect: 'error', signal: AbortSignal.timeout(15_000),
      headers: { 'Content-Type': 'application/json', ...headers },
      body: JSON.stringify({ resourceMetrics: [{ resource: { attributes: [{ key: 'service.name', value: { stringValue: 'sham' } }] }, scopeMetrics: [{ metrics }] }] })
    });
    const status = response.status;
    await response.body?.cancel().catch(() => {});
    if (!response.ok) throw new Error(`OpenTelemetry endpoint returned HTTP ${status}.`);
  }

  async tick() {
    if (this.stopping || this.jobTickPromise) return;
    const operation = (async () => {
      const now = new Date();
      await this.tickJobs(now);
      await this.tickBackup(now);
      await this.cleanupExpiredPreviews();
      await this.deliverAlerts();
      await this.exportTelemetry().catch((error) => this.manager.log(null, 'error', `OpenTelemetry export failed: ${error.message}`));
      await getRuntimeClient().status().catch(() => {});
    })().finally(() => { if (this.jobTickPromise === operation) this.jobTickPromise = null; });
    this.jobTickPromise = operation;
    return operation;
  }

  metricsText(performancePayload) {
    const payload = performancePayload || {};
    const latest = payload.latest || payload.current || {};
    const lines = [
      '# HELP sham_up Whether the SHAM control plane is running.',
      '# TYPE sham_up gauge',
      'sham_up 1',
      '# TYPE sham_running_sites gauge',
      `sham_running_sites ${Number(latest.runningSites ?? this.manager.running.size ?? 0)}`,
      '# TYPE sham_process_rss_bytes gauge',
      `sham_process_rss_bytes ${Number(latest.rssBytes || process.memoryUsage().rss)}`,
      '# TYPE sham_event_loop_milliseconds gauge',
      `sham_event_loop_milliseconds ${Number(latest.eventLoopMs || 0)}`
    ];
    for (const site of this.db.prepare('SELECT id, slug, runtime_isolation FROM sites ORDER BY id').all()) {
      const status = this.manager.statusFor(site.id, site);
      const label = String(site.slug).replace(/[^a-zA-Z0-9_]/g, '_');
      lines.push(`sham_site_up{site_id="${site.id}",site="${label}"} ${status.running ? 1 : 0}`);
      lines.push(`sham_site_websockets{site_id="${site.id}",site="${label}"} ${Number(status.webSockets || 0)}`);
    }
    return `${lines.join('\n')}\n`;
  }

  capabilities() {
    const containerizedSham = fs.existsSync('/.dockerenv');
    // The control plane never touches Docker directly; capability flags come
    // from the Runtime Agent's own last-known status (refreshed in the
    // background — see OperationsManager's status poll in operations-manager.js).
    const agentStatus = getRuntimeClient().getCachedStatus();
    const docker = Boolean(agentStatus.agentReachable && agentStatus.agentAuthenticated && agentStatus.dockerAvailable);
    return {
      docker,
      agentReachable: Boolean(agentStatus.agentReachable),
      agentAuthenticated: Boolean(agentStatus.agentAuthenticated),
      dockerAvailable: Boolean(agentStatus.dockerAvailable),
      dockerReason: docker ? '' : !agentStatus.agentReachable
        ? 'Runtime agent unavailable.'
        : !agentStatus.agentAuthenticated
          ? 'Runtime agent authentication failed.'
          : 'Docker daemon is unreachable from the runtime agent.',
      git: commandAvailable(GIT_BIN),
      buildpacks: docker && Boolean(agentStatus.buildpacksAvailable),
      nixpacks: docker && Boolean(agentStatus.nixpacksAvailable),
      anubis: docker && Boolean(ANUBIS_IMAGE),
      anubisImage: ANUBIS_IMAGE,
      containerizedSham
    };
  }

  operationsPayload(siteId = null) {
    return {
      environment: siteId ? this.listEnvironment(siteId) : [],
      databaseProfiles: this.listDatabaseProfiles(siteId),
      jobs: siteId ? this.listJobs(siteId) : [],
      releases: siteId ? this.listReleases(siteId) : [],
      deployments: siteId ? this.listDeployments(siteId) : [],
      previews: this.listPreviews(siteId),
      backups: this.db.prepare('SELECT id, destination, status, filename, bytes, detail, started_at AS startedAt, finished_at AS finishedAt FROM backup_runs ORDER BY id DESC LIMIT 30').all(),
      backupSettings: this.backupSettings(),
      alertDestinations: this.listAlertDestinations(),
      capabilities: this.capabilities()
    };
  }

  async shutdown() {
    this.stopping = true;
    clearInterval(this.timer);
    await this.jobTickPromise?.catch(() => {});
    await this.stalePreviewCleanupPromise?.catch(() => {});
    await Promise.allSettled([...this.operationProcesses].map((child) => terminateAndWait(child, 2000)));
    await Promise.allSettled([...this.runningJobs.values()].flatMap((runs) => [...runs]));
    for (const id of [...this.previewRuntimes.keys()]) await this.deletePreview(id).catch(() => {});
    for (const id of [...this.anubisRuntimes.keys()]) await this.stopAnubis(id).catch(() => {});
    await this.backupPromise?.catch(() => {});
  }
}

module.exports = { OperationsManager };
