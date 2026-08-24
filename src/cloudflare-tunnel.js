'use strict';

const fs = require('node:fs');
const path = require('node:path');
const net = require('node:net');
const http = require('node:http');
const https = require('node:https');
const { spawn } = require('node:child_process');
const { CLOUDFLARED_BIN } = require('./config');
const { operatorEnvironment } = require('./process-env');
const { decrypt, encrypt, getSecretSetting, setSecretSetting } = require('./secret-store');

const TOKEN_SETTING = 'cloudflare_tunnel_token';
const ENABLED_SETTING = 'cloudflare_tunnel_enabled';
const TUNNEL_ID_SETTING = 'cloudflare_tunnel_id';
const MAX_TOKEN_LENGTH = 16 * 1024;
const MAX_LOG_LENGTH = 24 * 1024;
const DEFAULT_ORIGIN_CHECK_INTERVAL_MS = 30_000;
const DEFAULT_AVAILABILITY_RECHECK_MS = 30_000;

function appendTail(current, text, limit = MAX_LOG_LENGTH) {
  const combined = `${current}${text}`;
  return combined.length > limit ? combined.slice(-limit) : combined;
}

function commandAvailable(command) {
  const value = String(command || '').trim();
  if (!value) return false;
  const candidates = (path.isAbsolute(value) || value.includes(path.sep))
    ? [value]
    : String(process.env.PATH || '').split(path.delimiter).filter(Boolean).flatMap((directory) => {
      const candidate = path.join(directory, value);
      return process.platform === 'win32' && !path.extname(candidate)
        ? [candidate, `${candidate}.exe`, `${candidate}.cmd`]
        : [candidate];
    });
  return candidates.some((candidate) => {
    try { fs.accessSync(candidate, fs.constants.X_OK); return true; }
    catch { return false; }
  });
}

function processOptions(options = {}) {
  return { ...options, detached: process.platform !== 'win32', windowsHide: true };
}

function terminate(child, signal = 'SIGTERM') {
  if (!child || child.exitCode !== null || child.signalCode !== null) return;
  try {
    if (process.platform !== 'win32' && child.pid) process.kill(-child.pid, signal);
    else child.kill(signal);
  } catch {
    try { child.kill(signal); } catch { /* Process already exited. */ }
  }
}

function terminateAndWait(child, graceMs = 5000) {
  if (!child || child.exitCode !== null || child.signalCode !== null) return Promise.resolve();
  return new Promise((resolve) => {
    let settled = false;
    let forceTimer;
    let fallbackTimer;
    const finish = () => {
      if (settled) return;
      settled = true;
      clearTimeout(forceTimer);
      clearTimeout(fallbackTimer);
      resolve();
    };
    child.once('exit', finish);
    child.once('close', finish);
    forceTimer = setTimeout(() => terminate(child, 'SIGKILL'), graceMs);
    fallbackTimer = setTimeout(finish, graceMs + 3000);
    forceTimer.unref?.();
    fallbackTimer.unref?.();
    terminate(child, 'SIGTERM');
  });
}


async function settleInBatches(items, worker, concurrency = 4) {
  const results = [];
  const width = Math.max(1, Math.min(Number(concurrency) || 1, 16));
  for (let index = 0; index < items.length; index += width) {
    const batch = items.slice(index, index + width);
    results.push(...await Promise.allSettled(batch.map(worker)));
  }
  return results;
}

function validateToken(value) {
  const token = String(value || '').trim();
  if (!token || token.length > MAX_TOKEN_LENGTH || /[\s\0]/.test(token)) {
    throw new Error('Cloudflare Tunnel token must be a single value no longer than 16 KiB.');
  }
  return token;
}

function validateTunnelId(value) {
  const id = String(value || '').trim().toLowerCase();
  if (!/^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/.test(id)) {
    throw new Error('Cloudflare Tunnel ID must be a UUID.');
  }
  return id;
}

function validateAccountId(value) {
  const id = String(value || '').trim().toLowerCase();
  if (!/^[0-9a-f]{32}$/.test(id)) throw new Error('Cloudflare account ID must be a 32-character hexadecimal ID.');
  return id;
}

function validatePublicHostname(value) {
  const hostname = String(value || '').trim().toLowerCase().replace(/\.$/, '');
  if (!hostname || hostname.length > 253 || !hostname.includes('.') || !/^(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/.test(hostname)) {
    throw new Error('Tunnel public hostname must be a valid hostname.');
  }
  return hostname;
}

function validateOriginService(value) {
  const service = String(value || '').trim();
  if (!service) return '';
  let url;
  try { url = new URL(service); } catch { throw new Error('Tunnel origin service must be a valid HTTP or HTTPS URL.'); }
  const hostname = String(url.hostname || '').replace(/^\[|\]$/g, '').toLowerCase();
  const loopback = hostname === 'localhost' || hostname === '::1' || /^127(?:\.\d{1,3}){3}$/.test(hostname);
  if (!['http:', 'https:'].includes(url.protocol) || url.username || url.password || url.search || url.hash || !loopback || (net.isIP(hostname) === 4 && hostname.split('.').some((part) => Number(part) > 255))) {
    throw new Error('Tunnel origin service must be a credential-free HTTP(S) loopback URL.');
  }
  return url.href.replace(/\/$/, '');
}

function probeOriginService(service, hostname, timeoutMs = 5000) {
  let target;
  try {
    const validated = validateOriginService(service);
    if (!validated) return Promise.resolve({ healthy: null, error: '' });
    target = new URL(validated);
  }
  catch (error) { return Promise.resolve({ healthy: false, error: error.message }); }
  const transport = target.protocol === 'https:' ? https : http;
  return new Promise((resolve) => {
    let settled = false;
    const finish = (result) => {
      if (settled) return;
      settled = true;
      resolve(result);
    };
    const request = transport.request(target, {
      method: 'GET',
      headers: { Host: hostname || target.hostname, 'User-Agent': 'SHAM-Tunnel-Health/1.0', Connection: 'close' }
    }, (response) => {
      response.resume();
      finish({ healthy: response.statusCode >= 200 && response.statusCode < 500, statusCode: response.statusCode || 0, error: '' });
    });
    request.once('error', (error) => finish({ healthy: false, error: error.message }));
    request.setTimeout(Math.max(250, Number(timeoutMs) || 5000), () => request.destroy(new Error('Origin health check timed out.')));
    request.end();
  });
}

class DatabaseTunnelSettingsStore {
  constructor(db, siteId = null) {
    this.db = db;
    this.siteId = siteId === null ? null : Number(siteId);
  }

  status() {
    if (this.siteId !== null) {
      const row = this.db.prepare('SELECT enabled, token, tunnel_id, public_hostname, origin_service, managed_route, tunnel_only, connector_mode FROM site_cloudflare_tunnels WHERE site_id = ?').get(this.siteId);
      return {
        enabled: Boolean(row?.enabled),
        tokenConfigured: Boolean(row?.token),
        tunnelId: row?.tunnel_id || '',
        publicHostname: row?.public_hostname || '',
        originService: row?.origin_service || '',
        managedRoute: Boolean(row?.managed_route),
        tunnelOnly: Boolean(row?.tunnel_only),
        connectorMode: row?.connector_mode === 'shared' ? 'shared' : 'dedicated'
      };
    }
    const enabled = this.db.prepare('SELECT value FROM settings WHERE key = ?').get(ENABLED_SETTING)?.value === '1';
    const storedToken = this.db.prepare('SELECT value FROM settings WHERE key = ?').get(TOKEN_SETTING)?.value || '';
    const tunnelId = this.db.prepare('SELECT value FROM settings WHERE key = ?').get(TUNNEL_ID_SETTING)?.value || '';
    return { enabled, tokenConfigured: Boolean(storedToken), tunnelId, publicHostname: '', originService: '', managedRoute: false, tunnelOnly: false, connectorMode: 'dedicated' };
  }

  token() {
    if (this.siteId !== null) {
      const stored = this.db.prepare('SELECT token FROM site_cloudflare_tunnels WHERE site_id = ?').get(this.siteId)?.token || '';
      return decrypt(stored, '');
    }
    return getSecretSetting(this.db, TOKEN_SETTING, '');
  }

  save({ enabled, token, clearToken = false, tunnelId, publicHostname, originService, managedRoute, tunnelOnly, connectorMode }) {
    if (this.siteId !== null) {
      const existing = this.db.prepare('SELECT token, tunnel_id, public_hostname, origin_service, managed_route, tunnel_only, connector_mode FROM site_cloudflare_tunnels WHERE site_id = ?').get(this.siteId) || {};
      const existingToken = existing.token || '';
      const storedToken = token !== undefined ? encrypt(token) : clearToken ? '' : existingToken;
      const nextTunnelId = tunnelId === undefined ? existing.tunnel_id || '' : tunnelId;
      const nextPublicHostname = publicHostname === undefined ? existing.public_hostname || '' : publicHostname;
      const nextOriginService = originService === undefined ? existing.origin_service || '' : originService;
      const nextManagedRoute = managedRoute === undefined ? Boolean(existing.managed_route) : Boolean(managedRoute);
      const nextTunnelOnly = tunnelOnly === undefined ? Boolean(existing.tunnel_only) : Boolean(tunnelOnly);
      const nextConnectorMode = connectorMode === undefined ? (existing.connector_mode === 'shared' ? 'shared' : 'dedicated') : connectorMode;
      if (!enabled && !storedToken && !nextTunnelId && !nextPublicHostname && !nextOriginService && !nextManagedRoute && !nextTunnelOnly) {
        this.db.prepare('DELETE FROM site_cloudflare_tunnels WHERE site_id = ?').run(this.siteId);
      } else {
        this.db.prepare(`
          INSERT INTO site_cloudflare_tunnels (site_id, enabled, token, tunnel_id, public_hostname, origin_service, managed_route, tunnel_only, connector_mode, updated_at)
          VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP)
          ON CONFLICT(site_id) DO UPDATE SET enabled = excluded.enabled, token = excluded.token, tunnel_id = excluded.tunnel_id,
            public_hostname = excluded.public_hostname, origin_service = excluded.origin_service, managed_route = excluded.managed_route,
            tunnel_only = excluded.tunnel_only, connector_mode = excluded.connector_mode, updated_at = CURRENT_TIMESTAMP
        `).run(this.siteId, enabled ? 1 : 0, storedToken, nextTunnelId, nextPublicHostname, nextOriginService, nextManagedRoute ? 1 : 0, nextTunnelOnly ? 1 : 0, nextConnectorMode);
      }
      return this.status();
    }

    const transaction = this.db.transaction(() => {
      this.db.prepare(`
        INSERT INTO settings (key, value, updated_at) VALUES (?, ?, CURRENT_TIMESTAMP)
        ON CONFLICT(key) DO UPDATE SET value = excluded.value, updated_at = CURRENT_TIMESTAMP
      `).run(ENABLED_SETTING, enabled ? '1' : '0');
      if (tunnelId !== undefined) this.db.prepare(`
        INSERT INTO settings (key, value, updated_at) VALUES (?, ?, CURRENT_TIMESTAMP)
        ON CONFLICT(key) DO UPDATE SET value = excluded.value, updated_at = CURRENT_TIMESTAMP
      `).run(TUNNEL_ID_SETTING, tunnelId);
      if (token !== undefined) setSecretSetting(this.db, TOKEN_SETTING, token);
      else if (clearToken) setSecretSetting(this.db, TOKEN_SETTING, '');
    });
    transaction();
    return this.status();
  }
}

class CloudflareTunnelManager {
  constructor({
    settingsStore,
    command = CLOUDFLARED_BIN,
    spawnProcess = spawn,
    commandAvailableCheck = commandAvailable,
    terminateProcess = terminateAndWait,
    environment = operatorEnvironment,
    log = () => {},
    now = () => new Date(),
    random = Math.random,
    originProbe = probeOriginService,
    restartBaseMs = 1000,
    restartMaxMs = 30_000,
    stableAfterMs = 60_000,
    originCheckIntervalMs = DEFAULT_ORIGIN_CHECK_INTERVAL_MS,
    availabilityRecheckMs = DEFAULT_AVAILABILITY_RECHECK_MS
  } = {}) {
    if (!settingsStore) throw new Error('Cloudflare Tunnel settings store is required.');
    this.settingsStore = settingsStore;
    this.command = command;
    this.spawnProcess = spawnProcess;
    this.commandAvailableCheck = commandAvailableCheck;
    this.terminateProcess = terminateProcess;
    this.environment = environment;
    this.log = log;
    this.now = now;
    this.random = typeof random === 'function' ? random : Math.random;
    this.originProbe = originProbe;
    this.restartBaseMs = Math.max(100, Number(restartBaseMs) || 1000);
    this.restartMaxMs = Math.max(this.restartBaseMs, Number(restartMaxMs) || 30_000);
    this.stableAfterMs = Math.max(100, Number(stableAfterMs) || 60_000);
    this.originCheckIntervalMs = Math.max(100, Number(originCheckIntervalMs) || DEFAULT_ORIGIN_CHECK_INTERVAL_MS);
    this.availabilityRecheckMs = Math.max(100, Number(availabilityRecheckMs) || DEFAULT_AVAILABILITY_RECHECK_MS);

    this.available = false;
    this.child = null;
    this.restartTimer = null;
    this.stableTimer = null;
    this.originTimer = null;
    this.availabilityTimer = null;
    this.operationTail = Promise.resolve();
    this.generation = 0;
    this.shuttingDown = false;
    this.state = 'stopped';
    this.startedAt = null;
    this.connectedAt = null;
    this.lastExit = null;
    this.lastError = '';
    this.lastLog = '';
    this.tokenReadable = true;
    this.restartCount = 0;
    this.consecutiveFailures = 0;
    this.failureClass = '';
    this.nextRetryAt = null;
    this.originHealth = { state: 'unknown', checkedAt: null, statusCode: null, lastError: '' };
    this.lastForwardedLogAt = 0;
    this.outputBuffers = { stdout: '', stderr: '' };
  }

  _enqueue(operation) {
    const run = this.operationTail.catch(() => {}).then(operation);
    this.operationTail = run;
    return run;
  }

  _configuration() {
    try { return this.settingsStore.status(); }
    catch (error) {
      this.lastError = `Could not read Cloudflare Tunnel settings: ${error.message}`;
      return { enabled: false, tokenConfigured: false, tunnelId: '', publicHostname: '', originService: '', managedRoute: false, tunnelOnly: false };
    }
  }

  status() {
    const configuration = this._configuration();
    this.available = Boolean(this.commandAvailableCheck(this.command));
    const childRunning = Boolean(this.child && this.child.exitCode === null && this.child.signalCode === null);
    return {
      available: this.available,
      command: this.command,
      enabled: configuration.enabled,
      tokenConfigured: configuration.tokenConfigured,
      tokenReadable: this.tokenReadable,
      route: {
        tunnelId: configuration.tunnelId || '',
        publicHostname: configuration.publicHostname || '',
        originService: configuration.originService || '',
        managedRoute: Boolean(configuration.managedRoute),
        tunnelOnly: Boolean(configuration.tunnelOnly),
        connectorMode: configuration.connectorMode === 'shared' ? 'shared' : 'dedicated'
      },
      state: this.state,
      running: childRunning,
      connected: childRunning && this.state === 'connected',
      pid: childRunning ? this.child.pid || null : null,
      startedAt: this.startedAt,
      connectedAt: this.connectedAt,
      restartCount: this.restartCount,
      failureClass: this.failureClass || null,
      nextRetryAt: this.nextRetryAt,
      origin: { ...this.originHealth },
      lastExit: this.lastExit,
      lastError: this.lastError,
      lastLog: this.lastLog.trim()
    };
  }

  start() {
    return this._enqueue(() => this._reconcile({ forceRestart: false }));
  }

  configure(input = {}) {
    return this._enqueue(async () => {
      const current = this._configuration();
      const enabled = Object.prototype.hasOwnProperty.call(input, 'enabled') ? Boolean(input.enabled) : current.enabled;
      const clearToken = Boolean(input.clearToken);
      const hasToken = Object.prototype.hasOwnProperty.call(input, 'token') && String(input.token || '').trim() !== '';
      const token = hasToken ? validateToken(input.token) : undefined;
      const tunnelId = Object.prototype.hasOwnProperty.call(input, 'tunnelId') ? (String(input.tunnelId || '').trim() ? validateTunnelId(input.tunnelId) : '') : undefined;
      const publicHostname = Object.prototype.hasOwnProperty.call(input, 'publicHostname') ? (String(input.publicHostname || '').trim() ? validatePublicHostname(input.publicHostname) : '') : undefined;
      const originService = Object.prototype.hasOwnProperty.call(input, 'originService') ? validateOriginService(input.originService) : undefined;
      const managedRoute = Object.prototype.hasOwnProperty.call(input, 'managedRoute') ? Boolean(input.managedRoute) : undefined;
      const tunnelOnly = Object.prototype.hasOwnProperty.call(input, 'tunnelOnly') ? Boolean(input.tunnelOnly) : undefined;
      const connectorMode = Object.prototype.hasOwnProperty.call(input, 'connectorMode')
        ? (String(input.connectorMode) === 'shared' ? 'shared' : String(input.connectorMode) === 'dedicated' ? 'dedicated' : (() => { throw new Error('Tunnel connector mode must be dedicated or shared.'); })())
        : undefined;
      if (clearToken && token !== undefined) throw new Error('Choose either a new tunnel token or clear the saved token.');
      const tokenConfigured = token !== undefined ? true : clearToken ? false : current.tokenConfigured;
      if (enabled && !tokenConfigured) throw new Error('Set a Cloudflare Tunnel token before enabling the connector.');
      if (enabled && token === undefined && !clearToken) {
        try { validateToken(this.settingsStore.token()); this.tokenReadable = true; }
        catch {
          this.tokenReadable = false;
          throw new Error('The saved Cloudflare Tunnel token cannot be read. Replace it or disable and clear it.');
        }
      }

      const route = {
        tunnelId: tunnelId === undefined ? current.tunnelId || '' : tunnelId,
        publicHostname: publicHostname === undefined ? current.publicHostname || '' : publicHostname,
        originService: originService === undefined ? current.originService || '' : originService,
        managedRoute: managedRoute === undefined ? Boolean(current.managedRoute) : managedRoute
      };
      if (route.managedRoute && (!route.tunnelId || !route.publicHostname || !route.originService)) {
        throw new Error('Managed tunnel routing requires a tunnel ID, public hostname, and loopback origin service.');
      }

      this.settingsStore.save({ enabled, token, clearToken, tunnelId, publicHostname, originService, managedRoute, tunnelOnly, connectorMode });
      this.tokenReadable = true;
      this.lastError = '';
      this.failureClass = '';
      await this._reconcile({ forceRestart: true });
      return this.status();
    });
  }

  restart() {
    return this._enqueue(async () => {
      const configuration = this._configuration();
      if (!configuration.enabled) throw new Error('Enable Cloudflare Tunnel before restarting it.');
      if (!configuration.tokenConfigured) throw new Error('Set a Cloudflare Tunnel token before restarting it.');
      this.lastError = '';
      await this._reconcile({ forceRestart: true });
      return this.status();
    });
  }

  async _reconcile({ forceRestart }) {
    const configuration = this._configuration();
    this.available = Boolean(this.commandAvailableCheck(this.command));
    if (this.shuttingDown) return this.status();
    if (!configuration.enabled) {
      await this._stopChild('disabled');
      return this.status();
    }
    if (!configuration.tokenConfigured) {
      await this._stopChild('needs-token');
      this.lastError = 'No Cloudflare Tunnel token is configured.';
      return this.status();
    }
    if (!this.available) {
      await this._stopChild('unavailable');
      this.lastError = `Cloudflare Tunnel is enabled, but ${this.command} is not executable.`;
      this._scheduleAvailabilityCheck();
      return this.status();
    }
    if (forceRestart) await this._stopChild('stopped');
    if (!this.child) await this._launch();
    return this.status();
  }

  async _launch() {
    if (this.shuttingDown) return;
    this._clearRestartTimer();
    this._clearAvailabilityTimer();
    let token;
    try {
      token = validateToken(this.settingsStore.token());
      this.tokenReadable = true;
    } catch (error) {
      this.tokenReadable = false;
      this.state = 'error';
      this.lastError = `The saved Cloudflare Tunnel token could not be read: ${error.message}`;
      this.log('error', this.lastError);
      return;
    }

    const generation = ++this.generation;
    this.outputBuffers = { stdout: '', stderr: '' };
    this.startedAt = this.now().toISOString();
    this.connectedAt = null;
    this.lastExit = null;
    this.nextRetryAt = null;
    this.originHealth = { state: this._configuration().originService ? 'waiting-for-connector' : 'not-configured', checkedAt: null, statusCode: null, lastError: '' };
    this.state = 'starting';

    let child;
    try {
      child = this.spawnProcess(
        this.command,
        ['tunnel', '--no-autoupdate', 'run'],
        processOptions({ env: this.environment({ TUNNEL_TOKEN: token }), stdio: ['ignore', 'pipe', 'pipe'] })
      );
    } catch (error) {
      this.lastError = `${this.command} could not start: ${error.message}`;
      this.failureClass = 'launch';
      this.state = 'error';
      this._scheduleRestart(generation);
      return;
    }

    this.child = child;
    let settled = false;
    const finish = (code, signal, error = null) => {
      if (settled) return;
      settled = true;
      this._handleExit({ child, generation, code, signal, error });
    };
    child.stdout?.on('data', (chunk) => this._consumeOutput('stdout', chunk, token, generation));
    child.stderr?.on('data', (chunk) => this._consumeOutput('stderr', chunk, token, generation));
    child.once('error', (error) => finish(null, null, error));
    child.once('exit', (code, signal) => finish(code, signal));

    this._clearStableTimer();
    this.stableTimer = setTimeout(() => {
      if (generation !== this.generation || this.child !== child) return;
      this.consecutiveFailures = 0;
    }, this.stableAfterMs);
    this.stableTimer.unref?.();
    this.log('info', 'Cloudflare Tunnel connector started.');
  }

  _consumeOutput(stream, chunk, token, generation) {
    if (generation !== this.generation) return;
    const text = `${this.outputBuffers[stream] || ''}${Buffer.isBuffer(chunk) ? chunk.toString('utf8') : String(chunk)}`;
    const lines = text.split(/\r?\n/);
    this.outputBuffers[stream] = (lines.pop() || '').slice(-4096);
    for (const rawLine of lines) this._consumeLine(rawLine, token, generation);
  }

  _consumeLine(rawLine, token, generation) {
    if (generation !== this.generation) return;
    const line = String(rawLine || '').replaceAll(token, '[redacted]').replace(/[\r\n\0]/g, ' ').trim().slice(0, 2000);
    if (!line) return;
    this.lastLog = appendTail(this.lastLog, `${line}\n`);

    if (/registered tunnel connection|connection .* registered|tunnel connection registered/i.test(line)) {
      if (this.state !== 'connected') {
        this.state = 'connected';
        this.connectedAt = this.now().toISOString();
        this.lastError = '';
        this.failureClass = '';
        this.log('info', 'Cloudflare Tunnel connected to the Cloudflare edge.');
      }
      this._checkOrigin(generation).catch((error) => {
        this.originHealth = { state: 'unhealthy', checkedAt: this.now().toISOString(), statusCode: null, lastError: error.message };
      });
      return;
    }

    const errorLine = /(?:^|[\s"=])(error|fatal|err)(?:[\s"=:]|$)|failed|unable to/i.test(line);
    if (errorLine) {
      this.lastError = line;
      if (/(?:invalid|expired|revoked|malformed).*token|token.*(?:invalid|expired|revoked)|authentication failed|unauthorized|not authorized/i.test(line)) {
        this.failureClass = 'authentication';
      }
      const now = Date.now();
      if (now - this.lastForwardedLogAt >= 5000) {
        this.lastForwardedLogAt = now;
        this.log('error', `Cloudflare Tunnel: ${line}`);
      }
    }
  }

  _handleExit({ child, generation, code, signal, error }) {
    if (generation !== this.generation || this.child !== child) return;
    this.child = null;
    this._clearStableTimer();
    this._clearOriginTimer();
    const description = error ? error.message : `exit ${code ?? 'unknown'}${signal ? ` (${signal})` : ''}`;
    this.lastExit = { code: code ?? null, signal: signal || null, at: this.now().toISOString() };
    const stopError = error ? `${this.command} could not start: ${description}` : `Cloudflare Tunnel stopped with ${description}.`;
    if (!this.failureClass) this.failureClass = error ? 'launch' : 'runtime';
    if (this.failureClass === 'authentication') {
      this.lastError = this.lastError || stopError;
      this.nextRetryAt = null;
      this.state = 'needs-attention';
      this.log('error', 'Cloudflare Tunnel stopped after an authentication failure; automatic retries are paused until its token is replaced or the connector is manually restarted.');
      return;
    }
    this.lastError = stopError;
    this.state = 'error';
    this.log('error', this.lastError);
    this._scheduleRestart(generation);
  }

  async _checkOrigin(generation) {
    if (generation !== this.generation || this.state !== 'connected') return;
    const configuration = this._configuration();
    if (!configuration.originService) {
      this.originHealth = { state: 'not-configured', checkedAt: null, statusCode: null, lastError: '' };
      return;
    }
    this.originHealth = { ...this.originHealth, state: 'checking', lastError: '' };
    const result = await this.originProbe(configuration.originService, configuration.publicHostname);
    if (generation !== this.generation || this.state !== 'connected') return;
    this.originHealth = {
      state: result.healthy ? 'healthy' : 'unhealthy',
      checkedAt: this.now().toISOString(),
      statusCode: Number.isInteger(result.statusCode) ? result.statusCode : null,
      lastError: String(result.error || '').slice(0, 1000)
    };
    this._clearOriginTimer();
    this.originTimer = setTimeout(() => {
      this.originTimer = null;
      this._checkOrigin(generation).catch((error) => {
        if (generation === this.generation) this.originHealth = { state: 'unhealthy', checkedAt: this.now().toISOString(), statusCode: null, lastError: error.message };
      });
    }, this.originCheckIntervalMs);
    this.originTimer.unref?.();
  }

  _scheduleRestart(generation) {
    if (this.shuttingDown || this.failureClass === 'authentication' || generation !== this.generation || this.restartTimer) return;
    const configuration = this._configuration();
    if (!configuration.enabled || !configuration.tokenConfigured) return;
    const exponent = Math.min(this.consecutiveFailures, 10);
    const baseDelay = Math.min(this.restartMaxMs, this.restartBaseMs * (2 ** exponent));
    const jitter = 0.8 + Math.min(1, Math.max(0, Number(this.random()) || 0)) * 0.4;
    const delay = Math.max(1, Math.round(baseDelay * jitter));
    this.consecutiveFailures += 1;
    this.restartCount += 1;
    this.state = 'backoff';
    this.nextRetryAt = new Date(this.now().getTime() + delay).toISOString();
    this.restartTimer = setTimeout(() => {
      this.restartTimer = null;
      this.nextRetryAt = null;
      this._enqueue(async () => {
        if (this.shuttingDown || generation !== this.generation || this.child) return;
        this.available = Boolean(this.commandAvailableCheck(this.command));
        if (!this.available) {
          this.state = 'unavailable';
          this.lastError = `Cloudflare Tunnel is enabled, but ${this.command} is not executable.`;
          this._scheduleAvailabilityCheck();
          return;
        }
        await this._launch();
      }).catch((error) => {
        this.state = 'error';
        this.lastError = error.message;
      });
    }, delay);
    this.restartTimer.unref?.();
  }

  _clearRestartTimer() {
    clearTimeout(this.restartTimer);
    this.restartTimer = null;
    this.nextRetryAt = null;
  }

  _scheduleAvailabilityCheck() {
    if (this.shuttingDown || this.availabilityTimer) return;
    const configuration = this._configuration();
    if (!configuration.enabled || !configuration.tokenConfigured) return;
    this.availabilityTimer = setTimeout(() => {
      this.availabilityTimer = null;
      this._enqueue(() => this._reconcile({ forceRestart: false })).catch((error) => {
        this.state = 'error';
        this.lastError = error.message;
      });
    }, this.availabilityRecheckMs);
    this.availabilityTimer.unref?.();
  }

  _clearAvailabilityTimer() {
    clearTimeout(this.availabilityTimer);
    this.availabilityTimer = null;
  }

  _clearOriginTimer() {
    clearTimeout(this.originTimer);
    this.originTimer = null;
  }

  _clearStableTimer() {
    clearTimeout(this.stableTimer);
    this.stableTimer = null;
  }

  async _stopChild(nextState = 'stopped') {
    this._clearRestartTimer();
    this._clearStableTimer();
    this._clearOriginTimer();
    this._clearAvailabilityTimer();
    this.outputBuffers = { stdout: '', stderr: '' };
    const child = this.child;
    this.child = null;
    this.generation += 1;
    if (child) await this.terminateProcess(child);
    this.state = nextState;
    this.startedAt = null;
    this.connectedAt = null;
    this.originHealth = { state: nextState === 'disabled' ? 'not-configured' : 'unknown', checkedAt: null, statusCode: null, lastError: '' };
    if (nextState === 'disabled' || nextState === 'stopped') this.failureClass = '';
  }

  shutdown() {
    return this._enqueue(async () => {
      this.shuttingDown = true;
      await this._stopChild('stopped');
      return this.status();
    });
  }
}

class SiteCloudflareTunnelRegistry {
  constructor({ db, log = () => {}, managerOptions = {}, managerFactory = null, sharedManager = null, settingsStoreFactory = null } = {}) {
    if (!db) throw new Error('A database is required for site Cloudflare Tunnels.');
    this.db = db;
    this.log = log;
    this.managerOptions = managerOptions;
    this.managerFactory = managerFactory;
    this.sharedManager = sharedManager;
    this.settingsStoreFactory = settingsStoreFactory;
    this.managers = new Map();
  }

  _siteId(siteId) {
    const id = Number(siteId);
    if (!Number.isSafeInteger(id) || id <= 0) throw new Error('A valid site id is required.');
    return id;
  }

  _settings(siteId) {
    const id = this._siteId(siteId);
    return this.settingsStoreFactory ? this.settingsStoreFactory(this.db, id) : new DatabaseTunnelSettingsStore(this.db, id);
  }

  _sharedStatus(siteId) {
    const configuration = this._settings(siteId).status();
    const shared = this.sharedManager?.status();
    const sharedEnabled = Boolean(shared?.enabled && shared?.tokenConfigured);
    const enabled = Boolean(configuration.enabled);
    return {
      ...(shared || { available: this.available(), tokenReadable: true, restartCount: 0, lastError: '', lastLog: '', startedAt: null, connectedAt: null, lastExit: null, failureClass: null, nextRetryAt: null, origin: { state: 'not-configured', checkedAt: null, statusCode: null, lastError: '' } }),
      enabled,
      tokenConfigured: Boolean(shared?.tokenConfigured),
      state: !enabled ? 'disabled' : sharedEnabled ? shared.state : 'needs-token',
      running: enabled && Boolean(shared?.running),
      connected: enabled && Boolean(shared?.connected),
      lastError: !enabled || sharedEnabled ? shared?.lastError || '' : 'Configure and enable the instance shared Cloudflare Tunnel connector before assigning sites to it.',
      route: {
        tunnelId: configuration.tunnelId || '',
        publicHostname: configuration.publicHostname || '',
        originService: configuration.originService || '',
        managedRoute: Boolean(configuration.managedRoute),
        tunnelOnly: Boolean(configuration.tunnelOnly),
        connectorMode: 'shared'
      }
    };
  }

  _manager(siteId) {
    const id = this._siteId(siteId);
    if (!this.managers.has(id)) {
      const settingsStore = this._settings(id);
      const options = {
        ...this.managerOptions,
        settingsStore,
        log: (level, message) => this.log(id, level, message)
      };
      this.managers.set(id, this.managerFactory ? this.managerFactory(options, id) : new CloudflareTunnelManager(options));
    }
    return this.managers.get(id);
  }

  available() {
    const probe = this.managers.values().next().value;
    if (probe) return Boolean(probe.status().available);
    if (this.sharedManager) return Boolean(this.sharedManager.status().available);
    const command = this.managerOptions.command || CLOUDFLARED_BIN;
    const check = this.managerOptions.commandAvailableCheck || commandAvailable;
    return Boolean(check(command));
  }

  status(siteId) {
    if (!this.sharedManager) {
      const status = this._manager(siteId).status();
      return !status.enabled && status.state === 'stopped' ? { ...status, state: 'disabled' } : status;
    }
    const configuration = this._settings(siteId).status();
    if (configuration.connectorMode === 'shared') return this._sharedStatus(siteId);
    const status = this._manager(siteId).status();
    if (!status.enabled && status.state === 'stopped') return { ...status, state: 'disabled' };
    return status;
  }

  summary(siteId) {
    const status = this.status(siteId);
    return {
      available: status.available,
      enabled: status.enabled,
      tokenConfigured: status.tokenConfigured,
      tokenReadable: status.tokenReadable,
      state: status.state,
      running: status.running,
      connected: status.connected,
      connectedAt: status.connectedAt,
      restartCount: status.restartCount,
      failureClass: status.failureClass,
      nextRetryAt: status.nextRetryAt,
      origin: status.origin,
      route: status.route,
      lastError: status.lastError
    };
  }

  listStatus() {
    return this.db.prepare('SELECT id, name, domain FROM sites ORDER BY name COLLATE NOCASE, id').all().map((site) => ({
      siteId: site.id,
      name: site.name,
      domain: site.domain || '',
      ...this.summary(site.id)
    }));
  }

  async configure(siteId, input = {}) {
    const id = this._siteId(siteId);
    if (!this.sharedManager && !Object.prototype.hasOwnProperty.call(input, 'connectorMode')) {
      await this._manager(id).configure(input);
      return this.status(id);
    }
    const settings = this._settings(id);
    const current = settings.status();
    const connectorMode = Object.prototype.hasOwnProperty.call(input, 'connectorMode')
      ? String(input.connectorMode || '')
      : current.connectorMode;
    if (!['dedicated', 'shared'].includes(connectorMode)) throw new Error('Tunnel connector mode must be dedicated or shared.');
    if (connectorMode === 'shared') {
      if (!this.sharedManager) throw new Error('This SHAM installation does not have an instance shared Tunnel connector.');
      if (Object.prototype.hasOwnProperty.call(input, 'token') || input.clearToken) throw new Error('Shared connectors use the instance connector token; configure it from the instance Tunnel settings.');
      const enabled = Object.prototype.hasOwnProperty.call(input, 'enabled') ? Boolean(input.enabled) : current.enabled;
      const tunnelId = Object.prototype.hasOwnProperty.call(input, 'tunnelId') ? (String(input.tunnelId || '').trim() ? validateTunnelId(input.tunnelId) : '') : current.tunnelId;
      const publicHostname = Object.prototype.hasOwnProperty.call(input, 'publicHostname') ? (String(input.publicHostname || '').trim() ? validatePublicHostname(input.publicHostname) : '') : current.publicHostname;
      const originService = Object.prototype.hasOwnProperty.call(input, 'originService') ? validateOriginService(input.originService) : current.originService;
      const managedRoute = Object.prototype.hasOwnProperty.call(input, 'managedRoute') ? Boolean(input.managedRoute) : current.managedRoute;
      const tunnelOnly = Object.prototype.hasOwnProperty.call(input, 'tunnelOnly') ? Boolean(input.tunnelOnly) : current.tunnelOnly;
      if (managedRoute && (!tunnelId || !publicHostname || !originService)) throw new Error('Managed tunnel routing requires a tunnel ID, public hostname, and loopback origin service.');
      const shared = this.sharedManager.status();
      if (enabled && (!shared.enabled || !shared.tokenConfigured)) throw new Error('Configure and enable the instance shared Cloudflare Tunnel connector before assigning sites to it.');
      if (managedRoute && (!shared.route?.tunnelId || shared.route.tunnelId !== tunnelId)) {
        throw new Error('Managed shared routes must use the tunnel ID configured on the instance shared connector.');
      }
      const dedicated = this.managers.get(id);
      if (dedicated) await dedicated.shutdown();
      this.managers.delete(id);
      settings.save({ enabled, clearToken: true, tunnelId, publicHostname, originService, managedRoute, tunnelOnly, connectorMode: 'shared' });
      return this.status(id);
    }
    await this._manager(id).configure({ ...input, connectorMode: 'dedicated' });
    return this.status(siteId);
  }

  async restart(siteId) {
    const id = this._siteId(siteId);
    if (!this.sharedManager) {
      await this._manager(id).restart();
      return this.status(id);
    }
    if (this._settings(id).status().connectorMode === 'shared') {
      if (!this.sharedManager) throw new Error('This SHAM installation does not have an instance shared Tunnel connector.');
      await this.sharedManager.restart();
    } else await this._manager(id).restart();
    return this.status(siteId);
  }

  async startEnabled() {
    const rows = this.db.prepare("SELECT site_id FROM site_cloudflare_tunnels WHERE enabled = 1 AND connector_mode != 'shared' ORDER BY site_id").all();
    const results = await settleInBatches(rows, ({ site_id: siteId }) => this._manager(siteId).start(), 4);
    for (let index = 0; index < results.length; index += 1) {
      if (results[index].status === 'rejected') this.log(rows[index].site_id, 'error', `Could not start Cloudflare Tunnel: ${results[index].reason?.message || results[index].reason}`);
    }
    if (this.sharedManager && this.db.prepare("SELECT 1 FROM site_cloudflare_tunnels WHERE enabled = 1 AND connector_mode = 'shared' LIMIT 1").get()) await this.sharedManager.start();
    return this.listStatus();
  }

  start(siteId) {
    const id = this._siteId(siteId);
    if (!this.sharedManager) return this._manager(id).start();
    if (this._settings(id).status().connectorMode === 'shared') {
      if (!this.sharedManager) return Promise.reject(new Error('This SHAM installation does not have an instance shared Tunnel connector.'));
      return this.sharedManager.start();
    }
    return this._manager(id).start();
  }

  async stop(siteId) {
    const id = this._siteId(siteId);
    if (!this.sharedManager) {
      const manager = this.managers.get(id);
      if (manager) await manager.shutdown();
      this.managers.delete(id);
      return;
    }
    if (this._settings(id).status().connectorMode === 'shared') {
      this.managers.delete(id);
      return;
    }
    const manager = this.managers.get(id);
    if (manager) await manager.shutdown();
    this.managers.delete(id);
  }

  async remove(siteId) {
    const id = this._siteId(siteId);
    await this.stop(id);
    this.db.prepare('DELETE FROM site_cloudflare_tunnels WHERE site_id = ?').run(id);
  }

  async shutdown() {
    const managers = [...this.managers.values()];
    await settleInBatches(managers, (manager) => manager.shutdown(), 4);
    this.managers.clear();
  }
}

module.exports = {
  CloudflareTunnelManager,
  DatabaseTunnelSettingsStore,
  SiteCloudflareTunnelRegistry,
  commandAvailable,
  terminateAndWait,
  validateToken,
  validateTunnelId,
  validateAccountId,
  validatePublicHostname,
  validateOriginService,
  probeOriginService,
  TOKEN_SETTING,
  ENABLED_SETTING,
  TUNNEL_ID_SETTING
};
