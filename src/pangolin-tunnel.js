'use strict';

const fs = require('node:fs');
const path = require('node:path');
const { spawn } = require('node:child_process');
const { NEWT_BIN } = require('./config');
const { operatorEnvironment } = require('./process-env');
const { getSecretSetting, setSecretSetting } = require('./secret-store');

const SETTINGS = {
  enabled: 'pangolin_newt_enabled',
  endpoint: 'pangolin_endpoint',
  id: 'pangolin_newt_id',
  secret: 'pangolin_newt_secret'
};
const MAX_VALUE_LENGTH = 16 * 1024;

function executableAvailable(command) {
  const value = String(command || '').trim();
  if (!value) return false;
  const candidates = path.isAbsolute(value) || value.includes(path.sep)
    ? [value]
    : String(process.env.PATH || '').split(path.delimiter).filter(Boolean).map((directory) => path.join(directory, value));
  return candidates.some((candidate) => {
    try { fs.accessSync(candidate, fs.constants.X_OK); return true; }
    catch { return false; }
  });
}

function validateCredential(value, label) {
  const result = String(value || '').trim();
  if (!result || result.length > MAX_VALUE_LENGTH || /[\0\r\n]/.test(result)) {
    throw new Error(`${label} must be a non-empty single-line value no longer than 16 KiB.`);
  }
  return result;
}

function validateEndpoint(value) {
  let endpoint;
  try { endpoint = new URL(String(value || '').trim()); }
  catch { throw new Error('Pangolin endpoint must be a valid HTTPS URL.'); }
  const local = ['localhost', '127.0.0.1', '::1'].includes(endpoint.hostname.replace(/^\[|\]$/g, '').toLowerCase());
  if ((endpoint.protocol !== 'https:' && !(local && endpoint.protocol === 'http:')) || endpoint.username || endpoint.password || endpoint.search || endpoint.hash) {
    throw new Error('Pangolin endpoint must be a credential-free HTTPS URL (HTTP is allowed only for loopback testing).');
  }
  return endpoint.href.replace(/\/$/, '');
}

function terminate(child, signal = 'SIGTERM') {
  if (!child || child.exitCode !== null || child.signalCode !== null) return;
  try {
    if (process.platform !== 'win32' && child.pid) process.kill(-child.pid, signal);
    else child.kill(signal);
  } catch { try { child.kill(signal); } catch { /* Already stopped. */ } }
}

function stopProcess(child, graceMs = 5000) {
  if (!child || child.exitCode !== null || child.signalCode !== null) return Promise.resolve();
  return new Promise((resolve) => {
    let settled = false;
    const finish = () => { if (!settled) { settled = true; clearTimeout(force); clearTimeout(fallback); resolve(undefined); } };
    child.once('exit', finish);
    child.once('close', finish);
    const force = setTimeout(() => terminate(child, 'SIGKILL'), graceMs);
    const fallback = setTimeout(finish, graceMs + 3000);
    force.unref?.(); fallback.unref?.();
    terminate(child);
  });
}

class DatabasePangolinSettingsStore {
  constructor(db) { this.db = db; }

  _get(key, fallback = '') { return this.db.prepare('SELECT value FROM settings WHERE key = ?').get(key)?.value ?? fallback; }

  status() {
    return {
      enabled: this._get(SETTINGS.enabled, '0') === '1',
      endpoint: this._get(SETTINGS.endpoint),
      newtId: this._get(SETTINGS.id),
      secretConfigured: Boolean(this._get(SETTINGS.secret))
    };
  }

  secret() { return getSecretSetting(this.db, SETTINGS.secret, ''); }

  save({ enabled, endpoint, newtId, secret, clearSecret = false }) {
    const write = this.db.prepare(`INSERT INTO settings (key, value, updated_at) VALUES (?, ?, CURRENT_TIMESTAMP)
      ON CONFLICT(key) DO UPDATE SET value = excluded.value, updated_at = CURRENT_TIMESTAMP`);
    this.db.transaction(() => {
      write.run(SETTINGS.enabled, enabled ? '1' : '0');
      write.run(SETTINGS.endpoint, endpoint);
      write.run(SETTINGS.id, newtId);
      if (secret !== undefined) setSecretSetting(this.db, SETTINGS.secret, secret);
      else if (clearSecret) setSecretSetting(this.db, SETTINGS.secret, '');
    })();
    return this.status();
  }
}

class PangolinTunnelManager {
  constructor({ settingsStore = null, command = NEWT_BIN, spawnProcess = spawn, availabilityCheck = executableAvailable, environment = operatorEnvironment, terminateProcess = stopProcess, log = (_level, _message) => {}, restartBaseMs = 1000, restartMaxMs = 30000 } = {}) {
    if (!settingsStore) throw new Error('Pangolin settings store is required.');
    this.settingsStore = settingsStore;
    this.command = command;
    this.spawnProcess = spawnProcess;
    this.availabilityCheck = availabilityCheck;
    this.environment = environment;
    this.terminateProcess = terminateProcess;
    this.log = log;
    this.restartBaseMs = Math.max(100, Number(restartBaseMs) || 1000);
    this.restartMaxMs = Math.max(this.restartBaseMs, Number(restartMaxMs) || 30000);
    this.child = null; this.timer = null; this.operation = Promise.resolve(); this.shuttingDown = false;
    this.state = 'stopped'; this.connectedAt = null; this.startedAt = null; this.lastError = ''; this.lastLog = '';
    this.restartCount = 0; this.generation = 0; this.secretReadable = true;
  }

  _enqueue(work) { const result = this.operation.catch(() => {}).then(work); this.operation = result; return result; }
  _configuration() { return this.settingsStore.status(); }

  status() {
    const config = this._configuration();
    const child = this.child;
    const running = Boolean(child && child.exitCode === null && child.signalCode === null);
    return { ...config, available: Boolean(this.availabilityCheck(this.command)), command: this.command, secretReadable: this.secretReadable,
      state: this.state, running, connected: running && this.state === 'connected', pid: running && child ? child.pid || null : null,
      startedAt: this.startedAt, connectedAt: this.connectedAt, restartCount: this.restartCount, lastError: this.lastError, lastLog: this.lastLog };
  }

  start() { return this._enqueue(() => this._reconcile(false)); }

  configure(input = {}) {
    return this._enqueue(async () => {
      const current = this._configuration();
      const enabled = Object.hasOwn(input, 'enabled') ? Boolean(input.enabled) : current.enabled;
      const endpoint = Object.hasOwn(input, 'endpoint')
        ? (String(input.endpoint || '').trim() ? validateEndpoint(input.endpoint) : '')
        : current.endpoint;
      const newtId = Object.hasOwn(input, 'newtId')
        ? (String(input.newtId || '').trim() ? validateCredential(input.newtId, 'Newt ID') : '')
        : current.newtId;
      const clearSecret = Boolean(input.clearSecret);
      const secret = Object.hasOwn(input, 'secret') && String(input.secret || '').trim() ? validateCredential(input.secret, 'Newt secret') : undefined;
      if (clearSecret && secret !== undefined) throw new Error('Choose either a new Newt secret or clear the saved secret.');
      const secretConfigured = secret !== undefined ? true : clearSecret ? false : current.secretConfigured;
      if (enabled && (!endpoint || !newtId || !secretConfigured)) throw new Error('Pangolin endpoint, Newt ID, and Newt secret are required before enabling the connector.');
      if (enabled && secret === undefined) {
        try { validateCredential(this.settingsStore.secret(), 'Newt secret'); this.secretReadable = true; }
        catch { this.secretReadable = false; throw new Error('The saved Newt secret cannot be read. Replace it or disable and clear it.'); }
      }
      this.settingsStore.save({ enabled, endpoint, newtId, secret, clearSecret });
      this.secretReadable = true; this.lastError = '';
      await this._reconcile(true);
      return this.status();
    });
  }

  restart() { return this._enqueue(async () => { if (!this._configuration().enabled) throw new Error('Enable Pangolin before restarting Newt.'); await this._reconcile(true); return this.status(); }); }

  async _reconcile(force) {
    const config = this._configuration();
    if (this.shuttingDown || !config.enabled) { await this._stop('disabled'); return this.status(); }
    if (!config.endpoint || !config.newtId || !config.secretConfigured) { await this._stop('needs-credentials'); return this.status(); }
    if (!this.availabilityCheck(this.command)) { await this._stop('unavailable'); this.lastError = `Newt executable not found: ${this.command}`; return this.status(); }
    if (force) await this._stop('stopped');
    if (!this.child) this._spawn(config);
    return this.status();
  }

  _spawn(config) {
    let secret;
    try { secret = validateCredential(this.settingsStore.secret(), 'Newt secret'); }
    catch (error) { this.secretReadable = false; this.state = 'needs-credentials'; this.lastError = error.message; return; }
    const generation = ++this.generation;
    const child = this.spawnProcess(this.command, [], {
      detached: process.platform !== 'win32', windowsHide: true, stdio: ['ignore', 'pipe', 'pipe'],
      env: this.environment({ PANGOLIN_ENDPOINT: config.endpoint, NEWT_ID: config.newtId, NEWT_SECRET: secret, LOG_LEVEL: 'INFO' })
    });
    this.child = child; this.state = 'starting'; this.startedAt = new Date().toISOString(); this.lastError = '';
    const consume = (chunk) => {
      const message = String(chunk || '').replaceAll(secret, '[redacted]').trim();
      if (!message) return;
      this.lastLog = message.slice(-24000);
      if (/tunnel connection.*established|connected to pangolin|websocket.*connected|received.*(?:wg|proxy)\/connect/i.test(message)) {
        this.state = 'connected'; this.connectedAt ||= new Date().toISOString(); this.restartCount = 0;
      }
      this.log('info', `[Pangolin] ${message}`);
    };
    child.stdout?.on('data', consume); child.stderr?.on('data', consume);
    child.once('error', (error) => { if (generation === this.generation) { this.lastError = error.message; this.state = 'error'; } });
    child.once('exit', (code, signal) => {
      if (generation !== this.generation) return;
      this.child = null;
      if (this.shuttingDown || !this._configuration().enabled) { this.state = 'stopped'; return; }
      this.state = 'backoff'; this.lastError = `Newt exited (${signal || (code ?? 'unknown')}).`;
      const delay = Math.min(this.restartMaxMs, this.restartBaseMs * (2 ** Math.min(this.restartCount++, 6)));
      this.timer = setTimeout(() => { this.timer = null; this._enqueue(() => this._reconcile(false)).catch(() => {}); }, delay);
      this.timer.unref?.();
    });
  }

  async _stop(state) {
    if (this.timer) clearTimeout(this.timer); this.timer = null; this.generation += 1;
    const child = this.child; this.child = null;
    if (child) await this.terminateProcess(child);
    this.state = state; this.connectedAt = null;
  }

  shutdown() { return this._enqueue(async () => { this.shuttingDown = true; await this._stop('stopped'); }); }
}

module.exports = { PangolinTunnelManager, DatabasePangolinSettingsStore, validateEndpoint, validateCredential, executableAvailable };
