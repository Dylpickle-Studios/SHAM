// @ts-nocheck -- not part of this session's checkJs rollout yet.
// This file still has genuine `tsc --noEmit` findings (mostly narrow
// `let x = null`-style inference and untyped Express handlers, the same
// patterns already fixed across most of src/) that need real per-file
// JSDoc work to resolve, not a suppression. Tracked as follow-up work;
// see tsconfig.json and docs/development.md. Do not add more files here
// without a similar comment and a plan to remove it.
const fs = require('node:fs');
const path = require('node:path');
const crypto = require('node:crypto');
const { Worker } = require('node:worker_threads');
const { PLUGINS_DIR, PLUGIN_ACTION_TIMEOUT_MS, PLUGIN_MAX_PENDING_ACTIONS } = require('./config');
const { safeRelativePath } = require('./validation');
const { extractPlugin } = require('./plugin-archive');
const { encrypt, decrypt, isEncrypted } = require('./secret-store');
const { verifyPluginSignature, normalizeTrustedKeys } = require('./plugin-signing');

const MAX_SETTING_BYTES = 64 * 1024;
const MAX_MANIFEST_BYTES = 512 * 1024;
const MAX_CLIENT_BYTES = 1024 * 1024;
const PLUGIN_DEACTIVATE_TIMEOUT_MS = 10_000;
const PLUGIN_PERMISSIONS = new Set(['data:read', 'data:write', 'settings:read', 'settings:write', 'ui:dashboard', 'network:outbound', 'runtime:read', 'runtime:manage']);

async function pathExistsAsync(target) {
  try { await fs.promises.access(target); return true; }
  catch { return false; }
}

function withTimeout(promise, timeoutMs, message) {
  return new Promise((resolve, reject) => {
    let settled = false;
    const timer = setTimeout(() => {
      if (settled) return;
      settled = true;
      reject(new Error(message));
    }, timeoutMs);
    timer.unref?.();
    Promise.resolve(promise).then(
      (value) => {
        if (settled) return;
        settled = true;
        clearTimeout(timer);
        resolve(value);
      },
      (error) => {
        if (settled) return;
        settled = true;
        clearTimeout(timer);
        reject(error);
      }
    );
  });
}

function text(value, limit) {
  return String(value ?? '').trim().slice(0, limit);
}

function normalizeCard(raw) {
  if (!raw || typeof raw !== 'object' || Array.isArray(raw)) return null;
  return {
    label: text(raw.label, 100),
    value: text(raw.value, 200),
    description: text(raw.description, 300),
    action: text(raw.action, 64),
    valuePath: text(raw.valuePath, 200)
  };
}

function normalizeUi(input) {
  if (!input || typeof input !== 'object' || Array.isArray(input)) return {};
  const dashboardCards = (Array.isArray(input.dashboardCards) ? input.dashboardCards : [])
    .slice(0, 20).map(normalizeCard).filter(Boolean);
  const pages = (Array.isArray(input.pages) ? input.pages : []).slice(0, 20).map((raw, index) => {
    if (!raw || typeof raw !== 'object' || Array.isArray(raw)) return null;
    return {
      id: text(raw.id || `page-${index + 1}`, 64),
      title: text(raw.title || `Plugin page ${index + 1}`, 100),
      description: text(raw.description, 500),
      cards: (Array.isArray(raw.cards) ? raw.cards : []).slice(0, 50).map(normalizeCard).filter(Boolean)
    };
  }).filter(Boolean);
  return { dashboardCards, pages };
}

const DECLARATIVE_PRIVATE_TABLES = [
  'users', 'settings', 'plugin_settings', 'audit_logs', 'sqlite_master', 'sqlite_schema'
];
const DECLARATIVE_LIFECYCLE_TABLES = ['sites', 'plugins'];
const DECLARATIVE_DANGEROUS_FUNCTIONS = ['load_extension', 'readfile', 'writefile', 'fts3_tokenizer'];

function sqlReferencesIdentifier(sql, identifier) {
  return new RegExp(`(?:^|[^a-zA-Z0-9_])${identifier.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')}(?:$|[^a-zA-Z0-9_])`, 'i').test(sql);
}

function validateDeclarativeSql(sql, mode) {
  const source = String(sql || '').trim();
  if (/--|\/\*/.test(source)) throw new Error('Declarative plugin queries may not contain SQL comments.');
  const normalized = source.replace(/;\s*$/, '').trim();
  if (!normalized || normalized.includes(';')) throw new Error('Declarative plugin queries must contain exactly one SQL statement.');
  if (mode === 'run') {
    if (!/^(INSERT|UPDATE|DELETE)\b/i.test(normalized)) {
      throw new Error('Declarative write actions may only use INSERT, UPDATE, or DELETE statements.');
    }
  } else if (!/^SELECT\b/i.test(normalized)) {
    throw new Error('Declarative read actions must use a SELECT statement.');
  }

  for (const identifier of [...DECLARATIVE_PRIVATE_TABLES, ...DECLARATIVE_DANGEROUS_FUNCTIONS]) {
    if (sqlReferencesIdentifier(normalized, identifier)) {
      throw new Error(`Declarative plugin SQL may not access ${identifier}. Use a reviewed JavaScript plugin when privileged access is required.`);
    }
  }
  if (mode === 'run') {
    for (const identifier of DECLARATIVE_LIFECYCLE_TABLES) {
      if (sqlReferencesIdentifier(normalized, identifier)) {
        throw new Error(`Declarative write actions may not modify ${identifier} directly because that would bypass SHAM lifecycle handling.`);
      }
    }
  }
  if (/\bpragma_[a-z0-9_]+\b/i.test(normalized)) {
    throw new Error('Declarative plugin SQL may not access SQLite pragma virtual tables.');
  }
  return normalized;
}

function validateManifest(input) {
  if (!input || typeof input !== 'object' || Array.isArray(input)) throw new Error('plugin.json must contain an object.');
  const id = String(input.id || '').trim().toLowerCase();
  if (!/^[a-z0-9][a-z0-9_-]{1,63}$/.test(id)) throw new Error('Plugin ID must be 2–64 lowercase letters, numbers, underscores, or hyphens.');
  const name = String(input.name || '').trim();
  if (!name || name.length > 100) throw new Error('Plugin name is required and must be at most 100 characters.');
  const version = String(input.version || '1.0.0').trim().slice(0, 40);
  const type = String(input.type || 'json').toLowerCase();
  if (!['json', 'js'].includes(type)) throw new Error('Plugin type must be json or js.');

  const seenSettings = new Set();
  const settings = [];
  for (const raw of Array.isArray(input.settings) ? input.settings.slice(0, 50) : []) {
    const key = String(raw?.key || '').trim();
    if (!/^[a-zA-Z][a-zA-Z0-9_.-]{0,63}$/.test(key) || seenSettings.has(key)) continue;
    seenSettings.add(key);
    settings.push({
      key,
      label: String(raw.label || key).trim().slice(0, 100),
      type: ['text', 'number', 'checkbox', 'textarea', 'password'].includes(raw.type) ? raw.type : 'text',
      default: raw.default ?? '',
      description: String(raw.description || '').slice(0, 300)
    });
  }

  const queryEntries = input.queries && typeof input.queries === 'object' && !Array.isArray(input.queries)
    ? Object.entries(input.queries).slice(0, 20)
    : [];
  const queries = {};
  for (const [action, definition] of queryEntries) {
    if (!/^[a-zA-Z][a-zA-Z0-9_-]{0,63}$/.test(action) || !definition || typeof definition !== 'object') continue;
    const mode = ['get', 'all', 'run'].includes(definition.mode) ? definition.mode : 'get';
    const rawSql = String(definition.sql || '').trim();
    if (!rawSql || rawSql.length > 5000) continue;
    queries[action] = {
      sql: validateDeclarativeSql(rawSql, mode),
      mode,
      params: Array.isArray(definition.params)
        ? definition.params.map((item) => String(item)).filter((item) => /^[a-zA-Z][a-zA-Z0-9_.-]{0,63}$/.test(item)).slice(0, 20)
        : []
    };
  }

  const requestedPermissions = Array.isArray(input.permissions) ? input.permissions.map(String) : [];
  const inferredPermissions = type === 'json'
    ? [Object.keys(queries).length ? (Object.values(queries).some((query) => query.mode === 'run') ? 'data:write' : 'data:read') : null, settings.length ? 'settings:read' : null, (input.ui || input.client) ? 'ui:dashboard' : null].filter(Boolean)
    : [];
  const permissions = [...new Set([...requestedPermissions, ...inferredPermissions])].filter((permission) => PLUGIN_PERMISSIONS.has(permission));
  const isolation = String(input.isolation || 'in-process').toLowerCase();
  if (!['in-process', 'worker'].includes(isolation)) throw new Error('Plugin isolation must be in-process or worker.');
  if (type === 'json' && isolation !== 'in-process') throw new Error('JSON plugins do not need worker isolation.');
  const signature = input.signature && typeof input.signature === 'object' ? {
    algorithm: String(input.signature.algorithm || '').toLowerCase(),
    keyId: String(input.signature.keyId || '').trim().slice(0, 100),
    value: String(input.signature.value || '').trim().slice(0, 1000)
  } : null;

  return {
    id,
    name,
    version,
    type,
    description: String(input.description || '').slice(0, 500),
    main: type === 'js' ? safeRelativePath(input.main || 'index.js', 'Plugin main file') : null,
    client: input.client ? safeRelativePath(input.client, 'Plugin client file') : null,
    settings,
    queries,
    ui: normalizeUi(input.ui),
    permissions,
    isolation,
    signature
  };
}

function parseStoredValue(value) {
  try { return JSON.parse(value); }
  catch { return null; }
}

function normalizeSettingValue(schema, value) {
  if (schema.type === 'checkbox') return value === true || value === 1 || value === '1' || value === 'true' || value === 'on';
  if (schema.type === 'number') {
    const number = Number(value);
    if (!Number.isFinite(number)) throw new Error(`“${schema.label}” must be a valid number.`);
    return number;
  }
  const text = String(value ?? '');
  if (Buffer.byteLength(text, 'utf8') > MAX_SETTING_BYTES) throw new Error(`“${schema.label}” exceeds the 64 KB setting limit.`);
  return text;
}

class WorkerPluginRuntime {
  constructor(manager, row, manifest, mainPath) {
    this.manager = manager;
    this.row = row;
    this.manifest = manifest;
    this.counter = 0;
    this.pending = new Map();
    this.failedError = null;
    this.stopping = false;
    this.failureNotified = false;
    this.worker = new Worker(path.join(__dirname, 'plugin-sandbox-worker.js'), {
      workerData: { mainPath, manifest, settings: manager.settingsFor(row.id), maxPendingRpc: PLUGIN_MAX_PENDING_ACTIONS }
    });
    const ready = new Promise((resolve, reject) => {
      this.readyResolve = resolve;
      this.readyReject = reject;
    });
    this.ready = withTimeout(ready, PLUGIN_ACTION_TIMEOUT_MS, `Plugin startup exceeded ${PLUGIN_ACTION_TIMEOUT_MS / 1000} seconds.`)
      .catch(async (error) => {
        this.fail(error);
        await this.worker.terminate().catch(() => {});
        throw error;
      });
    this.ready.catch(() => {});
    this.worker.on('message', (message) => this.onMessage(message));
    this.worker.once('error', (error) => this.fail(error));
    this.worker.once('exit', (code) => {
      if (!this.stopping) this.fail(new Error(`Plugin worker exited unexpectedly with code ${code}.`));
    });
  }

  onMessage(message) {
    if (message.type === 'ready') { this.readyResolve(); return; }
    if (message.type === 'fatal') { this.fail(new Error(message.error || 'Plugin worker failed.')); return; }
    if (message.type === 'log') {
      const logger = message.level === 'error' ? this.manager.logger.error : this.manager.logger.log;
      logger.call(this.manager.logger, `[plugin:${this.row.id}] ${String(message.message || '').slice(0, 2000)}`);
      return;
    }
    if (message.type === 'rpc') {
      this.handleRpc(message).catch((error) => this.worker.postMessage({ type: 'rpc-result', id: message.id, error: error.message }));
      return;
    }
    if (message.type === 'result' || message.type === 'deactivated') {
      const pending = this.pending.get(message.id);
      if (!pending) return;
      this.pending.delete(message.id);
      if (message.error) pending.reject(new Error(message.error)); else pending.resolve(message.value);
    }
  }

  async handleRpc(message) {
    const context = this.manager.context(this.row, this.manifest);
    const [first, second] = message.args || [];
    let value;
    if (message.method === 'data.all') value = context.data.all(first, second);
    else if (message.method === 'data.get') value = context.data.get(first, second);
    else if (message.method === 'data.run') value = context.data.run(first, second);
    else if (message.method === 'settings.set') value = context.settings.set(first, second);
    else if (message.method === 'runtime.list') value = context.runtime.list();
    else if (message.method === 'runtime.status') value = context.runtime.status(first);
    else if (message.method === 'runtime.start') value = await context.runtime.start(first);
    else if (message.method === 'runtime.stop') value = await context.runtime.stop(first);
    else if (message.method === 'runtime.restart') value = await context.runtime.restart(first);
    else throw new Error('Unsupported plugin worker operation.');
    this.worker.postMessage({ type: 'rpc-result', id: message.id, value });
  }

  fail(error) {
    if (this.failedError) return;
    this.failedError = error;
    this.readyReject?.(error);
    for (const pending of this.pending.values()) pending.reject(error);
    this.pending.clear();
    if (!this.stopping && !this.failureNotified) {
      this.failureNotified = true;
      this.manager.workerRuntimeFailed(this.row.id, error);
    }
  }

  async invoke(action, request) {
    if (this.failedError) throw this.failedError;
    if (this.pending.size >= PLUGIN_MAX_PENDING_ACTIONS) throw new Error('Plugin has too many pending actions.');
    await this.ready;
    const id = ++this.counter;
    const operation = new Promise((resolve, reject) => {
      this.pending.set(id, { resolve, reject });
      this.worker.postMessage({ type: 'invoke', id, action, request });
    });
    try {
      return await withTimeout(operation, PLUGIN_ACTION_TIMEOUT_MS, `Plugin action exceeded ${PLUGIN_ACTION_TIMEOUT_MS / 1000} seconds.`);
    } catch (error) {
      this.pending.delete(id);
      if (/exceeded/.test(error.message)) {
        this.fail(error);
        await this.worker.terminate().catch(() => {});
      }
      throw error;
    }
  }

  settingsChanged(values) { if (!this.failedError && !this.stopping) this.worker.postMessage({ type: 'settings', values }); }

  async deactivate() {
    this.stopping = true;
    try {
      await this.ready;
      const id = ++this.counter;
      await withTimeout(new Promise((resolve, reject) => {
        this.pending.set(id, { resolve, reject });
        this.worker.postMessage({ type: 'deactivate', id });
      }), PLUGIN_DEACTIVATE_TIMEOUT_MS, 'Plugin worker did not deactivate in time.');
    } finally { await this.worker.terminate(); }
  }
}

class PluginManager {
  constructor(db, logger = console, siteManager = null) {
    this.db = db;
    this.logger = logger;
    this.siteManager = siteManager;
    this.active = new Map();
    this.installWorkers = new Set();
    this.installOperations = new Set();
    this.activeActions = new Map();
    this.stopping = false;
  }

  workerRuntimeFailed(id, error) {
    const key = String(id);
    const active = this.active.get(key);
    if (active?.instance?.__workerRuntime?.stopping) return;
    this.active.delete(key);
    try { this.db.prepare('UPDATE plugins SET enabled = 0, updated_at = CURRENT_TIMESTAMP WHERE id = ?').run(key); }
    catch (dbError) { this.logger.error(`[plugin:${key}] Could not persist automatic disable: ${dbError.message}`); }
    this.logger.error(`[plugin:${key}] Disabled after worker failure: ${error.message}`);
  }

  pluginRoot(row) {
    return path.join(PLUGINS_DIR, row.directory_name);
  }

  getRow(id) {
    return this.db.prepare('SELECT * FROM plugins WHERE id = ?').get(String(id));
  }

  settingsFor(id) {
    const row = this.getRow(id);
    if (!row) return {};
    const manifest = validateManifest(JSON.parse(row.manifest_json));
    const secretKeys = new Set(manifest.settings.filter((item) => item.type === 'password').map((item) => item.key));
    return Object.fromEntries(this.db.prepare('SELECT key, value FROM plugin_settings WHERE plugin_id = ?').all(id)
      .map((stored) => {
        let value = parseStoredValue(stored.value);
        if (secretKeys.has(stored.key) && isEncrypted(value)) value = decrypt(value);
        return [stored.key, value];
      }));
  }

  setSettings(id, values, { clearSecrets = [] } = {}) {
    const row = this.getRow(id);
    if (!row) throw new Error('Plugin not found.');
    const manifest = validateManifest(JSON.parse(row.manifest_json));
    const schemaByKey = new Map(manifest.settings.map((item) => [item.key, item]));
    const clear = new Set(Array.isArray(clearSecrets) ? clearSecrets.map(String) : []);
    const write = this.db.prepare(`
      INSERT INTO plugin_settings (plugin_id, key, value, updated_at)
      VALUES (?, ?, ?, CURRENT_TIMESTAMP)
      ON CONFLICT(plugin_id, key) DO UPDATE SET value = excluded.value, updated_at = CURRENT_TIMESTAMP
    `);
    const transaction = this.db.transaction(() => {
      for (const [key, value] of Object.entries(values || {})) {
        const schema = schemaByKey.get(key);
        if (!schema) continue;
        if (schema.type === 'password' && value === '' && !clear.has(key)) continue;
        let normalized = schema.type === 'password' && clear.has(key) ? '' : normalizeSettingValue(schema, value);
        if (schema.type === 'password' && normalized) normalized = encrypt(normalized);
        write.run(id, key, JSON.stringify(normalized));
      }
      for (const key of clear) {
        const schema = schemaByKey.get(key);
        if (schema?.type === 'password' && !Object.hasOwn(values || {}, key)) write.run(id, key, JSON.stringify(''));
      }
    });
    transaction();
    const current = this.settingsFor(id);
    const active = this.active.get(String(id));
    try {
      active?.instance?.__workerRuntime?.settingsChanged(current);
      const result = active?.instance?.onSettingsChanged?.(current);
      Promise.resolve(result).catch((error) => this.logger.error(`[plugin:${id}] Settings hook failed: ${error.message}`));
    } catch (error) { this.logger.error(`[plugin:${id}] Settings hook failed: ${error.message}`); }
    return current;
  }

  context(row, manifest) {
    const permissions = new Set(manifest.permissions || []);
    const requirePermission = (permission) => {
      if (!permissions.has(permission)) throw new Error(`Plugin ${row.id} does not have the ${permission} permission.`);
    };
    return {
      id: row.id,
      manifest,
      permissions: [...permissions],
      data: {
        all: (sql, params = []) => { requirePermission('data:read'); return this.db.prepare(sql).all(...params); },
        get: (sql, params = []) => { requirePermission('data:read'); return this.db.prepare(sql).get(...params); },
        run: (sql, params = []) => { requirePermission('data:write'); return this.db.prepare(sql).run(...params); }
      },
      settings: {
        get: (key, fallback = null) => { requirePermission('settings:read'); return this.settingsFor(row.id)[key] ?? fallback; },
        all: () => { requirePermission('settings:read'); return this.settingsFor(row.id); },
        set: (key, value) => { requirePermission('settings:write'); return this.setSettings(row.id, { [key]: value }); }
      },
      runtime: {
        list: () => {
          requirePermission('runtime:read');
          if (!this.siteManager) return [];
          return this.db.prepare('SELECT id FROM sites ORDER BY name COLLATE NOCASE').all().map(({ id }) => {
            const site = this.siteManager.getSite(id);
            return { id: site.id, name: site.name, runtimeType: site.runtime_type, enabled: Boolean(site.enabled), status: this.siteManager.statusFor(id, site) };
          });
        },
        status: (siteId) => { requirePermission('runtime:read'); return this.siteManager?.statusFor(Number(siteId)) || null; },
        start: async (siteId) => { requirePermission('runtime:manage'); if (!this.siteManager) throw new Error('Runtime manager is unavailable.'); await this.siteManager.start(Number(siteId)); return this.siteManager.statusFor(Number(siteId)); },
        stop: async (siteId) => { requirePermission('runtime:manage'); if (!this.siteManager) throw new Error('Runtime manager is unavailable.'); await this.siteManager.stop(Number(siteId)); return this.siteManager.statusFor(Number(siteId)); },
        restart: async (siteId) => { requirePermission('runtime:manage'); if (!this.siteManager) throw new Error('Runtime manager is unavailable.'); await this.siteManager.restart(Number(siteId)); return this.siteManager.statusFor(Number(siteId)); }
      },
      log: (message) => this.logger.log(`[plugin:${row.id}] ${String(message).slice(0, 2000)}`)
    };
  }

  load(id) {
    if (this.active.has(String(id))) return this.active.get(String(id));
    const row = this.getRow(id);
    if (!row || !row.enabled) return null;
    const manifest = validateManifest(JSON.parse(row.manifest_json));
    let instance;

    if (manifest.type === 'js') {
      const mainPath = path.join(this.pluginRoot(row), ...manifest.main.split('/'));
      if (!fs.existsSync(mainPath)) throw new Error(`Plugin main file is missing: ${manifest.main}`);
      if (manifest.isolation === 'worker') {
        const runtime = new WorkerPluginRuntime(this, row, manifest, mainPath);
        instance = { __workerRuntime: runtime, deactivate: () => runtime.deactivate() };
      } else {
        delete require.cache[require.resolve(mainPath)];
        const moduleValue = require(mainPath);
        instance = typeof moduleValue.activate === 'function'
          ? moduleValue.activate(this.context(row, manifest)) || {}
          : moduleValue;
        if (instance && typeof instance.then === 'function') {
          throw new Error('Plugin activate() must return synchronously. Use async handlers for asynchronous work.');
        }
      }
    } else {
      const api = {};
      for (const [action, definition] of Object.entries(manifest.queries || {})) {
        const statement = this.db.prepare(definition.sql);
        api[action] = ({ body = {}, query = {}, user = null, method = 'GET' }) => {
          if (definition.mode === 'run') {
            if (user?.role !== 'admin') throw new Error('Administrator access is required for declarative write actions.');
            if (['GET', 'HEAD'].includes(String(method).toUpperCase())) throw new Error('Declarative write actions require a non-GET request.');
          }
          const values = definition.params.map((key) => body[key] ?? query[key] ?? null);
          if (definition.mode === 'all') return statement.all(...values);
          if (definition.mode === 'run') return statement.run(...values);
          return statement.get(...values);
        };
      }
      instance = { api };
    }

    this.active.set(String(id), { row, manifest, instance, clientSource: null });
    return this.active.get(String(id));
  }

  loadEnabled() {
    for (const row of this.db.prepare('SELECT id FROM plugins WHERE enabled = 1').all()) {
      try { this.load(row.id); }
      catch (error) {
        this.db.prepare('UPDATE plugins SET enabled = 0, updated_at = CURRENT_TIMESTAMP WHERE id = ?').run(row.id);
        this.logger.error(`[plugin:${row.id}] Disabled after load failure: ${error.message}`);
      }
    }
  }

  async unload(id) {
    id = String(id);
    const active = this.active.get(id);
    this.active.delete(id);
    if (active && !active.instance?.__workerRuntime) {
      const actions = [...this.activeActions.entries()].filter(([, pluginId]) => pluginId === id).map(([operation]) => operation);
      if (actions.length) {
        try {
          await withTimeout(Promise.allSettled(actions), PLUGIN_ACTION_TIMEOUT_MS, `Plugin actions did not stop within ${PLUGIN_ACTION_TIMEOUT_MS / 1000} seconds.`);
        } catch (error) {
          this.logger.error(`[plugin:${id}] ${error.message}`);
        }
      }
    }
    try {
      await withTimeout(
        Promise.resolve().then(() => active?.instance?.deactivate?.()),
        PLUGIN_DEACTIVATE_TIMEOUT_MS,
        `Plugin deactivation exceeded ${PLUGIN_DEACTIVATE_TIMEOUT_MS / 1000} seconds.`
      );
    } catch (error) {
      this.logger.error(`[plugin:${id}] Deactivation failed: ${error.message}`);
    }
  }

  list() {
    const rows = this.db.prepare('SELECT * FROM plugins ORDER BY name COLLATE NOCASE').all();
    const settingsRows = this.db.prepare('SELECT plugin_id, key, value FROM plugin_settings').all();
    const settingsByPlugin = new Map();
    for (const setting of settingsRows) {
      if (!settingsByPlugin.has(setting.plugin_id)) settingsByPlugin.set(setting.plugin_id, {});
      settingsByPlugin.get(setting.plugin_id)[setting.key] = parseStoredValue(setting.value);
    }

    return rows.map((row) => {
      const manifest = validateManifest(JSON.parse(row.manifest_json));
      const rawSettings = settingsByPlugin.get(row.id) || {};
      const secretKeys = new Set(manifest.settings.filter((item) => item.type === 'password').map((item) => item.key));
      const settings = Object.fromEntries(Object.entries(rawSettings).map(([key, value]) => [key, secretKeys.has(key) ? '' : value]));
      const secretConfigured = Object.fromEntries([...secretKeys].map((key) => [key, Boolean(rawSettings[key])]));
      return {
        id: row.id,
        name: row.name,
        version: row.version,
        type: row.type,
        enabled: Boolean(row.enabled),
        description: manifest.description,
        permissions: manifest.permissions,
        isolation: row.isolation || manifest.isolation,
        signatureStatus: row.signature_status || 'unsigned',
        signatureKeyId: manifest.signature?.keyId || null,
        settingsSchema: manifest.settings,
        settings,
        secretConfigured,
        hasClient: manifest.permissions.includes('ui:dashboard') && Boolean(manifest.client || manifest.type === 'json'),
        ui: manifest.type === 'json' ? manifest.ui : undefined,
        createdAt: row.created_at,
        updatedAt: row.updated_at
      };
    });
  }

  validatePreparedPlugin(staging, prepared = null) {
    const manifestPath = path.join(staging, 'plugin.json');
    let rawManifest = prepared?.rawManifest;
    let signature = prepared?.signature;
    if (!rawManifest) {
      if (!fs.existsSync(manifestPath)) throw new Error('Plugin archive must contain plugin.json at its root.');
      if (fs.statSync(manifestPath).size > MAX_MANIFEST_BYTES) throw new Error('plugin.json may not exceed 512 KB.');
      rawManifest = JSON.parse(fs.readFileSync(manifestPath, 'utf8'));
    }
    const manifest = validateManifest(rawManifest);
    if (!signature) {
      const trusted = this.db.prepare("SELECT value FROM settings WHERE key = 'plugin_trusted_keys_json'").get()?.value || '[]';
      signature = verifyPluginSignature(staging, rawManifest, normalizeTrustedKeys(trusted));
    }
    Object.defineProperty(manifest, '_signatureStatus', { value: signature.status, enumerable: false });
    Object.defineProperty(manifest, '_signer', { value: signature.signer, enumerable: false });
    if (manifest.type === 'js' && !fs.existsSync(path.join(staging, ...manifest.main.split('/')))) {
      throw new Error(`Plugin main file is missing: ${manifest.main}`);
    }
    if (manifest.client) {
      const clientPath = path.join(staging, ...manifest.client.split('/'));
      if (!fs.existsSync(clientPath)) throw new Error(`Plugin client file is missing: ${manifest.client}`);
      if (fs.statSync(clientPath).size > MAX_CLIENT_BYTES) throw new Error('Plugin client scripts may not exceed 1 MB.');
    }
    return manifest;
  }

  commitPreparedPlugin(staging, manifest) {
    let finalPath = null;
    try {
      if (this.getRow(manifest.id)) throw new Error(`A plugin with ID “${manifest.id}” is already installed.`);
      const directoryName = `plugin-${manifest.id}-${crypto.randomUUID()}`;
      finalPath = path.join(PLUGINS_DIR, directoryName);
      fs.renameSync(staging, finalPath);
      const insertPlugin = this.db.prepare(`
        INSERT INTO plugins (id, name, version, type, directory_name, manifest_json, permissions_json, signature_status, isolation)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
      `);
      const insertSetting = this.db.prepare(`
        INSERT INTO plugin_settings (plugin_id, key, value, updated_at)
        VALUES (?, ?, ?, CURRENT_TIMESTAMP)
      `);
      const insert = this.db.transaction(() => {
        insertPlugin.run(manifest.id, manifest.name, manifest.version, manifest.type, directoryName, JSON.stringify(manifest), JSON.stringify(manifest.permissions || []), manifest._signatureStatus || 'unsigned', manifest.isolation || 'in-process');
        for (const setting of manifest.settings) {
          let defaultValue = normalizeSettingValue(setting, setting.default);
          if (setting.type === 'password' && defaultValue) defaultValue = encrypt(defaultValue);
          insertSetting.run(manifest.id, setting.key, JSON.stringify(defaultValue));
        }
      });
      insert();
      return this.list().find((plugin) => plugin.id === manifest.id);
    } catch (error) {
      fs.rmSync(staging, { recursive: true, force: true });
      if (finalPath) fs.rmSync(finalPath, { recursive: true, force: true });
      throw error;
    }
  }

  async commitPreparedPluginAsync(staging, manifest) {
    let finalPath = null;
    try {
      if (this.getRow(manifest.id)) throw new Error(`A plugin with ID “${manifest.id}” is already installed.`);
      const directoryName = `plugin-${manifest.id}-${crypto.randomUUID()}`;
      finalPath = path.join(PLUGINS_DIR, directoryName);
      await fs.promises.rename(staging, finalPath);
      const insertPlugin = this.db.prepare(`
        INSERT INTO plugins (id, name, version, type, directory_name, manifest_json, permissions_json, signature_status, isolation)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
      `);
      const insertSetting = this.db.prepare(`
        INSERT INTO plugin_settings (plugin_id, key, value, updated_at)
        VALUES (?, ?, ?, CURRENT_TIMESTAMP)
      `);
      const insert = this.db.transaction(() => {
        insertPlugin.run(manifest.id, manifest.name, manifest.version, manifest.type, directoryName, JSON.stringify(manifest), JSON.stringify(manifest.permissions || []), manifest._signatureStatus || 'unsigned', manifest.isolation || 'in-process');
        for (const setting of manifest.settings) {
          let defaultValue = normalizeSettingValue(setting, setting.default);
          if (setting.type === 'password' && defaultValue) defaultValue = encrypt(defaultValue);
          insertSetting.run(manifest.id, setting.key, JSON.stringify(defaultValue));
        }
      });
      insert();
      return this.list().find((plugin) => plugin.id === manifest.id);
    } catch (error) {
      await fs.promises.rm(staging, { recursive: true, force: true }).catch(() => {});
      if (finalPath) await fs.promises.rm(finalPath, { recursive: true, force: true }).catch(() => {});
      throw error;
    }
  }

  install(source, { allowUnsigned = false } = {}) {
    const staging = path.join(PLUGINS_DIR, `.staging-${crypto.randomUUID()}`);
    fs.mkdirSync(staging, { recursive: true });
    try {
      extractPlugin(source, staging);
      const manifest = this.validatePreparedPlugin(staging);
      const globallyAllowed = this.db.prepare("SELECT value FROM settings WHERE key = 'allow_unsigned_plugins'").get()?.value === '1';
      if (manifest._signatureStatus === 'unsigned' && !allowUnsigned && !globallyAllowed) throw new Error('This plugin is unsigned. Confirm the unsigned-plugin risk or install a package signed by a trusted key.');
      return this.commitPreparedPlugin(staging, manifest);
    } catch (error) {
      fs.rmSync(staging, { recursive: true, force: true });
      throw error;
    }
  }

  async installAsync(source, { allowUnsigned = false } = {}) {
    if (this.stopping) throw new Error('Plugin manager is shutting down.');
    const staging = path.join(PLUGINS_DIR, `.staging-${crypto.randomUUID()}`);
    await fs.promises.mkdir(staging, { recursive: true });
    if (this.stopping) {
      await fs.promises.rm(staging, { recursive: true, force: true }).catch(() => {});
      throw new Error('Plugin manager is shutting down.');
    }
    const operation = new Promise((resolve, reject) => {
      let worker;
      try {
        const trustedKeys = this.db.prepare("SELECT value FROM settings WHERE key = 'plugin_trusted_keys_json'").get()?.value || '[]';
        worker = new Worker(path.join(__dirname, 'plugin-archive-worker.js'), {
          workerData: { source, destination: staging, trustedKeys }
        });
      } catch (error) {
        fs.promises.rm(staging, { recursive: true, force: true }).finally(() => reject(error));
        return;
      }
      this.installWorkers.add(worker);
      let settled = false;
      const finish = (callback, value) => {
        if (settled) return;
        settled = true;
        this.installWorkers.delete(worker);
        callback(value);
      };
      const failWithCleanup = async (error) => {
        await fs.promises.rm(staging, { recursive: true, force: true }).catch(() => {});
        finish(reject, error);
      };
      worker.once('message', async (message) => {
        if (!message?.ok) {
          await failWithCleanup(new Error(message?.error || 'Plugin extraction worker failed.'));
          return;
        }
        try {
          const manifest = this.validatePreparedPlugin(staging, message);
          const globallyAllowed = this.db.prepare("SELECT value FROM settings WHERE key = 'allow_unsigned_plugins'").get()?.value === '1';
          if (manifest._signatureStatus === 'unsigned' && !allowUnsigned && !globallyAllowed) throw new Error('This plugin is unsigned. Confirm the unsigned-plugin risk or install a package signed by a trusted key.');
          const plugin = await this.commitPreparedPluginAsync(staging, manifest);
          finish(resolve, plugin);
        } catch (error) {
          await failWithCleanup(error);
        }
      });
      worker.once('error', (error) => { void failWithCleanup(error); });
      worker.once('exit', (code) => {
        if (code === 0 || settled) return;
        void failWithCleanup(new Error(`Plugin extraction worker exited with code ${code}.`));
      });
    });
    this.installOperations.add(operation);
    return operation.finally(() => this.installOperations.delete(operation));
  }

  async toggle(id, enabled) {
    id = String(id);
    const row = this.getRow(id);
    if (!row) throw new Error('Plugin not found.');
    if (Boolean(row.enabled) === Boolean(enabled) && (enabled ? this.active.has(id) : !this.active.has(id))) {
      return this.list().find((plugin) => plugin.id === id);
    }
    if (enabled) {
      this.db.prepare('UPDATE plugins SET enabled = 1, updated_at = CURRENT_TIMESTAMP WHERE id = ?').run(id);
      try { this.load(id); }
      catch (error) {
        await this.unload(id);
        this.db.prepare('UPDATE plugins SET enabled = 0, updated_at = CURRENT_TIMESTAMP WHERE id = ?').run(id);
        throw error;
      }
    } else {
      await this.unload(id);
      try {
        this.db.prepare('UPDATE plugins SET enabled = 0, updated_at = CURRENT_TIMESTAMP WHERE id = ?').run(id);
      } catch (error) {
        if (row.enabled) {
          try { this.load(id); }
          catch (restoreError) { throw new Error(`The plugin could not be disabled and its runtime could not be restored: ${error.message}; ${restoreError.message}`); }
        }
        throw error;
      }
    }
    return this.list().find((plugin) => plugin.id === id);
  }

  async delete(id) {
    id = String(id);
    const row = this.getRow(id);
    if (!row) throw new Error('Plugin not found.');
    await this.unload(id);
    const root = this.pluginRoot(row);
    const trash = `${root}.delete-${crypto.randomUUID()}`;
    let staged = false;
    try {
      await fs.promises.rename(root, trash);
      staged = true;
    } catch (error) {
      if (error.code !== 'ENOENT') {
        if (row.enabled) {
          try { this.load(id); }
          catch (restoreError) { throw new Error(`Plugin files could not be staged for deletion and its runtime could not be restored: ${error.message}; ${restoreError.message}`); }
        }
        throw error;
      }
    }
    try {
      this.db.prepare('DELETE FROM plugins WHERE id = ?').run(id);
    } catch (error) {
      if (staged && await pathExistsAsync(trash) && !(await pathExistsAsync(root))) await fs.promises.rename(trash, root).catch(() => {});
      if (row.enabled) {
        try { this.load(id); }
        catch (restoreError) { throw new Error(`The plugin could not be deleted and its runtime could not be restored: ${error.message}; ${restoreError.message}`); }
      }
      throw error;
    }
    if (staged) {
      void fs.promises.rm(trash, { recursive: true, force: true }).catch((error) => {
        this.logger.error(`[plugin:${id}] Could not remove deleted plugin files: ${error.message}`);
      });
    }
  }

  async clientScript(id) {
    id = String(id);
    const row = this.getRow(id);
    if (!row || !row.enabled) throw new Error('Plugin is not enabled.');
    const active = this.active.get(id) || this.load(id);
    const manifest = active?.manifest || validateManifest(JSON.parse(row.manifest_json));
    if (!manifest.permissions.includes('ui:dashboard')) throw new Error('Plugin does not have the ui:dashboard permission.');
    if (active?.clientSource === null) {
      if (manifest.type === 'json') {
        active.clientSource = `window.SHAM.registerPlugin(${JSON.stringify({ id: manifest.id, name: manifest.name, type: 'json', ui: manifest.ui })});`;
      } else if (manifest.client) {
        const clientPath = path.join(this.pluginRoot(row), ...manifest.client.split('/'));
        let stat;
        try { stat = await fs.promises.stat(clientPath); }
        catch { throw new Error('Plugin client script is missing.'); }
        if (!stat.isFile() || stat.size > MAX_CLIENT_BYTES) throw new Error('Plugin client script is missing or exceeds 1 MB.');
        active.clientSource = await fs.promises.readFile(clientPath, 'utf8');
      } else {
        active.clientSource = '';
      }
    }
    const source = active?.clientSource ?? '';
    return `window.SHAM._loadingPluginId=${JSON.stringify(manifest.id)};
try {
${source}
} finally { window.SHAM._loadingPluginId=null; }
`;
  }

  async handleApi(id, action, request) {
    if (this.stopping) throw new Error('Plugin manager is shutting down.');
    if (this.activeActions.size >= PLUGIN_MAX_PENDING_ACTIONS) throw new Error('Too many plugin actions are already running.');
    const pluginId = String(id);
    const active = this.active.get(pluginId);
    if (!active) throw new Error('Plugin is not enabled.');
    let rawOperation;
    let responseOperation;
    if (active.instance?.__workerRuntime) {
      rawOperation = Promise.resolve(active.instance.__workerRuntime.invoke(action, request));
      responseOperation = rawOperation;
    } else {
      const handler = active.instance?.api?.[action];
      if (typeof handler !== 'function') throw new Error('Plugin action not found.');
      const context = this.context(active.row, active.manifest);
      rawOperation = Promise.resolve().then(() => handler({ ...request, data: context.data, settings: context.settings }));
      responseOperation = withTimeout(
        rawOperation,
        PLUGIN_ACTION_TIMEOUT_MS,
        `Plugin action exceeded ${PLUGIN_ACTION_TIMEOUT_MS / 1000} seconds.`
      );
    }
    this.activeActions.set(rawOperation, pluginId);
    rawOperation.then(
      () => this.activeActions.delete(rawOperation),
      () => this.activeActions.delete(rawOperation)
    );
    return responseOperation;
  }

  async shutdown() {
    this.stopping = true;
    await Promise.allSettled([...this.installWorkers].map((worker) => worker.terminate()));
    await Promise.allSettled([...this.installOperations]);
    this.installWorkers.clear();
    await Promise.allSettled([...this.active.keys()].map((id) => this.unload(id)));
    if (this.activeActions.size) {
      try {
        await withTimeout(Promise.allSettled([...this.activeActions.keys()]), PLUGIN_ACTION_TIMEOUT_MS, 'Plugin actions did not stop before shutdown.');
      } catch (error) {
        this.logger.error(`[plugins] ${error.message}`);
      }
    }
  }
}

module.exports = { PluginManager, validateManifest, validateDeclarativeSql };
