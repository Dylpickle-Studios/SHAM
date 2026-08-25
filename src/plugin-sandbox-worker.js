const fs = require('node:fs');
const path = require('node:path');
const vm = require('node:vm');
const { parentPort, workerData } = require('node:worker_threads');
if (!parentPort) throw new Error('This module must run inside a worker thread.');
const port = parentPort;

let rpcCounter = 0;
const pendingRpc = new Map();
let instance = {};
const MAX_PENDING_RPC = Math.max(1, Number(workerData.maxPendingRpc || 32));
const settingsCache = { ...(workerData.settings || {}) };

function rpc(method, args = []) {
  if (pendingRpc.size >= MAX_PENDING_RPC) return Promise.reject(new Error('Plugin has too many pending host operations.'));
  const id = ++rpcCounter;
  port.postMessage({ type: 'rpc', id, method, args });
  return new Promise((resolve, reject) => pendingRpc.set(id, { resolve, reject }));
}

function sandboxRequire(name) {
  const allowed = new Set(['node:buffer', 'buffer', 'node:crypto', 'crypto', 'node:util', 'util', 'node:url', 'url']);
  if (workerData.manifest.permissions.includes('network:outbound')) {
    for (const item of ['node:http', 'http', 'node:https', 'https', 'node:net', 'net', 'node:tls', 'tls', 'node:dns', 'dns']) allowed.add(item);
  }
  if (!allowed.has(name)) throw new Error(`Worker-isolated plugin cannot require “${name}”.`);
  return require(name);
}

function context() {
  const permissions = new Set(workerData.manifest.permissions || []);
  const requirePermission = (permission) => {
    if (!permissions.has(permission)) throw new Error(`Plugin does not have the ${permission} permission.`);
  };
  return {
    id: workerData.manifest.id,
    manifest: workerData.manifest,
    permissions: [...permissions],
    data: {
      all: (sql, params = []) => { requirePermission('data:read'); return rpc('data.all', [sql, params]); },
      get: (sql, params = []) => { requirePermission('data:read'); return rpc('data.get', [sql, params]); },
      run: (sql, params = []) => { requirePermission('data:write'); return rpc('data.run', [sql, params]); }
    },
    settings: {
      get: (key, fallback = null) => { requirePermission('settings:read'); return settingsCache[key] ?? fallback; },
      all: () => { requirePermission('settings:read'); return { ...settingsCache }; },
      set: async (key, value) => { requirePermission('settings:write'); const result = await rpc('settings.set', [key, value]); Object.assign(settingsCache, result); return result; }
    },
    runtime: {
      list: () => { requirePermission('runtime:read'); return rpc('runtime.list'); },
      status: (siteId) => { requirePermission('runtime:read'); return rpc('runtime.status', [siteId]); },
      start: (siteId) => { requirePermission('runtime:manage'); return rpc('runtime.start', [siteId]); },
      stop: (siteId) => { requirePermission('runtime:manage'); return rpc('runtime.stop', [siteId]); },
      restart: (siteId) => { requirePermission('runtime:manage'); return rpc('runtime.restart', [siteId]); }
    },
    log: (message) => port.postMessage({ type: 'log', message: String(message).slice(0, 2000) })
  };
}

async function activate() {
  const source = fs.readFileSync(workerData.mainPath, 'utf8');
  const module = { exports: {} };
  const sandbox = {
    module, exports: module.exports, require: sandboxRequire,
    __filename: workerData.mainPath, __dirname: path.dirname(workerData.mainPath),
    Buffer, URL, URLSearchParams, TextEncoder, TextDecoder,
    setTimeout, clearTimeout, setInterval, clearInterval, queueMicrotask,
    console: {
      log: (...args) => port.postMessage({ type: 'log', message: args.map(String).join(' ').slice(0, 2000) }),
      error: (...args) => port.postMessage({ type: 'log', level: 'error', message: args.map(String).join(' ').slice(0, 2000) })
    }
  };
  vm.createContext(sandbox, { name: `sham-plugin-${workerData.manifest.id}`, codeGeneration: { strings: false, wasm: false } });
  const wrapper = new vm.Script(`(function (exports, module, require, __filename, __dirname) { 'use strict';\n${source}\n})`, { filename: workerData.mainPath });
  wrapper.runInContext(sandbox, { timeout: 5000 })(module.exports, module, sandboxRequire, workerData.mainPath, path.dirname(workerData.mainPath));
  const exported = module.exports;
  instance = typeof exported.activate === 'function' ? exported.activate(context()) || {} : exported;
  if (instance && typeof instance.then === 'function') throw new Error('Plugin activate() must return synchronously.');
  port.postMessage({ type: 'ready' });
}

port.on('message', async (message) => {
  if (message.type === 'rpc-result') {
    const pending = pendingRpc.get(message.id);
    if (!pending) return;
    pendingRpc.delete(message.id);
    if (message.error) pending.reject(new Error(message.error)); else pending.resolve(message.value);
    return;
  }
  if (message.type === 'settings') { Object.assign(settingsCache, message.values || {}); return; }
  if (message.type === 'invoke') {
    try {
      const handler = instance?.api?.[message.action];
      if (typeof handler !== 'function') throw new Error('Plugin action not found.');
      const value = await handler({ ...(message.request || {}), data: context().data, settings: context().settings });
      port.postMessage({ type: 'result', id: message.id, value });
    } catch (error) { port.postMessage({ type: 'result', id: message.id, error: error.message }); }
    return;
  }
  if (message.type === 'deactivate') {
    try { await instance?.deactivate?.(); port.postMessage({ type: 'deactivated', id: message.id }); }
    catch (error) { port.postMessage({ type: 'deactivated', id: message.id, error: error.message }); }
  }
});

activate().catch((error) => port.postMessage({ type: 'fatal', error: error.message }));
