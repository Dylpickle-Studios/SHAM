'use strict';

const fs = require('node:fs');
const path = require('node:path');
const vm = require('node:vm');
const crypto = require('node:crypto');
const { parentPort, workerData } = require('node:worker_threads');
if (!parentPort) throw new Error('This module must run inside a worker thread.');
const port = parentPort;

// Node's default handling of an uncaught exception or unhandled rejection formats the
// thrown value with the host realm's util.inspect, which hands host functions to any
// custom inspector a guest object defines. Never touch the value: report and exit.
function guestFault() {
  try { port.postMessage({ type: 'fatal', error: 'Plugin raised an uncaught exception or unhandled promise rejection.' }); }
  finally { process.exit(1); }
}
process.on('uncaughtException', guestFault);
process.on('unhandledRejection', guestFault);

// Isolation contract: plugin code may only ever reach objects created inside its own
// vm context. Every host value that crosses the boundary is a primitive string, so
// constructor walks (`x.constructor.constructor('return process')()`), thrown host
// errors, host promises, and callback `this` values cannot lead back to this realm.
// The context's own intrinsics are not trusted by the host: the host never reads
// properties of, awaits, or passes callbacks to anything returned from the guest.

const MAX_PENDING_RPC = Math.max(1, Number(workerData.maxPendingRpc || 32));
const MAX_BRIDGE_BYTES = 8 * 1024 * 1024;
const MAX_TIMERS = 256;
const MAX_FETCH_BYTES = 8 * 1024 * 1024;
const permissions = new Set(workerData.manifest.permissions || []);
const RPC_PERMISSIONS = {
  'data.all': 'data:read', 'data.get': 'data:read', 'data.run': 'data:write', 'settings.set': 'settings:write',
  'runtime.list': 'runtime:read', 'runtime.status': 'runtime:read',
  'runtime.start': 'runtime:manage', 'runtime.stop': 'runtime:manage', 'runtime.restart': 'runtime:manage'
};

let rpcCounter = 0;
const pendingRpc = new Set();
const timers = new Map();
/** @type {(operation: string, ...args: unknown[]) => unknown} */
let guest = () => undefined;

const GUEST_BOOTSTRAP = `(function (bridge, manifestJson, settingsJson) {
  'use strict';
  const parse = JSON.parse;
  const stringify = JSON.stringify;
  const apply = Reflect.apply;
  const PromiseCtor = Promise;
  const ErrorCtor = Error;
  const TypeErrorCtor = TypeError;
  const StringCtor = String;
  const NumberCtor = Number;
  const Uint8ArrayCtor = Uint8Array;
  const assign = Object.assign;
  const pending = Object.create(null);
  const timers = Object.create(null);
  const manifest = parse(manifestJson);
  const permissions = manifest.permissions || [];
  const settingsCache = parse(settingsJson || '{}');
  let instance = {};
  let timerCounter = 0;

  function describe(error) {
    try { return StringCtor(error && error.message !== undefined ? error.message : error).slice(0, 2000); }
    catch { return 'Plugin operation failed.'; }
  }
  function call(operation, payload) {
    let encoded;
    try { encoded = stringify(payload === undefined ? null : payload); }
    catch { throw new TypeErrorCtor('Plugin values passed to SHAM must be JSON-serializable.'); }
    let response;
    // The host bridge never throws by design; a binding-less catch keeps any engine error out of reach.
    try { response = bridge(operation, encoded); }
    catch { throw new ErrorCtor('SHAM host call failed.'); }
    const result = parse(response);
    if (!result.ok) throw new ErrorCtor(StringCtor(result.error));
    return result.value;
  }
  function hasPermission(permission) {
    for (let index = 0; index < permissions.length; index += 1) if (permissions[index] === permission) return true;
    return false;
  }
  function requirePermission(permission) {
    if (!hasPermission(permission)) throw new ErrorCtor('Plugin does not have the ' + permission + ' permission.');
  }
  function asyncCall(operation, payload) {
    return new PromiseCtor((resolve, reject) => {
      const id = call(operation, payload);
      pending[id] = { resolve, reject };
    });
  }
  function rpc(method, args) { return asyncCall('rpc', { method, args: args === undefined ? [] : args }); }
  function log(level, values) {
    let message = '';
    try { for (let index = 0; index < values.length; index += 1) message += (index ? ' ' : '') + StringCtor(values[index]); }
    catch { message = '[unprintable plugin log message]'; }
    call('log', { level, message: message.slice(0, 2000) });
  }
  function setTimer(repeat, callback, ms, args) {
    if (typeof callback !== 'function') throw new TypeErrorCtor('Timer callback must be a function.');
    const id = ++timerCounter;
    call('timer.set', { id, ms: NumberCtor(ms) || 0, repeat });
    timers[id] = { callback, args, repeat };
    return id;
  }
  function clearTimer(id) {
    const key = NumberCtor(id);
    if (!timers[key]) return;
    delete timers[key];
    call('timer.clear', { id: key });
  }
  function toHex(bytes) {
    let output = '';
    for (let index = 0; index < bytes.length; index += 1) output += (bytes[index] & 255).toString(16).padStart(2, '0');
    return output;
  }
  function fromHex(hex) {
    const bytes = new Uint8ArrayCtor(hex.length / 2);
    for (let index = 0; index < bytes.length; index += 1) bytes[index] = parseInt(hex.slice(index * 2, index * 2 + 2), 16);
    return bytes;
  }
  function chunk(value) {
    if (typeof value === 'string') return { text: value };
    if (value instanceof Uint8ArrayCtor) return { hex: toHex(value) };
    throw new TypeErrorCtor('Hash input must be a string or Uint8Array.');
  }
  function digestBuilder(algorithm, key) {
    const chunks = [];
    const builder = {
      update(value) { chunks.push(chunk(value)); return builder; },
      digest(encoding) {
        const result = call('crypto.digest', { algorithm: StringCtor(algorithm), key: key === undefined ? null : chunk(key), chunks });
        if (encoding === 'hex') return result.hex;
        if (encoding === 'base64') return result.base64;
        if (encoding === 'base64url') return result.base64url;
        return fromHex(result.hex);
      }
    };
    return builder;
  }
  const cryptoModule = {
    randomUUID() { return call('crypto.uuid', null); },
    randomBytes(size) { return fromHex(call('crypto.random', { size: NumberCtor(size) })); },
    createHash(algorithm) { return digestBuilder(algorithm, undefined); },
    createHmac(algorithm, key) { return digestBuilder(algorithm, key); }
  };
  function guestRequire(name) {
    if (name === 'crypto' || name === 'node:crypto') return cryptoModule;
    throw new ErrorCtor('Worker-isolated plugins cannot require "' + StringCtor(name) + '". Use the SHAM plugin API (fetch, crypto, timers) instead.');
  }
  async function guestFetch(url, options) {
    requirePermission('network:outbound');
    const init = options || {};
    const response = await asyncCall('fetch', {
      url: StringCtor(url),
      method: init.method === undefined ? 'GET' : StringCtor(init.method),
      headers: init.headers || {},
      body: init.body === undefined || init.body === null ? null : StringCtor(init.body)
    });
    const headers = response.headers;
    return {
      ok: response.status >= 200 && response.status < 300,
      status: response.status,
      statusText: response.statusText,
      url: response.url,
      headers: { get(name) { const value = headers[StringCtor(name).toLowerCase()]; return value === undefined ? null : value; } },
      async text() { return response.body; },
      async json() { return parse(response.body); }
    };
  }

  const data = {
    all: (sql, params = []) => { requirePermission('data:read'); return rpc('data.all', [sql, params]); },
    get: (sql, params = []) => { requirePermission('data:read'); return rpc('data.get', [sql, params]); },
    run: (sql, params = []) => { requirePermission('data:write'); return rpc('data.run', [sql, params]); }
  };
  const settings = {
    get: (key, fallback = null) => { requirePermission('settings:read'); return settingsCache[key] ?? fallback; },
    all: () => { requirePermission('settings:read'); return assign({}, settingsCache); },
    set: async (key, value) => { requirePermission('settings:write'); const result = await rpc('settings.set', [key, value]); assign(settingsCache, result); return result; }
  };
  const api = {
    id: manifest.id,
    manifest,
    permissions: permissions.slice(),
    data,
    settings,
    runtime: {
      list: () => { requirePermission('runtime:read'); return rpc('runtime.list'); },
      status: (siteId) => { requirePermission('runtime:read'); return rpc('runtime.status', [siteId]); },
      start: (siteId) => { requirePermission('runtime:manage'); return rpc('runtime.start', [siteId]); },
      stop: (siteId) => { requirePermission('runtime:manage'); return rpc('runtime.stop', [siteId]); },
      restart: (siteId) => { requirePermission('runtime:manage'); return rpc('runtime.restart', [siteId]); }
    },
    log: (message) => log('info', [message])
  };

  const console = {
    log: (...values) => log('info', values),
    info: (...values) => log('info', values),
    warn: (...values) => log('error', values),
    error: (...values) => log('error', values),
    debug: (...values) => log('info', values)
  };
  assign(globalThis, {
    console,
    fetch: guestFetch,
    setTimeout: (callback, ms, ...args) => setTimer(false, callback, ms, args),
    setInterval: (callback, ms, ...args) => setTimer(true, callback, ms, args),
    clearTimeout: clearTimer,
    clearInterval: clearTimer,
    queueMicrotask: (callback) => { PromiseCtor.resolve().then(() => apply(callback, undefined, [])); }
  });

  function report(operation, payload) {
    try { call(operation, payload); }
    catch (error) { try { call(operation, { id: payload.id, error: describe(error) }); } catch { /* host is gone */ } }
  }
  function settle(operation, id, work) {
    try {
      PromiseCtor.resolve(work()).then(
        (value) => report(operation, { id, value: value === undefined ? null : value }),
        (error) => report(operation, { id, error: describe(error) })
      );
    } catch (error) { report(operation, { id, error: describe(error) }); }
  }

  return function guest(operation, first, second, third) {
    if (operation === 'activate') {
      try {
        const module = { exports: {} };
        apply(first, undefined, [module.exports, module, guestRequire, second, third]);
        const exported = module.exports;
        instance = exported && typeof exported.activate === 'function' ? exported.activate(api) || {} : exported;
        if (instance && typeof instance.then === 'function') throw new ErrorCtor('Plugin activate() must return synchronously.');
        return '';
      } catch (error) { return describe(error) || 'Plugin activation failed.'; }
    }
    if (operation === 'invoke') {
      settle('result', first, () => {
        const handlers = instance && instance.api;
        const handler = handlers && handlers[second];
        if (typeof handler !== 'function') throw new ErrorCtor('Plugin action not found.');
        const request = parse(third);
        request.data = data;
        request.settings = settings;
        return apply(handler, undefined, [request]);
      });
    } else if (operation === 'deactivate') {
      settle('deactivated', first, () => (instance && typeof instance.deactivate === 'function' ? apply(instance.deactivate, instance, []) : undefined));
    } else if (operation === 'deliver') {
      const entry = pending[first];
      if (!entry) return;
      delete pending[first];
      const result = parse(second);
      if (result.ok) entry.resolve(result.value); else entry.reject(new ErrorCtor(StringCtor(result.error)));
    } else if (operation === 'fire') {
      const timer = timers[first];
      if (!timer) return;
      if (!timer.repeat) delete timers[first];
      try { apply(timer.callback, undefined, timer.args); }
      catch (error) { log('error', ['Timer callback failed: ' + describe(error)]); }
    } else if (operation === 'settings') {
      assign(settingsCache, parse(second));
    }
    return undefined;
  };
})`;

function deliver(id, outcome) {
  let encoded;
  try { encoded = JSON.stringify(outcome.error === undefined ? { ok: true, value: outcome.value ?? null } : { ok: false, error: String(outcome.error) }); }
  catch { encoded = JSON.stringify({ ok: false, error: 'SHAM returned a value that cannot be passed to the plugin.' }); }
  callGuest('deliver', id, encoded);
}

// Guest code can throw anything (including objects with hostile getters); never inspect it here.
function callGuest(operation, ...args) {
  try { return guest(operation, ...args); }
  catch { port.postMessage({ type: 'log', level: 'error', message: `Plugin ${operation} handler threw outside the SHAM sandbox wrapper.` }); return undefined; }
}

async function hostFetch(input) {
  const url = new URL(String(input?.url || ''));
  if (!['http:', 'https:'].includes(url.protocol)) throw new Error('Plugin fetch only supports http and https URLs.');
  const headers = {};
  for (const [key, value] of Object.entries(input.headers && typeof input.headers === 'object' ? input.headers : {}).slice(0, 100)) headers[String(key)] = String(value);
  const response = await fetch(url, { method: String(input.method || 'GET').toUpperCase(), headers, body: input.body ?? undefined, redirect: 'follow', signal: AbortSignal.timeout(30_000) });
  const chunks = [];
  let size = 0;
  if (response.body) {
    for await (const part of response.body) {
      size += part.byteLength;
      if (size > MAX_FETCH_BYTES) throw new Error('Plugin fetch response exceeds 8 MB.');
      chunks.push(Buffer.from(part));
    }
  }
  return { status: response.status, statusText: response.statusText, url: response.url, headers: Object.fromEntries(response.headers), body: Buffer.concat(chunks).toString('utf8') };
}

function bytesFrom(value) {
  if (value && typeof value.text === 'string') return Buffer.from(value.text, 'utf8');
  if (value && typeof value.hex === 'string' && /^(?:[0-9a-f]{2})*$/i.test(value.hex)) return Buffer.from(value.hex, 'hex');
  throw new Error('Hash input is invalid.');
}

function handleHostCall(operation, input) {
  if (operation === 'log') {
    port.postMessage({ type: 'log', level: input?.level === 'error' ? 'error' : undefined, message: String(input?.message ?? '').slice(0, 2000) });
    return null;
  }
  if (operation === 'rpc') {
    const method = String(input?.method || '');
    const permission = RPC_PERMISSIONS[method];
    if (!permission) throw new Error('Unsupported plugin host operation.');
    if (!permissions.has(permission)) throw new Error(`Plugin does not have the ${permission} permission.`);
    if (pendingRpc.size >= MAX_PENDING_RPC) throw new Error('Plugin has too many pending host operations.');
    const id = ++rpcCounter;
    pendingRpc.add(id);
    port.postMessage({ type: 'rpc', id, method, args: Array.isArray(input.args) ? input.args : [] });
    return id;
  }
  if (operation === 'fetch') {
    if (!permissions.has('network:outbound')) throw new Error('Plugin does not have the network:outbound permission.');
    if (pendingRpc.size >= MAX_PENDING_RPC) throw new Error('Plugin has too many pending host operations.');
    const id = ++rpcCounter;
    pendingRpc.add(id);
    hostFetch(input).then((value) => ({ value }), (error) => ({ error: error?.message || 'Plugin fetch failed.' })).then((outcome) => {
      if (pendingRpc.delete(id)) deliver(id, outcome);
    });
    return id;
  }
  if (operation === 'timer.set') {
    const id = Number(input?.id);
    if (!Number.isSafeInteger(id) || timers.has(id)) throw new Error('Timer ID is invalid.');
    if (timers.size >= MAX_TIMERS) throw new Error('Plugin has too many active timers.');
    const ms = Math.min(Math.max(Number(input.ms) || 0, 0), 2_147_483_647);
    const fire = () => { if (!input.repeat) timers.delete(id); callGuest('fire', id); };
    timers.set(id, input.repeat ? setInterval(fire, Math.max(ms, 1)) : setTimeout(fire, ms));
    return null;
  }
  if (operation === 'timer.clear') {
    const timer = timers.get(Number(input?.id));
    if (timer) { clearTimeout(timer); clearInterval(timer); timers.delete(Number(input.id)); }
    return null;
  }
  if (operation === 'crypto.uuid') return crypto.randomUUID();
  if (operation === 'crypto.random') {
    const size = Number(input?.size);
    if (!Number.isInteger(size) || size < 0 || size > 65536) throw new Error('randomBytes size must be between 0 and 65536.');
    return crypto.randomBytes(size).toString('hex');
  }
  if (operation === 'crypto.digest') {
    const algorithm = String(input?.algorithm || '');
    const hash = input.key ? crypto.createHmac(algorithm, bytesFrom(input.key)) : crypto.createHash(algorithm);
    for (const part of Array.isArray(input.chunks) ? input.chunks : []) hash.update(bytesFrom(part));
    const digest = hash.digest();
    return { hex: digest.toString('hex'), base64: digest.toString('base64'), base64url: digest.toString('base64url') };
  }
  if (operation === 'result' || operation === 'deactivated') {
    port.postMessage({ type: operation, id: input?.id, value: input?.value ?? undefined, error: input?.error === undefined ? undefined : String(input.error) });
    return null;
  }
  throw new Error('Unsupported plugin host operation.');
}

// The only host function the guest can call. It is held in a bootstrap closure, takes
// and returns strings, and reports failures in-band instead of throwing host errors.
function hostBridge(operation, payload) {
  try {
    if (typeof operation !== 'string' || typeof payload !== 'string' || payload.length > MAX_BRIDGE_BYTES) throw new Error('Invalid plugin host call.');
    const value = handleHostCall(operation, JSON.parse(payload));
    return JSON.stringify({ ok: true, value: value ?? null });
  } catch (error) {
    return JSON.stringify({ ok: false, error: String(error?.message || 'Plugin host call failed.').slice(0, 2000) });
  }
}

function activate() {
  const options = { name: `sham-plugin-${workerData.manifest.id}`, codeGeneration: { strings: false, wasm: false } };
  // DONT_CONTEXTIFY gives the context an ordinary global with no host-realm sandbox object behind it.
  const context = vm.constants?.DONT_CONTEXTIFY ? vm.createContext(vm.constants.DONT_CONTEXTIFY, options) : vm.createContext(Object.create(null), options);
  const factory = new vm.Script(GUEST_BOOTSTRAP, { filename: 'sham-plugin-bootstrap.js' }).runInContext(context);
  guest = factory(hostBridge, JSON.stringify(workerData.manifest), JSON.stringify(workerData.settings || {}));
  const source = fs.readFileSync(workerData.mainPath, 'utf8');
  const wrapper = new vm.Script(`(function (exports, module, require, __filename, __dirname) { 'use strict';\n${source}\n})`, { filename: workerData.mainPath })
    .runInContext(context, { timeout: 5000 });
  const failure = callGuest('activate', wrapper, workerData.mainPath, path.dirname(workerData.mainPath));
  if (typeof failure !== 'string') throw new Error('Plugin activation failed.');
  if (failure) throw new Error(failure);
  port.postMessage({ type: 'ready' });
}

port.on('message', (message) => {
  if (message.type === 'rpc-result') {
    if (!pendingRpc.delete(message.id)) return;
    deliver(message.id, message.error ? { error: message.error } : { value: message.value });
    return;
  }
  if (message.type === 'settings') {
    let encoded;
    try { encoded = JSON.stringify(message.values || {}); } catch { return; }
    callGuest('settings', null, encoded);
    return;
  }
  if (message.type === 'invoke') {
    let request;
    try { request = JSON.stringify(message.request || {}); }
    catch { port.postMessage({ type: 'result', id: message.id, error: 'Plugin request is not JSON-serializable.' }); return; }
    callGuest('invoke', message.id, String(message.action), request);
    return;
  }
  if (message.type === 'deactivate') callGuest('deactivate', message.id);
});

try { activate(); }
catch (error) { port.postMessage({ type: 'fatal', error: error instanceof Error ? error.message : 'Plugin activation failed.' }); }
