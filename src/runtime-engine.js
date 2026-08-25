'use strict';

const fs = require('node:fs');
const path = require('node:path');
const net = require('node:net');
const http = require('node:http');
const https = require('node:https');
const { spawn } = require('node:child_process');
const { DATA_DIR } = require('./config');
const { runtimeEnvironment } = require('./process-env');

/** @typedef {import('node:child_process').ChildProcess} ChildProcess */

/** @param {import('node:child_process').SpawnOptions} [options] */
function runtimeProcessOptions(options = {}) {
  return { ...options, detached: process.platform !== 'win32' };
}

/**
 * @param {ChildProcess | null | undefined} child
 * @param {NodeJS.Signals} [signal]
 */
function terminateProcess(child, signal = 'SIGTERM') {
  if (!child || child.exitCode !== null || child.signalCode !== null) return;
  try {
    if (process.platform !== 'win32' && child.pid) process.kill(-child.pid, signal);
    else child.kill(signal);
  } catch {
    try { child.kill(signal); } catch { /* already gone */ }
  }
}

/**
 * @param {ChildProcess | null | undefined} child
 * @param {number} [graceMs]
 * @returns {Promise<void>}
 */
function terminateProcessAndWait(child, graceMs = 10_000) {
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
    forceTimer = setTimeout(() => terminateProcess(child, 'SIGKILL'), Math.max(500, graceMs));
    forceTimer.unref?.();
    fallbackTimer = setTimeout(finish, Math.max(500, graceMs) + 3000);
    fallbackTimer.unref?.();
    terminateProcess(child, 'SIGTERM');
  });
}

function lineLogger(stream, onLine, { maxLinesPerSecond = 200, maxLineLength = 1200, prefix = '' } = {}) {
  if (!stream) return () => {};
  let buffer = '';
  let truncated = false;
  let windowStarted = Date.now();
  let lines = 0;
  let suppressed = 0;
  const flushSuppressed = () => {
    if (!suppressed) return;
    onLine(`${prefix}suppressed ${suppressed} excessive log line${suppressed === 1 ? '' : 's'}`);
    suppressed = 0;
  };
  const emit = (line) => {
    const now = Date.now();
    if (now - windowStarted >= 1000) {
      flushSuppressed();
      windowStarted = now;
      lines = 0;
    }
    if (lines >= maxLinesPerSecond) { suppressed += 1; return; }
    lines += 1;
    onLine(`${prefix}${line}`);
  };
  const finishLine = () => {
    if (buffer || truncated) emit(`${buffer}${truncated ? ' …[truncated]' : ''}`);
    buffer = '';
    truncated = false;
  };
  const append = (text) => {
    if (!text || truncated) return;
    const remaining = Math.max(0, maxLineLength - buffer.length);
    buffer += text.slice(0, remaining);
    if (text.length > remaining) truncated = true;
  };
  const onData = (chunk) => {
    const text = chunk.toString();
    let cursor = 0;
    while (cursor < text.length) {
      const newline = text.indexOf('\n', cursor);
      if (newline === -1) { append(text.slice(cursor)); break; }
      let segment = text.slice(cursor, newline);
      if (segment.endsWith('\r')) segment = segment.slice(0, -1);
      append(segment);
      finishLine();
      cursor = newline + 1;
    }
  };
  const onEnd = () => { finishLine(); flushSuppressed(); };
  stream.on('data', onData);
  stream.once('end', onEnd);
  return () => { stream.off('data', onData); stream.off('end', onEnd); buffer = ''; truncated = false; };
}

/**
 * @param {string | string[]} command
 * @param {{ cwd?: string, env?: Record<string, string>, stdio?: import('node:child_process').StdioOptions }} [options]
 * @returns {ChildProcess}
 */
function shellCommand(command, { cwd, env, stdio = ['ignore', 'pipe', 'pipe'] } = {}) {
  const options = runtimeProcessOptions({ cwd, env: runtimeEnvironment(env), stdio });
  if (Array.isArray(command)) {
    if (!command.length) throw new Error('Runtime start command is empty.');
    return spawn(command[0], command.slice(1), options);
  }
  const value = String(command || '').trim();
  if (!value) throw new Error('Runtime start command is empty.');
  if (process.platform === 'win32') return spawn(process.env.ComSpec || 'cmd.exe', ['/d', '/s', '/c', value], options);
  return spawn('/bin/sh', ['-lc', value], options);
}

/** @typedef {{ ok: boolean, message?: string }} ProbeResult */

/**
 * @param {string | string[]} command
 * @param {{ cwd?: string, env?: Record<string, string>, timeoutMs?: number }} [options]
 * @returns {Promise<ProbeResult>}
 */
function commandExit(command, { cwd, env, timeoutMs = 5000 } = {}) {
  return new Promise((resolve) => {
    /** @type {ChildProcess} */
    let child;
    try { child = shellCommand(command, { cwd, env, stdio: 'ignore' }); }
    catch (error) { resolve({ ok: false, message: error instanceof Error ? error.message : String(error) }); return; }
    let settled = false;
    const timer = setTimeout(() => { terminateProcess(child, 'SIGKILL'); finish(false, 'Readiness command timed out.'); }, timeoutMs);
    timer.unref?.();
    /** @param {boolean} ok @param {string} [message] */
    const finish = (ok, message = '') => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      resolve({ ok, message });
    };
    child.once('error', (error) => finish(false, error.message));
    child.once('exit', (code, signal) => finish(code === 0, code === 0 ? '' : `Readiness command exited ${code ?? signal ?? 'unexpectedly'}.`));
  });
}

function tcpProbe(host, port, timeoutMs = 1500) {
  return new Promise((resolve) => {
    const socket = net.connect({ host, port });
    const timer = setTimeout(() => { socket.destroy(); resolve({ ok: false, message: 'TCP probe timed out.' }); }, timeoutMs);
    timer.unref?.();
    socket.once('connect', () => { clearTimeout(timer); socket.destroy(); resolve({ ok: true }); });
    socket.once('error', (error) => { clearTimeout(timer); socket.destroy(); resolve({ ok: false, message: error.message }); });
  });
}

function httpProbe({ host, port, path: pathname = '/', statusMin = 200, statusMax = 399, tls = false, timeoutMs = 2500, headers = {} }) {
  return new Promise((resolve) => {
    const client = tls ? https : http;
    let settled = false;
    const finish = (result) => {
      if (settled) return;
      settled = true;
      resolve(result);
    };
    const request = client.request({ host, port, path: pathname || '/', method: 'GET', headers, rejectUnauthorized: false, timeout: timeoutMs }, (response) => {
      response.resume();
      const status = Number(response.statusCode || 0);
      finish({ ok: status >= statusMin && status <= statusMax, status, message: `HTTP ${status}` });
    });
    request.once('timeout', () => { request.destroy(); finish({ ok: false, message: 'HTTP probe timed out.' }); });
    request.once('error', (error) => finish({ ok: false, message: error.message }));
    request.end();
  });
}

/**
 * @param {import('./types/runtime').RuntimeSpec & { cwd?: string, host?: string, internalPort?: number }} spec
 * @param {{ child?: ChildProcess | null, cwd?: string, env?: Record<string, string>, host?: string, port?: number, log?: (message: string) => void }} [options]
 * @returns {Promise<boolean>}
 */
async function waitForReadiness(spec, { child = null, cwd = spec.cwd, env = {}, host = spec.host, port = spec.internalPort, log = () => {} } = {}) {
  const probe = spec.readiness || { type: 'tcp', timeoutMs: 30_000 };
  const deadline = Date.now() + Math.max(1000, Number(probe.timeoutMs || 30_000));
  let lastMessage = 'Runtime did not become ready.';
  /** @type {Error | null} */
  let childError = null;
  const onChildError = (/** @type {Error} */ error) => { childError = error; };
  child?.once('error', onChildError);
  try {
    do {
      if (childError) throw new Error(`Runtime process could not start: ${/** @type {Error} */ (childError).message}`);
      if (child && (child.exitCode !== null || child.signalCode !== null)) throw new Error(`Runtime exited during startup${child.exitCode !== null ? ` with code ${child.exitCode}` : child.signalCode ? ` after ${child.signalCode}` : ''}.`);
      let result;
      if (probe.type === 'none') {
        // A disabled probe still waits one event-loop turn so spawn errors and immediate exits
        // cannot be promoted as a healthy runtime.
        await new Promise((resolve) => setImmediate(resolve));
        if (childError) throw new Error(`Runtime process could not start: ${/** @type {Error} */ (childError).message}`);
        if (child && (child.exitCode !== null || child.signalCode !== null)) throw new Error(`Runtime exited during startup${child.exitCode !== null ? ` with code ${child.exitCode}` : child.signalCode ? ` after ${child.signalCode}` : ''}.`);
        return true;
      }
      if (probe.type === 'http') result = await httpProbe({ host, port, path: probe.path, statusMin: probe.statusMin, statusMax: probe.statusMax, headers: { Host: spec.site?.domain || host, 'User-Agent': 'SHAM-Readiness/1.0' } });
      else if (probe.type === 'command') result = await commandExit(probe.command || '', { cwd, env, timeoutMs: Math.min(5000, Math.max(1000, deadline - Date.now())) });
      else result = await tcpProbe(host, port);
      if (result.ok) return true;
      lastMessage = result.message || lastMessage;
      await new Promise((resolve) => setTimeout(resolve, 150));
    } while (Date.now() < deadline);
    log(`Readiness probe timed out: ${lastMessage}`);
    throw new Error(`Runtime did not become ready within ${Math.ceil(Number(probe.timeoutMs || 30_000) / 1000)} seconds: ${lastMessage}`);
  } finally {
    child?.off('error', onChildError);
  }
}

async function createEnvFile(siteId, env) {
  const dir = path.join(DATA_DIR, 'tmp');
  await fs.promises.mkdir(dir, { recursive: true, mode: 0o700 });
  const filename = path.join(dir, `runtime-env-${Number(siteId) || 'preview'}-${process.pid}-${Date.now()}-${Math.random().toString(36).slice(2)}.env`);
  const lines = [];
  for (const [key, raw] of Object.entries(env || {})) {
    if (!/^[A-Za-z_][A-Za-z0-9_]*$/.test(key)) continue;
    const value = String(raw ?? '');
    if (/\0|\r|\n/.test(value)) throw new Error(`Environment variable ${key} cannot be passed to Docker because it contains a newline or NUL byte.`);
    lines.push(`${key}=${value}`);
  }
  await fs.promises.writeFile(filename, `${lines.join('\n')}\n`, { mode: 0o600, flag: 'wx' });
  return filename;
}

function managedContainerName(siteId, suffix = '') {
  return `sham-site-${Number(siteId)}${suffix ? `-${suffix}` : ''}`.replace(/[^a-zA-Z0-9_.-]/g, '-').slice(0, 120);
}

module.exports = {
  runtimeProcessOptions,
  terminateProcess,
  terminateProcessAndWait,
  lineLogger,
  shellCommand,
  commandExit,
  tcpProbe,
  httpProbe,
  waitForReadiness,
  createEnvFile,
  managedContainerName
};
