'use strict';

const fs = require('node:fs');
const http = require('node:http');
const { PROTOCOL_VERSION, PROTOCOL_HEADER, AUTH_HEADER, OPERATIONS, ERROR_CODES } = require('./protocol');
const { RuntimeAgentError, RuntimeAgentUnavailableError } = require('./errors');

/** @typedef {{ method: string, path: string, stream?: boolean }} AgentOperation */
/** @typedef {Record<string, any>} AgentRequestBody */
/**
 * @typedef {Object} RuntimeAgentStatus
 * @property {boolean} agentReachable
 * @property {boolean} agentAuthenticated
 * @property {boolean} dockerAvailable
 * @property {boolean} [composeAvailable]
 * @property {boolean} [buildpacksAvailable]
 * @property {boolean} [nixpacksAvailable]
 * @property {string} [reason]
 * @property {string | null} checkedAt
 */

// Talks to the privileged Runtime Agent over a local Unix domain socket.
// This is the only module in the control plane allowed to know that Docker
// operations happen out-of-process; everything else calls these methods the
// same way it used to call runTool(DOCKER_BIN, ...).
class RuntimeClient {
  /**
   * @param {{ socketPath?: string, tokenPath?: string, requestTimeoutMs?: number }} [options]
   */
  constructor({ socketPath, tokenPath, requestTimeoutMs = 120_000 } = {}) {
    this.socketPath = socketPath;
    this.tokenPath = tokenPath;
    this.requestTimeoutMs = requestTimeoutMs;
    /** @type {string | null} */
    this.cachedToken = null;
    /** @type {RuntimeAgentStatus} */
    this.lastStatus = { agentReachable: false, agentAuthenticated: false, dockerAvailable: false, checkedAt: null };
  }

  /** @param {{ forceReload?: boolean }} [options] */
  loadToken({ forceReload = false } = {}) {
    if (this.cachedToken && !forceReload) return this.cachedToken;
    try {
      const value = fs.readFileSync(/** @type {string} */ (this.tokenPath), 'utf8').trim();
      if (!value) throw new Error('empty token file');
      this.cachedToken = value;
      return value;
    } catch (error) {
      const detail = /** @type {NodeJS.ErrnoException} */ (error);
      throw new RuntimeAgentUnavailableError(`agent token is not available (${detail.code || detail.message})`);
    }
  }

  /**
   * Low-level request. Returns { statusCode, headers, body } for non-stream
   * calls, or a readable-stream-like emitter for stream: true operations.
   * @param {AgentOperation} operation
   * @param {{ body?: AgentRequestBody | null, stream?: boolean, retriedAuth?: boolean }} [options]
   */
  request(operation, { body = null, stream = false, retriedAuth = false } = {}) {
    if (!this.socketPath) return Promise.reject(new RuntimeAgentUnavailableError('SHAM_RUNTIME_AGENT_SOCKET is not configured'));
    let token;
    try { token = this.loadToken(); }
    catch (error) { return Promise.reject(error); }
    const payload = body === null ? null : Buffer.from(JSON.stringify(body));
    return new Promise((resolve, reject) => {
      const req = http.request({
        socketPath: this.socketPath,
        path: operation.path,
        method: operation.method,
        timeout: this.requestTimeoutMs,
        headers: {
          [PROTOCOL_HEADER]: String(PROTOCOL_VERSION),
          [AUTH_HEADER]: `Bearer ${token}`,
          ...(payload ? { 'content-type': 'application/json', 'content-length': payload.length } : {})
        }
      }, (res) => {
        if (res.statusCode === 401 && !retriedAuth) {
          res.resume();
          try { this.loadToken({ forceReload: true }); } catch { /* fall through to normal error */ }
          resolve(this.request(operation, { body, stream, retriedAuth: true }));
          return;
        }
        // A streaming operation only actually streams once the agent has
        // committed to a 2xx response; validation/ownership failures still
        // arrive as a plain JSON error body (see runtime-agent/server.js).
        const statusCode = res.statusCode || 0;
        if (stream && statusCode >= 200 && statusCode < 300) return resolve(this._readNdjsonStream(res));
        const chunks = [];
        let bytes = 0;
        res.on('data', (chunk) => { bytes += chunk.length; if (bytes <= 8 * 1024 * 1024) chunks.push(chunk); });
        res.once('end', () => {
          const raw = Buffer.concat(chunks).toString('utf8');
          let parsed = null;
          try { parsed = raw ? JSON.parse(raw) : null; } catch { /* non-JSON error body */ }
          if (statusCode >= 200 && statusCode < 300) return resolve(parsed);
          reject(this._translateErrorBody(statusCode, parsed, raw));
        });
        res.once('error', (error) => reject(new RuntimeAgentUnavailableError(error.message)));
      });
      req.once('timeout', () => { req.destroy(); reject(new RuntimeAgentUnavailableError('request to the runtime agent timed out')); });
      req.once('error', (error) => reject(new RuntimeAgentUnavailableError(this._describeConnectError(error))));
      if (payload) req.end(payload); else req.end();
    });
  }

  _describeConnectError(error) {
    if (error.code === 'ENOENT' || error.code === 'ECONNREFUSED') return 'runtime agent disconnected';
    return error.message;
  }

  _translateErrorBody(statusCode, parsed, raw) {
    const code = parsed?.error?.code || (statusCode === 401 ? ERROR_CODES.UNAUTHENTICATED : ERROR_CODES.INTERNAL);
    const message = parsed?.error?.message || raw?.slice(0, 500) || `Runtime agent returned HTTP ${statusCode}.`;
    if (code === ERROR_CODES.PROTOCOL_VERSION_MISMATCH) return new RuntimeAgentUnavailableError('control plane and runtime agent protocol versions do not match');
    if (code === ERROR_CODES.UNAUTHENTICATED) return new RuntimeAgentUnavailableError('runtime agent authentication failed');
    return new RuntimeAgentError(message, code);
  }

  // Parses a chunked NDJSON response into an async iterator of typed lines
  // plus a resolved terminal value. Consumers pass onLine for log fan-out.
  _readNdjsonStream(res) {
    let buffer = '';
    const lines = [];
    let finished = false;
    /** @type {InstanceType<typeof RuntimeAgentUnavailableError> | null} */
    let finalError = null;
    const waiters = [];
    const push = (line) => {
      if (waiters.length) waiters.shift()(line);
      else lines.push(line);
    };
    res.on('data', (chunk) => {
      buffer += chunk.toString('utf8');
      let idx;
      while ((idx = buffer.indexOf('\n')) !== -1) {
        const raw = buffer.slice(0, idx);
        buffer = buffer.slice(idx + 1);
        if (!raw.trim()) continue;
        let parsed;
        try { parsed = JSON.parse(raw); } catch { continue; }
        push(parsed);
      }
    });
    res.once('end', () => { finished = true; while (waiters.length) waiters.shift()(null); });
    res.once('error', (error) => { finalError = new RuntimeAgentUnavailableError(error.message); finished = true; while (waiters.length) waiters.shift()(null); });
    return {
      stop: () => res.destroy(),
      async *[Symbol.asyncIterator]() {
        for (;;) {
          if (lines.length) { yield lines.shift(); continue; }
          if (finished) break;
          const next = await new Promise((resolve) => waiters.push(resolve));
          if (next === null) break;
          yield next;
        }
        if (finalError) throw finalError;
      }
    };
  }

  async _consumeStream(operation, body, onLine) {
    const stream = await this.request(operation, { body, stream: true });
    let result = null;
    /** @type {InstanceType<typeof RuntimeAgentError> | null} */
    let opError = null;
    for await (const line of stream) {
      if (line.type === 'log' && onLine) onLine(line.level || 'info', line.line);
      else if (line.type === 'result') result = line.data;
      else if (line.type === 'error') opError = this._translateErrorBody(200, { error: line.error }, '');
    }
    if (opError) throw opError;
    return result;
  }

  async status() {
    try {
      const result = await this.request(OPERATIONS.STATUS);
      this.lastStatus = { agentReachable: true, agentAuthenticated: true, ...result, checkedAt: new Date().toISOString() };
    } catch (error) {
      this.lastStatus = {
        agentReachable: false,
        agentAuthenticated: false,
        dockerAvailable: false,
        composeAvailable: false,
        buildpacksAvailable: false,
        nixpacksAvailable: false,
        reason: error.message,
        checkedAt: new Date().toISOString()
      };
    }
    return this.lastStatus;
  }

  getCachedStatus() { return this.lastStatus; }

  // ---- Images ----
  buildImage({ tag, contextPath, mode, dockerfilePath, builder, onLine }) {
    return this._consumeStream(OPERATIONS.IMAGES_BUILD, { tag, contextPath, mode, dockerfilePath, builder }, onLine);
  }

  removeImage({ tag }) { return this.request(OPERATIONS.IMAGES_REMOVE, { body: { tag } }); }

  // ---- Containers ----
  runContainer(params) { return this.request(OPERATIONS.CONTAINERS_RUN, { body: params }); }

  stopContainer({ name, timeoutSec }) { return this.request(OPERATIONS.CONTAINERS_STOP, { body: { name, timeoutSec } }); }
  removeContainer({ name }) { return this.request(OPERATIONS.CONTAINERS_REMOVE, { body: { name } }); }
  async containerPort({ name, containerPort, timeoutMs }) {
    const result = await this.request(OPERATIONS.CONTAINERS_PORT, { body: { name, containerPort, timeoutMs } });
    return result.port;
  }

  async streamContainerLogs({ name, onLine }) {
    const stream = await this.request(OPERATIONS.CONTAINERS_LOGS, { body: { name }, stream: true });
    (async () => { try { for await (const line of stream) { if (line.type === 'log' && onLine) onLine(line.level || 'info', line.line); } } catch { /* stream ended */ } })();
    return { stop: () => stream.stop() };
  }

  async waitContainer({ name, onExit }) {
    const stream = await this.request(OPERATIONS.CONTAINERS_WAIT, { body: { name }, stream: true });
    (async () => {
      try {
        for await (const line of stream) {
          if (line.type === 'result' && onExit) onExit(Number.isInteger(line.data?.exitCode) ? line.data.exitCode : null);
        }
      } catch { /* stream ended / agent unavailable mid-wait */ }
    })();
    return { stop: () => stream.stop() };
  }

  containerExec({ name, command, timeoutMs, onLine }) { return this._consumeStream(OPERATIONS.CONTAINERS_EXEC, { name, command, timeoutMs }, onLine); }
  containerStats({ id }) { return this.request(OPERATIONS.CONTAINERS_STATS, { body: { id } }); }

  sandboxRun({ image, envFile, workspaceSource, command, timeoutMs, onLine }) {
    return this._consumeStream(OPERATIONS.CONTAINERS_SANDBOX_RUN, { image, envFile, workspaceSource, command, timeoutMs }, onLine);
  }

  sidecarRun(params) { return this.request(OPERATIONS.CONTAINERS_SIDECAR_RUN, { body: params }); }
  sidecarRemove({ name }) { return this.request(OPERATIONS.CONTAINERS_SIDECAR_REMOVE, { body: { name } }); }

  // ---- Networks ----
  ensureNetwork({ name, internal = true }) { return this.request(OPERATIONS.NETWORKS_ENSURE, { body: { name, internal } }); }
  connectNetwork({ network, containerId, alias }) { return this.request(OPERATIONS.NETWORKS_CONNECT, { body: { network, containerId, alias } }); }

  // ---- Compose ----
  composeConfig({ files, cwd, env, service, containerPort }) { return this.request(OPERATIONS.COMPOSE_CONFIG, { body: { files, cwd, env, service, containerPort } }); }
  composeUp({ project, files, cwd, env, service, containerPort, onLine }) { return this._consumeStream(OPERATIONS.COMPOSE_UP, { project, files, cwd, env, service, containerPort }, onLine); }
  async composePs({ project, files, cwd, env, service }) {
    const result = await this.request(OPERATIONS.COMPOSE_PS, { body: { project, files, cwd, env, service } });
    return result.containerId;
  }
  async composePort({ project, files, cwd, env, service, containerPort }) {
    const result = await this.request(OPERATIONS.COMPOSE_PORT, { body: { project, files, cwd, env, service, containerPort } });
    return result.port;
  }
  composeDown({ project, files, cwd, env }) { return this.request(OPERATIONS.COMPOSE_DOWN, { body: { project, files, cwd, env } }); }
  composeExec({ project, files, cwd, env, service, command, timeoutMs, onLine }) { return this._consumeStream(OPERATIONS.COMPOSE_EXEC, { project, files, cwd, env, service, command, timeoutMs }, onLine); }

  // ---- Cleanup ----
  cleanupComposeProject({ project, file, cwd }) { return this.request(OPERATIONS.CLEANUP_COMPOSE_PROJECT, { body: { project, file, cwd } }); }
  cleanupOrphanedComposeProject({ project }) { return this.request(OPERATIONS.CLEANUP_ORPHANED_COMPOSE_PROJECT, { body: { project } }); }
  cleanupManagedContainers() { return this.request(OPERATIONS.CLEANUP_MANAGED_CONTAINERS); }
  cleanupManagedImages() { return this.request(OPERATIONS.CLEANUP_MANAGED_IMAGES); }
}

/** @type {RuntimeClient | null} */
let sharedClient = null;
function getRuntimeClient() {
  if (sharedClient) return sharedClient;
  const { RUNTIME_AGENT_SOCKET_PATH, RUNTIME_AGENT_TOKEN_PATH, RUNTIME_AGENT_REQUEST_TIMEOUT_MS } = require('../config');
  sharedClient = new RuntimeClient({
    socketPath: RUNTIME_AGENT_SOCKET_PATH,
    tokenPath: RUNTIME_AGENT_TOKEN_PATH,
    requestTimeoutMs: RUNTIME_AGENT_REQUEST_TIMEOUT_MS
  });
  return sharedClient;
}

module.exports = { RuntimeClient, getRuntimeClient };
