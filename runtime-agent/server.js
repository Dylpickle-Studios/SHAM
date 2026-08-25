'use strict';

const http = require('node:http');
const fs = require('node:fs');
const { PROTOCOL_VERSION, PROTOCOL_HEADER, MAX_REQUEST_BODY_BYTES, OPERATIONS, ERROR_CODES } = require('../src/runtime/protocol');
const { DATA_DIR } = require('../src/config');
const { loadOrCreateToken, tokensMatch, extractBearerToken } = require('./auth');
const { ValidationError } = require('./validation');
const docker = require('./docker');
const { log } = require('./logger');

const ROUTES = {
  STATUS: { fn: () => docker.status(), describe: () => ({}) },
  IMAGES_BUILD: { fn: docker.imagesBuild, stream: true, describe: (b) => ({ tag: b.tag, mode: b.mode }) },
  IMAGES_REMOVE: { fn: docker.imagesRemove, describe: (b) => ({ tag: b.tag }) },
  CONTAINERS_RUN: { fn: docker.containersRun, describe: (b) => ({ name: b.name, siteId: b.siteId }) },
  CONTAINERS_STOP: { fn: docker.containersStop, describe: (b) => ({ name: b.name }) },
  CONTAINERS_REMOVE: { fn: docker.containersRemove, describe: (b) => ({ name: b.name }) },
  CONTAINERS_PORT: { fn: docker.containersPort, describe: (b) => ({ name: b.name }) },
  CONTAINERS_LOGS: { fn: docker.containersLogs, stream: true, describe: (b) => ({ name: b.name }) },
  CONTAINERS_WAIT: { fn: docker.containersWait, stream: true, describe: (b) => ({ name: b.name }) },
  CONTAINERS_EXEC: { fn: docker.containersExec, stream: true, describe: (b) => ({ name: b.name }) },
  CONTAINERS_STATS: { fn: docker.containersStats, describe: (b) => ({ id: b.id }) },
  CONTAINERS_SANDBOX_RUN: { fn: docker.containersSandboxRun, stream: true, describe: () => ({}) },
  CONTAINERS_SIDECAR_RUN: { fn: docker.containersSidecarRun, describe: (b) => ({ name: b.name }) },
  CONTAINERS_SIDECAR_REMOVE: { fn: docker.containersSidecarRemove, describe: (b) => ({ name: b.name }) },
  NETWORKS_ENSURE: { fn: docker.networksEnsure, describe: (b) => ({ network: b.name }) },
  NETWORKS_CONNECT: { fn: docker.networksConnect, describe: (b) => ({ network: b.network }) },
  COMPOSE_CONFIG: { fn: docker.composeConfigOp, describe: (b) => ({ service: b.service }) },
  COMPOSE_UP: { fn: docker.composeUp, stream: true, describe: (b) => ({ project: b.project, service: b.service }) },
  COMPOSE_PS: { fn: docker.composePs, describe: (b) => ({ project: b.project }) },
  COMPOSE_PORT: { fn: docker.composePort, describe: (b) => ({ project: b.project }) },
  COMPOSE_DOWN: { fn: docker.composeDown, describe: (b) => ({ project: b.project }) },
  COMPOSE_EXEC: { fn: docker.composeExec, stream: true, describe: (b) => ({ project: b.project }) },
  CLEANUP_COMPOSE_PROJECT: { fn: docker.cleanupComposeProject, describe: (b) => ({ project: b.project }) },
  CLEANUP_ORPHANED_COMPOSE_PROJECT: { fn: docker.cleanupOrphanedComposeProject, describe: (b) => ({ project: b.project }) },
  CLEANUP_MANAGED_CONTAINERS: { fn: docker.cleanupManagedContainers, describe: () => ({}) },
  CLEANUP_MANAGED_IMAGES: { fn: docker.cleanupManagedImages, describe: () => ({}) }
};

const ROUTE_BY_METHOD_PATH = new Map();
for (const [key, definition] of Object.entries(ROUTES)) {
  const operation = OPERATIONS[key];
  ROUTE_BY_METHOD_PATH.set(`${operation.method} ${operation.path}`, { key, operation, ...definition });
}

function sanitizeMessage(message) {
  return String(message || 'Runtime agent operation failed.').split(DATA_DIR).join('<data>');
}

function errorStatusAndCode(error) {
  if (error instanceof ValidationError) return [400, ERROR_CODES.INVALID_REQUEST];
  if (error?.code === 'NOT_FOUND') return [404, ERROR_CODES.NOT_FOUND];
  if (error?.code === 'NOT_OWNED') return [403, ERROR_CODES.RESOURCE_NOT_OWNED];
  return [500, ERROR_CODES.OPERATION_FAILED];
}

function sendJson(res, statusCode, body) {
  const payload = Buffer.from(JSON.stringify(body));
  res.writeHead(statusCode, { 'content-type': 'application/json', 'content-length': payload.length });
  res.end(payload);
}

function sendError(res, statusCode, code, message) {
  sendJson(res, statusCode, { error: { code, message: sanitizeMessage(message) } });
}

function readBody(req) {
  return new Promise((resolve, reject) => {
    const chunks = [];
    let bytes = 0;
    let settled = false;
    req.on('data', (chunk) => {
      if (settled) return;
      bytes += chunk.length;
      if (bytes > MAX_REQUEST_BODY_BYTES) {
        // Stop buffering and reject, but do not destroy the socket — the
        // caller still needs it intact to write the 413 response back.
        settled = true;
        req.pause();
        reject(Object.assign(new Error('Request body is too large.'), { code: 'BODY_TOO_LARGE' }));
        return;
      }
      chunks.push(chunk);
    });
    req.once('end', () => { if (!settled) { settled = true; resolve(Buffer.concat(chunks)); } });
    req.once('error', (error) => { if (!settled) { settled = true; reject(error); } });
  });
}

async function handleRequest(req, res, { token }) {
  const url = req.url.split('?')[0];

  if (req.method === 'GET' && url === '/health') { sendJson(res, 200, { status: 'ok' }); return; }

  const route = ROUTE_BY_METHOD_PATH.get(`${req.method} ${url}`);
  if (!route) { sendError(res, 404, ERROR_CODES.NOT_FOUND, 'Unknown operation.'); return; }

  const presented = extractBearerToken(req.headers.authorization);
  if (!tokensMatch(token, presented)) { sendError(res, 401, ERROR_CODES.UNAUTHENTICATED, 'Authentication failed.'); return; }

  const clientProtocol = Number(req.headers[PROTOCOL_HEADER]);
  if (clientProtocol !== PROTOCOL_VERSION) { sendError(res, 426, ERROR_CODES.PROTOCOL_VERSION_MISMATCH, 'Protocol version mismatch.'); return; }

  let body = {};
  if (req.method === 'POST') {
    let raw;
    try { raw = await readBody(req); }
    catch (error) {
      // The client may still be mid-write; refuse to keep this connection
      // alive for a pipelined follow-up request once we stop reading it.
      res.setHeader('connection', 'close');
      sendError(res, 413, ERROR_CODES.INVALID_REQUEST, error.message);
      req.socket.end();
      return;
    }
    if (raw.length) {
      try { body = JSON.parse(raw.toString('utf8')); }
      catch { sendError(res, 400, ERROR_CODES.INVALID_REQUEST, 'Request body must be valid JSON.'); return; }
      if (typeof body !== 'object' || body === null || Array.isArray(body)) { sendError(res, 400, ERROR_CODES.INVALID_REQUEST, 'Request body must be a JSON object.'); return; }
    }
  }

  const describe = route.describe ? route.describe(body) : {};
  const logEvent = route.key.toLowerCase().replace(/_/g, '.');

  if (!route.stream) {
    try {
      const result = await route.fn(body);
      log(logEvent, { ...describe, outcome: 'ok' });
      sendJson(res, 200, result === undefined ? {} : result);
    } catch (error) {
      log(logEvent, { ...describe, outcome: 'error', error: error.message });
      const [statusCode, code] = errorStatusAndCode(error);
      sendError(res, statusCode, code, error.message);
    }
    return;
  }

  // Validation/ownership checks in each operation run before any Docker
  // process is spawned, so most failures happen before the first emit() —
  // headers (and a real HTTP status code) are only committed at that point,
  // not unconditionally up front. A failure after streaming has started
  // falls back to an in-band NDJSON error line, since the status line can no
  // longer change.
  let headersSent = false;
  const ensureHeaders = () => {
    if (headersSent) return;
    headersSent = true;
    res.writeHead(200, { 'content-type': 'application/x-ndjson', 'transfer-encoding': 'chunked' });
  };
  const emit = (line) => { ensureHeaders(); if (!res.writableEnded) res.write(`${JSON.stringify(line)}\n`); };
  try {
    await route.fn(body, emit);
    log(logEvent, { ...describe, outcome: 'ok' });
  } catch (error) {
    log(logEvent, { ...describe, outcome: 'error', error: error.message });
    if (!headersSent) {
      const [statusCode, code] = errorStatusAndCode(error);
      sendError(res, statusCode, code, error.message);
      return;
    }
    emit({ type: 'error', error: { code: errorStatusAndCode(error)[1], message: sanitizeMessage(error.message) } });
  } finally {
    res.end();
  }
}

function createServer({ token }) {
  const server = http.createServer((req, res) => {
    handleRequest(req, res, { token }).catch((error) => {
      if (!res.headersSent) sendError(res, 500, ERROR_CODES.INTERNAL, error.message);
      else res.destroy();
    });
  });
  server.on('clientError', (error, socket) => { if (socket.writable) socket.end('HTTP/1.1 400 Bad Request\r\n\r\n'); });
  return server;
}

module.exports = { createServer };
