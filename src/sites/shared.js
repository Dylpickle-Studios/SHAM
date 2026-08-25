'use strict';

const { siteRoot, legacySiteRoot, dockerHostDataPath } = require('../site-paths');

const fs = require('node:fs');
const path = require('node:path');
const crypto = require('node:crypto');
const http = require('node:http');
const https = require('node:https');
const net = require('node:net');
const { spawn, execFile } = require('node:child_process');
const { Worker } = require('node:worker_threads');
const zlib = require('node:zlib');
const { promisify } = require('node:util');
const express = require('express');
const httpProxy = require('http-proxy');
const {
  SITES_DIR,
  NODE_START_TIMEOUT_MS,
  NPM_INSTALL_TIMEOUT_MS,
  NPM_INSTALL_WORKERS,
  NPM_INSTALL_QUEUE_LIMIT,
  HTTP_REQUEST_TIMEOUT_MS,
  STATS_FLUSH_INTERVAL_MS,
  VISITOR_RETENTION_DAYS,
  MINIFY_MAX_BYTES,
  MINIFY_CACHE_BYTES,
  MINIFY_WORKERS,
  MINIFY_QUEUE_LIMIT,
  COMPRESSION_WORKERS,
  COMPRESSION_QUEUE_LIMIT,
  VISITOR_PENDING_BUCKETS,
  FIREWALL_RATE_LIMIT_BUCKETS,
  TRUSTED_EDGE_PROXIES,
  DOCKER_BIN,
  DOCKER_INTERNAL_NETWORK,
  DOCKER_EGRESS_NETWORK,
  SITE_DATA_DIR,
  JWT_SECRET
} = require('../config');
const { safeRelativePath } = require('../validation');
const { certbotPaths, hasCertificate } = require('../integrations');
const { runtimeEnvironment, buildEnvironment, operatorEnvironment } = require('../process-env');
const { classifyClient } = require('../visitor-intelligence');

const gzipAsync = promisify(zlib.gzip);
const brotliAsync = promisify(zlib.brotliCompress);
const execFileAsync = promisify(execFile);
let dockerInternalNetworkPromise = null;
const COMPRESSIBLE_EXTENSIONS = new Set(['.html', '.htm', '.css', '.js', '.mjs', '.json', '.svg', '.xml', '.txt', '.csv', '.map', '.wasm']);
const INTERNAL_EDGE_TOKEN = crypto.randomBytes(32).toString('base64url');
const REQUEST_IDENTITY = Symbol('shamRequestIdentity');


function appendTail(current, chunk, limit = 64 * 1024) {
  const combined = current + chunk;
  return combined.length > limit ? combined.slice(-limit) : combined;
}

function cacheEntryBytes(entry) {
  let total = Number(entry?.bytes || 0);
  for (const value of Object.values(entry?.encoded || {})) {
    if (Buffer.isBuffer(value)) total += value.length;
  }
  return total;
}

function responseChunkBytes(chunk, encoding) {
  if (chunk === undefined || chunk === null || typeof chunk === 'function') return 0;
  if (typeof chunk === 'string') return Buffer.byteLength(chunk, typeof encoding === 'string' ? encoding : undefined);
  if (Buffer.isBuffer(chunk) || ArrayBuffer.isView(chunk)) return chunk.byteLength;
  return 0;
}

function processOptions(options = {}) {
  return { ...options, detached: process.platform !== 'win32' };
}

function terminateChild(child, signal = 'SIGTERM') {
  if (!child || child.exitCode !== null || child.signalCode !== null) return;
  try {
    if (process.platform !== 'win32' && child.pid) process.kill(-child.pid, signal);
    else child.kill(signal);
  } catch {
    try { child.kill(signal); } catch { /* The process already stopped. */ }
  }
}

async function ensureDockerInternalNetwork() {
  if (dockerInternalNetworkPromise) return dockerInternalNetworkPromise;
  dockerInternalNetworkPromise = getRuntimeClient().ensureNetwork({ name: DOCKER_INTERNAL_NETWORK, internal: true })
    .then(() => DOCKER_INTERNAL_NETWORK)
    .catch((error) => { dockerInternalNetworkPromise = null; throw error; });
  return dockerInternalNetworkPromise;
}

function terminateAndWait(child, graceMs = 2000) {
  if (!child || child.exitCode !== null || child.signalCode !== null) return Promise.resolve();
  return new Promise((resolve) => {
    let settled = false;
    const finish = () => {
      if (settled) return;
      settled = true;
      clearTimeout(forceTimer);
      clearTimeout(fallbackTimer);
      resolve();
    };
    child.once('exit', finish);
    const forceTimer = setTimeout(() => terminateChild(child, 'SIGKILL'), graceMs);
    forceTimer.unref?.();
    const fallbackTimer = setTimeout(finish, graceMs + 3000);
    fallbackTimer.unref?.();
    terminateChild(child, 'SIGTERM');
  });
}

function realFileInside(root, absolute) {
  try {
    const rootReal = fs.realpathSync(root);
    const targetReal = fs.realpathSync(absolute);
    return targetReal.startsWith(`${rootReal}${path.sep}`) && fs.statSync(targetReal).isFile();
  } catch {
    return false;
  }
}

async function realFileInsideAsync(root, absolute) {
  try {
    const [rootReal, targetReal] = await Promise.all([
      fs.promises.realpath(root),
      fs.promises.realpath(absolute)
    ]);
    const stat = await fs.promises.stat(targetReal);
    return targetReal.startsWith(`${rootReal}${path.sep}`) && stat.isFile();
  } catch {
    return false;
  }
}


function hostForUrl(host) {
  return net.isIP(host) === 6 ? `[${host}]` : host;
}

function normalizeIp(value) {
  let ip = String(value || '').trim().split(',')[0].trim();
  if (ip.startsWith('::ffff:') && net.isIP(ip.slice(7)) === 4) ip = ip.slice(7);
  const zone = ip.indexOf('%');
  if (zone !== -1) ip = ip.slice(0, zone);
  return net.isIP(ip) ? ip : 'unknown';
}

function requestHostname(req) {
  const raw = String(req.headers.host || '').trim().toLowerCase();
  if (!raw) return '';
  if (raw.startsWith('[')) {
    const end = raw.indexOf(']');
    return end === -1 ? raw : raw.slice(1, end);
  }
  return raw.replace(/:\d+$/, '').replace(/\.$/, '');
}

const TRUSTED_EDGE_RANGES = [
  '103.21.244.0/22', '103.22.200.0/22', '103.31.4.0/22', '104.16.0.0/13', '104.24.0.0/14',
  '108.162.192.0/18', '131.0.72.0/22', '141.101.64.0/18', '162.158.0.0/15', '172.64.0.0/13',
  '173.245.48.0/20', '188.114.96.0/20', '190.93.240.0/20', '197.234.240.0/22', '198.41.128.0/17',
  '2400:cb00::/32', '2606:4700::/32', '2803:f800::/32', '2405:b500::/32', '2405:8100::/32',
  '2a06:98c0::/29', '2c0f:f248::/32',
  ...TRUSTED_EDGE_PROXIES
];
const trustedEdgePeers = buildIpBlockList(TRUSTED_EDGE_RANGES);

function trustedEdgePeer(ip) {
  const version = net.isIP(ip);
  return Boolean(version && trustedEdgePeers.check(ip, version === 6 ? 'ipv6' : 'ipv4'));
}

function requestIdentity(site, req) {
  if (req[REQUEST_IDENTITY]) return req[REQUEST_IDENTITY];
  const peerIp = normalizeIp(req.socket?.remoteAddress);
  const suppliedEdgeToken = String(req.headers['x-sham-edge-token'] || '');
  const trustedInternalEdge = suppliedEdgeToken.length === INTERNAL_EDGE_TOKEN.length
    && crypto.timingSafeEqual(Buffer.from(suppliedEdgeToken), Buffer.from(INTERNAL_EDGE_TOKEN));
  const trustCloudflare = !trustedInternalEdge && site.cloudflare_enabled && trustedEdgePeer(peerIp);
  const forwardedIp = trustedInternalEdge ? normalizeIp(req.headers['x-sham-client-ip']) : 'unknown';
  const cloudflareIp = trustCloudflare ? normalizeIp(req.headers['cf-connecting-ip']) : 'unknown';
  const ip = forwardedIp !== 'unknown' ? forwardedIp : cloudflareIp !== 'unknown' ? cloudflareIp : peerIp;
  const rawCountry = trustedInternalEdge
    ? String(req.headers['x-sham-client-country'] || '').trim().toUpperCase()
    : trustCloudflare ? String(req.headers['cf-ipcountry'] || '').trim().toUpperCase() : '';
  const country = /^(?:[A-Z]{2}|T1)$/.test(rawCountry) ? rawCountry : 'ZZ';
  delete req.headers['x-sham-edge-token'];
  delete req.headers['x-sham-client-ip'];
  delete req.headers['x-sham-client-country'];
  const client = classifyClient(req.headers['user-agent']);
  req[REQUEST_IDENTITY] = { ip, country, clientType: client.type, userAgent: client.userAgent };
  return req[REQUEST_IDENTITY];
}

function buildIpBlockList(entries = []) {
  const list = new net.BlockList();
  for (const entry of entries) {
    const [ip, prefixRaw] = String(entry).split('/');
    const version = net.isIP(ip);
    if (!version) continue;
    const type = version === 6 ? 'ipv6' : 'ipv4';
    if (prefixRaw === undefined) list.addAddress(ip, type);
    else list.addSubnet(ip, Number(prefixRaw), type);
  }
  return list;
}

function ipMatchesList(ip, entries = []) {
  const version = net.isIP(ip);
  if (!version || !entries.length) return false;
  return buildIpBlockList(entries).check(ip, version === 6 ? 'ipv6' : 'ipv4');
}

function hydrateSite(row) {
  if (!row) return null;
  let headers = {};
  let firewall = {};
  let redirects = [];
  let errorPages = {};
  let cacheRules = [];
  try { headers = JSON.parse(row.headers_json || '{}'); } catch { headers = {}; }
  try { firewall = JSON.parse(row.firewall_json || '{}'); } catch { firewall = {}; }
  try { redirects = JSON.parse(row.redirects_json || '[]'); } catch { redirects = []; }
  try { errorPages = JSON.parse(row.error_pages_json || '{}'); } catch { errorPages = {}; }
  try { cacheRules = JSON.parse(row.cache_rules_json || '[]'); } catch { cacheRules = []; }
  return {
    ...row,
    enabled: Boolean(row.enabled),
    spa_fallback: Boolean(row.spa_fallback),
    install_dependencies: Boolean(row.install_dependencies),
    minify: Boolean(row.minify),
    obfuscate: Boolean(row.obfuscate),
    obfuscation_risk_acknowledged: Boolean(row.obfuscation_risk_acknowledged),
    domain_only: Boolean(row.domain_only),
    ssl_enabled: Boolean(row.ssl_enabled),
    cloudflare_enabled: Boolean(row.cloudflare_enabled),
    firewall_enabled: Boolean(row.firewall_enabled),
    compression: row.compression === undefined ? true : Boolean(row.compression),
    edge_enabled: Boolean(row.edge_enabled),
    runtime_isolation: row.runtime_isolation || 'process',
    outbound_network: row.outbound_network === undefined ? true : Boolean(row.outbound_network),
    anubis_enabled: Boolean(row.anubis_enabled),
    maintenance_enabled: Boolean(row.maintenance_enabled),
    release_mode: Boolean(row.release_mode),
    active_release_directory: row.active_release_directory || '',
    runtime_preset: row.runtime_preset || (row.runtime_type === 'node' ? 'node' : row.runtime_type === 'container' ? row.container_mode || 'image' : ''),
    start_command: row.start_command || '',
    runtime_port_env: row.runtime_port_env || 'PORT',
    working_directory: row.working_directory || '',
    readiness_type: row.readiness_type || 'tcp',
    readiness_path: row.readiness_path || '/',
    readiness_command: row.readiness_command || '',
    readiness_status_min: Number(row.readiness_status_min || 200),
    readiness_status_max: Number(row.readiness_status_max || 399),
    startup_timeout_seconds: Number(row.startup_timeout_seconds || 30),
    shutdown_grace_seconds: Number(row.shutdown_grace_seconds ?? 10),
    blue_green_drain_seconds: Number(row.blue_green_drain_seconds ?? 5),
    manifest_enabled: row.manifest_enabled === undefined ? true : Boolean(row.manifest_enabled),
    cloudflare_auto_sync: Boolean(row.cloudflare_auto_sync),
    container_mode: row.container_mode || 'image',
    container_port: Number(row.container_port || 3000),
    dockerfile_path: row.dockerfile_path || 'Dockerfile',
    compose_file: row.compose_file || 'compose.yaml',
    compose_service: row.compose_service || 'app',
    buildpack_builder: row.buildpack_builder || '',
    runtime_manifest_hash: row.runtime_manifest_hash || '',
    runtime_manifest_approved_hash: row.runtime_manifest_approved_hash || '',
    health_check_type: row.health_check_type || 'http',
    health_check_command: row.health_check_command || '',
    health_check_status_min: Number(row.health_check_status_min || 200),
    health_check_status_max: Number(row.health_check_status_max || 499),
    proxy_target: row.proxy_target || '',
    proxy_host_header: row.proxy_host_header || '',
    proxy_timeout_ms: Number(row.proxy_timeout_ms || 30000),
    pinned: Boolean(row.pinned),
    install_command: row.install_command || '',
    build_command: row.build_command || '',
    build_output_dir: row.build_output_dir || '',
    cpu_limit: Number(row.cpu_limit || 0),
    pids_limit: Number(row.pids_limit || 128),
    anubis_difficulty: Number(row.anubis_difficulty || 4),
    redirects: Array.isArray(redirects) ? redirects : [],
    errorPages: errorPages && typeof errorPages === 'object' && !Array.isArray(errorPages) ? errorPages : {},
    cacheRules: Array.isArray(cacheRules) ? cacheRules : [],
    health_check_interval: Number(row.health_check_interval || 30),
    max_restarts: Number(row.max_restarts || 5),
    memory_limit_mb: Number(row.memory_limit_mb || 0),
    max_connections: Number(row.max_connections || 0),
    headers,
    firewall: {
      mode: firewall.mode || 'local',
      cloudflareAction: firewall.cloudflareAction || 'managed_challenge',
      rateLimitPerMinute: Number(firewall.rateLimitPerMinute || 0),
      maxBodyKb: Number(firewall.maxBodyKb || 0),
      blockedIps: Array.isArray(firewall.blockedIps) ? firewall.blockedIps : [],
      allowedIps: Array.isArray(firewall.allowedIps) ? firewall.allowedIps : [],
      blockedCountries: Array.isArray(firewall.blockedCountries) ? firewall.blockedCountries : [],
      allowedCountries: Array.isArray(firewall.allowedCountries) ? firewall.allowedCountries : [],
      blockBots: Boolean(firewall.blockBots)
    }
  };
}

function listen(server, port, host) {
  return new Promise((resolve, reject) => {
    const onError = (error) => {
      server.off('listening', onListening);
      reject(error);
    };
    const onListening = () => {
      server.off('error', onError);
      resolve();
    };
    server.once('error', onError);
    server.once('listening', onListening);
    server.listen(port, host);
  });
}

function closeServer(server) {
  return new Promise((resolve) => {
    if (!server?.listening) return resolve();
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
    forceTimer = setTimeout(() => {
      server.closeAllConnections?.();
      fallbackTimer = setTimeout(finish, 1500);
      fallbackTimer.unref?.();
    }, 3000);
    forceTimer.unref?.();
    try {
      server.close(finish);
      server.closeIdleConnections?.();
    } catch {
      finish();
    }
  });
}

function freePort() {
  return new Promise((resolve, reject) => {
    const server = net.createServer();
    server.unref();
    server.once('error', reject);
    server.listen(0, '127.0.0.1', () => {
      const port = server.address().port;
      server.close(() => resolve(port));
    });
  });
}

function waitForPort(port, child, timeoutMs, host = '127.0.0.1') {
  const started = Date.now();
  return new Promise((resolve, reject) => {
    let settled = false;
    const onChildError = (error) => finish(reject, new Error(`Node process could not start: ${error.message}`));
    const finish = (callback, value) => {
      if (settled) return;
      settled = true;
      child.off('error', onChildError);
      callback(value);
    };
    child.once('error', onChildError);
    const attempt = () => {
      if (settled) return;
      if (child.exitCode !== null || child.signalCode !== null) {
        const detail = child.exitCode !== null ? `code ${child.exitCode}` : `signal ${child.signalCode}`;
        return finish(reject, new Error(`Node process exited with ${detail} before opening its port.`));
      }
      const socket = net.connect({ host, port });
      socket.setTimeout(500);
      socket.once('connect', () => {
        socket.removeAllListeners();
        socket.destroy();
        finish(resolve);
      });
      const retry = () => {
        socket.removeAllListeners();
        socket.destroy();
        if (settled) return;
        if (Date.now() - started >= timeoutMs) {
          finish(reject, new Error(`Node server did not listen on PORT=${port} within ${Math.round(timeoutMs / 1000)} seconds.`));
        } else {
          setTimeout(attempt, 250).unref?.();
        }
      };
      socket.once('error', retry);
      socket.once('timeout', retry);
    };
    attempt();
  });
}


function siteIsolation(site) {
  return site?.runtime_isolation === 'docker' ? 'docker' : 'process';
}

function dockerContainerName(siteId) { return `sham-site-${Number(siteId)}`; }


module.exports = {
  fs, path, crypto, http, https, net, spawn, execFile, Worker, zlib, promisify, express, httpProxy,
  SITES_DIR, NODE_START_TIMEOUT_MS, NPM_INSTALL_TIMEOUT_MS, NPM_INSTALL_WORKERS, NPM_INSTALL_QUEUE_LIMIT, HTTP_REQUEST_TIMEOUT_MS,
  STATS_FLUSH_INTERVAL_MS, VISITOR_RETENTION_DAYS, MINIFY_MAX_BYTES, MINIFY_CACHE_BYTES, MINIFY_WORKERS, MINIFY_QUEUE_LIMIT,
  COMPRESSION_WORKERS, COMPRESSION_QUEUE_LIMIT, VISITOR_PENDING_BUCKETS, FIREWALL_RATE_LIMIT_BUCKETS, TRUSTED_EDGE_PROXIES,
  DOCKER_BIN, DOCKER_INTERNAL_NETWORK, DOCKER_EGRESS_NETWORK, SITE_DATA_DIR, JWT_SECRET, safeRelativePath, certbotPaths, hasCertificate,
  runtimeEnvironment, buildEnvironment, operatorEnvironment, classifyClient, gzipAsync, brotliAsync, execFileAsync, COMPRESSIBLE_EXTENSIONS,
  INTERNAL_EDGE_TOKEN, REQUEST_IDENTITY, appendTail, cacheEntryBytes, responseChunkBytes, processOptions, terminateChild,
  ensureDockerInternalNetwork, terminateAndWait, realFileInside, realFileInsideAsync, hostForUrl, normalizeIp, requestHostname,
  TRUSTED_EDGE_RANGES, trustedEdgePeers, trustedEdgePeer, requestIdentity, buildIpBlockList, ipMatchesList, hydrateSite, listen, closeServer,
  freePort, waitForPort, siteIsolation, dockerContainerName, siteRoot, legacySiteRoot, dockerHostDataPath
};
