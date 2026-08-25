// @ts-nocheck -- not part of this session's checkJs rollout yet.
// This file still has genuine `tsc --noEmit` findings (mostly narrow
// `let x = null`-style inference and untyped Express handlers, the same
// patterns already fixed across most of src/) that need real per-file
// JSDoc work to resolve, not a suppression. Tracked as follow-up work;
// see tsconfig.json and docs/development.md. Do not add more files here
// without a similar comment and a plan to remove it.
'use strict';

const { siteRoot } = require('../site-paths');

const fs = require('node:fs');
const path = require('node:path');
const os = require('node:os');
const http = require('node:http');
const net = require('node:net');
const crypto = require('node:crypto');
const { spawn } = require('node:child_process');
const express = require('express');
const httpProxy = require('http-proxy');
const {
  DATA_DIR, SITES_DIR, RELEASES_DIR, PREVIEWS_DIR, BACKUPS_DIR, SITE_DATA_DIR,
  DOCKER_BIN, GIT_BIN, TAR_BIN, RESTIC_BIN, AWS_BIN, SFTP_BIN, ANUBIS_IMAGE,
  JOB_POLL_INTERVAL_MS, JOB_TIMEOUT_MS, BACKUP_TIMEOUT_MS, GIT_TIMEOUT_MS,
  PREVIEW_TTL_HOURS, HTTP_REQUEST_TIMEOUT_MS
} = require('../config');
const { encrypt, decrypt, getSecretSetting, setSecretSetting } = require('../secret-store');
const { safeRelativePath } = require('../validation');
const { runtimeEnvironment, buildEnvironment, operatorEnvironment } = require('../process-env');

function appendTail(current, text, limit = 128 * 1024) {
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
  return { ...options, detached: process.platform !== 'win32' };
}

function terminate(child, signal = 'SIGTERM') {
  if (!child || child.exitCode !== null || child.signalCode !== null) return;
  try {
    if (process.platform !== 'win32' && child.pid) process.kill(-child.pid, signal);
    else child.kill(signal);
  } catch {
    try { child.kill(signal); } catch { /* Already exited. */ }
  }
}

function terminateAndWait(child, graceMs = 2000) {
  if (!child || child.exitCode !== null || child.signalCode !== null) return Promise.resolve();
  return new Promise((resolve) => {
    let settled = false;
    const finish = () => { if (settled) return; settled = true; clearTimeout(force); clearTimeout(fallback); resolve(); };
    child.once('exit', finish);
    const force = setTimeout(() => terminate(child, 'SIGKILL'), graceMs);
    const fallback = setTimeout(finish, graceMs + 3000);
    force.unref?.(); fallback.unref?.();
    terminate(child, 'SIGTERM');
  });
}

function runProcess(command, args, { cwd, env, timeoutMs = 60_000, onLine = () => {}, onSpawn = () => {}, stdin = null, environmentMode = 'operator' } = {}) {
  return new Promise((resolve, reject) => {
    const environment = environmentMode === 'runtime' ? runtimeEnvironment(env) : environmentMode === 'build' ? buildEnvironment(env) : operatorEnvironment(env);
    const child = spawn(command, args, processOptions({ cwd, env: environment, stdio: ['pipe', 'pipe', 'pipe'] }));
    onSpawn(child);
    let output = '';
    let settled = false;
    let timedOut = false;
    let forceTimer;
    let fallbackTimer;
    const finish = (callback, value) => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      clearTimeout(forceTimer);
      clearTimeout(fallbackTimer);
      callback(value);
    };
    const consume = (level, chunk) => {
      const text = chunk.toString();
      output = appendTail(output, text);
      for (const line of text.split(/\r?\n/).filter(Boolean)) onLine(level, line.slice(0, 2000));
    };
    child.stdout.on('data', (chunk) => consume('info', chunk));
    child.stderr.on('data', (chunk) => consume('error', chunk));
    child.once('error', (error) => finish(reject, new Error(`${command} could not start: ${error.message}`)));
    child.once('close', (code, signal) => {
      if (timedOut) finish(reject, new Error(`${command} timed out.`));
      else if (code === 0) finish(resolve, { output: output.trim(), code, signal });
      else finish(reject, new Error(`${command} exited with ${code ?? signal}. ${output.trim().slice(-1600)}`));
    });
    child.stdin.on('error', (error) => {
      if (!['EPIPE', 'ERR_STREAM_DESTROYED'].includes(error.code)) finish(reject, new Error(`${command} stdin failed: ${error.message}`));
    });
    if (stdin !== null) child.stdin.end(String(stdin)); else child.stdin.end();
    const timer = setTimeout(() => {
      timedOut = true;
      terminate(child, 'SIGTERM');
      forceTimer = setTimeout(() => {
        terminate(child, 'SIGKILL');
        fallbackTimer = setTimeout(() => finish(reject, new Error(`${command} timed out and did not exit after termination.`)), 3000);
        fallbackTimer.unref?.();
      }, 2500);
      forceTimer.unref?.();
    }, timeoutMs);
    timer.unref?.();
  });
}


function runConfiguredCommand(command, options = {}) {
  const value = String(command || '').trim();
  if (!value) return Promise.resolve({ output: '', code: 0, signal: null });
  if (process.platform === 'win32') return runProcess(process.env.ComSpec || 'cmd.exe', ['/d', '/s', '/c', value], options);
  return runProcess('/bin/sh', ['-lc', value], options);
}

function parseField(field, minimum, maximum) {
  const values = new Set();
  for (const part of String(field).split(',')) {
    const [rangeRaw, stepRaw] = part.split('/');
    const step = stepRaw === undefined ? 1 : Number(stepRaw);
    if (!Number.isInteger(step) || step < 1 || step > maximum - minimum + 1) throw new Error('Invalid cron step.');
    let start = minimum;
    let end = maximum;
    if (rangeRaw !== '*') {
      const [startRaw, endRaw] = rangeRaw.split('-');
      start = Number(startRaw);
      end = endRaw === undefined ? (stepRaw === undefined ? start : maximum) : Number(endRaw);
    }
    if (!Number.isInteger(start) || !Number.isInteger(end) || start < minimum || end > maximum || start > end) throw new Error('Invalid cron range.');
    for (let value = start; value <= end; value += step) values.add(value);
  }
  return values;
}

function parseCron(expression) {
  const parts = String(expression || '').trim().split(/\s+/);
  if (parts.length !== 5) throw new Error('Schedule must contain five cron fields: minute hour day month weekday.');
  const weekdays = parseField(parts[4], 0, 7);
  if (weekdays.delete(7)) weekdays.add(0);
  return {
    minutes: parseField(parts[0], 0, 59),
    hours: parseField(parts[1], 0, 23),
    days: parseField(parts[2], 1, 31),
    months: parseField(parts[3], 1, 12),
    weekdays,
    dayWildcard: parts[2] === '*',
    weekdayWildcard: parts[4] === '*'
  };
}

function cronScheduleMatches(schedule, date) {
  const dayMatches = schedule.days.has(date.getDate());
  const weekdayMatches = schedule.weekdays.has(date.getDay());
  const calendarMatches = schedule.dayWildcard && schedule.weekdayWildcard
    ? true
    : schedule.dayWildcard
      ? weekdayMatches
      : schedule.weekdayWildcard
        ? dayMatches
        : dayMatches || weekdayMatches;
  return schedule.minutes.has(date.getMinutes())
    && schedule.hours.has(date.getHours())
    && schedule.months.has(date.getMonth() + 1)
    && calendarMatches;
}

function cronMatches(expression, date) {
  return cronScheduleMatches(parseCron(expression), date);
}

function nextCronDate(expression, after = new Date()) {
  const schedule = parseCron(expression);
  const candidate = new Date(after.getTime());
  candidate.setSeconds(0, 0);
  candidate.setMinutes(candidate.getMinutes() + 1);
  for (let index = 0; index < 366 * 24 * 60; index += 1) {
    if (cronScheduleMatches(schedule, candidate)) return candidate;
    candidate.setMinutes(candidate.getMinutes() + 1);
  }
  throw new Error('Schedule does not produce a run within one year.');
}

function safeName(value, fallback = 'item') {
  return String(value || fallback).normalize('NFKD').replace(/[^a-zA-Z0-9._-]+/g, '-').replace(/^-+|-+$/g, '').slice(0, 100) || fallback;
}

function pathInside(base, candidate) {
  const root = path.resolve(base);
  const target = path.resolve(candidate);
  return target === root || target.startsWith(`${root}${path.sep}`);
}

function sftpQuote(value, label = 'SFTP path') {
  const text = String(value || '');
  if (!text || /[\r\n\0]/.test(text)) throw new Error(`${label} is invalid.`);
  return `"${text.replaceAll('\\', '\\\\').replaceAll('"', '\\"')}"`;
}

function freePort() {
  return new Promise((resolve, reject) => {
    const server = net.createServer();
    server.unref();
    server.once('error', reject);
    server.listen(0, '127.0.0.1', () => {
      const address = server.address();
      server.close(() => resolve(address.port));
    });
  });
}

function closeServer(server) {
  return new Promise((resolve) => {
    if (!server?.listening) return resolve();
    let settled = false;
    let timer;
    const finish = () => {
      if (settled) return;
      settled = true;
      if (timer) clearTimeout(timer);
      resolve();
    };
    server.close(finish);
    timer = setTimeout(() => { server.closeAllConnections?.(); finish(); }, 3000);
    timer.unref?.();
  });
}

function requiredFile(site) {
  if (site.runtime_type === 'proxy') return '';
  if (site.runtime_type === 'node' && !site.start_command) return site.node_entry;
  if (site.runtime_type === 'static') return site.entry_file;
  return '';
}

async function ensureRequiredFile(site, root) {
  if (site.runtime_type === 'proxy' || !requiredFile(site)) return;
  const relative = safeRelativePath(requiredFile(site), 'Required runtime file');
  const absolute = path.join(root, ...relative.split('/'));
  const rootReal = await fs.promises.realpath(root);
  const fileReal = await fs.promises.realpath(absolute).catch(() => '');
  if (!fileReal.startsWith(`${rootReal}${path.sep}`) || !(await fs.promises.stat(fileReal).catch(() => null))?.isFile()) {
    throw new Error(`Required file “${relative}” is missing from the release.`);
  }
}

function validateGitUrl(value) {
  const url = String(value || '').trim();
  if (!url || url.length > 2048 || /[\r\n\0\s]/.test(url)) throw new Error('Git repository URL is invalid.');
  if (/^git@/i.test(url)) {
    if (!/^git@(?:\[[0-9A-Fa-f:]+\]|[A-Za-z0-9.-]+):[A-Za-z0-9._~+/-]+$/.test(url)) throw new Error('The git@ repository URL is invalid.');
    return url;
  }
  if (!/^(?:https?:\/\/|ssh:\/\/)/i.test(url)) throw new Error('Git URL must use HTTPS or SSH. Local file:// repositories are not allowed.');
  let parsed;
  try { parsed = new URL(url); } catch { throw new Error('Git repository URL is invalid.'); }
  if (!parsed.hostname) throw new Error('Git repository URL must include a host.');
  if (parsed.password || (/^https?:$/i.test(parsed.protocol) && parsed.username) || parsed.search) {
    throw new Error('Git credentials must not be embedded in the repository URL, and query parameters are not allowed. Use a deploy key or connected provider credential.');
  }
  if (parsed.hash) throw new Error('Git repository URL must not include a fragment.');
  try { decodeURIComponent(parsed.pathname); }
  catch { throw new Error('Git repository URL contains invalid URL encoding.'); }
  return url;
}

function validateBranch(value) {
  const branch = String(value || 'main').trim();
  if (!branch || branch.length > 200 || branch.startsWith('-') || /[\s~^:?*[\\]/.test(branch) || branch.includes('..')) throw new Error('Git branch or tag is invalid.');
  return branch;
}


module.exports = {
  fs, path, os, http, net, crypto, spawn, express, httpProxy,
  DATA_DIR, SITES_DIR, RELEASES_DIR, PREVIEWS_DIR, BACKUPS_DIR, SITE_DATA_DIR,
  DOCKER_BIN, GIT_BIN, TAR_BIN, RESTIC_BIN, AWS_BIN, SFTP_BIN, ANUBIS_IMAGE,
  JOB_POLL_INTERVAL_MS, JOB_TIMEOUT_MS, BACKUP_TIMEOUT_MS, GIT_TIMEOUT_MS, PREVIEW_TTL_HOURS, HTTP_REQUEST_TIMEOUT_MS,
  encrypt, decrypt, getSecretSetting, setSecretSetting, safeRelativePath, runtimeEnvironment, buildEnvironment, operatorEnvironment,
  appendTail, commandAvailable, processOptions, terminate, terminateAndWait, runProcess, runConfiguredCommand, parseField, parseCron,
  cronMatches, nextCronDate, safeName, pathInside, sftpQuote, freePort, closeServer, siteRoot, requiredFile, ensureRequiredFile,
  validateGitUrl, validateBranch
};
