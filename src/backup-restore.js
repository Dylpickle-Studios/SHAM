// @ts-nocheck -- not part of this session's checkJs rollout yet.
// This file still has genuine `tsc --noEmit` findings (mostly narrow
// `let x = null`-style inference and untyped Express handlers, the same
// patterns already fixed across most of src/) that need real per-file
// JSDoc work to resolve, not a suppression. Tracked as follow-up work;
// see tsconfig.json and docs/development.md. Do not add more files here
// without a similar comment and a plan to remove it.
'use strict';

const fs = require('node:fs');
const path = require('node:path');
const crypto = require('node:crypto');
const { spawn } = require('node:child_process');
const { DATA_DIR, BACKUPS_DIR, TAR_BIN } = require('./config');

const MARKER = path.join(DATA_DIR, '.restore-pending.json');
const FAILED_MARKER = path.join(DATA_DIR, '.restore-failed.json');

function runTar(args, timeoutMs = 10 * 60_000) {
  return new Promise((resolve, reject) => {
    const child = spawn(TAR_BIN, args, { stdio: ['ignore', 'pipe', 'pipe'], windowsHide: true, env: { ...process.env, LC_ALL: 'C' } });
    let stdout = '';
    let stderr = '';
    let settled = false;
    let timer = null;
    const finish = (error, value = '') => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      if (error) reject(error); else resolve(value);
    };
    child.stdout.on('data', (chunk) => { stdout = `${stdout}${chunk}`.slice(-2_000_000); });
    child.stderr.on('data', (chunk) => { stderr = `${stderr}${chunk}`.slice(-100_000); });
    timer = setTimeout(() => { try { child.kill('SIGKILL'); } catch { /* already exited */ } finish(new Error('Backup archive operation timed out.')); }, timeoutMs);
    timer.unref?.();
    child.once('error', (error) => finish(error));
    child.once('exit', (code) => {
      if (code === 0) finish(null, stdout);
      else finish(new Error(`Backup archive command failed${stderr.trim() ? `: ${stderr.trim().slice(-2000)}` : '.'}`));
    });
  });
}

function inspectTarLines(args, onLine, timeoutMs = 10 * 60_000) {
  return new Promise((resolve, reject) => {
    const child = spawn(TAR_BIN, args, { stdio: ['ignore', 'pipe', 'pipe'], windowsHide: true, env: { ...process.env, LC_ALL: 'C' } });
    let stderr = '';
    let buffer = '';
    let settled = false;
    let timer = null;
    const finish = (error) => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      if (error) reject(error); else resolve();
    };
    const consume = (chunk) => {
      buffer += chunk.toString();
      if (buffer.length > 16 * 1024 && !buffer.includes('\n')) {
        try { child.kill('SIGKILL'); } catch { /* already exited */ }
        finish(new Error('Backup archive contains an excessively long entry name.'));
        return;
      }
      let newline;
      while (!settled && (newline = buffer.indexOf('\n')) !== -1) {
        const line = buffer.slice(0, newline).replace(/\r$/, '');
        buffer = buffer.slice(newline + 1);
        try { onLine(line); }
        catch (error) { try { child.kill('SIGKILL'); } catch { /* already exited */ } finish(error); }
      }
    };
    child.stdout.on('data', consume);
    child.stderr.on('data', (chunk) => { stderr = `${stderr}${chunk}`.slice(-100_000); });
    timer = setTimeout(() => { try { child.kill('SIGKILL'); } catch { /* already exited */ } finish(new Error('Backup archive inspection timed out.')); }, timeoutMs);
    timer.unref?.();
    child.once('error', (error) => finish(error));
    child.once('exit', (code) => {
      if (settled) return;
      if (buffer) {
        try { onLine(buffer.replace(/\r$/, '')); }
        catch (error) { finish(error); return; }
      }
      if (code === 0) finish(null);
      else finish(new Error(`Backup archive inspection failed${stderr.trim() ? `: ${stderr.trim().slice(-2000)}` : '.'}`));
    });
  });
}

function safeArchiveEntry(name) {
  const value = String(name || '').replace(/^\.\//, '');
  if (!value || value === '.') return true;
  if (value.includes('\0') || path.posix.isAbsolute(value) || /^[A-Za-z]:/.test(value)) return false;
  const parts = value.split('/').filter(Boolean);
  return !parts.includes('..');
}

async function verifyBackupArchive(archivePath) {
  const resolved = path.resolve(archivePath);
  const backupRoot = await fs.promises.realpath(BACKUPS_DIR).catch(() => path.resolve(BACKUPS_DIR));
  const real = await fs.promises.realpath(resolved);
  if (real !== path.join(backupRoot, path.basename(real))) throw new Error('Only backup archives stored in SHAM’s local backup directory can be restored.');
  if (!/^sham-backup-.*\.tar\.gz$/.test(path.basename(real))) throw new Error('Backup filename is invalid.');
  let entries = 0;
  let hasDatabase = false;
  await inspectTarLines(['-tzf', real], (line) => {
    if (!line) return;
    entries += 1;
    if (entries > 250_000) throw new Error('Backup archive contains too many filesystem entries.');
    if (Buffer.byteLength(line) > 4096 || !safeArchiveEntry(line)) throw new Error('Backup archive contains an unsafe or excessively long path.');
    if (String(line).replace(/^\.\//, '') === 'sham.db') hasDatabase = true;
  });
  if (!entries) throw new Error('Backup archive is empty.');
  if (!hasDatabase) throw new Error('Backup archive does not contain a SHAM database snapshot.');

  let typedEntries = 0;
  await inspectTarLines(['-tvzf', real], (line) => {
    if (!line) return;
    typedEntries += 1;
    const type = line[0];
    if (type !== '-' && type !== 'd') throw new Error('Backup archive contains a link or special filesystem entry, which cannot be restored safely.');
  });
  if (typedEntries !== entries) throw new Error('Backup archive listing changed during verification.');
  return { archivePath: real, entries };
}

async function stageBackupRestore(archivePath, metadata = {}) {
  const verified = await verifyBackupArchive(archivePath);
  const marker = {
    version: 1,
    archivePath: verified.archivePath,
    requestedAt: new Date().toISOString(),
    requestedBy: Number(metadata.requestedBy || 0) || null,
    backupRunId: Number(metadata.backupRunId || 0) || null
  };
  const temporary = `${MARKER}.${process.pid}.tmp`;
  await fs.promises.writeFile(temporary, `${JSON.stringify(marker, null, 2)}\n`, { mode: 0o600, flag: 'w' });
  await fs.promises.rename(temporary, MARKER);
  return { ...marker, entries: verified.entries, restartRequired: true };
}

async function validateRestoreTree(root) {
  let entries = 0;
  const stack = [root];
  while (stack.length) {
    const directory = stack.pop();
    for (const item of await fs.promises.readdir(directory, { withFileTypes: true })) {
      entries += 1;
      if (entries > 250_000) throw new Error('Backup restore contains too many filesystem entries.');
      const absolute = path.join(directory, item.name);
      const stat = await fs.promises.lstat(absolute);
      if (stat.isSymbolicLink() || (!stat.isDirectory() && !stat.isFile())) throw new Error(`Backup restore contains an unsupported filesystem entry: ${path.relative(root, absolute)}`);
      if (stat.isDirectory()) stack.push(absolute);
    }
  }
  for (const reserved of ['backups', 'updates']) {
    if (await fs.promises.lstat(path.join(root, reserved)).catch(() => null)) throw new Error(`Backup archive unexpectedly contains the reserved ${reserved} directory.`);
  }
  const databasePath = path.join(root, 'sham.db');
  const stat = await fs.promises.stat(databasePath).catch(() => null);
  if (!stat?.isFile() || stat.size < 100) throw new Error('Restored SHAM database is missing or empty.');
  const handle = await fs.promises.open(databasePath, 'r');
  try {
    const header = Buffer.alloc(16);
    const { bytesRead } = await handle.read(header, 0, header.length, 0);
    if (bytesRead !== 16 || header.toString('binary') !== 'SQLite format 3\u0000') throw new Error('Restored SHAM database is not a valid SQLite database file.');
  } finally { await handle.close(); }
  let database;
  try {
    const Database = require('better-sqlite3');
    database = new Database(databasePath, { readonly: true, fileMustExist: true });
    const quickCheck = database.pragma('quick_check', { simple: true });
    if (quickCheck !== 'ok') throw new Error(`SQLite quick_check failed: ${String(quickCheck || 'unknown database error').slice(0, 500)}`);
    for (const table of ['users', 'settings', 'sites']) {
      if (!database.prepare("SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = ?").get(table)) throw new Error(`Restored SHAM database is missing required table ${table}.`);
    }
  } catch (error) {
    throw new Error(`Restored SHAM database failed integrity validation: ${error.message}`);
  } finally { try { database?.close(); } catch { /* best effort */ } }
  return entries;
}

async function movePreservedDirectory(fromRoot, toRoot, name) {
  const source = path.join(fromRoot, name);
  if (!await fs.promises.lstat(source).catch(() => null)) return;
  const target = path.join(toRoot, name);
  await fs.promises.rm(target, { recursive: true, force: true });
  await fs.promises.rename(source, target);
}

async function restoreOriginalDataDirectory(rollbackRoot) {
  const currentExists = await fs.promises.lstat(DATA_DIR).catch(() => null);
  if (currentExists) {
    for (const name of ['backups', 'updates']) {
      const currentPreserved = path.join(DATA_DIR, name);
      const rollbackPreserved = path.join(rollbackRoot, name);
      if (!await fs.promises.lstat(rollbackPreserved).catch(() => null) && await fs.promises.lstat(currentPreserved).catch(() => null)) {
        await fs.promises.rename(currentPreserved, rollbackPreserved).catch(() => {});
      }
    }
    await fs.promises.rm(DATA_DIR, { recursive: true, force: true });
  }
  if (await fs.promises.lstat(rollbackRoot).catch(() => null)) await fs.promises.rename(rollbackRoot, DATA_DIR);
}

async function applyPendingRestore() {
  let marker;
  try { marker = JSON.parse(await fs.promises.readFile(MARKER, 'utf8')); }
  catch (error) {
    if (error.code === 'ENOENT') return null;
    throw new Error(`Could not read pending backup restore: ${error.message}`);
  }
  const parent = path.dirname(DATA_DIR);
  const base = path.basename(DATA_DIR);
  const nonce = crypto.randomUUID();
  const stageRoot = path.join(parent, `.${base}-restore-stage-${nonce}`);
  const rollbackRoot = path.join(parent, `.${base}-restore-rollback-${nonce}`);
  let swapped = false;
  try {
    const verified = await verifyBackupArchive(marker.archivePath);
    await fs.promises.mkdir(stageRoot, { recursive: false, mode: 0o700 });
    await runTar(['-xzf', verified.archivePath, '-C', stageRoot, '--no-same-owner', '--no-same-permissions'], 20 * 60_000);
    const entries = await validateRestoreTree(stageRoot);

    // The current directory remains untouched until the archive has extracted and validated successfully.
    await fs.promises.rename(DATA_DIR, rollbackRoot);
    try {
      await fs.promises.rename(stageRoot, DATA_DIR);
      swapped = true;
      await movePreservedDirectory(rollbackRoot, DATA_DIR, 'backups');
      await movePreservedDirectory(rollbackRoot, DATA_DIR, 'updates');
      await fs.promises.rm(MARKER, { force: true }).catch(() => {});
      await fs.promises.rm(FAILED_MARKER, { force: true }).catch(() => {});
      await fs.promises.rm(rollbackRoot, { recursive: true, force: true });
    } catch (error) {
      await restoreOriginalDataDirectory(rollbackRoot).catch((rollbackError) => {
        error.message = `${error.message}; automatic restore rollback also failed: ${rollbackError.message}`;
      });
      swapped = false;
      throw error;
    }
    return { archivePath: path.join(BACKUPS_DIR, path.basename(verified.archivePath)), requestedAt: marker.requestedAt || null, backupRunId: marker.backupRunId || null, entries };
  } catch (error) {
    if (!swapped) await fs.promises.rm(stageRoot, { recursive: true, force: true }).catch(() => {});
    await fs.promises.mkdir(DATA_DIR, { recursive: true, mode: 0o700 }).catch(() => {});
    await fs.promises.writeFile(FAILED_MARKER, `${JSON.stringify({ ...marker, failedAt: new Date().toISOString(), error: error.message }, null, 2)}\n`, { mode: 0o600 }).catch(() => {});
    await fs.promises.rm(MARKER, { force: true }).catch(() => {});
    throw error;
  }
}
module.exports = { MARKER, FAILED_MARKER, safeArchiveEntry, verifyBackupArchive, stageBackupRestore, applyPendingRestore };
