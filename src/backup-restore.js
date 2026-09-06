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
const tar = require('tar');
const { DATA_DIR, BACKUPS_DIR } = require('./config');

const MARKER = path.join(DATA_DIR, '.restore-pending.json');
const FAILED_MARKER = path.join(DATA_DIR, '.restore-failed.json');
const WORK_ROOT = path.join(DATA_DIR, '.restore-work');
const JOURNAL = path.join(WORK_ROOT, 'journal.json');
const PRESERVED = new Set(['backups', 'updates', 'runtime-agent', '.restore-work', '.restore-pending.json', '.restore-failed.json']);

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
  const members = new Map();
  let invalid = '';
  // Read structured headers, including GNU/PAX long names, without parsing tar's human output.
  await tar.t({ file: real, strict: true, onReadEntry(entry) {
    if (invalid) return;
    const name = path.posix.normalize(entry.path).replace(/\/$/, '');
    if (!safeArchiveEntry(entry.path) || Buffer.byteLength(entry.path) > 4096 || entry.path.includes('\\')) { invalid = 'Backup archive contains an unsafe or excessively long path.'; return; }
    if (!['File', 'OldFile', 'Directory', 'SymbolicLink', 'Link'].includes(entry.type)) { invalid = 'Backup archive contains a special filesystem entry.'; return; }
    if (!name || name === '.') return;
    if (members.has(name)) { invalid = `Backup archive repeats path ${name}.`; return; }
    if (members.size >= 250_000) { invalid = 'Backup archive contains too many filesystem entries.'; return; }
    members.set(name, { type: entry.type, linkpath: entry.linkpath });
  } });
  if (invalid) throw new Error(invalid);
  if (!['File', 'OldFile'].includes(members.get('sham.db')?.type)) throw new Error('Backup archive does not contain a regular SHAM database snapshot.');
  const links = new Map();
  for (const [name, entry] of members) {
    if (!['SymbolicLink', 'Link'].includes(entry.type)) continue;
    const target = String(entry.linkpath || '');
    if (!target || target.includes('\\') || target.includes('\0') || path.posix.isAbsolute(target) || /^[A-Za-z]:/.test(target)) throw new Error(`Backup link ${name} has an unsafe target.`);
    links.set(name, entry);
  }
  const resolveLink = (name, visited = new Set()) => {
    if (visited.has(name) || visited.size >= 40) throw new Error('Backup archive contains a cyclic or excessively deep link.');
    const seen = new Set(visited).add(name);
    const entry = links.get(name);
    const resolved = entry.type === 'Link' ? [] : name.split('/').slice(0, -1);
    for (const segment of entry.linkpath.split('/')) {
      if (!segment || segment === '.') continue;
      if (segment === '..') {
        if (!resolved.length) throw new Error(`Backup link ${name} escapes the archive.`);
        resolved.pop();
      } else {
        resolved.push(segment);
        const prefix = resolved.join('/');
        if (links.has(prefix)) resolved.splice(0, resolved.length, ...resolveLink(prefix, seen));
      }
    }
    return resolved;
  };
  for (const [name, entry] of members) {
    const parts = name.split('/');
    for (let index = 1; index < parts.length; index += 1) {
      if (links.has(parts.slice(0, index).join('/'))) throw new Error('Backup archive cannot write through a link.');
    }
    if (!links.has(name)) continue;
    const target = resolveLink(name).join('/');
    if (entry.type === 'Link' && !['File', 'OldFile'].includes(members.get(target)?.type)) throw new Error('Backup hard links must reference a regular archive file.');
  }
  return { archivePath: real, entries: members.size };

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
      if (!stat.isSymbolicLink() && !stat.isDirectory() && !stat.isFile()) throw new Error(`Backup restore contains an unsupported filesystem entry: ${path.relative(root, absolute)}`);
      if (stat.isDirectory()) stack.push(absolute);
    }
  }
  for (const reserved of PRESERVED) {
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

async function writeJournal(value) {
  const temporary = `${JOURNAL}.tmp`;
  const handle = await fs.promises.open(temporary, 'w', 0o600);
  try { await handle.writeFile(`${JSON.stringify(value)}\n`); await handle.sync(); }
  finally { await handle.close(); }
  await fs.promises.rename(temporary, JOURNAL);
}

async function recoverInterruptedRestore() {
  let journal;
  try { journal = JSON.parse(await fs.promises.readFile(JOURNAL, 'utf8')); }
  catch (error) { if (error.code === 'ENOENT') return; throw error; }
  if (!['moving', 'installing', 'committed'].includes(journal.phase) || !Array.isArray(journal.incoming) || journal.incoming.some((name) => typeof name !== 'string' || !name || name === '.' || name === '..' || name.includes('/') || name.includes('\\') || PRESERVED.has(name))) throw new Error('Restore recovery journal is invalid; preserve .restore-work for manual recovery.');
  const rollbackRoot = path.join(WORK_ROOT, 'rollback');
  if (journal.phase !== 'committed') {
    // Save progress while rolling back too: a second interruption must never delete an already restored entry.
    journal.restored ||= [];
    for (const name of journal.incoming) {
      if (journal.phase === 'installing' && !journal.restored.includes(name)) await fs.promises.rm(path.join(DATA_DIR, name), { recursive: true, force: true });
    }
    for (const name of await fs.promises.readdir(rollbackRoot).catch((error) => { if (error.code === 'ENOENT') return []; throw error; })) {
      const source = path.join(rollbackRoot, name);
      const target = path.join(DATA_DIR, name);
      // Record intent before renaming; on a retry, an extant rollback entry always wins.
      if (!journal.restored.includes(name)) { journal.restored.push(name); await writeJournal(journal); }
      await fs.promises.rm(target, { recursive: true, force: true });
      await fs.promises.rename(source, target);
    }
  }
  await fs.promises.rm(JOURNAL, { force: true });
  await fs.promises.rm(path.join(WORK_ROOT, 'stage'), { recursive: true, force: true });
  await fs.promises.rm(rollbackRoot, { recursive: true, force: true });
}

async function applyPendingRestore() {
  const pending = await fs.promises.readFile(MARKER, 'utf8').catch((error) => { if (error.code === 'ENOENT') return null; throw error; });
  const interrupted = await fs.promises.stat(JOURNAL).catch(() => null);
  if (!pending && !interrupted && !fs.existsSync(path.join(WORK_ROOT, 'agent-paused'))) return null;
  const marker = pending ? JSON.parse(pending) : {};
  await fs.promises.mkdir(WORK_ROOT, { recursive: true, mode: 0o700 });
  const { pauseRuntimeAgent, resumeRuntimeAgent } = require('./restore-coordination');
  await pauseRuntimeAgent();
  const stageRoot = path.join(WORK_ROOT, 'stage');
  const rollbackRoot = path.join(WORK_ROOT, 'rollback');
  try {
    await recoverInterruptedRestore();
    if (!pending) return null;
    const verified = await verifyBackupArchive(marker.archivePath);
    await fs.promises.rm(rollbackRoot, { recursive: true, force: true });
    await fs.promises.rm(stageRoot, { recursive: true, force: true });
    await fs.promises.mkdir(stageRoot, { mode: 0o700 });
    await tar.x({ file: verified.archivePath, cwd: stageRoot, strict: true, preservePaths: false, preserveOwner: false, chmod: true,
      filter: (name) => !PRESERVED.has(name.replace(/^\.\//, '').split('/')[0]) });
    const entries = await validateRestoreTree(stageRoot);
    await fs.promises.mkdir(rollbackRoot, { mode: 0o700 });
    const incoming = await fs.promises.readdir(stageRoot);
    const journal = { phase: 'moving', incoming, restored: [] };
    await writeJournal(journal);
    for (const name of await fs.promises.readdir(DATA_DIR)) {
      if (!PRESERVED.has(name)) await fs.promises.rename(path.join(DATA_DIR, name), path.join(rollbackRoot, name));
    }
    journal.phase = 'installing';
    await writeJournal(journal);
    for (const name of incoming) await fs.promises.rename(path.join(stageRoot, name), path.join(DATA_DIR, name));
    journal.phase = 'committed';
    await writeJournal(journal);
    await fs.promises.rm(MARKER, { force: true });
    await fs.promises.rm(FAILED_MARKER, { force: true });
    await recoverInterruptedRestore();
    return { archivePath: verified.archivePath, requestedAt: marker.requestedAt || null, backupRunId: marker.backupRunId || null, entries };
  } catch (error) {
    try { await recoverInterruptedRestore(); }
    catch (rollbackError) { throw new Error(`${error.message}; automatic restore rollback failed: ${rollbackError.message}. Preserve .restore-work and retry startup.`); }
    await fs.promises.writeFile(FAILED_MARKER, `${JSON.stringify({ ...marker, failedAt: new Date().toISOString(), error: error.message }, null, 2)}\n`, { mode: 0o600 });
    await fs.promises.rm(MARKER, { force: true });
    throw error;
  } finally {
    // Keep the agent paused if recovery still needs to finish on the next startup.
    if (!await fs.promises.stat(JOURNAL).catch(() => null)) await resumeRuntimeAgent();
  }
}
module.exports = { MARKER, FAILED_MARKER, safeArchiveEntry, verifyBackupArchive, stageBackupRestore, applyPendingRestore, recoverInterruptedRestore };
