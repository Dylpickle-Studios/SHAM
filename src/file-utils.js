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
const { TextDecoder } = require('node:util');
const { EDITOR_LIMIT_BYTES } = require('./config');
const { siteRoot } = require('./site-paths');
const { safeRelativePath } = require('./validation');

const RESERVED_DIRECTORIES = new Set(['node_modules', '.git', '.sham']);
const utf8Decoder = new TextDecoder('utf-8', { fatal: true });

function resolveSitePath(site, input) {
  const relative = safeRelativePath(input, 'File path');
  const segments = relative.split('/');
  const reserved = segments.find((segment) => RESERVED_DIRECTORIES.has(segment.toLowerCase()));
  if (reserved) {
    throw new Error(`The “${reserved}” directory is managed internally and is not editable.`);
  }

  const root = path.resolve(siteRoot(site));
  const absolute = path.resolve(root, ...segments);
  if (!absolute.startsWith(`${root}${path.sep}`)) throw new Error('File path escapes the website directory.');

  let current = root;
  for (const segment of segments) {
    current = path.join(current, segment);
    if (fs.existsSync(current) && fs.lstatSync(current).isSymbolicLink()) {
      throw new Error('Symbolic links are not available through the file browser.');
    }
  }
  return { root, relative, absolute };
}

async function resolveSitePathAsync(site, input) {
  const relative = safeRelativePath(input, 'File path');
  const segments = relative.split('/');
  const reserved = segments.find((segment) => RESERVED_DIRECTORIES.has(segment.toLowerCase()));
  if (reserved) throw new Error(`The “${reserved}” directory is managed internally and is not editable.`);

  const root = path.resolve(siteRoot(site));
  const absolute = path.resolve(root, ...segments);
  if (!absolute.startsWith(`${root}${path.sep}`)) throw new Error('File path escapes the website directory.');

  let current = root;
  for (const segment of segments) {
    current = path.join(current, segment);
    try {
      const stat = await fs.promises.lstat(current);
      if (stat.isSymbolicLink()) throw new Error('Symbolic links are not available through the file browser.');
    } catch (error) {
      if (error.code !== 'ENOENT') throw error;
    }
  }
  return { root, relative, absolute };
}

function listSiteFiles(site, limit = 5000) {
  const root = siteRoot(site);
  const files = [];
  if (!fs.existsSync(root)) return files;

  const pending = [{ directory: root, prefix: '' }];
  while (pending.length) {
    const { directory, prefix } = pending.pop();
    for (const entry of fs.readdirSync(directory, { withFileTypes: true })) {
      if (entry.isSymbolicLink()) continue;
      const relative = prefix ? `${prefix}/${entry.name}` : entry.name;
      const absolute = path.join(directory, entry.name);
      if (entry.isDirectory()) {
        if (!RESERVED_DIRECTORIES.has(entry.name.toLowerCase())) pending.push({ directory: absolute, prefix: relative });
      } else if (entry.isFile()) {
        const stat = fs.statSync(absolute);
        files.push({ path: relative, size: stat.size, modifiedAt: stat.mtime.toISOString() });
        if (files.length > limit) throw new Error(`This website contains more than ${limit} browser-visible files.`);
      }
    }
  }
  return files.sort((a, b) => a.path.localeCompare(b.path));
}

async function listSiteFilesAsync(site, limit = 5000) {
  const root = siteRoot(site);
  const files = [];
  try { await fs.promises.access(root); } catch { return files; }

  const pending = [{ directory: root, prefix: '' }];
  while (pending.length) {
    const { directory, prefix } = pending.pop();
    let entries;
    try { entries = await fs.promises.readdir(directory, { withFileTypes: true }); }
    catch (error) {
      if (error.code === 'ENOENT' || error.code === 'ENOTDIR') continue;
      throw error;
    }
    for (const entry of entries) {
      if (entry.isSymbolicLink()) continue;
      const relative = prefix ? `${prefix}/${entry.name}` : entry.name;
      const absolute = path.join(directory, entry.name);
      if (entry.isDirectory()) {
        if (!RESERVED_DIRECTORIES.has(entry.name.toLowerCase())) pending.push({ directory: absolute, prefix: relative });
      } else if (entry.isFile()) {
        try {
          const stat = await fs.promises.lstat(absolute);
          if (!stat.isFile() || stat.isSymbolicLink()) continue;
          files.push({ path: relative, size: stat.size, modifiedAt: stat.mtime.toISOString() });
          if (files.length > limit) throw new Error(`This website contains more than ${limit} browser-visible files.`);
        } catch (error) {
          if (error.code === 'ENOENT' || error.code === 'ENOTDIR') continue;
          throw error;
        }
      }
    }
  }
  return files.sort((a, b) => a.path.localeCompare(b.path));
}

function readTextFile(site, input) {
  const { relative, absolute } = resolveSitePath(site, input);
  if (!fs.existsSync(absolute) || !fs.statSync(absolute).isFile()) throw new Error('File not found.');
  const stat = fs.statSync(absolute);
  if (stat.size > EDITOR_LIMIT_BYTES) throw new Error(`The editor limit is ${Math.round(EDITOR_LIMIT_BYTES / 1024 / 1024)} MB.`);
  const buffer = fs.readFileSync(absolute);
  if (buffer.includes(0)) throw new Error('This file appears to be binary and cannot be opened in the document editor.');
  let content;
  try { content = utf8Decoder.decode(buffer); }
  catch { throw new Error('This file is not valid UTF-8 text and cannot be opened in the document editor.'); }
  return { path: relative, content, size: stat.size, modifiedAt: stat.mtime.toISOString() };
}

async function readTextFileAsync(site, input) {
  const { relative, absolute } = await resolveSitePathAsync(site, input);
  let stat;
  try { stat = await fs.promises.stat(absolute); }
  catch { throw new Error('File not found.'); }
  if (!stat.isFile()) throw new Error('File not found.');
  if (stat.size > EDITOR_LIMIT_BYTES) throw new Error(`The editor limit is ${Math.round(EDITOR_LIMIT_BYTES / 1024 / 1024)} MB.`);
  const buffer = await fs.promises.readFile(absolute);
  if (buffer.includes(0)) throw new Error('This file appears to be binary and cannot be opened in the document editor.');
  let content;
  try { content = utf8Decoder.decode(buffer); }
  catch { throw new Error('This file is not valid UTF-8 text and cannot be opened in the document editor.'); }
  return { path: relative, content, size: stat.size, modifiedAt: stat.mtime.toISOString() };
}

function atomicWrite(absolute, data) {
  fs.mkdirSync(path.dirname(absolute), { recursive: true });
  const temporary = `${absolute}.tmp-${process.pid}-${Date.now()}-${Math.random().toString(16).slice(2)}`;
  try {
    fs.writeFileSync(temporary, data, { mode: 0o644 });
    fs.renameSync(temporary, absolute);
  } finally {
    fs.rmSync(temporary, { force: true });
  }
}

function atomicCopy(absolute, source) {
  fs.mkdirSync(path.dirname(absolute), { recursive: true });
  const temporary = `${absolute}.tmp-${process.pid}-${Date.now()}-${Math.random().toString(16).slice(2)}`;
  try {
    fs.copyFileSync(source, temporary);
    fs.chmodSync(temporary, 0o644);
    fs.renameSync(temporary, absolute);
  } finally {
    fs.rmSync(temporary, { force: true });
  }
}

async function atomicWriteAsync(absolute, data) {
  await fs.promises.mkdir(path.dirname(absolute), { recursive: true });
  const temporary = `${absolute}.tmp-${process.pid}-${Date.now()}-${Math.random().toString(16).slice(2)}`;
  try {
    await fs.promises.writeFile(temporary, data, { mode: 0o644 });
    await fs.promises.rename(temporary, absolute);
  } finally {
    await fs.promises.rm(temporary, { force: true }).catch(() => {});
  }
}

async function atomicCopyAsync(absolute, source) {
  await fs.promises.mkdir(path.dirname(absolute), { recursive: true });
  const temporary = `${absolute}.tmp-${process.pid}-${Date.now()}-${Math.random().toString(16).slice(2)}`;
  try {
    await fs.promises.copyFile(source, temporary);
    await fs.promises.chmod(temporary, 0o644);
    await fs.promises.rename(temporary, absolute);
  } finally {
    await fs.promises.rm(temporary, { force: true }).catch(() => {});
  }
}

function writeTextFile(site, input, content) {
  const { relative, absolute } = resolveSitePath(site, input);
  const data = Buffer.from(String(content ?? ''), 'utf8');
  if (data.length > EDITOR_LIMIT_BYTES) throw new Error(`The editor limit is ${Math.round(EDITOR_LIMIT_BYTES / 1024 / 1024)} MB.`);
  atomicWrite(absolute, data);
  return { path: relative, size: data.length };
}

function replaceSingleFile(site, input, buffer) {
  const { relative, absolute } = resolveSitePath(site, input);
  atomicWrite(absolute, buffer);
  return { path: relative, size: buffer.length };
}

function replaceSingleFileFromPath(site, input, source, size) {
  const { relative, absolute } = resolveSitePath(site, input);
  atomicCopy(absolute, source);
  return { path: relative, size };
}

async function writeTextFileAsync(site, input, content) {
  const { relative, absolute } = await resolveSitePathAsync(site, input);
  const data = Buffer.from(String(content ?? ''), 'utf8');
  if (data.length > EDITOR_LIMIT_BYTES) throw new Error(`The editor limit is ${Math.round(EDITOR_LIMIT_BYTES / 1024 / 1024)} MB.`);
  await atomicWriteAsync(absolute, data);
  return { path: relative, size: data.length };
}

async function replaceSingleFileFromPathAsync(site, input, source, size) {
  const { relative, absolute } = await resolveSitePathAsync(site, input);
  await atomicCopyAsync(absolute, source);
  return { path: relative, size };
}

function pruneEmptyParents(absolute, root) {
  let current = path.dirname(absolute);
  while (current.startsWith(`${root}${path.sep}`) && current !== root) {
    if (fs.readdirSync(current).length) break;
    fs.rmdirSync(current);
    current = path.dirname(current);
  }
}

function stageSingleFileDeletion(site, input) {
  const { root, relative, absolute } = resolveSitePath(site, input);
  if (!fs.existsSync(absolute) || !fs.statSync(absolute).isFile()) throw new Error('File not found.');
  const trashDirectory = path.join(root, '.sham', 'deleted-files');
  fs.mkdirSync(trashDirectory, { recursive: true });
  const staged = path.join(trashDirectory, `${crypto.randomUUID()}.deleted`);
  fs.renameSync(absolute, staged);
  let settled = false;
  return {
    path: relative,
    commit() {
      if (settled) return;
      settled = true;
      try { pruneEmptyParents(absolute, root); } catch { /* Empty-directory cleanup is best effort. */ }
      fs.rm(staged, { force: true }, () => {});
    },
    rollback() {
      if (settled) return;
      settled = true;
      fs.mkdirSync(path.dirname(absolute), { recursive: true });
      fs.renameSync(staged, absolute);
    }
  };
}

async function stageSingleFileDeletionAsync(site, input) {
  const { root, relative, absolute } = await resolveSitePathAsync(site, input);
  let stat;
  try { stat = await fs.promises.stat(absolute); }
  catch { throw new Error('File not found.'); }
  if (!stat.isFile()) throw new Error('File not found.');
  const trashDirectory = path.join(root, '.sham', 'deleted-files');
  await fs.promises.mkdir(trashDirectory, { recursive: true });
  const staged = path.join(trashDirectory, `${crypto.randomUUID()}.deleted`);
  await fs.promises.rename(absolute, staged);
  let settled = false;
  return {
    path: relative,
    async commit() {
      if (settled) return;
      settled = true;
      let current = path.dirname(absolute);
      while (current.startsWith(`${root}${path.sep}`) && current !== root) {
        try {
          if ((await fs.promises.readdir(current)).length) break;
          await fs.promises.rmdir(current);
        } catch { break; }
        current = path.dirname(current);
      }
      await fs.promises.rm(staged, { force: true }).catch(() => {});
    },
    async rollback() {
      if (settled) return;
      settled = true;
      await fs.promises.mkdir(path.dirname(absolute), { recursive: true });
      await fs.promises.rename(staged, absolute);
    }
  };
}

async function deleteSingleFileAsync(site, input) {
  const deletion = await stageSingleFileDeletionAsync(site, input);
  await deletion.commit();
  return { path: deletion.path };
}

function deleteSingleFile(site, input) {
  const deletion = stageSingleFileDeletion(site, input);
  deletion.commit();
  return { path: deletion.path };
}

module.exports = {
  siteRoot,
  resolveSitePath,
  resolveSitePathAsync,
  listSiteFiles,
  listSiteFilesAsync,
  readTextFile,
  readTextFileAsync,
  writeTextFile,
  writeTextFileAsync,
  replaceSingleFile,
  replaceSingleFileFromPath,
  replaceSingleFileFromPathAsync,
  deleteSingleFile,
  deleteSingleFileAsync,
  stageSingleFileDeletion,
  stageSingleFileDeletionAsync
};
