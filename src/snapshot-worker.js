const fs = require('node:fs');
const path = require('node:path');
const { parentPort, workerData } = require('node:worker_threads');
if (!parentPort) throw new Error('This module must run inside a worker thread.');
const AdmZip = require('adm-zip');

const EXCLUDED_DIRECTORIES = new Set(['node_modules', '.git', '.sham']);

function safeName(value) {
  const normalized = String(value || '').replaceAll('\\', '/');
  if (!normalized || normalized.startsWith('/') || /^[A-Za-z]:\//.test(normalized)) return false;
  const parts = normalized.split('/').filter(Boolean);
  return !parts.some((part) => part === '..' || part === '.');
}

function projectFiles(root) {
  const resolvedRoot = fs.realpathSync(root);
  const files = [];
  let bytes = 0;
  const visit = (directory, relativeDirectory = '') => {
    for (const entry of fs.readdirSync(directory, { withFileTypes: true })) {
      if (entry.isSymbolicLink()) throw new Error(`Snapshots do not support symbolic links: ${path.join(relativeDirectory, entry.name)}`);
      if (entry.isDirectory() && EXCLUDED_DIRECTORIES.has(entry.name)) continue;
      const relative = path.join(relativeDirectory, entry.name);
      const absolute = path.join(directory, entry.name);
      if (entry.isDirectory()) {
        visit(absolute, relative);
        continue;
      }
      if (!entry.isFile()) continue;
      if (files.length >= workerData.maxFiles) throw new Error(`Snapshot contains more than ${workerData.maxFiles} files.`);
      const flags = fs.constants.O_RDONLY | (fs.constants.O_NOFOLLOW || 0);
      const descriptor = fs.openSync(absolute, flags);
      try {
        const stat = fs.fstatSync(descriptor);
        if (!stat.isFile()) throw new Error(`Snapshot source changed while reading: ${relative}`);
        bytes += stat.size;
        if (bytes > workerData.maxBytes) throw new Error('Snapshot exceeds the configured project size limit. node_modules, .git, and .sham are excluded automatically.');
        const real = fs.realpathSync(absolute);
        if (!real.startsWith(`${resolvedRoot}${path.sep}`)) throw new Error(`Snapshot source escaped the project root: ${relative}`);
        files.push({ relative: relative.replaceAll('\\', '/'), data: fs.readFileSync(descriptor) });
      } finally { fs.closeSync(descriptor); }
    }
  };
  visit(root);
  return files;
}

function create() {
  const zip = new AdmZip();
  for (const file of projectFiles(workerData.source)) zip.addFile(`project/${file.relative}`, file.data);
  zip.addFile('snapshot.json', Buffer.from(JSON.stringify(workerData.metadata, null, 2)));
  fs.writeFileSync(workerData.destination, zip.toBuffer(), { flag: 'wx', mode: 0o600 });
}

function extract() {
  const zip = new AdmZip(workerData.source);
  const entries = zip.getEntries();
  if (entries.length > workerData.maxFiles + 1) throw new Error(`Snapshot contains more than ${workerData.maxFiles} project entries.`);
  let bytes = 0;
  const prepared = [];
  for (const entry of entries) {
    if (!safeName(entry.entryName)) throw new Error(`Snapshot contains an unsafe path: ${entry.entryName}`);
    if (!entry.entryName.startsWith('project/') || entry.isDirectory) continue;
    const relative = entry.entryName.slice('project/'.length);
    if (!relative || !safeName(relative)) throw new Error(`Snapshot contains an unsafe project path: ${entry.entryName}`);
    const declared = Number(entry.header?.size || 0);
    const compressed = Number(entry.header?.compressedSize || 0);
    if (!Number.isSafeInteger(declared) || declared < 0) throw new Error('Snapshot contains an invalid entry size.');
    if (compressed > 0 && declared > 1024 * 1024 && declared / compressed > 1000) throw new Error('Snapshot contains an unsafe compression ratio.');
    const data = entry.getData();
    if (data.length !== declared) throw new Error(`Snapshot entry could not be validated: ${relative}`);
    bytes += data.length;
    if (bytes > workerData.maxBytes) throw new Error('Snapshot expands beyond the configured project limit.');
    prepared.push({ relative, data });
  }
  for (const entry of prepared) {
    const output = path.resolve(workerData.destination, ...entry.relative.split('/'));
    if (!output.startsWith(`${path.resolve(workerData.destination)}${path.sep}`)) throw new Error('Snapshot contains an unsafe destination path.');
    fs.mkdirSync(path.dirname(output), { recursive: true });
    fs.writeFileSync(output, entry.data, { mode: 0o644 });
  }
}

try {
  if (workerData.mode === 'create') create();
  else if (workerData.mode === 'extract') extract();
  else throw new Error('Unknown snapshot worker mode.');
  parentPort.postMessage({ ok: true });
} catch (error) {
  parentPort.postMessage({ ok: false, error: error.message });
}
