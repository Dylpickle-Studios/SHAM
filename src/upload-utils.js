const fs = require('node:fs');
const path = require('node:path');
const crypto = require('node:crypto');
const { Worker, isMainThread, parentPort, workerData } = require('node:worker_threads');
const { safeRelativePath } = require('./validation');
const { UPLOAD_WORKERS, UPLOAD_QUEUE_LIMIT } = require('./config');

const MAX_FILES = 2000;
const activeWorkers = new Set();
const uploadQueue = [];
let uploadWorkersStopping = false;

function commonTopDirectory(paths) {
  if (!paths.length) return null;
  const firstParts = paths[0].split('/');
  if (firstParts.length < 2) return null;
  const candidate = firstParts[0];
  return paths.every((item) => item.startsWith(`${candidate}/`)) ? candidate : null;
}

function normalizedOutputPath(relativePath, stripTop) {
  let value = relativePath.replaceAll('\\', '/').replace(/^\.\//, '');
  if (stripTop && value.startsWith(`${stripTop}/`)) value = value.slice(stripTop.length + 1);
  return safeRelativePath(value, 'Uploaded file path');
}

function ensureInside(root, relativePath) {
  const absolute = path.resolve(root, ...relativePath.split('/'));
  const rootWithSep = `${path.resolve(root)}${path.sep}`;
  if (!absolute.startsWith(rootWithSep)) throw new Error('Upload contains an unsafe path.');
  return absolute;
}

function prepareStaging(destination) {
  const staging = `${destination}.staging-${crypto.randomUUID()}`;
  fs.mkdirSync(staging, { recursive: true });
  return staging;
}

function uploadSource(file, label) {
  if (file?.path) {
    try {
      const stat = fs.statSync(file.path);
      if (!stat.isFile()) throw new Error('not a regular file');
      if (Number.isSafeInteger(file.size) && file.size >= 0 && stat.size !== file.size) {
        throw new Error(`size changed from ${file.size} to ${stat.size} bytes`);
      }
      return file.path;
    } catch (error) {
      const reason = error?.code === 'ENOENT'
        ? 'the server-side temporary file disappeared before processing'
        : error.message;
      throw new Error(`${label} is no longer readable because ${reason}. Retry the upload. If this repeats, verify that SHAM_DATA_PATH is writable and that no cleanup task removes its data/tmp directory.`);
    }
  }
  if (Buffer.isBuffer(file?.buffer) || file?.buffer instanceof Uint8Array) return file.buffer;
  throw new Error(`${label} did not contain readable upload data.`);
}

function commitStaging(staging, destination) {
  const backup = `${destination}.backup-${crypto.randomUUID()}`;
  const existed = fs.existsSync(destination);
  try {
    if (existed) fs.renameSync(destination, backup);
    fs.renameSync(staging, destination);
  } catch (error) {
    fs.rmSync(staging, { recursive: true, force: true });
    if (existed && fs.existsSync(backup) && !fs.existsSync(destination)) fs.renameSync(backup, destination);
    throw error;
  }
  if (existed) fs.rm(backup, { recursive: true, force: true }, () => {});
}

function writeZip(source, staging, maxBytes) {
  const AdmZip = require('adm-zip');
  let entries;
  try {
    const zip = new AdmZip(source);
    entries = zip.getEntries().filter((entry) => !entry.isDirectory);
  } catch (error) {
    const unavailable = error?.code === 'ENOENT' ? ' The server-side temporary file became unavailable during processing; retry the upload.' : '';
    throw new Error(`The ZIP archive could not be opened. Confirm that it is a valid, non-encrypted ZIP file.${unavailable}`);
  }
  if (!entries.length) throw new Error('The ZIP archive contains no files.');
  if (entries.length > MAX_FILES) throw new Error(`The upload exceeds the ${MAX_FILES}-file limit.`);

  const names = entries.map((entry) => entry.entryName.replaceAll('\\', '/'));
  const stripTop = commonTopDirectory(names);
  const seen = new Set();
  let total = 0;

  for (const entry of entries) {
    const declaredSize = Number(entry.header?.size || 0);
    const compressedSize = Number(entry.header?.compressedSize || 0);
    if (!Number.isSafeInteger(declaredSize) || declaredSize < 0) throw new Error('ZIP entry has an invalid size.');
    if (compressedSize > 0 && declaredSize > 1024 * 1024 && declaredSize / compressedSize > 1000) {
      throw new Error('ZIP entry has an unsafe compression ratio.');
    }
    total += declaredSize;
    if (total > maxBytes) throw new Error('The uncompressed ZIP contents exceed the upload limit.');

    const relative = normalizedOutputPath(entry.entryName, stripTop);
    if (seen.has(relative)) throw new Error(`The upload contains a duplicate path: ${relative}`);
    seen.add(relative);
    const output = ensureInside(staging, relative);
    let data;
    try { data = entry.getData(); }
    catch { throw new Error(`Could not decompress ZIP entry “${relative}”. The archive may be damaged, encrypted, or use an unsupported compression method.`); }
    if (data.length !== declaredSize) throw new Error(`Could not validate ZIP entry: ${relative}`);
    if (total - declaredSize + data.length > maxBytes) throw new Error('The uncompressed ZIP contents exceed the upload limit.');
    fs.mkdirSync(path.dirname(output), { recursive: true });
    fs.writeFileSync(output, data, { mode: 0o644 });
  }
}

function writeFiles(files, relativePaths, staging, maxBytes) {
  if (!files.length) throw new Error('No website files were uploaded.');
  if (files.length > MAX_FILES) throw new Error(`The upload exceeds the ${MAX_FILES}-file limit.`);
  if (!Array.isArray(relativePaths) || relativePaths.length !== files.length) {
    throw new Error('The folder upload manifest is invalid.');
  }

  const sanitized = relativePaths.map((item) => String(item).replaceAll('\\', '/'));
  const stripTop = commonTopDirectory(sanitized);
  const seen = new Set();
  let total = 0;

  files.forEach((file, index) => {
    if (!Number.isSafeInteger(file.size) || file.size < 0) throw new Error('An uploaded file has an invalid size.');
    total += file.size;
    if (total > maxBytes) throw new Error('The uploaded files exceed the upload limit.');
    const relative = normalizedOutputPath(sanitized[index] || file.originalname, stripTop);
    if (seen.has(relative)) throw new Error(`The upload contains a duplicate path: ${relative}`);
    seen.add(relative);
    const output = ensureInside(staging, relative);
    fs.mkdirSync(path.dirname(output), { recursive: true });
    const source = uploadSource(file, `Uploaded file “${relative}”`);
    if (typeof source === 'string') fs.copyFileSync(source, output);
    else fs.writeFileSync(output, source, { mode: 0o644 });
    fs.chmodSync(output, 0o644);
  });
}

function installUpload({ archive, files, relativePaths, destination, entryFile, maxBytes }) {
  if (archive && files.length) throw new Error('Upload either one ZIP or a folder, not both.');
  const staging = prepareStaging(destination);
  try {
    if (archive) writeZip(uploadSource(archive, 'Uploaded ZIP archive'), staging, maxBytes);
    else writeFiles(files, relativePaths, staging, maxBytes);

    const entry = ensureInside(staging, safeRelativePath(entryFile, 'Entry file'));
    if (!fs.existsSync(entry) || !fs.statSync(entry).isFile()) {
      throw new Error(`Entry file “${entryFile}” was not found in the upload.`);
    }
    commitStaging(staging, destination);
  } catch (error) {
    fs.rmSync(staging, { recursive: true, force: true });
    throw error;
  }
}



function serializableUpload(options) {
  const copyFile = (file) => file ? {
    originalname: file.originalname,
    size: file.size,
    path: file.path,
    buffer: file.buffer
  } : null;
  return {
    archive: copyFile(options.archive),
    files: (options.files || []).map(copyFile),
    relativePaths: options.relativePaths,
    destination: options.destination,
    entryFile: options.entryFile,
    maxBytes: options.maxBytes
  };
}

function pumpUploadWorkers() {
  if (uploadWorkersStopping) return;
  while (activeWorkers.size < UPLOAD_WORKERS && uploadQueue.length) {
    const job = uploadQueue.shift();
    let worker;
    try {
      worker = new Worker(__filename, {
        workerData: { task: 'install-upload', options: job.options }
      });
    } catch (error) {
      job.reject(error);
      continue;
    }
    activeWorkers.add(worker);
    /** @type {{ ok: boolean, error?: string } | null} */
    let result = null;
    /** @type {Error | null} */
    let workerError = null;
    const finish = () => {
      activeWorkers.delete(worker);
      if (workerError) job.reject(workerError);
      else if (!result?.ok) job.reject(new Error(result?.error || 'Upload worker failed.'));
      else job.resolve();
      pumpUploadWorkers();
    };
    worker.once('message', (message) => { result = message; });
    worker.once('error', (error) => { workerError = error; });
    worker.once('exit', (code) => {
      if (code !== 0 && !workerError) workerError = new Error(`Upload worker exited with code ${code}.`);
      if (!result && !workerError) workerError = new Error('Upload worker exited without a result.');
      finish();
    });
  }
}

function installUploadAsync(options) {
  if (!isMainThread) return Promise.resolve(installUpload(options));
  if (uploadWorkersStopping) return Promise.reject(new Error('Upload processing is shutting down.'));
  if (activeWorkers.size + uploadQueue.length >= UPLOAD_QUEUE_LIMIT) {
    return Promise.reject(new Error('Too many project uploads are being processed. Try again shortly.'));
  }
  return new Promise((resolve, reject) => {
    uploadQueue.push({ options: serializableUpload(options), resolve, reject });
    pumpUploadWorkers();
  });
}

function uploadQueueStats() {
  return { active: activeWorkers.size, queued: uploadQueue.length, capacity: UPLOAD_WORKERS };
}

async function stopUploadWorkers() {
  uploadWorkersStopping = true;
  const queued = uploadQueue.splice(0);
  for (const job of queued) job.reject(new Error('Upload processing stopped during shutdown.'));
  await Promise.allSettled([...activeWorkers].map((worker) => worker.terminate()));
  activeWorkers.clear();
}

if (!isMainThread && workerData?.task === 'install-upload') {
  // Guaranteed non-null: worker_threads always sets parentPort for a
  // non-main thread, and this branch only runs when !isMainThread.
  const port = /** @type {import('node:worker_threads').MessagePort} */ (parentPort);
  try {
    installUpload(workerData.options);
    port.postMessage({ ok: true });
  } catch (error) {
    port.postMessage({ ok: false, error: error instanceof Error ? error.message : String(error) });
  }
}

module.exports = { installUpload, installUploadAsync, stopUploadWorkers, uploadQueueStats, MAX_FILES };
