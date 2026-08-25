const fs = require('node:fs');
const path = require('node:path');
const crypto = require('node:crypto');
const vm = require('node:vm');
const AdmZip = require('adm-zip');
const { parentPort, workerData } = require('node:worker_threads');
if (!parentPort) throw new Error('This module must run inside a worker thread.');
const { normalizeTrustedKeys, canonical } = require('./plugin-signing');

const MAX_UPDATE_BYTES = 512 * 1024 * 1024;
const MAX_UPDATE_FILES = 20_000;

function safeEntry(name) {
  const normalized = String(name || '').replaceAll('\\', '/');
  if (!normalized || normalized.startsWith('/') || normalized.includes('\0') || /^[A-Za-z]:\//.test(normalized)) throw new Error('Update archive contains an invalid path.');
  const clean = path.posix.normalize(normalized).replace(/^\.\//, '');
  if (!clean || clean === '..' || clean.startsWith('../')) throw new Error('Update archive attempts to escape its staging directory.');
  return clean;
}

function detectRoot(directory) {
  if (fs.existsSync(path.join(directory, 'package.json')) && fs.existsSync(path.join(directory, 'src', 'server.js'))) return directory;
  const entries = fs.readdirSync(directory, { withFileTypes: true }).filter((entry) => !entry.name.startsWith('.'));
  if (entries.length === 1 && entries[0].isDirectory()) {
    const nested = path.join(directory, entries[0].name);
    if (fs.existsSync(path.join(nested, 'package.json')) && fs.existsSync(path.join(nested, 'src', 'server.js'))) return nested;
  }
  throw new Error('Update ZIP must contain a SHAM package with package.json and src/server.js.');
}

function walk(root, current = root, files = []) {
  for (const entry of fs.readdirSync(current, { withFileTypes: true }).sort((a, b) => a.name.localeCompare(b.name))) {
    const absolute = path.join(current, entry.name);
    if (entry.isSymbolicLink()) throw new Error('SHAM update archives may not contain symbolic links.');
    if (entry.isDirectory()) walk(root, absolute, files);
    else if (entry.isFile()) files.push(path.relative(root, absolute).replaceAll('\\', '/'));
  }
  return files;
}


function validateJavaScript(root) {
  for (const relative of walk(root).filter((name) => name.endsWith('.js'))) {
    const filename = path.join(root, ...relative.split('/'));
    const stat = fs.statSync(filename);
    if (stat.size > 16 * 1024 * 1024) throw new Error(`JavaScript file “${relative}” exceeds the 16 MB update validation limit.`);
    let source = fs.readFileSync(filename, 'utf8');
    if (source.startsWith('#!')) source = source.replace(/^#!.*(?:\r?\n|$)/, '');
    try { new vm.Script(source, { filename: relative }); }
    catch (error) { throw new Error(`JavaScript syntax check failed for “${relative}”: ${error instanceof Error ? error.message : String(error)}`); }
  }
}

function updateDigest(root, packageManifest) {
  const hash = crypto.createHash('sha256');
  hash.update('SHAM-UPDATE-SIGNATURE-V1\0');
  hash.update(canonical({
    name: packageManifest.name,
    version: packageManifest.version,
    dependencies: packageManifest.dependencies || {},
    optionalDependencies: packageManifest.optionalDependencies || {}
  }));
  for (const relative of walk(root).filter((name) => name !== 'sham-update.json')) {
    const data = fs.readFileSync(path.join(root, ...relative.split('/')));
    hash.update('\0');
    hash.update(relative);
    hash.update('\0');
    hash.update(crypto.createHash('sha256').update(data).digest());
  }
  return hash.digest();
}

function verifyUpdateSignature(root, packageManifest, trustedKeys) {
  const signaturePath = path.join(root, 'sham-update.json');
  if (!fs.existsSync(signaturePath)) return { status: 'unsigned', keyId: null, signer: null };
  const stat = fs.statSync(signaturePath);
  if (!stat.isFile() || stat.size > 256 * 1024) throw new Error('sham-update.json is invalid or too large.');
  const signature = JSON.parse(fs.readFileSync(signaturePath, 'utf8'));
  if (signature.format !== 'sham-update-signature-v1' || signature.algorithm !== 'ed25519') throw new Error('The SHAM update signature manifest is invalid.');
  if (String(signature.version || '') !== String(packageManifest.version || '')) throw new Error('The update signature version does not match package.json.');
  const key = normalizeTrustedKeys(trustedKeys).find((entry) => entry.id === String(signature.keyId || ''));
  if (!key) throw new Error(`Update signature key “${String(signature.keyId || '')}” is not trusted by this SHAM instance.`);
  let publicKey;
  try { publicKey = crypto.createPublicKey(key.publicKey); }
  catch { throw new Error(`Trusted publisher key “${key.id}” is not a valid public key.`); }
  const value = Buffer.from(String(signature.value || ''), 'base64url');
  if (!value.length || !crypto.verify(null, updateDigest(root, packageManifest), publicKey, value)) {
    throw new Error('SHAM update signature verification failed. The archive may have been modified.');
  }
  return { status: 'verified', keyId: key.id, signer: key.name || key.id };
}

try {
  const zip = new AdmZip(workerData.archivePath);
  const entries = zip.getEntries();
  if (!entries.length || entries.length > MAX_UPDATE_FILES) throw new Error('Update archive has an invalid number of files.');
  let expanded = 0;
  for (const entry of entries) {
    const relative = safeEntry(entry.entryName);
    if (entry.isDirectory) continue;
    expanded += Number(entry.header?.size || 0);
    if (expanded > MAX_UPDATE_BYTES) throw new Error('Expanded update archive exceeds 512 MB.');
    const destination = path.join(workerData.stageBase, ...relative.split('/'));
    fs.mkdirSync(path.dirname(destination), { recursive: true });
    fs.writeFileSync(destination, entry.getData(), { mode: 0o600 });
  }
  const packageRoot = detectRoot(workerData.stageBase);
  const packageManifest = JSON.parse(fs.readFileSync(path.join(packageRoot, 'package.json'), 'utf8'));
  validateJavaScript(packageRoot);
  const signature = verifyUpdateSignature(packageRoot, packageManifest, workerData.trustedKeys || []);
  parentPort.postMessage({ ok: true, packageRoot, packageManifest, signature });
} catch (error) {
  parentPort.postMessage({ ok: false, error: error.message });
}
