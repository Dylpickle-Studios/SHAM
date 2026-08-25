const fs = require('node:fs');
const path = require('node:path');
const crypto = require('node:crypto');
const { Worker } = require('node:worker_threads');
const {
  ROOT_DIR,
  UPDATES_DIR,
  APP_RELEASES_DIR,
  ACTIVE_APP_PATH
} = require('./config');

const PENDING_PATH = path.join(UPDATES_DIR, 'pending-update.json');
const STATE_PATH = path.join(UPDATES_DIR, 'update-state.json');
const MAX_UPDATE_BYTES = 512 * 1024 * 1024;
const MANAGED_PATHS = ['src', 'public', 'bin', 'runtime-agent', 'docs', 'examples', 'test', 'scripts', '.github', 'README.md', 'AUDIT-REPORT.md', 'CHANGELOG.md', 'CONTRIBUTING.md', 'RELEASING.md', 'SECURITY.md', 'Dockerfile', 'docker-compose.yml', 'docker-compose.isolation.yml', '.dockerignore', '.env.example', '.gitattributes', '.gitignore', 'LICENSE', 'package.json', 'package-lock.json'];

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

function isInside(base, candidate) {
  const root = path.resolve(base);
  const target = path.resolve(candidate);
  return target === root || target.startsWith(`${root}${path.sep}`);
}

function readJsonSync(filename) {
  try { return JSON.parse(fs.readFileSync(filename, 'utf8')); }
  catch { return null; }
}

function validReleaseRoot(candidate) {
  if (!candidate || !isInside(APP_RELEASES_DIR, candidate)) return null;
  const root = path.resolve(candidate);
  try {
    if (!fs.statSync(root).isDirectory()) return null;
    if (!fs.statSync(path.join(root, 'package.json')).isFile()) return null;
    if (!fs.statSync(path.join(root, 'src', 'server.js')).isFile()) return null;
    return root;
  } catch { return null; }
}

function readActiveState() {
  const state = readJsonSync(ACTIVE_APP_PATH);
  const root = validReleaseRoot(state?.root);
  return root ? { ...state, root } : null;
}

function resolveActiveAppRoot() {
  return readActiveState()?.root || ROOT_DIR;
}

async function writeJsonAtomic(filename, value) {
  await fs.promises.mkdir(path.dirname(filename), { recursive: true });
  const temporary = `${filename}.${process.pid}.${crypto.randomUUID()}.tmp`;
  await fs.promises.writeFile(temporary, `${JSON.stringify(value, null, 2)}\n`, { mode: 0o600 });
  await fs.promises.rename(temporary, filename);
}

async function copyPath(source, destination) {
  const stat = await fs.promises.lstat(source);
  if (stat.isSymbolicLink()) throw new Error(`Refusing to copy symbolic link ${source}.`);
  if (stat.isDirectory()) {
    await fs.promises.mkdir(destination, { recursive: true });
    for (const name of await fs.promises.readdir(source)) await copyPath(path.join(source, name), path.join(destination, name));
  } else if (stat.isFile()) {
    await fs.promises.mkdir(path.dirname(destination), { recursive: true });
    await fs.promises.copyFile(source, destination);
    await fs.promises.chmod(destination, stat.mode & 0o777).catch(() => {});
  }
}

async function installManaged(sourceRoot, targetRoot) {
  await fs.promises.mkdir(targetRoot, { recursive: true });
  for (const name of MANAGED_PATHS) {
    const source = path.join(sourceRoot, name);
    try { await fs.promises.access(source); }
    catch { continue; }
    await copyPath(source, path.join(targetRoot, name));
  }
}

function stagingDirectoryFor(stagedRoot) {
  if (!stagedRoot) return null;
  const resolved = path.resolve(stagedRoot);
  const relative = path.relative(UPDATES_DIR, resolved);
  if (!relative || path.isAbsolute(relative) || relative === '..' || relative.startsWith(`..${path.sep}`)) return null;
  const stageName = relative.split(path.sep)[0];
  if (!/^stage-[0-9A-Za-z-]+$/.test(stageName)) return null;
  return path.join(UPDATES_DIR, stageName);
}

async function removeStagedRoot(stagedRoot) {
  const stageDirectory = stagingDirectoryFor(stagedRoot);
  if (stageDirectory) await fs.promises.rm(stageDirectory, { recursive: true, force: true });
}

async function pruneApplicationReleases(activeState, keep = 4) {
  let entries;
  try { entries = await fs.promises.readdir(APP_RELEASES_DIR, { withFileTypes: true }); }
  catch { return; }
  const releaseRoots = new Set(entries.filter((entry) => entry.isDirectory()).map((entry) => path.resolve(path.join(APP_RELEASES_DIR, entry.name))));
  const protectedRoots = new Set([activeState?.root, activeState?.previousRoot].filter(Boolean).map((value) => path.resolve(value)).filter((value) => releaseRoots.has(value)));
  const candidates = [];
  for (const entry of entries) {
    if (!entry.isDirectory()) continue;
    const root = path.resolve(path.join(APP_RELEASES_DIR, entry.name));
    if (protectedRoots.has(root)) continue;
    const stat = await fs.promises.stat(root).catch(() => null);
    if (stat) candidates.push({ root, mtimeMs: stat.mtimeMs });
  }
  candidates.sort((a, b) => b.mtimeMs - a.mtimeMs);
  for (const item of candidates.slice(Math.max(0, keep - protectedRoots.size))) {
    await fs.promises.rm(item.root, { recursive: true, force: true }).catch(() => {});
  }
}

class UpdateManager {
  constructor({ db = null } = {}) {
    this.db = db;
    this.workers = new Set();
    this.operations = new Set();
    this.mutationActive = false;
    this.stopping = false;
    this.reconcileHistory();
  }

  runMutation(callback) {
    if (this.stopping) throw new Error('Update manager is shutting down.');
    if (this.mutationActive) throw new Error('Another update operation is already running.');
    this.mutationActive = true;
    const operation = Promise.resolve().then(callback);
    this.operations.add(operation);
    return operation.finally(() => {
      this.operations.delete(operation);
      this.mutationActive = false;
    });
  }

  reconcileHistory() {
    if (!this.db) return;
    const state = readJsonSync(STATE_PATH);
    if (!state?.version || !['healthy', 'rolled-back'].includes(state.status)) return;
    try {
      this.db.prepare(`
        UPDATE update_history
        SET status = ?, detail = ?, applied_at = COALESCE(applied_at, CURRENT_TIMESTAMP)
        WHERE id = (SELECT id FROM update_history WHERE version = ? ORDER BY id DESC LIMIT 1)
      `).run(state.status === 'healthy' ? 'applied' : 'rolled-back', state.status === 'healthy' ? 'Persistent release activated successfully.' : state.error || 'Update was rolled back during startup.', state.version);
    } catch { /* Older databases can still display the on-disk update state. */ }
  }

  currentVersion() {
    try { return JSON.parse(fs.readFileSync(path.join(resolveActiveAppRoot(), 'package.json'), 'utf8')).version || 'unknown'; }
    catch { return 'unknown'; }
  }

  status() {
    const pending = readJsonSync(PENDING_PATH);
    const state = readJsonSync(STATE_PATH);
    const active = readActiveState();
    const history = this.db ? this.db.prepare('SELECT id, version, status, detail, archive_name AS archiveName, created_at AS createdAt, applied_at AS appliedAt FROM update_history ORDER BY id DESC LIMIT 20').all() : [];
    return { currentVersion: this.currentVersion(), pending, state, active, persistent: true, history };
  }

  stage(archivePath, originalName = 'sham-update.zip', { allowUnsigned = false } = {}) {
    return this.runMutation(async () => {
      if (readJsonSync(PENDING_PATH)) throw new Error('An update is already staged. Cancel or apply it before staging another archive.');
      const stat = await fs.promises.stat(archivePath);
      if (!stat.isFile() || stat.size > MAX_UPDATE_BYTES) throw new Error('Update archive is missing or exceeds 512 MB.');
      const stageBase = path.join(UPDATES_DIR, `stage-${crypto.randomUUID()}`);
      await fs.promises.mkdir(stageBase, { recursive: true });
      return new Promise((resolve, reject) => {
        let worker;
        const cleanup = async () => fs.promises.rm(stageBase, { recursive: true, force: true }).catch(() => {});
        try {
          const trustedKeys = this.db?.prepare("SELECT value FROM settings WHERE key = 'plugin_trusted_keys_json'").get()?.value || '[]';
          worker = new Worker(path.join(__dirname, 'update-worker.js'), { workerData: { archivePath, stageBase, trustedKeys } });
        } catch (error) { void cleanup().then(() => reject(error)); return; }
        this.workers.add(worker);
        let settled = false;
        const finish = (callback, value) => { if (settled) return; settled = true; this.workers.delete(worker); callback(value); };
        worker.once('message', async (message) => {
          if (!message?.ok) { await cleanup(); finish(reject, new Error(message?.error || 'Update extraction worker failed.')); return; }
          try {
            const manifest = message.packageManifest;
            const packageRoot = path.resolve(message.packageRoot);
            if (!isInside(stageBase, packageRoot)) throw new Error('Update staging path is invalid.');
            if (manifest.name !== 'simple-hosting-and-more' || !/^\d+\.\d+\.\d+(?:[-+][0-9A-Za-z.-]+)?$/.test(String(manifest.version || ''))) throw new Error('Update package name or version is invalid.');
            if (!fs.existsSync(path.join(packageRoot, 'src', 'bootstrap.js'))) throw new Error('Update package does not support safe bootstrapping.');
            if (message.signature?.status === 'unsigned' && !allowUnsigned) throw new Error('This SHAM update is unsigned. Add a trusted Ed25519 publisher signature or explicitly acknowledge the unsigned-update risk.');
            const currentManifest = JSON.parse(await fs.promises.readFile(path.join(resolveActiveAppRoot(), 'package.json'), 'utf8'));
            const dependencyShape = (value) => JSON.stringify(Object.fromEntries(Object.entries(value || {}).sort(([a], [b]) => a.localeCompare(b))));
            const dependenciesChanged = dependencyShape(manifest.dependencies) !== dependencyShape(currentManifest.dependencies)
              || dependencyShape(manifest.optionalDependencies) !== dependencyShape(currentManifest.optionalDependencies);
            if (dependenciesChanged) throw new Error('This update changes runtime dependencies. Use a reviewed container image or perform a manual upgrade so dependency installation can be verified before switching versions.');
            const pending = { version: manifest.version, stagedRoot: packageRoot, archiveName: path.basename(originalName), stagedAt: new Date().toISOString(), signature: message.signature };
            await writeJsonAtomic(PENDING_PATH, pending);
            if (this.db) this.db.prepare("INSERT INTO update_history (version, status, detail, archive_name) VALUES (?, 'staged', ?, ?)").run(manifest.version, message.signature?.status === 'verified' ? `Signature verified for ${message.signature.signer || message.signature.keyId}.` : 'Unsigned update explicitly acknowledged; update will activate from persistent storage on the next restart.', pending.archiveName);
            finish(resolve, pending);
          } catch (error) { await cleanup(); finish(reject, error); }
        });
        worker.once('error', async (error) => { await cleanup(); finish(reject, error); });
        worker.once('exit', async (code) => { if (code === 0 || settled) return; await cleanup(); finish(reject, new Error(`Update extraction worker exited with code ${code}.`)); });
      });
    });
  }

  cancel() {
    return this.runMutation(async () => {
      const pending = readJsonSync(PENDING_PATH);
      await fs.promises.rm(PENDING_PATH, { force: true });
      await removeStagedRoot(pending?.stagedRoot);
      return { cancelled: Boolean(pending) };
    });
  }

  async shutdown() {
    this.stopping = true;
    for (const worker of this.workers) worker.terminate().catch(() => {});
    await Promise.allSettled([...this.operations]);
  }
}

async function applyPendingUpdate() {
  const pending = readJsonSync(PENDING_PATH);
  if (!pending) return null;
  const stagedRoot = path.resolve(String(pending.stagedRoot || ''));
  if (!isInside(UPDATES_DIR, stagedRoot) || !fs.existsSync(path.join(stagedRoot, 'package.json'))) {
    await fs.promises.rm(PENDING_PATH, { force: true });
    throw new Error('Pending update staging directory is invalid.');
  }
  const previousActive = readActiveState();
  const previousRoot = previousActive?.root || ROOT_DIR;
  const releaseName = `${String(pending.version).replace(/[^0-9A-Za-z._-]/g, '-')}-${Date.now()}-${crypto.randomUUID()}`;
  const releaseRoot = path.join(APP_RELEASES_DIR, releaseName);
  const state = {
    ...pending,
    status: 'applying',
    root: releaseRoot,
    previousRoot,
    previousActive,
    startedAt: new Date().toISOString()
  };
  await writeJsonAtomic(STATE_PATH, state);
  try {
    await installManaged(stagedRoot, releaseRoot);
    const manifest = JSON.parse(await fs.promises.readFile(path.join(releaseRoot, 'package.json'), 'utf8'));
    if (manifest.name !== 'simple-hosting-and-more' || String(manifest.version) !== String(pending.version)) throw new Error('Installed release metadata does not match the staged update.');
    const active = { version: pending.version, root: releaseRoot, previousRoot, activatedAt: new Date().toISOString(), status: 'booting' };
    await writeJsonAtomic(ACTIVE_APP_PATH, active);
    state.status = 'booting';
    state.activatedAt = active.activatedAt;
    await writeJsonAtomic(STATE_PATH, state);
    await fs.promises.rm(PENDING_PATH, { force: true });
    await removeStagedRoot(stagedRoot);
    return state;
  } catch (error) {
    await fs.promises.rm(releaseRoot, { recursive: true, force: true }).catch(() => {});
    state.status = 'rolled-back';
    state.error = error.message;
    state.finishedAt = new Date().toISOString();
    await writeJsonAtomic(STATE_PATH, state);
    throw new Error(`SHAM update failed before activation: ${error.message}`);
  }
}

async function markAppliedUpdateHealthy(state) {
  if (!state?.root) return null;
  const active = readActiveState();
  if (!active || path.resolve(active.root) !== path.resolve(state.root)) return null;
  const healthy = { ...active, status: 'healthy', healthyAt: new Date().toISOString() };
  await writeJsonAtomic(ACTIVE_APP_PATH, healthy);
  const finalState = { ...state, status: 'healthy', healthyAt: healthy.healthyAt, finishedAt: healthy.healthyAt };
  await writeJsonAtomic(STATE_PATH, finalState);
  await pruneApplicationReleases(healthy);
  return finalState;
}

async function rollbackAppliedUpdate(state, reason) {
  if (!state) return null;
  const previousActive = state.previousActive && validReleaseRoot(state.previousActive.root) ? state.previousActive : null;
  if (previousActive) await writeJsonAtomic(ACTIVE_APP_PATH, { ...previousActive, status: 'healthy', restoredAt: new Date().toISOString() });
  else await fs.promises.rm(ACTIVE_APP_PATH, { force: true });
  if (state.root && isInside(APP_RELEASES_DIR, state.root)) await fs.promises.rm(state.root, { recursive: true, force: true }).catch(() => {});
  const rolledBack = { ...state, status: 'rolled-back', error: String(reason?.message || reason || 'Startup validation failed.'), finishedAt: new Date().toISOString() };
  await writeJsonAtomic(STATE_PATH, rolledBack);
  return rolledBack;
}

module.exports = {
  UpdateManager,
  applyPendingUpdate,
  markAppliedUpdateHealthy,
  rollbackAppliedUpdate,
  resolveActiveAppRoot,
  readActiveState,
  safeEntry,
  detectRoot,
  stagingDirectoryFor,
  removeStagedRoot
};
