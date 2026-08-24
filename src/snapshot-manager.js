const fs = require('node:fs');
const path = require('node:path');
const crypto = require('node:crypto');
const { Worker } = require('node:worker_threads');
const { SNAPSHOTS_DIR, UPLOAD_LIMIT_BYTES, SNAPSHOT_RETENTION, SNAPSHOT_WORKERS, SNAPSHOT_QUEUE_LIMIT } = require('./config');
const { siteRoot } = require('./site-paths');
const { MAX_FILES } = require('./upload-utils');
const { realFileInsideAsync } = require('./sites/shared');

async function pathExistsAsync(target) {
  try { await fs.promises.access(target); return true; }
  catch { return false; }
}

class SnapshotManager {
  constructor(db, logger = console) {
    this.db = db;
    this.logger = logger;
    this.active = 0;
    this.queue = [];
    this.workers = new Set();
    this.stopping = false;
    fs.mkdirSync(SNAPSHOTS_DIR, { recursive: true });
  }

  queueLength() { return this.queue.length; }
  acquire() {
    if (this.stopping) return Promise.reject(new Error('Snapshot service is shutting down.'));
    if (this.active < SNAPSHOT_WORKERS) { this.active += 1; return Promise.resolve(); }
    if (this.queue.length >= SNAPSHOT_QUEUE_LIMIT) return Promise.reject(new Error('Too many snapshot operations are queued.'));
    return new Promise((resolve, reject) => this.queue.push({ resolve, reject }));
  }
  release() {
    const next = this.queue.shift();
    if (next) next.resolve();
    else this.active = Math.max(0, this.active - 1);
  }

  worker(data) {
    return new Promise((resolve, reject) => {
      let worker;
      try { worker = new Worker(path.join(__dirname, 'snapshot-worker.js'), { workerData: data }); }
      catch (error) { reject(error); return; }
      this.workers.add(worker);
      let message = null;
      let failure = null;
      worker.once('message', (value) => { message = value; });
      worker.once('error', (error) => { failure = error; });
      worker.once('exit', (code) => {
        this.workers.delete(worker);
        if (failure) reject(failure);
        else if (code !== 0) reject(new Error(`Snapshot worker exited with code ${code}.`));
        else if (!message?.ok) reject(new Error(message?.error || 'Snapshot worker failed.'));
        else resolve();
      });
    });
  }

  list(siteId) {
    return this.db.prepare(`SELECT id, site_id AS siteId, label, bytes, created_at AS createdAt FROM site_snapshots WHERE site_id = ? ORDER BY id DESC`).all(siteId);
  }

  async create(site, label = '') {
    await this.acquire();
    try {
      const source = siteRoot(site);
      const directory = path.join(SNAPSHOTS_DIR, String(site.id));
      await fs.promises.mkdir(directory, { recursive: true });
      const token = `${Date.now()}-${crypto.randomUUID()}`;
      const temporary = path.join(directory, `${token}.tmp`);
      const destination = path.join(directory, `${token}.zip`);
      const metadata = { siteId: site.id, createdAt: new Date().toISOString(), config: site };
      try {
        await this.worker({ mode: 'create', source, destination: temporary, metadata, maxFiles: MAX_FILES, maxBytes: UPLOAD_LIMIT_BYTES });
        await fs.promises.rename(temporary, destination);
      } catch (error) {
        await fs.promises.rm(temporary, { force: true }).catch(() => {});
        throw error;
      }
      const stat = await fs.promises.stat(destination);
      const result = this.db.prepare(`INSERT INTO site_snapshots (site_id, label, filename, bytes) VALUES (?, ?, ?, ?)`)
        .run(site.id, String(label || '').trim().slice(0, 120), path.relative(SNAPSHOTS_DIR, destination), stat.size);
      const stale = this.db.prepare(`SELECT id, filename FROM site_snapshots WHERE site_id = ? ORDER BY id DESC LIMIT -1 OFFSET ?`).all(site.id, SNAPSHOT_RETENTION);
      for (const row of stale) await this.delete(site.id, row.id).catch(() => {});
      return this.db.prepare(`SELECT id, site_id AS siteId, label, bytes, created_at AS createdAt FROM site_snapshots WHERE id = ?`).get(result.lastInsertRowid);
    } finally { this.release(); }
  }

  row(siteId, snapshotId) {
    const row = this.db.prepare('SELECT * FROM site_snapshots WHERE id = ? AND site_id = ?').get(snapshotId, siteId);
    if (!row) throw new Error('Snapshot not found.');
    const absolute = path.resolve(SNAPSHOTS_DIR, row.filename);
    if (!absolute.startsWith(`${path.resolve(SNAPSHOTS_DIR)}${path.sep}`)) throw new Error('Snapshot path is unsafe.');
    return { ...row, absolute };
  }

  async restore(site, snapshotId) {
    await this.acquire();
    const root = siteRoot(site);
    const staging = `${root}.snapshot-${crypto.randomUUID()}`;
    const backup = `${root}.before-restore-${crypto.randomUUID()}`;
    try {
      const row = this.row(site.id, snapshotId);
      await fs.promises.mkdir(staging, { recursive: true });
      await this.worker({ mode: 'extract', source: row.absolute, destination: staging, maxFiles: MAX_FILES, maxBytes: UPLOAD_LIMIT_BYTES });
      const requiredRelative = site.runtime_type === 'node' && !site.start_command
        ? site.node_entry
        : site.runtime_type === 'static' ? site.entry_file : '';
      if (requiredRelative) {
        const required = path.join(staging, ...String(requiredRelative).split('/'));
        if (!(await realFileInsideAsync(staging, required))) throw new Error('Snapshot does not contain the configured entry file.');
      }
      await fs.promises.rename(root, backup);
      try { await fs.promises.rename(staging, root); }
      catch (error) { await fs.promises.rename(backup, root).catch(() => {}); throw error; }
      const cleanupWarning = await fs.promises.rm(backup, { recursive: true, force: true })
        .then(() => null, (error) => `Snapshot restored, but the previous project backup could not be removed: ${error.message}`);
      return { restoredAt: new Date().toISOString(), snapshotId: Number(snapshotId), warning: cleanupWarning };
    } catch (error) {
      await fs.promises.rm(staging, { recursive: true, force: true }).catch(() => {});
      if (await pathExistsAsync(backup) && !(await pathExistsAsync(root))) await fs.promises.rename(backup, root).catch(() => {});
      throw error;
    } finally { this.release(); }
  }

  async delete(siteId, snapshotId) {
    const row = this.row(siteId, snapshotId);
    await fs.promises.rm(row.absolute, { force: true });
    this.db.prepare('DELETE FROM site_snapshots WHERE id = ? AND site_id = ?').run(snapshotId, siteId);
  }

  async shutdown() {
    this.stopping = true;
    for (const job of this.queue.splice(0)) job.reject(new Error('Snapshot operation stopped during shutdown.'));
    await Promise.allSettled([...this.workers].map((worker) => worker.terminate()));
    this.workers.clear();
  }
}

module.exports = { SnapshotManager };
