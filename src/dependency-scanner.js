// @ts-nocheck -- not part of this session's checkJs rollout yet.
// This file still has genuine `tsc --noEmit` findings (mostly narrow
// `let x = null`-style inference and untyped Express handlers, the same
// patterns already fixed across most of src/) that need real per-file
// JSDoc work to resolve, not a suppression. Tracked as follow-up work;
// see tsconfig.json and docs/development.md. Do not add more files here
// without a similar comment and a plan to remove it.
const fs = require('node:fs');
const path = require('node:path');
const { spawn } = require('node:child_process');
const { DEPENDENCY_SCAN_TIMEOUT_MS, DEPENDENCY_SCAN_WORKERS, DEPENDENCY_SCAN_QUEUE_LIMIT } = require('./config');
const { siteRoot } = require('./site-paths');
const { realFileInsideAsync } = require('./sites/shared');
const { buildEnvironment } = require('./process-env');

function tail(value, chunk, limit = 2 * 1024 * 1024) {
  const combined = value + chunk;
  return combined.length > limit ? combined.slice(-limit) : combined;
}

function staticFindings(packageJson, hasLockfile) {
  const findings = [];
  if (!hasLockfile) findings.push({ severity: 'high', code: 'missing-lockfile', message: 'No package-lock.json or npm-shrinkwrap.json is present; dependency resolution is not reproducible.' });
  const all = { ...(packageJson.dependencies || {}), ...(packageJson.optionalDependencies || {}) };
  for (const [name, spec] of Object.entries(all)) {
    const value = String(spec);
    if (/^(?:git\+|git:|https?:|file:|link:|workspace:)/i.test(value)) findings.push({ severity: 'moderate', code: 'non-registry-dependency', package: name, message: `${name} uses a non-registry dependency source (${value.slice(0, 120)}).` });
    if (value === '*' || value === 'latest') findings.push({ severity: 'moderate', code: 'unbounded-version', package: name, message: `${name} does not pin a predictable version range.` });
  }
  const scripts = packageJson.scripts || {};
  for (const name of ['preinstall', 'install', 'postinstall']) {
    if (scripts[name]) findings.push({ severity: 'info', code: 'install-script', message: `package.json defines a ${name} script. Review it before installing dependencies.` });
  }
  return findings;
}

class DependencyScanner {
  constructor(db, logger = console) {
    this.db = db;
    this.logger = logger;
    this.active = 0;
    this.queue = [];
    this.children = new Set();
    this.operations = new Set();
    this.stopping = false;
  }

  queueLength() { return this.queue.length; }

  acquire() {
    if (this.stopping) return Promise.reject(new Error('Dependency scanning is shutting down.'));
    if (this.active < DEPENDENCY_SCAN_WORKERS) { this.active += 1; return Promise.resolve(); }
    if (this.queue.length >= DEPENDENCY_SCAN_QUEUE_LIMIT) return Promise.reject(new Error('Too many dependency scans are queued.'));
    return new Promise((resolve, reject) => this.queue.push({ resolve, reject }));
  }

  release() {
    const next = this.queue.shift();
    if (next) next.resolve();
    else this.active = Math.max(0, this.active - 1);
  }

  async scan(site) {
    const operation = (async () => {
      await this.acquire();
      try { return await this._scan(site); }
      finally { this.release(); }
    })();
    this.operations.add(operation);
    try { return await operation; }
    finally { this.operations.delete(operation); }
  }

  async _scan(site) {
    const root = siteRoot(site);
    const packagePath = path.join(root, 'package.json');
    if (!(await realFileInsideAsync(root, packagePath))) throw new Error('A safe package.json file was not found.');
    let packageJson;
    try { packageJson = JSON.parse(await fs.promises.readFile(packagePath, 'utf8')); }
    catch { throw new Error('package.json is not valid JSON.'); }
    const lockfiles = ['package-lock.json', 'npm-shrinkwrap.json'];
    let lockfile = null;
    for (const name of lockfiles) {
      const candidate = path.join(root, name);
      if (await realFileInsideAsync(root, candidate)) { lockfile = name; break; }
    }
    const findings = staticFindings(packageJson, Boolean(lockfile));
    let audit = null;
    let registryError = null;
    if (lockfile) {
      const command = process.platform === 'win32' ? 'npm.cmd' : 'npm';
      try {
        audit = await new Promise((resolve, reject) => {
          const child = spawn(command, ['audit', '--json', '--omit=dev', '--package-lock-only'], { cwd: root, env: buildEnvironment({ NODE_ENV: 'production' }), stdio: ['ignore', 'pipe', 'pipe'], detached: process.platform !== 'win32' });
          this.children.add(child);
          let stdout = '';
          let stderr = '';
          let settled = false;
          const finish = (callback, value) => {
            if (settled) return;
            settled = true;
            clearTimeout(timer);
            this.children.delete(child);
            callback(value);
          };
          child.stdout.on('data', (chunk) => { stdout = tail(stdout, chunk.toString()); });
          child.stderr.on('data', (chunk) => { stderr = tail(stderr, chunk.toString(), 256 * 1024); });
          const timer = setTimeout(() => {
            try { process.platform !== 'win32' ? process.kill(-child.pid, 'SIGKILL') : child.kill('SIGKILL'); } catch { /* already gone */ }
            finish(reject, new Error('npm audit timed out.'));
          }, DEPENDENCY_SCAN_TIMEOUT_MS);
          timer.unref?.();
          child.once('error', (error) => finish(reject, error));
          child.once('close', (code) => {
            let parsed;
            try { parsed = JSON.parse(stdout || '{}'); }
            catch { return finish(reject, new Error(`npm audit returned invalid JSON. ${stderr.slice(-500)}`)); }
            // npm audit returns a non-zero code when vulnerabilities exist; parsed output is still valid.
            finish(resolve, { code, report: parsed });
          });
        });
      } catch (error) { registryError = error.message; }
    }

    const vulnerabilities = audit?.report?.metadata?.vulnerabilities || {};
    const result = {
      scannedAt: new Date().toISOString(),
      lockfile,
      packageName: String(packageJson.name || ''),
      findings,
      registryAvailable: Boolean(audit),
      registryError,
      vulnerabilities: {
        info: Number(vulnerabilities.info || 0),
        low: Number(vulnerabilities.low || 0),
        moderate: Number(vulnerabilities.moderate || 0),
        high: Number(vulnerabilities.high || 0),
        critical: Number(vulnerabilities.critical || 0),
        total: Number(vulnerabilities.total || 0)
      },
      audit: audit?.report || null
    };
    this.db.prepare(`INSERT INTO dependency_scans (site_id, result_json, created_at) VALUES (?, ?, CURRENT_TIMESTAMP)`).run(site.id, JSON.stringify(result));
    this.db.prepare(`DELETE FROM dependency_scans WHERE site_id = ? AND id NOT IN (SELECT id FROM dependency_scans WHERE site_id = ? ORDER BY id DESC LIMIT 10)`).run(site.id, site.id);
    return result;
  }

  latest(siteId) {
    const row = this.db.prepare('SELECT result_json FROM dependency_scans WHERE site_id = ? ORDER BY id DESC LIMIT 1').get(siteId);
    if (!row) return null;
    try { return JSON.parse(row.result_json); } catch { return null; }
  }

  async shutdown() {
    this.stopping = true;
    for (const job of this.queue.splice(0)) job.reject(new Error('Dependency scanning stopped during shutdown.'));
    const children = [...this.children];
    const exits = children.map((child) => new Promise((resolve) => child.once('close', resolve)));
    for (const child of children) {
      try { process.platform !== 'win32' ? process.kill(-child.pid, 'SIGTERM') : child.kill('SIGTERM'); } catch { /* gone */ }
    }
    if (children.length) {
      await Promise.race([
        Promise.allSettled(exits),
        new Promise((resolve) => setTimeout(resolve, 2000))
      ]);
      for (const child of this.children) {
        try { process.platform !== 'win32' ? process.kill(-child.pid, 'SIGKILL') : child.kill('SIGKILL'); } catch { /* gone */ }
      }
    }
    await Promise.race([
      Promise.allSettled([...this.operations]),
      new Promise((resolve) => setTimeout(resolve, 5000))
    ]);
  }
}

module.exports = { DependencyScanner, staticFindings };
