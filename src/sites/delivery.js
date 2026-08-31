// @ts-nocheck -- not part of this session's checkJs rollout yet.
// This file still has genuine `tsc --noEmit` findings (mostly narrow
// `let x = null`-style inference and untyped Express handlers, the same
// patterns already fixed across most of src/) that need real per-file
// JSDoc work to resolve, not a suppression. Tracked as follow-up work;
// see tsconfig.json and docs/development.md. Do not add more files here
// without a similar comment and a plan to remove it.
'use strict';

const { CoreSiteManager } = require('./core');
const { fs, path, crypto, http, https, spawn, zlib, express, NPM_INSTALL_TIMEOUT_MS, NPM_INSTALL_WORKERS, NPM_INSTALL_QUEUE_LIMIT, MINIFY_MAX_BYTES, MINIFY_CACHE_BYTES, MINIFY_QUEUE_LIMIT, safeRelativePath, certbotPaths, hasCertificate, buildEnvironment, gzipAsync, brotliAsync, COMPRESSIBLE_EXTENSIONS, appendTail, cacheEntryBytes, processOptions, terminateChild, realFileInsideAsync, siteRoot } = require('./shared');

class DeliverySiteManager extends CoreSiteManager {
  publicServer(site, handler) {
    if (site.ssl_enabled) {
      if (!site.domain || !hasCertificate(site.domain)) throw new Error('SSL is enabled but the certificate files are missing.');
      const certificate = certbotPaths(site.domain);
      return {
        protocol: 'https',
        server: https.createServer({ key: fs.readFileSync(certificate.key), cert: fs.readFileSync(certificate.cert) }, handler)
      };
    }
    return { protocol: 'http', server: http.createServer(handler) };
  }

  applyHeaders(site, res, req = null) {
    const preset = site.security_preset || 'balanced';
    if (preset !== 'off') {
      res.setHeader('X-Content-Type-Options', 'nosniff');
      res.setHeader('Referrer-Policy', preset === 'strict' ? 'no-referrer' : 'strict-origin-when-cross-origin');
      res.setHeader('X-Frame-Options', 'DENY');
      res.setHeader('Permissions-Policy', 'camera=(), microphone=(), geolocation=(), payment=(), usb=()');
      if (site.ssl_enabled) res.setHeader('Strict-Transport-Security', preset === 'strict' ? 'max-age=31536000; includeSubDomains' : 'max-age=31536000');
      const csp = site.csp || (preset === 'strict'
        ? "default-src 'self'; base-uri 'self'; object-src 'none'; frame-ancestors 'none'; form-action 'self'; upgrade-insecure-requests"
        : preset === 'balanced' ? "object-src 'none'; base-uri 'self'; frame-ancestors 'none'" : '');
      if (csp) res.setHeader('Content-Security-Policy', csp);
    }
    for (const [name, value] of Object.entries(site.headers || {})) res.setHeader(name, value);
    if (req) {
      const pathname = (() => { try { return new URL(req.url, 'http://localhost').pathname; } catch { return '/'; } })();
      for (const rule of site.cacheRules || []) {
        if (!rule || typeof rule !== 'object') continue;
        const pattern = String(rule.path || '');
        if (!pattern || !(rule.type === 'prefix' ? pathname.startsWith(pattern) : pathname === pattern)) continue;
        const seconds = Math.min(Math.max(Number(rule.seconds) || 0, 0), 31536000);
        res.setHeader('Cache-Control', seconds > 0 ? `public, max-age=${seconds}${rule.immutable ? ', immutable' : ''}` : 'no-store');
        break;
      }
    }
  }

  removeCachedEntry(key) {
    const entry = this.minifyCache.get(key);
    if (!entry) return;
    this.minifyCache.delete(key);
    this.minifyCacheBytes = Math.max(0, this.minifyCacheBytes - Number(entry.cacheBytes || cacheEntryBytes(entry)));
    if (entry.cacheKey === key) entry.cacheKey = null;
  }

  touchCachedEntry(entry) {
    const key = entry?.cacheKey;
    if (!key || this.minifyCache.get(key) !== entry) return;
    this.minifyCache.delete(key);
    this.minifyCache.set(key, entry);
  }

  trimMinifyCache(protectedKey = null) {
    while (this.minifyCacheBytes > MINIFY_CACHE_BYTES && this.minifyCache.size) {
      let candidate = this.minifyCache.keys().next().value;
      if (candidate === protectedKey && this.minifyCache.size > 1) {
        candidate = [...this.minifyCache.keys()].find((key) => key !== protectedKey);
      }
      this.removeCachedEntry(candidate);
    }
  }

  cacheMinified(key, absolute, entry) {
    entry.encoded ||= {};
    entry.encodedPending ||= {};
    entry.cacheBytes = cacheEntryBytes(entry);
    entry.cacheKey = null;
    if (entry.cacheBytes > MINIFY_CACHE_BYTES) return;
    this.removeCachedEntry(key);
    for (const [existingKey, existing] of this.minifyCache) {
      if (existing.absolute === absolute && existingKey !== key) this.removeCachedEntry(existingKey);
    }
    entry.cacheKey = key;
    this.minifyCache.set(key, entry);
    this.minifyCacheBytes += entry.cacheBytes;
    this.trimMinifyCache(key);
  }

  async minifiedFile(site, absolute) {
    const stat = await fs.promises.stat(absolute);
    if (stat.size > MINIFY_MAX_BYTES) return null;
    const key = `${absolute}:${stat.mtimeMs}:${stat.size}:${site.minify ? 1 : 0}:${site.obfuscate ? 1 : 0}`;
    const cached = this.minifyCache.get(key);
    if (cached) {
      this.minifyCache.delete(key);
      this.minifyCache.set(key, cached);
      return cached;
    }
    if (this.minifyPending.has(key)) return this.minifyPending.get(key);

    const pending = (async () => {
      const extension = path.extname(absolute).toLowerCase();
      if (this.minifyWorkers.size + this.minifyQueue.length >= MINIFY_QUEUE_LIMIT) {
        const now = Date.now();
        if (now - this.minifyBusyLoggedAt > 60_000) {
          this.minifyBusyLoggedAt = now;
          this.log(site.id, 'error', 'Asset transformation queue is full; temporarily serving original files.');
        }
        return null;
      }
      const source = await fs.promises.readFile(absolute, 'utf8');
      let output;
      try {
        output = await this.runMinifier({
          source,
          extension,
          minify: Boolean(site.minify),
          obfuscate: Boolean(site.obfuscate)
        });
      } catch (error) {
        this.log(site.id, 'error', `Asset transformation failed for ${path.basename(absolute)}; serving the original file: ${error.message}`);
        output = source;
      }
      const data = Buffer.from(output, 'utf8');
      const digest = crypto.createHash('sha256').update(data).digest('base64url').slice(0, 24);
      const entry = {
        absolute,
        data,
        bytes: data.length,
        lastModified: stat.mtime.toUTCString(),
        etag: `"${digest}"`
      };
      this.cacheMinified(key, absolute, entry);
      return entry;
    })();

    this.minifyPending.set(key, pending);
    try { return await pending; }
    finally { this.minifyPending.delete(key); }
  }

  acceptedEncoding(req) {
    const accepted = new Map();
    for (const item of String(req.headers['accept-encoding'] || '').toLowerCase().split(',')) {
      const [nameRaw, ...parameters] = item.trim().split(';');
      const name = nameRaw.trim();
      if (!name) continue;
      let quality = 1;
      for (const parameter of parameters) {
        const match = /^q\s*=\s*(0(?:\.\d{0,3})?|1(?:\.0{0,3})?)$/i.exec(parameter.trim());
        if (match) quality = Number(match[1]);
      }
      accepted.set(name, Math.max(accepted.get(name) || 0, quality));
    }
    const wildcard = accepted.get('*') || 0;
    const brotli = accepted.has('br') ? accepted.get('br') : wildcard;
    const gzip = accepted.has('gzip') ? accepted.get('gzip') : wildcard;
    if (brotli > 0 && brotli >= gzip) return 'br';
    if (gzip > 0) return 'gzip';
    return null;
  }

  async encodedData(entry, encoding) {
    if (!encoding || entry.data.length < 1024) return { data: entry.data, encoding: null };
    entry.encoded ||= {};
    entry.encodedPending ||= {};
    if (entry.encoded[encoding]) {
      this.touchCachedEntry(entry);
      return { data: entry.encoded[encoding], encoding };
    }
    if (entry.encodedPending[encoding]) {
      try { return { data: await entry.encodedPending[encoding], encoding }; }
      catch { return { data: entry.data, encoding: null }; }
    }

    const pending = this.runCompression(() => encoding === 'br'
      ? brotliAsync(entry.data, { params: { [zlib.constants.BROTLI_PARAM_QUALITY]: 5 } })
      : gzipAsync(entry.data, { level: 6 }));
    entry.encodedPending[encoding] = pending;
    try {
      const data = await pending;
      entry.encoded[encoding] = data;
      const key = entry.cacheKey;
      if (key && this.minifyCache.get(key) === entry) {
        const previousBytes = Number(entry.cacheBytes || entry.bytes || 0);
        entry.cacheBytes = cacheEntryBytes(entry);
        this.minifyCacheBytes += entry.cacheBytes - previousBytes;
        this.touchCachedEntry(entry);
        this.trimMinifyCache(key);
      }
      return { data, encoding };
    } catch (error) {
      const now = Date.now();
      if (now - this.compressionBusyLoggedAt > 60_000) {
        this.compressionBusyLoggedAt = now;
        this.log(null, 'error', `Static compression was skipped; serving the original response: ${error.message}`);
      }
      return { data: entry.data, encoding: null };
    } finally {
      delete entry.encodedPending[encoding];
    }
  }

  async plainFile(site, absolute) {
    const stat = await fs.promises.stat(absolute);
    if (stat.size > MINIFY_MAX_BYTES) return null;
    const key = `plain:${absolute}:${stat.mtimeMs}:${stat.size}`;
    const cached = this.minifyCache.get(key);
    if (cached) {
      this.touchCachedEntry(cached);
      return cached;
    }
    const data = await fs.promises.readFile(absolute);
    const digest = crypto.createHash('sha256').update(data).digest('base64url').slice(0, 24);
    const entry = { absolute, data, bytes: data.length, lastModified: stat.mtime.toUTCString(), etag: `"${digest}"` };
    this.cacheMinified(key, absolute, entry);
    return entry;
  }

  async precompressedFile(root, absolute, encoding) {
    if (!encoding) return null;
    const candidate = `${absolute}.${encoding === 'br' ? 'br' : 'gz'}`;
    try {
      if (!(await realFileInsideAsync(root, candidate))) return null;
      const [sourceStat, encodedStat] = await Promise.all([fs.promises.stat(absolute), fs.promises.stat(candidate)]);
      if (!encodedStat.isFile() || encodedStat.mtimeMs < sourceStat.mtimeMs) return null;
      return { path: candidate, stat: encodedStat, encoding };
    } catch { return null; }
  }

  async sendEntry(site, absolute, entry, req, res) {
    res.type(path.extname(absolute));
    res.setHeader('Last-Modified', entry.lastModified);
    res.setHeader('Cache-Control', site.cache_seconds > 0 ? `public, max-age=${site.cache_seconds}` : 'no-cache');
    let encoded = { data: entry.data, encoding: null };
    if (site.compression && COMPRESSIBLE_EXTENSIONS.has(path.extname(absolute).toLowerCase())) {
      encoded = await this.encodedData(entry, this.acceptedEncoding(req));
      res.setHeader('Vary', 'Accept-Encoding');
      if (encoded.encoding) res.setHeader('Content-Encoding', encoded.encoding);
    }
    // A strong validator must identify the representation, not only the source
    // bytes. Otherwise a client can reuse a gzip/br response after receiving a
    // 304 for an identity request (or vice versa).
    const etag = encoded.encoding ? `${entry.etag.slice(0, -1)}-${encoded.encoding}"` : entry.etag;
    res.setHeader('ETag', etag);
    res.setHeader('Content-Length', String(encoded.data.length));
    if (req.fresh) { res.status(304).end(); return true; }
    if (req.method === 'HEAD') { res.end(); return true; }
    res.end(encoded.data);
    return true;
  }

  async sendPlainOptimized(site, absolute, req, res) {
    const encoding = site.compression ? this.acceptedEncoding(req) : null;
    const sidecar = await this.precompressedFile(siteRoot(site), absolute, encoding);
    if (sidecar) {
      const etag = `W/"${Math.floor(sidecar.stat.mtimeMs).toString(16)}-${sidecar.stat.size.toString(16)}-${sidecar.encoding}"`;
      res.type(path.extname(absolute));
      res.setHeader('Content-Encoding', sidecar.encoding);
      res.setHeader('Vary', 'Accept-Encoding');
      res.setHeader('ETag', etag);
      res.setHeader('Last-Modified', sidecar.stat.mtime.toUTCString());
      res.setHeader('Cache-Control', site.cache_seconds > 0 ? `public, max-age=${site.cache_seconds}` : 'no-cache');
      if (req.fresh) { res.status(304).end(); return true; }
      res.setHeader('Content-Length', String(sidecar.stat.size));
      if (req.method === 'HEAD') { res.end(); return true; }
      fs.createReadStream(sidecar.path).on('error', (error) => {
        if (!res.headersSent) res.status(404).end();
        else res.destroy(error);
      }).pipe(res);
      return true;
    }
    const entry = await this.plainFile(site, absolute);
    return entry ? this.sendEntry(site, absolute, entry, req, res) : false;
  }

  async sendMinified(site, absolute, req, res) {
    const entry = await this.minifiedFile(site, absolute);
    if (!entry) return false;
    return this.sendEntry(site, absolute, entry, req, res);
  }

  createStaticApp(site, root, entry) {
    const app = express();
    app.disable('x-powered-by');
    app.use((req, res, next) => {
      this.applyHeaders(site, res, req);
      next();
    });

    app.use(async (req, res, next) => {
      if (!['GET', 'HEAD'].includes(req.method) || req.path === '/') return next();
      try {
        const decoded = decodeURIComponent(req.path);
        const relative = safeRelativePath(decoded.replace(/^\/+/, ''), 'Request path');
        const absolute = path.resolve(root, ...relative.split('/'));
        if (!absolute.startsWith(`${path.resolve(root)}${path.sep}`)) return res.sendStatus(404);
        try {
          await fs.promises.access(absolute);
          if (!(await realFileInsideAsync(root, absolute))) return res.sendStatus(404);
        } catch (error) {
          if (error.code !== 'ENOENT') return res.sendStatus(404);
        }
        next();
      } catch {
        res.sendStatus(404);
      }
    });

    app.use(async (req, res, next) => {
      if (!['GET', 'HEAD'].includes(req.method)) return next();
      try {
        const decoded = decodeURIComponent(req.path);
        const relative = decoded === '/' ? site.entry_file : safeRelativePath(decoded.replace(/^\/+/, ''), 'Request path');
        const absolute = path.resolve(root, ...relative.split('/'));
        const extension = path.extname(absolute).toLowerCase();
        if (!COMPRESSIBLE_EXTENSIONS.has(extension)) return next();
        if (!(await realFileInsideAsync(root, absolute))) return next();
        const transformed = (site.minify || site.obfuscate) && ['.html', '.htm', '.css', '.js', '.mjs'].includes(extension);
        if (transformed ? await this.sendMinified(site, absolute, req, res) : site.compression && await this.sendPlainOptimized(site, absolute, req, res)) return;
        next();
      } catch (error) {
        this.log(site.id, 'error', `Could not serve an optimized asset: ${error.message}`);
        next();
      }
    });

    app.use(express.static(root, {
      index: false,
      dotfiles: 'deny',
      fallthrough: true,
      maxAge: Math.max(0, site.cache_seconds) * 1000
    }));

    app.use(async (req, res) => {
      if (!['GET', 'HEAD'].includes(req.method)) return res.sendStatus(404);
      if (req.path === '/' || site.spa_fallback) {
        if (!(await realFileInsideAsync(root, entry))) return res.status(404).type('text/plain').send('Entry file not found');
        if ((site.minify || site.obfuscate) && ['.html', '.htm'].includes(path.extname(entry).toLowerCase())) {
          if (await this.sendMinified(site, entry, req, res)) return;
        } else if (site.compression && await this.sendPlainOptimized(site, entry, req, res)) return;
        return res.sendFile(entry);
      }
      const page = this.errorPage(site, 404, 'Not found');
      res.status(404).type(page.type).send(page.body);
    });
    return app;
  }

  async dependencyFingerprint(root) {
    const hash = crypto.createHash('sha256');
    for (const filename of ['package.json', 'package-lock.json', 'npm-shrinkwrap.json']) {
      const absolute = path.join(root, filename);
      if (await realFileInsideAsync(root, absolute)) {
        hash.update(filename);
        hash.update(await fs.promises.readFile(absolute));
      }
    }
    return hash.digest('hex');
  }

  async dependenciesAreCurrent(root) {
    const marker = path.join(root, '.sham', 'dependency-state.json');
    try {
      const [modules, markerText] = await Promise.all([
        fs.promises.stat(path.join(root, 'node_modules')),
        fs.promises.readFile(marker, 'utf8')
      ]);
      if (!modules.isDirectory()) return false;
      const stored = JSON.parse(markerText);
      return stored.fingerprint === await this.dependencyFingerprint(root);
    } catch {
      return false;
    }
  }

  async ensureDependencies(site) {
    const root = siteRoot(site);
    if (await this.dependenciesAreCurrent(root)) {
      this.log(site.id, 'info', 'Dependencies are already current; skipped npm install.');
      return;
    }
    await this.runInstall(site);
  }

  acquireInstallSlot() {
    if (this.installStopping) return Promise.reject(new Error('Dependency installation is shutting down.'));
    if (this.installActive < NPM_INSTALL_WORKERS) {
      this.installActive += 1;
      return Promise.resolve();
    }
    if (this.installQueue.length >= NPM_INSTALL_QUEUE_LIMIT) {
      return Promise.reject(new Error('Too many dependency installations are queued. Try again shortly.'));
    }
    return new Promise((resolve, reject) => this.installQueue.push({ resolve, reject }));
  }

  releaseInstallSlot() {
    const next = this.installQueue.shift();
    if (next) {
      next.resolve();
      return;
    }
    this.installActive = Math.max(0, this.installActive - 1);
  }

  async runInstall(siteOrId, { fresh = false } = {}) {
    const site = typeof siteOrId === 'object' ? siteOrId : this.getSite(siteOrId);
    if (!site) throw new Error('Site not found.');
    if (this.installing.has(site.id)) return this.installing.get(site.id);
    const operation = (async () => {
      await this.acquireInstallSlot();
      try { return await this._runInstall(site, { fresh }); }
      finally { this.releaseInstallSlot(); }
    })();
    this.installing.set(site.id, operation);
    try { return await operation; }
    finally { this.installing.delete(site.id); }
  }

  async _runInstall(site, { fresh = false } = {}) {
    const root = siteRoot(site);
    const packageFile = path.join(root, 'package.json');
    if (!(await realFileInsideAsync(root, packageFile))) throw new Error('A regular package.json file was not found in this website.');
    const lockfile = path.join(root, 'package-lock.json');
    if (fresh) {
      this.log(site.id, 'info', 'Removing existing Node.js dependencies before a fresh install…');
      await fs.promises.rm(path.join(root, 'node_modules'), { recursive: true, force: true, maxRetries: 2 });
    }
    const npmCommand = fresh && await realFileInsideAsync(root, lockfile) ? 'ci' : 'install';
    this.log(site.id, 'info', `Running npm ${npmCommand} --omit=dev…`);
    const command = process.platform === 'win32' ? 'npm.cmd' : 'npm';
    await new Promise((resolve, reject) => {
      const child = spawn(command, [npmCommand, '--omit=dev', '--no-audit', '--no-fund'], processOptions({
        cwd: root,
        env: buildEnvironment({ NODE_ENV: 'production' }),
        stdio: ['ignore', 'pipe', 'pipe']
      }));
      this.installProcesses.set(site.id, child);
      let output = '';
      let settled = false;
      let timedOut = false;
      let timer;
      let forceTimer;
      let fallbackTimer;
      const finish = (callback, value) => {
        if (settled) return;
        settled = true;
        clearTimeout(timer);
        clearTimeout(forceTimer);
        clearTimeout(fallbackTimer);
        if (this.installProcesses.get(site.id) === child) this.installProcesses.delete(site.id);
        callback(value);
      };
      const logChunk = (level, chunk) => {
        const text = chunk.toString();
        output = appendTail(output, text);
        for (const line of text.split(/\r?\n/).filter(Boolean)) this.logOutput(site.id, level, `npm: ${line.slice(0, 1000)}`);
      };
      child.stdout.on('data', (chunk) => logChunk('info', chunk));
      child.stderr.on('data', (chunk) => logChunk('error', chunk));
      timer = setTimeout(() => {
        timedOut = true;
        terminateChild(child, 'SIGTERM');
        forceTimer = setTimeout(() => {
          terminateChild(child, 'SIGKILL');
          fallbackTimer = setTimeout(() => finish(reject, new Error('npm install timed out and did not exit after termination.')), 3000);
          fallbackTimer.unref?.();
        }, 2000);
        forceTimer.unref?.();
      }, NPM_INSTALL_TIMEOUT_MS);
      timer.unref?.();
      child.once('error', (error) => { this.flushOutputLogs(site.id); finish(reject, new Error(`npm could not start: ${error.message}`)); });
      child.once('close', (code) => {
        this.flushOutputLogs(site.id);
        if (timedOut) finish(reject, new Error('npm install timed out.'));
        else if (code === 0) finish(resolve);
        else finish(reject, new Error(`npm install exited with code ${code}. ${output.trim().slice(-1200)}`));
      });
    });
    const markerDir = path.join(root, '.sham');
    await fs.promises.mkdir(markerDir, { recursive: true });
    await fs.promises.writeFile(path.join(markerDir, 'dependency-state.json'), JSON.stringify({
      fingerprint: await this.dependencyFingerprint(root),
      installedAt: new Date().toISOString()
    }, null, 2), { mode: 0o600 });
    this.log(site.id, 'info', `npm ${npmCommand} completed${fresh ? ' with a fresh dependency tree' : ''}.`);
  }

}

module.exports = { DeliverySiteManager };
