'use strict';

// This harness deliberately uses SHAM's HTTP API and child-process bootstrap.
// It does not import server internals or write deployment state directly.
const assert = require('node:assert/strict');
const fs = require('node:fs/promises');
const http = require('node:http');
const net = require('node:net');
const os = require('node:os');
const path = require('node:path');
const { once } = require('node:events');
const { execFile } = require('node:child_process');
const { promisify } = require('node:util');

const execFileAsync = promisify(execFile);
const ROOT = path.resolve(__dirname, '..', '..');
const FIXTURES = path.join(__dirname, '..', 'fixtures', 'integration');

async function freePort() {
  const server = net.createServer();
  server.unref();
  await new Promise((resolve, reject) => server.once('error', reject).listen(0, '127.0.0.1', resolve));
  const { port } = server.address();
  await new Promise((resolve) => server.close(resolve));
  return port;
}

async function waitFor(check, { timeoutMs = 20_000, intervalMs = 100, message = 'Timed out waiting for test condition.' } = {}) {
  const deadline = Date.now() + timeoutMs;
  let lastError = null;
  while (Date.now() < deadline) {
    try {
      const value = await check();
      if (value) return value;
    } catch (error) { lastError = error; }
    await new Promise((resolve) => setTimeout(resolve, intervalMs));
  }
  throw new Error(`${message}${lastError ? ` Last error: ${lastError.message}` : ''}`);
}

async function run(command, args, options = {}) {
  return execFileAsync(command, args, { ...options, maxBuffer: 2 * 1024 * 1024 });
}

function staticFileServer(root) {
  const server = http.createServer(async (req, res) => {
    try {
      const relative = decodeURIComponent(new URL(req.url, 'http://localhost').pathname).replace(/^\/+/, '');
      const file = path.resolve(root, relative);
      if (!file.startsWith(`${root}${path.sep}`)) throw new Error('invalid path');
      const body = await fs.readFile(file);
      res.writeHead(200, { 'content-length': body.length });
      res.end(body);
    } catch { res.writeHead(404).end(); }
  });
  return server;
}

class ShamHarness {
  constructor({ appRoot = ROOT, dataDir = '', fixture = 'node-v1' } = {}) {
    this.appRoot = appRoot;
    this.suppliedDataDir = dataDir;
    this.dataDir = '';
    this.port = 0;
    this.edgePort = 0;
    this.baseUrl = '';
    this.cookie = '';
    this.process = null;
    this.runtimeAgent = null;
    this.output = '';
    this.gitRoot = '';
    this.gitWorktree = '';
    this.gitBare = '';
    this.gitServer = null;
    this.gitUrl = '';
    this.fixture = fixture;
  }

  async start({ docker = false, register = true } = {}) {
    this.dataDir = this.suppliedDataDir || await fs.mkdtemp(path.join(os.tmpdir(), 'sham-integration-'));
    if (this.suppliedDataDir) await fs.mkdir(this.dataDir, { recursive: true, mode: 0o700 });
    this.port = await freePort();
    this.edgePort = await freePort();
    this.baseUrl = `http://127.0.0.1:${this.port}`;
    await this.startGitRepository();
    if (docker) await this.startRuntimeAgent();
    await this.startSham();
    if (register) await this.registerAdmin();
    return this;
  }

  async startSham() {
    const { spawn } = require('node:child_process');
    this.process = spawn(process.execPath, ['src/bootstrap.js'], {
      cwd: this.appRoot,
      env: {
        ...process.env,
        NODE_ENV: 'test',
        SHAM_TEST_MODE: '1',
        SHAM_DATA_PATH: this.dataDir,
        SHAM_HOST: '127.0.0.1',
        SHAM_PORT: String(this.port),
        SHAM_EDGE_HOST: '127.0.0.1',
        SHAM_EDGE_HTTP_PORT: String(this.edgePort),
        SHAM_EDGE_HTTPS_PORT: '0',
        SHAM_JWT_SECRET: 'integration-only-secret-at-least-thirty-two-characters',
        SHAM_PUBLIC_ORIGIN: this.baseUrl
      },
      stdio: ['ignore', 'pipe', 'pipe'],
      detached: process.platform !== 'win32'
    });
    this.process.stdout.on('data', (chunk) => { this.output = `${this.output}${chunk}`.slice(-80_000); });
    this.process.stderr.on('data', (chunk) => { this.output = `${this.output}${chunk}`.slice(-80_000); });
    await waitFor(async () => (await fetch(`${this.baseUrl}/api/health`)).ok, {
      message: `SHAM did not become healthy.\n${this.output}`
    });
  }

  async startRuntimeAgent() {
    const { spawn } = require('node:child_process');
    this.runtimeAgent = spawn(process.execPath, ['runtime-agent/index.js'], {
      cwd: this.appRoot,
      env: {
        ...process.env,
        NODE_ENV: 'test', SHAM_TEST_MODE: '1', SHAM_DATA_PATH: this.dataDir,
        SHAM_DOCKER_HOST_DATA_PATH: this.dataDir,
        SHAM_DOCKER_INTERNAL_NETWORK: `sham-test-internal-${path.basename(this.dataDir)}`,
        SHAM_DOCKER_EGRESS_NETWORK: `sham-test-egress-${path.basename(this.dataDir)}`
      },
      stdio: ['ignore', 'pipe', 'pipe'], detached: process.platform !== 'win32'
    });
    this.runtimeAgent.stdout.on('data', (chunk) => { this.output = `${this.output}${chunk}`.slice(-80_000); });
    this.runtimeAgent.stderr.on('data', (chunk) => { this.output = `${this.output}${chunk}`.slice(-80_000); });
    const socket = path.join(this.dataDir, 'runtime-agent', 'agent.sock');
    await waitFor(async () => {
      try { await fs.access(socket); return true; } catch { return false; }
    }, { message: `Runtime agent did not start.\n${this.output}` });
  }

  async restartSham() {
    await this.stopSham();
    await this.startSham();
  }

  async stopSham() {
    if (!this.process || this.process.exitCode !== null) return;
    const child = this.process;
    child.kill('SIGTERM');
    await Promise.race([once(child, 'exit'), new Promise((resolve) => setTimeout(resolve, 8_000))]);
    if (child.exitCode === null) child.kill('SIGKILL');
  }

  async request(endpoint, { method = 'GET', body, headers = {} } = {}) {
    const response = await fetch(`${this.baseUrl}${endpoint}`, {
      method,
      headers: { ...(body === undefined ? {} : { 'content-type': 'application/json' }), ...(this.cookie ? { cookie: this.cookie } : {}), ...headers },
      body: body === undefined ? undefined : JSON.stringify(body)
    });
    const setCookie = response.headers.get('set-cookie');
    if (setCookie) this.cookie = setCookie.split(';', 1)[0];
    const text = await response.text();
    let data;
    try { data = text ? JSON.parse(text) : null; } catch { data = text; }
    if (!response.ok) throw new Error(`${method} ${endpoint} returned ${response.status}: ${data?.error || text}`);
    return data;
  }

  async registerAdmin() {
    const setup = await this.request('/api/bootstrap');
    assert.equal(setup.needsSetup, true);
    await this.request('/api/auth/register', { method: 'POST', body: { username: 'integration-admin', password: 'integration-password-123!' } });
  }

  async loginAdmin() {
    // Authentication/session formats can change across an upgrade. Exercise
    // the supported login flow instead of carrying a legacy cookie into the
    // upgraded process.
    this.cookie = '';
    const result = await this.request('/api/auth/login', {
      method: 'POST',
      body: { username: 'integration-admin', password: 'integration-password-123!' }
    });
    assert.equal(result.mfaRequired, undefined, 'integration administrator unexpectedly requires MFA');
    assert.ok(this.cookie, 'administrator login did not issue a session cookie');
    return result.user;
  }

  async startGitRepository() {
    this.gitRoot = await fs.mkdtemp(path.join(os.tmpdir(), 'sham-git-fixture-'));
    this.gitWorktree = path.join(this.gitRoot, 'work');
    this.gitBare = path.join(this.gitRoot, 'fixture.git');
    await fs.mkdir(this.gitWorktree);
    await fs.cp(path.join(FIXTURES, this.fixture), this.gitWorktree, { recursive: true });
    await run('git', ['init', '--initial-branch=main'], { cwd: this.gitWorktree });
    await run('git', ['config', 'user.email', 'integration@example.test'], { cwd: this.gitWorktree });
    await run('git', ['config', 'user.name', 'SHAM integration'], { cwd: this.gitWorktree });
    await run('git', ['add', '.'], { cwd: this.gitWorktree });
    await run('git', ['commit', '-m', 'version 1'], { cwd: this.gitWorktree });
    await run('git', ['clone', '--bare', this.gitWorktree, this.gitBare]);
    await run('git', ['update-server-info'], { cwd: this.gitBare });
    this.gitServer = staticFileServer(this.gitRoot);
    await new Promise((resolve) => this.gitServer.listen(0, '127.0.0.1', resolve));
    this.gitUrl = `http://127.0.0.1:${this.gitServer.address().port}/fixture.git`;
  }

  async publishFixture(name, message = name) {
    await fs.rm(this.gitWorktree, { recursive: true, force: true });
    await run('git', ['clone', this.gitBare, this.gitWorktree]);
    // Each fixture revision is a real commit. Configure its identity locally
    // so the test remains self-contained on fresh CI runners.
    await run('git', ['config', 'user.email', 'integration@example.test'], { cwd: this.gitWorktree });
    await run('git', ['config', 'user.name', 'SHAM integration'], { cwd: this.gitWorktree });
    await fs.cp(path.join(FIXTURES, name), this.gitWorktree, { recursive: true });
    await run('git', ['add', '.'], { cwd: this.gitWorktree });
    await run('git', ['commit', '-m', message], { cwd: this.gitWorktree });
    await run('git', ['push', 'origin', 'main'], { cwd: this.gitWorktree });
    await run('git', ['update-server-info'], { cwd: this.gitBare });
  }

  async useSmartGitHttp() {
    const { spawn } = require('node:child_process');
    this.gitServer.closeIdleConnections?.();
    this.gitServer.closeAllConnections?.();
    await new Promise((resolve) => this.gitServer.close(resolve));
    this.gitServer = http.createServer((request, response) => {
      const url = new URL(request.url, 'http://localhost');
      const child = spawn('git', ['http-backend'], {
        env: {
          ...process.env,
          GIT_PROJECT_ROOT: this.gitRoot,
          GIT_HTTP_EXPORT_ALL: '1',
          PATH_INFO: url.pathname,
          QUERY_STRING: url.search.slice(1),
          REQUEST_METHOD: request.method,
          CONTENT_TYPE: request.headers['content-type'] || '',
          CONTENT_LENGTH: request.headers['content-length'] || '',
          REMOTE_ADDR: '127.0.0.1'
        }, stdio: ['pipe', 'pipe', 'pipe']
      });
      const chunks = [];
      child.stdout.on('data', (chunk) => chunks.push(chunk));
      child.once('error', () => response.writeHead(500).end());
      child.once('exit', (code) => {
        if (response.writableEnded) return;
        if (code !== 0) return response.writeHead(500).end();
        const output = Buffer.concat(chunks);
        const separator = output.indexOf('\r\n\r\n');
        if (separator < 0) return response.writeHead(500).end();
        const headers = output.subarray(0, separator).toString('utf8').split('\r\n');
        let status = 200;
        for (const header of headers) {
          const [name, ...values] = header.split(':');
          if (name.toLowerCase() === 'status') status = Number(values.join(':').trim().split(/\s+/, 1)[0]) || 500;
          else if (name && values.length) response.setHeader(name, values.join(':').trim());
        }
        response.writeHead(status).end(output.subarray(separator + 4));
      });
      request.pipe(child.stdin);
    });
    await new Promise((resolve) => this.gitServer.listen(0, '127.0.0.1', resolve));
    this.gitUrl = `http://127.0.0.1:${this.gitServer.address().port}/fixture.git`;
  }

  async createNodeSite({ name = 'integration-node', domain = 'node.integration.test', enabled = true, additionalListeners = [] } = {}) {
    const sitePort = await freePort();
    const result = await this.request('/api/sites', {
      method: 'POST',
      body: {
        name, port: sitePort, runtimeType: 'node', nodeEntry: 'server.js', enabled,
        edgeEnabled: true, domain, gitUrl: this.gitUrl, gitBranch: 'main', source: 'git',
        readinessType: 'http', readinessPath: '/health', healthCheckType: 'http', healthCheckPath: '/health',
        startupTimeoutSeconds: 3, blueGreenDrainSeconds: 0, additionalListeners
      }
    });
    return result.site;
  }

  async createComposeSite({ name = 'integration-compose', domain = 'compose.integration.test' } = {}) {
    const sitePort = await freePort();
    const result = await this.request('/api/sites', {
      method: 'POST',
      body: {
        name, port: sitePort, runtimeType: 'compose', composeFile: 'compose.yaml', composeService: 'app', enabled: true,
        edgeEnabled: true, domain, gitUrl: this.gitUrl, gitBranch: 'main', source: 'git',
        readinessType: 'http', readinessPath: '/', startupTimeoutSeconds: 60, blueGreenDrainSeconds: 0
      }
    });
    return result.site;
  }

  async deployGit(site) {
    return this.request(`/api/sites/${site.id}/deploy/git`, { method: 'POST', body: { url: this.gitUrl, branch: 'main' } });
  }

  async edgeText(domain) {
    return new Promise((resolve, reject) => {
      const request = http.request({ host: '127.0.0.1', port: this.edgePort, path: '/', headers: { Host: domain } }, (response) => {
        const chunks = [];
        response.on('data', (chunk) => chunks.push(chunk));
        response.once('end', () => resolve({ status: response.statusCode, body: Buffer.concat(chunks).toString('utf8') }));
      });
      request.once('error', reject);
      request.end();
    });
  }

  async siteText(port) {
    return new Promise((resolve, reject) => {
      const request = http.request({ host: '127.0.0.1', port, path: '/' }, (response) => {
        const chunks = [];
        response.on('data', (chunk) => chunks.push(chunk));
        response.once('end', () => resolve({ status: response.statusCode, body: Buffer.concat(chunks).toString('utf8') }));
      });
      request.once('error', reject);
      request.end();
    });
  }

  async waitForSite(port, expected) {
    await waitFor(async () => {
      const response = await this.siteText(port);
      return response.status === 200 && response.body.includes(expected);
    }, { timeoutMs: 20_000, message: `Expected ${expected} from SHAM site listener on port ${port}.\n${this.output.slice(-4000)}` });
  }

  async waitForEdge(domain, expected) {
    return waitFor(async () => {
      const response = await this.edgeText(domain);
      return response.status === 200 && response.body === expected ? response : null;
    }, { message: `Expected ${expected} through SHAM edge proxy.\n${this.output}` });
  }

  async diagnostics() {
    let sites = null;
    let logs = null;
    try { sites = await this.request('/api/sites'); logs = await this.request('/api/runtime-logs?limit=100'); } catch { /* Shutdown failures should preserve original failure. */ }
    return JSON.stringify({ shamOutput: this.output, sites, logs }, null, 2);
  }

  async close() {
    await this.stopSham();
    if (this.runtimeAgent && this.runtimeAgent.exitCode === null) {
      this.runtimeAgent.kill('SIGTERM');
      await Promise.race([once(this.runtimeAgent, 'exit'), new Promise((resolve) => setTimeout(resolve, 8_000))]);
      if (this.runtimeAgent.exitCode === null) this.runtimeAgent.kill('SIGKILL');
    }
    if (this.gitServer) {
      this.gitServer.closeIdleConnections?.();
      this.gitServer.closeAllConnections?.();
      await new Promise((resolve) => this.gitServer.close(resolve));
    }
    if (this.dataDir) await fs.rm(this.dataDir, { recursive: true, force: true });
    if (this.gitRoot) await fs.rm(this.gitRoot, { recursive: true, force: true });
  }
}

module.exports = { ShamHarness, waitFor, freePort, ROOT, FIXTURES, run };
