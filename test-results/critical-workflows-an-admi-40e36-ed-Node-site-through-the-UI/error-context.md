# Instructions

- Following Playwright test failed.
- Explain why, be concise, respect Playwright best practices.
- Provide a snippet of code with the fix, if possible.

# Test info

- Name: critical-workflows.spec.js >> an administrator creates and deploys a Git-backed Node site through the UI
- Location: test/e2e/critical-workflows.spec.js:69:1

# Error details

```
Error: Expected SHAM_TEST_VERSION_1 through SHAM edge proxy.
(node:2438157) Warning: The 'NO_COLOR' env is ignored due to the 'FORCE_COLOR' env being set.
(Use `node --trace-warnings ...` to show where the warning was created)
SHAM dashboard listening on http://127.0.0.1:42595
SHAM data path: /tmp/sham-integration-oa5m6i
[site:1] Deployment queued.
[site:1] git: Cloning into '/tmp/sham-integration-oa5m6i/sites/site-d887bd2c-71cf-4feb-9b25-0cf646c5197f.git-1a15415c-b3de-49c5-8671-56ec8108bc67'...
[site:1] git: fatal: dumb http transport does not support shallow capabilities
[site:1] Git remote does not support shallow clones; retrying a full clone.
[site:1] git: Cloning into '/tmp/sham-integration-oa5m6i/sites/site-d887bd2c-71cf-4feb-9b25-0cf646c5197f.git-1a15415c-b3de-49c5-8671-56ec8108bc67'...
[site:1] Build completed for 85c446dce; activating release.
[site:1] Deployment activated successfully.

```

# Test source

```ts
  1   | 'use strict';
  2   | 
  3   | // This harness deliberately uses SHAM's HTTP API and child-process bootstrap.
  4   | // It does not import server internals or write deployment state directly.
  5   | const assert = require('node:assert/strict');
  6   | const fs = require('node:fs/promises');
  7   | const http = require('node:http');
  8   | const net = require('node:net');
  9   | const os = require('node:os');
  10  | const path = require('node:path');
  11  | const { once } = require('node:events');
  12  | const { execFile } = require('node:child_process');
  13  | const { promisify } = require('node:util');
  14  | 
  15  | const execFileAsync = promisify(execFile);
  16  | const ROOT = path.resolve(__dirname, '..', '..');
  17  | const FIXTURES = path.join(__dirname, '..', 'fixtures', 'integration');
  18  | 
  19  | async function freePort() {
  20  |   const server = net.createServer();
  21  |   server.unref();
  22  |   await new Promise((resolve, reject) => server.once('error', reject).listen(0, '127.0.0.1', resolve));
  23  |   const { port } = server.address();
  24  |   await new Promise((resolve) => server.close(resolve));
  25  |   return port;
  26  | }
  27  | 
  28  | async function waitFor(check, { timeoutMs = 20_000, intervalMs = 100, message = 'Timed out waiting for test condition.' } = {}) {
  29  |   const deadline = Date.now() + timeoutMs;
  30  |   let lastError = null;
  31  |   while (Date.now() < deadline) {
  32  |     try {
  33  |       const value = await check();
  34  |       if (value) return value;
  35  |     } catch (error) { lastError = error; }
  36  |     await new Promise((resolve) => setTimeout(resolve, intervalMs));
  37  |   }
> 38  |   throw new Error(`${message}${lastError ? ` Last error: ${lastError.message}` : ''}`);
      |         ^ Error: Expected SHAM_TEST_VERSION_1 through SHAM edge proxy.
  39  | }
  40  | 
  41  | async function run(command, args, options = {}) {
  42  |   return execFileAsync(command, args, { ...options, maxBuffer: 2 * 1024 * 1024 });
  43  | }
  44  | 
  45  | function staticFileServer(root) {
  46  |   const server = http.createServer(async (req, res) => {
  47  |     try {
  48  |       const relative = decodeURIComponent(new URL(req.url, 'http://localhost').pathname).replace(/^\/+/, '');
  49  |       const file = path.resolve(root, relative);
  50  |       if (!file.startsWith(`${root}${path.sep}`)) throw new Error('invalid path');
  51  |       const body = await fs.readFile(file);
  52  |       res.writeHead(200, { 'content-length': body.length });
  53  |       res.end(body);
  54  |     } catch { res.writeHead(404).end(); }
  55  |   });
  56  |   return server;
  57  | }
  58  | 
  59  | class ShamHarness {
  60  |   constructor({ appRoot = ROOT, dataDir = '' } = {}) {
  61  |     this.appRoot = appRoot;
  62  |     this.suppliedDataDir = dataDir;
  63  |     this.dataDir = '';
  64  |     this.port = 0;
  65  |     this.edgePort = 0;
  66  |     this.baseUrl = '';
  67  |     this.cookie = '';
  68  |     this.process = null;
  69  |     this.runtimeAgent = null;
  70  |     this.output = '';
  71  |     this.gitRoot = '';
  72  |     this.gitWorktree = '';
  73  |     this.gitBare = '';
  74  |     this.gitServer = null;
  75  |     this.gitUrl = '';
  76  |   }
  77  | 
  78  |   async start({ docker = false, register = true } = {}) {
  79  |     this.dataDir = this.suppliedDataDir || await fs.mkdtemp(path.join(os.tmpdir(), 'sham-integration-'));
  80  |     if (this.suppliedDataDir) await fs.mkdir(this.dataDir, { recursive: true, mode: 0o700 });
  81  |     this.port = await freePort();
  82  |     this.edgePort = await freePort();
  83  |     this.baseUrl = `http://127.0.0.1:${this.port}`;
  84  |     await this.startGitRepository();
  85  |     if (docker) await this.startRuntimeAgent();
  86  |     await this.startSham();
  87  |     if (register) await this.registerAdmin();
  88  |     return this;
  89  |   }
  90  | 
  91  |   async startSham() {
  92  |     const { spawn } = require('node:child_process');
  93  |     this.process = spawn(process.execPath, ['src/bootstrap.js'], {
  94  |       cwd: this.appRoot,
  95  |       env: {
  96  |         ...process.env,
  97  |         NODE_ENV: 'test',
  98  |         SHAM_TEST_MODE: '1',
  99  |         SHAM_DATA_PATH: this.dataDir,
  100 |         SHAM_HOST: '127.0.0.1',
  101 |         SHAM_PORT: String(this.port),
  102 |         SHAM_EDGE_HOST: '127.0.0.1',
  103 |         SHAM_EDGE_HTTP_PORT: String(this.edgePort),
  104 |         SHAM_EDGE_HTTPS_PORT: '0',
  105 |         SHAM_JWT_SECRET: 'integration-only-secret-at-least-thirty-two-characters',
  106 |         SHAM_PUBLIC_ORIGIN: this.baseUrl
  107 |       },
  108 |       stdio: ['ignore', 'pipe', 'pipe'],
  109 |       detached: process.platform !== 'win32'
  110 |     });
  111 |     this.process.stdout.on('data', (chunk) => { this.output = `${this.output}${chunk}`.slice(-80_000); });
  112 |     this.process.stderr.on('data', (chunk) => { this.output = `${this.output}${chunk}`.slice(-80_000); });
  113 |     await waitFor(async () => (await fetch(`${this.baseUrl}/api/health`)).ok, {
  114 |       message: `SHAM did not become healthy.\n${this.output}`
  115 |     });
  116 |   }
  117 | 
  118 |   async startRuntimeAgent() {
  119 |     const { spawn } = require('node:child_process');
  120 |     this.runtimeAgent = spawn(process.execPath, ['runtime-agent/index.js'], {
  121 |       cwd: this.appRoot,
  122 |       env: {
  123 |         ...process.env,
  124 |         NODE_ENV: 'test', SHAM_TEST_MODE: '1', SHAM_DATA_PATH: this.dataDir,
  125 |         SHAM_DOCKER_HOST_DATA_PATH: this.dataDir,
  126 |         SHAM_DOCKER_INTERNAL_NETWORK: `sham-test-internal-${path.basename(this.dataDir)}`,
  127 |         SHAM_DOCKER_EGRESS_NETWORK: `sham-test-egress-${path.basename(this.dataDir)}`
  128 |       },
  129 |       stdio: ['ignore', 'pipe', 'pipe'], detached: process.platform !== 'win32'
  130 |     });
  131 |     this.runtimeAgent.stdout.on('data', (chunk) => { this.output = `${this.output}${chunk}`.slice(-80_000); });
  132 |     this.runtimeAgent.stderr.on('data', (chunk) => { this.output = `${this.output}${chunk}`.slice(-80_000); });
  133 |     const socket = path.join(this.dataDir, 'runtime-agent', 'agent.sock');
  134 |     await waitFor(async () => {
  135 |       try { await fs.access(socket); return true; } catch { return false; }
  136 |     }, { message: `Runtime agent did not start.\n${this.output}` });
  137 |   }
  138 | 
```