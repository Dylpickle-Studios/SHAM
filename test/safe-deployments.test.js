const test = require('node:test');
const assert = require('node:assert/strict');

const { source: read } = require('./source-tree');

test('safe-deployment configuration rejects incompatible isolation and anti-bot combinations', () => {
  const { validateSiteInput } = require('../src/validation');
  assert.throws(() => validateSiteInput({ name: 'Static', runtimeType: 'static', port: 4120, runtimeIsolation: 'docker' }), /currently applies to Node\.js sites/);
  assert.throws(() => validateSiteInput({ name: 'Bot', runtimeType: 'static', port: 4121, domain: 'example.test', anubisEnabled: true }), /shared edge proxy/);
  assert.throws(() => validateSiteInput({ name: 'Metrics', runtimeType: 'node', port: 4123, domain: 'example.test', edgeEnabled: true, anubisEnabled: true, anubisPreset: 'custom', anubisPolicy: 'metrics:\n  bind: :9090' }), /metrics section is managed by SHAM/);
  const site = validateSiteInput({ name: 'Safe node', runtimeType: 'node', port: 4122, domain: 'example.test', edgeEnabled: true, runtimeIsolation: 'docker', anubisEnabled: true });
  assert.equal(site.runtime_isolation, 'docker');
  assert.equal(site.anubis_enabled, true);
});

test('scheduled jobs use bounded five-field cron parsing', () => {
  const source = read('src/operations-manager.js');
  assert.match(source, /function parseCron\(expression\)/);
  assert.match(source, /parts\.length !== 5/);
  assert.match(source, /five cron fields/);
  assert.match(source, /366 \* 24 \* 60/);
  assert.match(source, /function nextCronDate\(expression/);
});

test('backup credentials are masked in API payloads and preserved on blank updates', () => {
  const source = read('src/operations-manager.js');
  assert.match(source, /_backupSettings\(\)/);
  assert.match(source, /secretFields/);
  assert.match(source, /sensitive\.has\(key\).*continue/);
  assert.match(source, /backupSettings: this\.backupSettings\(\)/);
  assert.doesNotMatch(source.slice(source.indexOf('  backupSettings()'), source.indexOf('  saveBackupSettings')), /return \{[\s\S]*config\s*\}/);
});

test('Anubis sidecars are pinned, resource-limited, and use host-visible mounts', () => {
  const source = read('src/operations-manager.js');
  const config = read('src/config.js');
  const agentDocker = read('runtime-agent/docker.js');
  assert.match(config, /ghcr\.io\/techarohq\/anubis:v1\.26\.2/);
  assert.match(source, /client\.sidecarRun\(/);
  assert.match(source, /policyFile: policyPath/);
  // Only the agent resolves container mount sources to host-visible paths,
  // and only ever for its own pinned ANUBIS_IMAGE (never a caller-supplied one).
  assert.match(agentDocker, /hostBindPath\(params\.policyFile\)/);
  assert.match(agentDocker, /SHAM_DOCKER_HOST_DATA_PATH/);
  assert.match(agentDocker, /ANUBIS_IMAGE\]/);
  assert.match(agentDocker, /'--memory', '256m'/);
  assert.match(agentDocker, /'--cpus', '1'/);
  assert.match(agentDocker, /'--pids-limit', '128'/);
  assert.match(source, /this\.anubisPolicy\(site, metricsPort\)/);
  assert.match(source, /metrics:\\n {2}bind: "127\.0\.0\.1:\$\{metricsPort\}"/);
  assert.doesNotMatch(source, /METRICS_BIND=/);
});

test('Docker isolation keeps native host ingress and uses shared networks for a containerized control plane', () => {
  const source = read('src/site-manager.js');
  const agentDocker = read('runtime-agent/docker.js');
  const config = read('src/config.js');
  const overlay = read('docker-compose.isolation.yml');
  assert.match(config, /SHAM_DOCKER_INTERNAL_NETWORK/);
  assert.match(config, /SHAM_DOCKER_EGRESS_NETWORK/);
  // The control plane only decides which network a runtime should join; the
  // privileged agent is the only process that ever runs `docker network create`.
  assert.match(agentDocker, /'network', 'create', '--driver', 'bridge', '--label', MANAGED_LABEL/);
  assert.match(agentDocker, /if \(internal\) args\.push\('--internal'\)/);
  assert.match(source, /const network = site\.outbound_network \? DOCKER_EGRESS_NETWORK : DOCKER_INTERNAL_NETWORK/);
  assert.match(source, /internalHost = name/);
  assert.match(overlay, /internal: true/);
  assert.match(overlay, /sham_runtime_egress/);
  assert.doesNotMatch(source, /args\.push\('--network', 'none'\)/);
});

test('deploy webhooks are HMAC-authenticated, rate-limited, and serialized', () => {
  const server = read('src/server.js');
  const auth = server.slice(server.indexOf('function authenticateDeployWebhook'), server.indexOf("app.get('/api/sites/:id/operations'"));
  assert.match(server, /const webhookLimiter = createRateLimiter/);
  assert.match(auth, /webhookLimiter, authenticateDeployWebhook, serializeSiteMutation/);
  assert.match(auth, /createHmac\('sha256'/);
  assert.match(auth, /timingSafeEqual/);
  assert.match(auth, /DEPLOY_WEBHOOK_SECRET/);
});

test('SHAM update staging is worker-based and verifies signed archives', () => {
  const manager = read('src/update-manager.js');
  const worker = read('src/update-worker.js');
  const server = read('src/server.js');
  assert.match(manager, /new Worker\(path\.join\(__dirname, 'update-worker\.js'\)/);
  assert.match(worker, /SHAM-UPDATE-SIGNATURE-V1/);
  assert.match(worker, /crypto\.verify/);
  assert.match(manager, /This SHAM update is unsigned/);
  assert.match(manager, /changes runtime dependencies/);
  assert.match(server, /allowUnsigned: bool\(req\.body\.allowUnsigned/);
  assert.match(server, /updateManager\.shutdown\(\)/);
});

test('operational data and exports stay administrator-only', () => {
  const server = read('src/server.js');
  assert.match(server, /app\.get\('\/api\/sites\/:id\/operations', requireAuth, requireAdmin/);
  assert.match(server, /app\.get\('\/api\/sites\/:id\/config\/export', requireAuth, requireAdmin/);
  assert.match(server, /app\.get\('\/api\/runtime-logs\/search', requireAuth, requireAdmin/);
  assert.match(server, /directory_name: undefined/);
});

test('Operations UI exposes the new capabilities within the shared theme system', () => {
  const html = read('public/index.html');
  const app = read('public/app.js');
  const css = read('public/styles.css');
  for (const id of ['section-operations', 'site-runtime-isolation', 'site-anubis-enabled', 'git-deploy-form', 'environment-form', 'job-form', 'backup-form', 'update-form', 'update-allow-unsigned']) {
    assert.match(html, new RegExp(`id="${id}"`));
  }
  assert.match(app, /updateIsolationFields/);
  assert.match(app, /loadOperations/);
  assert.match(css, /\.operations-grid/);
  assert.match(css, /var\(--panel\)|var\(--surface/);
});


test('release activation validates runtime before committing release metadata', () => {
  const source = read('src/operations-manager.js');
  const activation = source.slice(source.indexOf('  async activateRelease('), source.indexOf('  async deployGit('));
  const rollback = source.slice(source.indexOf('  async rollbackRelease('), source.indexOf('  async pruneReleases('));
  assert.ok(activation.indexOf('await this.manager.start(site.id)') < activation.indexOf('transaction();'));
  assert.ok(rollback.indexOf('await this.manager.start(site.id)') < rollback.indexOf('transaction();'));
  assert.match(source, /runProcess\(GIT_BIN, \['rev-parse', 'HEAD'\]/);
  assert.match(source, /commitSha: cloned\.commitSha/);
});

test('overlapping scheduled jobs and failed previews are fully tracked and cleaned up', () => {
  const source = read('src/operations-manager.js');
  assert.match(source, /const activeRuns = this\.runningJobs\.get\(job\.id\) \|\| new Set\(\)/);
  assert.match(source, /activeRuns\.add\(operation\)/);
  assert.match(source, /flatMap\(\(runs\) => \[\.\.\.runs\]\)/);
  assert.match(source, /else if \(previewChild\) await terminateAndWait\(previewChild\)/);
});

test('external backup adapters preserve credentials and record concrete destinations', () => {
  const source = read('src/operations-manager.js');
  assert.match(source, /provider === 'local' && config\.destination/);
  assert.match(source, /COPYFILE_EXCL/);
  assert.match(source, /AWS_SESSION_TOKEN/);
  assert.match(source, /'--endpoint-url'/);
  assert.match(source, /sftp-key-/);
  assert.match(source, /UPDATE backup_runs SET destination = \?/);
});

test('Docker image and optional isolation overlay include required tooling without enabling the socket by default', () => {
  const dockerfile = read('Dockerfile');
  const base = read('docker-compose.yml');
  const overlay = read('docker-compose.isolation.yml');
  assert.match(dockerfile, /awscli[\s\S]*docker\.io[\s\S]*git[\s\S]*restic/);
  assert.match(dockerfile, /CMD \["node", "src\/bootstrap\.js"\]/);
  assert.doesNotMatch(dockerfile, /EXPOSE .*4100-4199/);
  assert.doesNotMatch(base, /docker\.sock/);
  assert.match(overlay, /\/var\/run\/docker\.sock/);
  assert.match(overlay, /SHAM_DOCKER_HOST_DATA_PATH/);
  assert.match(overlay, /control over containers on the host/);
});

test('operations readiness reports actual Docker prerequisites and documents deployment headers and networks', () => {
  const operations = read('src/operations-manager.js');
  const app = read('public/app.js');
  const readme = read('README.md');
  assert.match(operations, /function commandAvailable\(command\)/);
  // Docker capability flags now come from the Runtime Agent's own status
  // report rather than probing the (no longer present) local Docker socket.
  assert.match(operations, /agentReachable/);
  assert.match(operations, /agentAuthenticated/);
  assert.match(operations, /dockerAvailable/);
  assert.match(app, /capabilities\.dockerReason/);
  assert.match(readme, /X-Hub-Signature-256/);
  assert.match(readme, /X-SHAM-Signature/);
  assert.match(readme, /SHAM_DOCKER_INTERNAL_NETWORK/);
  assert.match(readme, /SHAM_DOCKER_EGRESS_NETWORK/);
});
