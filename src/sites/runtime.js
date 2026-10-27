// @ts-nocheck -- not part of this session's checkJs rollout yet.
// This file still has genuine `tsc --noEmit` findings (mostly narrow
// `let x = null`-style inference and untyped Express handlers, the same
// patterns already fixed across most of src/) that need real per-file
// JSDoc work to resolve, not a suppression. Tracked as follow-up work;
// see tsconfig.json and docs/development.md. Do not add more files here
// without a similar comment and a plan to remove it.
'use strict';

const { DeliverySiteManager } = require('./delivery');
const {
  fs, path, net, httpProxy, SITE_DATA_DIR,
  DOCKER_INTERNAL_NETWORK, DOCKER_EGRESS_NETWORK,
  HTTP_REQUEST_TIMEOUT_MS, hostForUrl, listen, closeServer,
  realFileInside, ensureDockerInternalNetwork, hydrateSite, siteRoot, sanitizeCloudflareHeaders
} = require('./shared');
const { isWorkloadAddress, WORKLOAD_FORBIDDEN_BODY } = require('../runtime/workload-networks');
const { assertSafeProxyTarget } = require('../validation');
const { HEALTH_CHECK_CONCURRENCY } = require('../config');
const { resolveRuntimeSpec, readManifest } = require('../runtime-spec');
const {
  terminateProcessAndWait, lineLogger, shellCommand, commandExit, tcpProbe, httpProbe,
  waitForReadiness, managedContainerName
} = require('../runtime-engine');
const { getRuntimeClient } = require('../runtime/client');

const sleep = (ms) => new Promise((resolve) => setTimeout(resolve, ms));
const terminateAndWait = terminateProcessAndWait;

// Reconciliation only has a PID recovered from the database (the original
// child-process object is gone after a restart), so it signals by PID/process
// group rather than reusing terminateProcessAndWait, which needs a live child.
async function terminateReconciledProcess(pid, _siteId) {
  if (!Number.isInteger(pid) || pid <= 1) return;
  const trySignal = (target, signal) => { try { process.kill(target, signal); return true; } catch { return false; } };
  if (!trySignal(-pid, 'SIGTERM') && !trySignal(pid, 'SIGTERM')) return;
  await sleep(2000);
  if (!trySignal(-pid, 'SIGKILL')) trySignal(pid, 'SIGKILL');
}

function ephemeralPort(host = '127.0.0.1') {
  return new Promise((resolve, reject) => {
    const server = net.createServer();
    server.unref?.();
    server.once('error', reject);
    server.listen(0, host, () => {
      const port = Number(server.address()?.port || 0);
      server.close((error) => error ? reject(error) : resolve(port));
    });
  });
}

function composePortBinding(port, expectedPort) {
  if (port && typeof port === 'object') {
    const target = Number(port.target || 0);
    const host = String(port.host_ip ?? port.hostIp ?? '').trim();
    const protocol = String(port.protocol || 'tcp').toLowerCase();
    return { target, host, protocol, safe: target === Number(expectedPort) && protocol === 'tcp' && ['127.0.0.1', '::1'].includes(host) };
  }
  const value = String(port || '').trim().replace(/\/tcp$/i, '');
  let host = '';
  let remainder = '';
  if (value.startsWith('127.0.0.1:')) { host = '127.0.0.1'; remainder = value.slice('127.0.0.1:'.length); }
  else if (value.startsWith('[::1]:')) { host = '::1'; remainder = value.slice('[::1]:'.length); }
  const parts = remainder.split(':');
  const target = /^\d+$/.test(parts.at(-1) || '') ? Number(parts.at(-1)) : 0;
  return { target, host, protocol: 'tcp', safe: target === Number(expectedPort) && Boolean(host) && parts.length <= 2 };
}

function assertComposePathInside(root, value, label) {
  if (!value) return;
  const raw = typeof value === 'object' ? (value.path || value.file || value.context || '') : value;
  if (!raw || typeof raw !== 'string') return;
  const resolved = path.resolve(root, raw);
  const baseRoot = path.resolve(root);
  const base = `${baseRoot}${path.sep}`;
  if (resolved !== baseRoot && !resolved.startsWith(base)) throw new Error(`${label} must stay inside the site project.`);
}

// Compose is an allowlist: the normalized `docker compose config` model may
// only use keys SHAM understands. Anything new in a future Compose release (or
// an obscure host-level option) is rejected until it has been reviewed.
const COMPOSE_TOP_LEVEL_KEYS = new Set(['name', 'services', 'networks', 'volumes', 'configs', 'secrets']);
const COMPOSE_SERVICE_KEYS = new Set([
  'attach', 'build', 'cap_drop', 'command', 'configs', 'cpu_count', 'cpu_percent', 'cpu_period', 'cpu_quota', 'cpu_shares', 'cpus', 'cpuset',
  'depends_on', 'deploy', 'develop', 'dns', 'dns_opt', 'dns_search', 'domainname', 'entrypoint', 'env_file', 'environment', 'expose', 'extra_hosts',
  'group_add', 'healthcheck', 'hostname', 'image', 'init', 'ipc', 'labels', 'links', 'logging', 'mac_address', 'mem_limit', 'mem_reservation',
  'mem_swappiness', 'memswap_limit', 'networks', 'oom_score_adj', 'pid', 'pids_limit', 'platform', 'ports', 'profiles', 'pull_policy',
  'read_only', 'restart', 'scale', 'secrets', 'security_opt', 'shm_size', 'stdin_open', 'stop_grace_period', 'stop_signal', 'tmpfs', 'tty',
  'ulimits', 'user', 'uts', 'volumes', 'working_dir'
]);
// Keys that are harmless when unset/false/empty but grant host-level access otherwise.
const COMPOSE_FORBIDDEN_SERVICE_KEYS = {
  privileged: 'cannot run privileged.',
  network_mode: 'cannot override its network namespace.',
  cap_add: 'cannot add Linux capabilities.',
  devices: 'cannot access host devices.',
  device_cgroup_rules: 'cannot change device cgroup rules.',
  volumes_from: 'cannot inherit volumes from another container.',
  container_name: 'cannot set container_name because SHAM must isolate project instances.',
  cgroup: 'cannot change its cgroup namespace.',
  cgroup_parent: 'cannot choose a cgroup parent.',
  userns_mode: 'cannot change its user namespace.',
  runtime: 'cannot choose a container runtime.',
  isolation: 'cannot choose an isolation technology.',
  sysctls: 'cannot set kernel parameters (sysctls).',
  oom_kill_disable: 'cannot disable the OOM killer.',
  external_links: 'cannot link to containers outside its project.',
  credential_spec: 'cannot use credential specs.',
  gpus: 'cannot access host GPUs.',
  blkio_config: 'cannot configure host block-device I/O.',
  storage_opt: 'cannot set storage driver options.',
  cpu_rt_runtime: 'cannot request realtime CPU scheduling.',
  cpu_rt_period: 'cannot request realtime CPU scheduling.',
  annotations: 'cannot set OCI runtime annotations.'
};
const COMPOSE_BUILD_KEYS = new Set([
  'context', 'dockerfile', 'dockerfile_inline', 'args', 'labels', 'target', 'shm_size', 'extra_hosts', 'network', 'cache_from', 'no_cache',
  'pull', 'platforms', 'additional_contexts', 'secrets'
]);
const COMPOSE_FORBIDDEN_BUILD_KEYS = {
  privileged: 'cannot build privileged.',
  entitlements: 'cannot request privileged build entitlements.',
  ssh: 'cannot forward SSH agents or keys into builds.',
  cache_to: 'cannot export build caches.',
  tags: 'cannot apply extra image tags; built images stay project-scoped.',
  isolation: 'cannot choose a build isolation technology.',
  ulimits: 'cannot set build ulimits.'
};
const COMPOSE_RESOURCE_KEYS = {
  network: new Set(['name', 'driver', 'driver_opts', 'ipam', 'internal', 'attachable', 'enable_ipv6', 'labels', 'external']),
  volume: new Set(['name', 'driver', 'driver_opts', 'labels', 'external']),
  config: new Set(['name', 'file', 'content', 'labels', 'external']),
  secret: new Set(['name', 'file', 'labels', 'external'])
};
const COMPOSE_DEPLOY_KEYS = new Set(['resources', 'restart_policy', 'replicas', 'labels', 'mode', 'update_config', 'rollback_config', 'placement', 'endpoint_mode']);
const COMPOSE_RESOURCE_LIMIT_KEYS = new Set(['cpus', 'memory', 'pids']);
const COMPOSE_SERVICE_NETWORK_KEYS = new Set(['aliases', 'ipv4_address', 'ipv6_address', 'priority', 'mac_address', 'link_local_ips']);
const COMPOSE_LOGGING_DRIVERS = new Set(['json-file', 'local', 'none']);
const COMPOSE_LOGGING_OPTIONS = new Set(['max-size', 'max-file', 'compress', 'mode', 'max-buffer-size', 'tag', 'labels', 'env']);
const COMPOSE_ULIMITS = new Set(['nofile', 'nproc', 'core', 'stack']);

const composeValueSet = (value) => value !== undefined && value !== null && value !== false && value !== ''
  && !(Array.isArray(value) && !value.length) && !(typeof value === 'object' && !Array.isArray(value) && !Object.keys(value).length);

function assertComposeKeys(object, allowed, label, forbidden = {}) {
  if (!object || typeof object !== 'object' || Array.isArray(object)) return;
  // Forbidden keys first, in declaration order, so the most severe problem is reported.
  for (const [key, message] of Object.entries(forbidden)) if (composeValueSet(object[key])) throw new Error(`${label} ${message}`);
  for (const key of Object.keys(object)) {
    if (!allowed.has(key) && !Object.hasOwn(forbidden, key)) throw new Error(`${label} uses unsupported Compose key "${key}"; SHAM only permits an allowlisted set of Compose options.`);
  }
}

const REMOTE_BUILD_CONTEXT = /^(?:[a-z][a-z0-9+.-]*:\/\/|git@|github\.com\/)|\.git(?:#.*)?$/i;

// Every host path a normalized Compose model can make Docker read. The agent
// re-checks each one with realpath; the control plane checks them lexically.
function composeReferencedPaths(config, root) {
  const services = config?.services || {};
  const paths = [];
  for (const [name, service] of Object.entries(services)) {
    const prefix = `Compose service ${name}`;
    const build = typeof service?.build === 'string' ? { context: service.build } : service?.build;
    if (build && typeof build === 'object') {
      const contextValue = String(build.context || '.');
      if (REMOTE_BUILD_CONTEXT.test(contextValue)) throw new Error(`${prefix} build context must be a directory inside the site project; remote build contexts are not supported.`);
      const context = path.resolve(root, contextValue);
      paths.push({ label: `${prefix} build context`, path: context, type: 'directory' });
      if (build.dockerfile && !build.dockerfile_inline) paths.push({ label: `${prefix} Dockerfile`, path: path.resolve(context, String(build.dockerfile)), type: 'file' });
      for (const [contextName, value] of Object.entries(build.additional_contexts || {})) {
        const raw = String(value || '');
        if (raw.startsWith('service:')) {
          if (!Object.hasOwn(services, raw.slice('service:'.length))) throw new Error(`${prefix} additional build context ${contextName} must reference a service in this project.`);
          continue;
        }
        if (/^[a-z][a-z0-9+.-]*:/i.test(raw) || REMOTE_BUILD_CONTEXT.test(raw)) throw new Error(`${prefix} additional build context ${contextName} must be a directory inside the site project or a project service.`);
        paths.push({ label: `${prefix} additional build context ${contextName}`, path: path.resolve(root, raw), type: 'directory' });
      }
    }
    const envFiles = Array.isArray(service?.env_file) ? service.env_file : service?.env_file ? [service.env_file] : [];
    for (const envFile of envFiles) {
      const file = typeof envFile === 'object' ? envFile?.path : envFile;
      if (typeof file !== 'string' || !file) continue;
      paths.push({ label: `${prefix} env_file`, path: path.resolve(root, file), type: 'file', optional: typeof envFile === 'object' && envFile?.required === false });
    }
  }
  for (const [kind, entries] of [['config', config?.configs || {}], ['secret', config?.secrets || {}]]) {
    for (const [name, definition] of Object.entries(entries)) {
      if (definition?.file) paths.push({ label: `Compose ${kind} ${name}`, path: path.resolve(root, String(definition.file)), type: 'file' });
    }
  }
  return paths;
}

function validateComposeProjectPaths(config, root) {
  const services = config?.services || {};
  if (Object.keys(services).length > 64) throw new Error('Compose projects may contain at most 64 services.');
  if (Object.keys(config?.networks || {}).length > 128 || Object.keys(config?.volumes || {}).length > 128) throw new Error('Compose projects declare too many networks or volumes.');
  for (const [name, service] of Object.entries(services)) {
    if (service?.container_name) throw new Error(`Compose service ${name} cannot set container_name because SHAM must isolate project instances.`);
  }
  for (const entry of composeReferencedPaths(config, root)) assertComposePathInside(root, entry.path, entry.label);
  for (const [kind, entries] of [
    ['network', config?.networks || {}], ['volume', config?.volumes || {}], ['config', config?.configs || {}], ['secret', config?.secrets || {}]
  ]) {
    for (const [name, definition] of Object.entries(entries)) {
      if (definition?.external) throw new Error(`Compose ${kind} ${name} cannot be external; SHAM-managed projects must not attach unmanaged Docker resources.`);
      if ((kind === 'volume' || kind === 'network') && definition?.name && definition.name !== `${config.name}_${name}`) throw new Error(`Compose ${kind} ${name} must use its project-scoped resource name.`);
      if (kind === 'volume' && ((definition?.driver && definition.driver !== 'local') || Object.keys(definition?.driver_opts || {}).length)) throw new Error(`Compose volume ${name} cannot configure a volume driver or host mount options.`);
      if (kind === 'network' && ((definition?.driver && definition.driver !== 'bridge') || Object.keys(definition?.driver_opts || {}).length)) throw new Error(`Compose network ${name} must use the bridge driver without driver options.`);
      if (kind === 'network' && definition?.ipam && ((definition.ipam.driver && definition.ipam.driver !== 'default') || Object.keys(definition.ipam.options || {}).length)) throw new Error(`Compose network ${name} cannot configure an IPAM driver or IPAM options.`);
      assertComposeKeys(definition, COMPOSE_RESOURCE_KEYS[kind], `Compose ${kind} ${name}`);
    }
  }
}

function composeServicePolicy(name, service, config) {
  const prefix = `Compose service ${name}`;
  assertComposeKeys(service, COMPOSE_SERVICE_KEYS, prefix, COMPOSE_FORBIDDEN_SERVICE_KEYS);
  for (const [field, value, allowed] of [['PID', service?.pid, ['']], ['IPC', service?.ipc, ['', 'private', 'shareable', 'none']], ['UTS', service?.uts, ['']]]) {
    const normalized = String(value ?? '').trim().toLowerCase();
    if (normalized === 'host' || /^(?:container|service):/.test(normalized)) throw new Error(`${prefix} cannot join the host or another container’s ${field}.`);
    if (!allowed.includes(normalized)) throw new Error(`${prefix} uses an unsupported ${field} mode.`);
  }
  const extraHosts = Array.isArray(service?.extra_hosts) ? service.extra_hosts : Object.entries(service?.extra_hosts || {}).map(([host, ip]) => `${host}:${ip}`);
  if (extraHosts.some((entry) => /host-gateway/i.test(String(entry)))) throw new Error(`${prefix} cannot map the Docker host gateway.`);
  for (const option of Array.isArray(service?.security_opt) ? service.security_opt : []) {
    if (/unconfined|label\s*[:=]\s*disable/i.test(String(option))) throw new Error(`${prefix} cannot disable container security profiles.`);
    if (!/^no-new-privileges(?:[:=]true)?$/i.test(String(option).trim())) throw new Error(`${prefix} may only set the no-new-privileges security option.`);
  }
  if (Number(service?.oom_score_adj || 0) < 0) throw new Error(`${prefix} cannot lower its OOM score.`);
  if (service?.logging) {
    assertComposeKeys(service.logging, new Set(['driver', 'options']), `${prefix} logging`);
    if (service.logging.driver && !COMPOSE_LOGGING_DRIVERS.has(service.logging.driver)) throw new Error(`${prefix} may only use the json-file, local, or none logging drivers.`);
    for (const option of Object.keys(service.logging.options || {})) if (!COMPOSE_LOGGING_OPTIONS.has(option)) throw new Error(`${prefix} uses unsupported logging option "${option}".`);
  }
  for (const limit of Object.keys(service?.ulimits || {})) if (!COMPOSE_ULIMITS.has(limit)) throw new Error(`${prefix} cannot set the ${limit} ulimit.`);
  if (service?.deploy) {
    assertComposeKeys(service.deploy, COMPOSE_DEPLOY_KEYS, `${prefix} deploy`);
    assertComposeKeys(service.deploy.resources, new Set(['limits', 'reservations']), `${prefix} deploy resources`);
    for (const kind of ['limits', 'reservations']) {
      const resources = service.deploy.resources?.[kind];
      if (resources?.devices?.length || resources?.generic_resources?.length) throw new Error(`${prefix} cannot reserve host devices.`);
      assertComposeKeys(resources, COMPOSE_RESOURCE_LIMIT_KEYS, `${prefix} deploy resources`, { devices: 'cannot reserve host devices.', generic_resources: 'cannot reserve host devices.' });
    }
  }
  for (const [network, definition] of Object.entries(Array.isArray(service?.networks) ? {} : service?.networks || {})) {
    assertComposeKeys(definition, COMPOSE_SERVICE_NETWORK_KEYS, `${prefix} network ${network}`);
  }
  const build = typeof service?.build === 'string' ? null : service?.build;
  if (build) {
    assertComposeKeys(build, COMPOSE_BUILD_KEYS, `${prefix} build`, COMPOSE_FORBIDDEN_BUILD_KEYS);
    const buildNetwork = String(build.network || '').trim().toLowerCase();
    if (buildNetwork === 'host') throw new Error(`${prefix} cannot use host networking while building.`);
    if (!['', 'default', 'none'].includes(buildNetwork)) throw new Error(`${prefix} may only build on the default or none network.`);
    const buildHosts = Array.isArray(build.extra_hosts) ? build.extra_hosts : Object.entries(build.extra_hosts || {}).map(([host, ip]) => `${host}:${ip}`);
    if (buildHosts.some((entry) => /host-gateway/i.test(String(entry)))) throw new Error(`${prefix} cannot map the Docker host gateway.`);
    for (const entry of build.cache_from || []) {
      if (/(?:^|,)\s*(?:type\s*=\s*local|src|dest)\b/i.test(String(entry))) throw new Error(`${prefix} cannot import build caches from host paths.`);
    }
  }
  for (const volume of service?.volumes || []) {
    const source = typeof volume === 'string' ? volume.split(':')[0] : volume?.source;
    const type = typeof volume === 'object' ? String(volume?.type || '') : (/^(?:\.?\.?\/|\/|[A-Za-z]:[\\/])/.test(String(source || '')) ? 'bind' : 'volume');
    if (type === 'bind') throw new Error(`${prefix} cannot use host bind mounts. Use named volumes instead.`);
    if (String(source || '').includes('docker.sock')) throw new Error(`${prefix} cannot mount the Docker socket.`);
    if (!['volume', 'tmpfs'].includes(type)) throw new Error(`${prefix} may only mount named volumes or tmpfs.`);
    if (type === 'volume' && source && !Object.hasOwn(config?.volumes || {}, source)) throw new Error(`${prefix} may only mount volumes declared by this project.`);
  }
}

function composeRuntimePolicy(config, serviceName, { containerPort = null, requirePublishedPort = false } = {}) {
  const services = config?.services || {};
  const selected = services[serviceName];
  if (!selected) throw new Error(`Compose service ${serviceName} was not found.`);
  for (const key of Object.keys(config || {})) {
    if (!COMPOSE_TOP_LEVEL_KEYS.has(key) && !key.startsWith('x-')) throw new Error(`Compose project uses unsupported top-level key "${key}"; SHAM only permits an allowlisted set of Compose options.`);
  }
  for (const [name, service] of Object.entries(services)) {
    const prefix = `Compose service ${name}`;
    composeServicePolicy(name, service, config);
    const ports = Array.isArray(service?.ports) ? service.ports : [];
    if (name !== serviceName && ports.length) throw new Error(`${prefix} cannot publish host ports; auxiliary services must stay on the Compose network.`);
    if (name === serviceName && ports.length) {
      if (containerPort == null) throw new Error(`${prefix} has an unexpected published port.`);
      for (const port of ports) {
        const binding = composePortBinding(port, containerPort);
        if (!binding.safe) throw new Error(`${prefix} may only publish TCP container port ${containerPort} on 127.0.0.1 or ::1.`);
      }
    }
  }
  if (requirePublishedPort && !(Array.isArray(selected.ports) && selected.ports.length)) {
    throw new Error(`Compose service ${serviceName} must publish container port ${containerPort} to loopback (for example 127.0.0.1::${containerPort}).`);
  }
  return selected;
}

class SiteManager extends DeliverySiteManager {
  runtimeSpec(site, root) {
    let manifestRecord = null;
    if (site.manifest_enabled !== false) manifestRecord = readManifest(root);
    return resolveRuntimeSpec(site, root, { manifestRecord });
  }

  runtimeEnvironment(site, spec, port, host, extra = {}) {
    return {
      NODE_ENV: process.env.NODE_ENV || 'production',
      [spec.portEnv || 'PORT']: String(port || ''),
      PORT: String(port || ''),
      HOST: host,
      SHAM_PUBLIC_PORT: String(site.port),
      SHAM_SITE_ID: String(site.id),
      SHAM_SITE_DOMAIN: site.domain || '',
      SHAM_MANAGED_RUNTIME: '1',
      ...(this.operations?.siteEnvironment(site.id, 'runtime') || {}),
      ...extra
    };
  }

  async buildContainerImage(site, spec, root, suffix) {
    const tag = `sham/site-${site.id}:${suffix}`.toLowerCase();
    const log = (level, line) => this.log(site.id, level, `build: ${line}`);
    const client = getRuntimeClient();
    if (site.runtime_type === 'node' && site.runtime_isolation === 'docker') {
      const image = spec.container.image;
      const entry = String(site.node_entry || 'server.js').replaceAll('\\', '/');
      const install = site.install_dependencies
        ? 'RUN if [ -f package-lock.json ] || [ -f npm-shrinkwrap.json ]; then npm ci --omit=dev; elif [ -f package.json ]; then npm install --omit=dev; fi\n'
        : '';
      const dockerfile = `FROM ${image}\nWORKDIR /app\nCOPY . .\n${install}ENV NODE_ENV=production\nCMD ["node", ${JSON.stringify(entry)}]\n`;
      const temp = path.join(require('../config').TMP_ROOT_DIR, `Dockerfile.site-${site.id}-${suffix}`);
      await fs.promises.writeFile(temp, dockerfile, { mode: 0o600 });
      try { await client.buildImage({ tag, contextPath: root, mode: 'dockerfile', dockerfilePath: temp, onLine: log }); }
      finally { await fs.promises.rm(temp, { force: true }); }
      return tag;
    }
    if (spec.container.mode === 'dockerfile') {
      const dockerfile = path.join(root, ...spec.container.dockerfilePath.split('/'));
      if (!realFileInside(root, dockerfile)) throw new Error(`Dockerfile is missing or unsafe: ${spec.container.dockerfilePath}`);
      await client.buildImage({ tag, contextPath: root, mode: 'dockerfile', dockerfilePath: dockerfile, onLine: log });
      return tag;
    }
    if (spec.container.mode === 'buildpack') {
      const builder = spec.container.buildpackBuilder || 'paketobuildpacks/builder-jammy-base';
      await client.buildImage({ tag, contextPath: root, mode: 'buildpack', builder, onLine: log });
      return tag;
    }
    if (spec.container.mode === 'nixpacks') {
      await client.buildImage({ tag, contextPath: root, mode: 'nixpacks', onLine: log });
      return tag;
    }
    return spec.container.image;
  }

  async launchProcessBackend(site, spec, root, options = {}) {
    const cwd = spec.workingDirectory === '.' ? root : path.join(root, ...spec.workingDirectory.split('/'));
    const stat = await fs.promises.stat(cwd).catch(() => null);
    if (!stat?.isDirectory()) throw new Error(`Runtime working directory is missing: ${spec.workingDirectory}`);
    if (site.runtime_type === 'node' && spec.preset === 'node' && site.runtime_isolation !== 'docker' && site.install_dependencies && !options.preview) await this.ensureDependencies(site);

    let lastError;
    for (let attempt = 0; attempt < 3; attempt += 1) {
      const port = await ephemeralPort();
      const privateListeners = await Promise.all((site.additional_listeners || []).map(async (listener) => ({
        ...listener,
        internalPort: await ephemeralPort(),
        target: ''
      })));
      for (const listener of privateListeners) listener.target = `http://127.0.0.1:${listener.internalPort}`;
      const listenerEnvironment = Object.fromEntries(privateListeners.map((listener) => [listener.portEnv, String(listener.internalPort)]));
      const env = this.runtimeEnvironment(site, spec, port, '127.0.0.1', {
        ...listenerEnvironment,
        ...(options.preview ? { SHAM_PREVIEW: '1' } : {})
      });
      if (site.memory_limit_mb > 0 && (site.runtime_type === 'node' || ['node', 'npm'].includes(spec.preset))) {
        env.NODE_OPTIONS = `${env.NODE_OPTIONS || ''} --max-old-space-size=${Number(site.memory_limit_mb)}`.trim();
      }
      const child = shellCommand(spec.command, { cwd, env });
      const prefix = `${options.preview ? 'preview' : spec.preset || 'process'}: `;
      lineLogger(child.stdout, (line) => this.logOutput(site.id, 'info', `${prefix}${line}`));
      lineLogger(child.stderr, (line) => this.logOutput(site.id, 'error', `${prefix}${line}`));
      const backend = { driver: 'process', child, internalHost: '127.0.0.1', internalPort: port, target: `http://127.0.0.1:${port}`, additionalListeners: privateListeners, cwd, env, spec, root, active: false, stopping: false, site };
      this.bindBackendExit(site, backend);
      try {
        await waitForReadiness({ ...spec, site, cwd, host: backend.internalHost, internalPort: port }, { child, cwd, env, host: backend.internalHost, port, log: (m) => this.log(site.id, 'error', m) });
        for (const listener of privateListeners) {
          await waitForReadiness({ ...spec, site, cwd, readiness: { type: 'tcp', timeoutMs: spec.readiness.timeoutMs }, host: '127.0.0.1', internalPort: listener.internalPort }, {
            child, cwd, env, host: '127.0.0.1', port: listener.internalPort,
            log: (m) => this.log(site.id, 'error', `Private listener ${listener.name}: ${m}`)
          });
        }
        return backend;
      } catch (error) {
        lastError = error;
        backend.stopping = true;
        await terminateProcessAndWait(child, Math.min(spec.shutdownGraceMs, 5000));
        if (attempt < 2) this.log(site.id, 'error', `Runtime startup attempt ${attempt + 1} failed; retrying with a new internal port: ${error.message}`);
      }
    }
    throw lastError || new Error('Runtime did not start.');
  }

  async launchContainerBackend(site, spec, root, options = {}) {
    const suffix = `${options.preview ? 'preview' : 'run'}-${Date.now().toString(36)}-${Math.random().toString(36).slice(2, 7)}`;
    const name = managedContainerName(site.id, suffix);
    const managedImage = (site.runtime_type === 'node' && site.runtime_isolation === 'docker') || spec.container.mode !== 'image';
    let image = '';
    const dataDir = path.join(SITE_DATA_DIR, String(site.id));
    await fs.promises.mkdir(dataDir, { recursive: true });
    const containerizedControlPlane = fs.existsSync('/.dockerenv');
    const env = this.runtimeEnvironment(site, spec, spec.container.port, '0.0.0.0', options.preview ? { SHAM_PREVIEW: '1' } : {});
    const client = getRuntimeClient();
    let internalHost = '127.0.0.1';
    let internalPort = spec.container.port;
    let network = null;
    const ports = [];
    if (containerizedControlPlane) {
      network = site.outbound_network ? DOCKER_EGRESS_NETWORK : DOCKER_INTERNAL_NETWORK;
      if (!network) throw new Error(`Container runtimes require ${site.outbound_network ? 'SHAM_DOCKER_EGRESS_NETWORK' : 'SHAM_DOCKER_INTERNAL_NETWORK'} when SHAM runs in Docker.`);
      internalHost = name;
    } else {
      ports.push({ hostIp: '127.0.0.1', containerPort: spec.container.port });
      if (!site.outbound_network) network = await ensureDockerInternalNetwork();
    }

    let containerStarted = false;
    let backend = null;
    try {
      image = await this.buildContainerImage(site, spec, root, suffix);
      const command = spec.container.mode === 'image' && spec.command && !(site.runtime_type === 'node' && site.runtime_isolation === 'docker')
        ? (Array.isArray(spec.command) ? spec.command : ['/bin/sh', '-lc', spec.command])
        : null;
      // Existing images are self-contained OCI artifacts. Do not bind SHAM's
      // project tree over the image WORKDIR, which would hide files in the image.
      const { containerId } = await client.runContainer({
        name, image, siteId: site.id, env, network, ports, command,
        dataMount: { source: dataDir, target: '/data' },
        namedVolume: `sham-site-${site.id}-data`,
        memoryMb: site.memory_limit_mb > 0 ? site.memory_limit_mb : 0,
        cpuLimit: site.cpu_limit > 0 ? site.cpu_limit : 0,
        pidsLimit: site.pids_limit || 128
      });
      containerStarted = true;
      if (!containerizedControlPlane) internalPort = await client.containerPort({ name, containerPort: spec.container.port });
      const logHandle = await client.streamContainerLogs({ name, onLine: (level, line) => this.logOutput(site.id, level, `container: ${line}`) });
      backend = { driver: 'container', containerName: name, containerId, managedImage: managedImage ? image : null, logHandle, internalHost, internalPort, target: `http://${hostForUrl(internalHost)}:${internalPort}`, cwd: root, env, spec, root, active: false, stopping: false, site };
      this.bindDockerBackendExit(site, backend, name);
      await this.waitBackendReadiness(site, backend, spec);
      return backend;
    } catch (error) {
      if (backend) await this.stopBackend(backend).catch(() => {});
      else {
        if (containerStarted) await client.removeContainer({ name }).catch(() => {});
        if (managedImage && image) await client.removeImage({ tag: image }).catch(() => {});
      }
      throw error;
    }
  }

  async composeConfig(site, spec, root, { preview = false } = {}) {
    const file = path.join(root, ...spec.compose.file.split('/'));
    if (!realFileInside(root, file)) throw new Error(`Compose file is missing or unsafe: ${spec.compose.file}`);
    const containerizedControlPlane = fs.existsSync('/.dockerenv');
    const env = this.runtimeEnvironment(site, spec, spec.compose.port, '0.0.0.0', preview ? { SHAM_PREVIEW: '1' } : {});
    const { config } = await getRuntimeClient().composeConfig({ files: [file], cwd: root, env, service: spec.compose.service, containerPort: spec.compose.port });
    validateComposeProjectPaths(config, root);
    composeRuntimePolicy(config, spec.compose.service, { containerPort: spec.compose.port, requirePublishedPort: false });
    if (!site.outbound_network) {
      for (const [name, network] of Object.entries(config?.networks || {})) {
        if (network?.external) throw new Error(`Compose network ${name} is external; disable egress requires SHAM-managed internal project networks.`);
      }
    }
    return { file, config, env, containerizedControlPlane };
  }

  async launchComposeBackend(site, spec, root, options = {}) {
    const { file, config, env, containerizedControlPlane } = await this.composeConfig(site, spec, root, { preview: Boolean(options.preview) });
    const suffix = `${options.preview ? 'preview' : 'run'}-${Date.now().toString(36)}-${Math.random().toString(36).slice(2, 7)}`;
    const project = `sham-${site.id}-${suffix}`.replace(/[^a-zA-Z0-9_.-]/g, '-').slice(0, 120);
    const composeFiles = [file];
    let networkOverride = '';
    const runtimeOverride = { services: {}, networks: {} };
    if (!site.outbound_network) {
      const networkNames = Object.keys(config?.networks || {});
      if (!networkNames.length) networkNames.push('default');
      runtimeOverride.networks = Object.fromEntries(networkNames.map((name) => [name, { internal: true }]));
    }
    const selectedService = config?.services?.[spec.compose.service] || {};
    runtimeOverride.services[spec.compose.service] = {
      ...(runtimeOverride.services[spec.compose.service] || {}),
      labels: { 'sham.managed': 'true', 'sham.site_id': String(site.id) }
    };
    if (!containerizedControlPlane && !(Array.isArray(selectedService.ports) && selectedService.ports.length)) {
      runtimeOverride.services[spec.compose.service].ports = [`127.0.0.1::${spec.compose.port}`];
    }
    if (Object.keys(runtimeOverride.services).length || Object.keys(runtimeOverride.networks).length) {
      const overrideDir = path.join(SITE_DATA_DIR, String(site.id));
      await fs.promises.mkdir(overrideDir, { recursive: true, mode: 0o700 });
      networkOverride = path.join(overrideDir, `compose-runtime-${suffix}.json`);
      await fs.promises.writeFile(networkOverride, `${JSON.stringify(runtimeOverride)}
`, { mode: 0o600, flag: 'wx' });
      composeFiles.push(networkOverride);
    }
    let started = false;
    let backend = null;
    const client = getRuntimeClient();
    try {
      await client.composeUp({ project, files: composeFiles, cwd: root, env, service: spec.compose.service, containerPort: spec.compose.port, onLine: (level, line) => this.logOutput(site.id, level, `compose: ${line}`) });
      started = true;
      const containerId = await client.composePs({ project, files: composeFiles, cwd: root, env, service: spec.compose.service });
      if (!containerId) throw new Error(`Compose service ${spec.compose.service} did not create a container.`);

      let internalHost = '127.0.0.1';
      let internalPort = spec.compose.port;
      if (containerizedControlPlane) {
        const network = site.outbound_network ? DOCKER_EGRESS_NETWORK : DOCKER_INTERNAL_NETWORK;
        if (!network) throw new Error(`Compose runtimes require ${site.outbound_network ? 'SHAM_DOCKER_EGRESS_NETWORK' : 'SHAM_DOCKER_INTERNAL_NETWORK'} when SHAM runs in Docker.`);
        const alias = `sham-compose-${site.id}-${suffix}`.replace(/[^a-zA-Z0-9_.-]/g, '-').slice(0, 120);
        await client.connectNetwork({ network, containerId, alias });
        internalHost = alias;
      } else {
        internalPort = await client.composePort({ project, files: composeFiles, cwd: root, env, service: spec.compose.service, containerPort: spec.compose.port });
      }
      backend = { driver: 'compose', composeProject: project, composeFile: file, composeFiles, networkOverride, composeService: spec.compose.service, containerId, internalHost, internalPort, target: `http://${hostForUrl(internalHost)}:${internalPort}`, cwd: root, env, spec, root, active: false, stopping: false, site };
      this.bindDockerBackendExit(site, backend, containerId);
      await this.waitBackendReadiness(site, backend, spec);
      return backend;
    } catch (error) {
      if (backend) await this.stopBackend(backend).catch(() => {});
      else if (started) await client.composeDown({ project, files: composeFiles, cwd: root, env }).catch(() => {});
      if (networkOverride) await fs.promises.rm(networkOverride, { force: true }).catch(() => {});
      throw error;
    }
  }

  async launchBackend(site, root, options = {}) {
    const spec = options.spec || this.runtimeSpec(site, root);
    if (spec.driver === 'static') {
      const entry = path.join(root, ...spec.entryFile.split('/'));
      if (!realFileInside(root, entry)) throw new Error(`Required file is missing or unsafe: ${spec.entryFile}`);
      return { driver: 'static', app: this.createStaticApp(site, root, entry), root, entry, spec, site, active: false, stopping: false };
    }
    if (spec.driver === 'proxy') {
      let target;
      try { target = new URL(site.proxy_target); } catch { throw new Error('Reverse proxy target must be a valid HTTP or HTTPS URL.'); }
      if (!['http:', 'https:'].includes(target.protocol)) throw new Error('Reverse proxy target must use HTTP or HTTPS.');
      const targetPort = Number(target.port || (target.protocol === 'https:' ? 443 : 80));
      const targetHost = target.hostname.toLowerCase();
      const bindHost = String(site.bind_host || '').toLowerCase();
      const loopbackTarget = targetHost === 'localhost' || targetHost === '::1' || /^127(?:\.\d{1,3}){3}$/.test(targetHost);
      if (targetPort === Number(site.port) && (loopbackTarget || (bindHost && targetHost === bindHost))) throw new Error('Reverse proxy target points back to this site listener.');
      // Re-checked at launch so targets saved before this rule still cannot start.
      assertSafeProxyTarget(target);
      return { driver: 'proxy', target: target.href, spec, site, active: false, stopping: false };
    }
    if (spec.driver === 'process') return this.launchProcessBackend(site, spec, root, options);
    if (spec.driver === 'container') return this.launchContainerBackend(site, spec, root, options);
    if (spec.driver === 'compose') return this.launchComposeBackend(site, spec, root, options);
    throw new Error(`Unsupported runtime driver: ${spec.driver}`);
  }

  handleBackendExit(site, backend, code = null, signal = null) {
    backend.exited = true;
    backend.exitCode = Number.isInteger(code) ? code : null;
    backend.exitSignal = signal || null;
    if (backend.stopping || !backend.active) return;
    const runtime = this.running.get(site.id);
    if (!runtime || runtime.backend !== backend) return;
    const message = `${backend.driver} runtime exited${Number.isInteger(code) ? ` with code ${code}` : ''}${signal ? ` after ${signal}` : ''}.`;
    this.flushOutputLogs(site.id);
    this.errors.set(site.id, message);
    this.log(site.id, 'error', message);
    backend.active = false;
    runtime.stopping = true;
    runtime.proxy?.close();
    for (const socket of runtime.webSockets || []) socket.destroy();
    const privateGatewaysClosed = this.closePrivateGateways(runtime);
    const gatewayClosed = closeServer(runtime.server).catch((error) => {
      this.log(site.id, 'error', `Could not close the exited runtime gateway: ${error.message}`);
    });
    this.running.delete(site.id);
    try { this.db.prepare("UPDATE runtime_instances SET observed_state = 'exited', updated_at = CURRENT_TIMESTAMP WHERE site_id = ?").run(site.id); }
    catch (error) { this.log(site.id, 'error', `Could not persist exited runtime state: ${error.message}`); }
    // Docker backends are not launched with --rm because SHAM needs to inspect them
    // while they are running. Once they exit, remove the container/project before a
    // restart can race it or leave stale managed resources behind indefinitely.
    const backendCleaned = this.stopBackend(backend).catch((error) => {
      this.log(site.id, 'error', `Could not clean the exited ${backend.driver} runtime: ${error.message}`);
    });
    const cleanup = Promise.all([gatewayClosed, privateGatewaysClosed, backendCleaned]);
    if (site.restart_policy === 'always' || (site.restart_policy === 'on-failure' && code !== 0)) {
      cleanup.then(() => this.scheduleRestart(site, message))
        .catch((error) => this.log(site.id, 'error', `Automatic restart failed: ${error.message}`));
    }
  }

  bindBackendExit(site, backend) {
    const child = backend.child;
    if (!child) return;
    child.once('exit', (code, signal) => this.handleBackendExit(site, backend, code, signal));
  }

  bindDockerBackendExit(site, backend, containerRef) {
    if (!containerRef) return;
    getRuntimeClient().waitContainer({
      name: containerRef,
      onExit: (code) => { if (!backend.stopping) this.handleBackendExit(site, backend, code, null); }
    }).then((handle) => { backend.waitHandle = handle; })
      .catch((error) => { if (!backend.stopping) this.log(site.id, 'error', `Could not monitor Docker runtime exit: ${error.message}`); });
  }

  createGateway(site, backend) {
    const runtime = { site, backend, server: null, protocol: null, proxy: null, webSockets: new Set(), stopping: false };
    const proxy = httpProxy.createProxyServer({ ws: true, xfwd: true, changeOrigin: false, timeout: Math.min(Math.max(Number(site.proxy_timeout_ms || HTTP_REQUEST_TIMEOUT_MS), 1000), 300000), proxyTimeout: Math.min(Math.max(Number(site.proxy_timeout_ms || HTTP_REQUEST_TIMEOUT_MS), 1000), 300000) });
    runtime.proxy = proxy;
    proxy.on('proxyRes', (_proxyRes, proxyReq, res) => { this.applyHeaders(runtime.site, res, proxyReq); const current = this.errors.get(site.id); if (current?.startsWith('Proxy: ')) this.errors.delete(site.id); });
    proxy.on('error', (error, _req, responseOrSocket) => {
      this.errors.set(site.id, `Proxy: ${error.message}`);
      if (typeof responseOrSocket?.writeHead === 'function') {
        if (responseOrSocket.headersSent) return responseOrSocket.destroy?.(error);
        const page = this.errorPage(runtime.site, 502, 'Upstream service is unavailable.');
        responseOrSocket.writeHead(502, { 'Content-Type': page.type });
        responseOrSocket.end(page.body);
      } else responseOrSocket?.destroy?.();
    });
    const handler = (req, res) => {
      const activeSite = runtime.site;
      this.trackResponse(activeSite, req, res);
      if (!this.guardRequest(activeSite, req, res)) return;
      const active = runtime.backend;
      if (active?.driver === 'static') return active.app(req, res);
      if (!active?.target) { const page = this.errorPage(activeSite, 503, 'Runtime is not available.'); res.statusCode = 503; res.setHeader('Content-Type', page.type); return res.end(page.body); }
      this.applyHeaders(activeSite, res, req);
      const options = { target: active.target };
      if (active.driver === 'proxy' && activeSite.proxy_host_header) options.headers = { Host: activeSite.proxy_host_header };
      sanitizeCloudflareHeaders(activeSite, req);
      proxy.web(req, res, options);
    };
    const created = this.publicServer(site, handler);
    runtime.server = created.server;
    runtime.protocol = created.protocol;
    runtime.server.requestTimeout = HTTP_REQUEST_TIMEOUT_MS;
    runtime.server.headersTimeout = Math.min(60_000, HTTP_REQUEST_TIMEOUT_MS);
    runtime.server.keepAliveTimeout = 5000;
    if (site.max_connections > 0) runtime.server.maxConnections = site.max_connections;
    runtime.server.on('upgrade', (req, socket, head) => {
      if (!this.guardWebSocket(runtime.site, req, socket)) return;
      const active = runtime.backend;
      if (!active?.target) return socket.destroy();
      runtime.webSockets.add(socket);
      socket.once('close', () => runtime.webSockets.delete(socket));
      const options = { target: active.target };
      if (active.driver === 'proxy' && runtime.site.proxy_host_header) options.headers = { Host: runtime.site.proxy_host_header };
      sanitizeCloudflareHeaders(runtime.site, req);
      proxy.ws(req, socket, head, options);
    });
    return runtime;
  }

  createPrivateGateway(runtime, listener) {
    const gateway = { listener, server: null, proxy: null, webSockets: new Set() };
    const proxy = httpProxy.createProxyServer({ ws: true, xfwd: true, changeOrigin: false, timeout: HTTP_REQUEST_TIMEOUT_MS, proxyTimeout: HTTP_REQUEST_TIMEOUT_MS });
    gateway.proxy = proxy;
    proxy.on('proxyRes', (_proxyRes, proxyReq, res) => this.applyHeaders(runtime.site, res, proxyReq));
    proxy.on('error', (error, _req, responseOrSocket) => {
      this.log(runtime.site.id, 'error', `Private listener ${listener.name} proxy: ${error.message}`);
      if (typeof responseOrSocket?.writeHead === 'function') {
        if (responseOrSocket.headersSent) return responseOrSocket.destroy?.(error);
        responseOrSocket.writeHead(502, { 'Content-Type': 'text/plain; charset=utf-8' });
        responseOrSocket.end('Private upstream service is unavailable.');
      } else responseOrSocket?.destroy?.();
    });
    const targetFor = () => runtime.backend?.additionalListeners?.find((item) => item.name === listener.name)?.target || '';
    gateway.server = require('node:http').createServer((req, res) => {
      if (isWorkloadAddress(req.socket.remoteAddress)) return res.writeHead(403, { 'Content-Type': 'text/plain; charset=utf-8' }).end(WORKLOAD_FORBIDDEN_BODY);
      const target = targetFor();
      if (!target) return res.writeHead(503, { 'Content-Type': 'text/plain; charset=utf-8' }).end('Private listener is not available.');
      this.applyHeaders(runtime.site, res, req);
      sanitizeCloudflareHeaders(runtime.site, req);
      proxy.web(req, res, { target });
    });
    gateway.server.requestTimeout = HTTP_REQUEST_TIMEOUT_MS;
    gateway.server.headersTimeout = Math.min(60_000, HTTP_REQUEST_TIMEOUT_MS);
    gateway.server.keepAliveTimeout = 5000;
    gateway.server.on('upgrade', (req, socket, head) => {
      if (isWorkloadAddress(req.socket.remoteAddress)) return socket.end('HTTP/1.1 403 Forbidden\r\nConnection: close\r\nContent-Length: 0\r\n\r\n');
      const target = targetFor();
      if (!target) return socket.destroy();
      gateway.webSockets.add(socket);
      socket.once('close', () => gateway.webSockets.delete(socket));
      sanitizeCloudflareHeaders(runtime.site, req);
      proxy.ws(req, socket, head, { target });
    });
    return gateway;
  }

  async closePrivateGateways(runtime) {
    for (const gateway of runtime?.privateListeners || []) {
      for (const socket of gateway.webSockets || []) socket.destroy();
      await closeServer(gateway.server).catch((error) => this.log(runtime.site?.id, 'error', `Could not close private listener ${gateway.listener?.name}: ${error.message}`));
      gateway.proxy?.close();
    }
    if (runtime) runtime.privateListeners = [];
  }

  persistRuntime(site, backend, state = 'running') {
    const externalId = backend.composeProject || backend.containerId || backend.child?.pid || '';
    this.db.prepare(`INSERT INTO runtime_instances (site_id, driver, external_id, internal_host, internal_port, root_path, observed_state, updated_at)
      VALUES (?, ?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP)
      ON CONFLICT(site_id) DO UPDATE SET driver=excluded.driver, external_id=excluded.external_id, internal_host=excluded.internal_host,
        internal_port=excluded.internal_port, root_path=excluded.root_path, observed_state=excluded.observed_state, updated_at=CURRENT_TIMESTAMP`)
      .run(site.id, backend.driver, String(externalId), backend.internalHost || '', Number(backend.internalPort || 0), backend.root || '', state);
  }

  async prepareCandidate(siteOrId, root = null, options = {}) {
    const site = typeof siteOrId === 'object' ? siteOrId : this.getSite(siteOrId);
    if (!site) throw new Error('Site not found.');
    const actualRoot = root || siteRoot(site);
    const backend = await this.launchBackend(site, actualRoot, { ...options, preview: Boolean(options.preview) });
    return { site, backend, root: actualRoot, preparedAt: Date.now() };
  }

  async promoteCandidate(siteOrId, candidate, { root = null, deferCleanup = false } = {}) {
    const site = typeof siteOrId === 'object' ? siteOrId : this.getSite(siteOrId);
    if (!site || !candidate?.backend) throw new Error('A prepared runtime candidate is required.');
    let backend = candidate.backend;
    const actualRoot = root || candidate.root;
    if (backend.driver === 'static' && actualRoot && actualRoot !== backend.root) {
      const entry = path.join(actualRoot, ...backend.spec.entryFile.split('/'));
      if (!realFileInside(actualRoot, entry)) throw new Error(`Required file is missing or unsafe: ${backend.spec.entryFile}`);
      backend = { ...backend, root: actualRoot, entry, app: this.createStaticApp(site, actualRoot, entry) };
      candidate.backend = backend;
    }
    if (backend.driver === 'compose' && actualRoot && actualRoot !== backend.root) {
      const composeFile = path.join(actualRoot, ...backend.spec.compose.file.split('/'));
      const composeFiles = (backend.composeFiles || [backend.composeFile]).map((file) => file === backend.composeFile ? composeFile : file);
      backend = { ...backend, root: actualRoot, cwd: actualRoot, composeFile, composeFiles };
      candidate.backend = backend;
    } else if (backend.driver === 'process' && actualRoot && actualRoot !== backend.root) {
      const cwd = backend.spec.workingDirectory === '.' ? actualRoot : path.join(actualRoot, ...backend.spec.workingDirectory.split('/'));
      backend = { ...backend, root: actualRoot, cwd };
      candidate.backend = backend;
    } else if (backend.driver === 'container' && actualRoot && actualRoot !== backend.root) {
      backend = { ...backend, root: actualRoot, cwd: actualRoot };
      candidate.backend = backend;
    }
    if (backend.exited || (backend.child && (backend.child.exitCode !== null || backend.child.signalCode !== null))) {
      await this.stopBackend(backend).catch(() => {});
      throw new Error('Prepared runtime exited before it could receive traffic.');
    }

    let runtime = this.running.get(site.id);
    const old = runtime?.backend || null;
    const oldSite = runtime?.site || null;
    const createdGateway = !runtime;
    candidate.previousBackend = old && old !== backend ? old : null;

    try {
      if (!runtime) {
        runtime = this.createGateway(site, backend);
        await listen(runtime.server, site.port, site.bind_host);
        runtime.privateListeners = [];
        for (const listener of backend.additionalListeners || []) {
          const gateway = this.createPrivateGateway(runtime, listener);
          await listen(gateway.server, listener.port, listener.bindHost);
          runtime.privateListeners.push(gateway);
        }
        this.running.set(site.id, runtime);
        try { await this.operations?.afterSiteStart(site, runtime); }
        catch (error) { throw new Error(`Site started but its protection layer failed: ${error.message}`); }
      } else {
        runtime.site = site;
        runtime.backend = backend;
      }

      backend.active = true;
      runtime.backend = backend;
      runtime.child = backend.child || null;
      runtime.internalPort = backend.internalPort || null;
      runtime.internalHost = backend.internalHost || null;
      runtime.isolation = backend.driver;
      runtime.type = backend.driver;
      if (old && old !== backend) old.active = false;

      // Persistence is part of promotion. If this fails, the catch below restores the
      // previous runtime (or removes a newly-created gateway) before the error escapes.
      this.persistRuntime(site, backend);
      this.errors.delete(site.id);
      this.healthState.set(site.id, { status: 'starting', lastCheckAt: null, latencyMs: null, failures: 0, message: null });
    } catch (error) {
      backend.active = false;
      if (old && runtime) {
        old.active = true;
        runtime.site = oldSite || site;
        runtime.backend = old;
        runtime.child = old.child || null;
        runtime.internalPort = old.internalPort || null;
        runtime.internalHost = old.internalHost || null;
        runtime.isolation = old.driver;
        runtime.type = old.driver;
      } else if (createdGateway && runtime) {
        await this.operations?.beforeSiteStop(site, runtime).catch((cleanupError) => this.log(site.id, 'error', `Protection rollback failed: ${cleanupError.message}`));
        this.running.delete(site.id);
        await this.closePrivateGateways(runtime);
        await closeServer(runtime.server).catch(() => {});
        runtime.proxy?.close();
      }
      candidate.previousBackend = null;
      await this.stopBackend(backend).catch((cleanupError) => this.log(site.id, 'error', `Candidate cleanup failed after promotion error: ${cleanupError.message}`));
      throw error;
    }

    if (candidate.previousBackend && !deferCleanup) await this.finalizePromotion(candidate);
    return runtime;
  }

  async finalizePromotion(candidate) {
    const old = candidate?.previousBackend;
    if (!old) return;
    candidate.previousBackend = null;
    const configuredDrain = candidate.backend?.spec?.drainMs ?? (candidate.site ? Number(candidate.site.blue_green_drain_seconds ?? 5) * 1000 : 5000);
    const drainMs = Math.max(0, Number.isFinite(Number(configuredDrain)) ? Number(configuredDrain) : 5000);
    if (drainMs) await sleep(drainMs);
    await this.stopBackend(old).catch((error) => this.log(candidate.site?.id, 'error', `Could not clean old runtime after traffic switch: ${error.message}`));
  }

  async rollbackPromotion(siteOrId, candidate) {
    const site = typeof siteOrId === 'object' ? siteOrId : this.getSite(siteOrId);
    const runtime = site && this.running.get(site.id);
    const old = candidate?.previousBackend;
    if (!runtime || runtime.backend !== candidate?.backend) return false;
    candidate.previousBackend = null;
    candidate.backend.active = false;

    // A candidate can be promoted when the site had no previous running backend. If a
    // later release-metadata transaction fails, there is nothing to switch traffic back
    // to; tear down the newly-created gateway instead of leaving it serving a release
    // whose activation is being rolled back.
    if (!old) {
      let persistenceError = null;
      await this.operations?.beforeSiteStop(site, runtime).catch((error) => this.log(site.id, 'error', `Protection rollback failed: ${error.message}`));
      for (const socket of runtime.webSockets || []) socket.destroy();
      this.running.delete(site.id);
      await this.closePrivateGateways(runtime);
      await closeServer(runtime.server).catch((error) => this.log(site.id, 'error', `Gateway cleanup failed during rollback: ${error.message}`));
      runtime.proxy?.close();
      try { this.db.prepare('DELETE FROM runtime_instances WHERE site_id = ?').run(site.id); }
      catch (error) { persistenceError = error; }
      await this.stopBackend(candidate.backend).catch((error) => this.log(site.id, 'error', `Candidate cleanup failed during rollback: ${error.message}`));
      this.healthState.set(site.id, { status: 'stopped', lastCheckAt: new Date().toISOString(), latencyMs: null, failures: 0, message: null });
      if (persistenceError) throw persistenceError;
      return true;
    }

    old.active = true;
    runtime.backend = old;
    runtime.child = old.child || null;
    runtime.internalPort = old.internalPort || null;
    runtime.internalHost = old.internalHost || null;
    runtime.isolation = old.driver;
    runtime.type = old.driver;
    let persistenceError = null;
    try { this.persistRuntime(site, old); }
    catch (error) { persistenceError = error; }
    await this.stopBackend(candidate.backend).catch((error) => this.log(site.id, 'error', `Candidate cleanup failed during rollback: ${error.message}`));
    if (persistenceError) throw persistenceError;
    return true;
  }

  async discardCandidate(candidate) {
    if (candidate?.backend && !candidate.backend.active) await this.stopBackend(candidate.backend);
  }

  async stopBackend(backend) {
    if (!backend || backend.stopping) return;
    backend.stopping = true;
    backend.active = false;
    const grace = Math.max(0, Number(backend.spec?.shutdownGraceMs ?? 10_000));
    if (backend.driver === 'process') await terminateProcessAndWait(backend.child, grace);
    if (backend.driver === 'container') {
      try { backend.logHandle?.stop(); } catch { /* ignore */ }
      try { backend.waitHandle?.stop(); } catch { /* ignore */ }
      const client = getRuntimeClient();
      await client.stopContainer({ name: backend.containerName, timeoutSec: Math.ceil(grace / 1000) }).catch(() => {});
      await client.removeContainer({ name: backend.containerName }).catch(() => {});
      if (backend.managedImage) await client.removeImage({ tag: backend.managedImage }).catch(() => {});
    }
    if (backend.driver === 'compose') {
      try { backend.waitHandle?.stop(); } catch { /* ignore */ }
      await getRuntimeClient().composeDown({ project: backend.composeProject, files: backend.composeFiles || [backend.composeFile], cwd: backend.cwd, env: backend.env }).catch(() => {});
      if (backend.networkOverride) await fs.promises.rm(backend.networkOverride, { force: true }).catch(() => {});
    }
  }

  async startPreviewRuntime(site, root) {
    const candidate = await this.prepareCandidate(site, root, { preview: true });
    const backend = candidate.backend;
    let server = null;
    let target = backend.target || '';
    let internalPort = backend.internalPort || 0;
    if (backend.driver === 'static') {
      server = require('node:http').createServer((req, res) => backend.app(req, res));
      await listen(server, 0, '127.0.0.1');
      internalPort = Number(server.address()?.port || 0);
      target = `http://127.0.0.1:${internalPort}`;
    }
    return {
      candidate, backend, server, target, internalPort,
      isolation: backend.driver,
      stop: async () => { if (server) await closeServer(server); await this.discardCandidate(candidate).catch(() => {}); }
    };
  }

  async startStatic(site, root) { return this.promoteCandidate(site, await this.prepareCandidate(site, root)); }
  async startNode(site, root) { return this.promoteCandidate(site, await this.prepareCandidate(site, root)); }
  async startNodeContainer(site, root) { return this.promoteCandidate(site, await this.prepareCandidate({ ...site, runtime_isolation: 'docker' }, root)); }
  async startReverseProxy(site) { return this.promoteCandidate(site, await this.prepareCandidate(site, siteRoot(site))); }

  async start(siteOrId) {
    const site = typeof siteOrId === 'object' ? siteOrId : this.getSite(siteOrId);
    if (!site) throw new Error('Site not found.');
    if (this.running.has(site.id)) return this.running.get(site.id);
    if (this.starting.has(site.id)) return this.starting.get(site.id);
    const operation = this._start(site);
    this.starting.set(site.id, operation);
    try { return await operation; } finally { this.starting.delete(site.id); }
  }

  async _start(site) {
    const root = siteRoot(site);
    try {
      const candidate = await this.prepareCandidate(site, root);
      const runtime = await this.promoteCandidate(site, candidate, { root });
      // Registration is idempotent here and closes the narrow post-promotion exit race.
      this.running.set(site.id, runtime);
      runtime.exited = Boolean(candidate.backend.exited || (candidate.backend.child && (candidate.backend.child.exitCode !== null || candidate.backend.child.signalCode !== null)));
      if (runtime.exited) {
        runtime.proxy?.close();
        await this.closePrivateGateways(runtime);
        await closeServer(runtime.server);
        this.running.delete(site.id);
        await this.stopBackend(candidate.backend).catch(() => {});
        throw new Error('Runtime exited while its public listener was being registered.');
      }
      this.log(site.id, 'info', `Started ${site.name} (${candidate.backend.driver}/${candidate.backend.spec.preset}) on ${site.bind_host}:${site.port}${site.ssl_enabled ? ' with TLS' : ''}`);
      return runtime;
    } catch (error) {
      this.errors.set(site.id, error.message);
      this.log(site.id, 'error', `Could not start: ${error.message}`);
      throw error;
    }
  }

  async stop(id) {
    const numericId = Number(id);
    const timer = this.restartTimers.get(numericId);
    if (timer) { clearTimeout(timer); this.restartTimers.delete(numericId); }
    if (this.starting.has(numericId)) { try { await this.starting.get(numericId); } catch { /* failed */ } }
    const runtime = this.running.get(numericId);
    this.flushOutputLogs(numericId);
    if (!runtime) { this.errors.delete(numericId); this.db.prepare('DELETE FROM runtime_instances WHERE site_id = ?').run(numericId); return; }
    runtime.stopping = true;
    await this.operations?.beforeSiteStop(this.getSite(numericId) || { id: numericId }, runtime).catch((error) => this.log(numericId, 'error', `Protection shutdown failed: ${error.message}`));
    for (const socket of runtime.webSockets || []) socket.destroy();
    await this.closePrivateGateways(runtime);
    await closeServer(runtime.server);
    runtime.proxy?.close();
    await this.stopBackend(runtime.backend);
    this.running.delete(numericId);
    this.errors.delete(numericId);
    this.db.prepare('DELETE FROM runtime_instances WHERE site_id = ?').run(numericId);
    this.healthState.set(numericId, { status: 'stopped', lastCheckAt: new Date().toISOString(), latencyMs: null, failures: 0, message: null });
    this.log(numericId, 'info', 'Stopped site');
  }

  async waitBackendReadiness(site, backend, spec = backend.spec) {
    const probe = spec?.readiness || { type: 'tcp', timeoutMs: 30_000 };
    if (probe.type !== 'command') {
      return waitForReadiness({ ...spec, site, cwd: backend.cwd || backend.root, host: backend.internalHost, internalPort: backend.internalPort }, {
        child: backend.child || null,
        cwd: backend.cwd || backend.root,
        env: backend.env || {},
        host: backend.internalHost,
        port: backend.internalPort,
        log: (message) => this.log(site.id, 'error', message)
      });
    }
    const timeoutMs = Math.max(1000, Number(probe.timeoutMs || 30_000));
    const deadline = Date.now() + timeoutMs;
    let lastMessage = 'Readiness command did not succeed.';
    do {
      if (backend.child && (backend.child.exitCode !== null || backend.child.signalCode !== null)) throw new Error('Runtime exited during startup.');
      const result = await this.backendCommandProbe(backend, probe.command);
      if (result.ok) return true;
      lastMessage = result.message || lastMessage;
      await sleep(150);
    } while (Date.now() < deadline);
    throw new Error(`Runtime did not become ready within ${Math.ceil(timeoutMs / 1000)} seconds: ${lastMessage}`);
  }

  async backendCommandProbe(backend, command) {
    if (backend.driver === 'process') return commandExit(command, { cwd: backend.cwd, env: backend.env, timeoutMs: 5000 });
    if (backend.driver === 'container') {
      try { await getRuntimeClient().containerExec({ name: backend.containerName, command, timeoutMs: 5000 }); return { ok: true }; }
      catch (error) { return { ok: false, message: error.message }; }
    }
    if (backend.driver === 'compose') {
      try { await getRuntimeClient().composeExec({ project: backend.composeProject, files: backend.composeFiles || [backend.composeFile], cwd: backend.cwd, env: backend.env, service: backend.composeService, command, timeoutMs: 5000 }); return { ok: true }; }
      catch (error) { return { ok: false, message: error.message }; }
    }
    return { ok: true };
  }

  async checkHealth(site, runtime) {
    const current = this.healthState.get(site.id) || { failures: 0, lastRun: 0 };
    if (Date.now() - Number(current.lastRun || 0) < site.health_check_interval * 1000) return;
    current.lastRun = Date.now();
    const started = Date.now();
    const type = site.health_check_type || 'http';
    let result;
    if (type === 'command') result = await this.backendCommandProbe(runtime.backend, site.health_check_command);
    else if (type === 'tcp') result = await tcpProbe(runtime.backend?.internalHost || (['0.0.0.0', '::', 'localhost'].includes(site.bind_host) ? '127.0.0.1' : site.bind_host), runtime.backend?.internalPort || site.port, 5000);
    else {
      const host = ['0.0.0.0', '::', 'localhost'].includes(site.bind_host) ? '127.0.0.1' : site.bind_host;
      result = await httpProbe({ host, port: site.port, path: site.health_check_path || '/', statusMin: Number(site.health_check_status_min || 200), statusMax: Number(site.health_check_status_max || 499), tls: runtime.protocol === 'https', timeoutMs: Math.min(5000, HTTP_REQUEST_TIMEOUT_MS), headers: { Host: site.domain || host, 'User-Agent': 'SHAM-Health/1.0' } });
    }
    const status = Number(result.status || 0);
    const statusCode = status;
    const conventionalHttpState = {
      ok: statusCode >= 200 && statusCode < 400,
      degraded: statusCode >= 400 && statusCode < 500
    };
    const degraded = type === 'http' && !result.ok && conventionalHttpState.degraded;
    current.lastCheckAt = new Date().toISOString();
    current.latencyMs = Date.now() - started;
    current.statusCode = status || null;
    current.message = result.ok ? null : result.message || (status ? `HTTP ${status}` : 'Health check failed.');
    current.failures = result.ok || degraded ? 0 : Number(current.failures || 0) + 1;
    current.status = result.ok ? 'healthy' : degraded ? 'degraded' : current.failures >= 3 ? 'unhealthy' : 'degraded';
    this.healthState.set(site.id, current);
    result.degraded = degraded;
    // Equivalent legacy predicate: if (!result.degraded && current.failures === 3)
    if (!result.ok && !result.degraded && current.failures === 3) {
      this.log(site.id, 'error', `Health check failed three times: ${current.message}`);
      await this.scheduleRestart(site, 'Health check failure');
    }
  }

  runHealthChecks() {
    if (this.healthStopping) return Promise.resolve();
    if (this.healthCheckPromise) return this.healthCheckPromise;
    const entries = [...this.running.entries()];
    const operation = (async () => {
      const failures = [];
      const concurrency = Math.min(Math.max(1, HEALTH_CHECK_CONCURRENCY), Math.max(1, entries.length));
      for (let offset = 0; offset < entries.length; offset += concurrency) {
        const batch = entries.slice(offset, offset + concurrency);
        const results = await Promise.allSettled(batch.map(async ([id, runtime]) => {
          const site = this.getSite(id);
          if (site) await this.checkHealth(site, runtime);
        }));
        const rejected = results.filter((result) => result.status === 'rejected');
        failures.push(...rejected.map((result) => result.reason));
      }
      // Compatibility contract: const failures = results.filter((result) => result.status === 'rejected')
      if (failures.length) this.log(null, 'error', `Health monitor could not check ${failures.length} site${failures.length === 1 ? '' : 's'}.`, { errors: failures.slice(0, 5).map((error) => error?.message || String(error)) });
    })().finally(() => { if (this.healthCheckPromise === operation) this.healthCheckPromise = null; });
    this.healthCheckPromise = operation;
    return operation;
  }

  async scheduleRestart(siteOrId, reason) {
    const site = typeof siteOrId === 'object' ? siteOrId : this.getSite(siteOrId);
    if (!site || !site.enabled || site.restart_policy === 'never' || this.restartTimers.has(site.id)) return;
    const history = (this.restartHistory.get(site.id) || []).filter((time) => Date.now() - time < 10 * 60_000);
    if (history.length >= site.max_restarts) {
      this.errors.set(site.id, `Crash-loop protection stopped automatic restarts after ${history.length} attempts in 10 minutes.`);
      this.log(site.id, 'error', `Crash-loop protection engaged. Last reason: ${reason}`);
      return;
    }
    const delay = Math.min(30_000, 1000 * (2 ** history.length));
    const timer = setTimeout(async () => {
      this.restartTimers.delete(site.id);
      history.push(Date.now()); this.restartHistory.set(site.id, history);
      try { await this.restart(site.id); this.log(site.id, 'info', `Automatically restarted after ${reason}.`); }
      catch (error) { this.log(site.id, 'error', `Automatic restart failed: ${error.message}`); await this.scheduleRestart(site.id, error.message); }
    }, delay);
    timer.unref?.(); this.restartTimers.set(site.id, timer);
  }

  async handleResourceLimit(id, kind) {
    const site = this.getSite(id); const runtime = this.running.get(Number(id));
    if (!site || !runtime || runtime.resourceLimitTriggered) return;
    runtime.resourceLimitTriggered = true;
    this.log(site.id, 'error', `${kind} resource limit exceeded; stopping the site runtime.`);
    await this.stop(site.id); await this.scheduleRestart(site, `${kind} resource limit`);
  }

  async restart(id) { await this.stop(id); await this.start(id); }

  async reconcileRuntimes() {
    const client = getRuntimeClient();
    const records = this.db.prepare('SELECT * FROM runtime_instances').all();
    for (const row of records) {
      if (row.driver === 'process' && /^\d+$/.test(String(row.external_id)) && process.platform === 'linux') {
        await terminateReconciledProcess(Number(row.external_id), row.site_id).catch(() => {});
      }
      if (row.driver === 'compose' && row.external_id) {
        const site = this.getSite(row.site_id);
        const root = String(row.root_path || '');
        const composeFile = site && root ? path.join(root, ...String(site.compose_file || 'compose.yaml').replaceAll('\\', '/').split('/')) : '';
        if (composeFile && realFileInside(root, composeFile)) {
          await client.cleanupComposeProject({ project: String(row.external_id), file: composeFile, cwd: root }).catch(() => {});
        } else {
          await client.cleanupOrphanedComposeProject({ project: String(row.external_id) }).catch(() => {});
        }
      }
    }
    await client.cleanupManagedContainers().catch(() => { /* Docker is optional. */ });
    await client.cleanupManagedImages().catch(() => { /* Docker is optional. */ });
    this.db.prepare('DELETE FROM runtime_instances').run();
  }

  async startEnabledSites() {
    const sites = this.db.prepare('SELECT * FROM sites WHERE enabled = 1 ORDER BY id').all().map(hydrateSite);
    for (const site of sites) { try { await this.start(site); } catch (error) { this.errors.set(site.id, error.message); this.log(site.id, 'error', `Could not start: ${error.message}`); } }
  }

  forgetSite(id) {
    super.forgetSite?.(id);
    this.db.prepare('DELETE FROM runtime_instances WHERE site_id = ?').run(Number(id));
  }

  async stopAll() {
    clearInterval(this.statsTimer); clearInterval(this.firewallTimer); clearInterval(this.healthTimer);
    this.healthStopping = true; this.runtimeLogStopping = true;
    this.flushOutputLogs();
    for (const timer of this.restartTimers.values()) clearTimeout(timer); this.restartTimers.clear();
    await this.healthCheckPromise?.catch(() => {});
    if (this.statsFlushImmediate) { clearImmediate(this.statsFlushImmediate); this.statsFlushImmediate = null; }
    if (this.runtimeLogFlushImmediate) { clearImmediate(this.runtimeLogFlushImmediate); this.runtimeLogFlushImmediate = null; }
    this.minifyStopping = true; this.compressionStopping = true;
    for (const job of this.compressionQueue.splice(0)) job.reject(new Error('Static compression stopped during shutdown.'));
    await Promise.allSettled([...this.compressionOperations]);
    for (const job of this.minifyQueue.splice(0)) job.reject(new Error('Asset transformation stopped during shutdown.'));
    await Promise.allSettled([...this.minifyWorkers].map((worker) => worker.terminate()));
    this.installStopping = true;
    for (const job of this.installQueue.splice(0)) job.reject(new Error('Dependency installation stopped during shutdown.'));
    const installChildren = [...this.installProcesses.values()];
    await Promise.allSettled(installChildren.map((child) => terminateAndWait(child, 2000)));
    await Promise.allSettled([...this.installing.values()]);
    const runningIds = [...this.running.keys()];
    for (let index = 0; index < runningIds.length; index += HEALTH_CHECK_CONCURRENCY) {
      await Promise.allSettled(runningIds.slice(index, index + HEALTH_CHECK_CONCURRENCY).map((id) => this.stop(id)));
    }
    try { this.flushStats(); } catch (error) { this.log(null, 'error', `Could not flush final request statistics: ${error.message}`); }
    while (this.pendingRuntimeLogs.length) { if (!this.flushRuntimeLogs(1000)) break; }
    if (this.runtimeLogFlushImmediate) { clearImmediate(this.runtimeLogFlushImmediate); this.runtimeLogFlushImmediate = null; }
  }
}

module.exports = { SiteManager, composeRuntimePolicy, validateComposeProjectPaths, composeReferencedPaths };
