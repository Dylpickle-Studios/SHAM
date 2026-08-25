'use strict';

const fs = require('node:fs');
const path = require('node:path');
const { spawn } = require('node:child_process');
const { operatorEnvironment } = require('../src/process-env');
const { DOCKER_BIN, PACK_BIN, NIXPACKS_BIN, DOCKER_INTERNAL_NETWORK, DOCKER_EGRESS_NETWORK, ANUBIS_IMAGE, DATA_DIR } = require('../src/config');
const { composeRuntimePolicy, validateComposeProjectPaths } = require('../src/sites/runtime');
const {
  ValidationError, assertContainerName, assertComposeProject, assertImageTag, assertManagedImageTag,
  assertNetworkName, assertEnv, assertCommandString, assertPathInsideRoot, assertPort, assertPositiveInt
} = require('./validation');

const MANAGED_LABEL = 'sham.managed=true';

class AgentOperationError extends Error {
  /**
   * @param {string} message
   * @param {'NOT_FOUND' | 'NOT_OWNED'} code
   */
  constructor(message, code) {
    super(message);
    this.name = 'AgentOperationError';
    this.code = code;
  }
}

/**
 * @typedef {Object} RunToolOptions
 * @property {string} [cwd]
 * @property {Record<string, string>} [env]
 * @property {number} [timeoutMs]
 * @property {((level: 'info' | 'error', line: string) => void) | null} [onLine]
 * @property {number} [maxOutputBytes]
 * @property {boolean} [rejectOutputOverflow]
 */
/** @typedef {{ stdout: string, stderr: string, code: 0 }} RunToolResult */

/**
 * @param {string} bin
 * @param {string[]} args
 * @param {RunToolOptions} [options]
 * @returns {Promise<RunToolResult>}
 */
function runTool(bin, args, { cwd, env, timeoutMs = 20 * 60_000, onLine = null, maxOutputBytes = 200_000, rejectOutputOverflow = false } = {}) {
  return new Promise((resolve, reject) => {
    let child;
    try { child = spawn(bin, args, { cwd, env: { ...operatorEnvironment(), ...(env || {}) }, stdio: ['ignore', 'pipe', 'pipe'], windowsHide: true }); }
    catch (error) { reject(error); return; }
    let stdout = '';
    let stderr = '';
    let settled = false;
    let stdoutBuffer = '';
    let stderrBuffer = '';
    const finish = (error, value) => { if (settled) return; settled = true; clearTimeout(timer); if (error) reject(error); else resolve(value); };
    const consumeLines = (bufferKey, chunk, level) => {
      if (bufferKey === 'stdout') stdoutBuffer += chunk.toString();
      else stderrBuffer += chunk.toString();
      let buffer = bufferKey === 'stdout' ? stdoutBuffer : stderrBuffer;
      let index;
      while ((index = buffer.indexOf('\n')) !== -1) {
        const line = buffer.slice(0, index).replace(/\r$/, '');
        buffer = buffer.slice(index + 1);
        if (onLine && line) onLine(level, line);
      }
      if (bufferKey === 'stdout') stdoutBuffer = buffer; else stderrBuffer = buffer;
    };
    child.stdout.on('data', (chunk) => {
      if (rejectOutputOverflow && Buffer.byteLength(stdout) + chunk.length > maxOutputBytes) {
        try { child.kill('SIGKILL'); } catch { /* gone */ }
        finish(new Error(`${bin} stdout exceeded the ${Math.ceil(maxOutputBytes / 1024)} KiB capture limit.`));
        return;
      }
      if (Buffer.byteLength(stdout) < maxOutputBytes) stdout += chunk.toString();
      consumeLines('stdout', chunk, 'info');
    });
    child.stderr.on('data', (chunk) => {
      if (Buffer.byteLength(stderr) < maxOutputBytes) stderr += chunk.toString();
      consumeLines('stderr', chunk, 'error');
    });
    const timer = setTimeout(() => { try { child.kill('SIGKILL'); } catch { /* gone */ } finish(new Error(`${bin} timed out after ${Math.ceil(timeoutMs / 1000)} seconds.`)); }, timeoutMs);
    timer.unref?.();
    child.once('error', (error) => finish(error));
    child.once('exit', (code, signal) => {
      if (code === 0) finish(null, { stdout: stdout.trim(), stderr: stderr.trim(), code: 0 });
      else finish(new Error(`${bin} exited ${code ?? signal ?? 'unexpectedly'}${stderr.trim() ? `: ${stderr.trim().slice(-2000)}` : ''}`));
    });
  });
}

/**
 * @param {string} bin
 * @param {string[]} args
 * @param {{ cwd?: string, env?: Record<string, string> }} [options]
 */
function spawnStreaming(bin, args, { cwd, env } = {}) {
  return spawn(bin, args, { cwd, env: { ...operatorEnvironment(), ...(env || {}) }, stdio: ['ignore', 'pipe', 'pipe'], windowsHide: true });
}

function projectRoot(candidate) { return assertPathInsideRoot(DATA_DIR, candidate, 'Path'); }

function agentContainerized() { return fs.existsSync('/.dockerenv'); }

// Bind mount sources must be host-visible paths for the Docker daemon, which
// runs on the host even when this agent process is itself containerized.
// SHAM_DOCKER_HOST_DATA_PATH must be set on the agent (not the control
// plane) for that translation, matching where docker.sock is now mounted.
function hostBindPath(containerPath) {
  const validated = projectRoot(containerPath);
  if (!agentContainerized()) return validated;
  const hostRoot = String(process.env.SHAM_DOCKER_HOST_DATA_PATH || '').trim();
  if (!hostRoot) throw new Error('Bind mounts require SHAM_DOCKER_HOST_DATA_PATH to be set on the runtime agent.');
  const relative = path.relative(DATA_DIR, validated);
  if (relative.startsWith('..') || path.isAbsolute(relative)) throw new Error('Mount path is outside the SHAM data directory.');
  return path.join(path.resolve(hostRoot), relative);
}

async function inspectRef(ref) {
  try {
    const result = await runTool(DOCKER_BIN, ['inspect', ref], { timeoutMs: 15_000 });
    const parsed = JSON.parse(result.stdout);
    return Array.isArray(parsed) ? parsed[0] || null : null;
  } catch { return null; }
}

function isManaged(inspected) {
  const labels = inspected?.Config?.Labels || {};
  if (labels['sham.managed'] === 'true') return true;
  const project = labels['com.docker.compose.project'] || '';
  return /^sham-\d+-/.test(project);
}

async function assertOwnedContainer(ref) {
  const inspected = await inspectRef(ref);
  if (!inspected) throw new AgentOperationError('Container not found.', 'NOT_FOUND');
  if (!isManaged(inspected)) throw new AgentOperationError('Container is not managed by SHAM.', 'NOT_OWNED');
  return inspected;
}

function composeFileArgs(files) { return files.flatMap((file) => ['-f', file]); }

function validateComposeFiles(files) {
  if (!Array.isArray(files) || !files.length || files.length > 4) throw new ValidationError('Compose file list is invalid.');
  return files.map((file) => projectRoot(file));
}

async function fetchAndValidateComposeConfig({ files, cwd, env, service, containerPort }) {
  const validatedFiles = validateComposeFiles(files);
  const root = projectRoot(cwd);
  const result = await runTool(DOCKER_BIN, ['compose', ...composeFileArgs(validatedFiles), 'config', '--format', 'json'], { cwd: root, env, timeoutMs: 30_000, maxOutputBytes: 2 * 1024 * 1024, rejectOutputOverflow: true });
  let config;
  try { config = JSON.parse(result.stdout); } catch { throw new Error('Docker Compose did not return a valid normalized configuration.'); }
  validateComposeProjectPaths(config, root);
  composeRuntimePolicy(config, service, { containerPort, requirePublishedPort: false });
  return { config, root, validatedFiles };
}

// ---------------------------------------------------------------------------
// Images
// ---------------------------------------------------------------------------

async function imagesBuild({ tag, contextPath, mode, dockerfilePath, builder }, emit) {
  assertImageTag(tag, 'Image tag');
  const root = projectRoot(contextPath);
  const log = (level, line) => emit({ type: 'log', level, line });
  if (mode === 'dockerfile') {
    const dockerfile = projectRoot(dockerfilePath);
    await runTool(DOCKER_BIN, ['build', '-f', dockerfile, '-t', tag, root], { onLine: log });
  } else if (mode === 'buildpack') {
    const builderImage = assertImageTag(builder || 'paketobuildpacks/builder-jammy-base', 'Buildpack builder');
    await runTool(PACK_BIN, ['build', tag, '--path', root, '--builder', builderImage], { onLine: log });
  } else if (mode === 'nixpacks') {
    await runTool(NIXPACKS_BIN, ['build', root, '--name', tag], { onLine: log });
  } else {
    throw new ValidationError('Unsupported build mode.');
  }
  emit({ type: 'result', data: { tag } });
}

async function imagesRemove({ tag }) {
  assertManagedImageTag(tag, 'Image tag');
  await runTool(DOCKER_BIN, ['image', 'rm', '-f', tag], { timeoutMs: 60_000 }).catch(() => {});
  return { removed: true };
}

// ---------------------------------------------------------------------------
// Containers
// ---------------------------------------------------------------------------

function validatePortSpec(ports) {
  if (ports === undefined || ports === null) return [];
  if (!Array.isArray(ports) || ports.length > 8) throw new ValidationError('Port list is invalid.');
  return ports.map((entry) => {
    const hostIp = String(entry.hostIp || '127.0.0.1');
    if (!['127.0.0.1', '::1'].includes(hostIp)) throw new ValidationError('Published ports may only bind to loopback addresses.');
    const containerPort = assertPort(entry.containerPort, 'Container port');
    return `${hostIp}::${containerPort}`;
  });
}

async function containersRun(params) {
  const name = assertContainerName(params.name, 'Container name');
  const image = assertImageTag(params.image, 'Image');
  const siteId = assertPositiveInt(params.siteId, 'Site id', { min: 1, max: Number.MAX_SAFE_INTEGER });
  const network = params.network ? assertNetworkName(params.network, 'Network') : null;
  const env = assertEnv(params.env, 'Environment');
  const dataMount = params.dataMount ? { source: params.dataMount.source, target: assertContainerPath(params.dataMount.target) } : null;
  const namedVolume = params.namedVolume ? String(params.namedVolume).slice(0, 200) : null;
  if (namedVolume && !/^[a-zA-Z0-9][a-zA-Z0-9_.-]{0,120}$/.test(namedVolume)) throw new ValidationError('Named volume is invalid.');
  const memoryMb = params.memoryMb ? assertPositiveInt(params.memoryMb, 'Memory limit', { min: 1, max: 1_048_576 }) : 0;
  const cpuLimit = params.cpuLimit ? Number(params.cpuLimit) : 0;
  const pidsLimit = assertPositiveInt(params.pidsLimit, 'PID limit', { min: 1, max: 100_000, fallback: 128 });
  const command = Array.isArray(params.command) ? params.command.map((entry) => assertCommandString(String(entry), 'Command argument')) : null;

  const args = [
    'run', '-d', '--name', name,
    '--label', MANAGED_LABEL, '--label', `sham.site_id=${siteId}`,
    '--init', '--cap-drop', 'ALL', '--security-opt', 'no-new-privileges:true', '--read-only',
    '--pids-limit', String(pidsLimit), '--tmpfs', '/tmp:rw,noexec,nosuid,size=64m'
  ];
  // Validate the mount source unconditionally, before deciding whether it is
  // actually used, so a caller cannot dodge the containment check merely by
  // exercising the named-volume fallback branch.
  if (dataMount) projectRoot(dataMount.source);
  if (dataMount && agentContainerized() && !String(process.env.SHAM_DOCKER_HOST_DATA_PATH || '').trim()) {
    if (!namedVolume) throw new Error('A named volume fallback is required when the runtime agent has no host data path configured.');
    args.push('-v', `${namedVolume}:${dataMount.target}:rw`);
  } else if (dataMount) {
    args.push('-v', `${hostBindPath(dataMount.source)}:${dataMount.target}:rw`);
  } else if (namedVolume) {
    args.push('-v', `${namedVolume}:/data:rw`);
  }
  if (network) args.push('--network', network);
  for (const binding of validatePortSpec(params.ports)) args.push('-p', binding);
  if (memoryMb > 0) args.push('--memory', `${memoryMb}m`);
  if (cpuLimit > 0 && Number.isFinite(cpuLimit)) args.push('--cpus', String(cpuLimit));
  for (const key of Object.keys(env)) args.push('-e', key);
  args.push(image);
  if (command) args.push(...command);

  const result = await runTool(DOCKER_BIN, args, { env, timeoutMs: 120_000 });
  const containerId = result.stdout.split(/\s+/).at(-1) || name;
  return { containerId, name };
}

function assertContainerPath(value) {
  if (typeof value !== 'string' || !/^\/[a-zA-Z0-9_./-]{0,200}$/.test(value)) throw new ValidationError('Container mount path is invalid.');
  return value;
}

async function containersStop({ name, timeoutSec }) {
  const containerName = assertContainerName(name, 'Container name');
  await assertOwnedContainer(containerName);
  const seconds = assertPositiveInt(timeoutSec, 'Stop timeout', { min: 0, max: 600, fallback: 10 });
  await runTool(DOCKER_BIN, ['stop', '--time', String(seconds), containerName], { timeoutMs: (seconds + 10) * 1000 }).catch(() => {});
  return { stopped: true };
}

async function containersRemove({ name }) {
  const containerName = assertContainerName(name, 'Container name');
  await assertOwnedContainer(containerName).catch((error) => { if (error.code !== 'NOT_FOUND') throw error; });
  await runTool(DOCKER_BIN, ['rm', '-f', containerName], { timeoutMs: 30_000 }).catch(() => {});
  return { removed: true };
}

async function containersPort({ name, containerPort, timeoutMs }) {
  const containerName = assertContainerName(name, 'Container name');
  await assertOwnedContainer(containerName);
  const port = assertPort(containerPort, 'Container port');
  const deadline = Date.now() + Math.max(1000, Number(timeoutMs) || 15_000);
  while (Date.now() < deadline) {
    const result = await runTool(DOCKER_BIN, ['port', containerName, `${port}/tcp`], { timeoutMs: 2000 }).catch(() => ({ stdout: '' }));
    const match = /(?:127\.0\.0\.1|0\.0\.0\.0|\[::\]|::1):(\d+)\s*$/.exec(result.stdout.split(/\r?\n/)[0] || '');
    if (match) return { port: Number(match[1]) };
    await new Promise((resolve) => setTimeout(resolve, 100));
  }
  throw new Error(`Docker did not publish container port ${port} in time.`);
}

async function containersLogs({ name }, emit) {
  const containerName = assertContainerName(name, 'Container name');
  await assertOwnedContainer(containerName);
  return /** @type {Promise<void>} */ (new Promise((resolve) => {
    const child = spawnStreaming(DOCKER_BIN, ['logs', '-f', '--tail', '200', containerName]);
    child.stdout.on('data', (chunk) => emit({ type: 'log', level: 'info', line: chunk.toString().trimEnd() }));
    child.stderr.on('data', (chunk) => emit({ type: 'log', level: 'error', line: chunk.toString().trimEnd() }));
    const finish = () => { emit({ type: 'result', data: {} }); resolve(); };
    child.once('exit', finish);
    child.once('error', finish);
  }));
}

async function containersWait({ name }, emit) {
  const containerName = assertContainerName(name, 'Container name');
  await assertOwnedContainer(containerName);
  return /** @type {Promise<void>} */ (new Promise((resolve) => {
    const child = spawnStreaming(DOCKER_BIN, ['wait', containerName]);
    let output = '';
    child.stdout.on('data', (chunk) => { output = `${output}${chunk}`.slice(-64); });
    const finish = () => {
      const code = Number.parseInt(output.trim().split(/\s+/).at(-1) || '', 10);
      emit({ type: 'result', data: { exitCode: Number.isInteger(code) ? code : null } });
      resolve();
    };
    child.once('exit', finish);
    child.once('error', finish);
  }));
}

async function containersExec({ name, command, timeoutMs }, emit) {
  const containerName = assertContainerName(name, 'Container name');
  await assertOwnedContainer(containerName);
  const cmd = assertCommandString(command, 'Command');
  const timeout = assertPositiveInt(timeoutMs, 'Timeout', { min: 100, max: 300_000, fallback: 5000 });
  await runTool(DOCKER_BIN, ['exec', containerName, '/bin/sh', '-lc', cmd], { timeoutMs: timeout, onLine: (level, line) => emit({ type: 'log', level, line }) });
  emit({ type: 'result', data: { ok: true } });
}

async function containersStats({ id }) {
  const containerId = assertContainerName(id, 'Container id');
  await assertOwnedContainer(containerId);
  const result = await runTool(DOCKER_BIN, ['stats', '--no-stream', '--format', '{{json .}}', containerId], { timeoutMs: 5000 });
  try { return JSON.parse(result.stdout); } catch { return null; }
}

async function containersSandboxRun({ image, envFile, workspaceSource, command, timeoutMs }, emit) {
  const img = assertImageTag(image, 'Image');
  const cmd = assertCommandString(command, 'Command');
  const workspace = hostBindPath(workspaceSource);
  const validatedEnvFile = envFile ? projectRoot(envFile) : null;
  const args = ['run', '--rm', '--init', '--cap-drop', 'ALL', '--security-opt', 'no-new-privileges:true'];
  if (validatedEnvFile) args.push('--env-file', validatedEnvFile);
  args.push('-v', `${workspace}:/workspace:rw`, '-w', '/workspace', img, '/bin/sh', '-lc', cmd);
  const timeout = assertPositiveInt(timeoutMs, 'Timeout', { min: 1000, max: 3_600_000, fallback: 600_000 });
  await runTool(DOCKER_BIN, args, { timeoutMs: timeout, onLine: (level, line) => emit({ type: 'log', level, line }) });
  emit({ type: 'result', data: {} });
}

// A single, tightly scoped sidecar kind (Anubis) rather than a general
// "run any container" endpoint. The image is pinned to this agent's own
// configured ANUBIS_IMAGE and never taken from the caller.
async function containersSidecarRun(params) {
  const name = assertContainerName(params.name, 'Sidecar name');
  if (!name.startsWith('sham-anubis-')) throw new ValidationError('Sidecar name must be a SHAM Anubis instance.');
  const policyFile = hostBindPath(params.policyFile);
  const port = assertPort(params.port, 'Bind port');
  const targetPort = assertPort(params.targetPort, 'Target port');
  const difficulty = assertPositiveInt(params.difficulty, 'Difficulty', { min: 1, max: 10, fallback: 4 });
  const domain = assertCommandString(params.domain || 'localhost', 'Domain', { maxLength: 253 });
  if (/[^a-zA-Z0-9.-]/.test(domain)) throw new ValidationError('Domain is invalid.');
  const networkMode = params.networkMode === 'host' ? 'host' : String(params.networkMode || '');
  if (networkMode !== 'host' && !/^container:[a-zA-Z0-9][a-zA-Z0-9_.-]{0,120}$/.test(networkMode)) throw new ValidationError('Sidecar network mode is invalid.');

  const args = ['run', '-d', '--name', name, '--label', MANAGED_LABEL, '--network', networkMode,
    '--cap-drop', 'ALL', '--security-opt', 'no-new-privileges:true', '--read-only',
    '--memory', '256m', '--cpus', '1', '--pids-limit', '128',
    '--tmpfs', '/tmp:rw,noexec,nosuid,size=32m', '-v', `${policyFile}:/data/cfg/botPolicy.yaml:ro`,
    '-e', `BIND=127.0.0.1:${port}`, '-e', 'BIND_NETWORK=tcp',
    '-e', `TARGET=http://127.0.0.1:${targetPort}`, '-e', 'POLICY_FNAME=/data/cfg/botPolicy.yaml',
    '-e', `DIFFICULTY=${difficulty}`, '-e', 'SERVE_ROBOTS_TXT=true',
    '-e', `REDIRECT_DOMAINS=${domain}`, '-e', `COOKIE_DOMAIN=${domain}`, ANUBIS_IMAGE];
  await runTool(DOCKER_BIN, args, { timeoutMs: 30_000 });
  return { started: true };
}

async function containersSidecarRemove({ name }) {
  const containerName = assertContainerName(name, 'Sidecar name');
  if (!containerName.startsWith('sham-anubis-')) throw new ValidationError('Sidecar name must be a SHAM Anubis instance.');
  await runTool(DOCKER_BIN, ['rm', '-f', containerName], { timeoutMs: 15_000 }).catch(() => {});
  return { removed: true };
}

// ---------------------------------------------------------------------------
// Networks
// ---------------------------------------------------------------------------

async function networksEnsure({ name, internal = true }) {
  const network = assertNetworkName(name, 'Network');
  if (![DOCKER_INTERNAL_NETWORK, DOCKER_EGRESS_NETWORK].includes(network)) throw new ValidationError('Network is not a configured SHAM runtime network.');
  try { await runTool(DOCKER_BIN, ['network', 'inspect', network], { timeoutMs: 15_000 }); return { name: network }; }
  catch {
    const args = ['network', 'create', '--driver', 'bridge', '--label', MANAGED_LABEL];
    if (internal) args.push('--internal');
    args.push(network);
    try { await runTool(DOCKER_BIN, args, { timeoutMs: 30_000 }); }
    catch (error) { await runTool(DOCKER_BIN, ['network', 'inspect', network], { timeoutMs: 15_000 }).catch(() => { throw error; }); }
    return { name: network };
  }
}

async function networksConnect({ network, containerId, alias }) {
  const networkName = assertNetworkName(network, 'Network');
  if (![DOCKER_INTERNAL_NETWORK, DOCKER_EGRESS_NETWORK].includes(networkName)) throw new ValidationError('Network is not a configured SHAM runtime network.');
  const inspected = await assertOwnedContainer(containerId);
  const aliasName = assertNetworkName(alias, 'Network alias');
  await runTool(DOCKER_BIN, ['network', 'connect', '--alias', aliasName, networkName, inspected.Id], { timeoutMs: 30_000 });
  return { connected: true };
}

// ---------------------------------------------------------------------------
// Compose
// ---------------------------------------------------------------------------

async function composeConfigOp({ files, cwd, env, service, containerPort }) {
  const { config } = await fetchAndValidateComposeConfig({ files, cwd, env, service, containerPort });
  return { config };
}

async function composeUp({ project, files, cwd, env, service, containerPort }, emit) {
  const projectName = assertComposeProject(project, 'Compose project');
  const { root, validatedFiles } = await fetchAndValidateComposeConfig({ files, cwd, env, service, containerPort });
  await runTool(DOCKER_BIN, ['compose', '-p', projectName, ...composeFileArgs(validatedFiles), 'up', '-d', '--build', service], {
    cwd: root, env, onLine: (level, line) => emit({ type: 'log', level, line })
  });
  emit({ type: 'result', data: {} });
}

async function composePs({ project, files, cwd, env, service }) {
  const projectName = assertComposeProject(project, 'Compose project');
  const validatedFiles = validateComposeFiles(files);
  const root = projectRoot(cwd);
  const result = await runTool(DOCKER_BIN, ['compose', '-p', projectName, ...composeFileArgs(validatedFiles), 'ps', '-q', service], { cwd: root, env, timeoutMs: 30_000 });
  return { containerId: result.stdout.trim() };
}

async function composePort({ project, files, cwd, env, service, containerPort }) {
  const projectName = assertComposeProject(project, 'Compose project');
  const validatedFiles = validateComposeFiles(files);
  const root = projectRoot(cwd);
  const port = assertPort(containerPort, 'Container port');
  const result = await runTool(DOCKER_BIN, ['compose', '-p', projectName, ...composeFileArgs(validatedFiles), 'port', service, String(port)], { cwd: root, env, timeoutMs: 30_000 });
  const match = /:(\d+)\s*$/.exec(result.stdout.trim());
  if (!match) throw new Error(`Compose service ${service} did not publish container port ${port} to loopback.`);
  return { port: Number(match[1]) };
}

async function composeDown({ project, files, cwd, env }) {
  const projectName = assertComposeProject(project, 'Compose project');
  const validatedFiles = validateComposeFiles(files);
  const root = projectRoot(cwd);
  await runTool(DOCKER_BIN, ['compose', '-p', projectName, ...composeFileArgs(validatedFiles), 'down', '--remove-orphans'], { cwd: root, env, timeoutMs: 90_000 }).catch(() => {});
  return { removed: true };
}

async function composeExec({ project, files, cwd, env, service, command, timeoutMs }, emit) {
  const projectName = assertComposeProject(project, 'Compose project');
  const validatedFiles = validateComposeFiles(files);
  const root = projectRoot(cwd);
  const cmd = assertCommandString(command, 'Command');
  const timeout = assertPositiveInt(timeoutMs, 'Timeout', { min: 100, max: 300_000, fallback: 5000 });
  await runTool(DOCKER_BIN, ['compose', '-p', projectName, ...composeFileArgs(validatedFiles), 'exec', '-T', service, '/bin/sh', '-lc', cmd], { cwd: root, env, timeoutMs: timeout, onLine: (level, line) => emit({ type: 'log', level, line }) });
  emit({ type: 'result', data: { ok: true } });
}

// ---------------------------------------------------------------------------
// Cleanup (reconciliation of SHAM-owned resources only)
// ---------------------------------------------------------------------------

async function cleanupComposeProject({ project, file, cwd }) {
  const projectName = assertComposeProject(project, 'Compose project');
  const composeFile = projectRoot(file);
  const root = projectRoot(cwd);
  await runTool(DOCKER_BIN, ['compose', '-p', projectName, '-f', composeFile, 'down', '--remove-orphans'], { cwd: root, timeoutMs: 60_000 }).catch(() => {});
  return { cleaned: true };
}

async function cleanupOrphanedComposeProject({ project }) {
  const projectName = assertComposeProject(project, 'Compose project');
  const containers = await runTool(DOCKER_BIN, ['ps', '-aq', '--filter', `label=com.docker.compose.project=${projectName}`], { timeoutMs: 20_000 }).catch(() => ({ stdout: '' }));
  for (const id of containers.stdout.split(/\s+/).filter(Boolean)) await runTool(DOCKER_BIN, ['rm', '-f', id], { timeoutMs: 30_000 }).catch(() => {});
  const networks = await runTool(DOCKER_BIN, ['network', 'ls', '-q', '--filter', `label=com.docker.compose.project=${projectName}`], { timeoutMs: 20_000 }).catch(() => ({ stdout: '' }));
  for (const id of networks.stdout.split(/\s+/).filter(Boolean)) await runTool(DOCKER_BIN, ['network', 'rm', id], { timeoutMs: 30_000 }).catch(() => {});
  return { cleaned: true };
}

async function cleanupManagedContainers() {
  const result = await runTool(DOCKER_BIN, ['ps', '-aq', '--filter', `label=${MANAGED_LABEL}`], { timeoutMs: 20_000 });
  for (const id of result.stdout.split(/\s+/).filter(Boolean)) await runTool(DOCKER_BIN, ['rm', '-f', id], { timeoutMs: 30_000 }).catch(() => {});
  return { cleaned: true };
}

async function cleanupManagedImages() {
  const images = await runTool(DOCKER_BIN, ['image', 'ls', '--format', '{{.Repository}}:{{.Tag}}'], { timeoutMs: 20_000 });
  for (const image of images.stdout.split(/\r?\n/).map((value) => value.trim()).filter((value) => /^sham\/site-\d+:/.test(value))) {
    await runTool(DOCKER_BIN, ['image', 'rm', '-f', image], { timeoutMs: 60_000 }).catch(() => {});
  }
  return { cleaned: true };
}

// ---------------------------------------------------------------------------
// Status
// ---------------------------------------------------------------------------

function commandAvailable(bin) {
  try { require('node:child_process').execFileSync(bin, ['--version'], { stdio: 'ignore', timeout: 5000 }); return true; }
  catch { return false; }
}

async function status() {
  let dockerAvailable = false;
  let dockerVersion = '';
  try {
    const result = await runTool(DOCKER_BIN, ['version', '--format', '{{.Server.Version}}'], { timeoutMs: 5000 });
    dockerAvailable = true;
    dockerVersion = result.stdout.trim();
  } catch { /* daemon unreachable */ }
  return {
    dockerAvailable,
    dockerVersion,
    composeAvailable: dockerAvailable && commandAvailable(DOCKER_BIN),
    buildpacksAvailable: commandAvailable(PACK_BIN),
    nixpacksAvailable: commandAvailable(NIXPACKS_BIN)
  };
}

module.exports = {
  imagesBuild, imagesRemove,
  containersRun, containersStop, containersRemove, containersPort, containersLogs, containersWait,
  containersExec, containersStats, containersSandboxRun, containersSidecarRun, containersSidecarRemove,
  networksEnsure, networksConnect,
  composeConfigOp, composeUp, composePs, composePort, composeDown, composeExec,
  cleanupComposeProject, cleanupOrphanedComposeProject, cleanupManagedContainers, cleanupManagedImages,
  status
};
