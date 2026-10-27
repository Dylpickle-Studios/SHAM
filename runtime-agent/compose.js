'use strict';

const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { composeReferencedPaths } = require('../src/sites/runtime');
const { ValidationError } = require('./validation');

// Docker's default set minus MKNOD, NET_RAW, SETFCAP, SYS_CHROOT and
// AUDIT_WRITE: enough for common images (postgres, nginx, redis) to drop
// privileges and chown their data directories.
const COMPOSE_COMPAT_CAPABILITIES = Object.freeze(['CHOWN', 'DAC_OVERRIDE', 'FOWNER', 'FSETID', 'KILL', 'SETGID', 'SETUID', 'SETPCAP', 'NET_BIND_SERVICE']);
const MAX_INLINE_FILE_BYTES = 1024 * 1024;

// Plain keys need whitespace after the colon; quoted (JSON-style) keys do not.
const keyPattern = (name) => new RegExp(String.raw`(?:^|[{,])[ \t]*(?:-[ \t]+)*(?:![^\s]*[ \t]+)?(?:&[^\s]+[ \t]+)?(?:"${name}"[ \t]*:|'${name}'[ \t]*:|${name}[ \t]*:(?=[ \t]|$))`);
const INCLUDE_KEY = keyPattern('include');
const EXTENDS_KEY = keyPattern('extends');
const FILE_KEY = keyPattern('file');

// `include` and `extends.file` merge other YAML files before normalization and
// leave no trace in `compose config` output, so their paths cannot be checked
// afterwards. Reject them in the raw source instead, along with the YAML
// constructs (escaped, explicit, or aliased keys) that could hide those keys.
function assertNoExternalComposeSources(text, label = 'Compose file') {
  const lines = String(text).split(/\r?\n/);
  for (let index = 0; index < lines.length; index += 1) {
    const line = lines[index];
    if (/^[ \t]*(?:-[ \t]+)*\?(?:[ \t]|$)/.test(line)) throw new ValidationError(`${label} cannot use explicit YAML mapping keys.`);
    if (/(?:^|[{,])[ \t]*(?:-[ \t]+)*\*[^\s:,{}]+[ \t]*:(?=[ \t]|$)/.test(line)) throw new ValidationError(`${label} cannot use YAML aliases as mapping keys.`);
    if (/"(?:[^"\\]|\\.)*\\(?:[^"\\]|\\.)*"[ \t]*:/.test(line)) throw new ValidationError(`${label} cannot use escape sequences in mapping keys.`);
    if (INCLUDE_KEY.test(line)) throw new ValidationError(`${label} cannot use include; SHAM validates a single Compose project tree.`);
    const match = EXTENDS_KEY.exec(line);
    if (!match) continue;
    const column = match.index + match[0].search(/['"]?extends/);
    const rest = line.slice(match.index + match[0].length).trim();
    const external = () => new ValidationError(`${label} cannot extend services from other files; define the service in this Compose file.`);
    if (rest) {
      // Same-line value: a plain service name, or a flow mapping that must
      // close on this line (checked up to its closing brace, as in JSON).
      let value = rest;
      if (rest.startsWith('{')) {
        let depth = 0;
        let end = -1;
        for (let position = 0; position < rest.length && end === -1; position += 1) {
          if (rest[position] === '{') depth += 1;
          else if (rest[position] === '}' && --depth === 0) end = position;
        }
        if (end === -1) throw external();
        value = rest.slice(1, end);
      }
      if (FILE_KEY.test(`,${value}`) || /[*]|<</.test(value)) throw external();
      continue;
    }
    for (let child = index + 1; child < lines.length; child += 1) {
      const next = lines[child];
      if (!next.trim() || /^[ \t]*#/.test(next)) continue;
      if (next.search(/\S/) <= column) break;
      if (FILE_KEY.test(next) || /[*]|<</.test(next)) throw external();
    }
  }
}

function insideRoot(root, candidate) { return candidate === root || candidate.startsWith(`${root}${path.sep}`); }

/**
 * Realpath containment for every host path the normalized model references.
 * @param {any} config
 * @param {string} root realpath of the project directory
 */
function assertComposeRealPaths(config, root) {
  const resolved = new Map();
  let entries;
  try { entries = composeReferencedPaths(config, root); }
  catch (error) { throw new ValidationError(error instanceof Error ? error.message : String(error)); }
  for (const entry of entries) {
    if (entry.path.includes('$')) throw new ValidationError(`${entry.label} cannot use variable interpolation in its path.`);
    let real;
    try { real = fs.realpathSync(entry.path); }
    catch (error) {
      if (entry.optional && /** @type {NodeJS.ErrnoException} */ (error).code === 'ENOENT') continue;
      throw new ValidationError(`${entry.label} is missing or cannot be resolved inside the site project.`);
    }
    if (!insideRoot(root, real)) throw new ValidationError(`${entry.label} must stay inside the site project.`);
    const stat = fs.statSync(real);
    if (entry.type === 'directory' ? !stat.isDirectory() : !stat.isFile()) throw new ValidationError(`${entry.label} must be a ${entry.type}.`);
    resolved.set(entry.path, real);
  }
  return resolved;
}

// Read a referenced file through one descriptor and re-check where that
// descriptor really points, so a symlink swapped in after validation cannot
// redirect the read outside the project.
function readContainedFile(root, file, label) {
  const fd = fs.openSync(file, fs.constants.O_RDONLY | (fs.constants.O_NOFOLLOW || 0));
  try {
    let actual = file;
    try { actual = fs.realpathSync(`/proc/self/fd/${fd}`); } catch { /* non-Linux: realpath was checked above */ }
    if (!insideRoot(root, actual)) throw new ValidationError(`${label} must stay inside the site project.`);
    const stat = fs.fstatSync(fd);
    if (!stat.isFile()) throw new ValidationError(`${label} must be a file.`);
    if (stat.size > MAX_INLINE_FILE_BYTES) throw new ValidationError(`${label} is larger than ${MAX_INLINE_FILE_BYTES / 1024} KiB.`);
    return fs.readFileSync(fd);
  } finally { fs.closeSync(fd); }
}

function inlineText(buffer, label) {
  const text = buffer.toString('utf8');
  if (!Buffer.from(text, 'utf8').equals(buffer)) throw new ValidationError(`${label} must be UTF-8 text.`);
  // Compose interpolates the generated file again; keep literal dollars literal.
  return text.replaceAll('$', '$$$$');
}

const capabilityName = (value) => String(value || '').trim().toUpperCase().replace(/^CAP_/, '');

/**
 * Produce the exact model `docker compose up` will run: forced capability and
 * privilege hardening, realpath-pinned build paths, and project files inlined
 * so nothing is re-read from the (mutable) project tree except build contexts.
 * @param {any} config validated, normalized Compose model
 * @param {{ root: string, resolved: Map<string, string>, secretDir: string }} options
 */
function hardenComposeConfig(config, { root, resolved, secretDir }) {
  const hardened = structuredClone(config);
  const real = (candidate) => resolved.get(candidate) || candidate;
  const configs = hardened.configs || {};
  const secrets = hardened.secrets || {};
  for (const [name, definition] of Object.entries(configs)) {
    if (!definition?.file) continue;
    const file = real(path.resolve(root, definition.file));
    const inlined = { ...definition, content: inlineText(readContainedFile(root, file, `Compose config ${name}`), `Compose config ${name}`) };
    delete inlined.file;
    configs[name] = inlined;
  }
  const buildSecrets = new Set();
  for (const service of Object.values(hardened.services || {})) {
    for (const entry of service?.build?.secrets || []) buildSecrets.add(typeof entry === 'string' ? entry : entry?.source);
  }
  const secretContent = new Map();
  for (const [name, definition] of Object.entries(secrets)) {
    if (!definition?.file) continue;
    const file = real(path.resolve(root, definition.file));
    const content = readContainedFile(root, file, `Compose secret ${name}`);
    secretContent.set(name, content);
    if (buildSecrets.has(name)) {
      // Build secrets are read by the local Compose client, so a private
      // snapshot works even when the agent itself is containerized.
      const snapshot = path.join(secretDir, `secret-${secretContent.size}`);
      fs.writeFileSync(snapshot, content, { mode: 0o600, flag: 'wx' });
      secrets[name] = { ...definition, file: snapshot };
    } else delete secrets[name];
  }
  for (const name of secretContent.keys()) {
    if (Object.hasOwn(configs, `sham-secret-${name}`)) throw new ValidationError(`Compose config name sham-secret-${name} is reserved for SHAM secret delivery.`);
  }
  // `image` next to `build` tags the result. Never let a project retag a host image
  // (for example SHAM's own, or one another site runs); give the build the
  // project-scoped name Compose would choose, and point every service that
  // referenced the original tag at it so shared-image projects keep working.
  const builtImages = new Map();
  for (const [serviceName, service] of Object.entries(hardened.services || {})) {
    if (service.build && service.image && !builtImages.has(String(service.image))) builtImages.set(String(service.image), `${hardened.name || 'sham'}-${serviceName}`.toLowerCase());
  }
  for (const service of Object.values(hardened.services || {})) {
    if (service.image && builtImages.has(String(service.image))) {
      service.image = builtImages.get(String(service.image));
      // The tag only exists once the project builds it; never pull a same-named image.
      if (!service.build) service.pull_policy = 'never';
    }
    const dropped = new Set((service.cap_drop || []).map(capabilityName));
    service.cap_drop = ['ALL'];
    service.cap_add = dropped.has('ALL') ? [] : COMPOSE_COMPAT_CAPABILITIES.filter((capability) => !dropped.has(capability));
    service.security_opt = ['no-new-privileges:true'];
    // Only `compose watch` reads develop; SHAM never runs it.
    delete service.develop;
    if (service.build) {
      const build = typeof service.build === 'string' ? { context: service.build } : service.build;
      const context = path.resolve(root, String(build.context || '.'));
      build.context = real(context);
      if (build.dockerfile && !build.dockerfile_inline) build.dockerfile = real(path.resolve(context, String(build.dockerfile)));
      for (const [contextName, value] of Object.entries(build.additional_contexts || {})) {
        if (!String(value).startsWith('service:')) build.additional_contexts[contextName] = real(path.resolve(root, String(value)));
      }
      service.build = build;
    }
    if (Array.isArray(service.env_file)) {
      service.env_file = service.env_file.map((entry) => typeof entry === 'object' ? { ...entry, path: real(path.resolve(root, entry.path)) } : real(path.resolve(root, entry)));
    }
    // File-backed secrets become bind mounts of host paths; deliver the
    // validated bytes as Compose config content at the same target instead.
    const remaining = [];
    for (const entry of service.secrets || []) {
      const reference = typeof entry === 'string' ? { source: entry } : { ...entry };
      if (!secretContent.has(reference.source)) { remaining.push(entry); continue; }
      const configName = `sham-secret-${reference.source}`;
      configs[configName] ||= { name: `${hardened.name || 'sham'}_${configName}`, content: inlineText(secretContent.get(reference.source), `Compose secret ${reference.source}`) };
      const target = String(reference.target || reference.source);
      service.configs = [...(service.configs || []), {
        source: configName,
        target: target.startsWith('/') ? target : `/run/secrets/${target}`,
        ...(reference.uid !== undefined ? { uid: reference.uid } : {}),
        ...(reference.gid !== undefined ? { gid: reference.gid } : {}),
        ...(reference.mode !== undefined ? { mode: reference.mode } : {})
      }];
    }
    if (service.secrets) {
      if (remaining.length) service.secrets = remaining;
      else delete service.secrets;
    }
  }
  if (Object.keys(configs).length) hardened.configs = configs;
  if (Object.keys(secrets).length) hardened.secrets = secrets; else delete hardened.secrets;
  return hardened;
}

/**
 * Write the validated model to the agent's own private temp directory. In the
 * isolation overlay that is the agent container's /tmp, never the shared /data
 * volume the control plane (or a workload build) could write to.
 * @param {any} config
 * @param {{ root: string, resolved: Map<string, string> }} options
 */
async function writeHardenedComposeProject(config, { root, resolved }) {
  const directory = await fs.promises.mkdtemp(path.join(os.tmpdir(), 'sham-agent-compose-'));
  try {
    await fs.promises.chmod(directory, 0o700);
    const hardened = hardenComposeConfig(config, { root, resolved, secretDir: directory });
    const file = path.join(directory, 'compose.json');
    await fs.promises.writeFile(file, `${JSON.stringify(hardened)}\n`, { mode: 0o600, flag: 'wx' });
    return { directory, file, config: hardened };
  } catch (error) {
    await fs.promises.rm(directory, { recursive: true, force: true });
    throw error;
  }
}

// Models from a previous agent process are unreachable (the project map is in
// memory); teardown then falls back to Compose labels. Skip recent directories
// in case another agent shares this temp directory and is mid-`up`.
function removeStaleComposeProjects({ olderThanMs = 10 * 60_000 } = {}) {
  const root = os.tmpdir();
  let entries;
  try { entries = fs.readdirSync(root, { withFileTypes: true }); } catch { return; }
  for (const entry of entries) {
    if (!entry.isDirectory() || !entry.name.startsWith('sham-agent-compose-')) continue;
    const directory = path.join(root, entry.name);
    try {
      const stat = fs.lstatSync(directory);
      if (stat.uid === process.getuid?.() && Date.now() - stat.mtimeMs > olderThanMs) fs.rmSync(directory, { recursive: true, force: true });
    } catch { /* already gone */ }
  }
}

module.exports = {
  COMPOSE_COMPAT_CAPABILITIES, removeStaleComposeProjects,
  assertNoExternalComposeSources, assertComposeRealPaths, hardenComposeConfig, writeHardenedComposeProject
};
