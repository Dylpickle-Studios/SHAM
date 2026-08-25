'use strict';

const fs = require('node:fs');
const path = require('node:path');
const crypto = require('node:crypto');

const RUNTIME_PRESETS = Object.freeze({
  static: { driver: 'static', entryFile: 'index.html' },
  node: { driver: 'process', command: 'node server.js', portEnv: 'PORT', readiness: 'tcp' },
  npm: { driver: 'process', command: 'npm run start', portEnv: 'PORT', readiness: 'http' },
  bun: { driver: 'process', command: 'bun run start', portEnv: 'PORT', readiness: 'http' },
  deno: { driver: 'process', command: 'deno run --allow-net --allow-env --allow-read server.ts', portEnv: 'PORT', readiness: 'http' },
  fastapi: { driver: 'process', command: 'uvicorn app:app --host "$HOST" --port "$PORT"', portEnv: 'PORT', readiness: 'http' },
  django: { driver: 'process', command: 'gunicorn app.wsgi:application --bind "$HOST:$PORT"', portEnv: 'PORT', readiness: 'http' },
  go: { driver: 'process', command: './app', portEnv: 'PORT', readiness: 'http' },
  java: { driver: 'process', command: 'java -jar app.jar', portEnv: 'PORT', readiness: 'http' },
  custom: { driver: 'process', command: '', portEnv: 'PORT', readiness: 'http' },
  dockerfile: { driver: 'container', containerMode: 'dockerfile', dockerfilePath: 'Dockerfile', containerPort: 3000, portEnv: 'PORT', readiness: 'http' },
  buildpack: { driver: 'container', containerMode: 'buildpack', containerPort: 3000, portEnv: 'PORT', readiness: 'http' },
  nixpacks: { driver: 'container', containerMode: 'nixpacks', containerPort: 3000, portEnv: 'PORT', readiness: 'http' },
  image: { driver: 'container', containerMode: 'image', containerPort: 3000, portEnv: 'PORT', readiness: 'http' },
  compose: { driver: 'compose', composeFile: 'compose.yaml', composeService: 'app', containerPort: 3000, readiness: 'http' },
  proxy: { driver: 'proxy' }
});

function safeRelative(value, label) {
  const normalized = String(value || '').replaceAll('\\', '/').replace(/^\.\//, '');
  if (!normalized || normalized === '.') return normalized === '.' ? '.' : '';
  if (normalized.startsWith('/') || /^[A-Za-z]:\//.test(normalized) || normalized.split('/').some((part) => !part || part === '.' || part === '..')) {
    throw new Error(`${label} must be a safe relative path.`);
  }
  if (normalized.length > 500 || normalized.includes('\0')) throw new Error(`${label} is invalid or too long.`);
  return normalized;
}

function cleanCommand(value, label = 'Runtime command') {
  const text = String(value || '').trim();
  if (text.length > 8000 || text.includes('\0') || /[\r\n]/.test(text)) throw new Error(`${label} is invalid or too long.`);
  return text;
}


function cleanRuntimeCommand(value, label = 'Runtime command') {
  if (!Array.isArray(value)) return cleanCommand(value, label);
  if (!value.length || value.length > 128) throw new Error(`${label} argument vector must contain between 1 and 128 items.`);
  let total = 0;
  const argv = value.map((item, index) => {
    if (typeof item !== 'string') throw new Error(`${label} argument ${index + 1} must be a string.`);
    if (!item.length || item.length > 4096 || /\0|\r|\n/.test(item)) throw new Error(`${label} argument ${index + 1} is invalid or too long.`);
    total += item.length;
    return item;
  });
  if (total > 8000) throw new Error(`${label} argument vector is too long.`);
  return argv;
}

function cleanImage(value) {
  const image = String(value || '').trim();
  if (!image || image.length > 300 || !/^[A-Za-z0-9][A-Za-z0-9._/@:+-]*$/.test(image) || image.startsWith('-')) throw new Error('Container image reference is invalid.');
  return image;
}

function cleanEnvName(value, fallback = 'PORT') {
  const name = String(value || fallback).trim().toUpperCase();
  if (!/^[A-Z_][A-Z0-9_]{0,127}$/.test(name)) throw new Error('Runtime port environment-variable name is invalid.');
  return name;
}

function boundedNumber(value, fallback, min, max, label) {
  if (value === undefined || value === null || value === '') return fallback;
  const number = Number(value);
  if (!Number.isFinite(number) || number < min || number > max) throw new Error(`${label} must be between ${min} and ${max}.`);
  return number;
}

function scalar(value) {
  const raw = String(value).trim();
  if (!raw) return '';
  if (raw === 'true') return true;
  if (raw === 'false') return false;
  if (raw === 'null' || raw === '~') return null;
  if (/^-?\d+(?:\.\d+)?$/.test(raw)) return Number(raw);
  if ((raw.startsWith('"') && raw.endsWith('"')) || (raw.startsWith("'") && raw.endsWith("'"))) {
    if (raw.startsWith('"')) { try { return JSON.parse(raw); } catch { /* below */ } }
    return raw.slice(1, -1).replace(/''/g, "'");
  }
  if ((raw.startsWith('[') && raw.endsWith(']')) || (raw.startsWith('{') && raw.endsWith('}'))) {
    try { return JSON.parse(raw); } catch { /* text */ }
  }
  return raw;
}

function stripYamlComment(sourceLine) {
  let single = false;
  let double = false;
  let escaped = false;
  for (let index = 0; index < sourceLine.length; index += 1) {
    const char = sourceLine[index];
    if (double) {
      if (escaped) { escaped = false; continue; }
      if (char === '\\') { escaped = true; continue; }
      if (char === '"') double = false;
      continue;
    }
    if (single) {
      if (char === "'" && sourceLine[index + 1] === "'") { index += 1; continue; }
      if (char === "'") single = false;
      continue;
    }
    if (char === '"') { double = true; continue; }
    if (char === "'") { single = true; continue; }
    if (char === '#' && (index === 0 || /\s/.test(sourceLine[index - 1]))) return sourceLine.slice(0, index).trimEnd();
  }
  return sourceLine;
}

// A deliberately small YAML subset: nested mappings and scalar/JSON-style values.
// Runtime manifests are execution policy, so unsupported YAML constructs fail closed.
function parseSimpleYaml(text) {
  const root = {};
  const stack = [{ indent: -1, value: root }];
  for (const [index, sourceLine] of String(text || '').split(/\r?\n/).entries()) {
    if (!sourceLine.trim() || /^\s*#/.test(sourceLine)) continue;
    const leading = sourceLine.match(/^\s*/)?.[0] || '';
    if (leading.includes('\t')) throw new Error(`sham.yaml line ${index + 1} uses tabs; use spaces.`);
    const line = stripYamlComment(sourceLine);
    const indent = line.length - line.trimStart().length;
    const match = /^\s*([A-Za-z0-9_.-]+)\s*:\s*(.*)$/.exec(line);
    if (!match) throw new Error(`sham.yaml line ${index + 1} is outside the supported mapping subset.`);
    // `stack` always has at least its root entry (pushed before this loop
    // starts and never fully popped, since the loop condition requires
    // stack.length > 1 to pop), so .at(-1) is never undefined here.
    while (stack.length > 1 && indent <= /** @type {{indent: number}} */ (stack.at(-1)).indent) stack.pop();
    const parent = /** @type {{value: Record<string, any>}} */ (stack.at(-1)).value;
    if (Object.prototype.hasOwnProperty.call(parent, match[1])) throw new Error(`sham.yaml line ${index + 1} repeats key ${match[1]}.`);
    if (!match[2]) {
      parent[match[1]] = {};
      stack.push({ indent, value: parent[match[1]] });
    } else parent[match[1]] = scalar(match[2]);
  }
  return root;
}

function readManifest(root) {
  const candidates = ['sham.yaml', 'sham.yml', 'sham.json'];
  const filename = candidates.find((name) => fs.existsSync(path.join(root, name)));
  if (!filename) return null;
  const absolute = path.join(root, filename);
  const raw = fs.readFileSync(absolute, 'utf8');
  if (Buffer.byteLength(raw) > 256 * 1024) throw new Error('SHAM manifest is too large.');
  const manifest = filename.endsWith('.json') ? JSON.parse(raw) : parseSimpleYaml(raw);
  if (!manifest || Array.isArray(manifest) || typeof manifest !== 'object') throw new Error('SHAM manifest must contain an object/mapping.');
  return { filename, manifest, raw };
}

function legacyPreset(site) {
  if (site.runtime_type === 'static') return 'static';
  if (site.runtime_type === 'proxy') return 'proxy';
  if (site.runtime_type === 'node') return site.runtime_isolation === 'docker' ? 'image' : 'node';
  if (site.runtime_type === 'container') return site.runtime_preset || ({ dockerfile: 'dockerfile', buildpack: 'buildpack', nixpacks: 'nixpacks' }[site.container_mode] || 'image');
  if (site.runtime_type === 'compose') return 'compose';
  if (site.runtime_type === 'process') return site.runtime_preset || 'custom';
  return 'static';
}

function manifestOverrides(record) {
  const manifest = record?.manifest;
  if (!manifest) return {};
  const runtime = manifest.runtime && typeof manifest.runtime === 'object' ? manifest.runtime : {};
  const build = manifest.build && typeof manifest.build === 'object' ? manifest.build : {};
  const readiness = manifest.readiness && typeof manifest.readiness === 'object' ? manifest.readiness : (manifest.health && typeof manifest.health === 'object' ? manifest.health : {});
  const shutdown = manifest.shutdown && typeof manifest.shutdown === 'object' ? manifest.shutdown : {};
  const container = manifest.container && typeof manifest.container === 'object' ? manifest.container : {};
  const compose = manifest.compose && typeof manifest.compose === 'object' ? manifest.compose : {};
  return {
    preset: runtime.preset,
    driver: runtime.driver,
    command: runtime.command,
    workingDirectory: runtime.workingDirectory ?? runtime.working_directory,
    portEnv: runtime.portEnv ?? runtime.port_env,
    installCommand: build.install ?? build.installCommand,
    buildCommand: build.command ?? build.buildCommand,
    buildOutputDir: build.output ?? build.outputDirectory,
    readinessType: readiness.type,
    readinessPath: readiness.path,
    readinessCommand: readiness.command,
    readinessStatusMin: readiness.statusMin ?? readiness.status_min,
    readinessStatusMax: readiness.statusMax ?? readiness.status_max,
    startupTimeoutSeconds: readiness.timeoutSeconds ?? readiness.timeout_seconds,
    shutdownGraceSeconds: shutdown.graceSeconds ?? shutdown.grace_seconds,
    drainSeconds: shutdown.drainSeconds ?? shutdown.drain_seconds,
    containerMode: container.mode ?? container.buildMode ?? container.build_mode,
    image: container.image,
    containerPort: container.port,
    dockerfilePath: container.dockerfile ?? container.dockerfilePath,
    buildpackBuilder: container.builder,
    composeFile: compose.file,
    composeService: compose.service,
    composePort: compose.port
  };
}

function resolveRuntimeSpec(site, root, { manifestRecord = null } = {}) {
  const useManifest = site.manifest_enabled === undefined ? true : Boolean(site.manifest_enabled);
  const override = useManifest ? manifestOverrides(manifestRecord) : {};
  const legacyDockerNode = site.runtime_type === 'node' && site.runtime_isolation === 'docker' && !override.preset && (!site.runtime_preset || site.runtime_preset === 'node');
  const presetName = String(legacyDockerNode ? 'image' : (override.preset || site.runtime_preset || legacyPreset(site))).trim().toLowerCase();
  const preset = RUNTIME_PRESETS[presetName];
  if (!preset) throw new Error(`Unknown runtime preset: ${presetName || '(empty)'}.`);
  const requestedDriver = String(override.driver || preset.driver).trim().toLowerCase();
  if (!['static', 'process', 'container', 'compose', 'proxy'].includes(requestedDriver)) throw new Error('Runtime driver must be static, process, container, compose, or proxy.');
  const legacyNode = site.runtime_type === 'node' ? `node ${JSON.stringify(String(site.node_entry || 'server.js'))}` : '';
  const workingRaw = String(override.workingDirectory ?? site.working_directory ?? '.').trim() || '.';
  const readinessType = String(override.readinessType || site.readiness_type || preset.readiness || (['static', 'proxy'].includes(requestedDriver) ? 'none' : 'http')).toLowerCase();
  if (!['none', 'tcp', 'http', 'command'].includes(readinessType)) throw new Error('Readiness type must be none, tcp, http, or command.');
  const readinessPath = String(override.readinessPath ?? site.readiness_path ?? site.health_check_path ?? '/').trim() || '/';
  if (!readinessPath.startsWith('/') || readinessPath.length > 500 || /[\r\n]/.test(readinessPath)) throw new Error('Readiness path must begin with / and be at most 500 characters.');
  const statusMin = Math.trunc(boundedNumber(override.readinessStatusMin ?? site.readiness_status_min, 200, 100, 599, 'Readiness minimum status'));
  const statusMax = Math.trunc(boundedNumber(override.readinessStatusMax ?? site.readiness_status_max, 399, 100, 599, 'Readiness maximum status'));
  if (statusMin > statusMax) throw new Error('Readiness minimum status cannot exceed the maximum status.');
  const mode = String(override.containerMode || site.container_mode || preset.containerMode || 'image').toLowerCase();
  if (!['image', 'dockerfile', 'buildpack', 'nixpacks'].includes(mode)) throw new Error('Container mode must be image, dockerfile, buildpack, or nixpacks.');
  const containerPort = Math.trunc(boundedNumber(override.containerPort ?? override.composePort ?? site.container_port ?? preset.containerPort, 3000, 1, 65535, 'Container port'));
  const spec = {
    preset: presetName,
    driver: requestedDriver,
    command: cleanRuntimeCommand(override.command ?? ((site.runtime_type === 'node' && presetName === 'node') ? legacyNode : (site.start_command ?? preset.command ?? legacyNode))),
    workingDirectory: workingRaw === '.' ? '.' : safeRelative(workingRaw, 'Working directory'),
    portEnv: cleanEnvName(override.portEnv || site.runtime_port_env || preset.portEnv || 'PORT'),
    installCommand: cleanCommand(override.installCommand ?? site.install_command ?? '', 'Install command'),
    buildCommand: cleanCommand(override.buildCommand ?? site.build_command ?? '', 'Build command'),
    buildOutputDir: (() => { const value = String(override.buildOutputDir ?? site.build_output_dir ?? '').trim(); return value ? safeRelative(value, 'Build output directory') : ''; })(),
    readiness: {
      type: readinessType,
      path: readinessPath,
      command: cleanRuntimeCommand(override.readinessCommand ?? site.readiness_command ?? '', 'Readiness command'),
      statusMin,
      statusMax,
      timeoutMs: boundedNumber(override.startupTimeoutSeconds ?? site.startup_timeout_seconds, 30, 1, 600, 'Startup timeout') * 1000
    },
    shutdownGraceMs: boundedNumber(override.shutdownGraceSeconds ?? site.shutdown_grace_seconds, 10, 0, 300, 'Shutdown grace') * 1000,
    drainMs: boundedNumber(override.drainSeconds ?? site.blue_green_drain_seconds, 5, 0, 300, 'Blue/green drain') * 1000,
    container: {
      mode,
      image: cleanImage(override.image || site.container_image || 'node:22-alpine'),
      port: containerPort,
      dockerfilePath: safeRelative(override.dockerfilePath || site.dockerfile_path || preset.dockerfilePath || 'Dockerfile', 'Dockerfile path'),
      buildpackBuilder: (() => { const value = String(override.buildpackBuilder || site.buildpack_builder || '').trim(); return value ? cleanImage(value) : ''; })()
    },
    compose: {
      file: safeRelative(override.composeFile || site.compose_file || preset.composeFile || 'compose.yaml', 'Compose file'),
      service: String(override.composeService || site.compose_service || preset.composeService || '').trim(),
      port: containerPort
    },
    entryFile: safeRelative(site.entry_file || preset.entryFile || 'index.html', 'Entry file'),
    root,
    manifestRecord
  };
  if (spec.driver === 'process' && !spec.command) throw new Error('Process runtimes require a start command.');
  if (spec.driver === 'compose' && !/^[A-Za-z0-9][A-Za-z0-9_.-]{0,127}$/.test(spec.compose.service)) throw new Error('Docker Compose runtimes require a valid service name.');
  if (spec.readiness.type === 'command' && !spec.readiness.command) throw new Error('Command readiness requires a readiness command.');
  return spec;
}

function executionPolicy(spec) {
  return {
    preset: spec.preset,
    driver: spec.driver,
    command: spec.command,
    workingDirectory: spec.workingDirectory,
    portEnv: spec.portEnv,
    installCommand: spec.installCommand,
    buildCommand: spec.buildCommand,
    buildOutputDir: spec.buildOutputDir,
    readiness: spec.readiness,
    shutdownGraceMs: spec.shutdownGraceMs,
    drainMs: spec.drainMs,
    container: spec.container,
    compose: spec.compose
  };
}

function executionPolicyHash(spec) {
  return crypto.createHash('sha256').update(JSON.stringify(executionPolicy(spec))).digest('hex');
}

module.exports = { RUNTIME_PRESETS, parseSimpleYaml, readManifest, resolveRuntimeSpec, executionPolicy, executionPolicyHash, safeRelative };
