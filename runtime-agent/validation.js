'use strict';

const fs = require('node:fs');
const path = require('node:path');

const NAME_RE = /^sham-(?:site|anubis|compose)-[a-zA-Z0-9][a-zA-Z0-9_.-]{0,90}$/;
const PROJECT_RE = /^sham-\d+-[a-zA-Z0-9][a-zA-Z0-9_.-]{0,90}$/;
const TAG_RE = /^[a-zA-Z0-9][a-zA-Z0-9._/@:-]{0,255}$/;
const MANAGED_TAG_RE = /^sham\/site-\d+:[a-zA-Z0-9][a-zA-Z0-9._-]{0,80}$/;
const NETWORK_RE = /^[a-zA-Z0-9][a-zA-Z0-9_.-]{0,90}$/;
const ENV_KEY_RE = /^[A-Za-z_][A-Za-z0-9_]*$/;

class ValidationError extends Error {}

/**
 * @param {unknown} value
 * @param {string} label
 * @param {{ maxLength?: number }} [options]
 * @returns {string}
 */
function assertString(value, label, { maxLength = 4096 } = {}) {
  if (typeof value !== 'string' || !value || value.length > maxLength || /\0/.test(value)) {
    throw new ValidationError(`${label} is missing or invalid.`);
  }
  return value;
}

/**
 * @param {unknown} value
 * @param {string} [label]
 */
function assertContainerName(value, label = 'Container name') {
  const name = assertString(value, label);
  if (!NAME_RE.test(name)) throw new ValidationError(`${label} does not match the SHAM-managed naming convention.`);
  return name;
}

/**
 * @param {unknown} value
 * @param {string} [label]
 */
function assertComposeProject(value, label = 'Compose project') {
  const project = assertString(value, label);
  if (!PROJECT_RE.test(project)) throw new ValidationError(`${label} does not match the SHAM-managed naming convention.`);
  return project;
}

/**
 * @param {unknown} value
 * @param {string} [label]
 */
function assertImageTag(value, label = 'Image tag') {
  const tag = assertString(value, label, { maxLength: 512 });
  if (!TAG_RE.test(tag)) throw new ValidationError(`${label} is invalid.`);
  return tag;
}

/**
 * @param {unknown} value
 * @param {string} [label]
 */
function assertManagedImageTag(value, label = 'Image tag') {
  const tag = assertImageTag(value, label);
  if (!MANAGED_TAG_RE.test(tag)) throw new ValidationError(`${label} must be a SHAM-managed site image.`);
  return tag;
}

/**
 * @param {unknown} value
 * @param {string} [label]
 */
function assertNetworkName(value, label = 'Network name') {
  const name = assertString(value, label);
  if (!NETWORK_RE.test(name)) throw new ValidationError(`${label} is invalid.`);
  return name;
}

/**
 * @param {unknown} env
 * @param {string} [label]
 * @returns {Record<string, string>}
 */
function assertEnv(env, label = 'Environment') {
  if (env === undefined || env === null) return {};
  if (typeof env !== 'object' || Array.isArray(env)) throw new ValidationError(`${label} must be an object.`);
  const entries = Object.entries(env);
  if (entries.length > 200) throw new ValidationError(`${label} defines too many variables.`);
  /** @type {Record<string, string>} */
  const result = {};
  for (const [key, raw] of entries) {
    if (!ENV_KEY_RE.test(key)) throw new ValidationError(`${label} variable name "${key}" is invalid.`);
    const value = String(raw ?? '');
    if (/\0/.test(value) || value.length > 32 * 1024) throw new ValidationError(`${label} variable "${key}" is invalid.`);
    result[key] = value;
  }
  return result;
}

/**
 * @param {unknown} value
 * @param {string} [label]
 * @param {{ maxLength?: number }} [options]
 */
function assertCommandString(value, label = 'Command', { maxLength = 8192 } = {}) {
  return assertString(value, label, { maxLength });
}

// Every filesystem path the agent is asked to touch must resolve inside the
// shared data root (the same volume the control plane writes into). This is
// re-checked here even though the control plane already validated it, because
// the agent must not trust the control plane process is uncompromised.
/**
 * @param {string} root
 * @param {unknown} candidate
 * @param {string} [label]
 */
function assertPathInsideRoot(root, candidate, label = 'Path') {
  const candidatePath = assertString(candidate, label, { maxLength: 4096 });
  let resolvedRoot;
  let resolvedTarget;
  try {
    resolvedRoot = fs.realpathSync(root);
    resolvedTarget = fs.realpathSync(candidatePath);
  } catch (error) {
    const message = error instanceof Error ? error.message : String(error);
    throw new ValidationError(`${label} could not be resolved: ${message}`);
  }
  const base = `${resolvedRoot}${path.sep}`;
  if (resolvedTarget !== resolvedRoot && !resolvedTarget.startsWith(base)) {
    throw new ValidationError(`${label} must stay inside the SHAM data directory.`);
  }
  return resolvedTarget;
}

/**
 * @param {unknown} value
 * @param {string} [label]
 */
function assertPort(value, label = 'Port') {
  const port = Number(value);
  if (!Number.isInteger(port) || port < 1 || port > 65535) throw new ValidationError(`${label} is invalid.`);
  return port;
}

/**
 * @param {unknown} value
 * @param {string} label
 * @param {{ min?: number, max?: number, fallback?: number }} [options]
 * @returns {number}
 */
function assertPositiveInt(value, label, { min = 0, max = Number.MAX_SAFE_INTEGER, fallback = undefined } = {}) {
  if (value === undefined || value === null || value === '') {
    if (fallback !== undefined) return fallback;
    throw new ValidationError(`${label} is required.`);
  }
  const number = Number(value);
  if (!Number.isFinite(number) || number < min || number > max) throw new ValidationError(`${label} is invalid.`);
  return number;
}

module.exports = {
  ValidationError,
  NAME_RE, PROJECT_RE, TAG_RE, MANAGED_TAG_RE,
  assertString, assertContainerName, assertComposeProject, assertImageTag, assertManagedImageTag,
  assertNetworkName, assertEnv, assertCommandString, assertPathInsideRoot, assertPort, assertPositiveInt
};
