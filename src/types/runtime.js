'use strict';

// JSDoc-only module — see src/types/site.js.

/**
 * How a runtime backend should be checked for readiness before it receives
 * traffic (see src/runtime-engine.js's waitForReadiness / src/runtime-spec.js).
 * @typedef {Object} ReadinessProbe
 * @property {'http' | 'tcp' | 'command' | 'none'} type
 * @property {number} [timeoutMs]
 * @property {string} [path]
 * @property {number} [statusMin]
 * @property {number} [statusMax]
 * @property {string} [command]
 */

/**
 * The resolved execution plan for a site's runtime, produced by
 * `resolveRuntimeSpec()` (src/runtime-spec.js) from the Site plus any
 * sham.yaml manifest. Not every driver populates every field.
 * @typedef {Object} RuntimeSpec
 * @property {'static' | 'process' | 'container' | 'compose' | 'proxy'} driver
 * @property {string} [preset]
 * @property {string | string[]} [command]
 * @property {string} [entryFile]
 * @property {string} workingDirectory
 * @property {string} [portEnv]
 * @property {ReadinessProbe} readiness
 * @property {number} shutdownGraceMs
 * @property {number} [drainMs]
 * @property {{ mode: string, image: string, port: number, dockerfilePath?: string, buildpackBuilder?: string }} [container]
 * @property {{ file: string, service: string, port: number }} [compose]
 * @property {import('./site').Site} [site]
 */

/**
 * A single {ok, message} result from a TCP/HTTP/command readiness or health
 * probe (src/runtime-engine.js's tcpProbe/httpProbe/commandExit).
 * @typedef {Object} ProbeResult
 * @property {boolean} ok
 * @property {string} [message]
 * @property {number} [status]
 */

/**
 * The live backend process/container powering a running site — one of
 * several driver-specific shapes produced by src/sites/runtime.js.
 * @typedef {Object} RuntimeBackend
 * @property {'static' | 'process' | 'container' | 'compose' | 'proxy'} driver
 * @property {boolean} active
 * @property {boolean} stopping
 * @property {string} [internalHost]
 * @property {number} [internalPort]
 * @property {string} [target]
 * @property {string} [containerName]
 * @property {string} [containerId]
 * @property {string} [composeProject]
 * @property {import('node:child_process').ChildProcess} [child]
 */

module.exports = {};
