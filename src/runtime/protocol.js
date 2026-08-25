'use strict';

// Shared between the control plane (src/runtime/client.js) and the privileged
// Runtime Agent (runtime-agent/server.js). Bumping this forces both sides to
// agree on the request/response contract instead of silently drifting.
const PROTOCOL_VERSION = 1;
const PROTOCOL_HEADER = 'x-sham-runtime-protocol';
const AUTH_HEADER = 'authorization';
const MAX_REQUEST_BODY_BYTES = 256 * 1024;
const MAX_STREAM_LINE_BYTES = 16 * 1024;

// Every allowlisted operation the agent exposes. The client and server both
// import this list so neither side can silently grow an extra route.
const OPERATIONS = Object.freeze({
  STATUS: { method: 'GET', path: '/v1/status' },
  IMAGES_BUILD: { method: 'POST', path: '/v1/images/build', stream: true },
  IMAGES_REMOVE: { method: 'POST', path: '/v1/images/remove' },
  CONTAINERS_RUN: { method: 'POST', path: '/v1/containers/run' },
  CONTAINERS_STOP: { method: 'POST', path: '/v1/containers/stop' },
  CONTAINERS_REMOVE: { method: 'POST', path: '/v1/containers/remove' },
  CONTAINERS_PORT: { method: 'POST', path: '/v1/containers/port' },
  CONTAINERS_LOGS: { method: 'POST', path: '/v1/containers/logs', stream: true },
  CONTAINERS_WAIT: { method: 'POST', path: '/v1/containers/wait', stream: true },
  CONTAINERS_EXEC: { method: 'POST', path: '/v1/containers/exec', stream: true },
  CONTAINERS_STATS: { method: 'POST', path: '/v1/containers/stats' },
  CONTAINERS_SANDBOX_RUN: { method: 'POST', path: '/v1/containers/sandbox-run', stream: true },
  CONTAINERS_SIDECAR_RUN: { method: 'POST', path: '/v1/containers/sidecar-run' },
  CONTAINERS_SIDECAR_REMOVE: { method: 'POST', path: '/v1/containers/sidecar-remove' },
  NETWORKS_ENSURE: { method: 'POST', path: '/v1/networks/ensure' },
  NETWORKS_CONNECT: { method: 'POST', path: '/v1/networks/connect' },
  COMPOSE_CONFIG: { method: 'POST', path: '/v1/compose/config' },
  COMPOSE_UP: { method: 'POST', path: '/v1/compose/up', stream: true },
  COMPOSE_PS: { method: 'POST', path: '/v1/compose/ps' },
  COMPOSE_PORT: { method: 'POST', path: '/v1/compose/port' },
  COMPOSE_DOWN: { method: 'POST', path: '/v1/compose/down' },
  COMPOSE_EXEC: { method: 'POST', path: '/v1/compose/exec', stream: true },
  CLEANUP_COMPOSE_PROJECT: { method: 'POST', path: '/v1/cleanup/compose-project' },
  CLEANUP_ORPHANED_COMPOSE_PROJECT: { method: 'POST', path: '/v1/cleanup/orphaned-compose-project' },
  CLEANUP_MANAGED_CONTAINERS: { method: 'POST', path: '/v1/cleanup/managed-containers' },
  CLEANUP_MANAGED_IMAGES: { method: 'POST', path: '/v1/cleanup/managed-images' }
});

const ERROR_CODES = Object.freeze({
  UNAUTHENTICATED: 'UNAUTHENTICATED',
  PROTOCOL_VERSION_MISMATCH: 'PROTOCOL_VERSION_MISMATCH',
  INVALID_REQUEST: 'INVALID_REQUEST',
  NOT_FOUND: 'NOT_FOUND',
  RESOURCE_NOT_OWNED: 'RESOURCE_NOT_OWNED',
  DOCKER_UNAVAILABLE: 'DOCKER_UNAVAILABLE',
  OPERATION_FAILED: 'OPERATION_FAILED',
  INTERNAL: 'INTERNAL'
});

module.exports = { PROTOCOL_VERSION, PROTOCOL_HEADER, AUTH_HEADER, MAX_REQUEST_BODY_BYTES, MAX_STREAM_LINE_BYTES, OPERATIONS, ERROR_CODES };
