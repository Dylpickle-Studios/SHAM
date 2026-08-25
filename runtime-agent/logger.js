'use strict';

// Structured, secret-free logging for privileged operations. Never pass env
// objects, tokens, or full request bodies to this — callers pass a small
// allowlist of identifying fields (site id, container/project name, outcome).
function log(event, fields = {}) {
  const safeFields = {};
  for (const [key, value] of Object.entries(fields)) {
    if (value === undefined || value === null) continue;
    safeFields[key] = typeof value === 'string' ? value.slice(0, 300) : value;
  }
  process.stdout.write(`${JSON.stringify({ ts: new Date().toISOString(), event, ...safeFields })}\n`);
}

module.exports = { log };
