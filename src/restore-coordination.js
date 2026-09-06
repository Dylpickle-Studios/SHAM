'use strict';

const fs = require('node:fs');
const path = require('node:path');
const { DATA_DIR } = require('./config');
const { getRuntimeClient } = require('./runtime/client');
const { OPERATIONS } = require('./runtime/protocol');

const RESTORE_PAUSE = path.join(DATA_DIR, '.restore-work', 'agent-paused');

async function pauseRuntimeAgent() {
  await fs.promises.mkdir(path.dirname(RESTORE_PAUSE), { recursive: true, mode: 0o700 });
  await fs.promises.writeFile(RESTORE_PAUSE, 'Backup restore in progress.\n', { mode: 0o600 });
  const client = getRuntimeClient();
  // A stopped/unconfigured agent cannot write to the volume. An agent starting
  // concurrently also checks the pause marker before accepting any operation.
  if (!client.socketPath || !fs.existsSync(client.socketPath)) return;
  try { await client.request(OPERATIONS.RESTORE_QUIESCE); }
  catch (error) {
    if (error.message.includes('runtime agent disconnected')) return;
    if (!fs.existsSync(path.join(DATA_DIR, '.restore-work', 'journal.json'))) await resumeRuntimeAgent();
    throw new Error(`Could not pause Runtime Agent for restore: ${error.message}`);
  }
}

async function resumeRuntimeAgent() {
  await fs.promises.rm(RESTORE_PAUSE, { force: true });
}

module.exports = { RESTORE_PAUSE, pauseRuntimeAgent, resumeRuntimeAgent };
