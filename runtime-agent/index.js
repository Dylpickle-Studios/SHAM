'use strict';

const fs = require('node:fs');
const path = require('node:path');
const { RUNTIME_AGENT_SOCKET_PATH, RUNTIME_AGENT_TOKEN_PATH } = require('../src/config');
const { loadOrCreateToken } = require('./auth');
const { createServer } = require('./server');
const { log } = require('./logger');

function removeStaleSocket(socketPath) {
  try { fs.unlinkSync(socketPath); } catch (error) { if (error.code !== 'ENOENT') throw error; }
}

function main() {
  const socketPath = RUNTIME_AGENT_SOCKET_PATH;
  const token = loadOrCreateToken(RUNTIME_AGENT_TOKEN_PATH);

  fs.mkdirSync(path.dirname(socketPath), { recursive: true, mode: 0o700 });
  removeStaleSocket(socketPath);

  const server = createServer({ token });
  server.listen(socketPath, () => {
    try { fs.chmodSync(socketPath, 0o660); } catch { /* best effort on non-POSIX storage */ }
    log('agent.started', { socketPath });
  });
  server.on('error', (error) => { log('agent.listen_error', { error: error.message }); process.exitCode = 1; });

  const shutdown = () => {
    log('agent.stopping', {});
    server.close(() => { removeStaleSocket(socketPath); process.exit(0); });
    setTimeout(() => process.exit(0), 5000).unref();
  };
  process.once('SIGTERM', shutdown);
  process.once('SIGINT', shutdown);
}

if (require.main === module) main();

module.exports = { main };
