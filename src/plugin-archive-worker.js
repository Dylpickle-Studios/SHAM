const fs = require('node:fs');
const path = require('node:path');
const { parentPort, workerData } = require('node:worker_threads');
if (!parentPort) throw new Error('This module must run inside a worker thread.');
const { extractPlugin } = require('./plugin-archive');
const { verifyPluginSignature, normalizeTrustedKeys } = require('./plugin-signing');

const MAX_MANIFEST_BYTES = 512 * 1024;

try {
  extractPlugin(workerData.source, workerData.destination);
  const manifestPath = path.join(workerData.destination, 'plugin.json');
  const stat = fs.statSync(manifestPath);
  if (!stat.isFile()) throw new Error('Plugin archive must contain plugin.json at its root.');
  if (stat.size > MAX_MANIFEST_BYTES) throw new Error('plugin.json may not exceed 512 KB.');
  const rawManifest = JSON.parse(fs.readFileSync(manifestPath, 'utf8'));
  const signature = verifyPluginSignature(
    workerData.destination,
    rawManifest,
    normalizeTrustedKeys(workerData.trustedKeys || [])
  );
  parentPort.postMessage({ ok: true, rawManifest, signature });
} catch (error) {
  parentPort.postMessage({ ok: false, error: error.message });
}
