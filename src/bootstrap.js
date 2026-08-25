// @ts-nocheck -- not part of this session's checkJs rollout yet.
// This file still has genuine `tsc --noEmit` findings (mostly narrow
// `let x = null`-style inference and untyped Express handlers, the same
// patterns already fixed across most of src/) that need real per-file
// JSDoc work to resolve, not a suppression. Tracked as follow-up work;
// see tsconfig.json and docs/development.md. Do not add more files here
// without a similar comment and a plan to remove it.
'use strict';

require('./env');

const fs = require('node:fs');
const path = require('node:path');
const Module = require('node:module');

const IMAGE_ROOT = path.resolve(__dirname, '..');

function exposeImageDependencies() {
  const modules = path.join(IMAGE_ROOT, 'node_modules');
  if (!fs.existsSync(modules)) return;
  const current = String(process.env.NODE_PATH || '').split(path.delimiter).filter(Boolean);
  if (!current.includes(modules)) process.env.NODE_PATH = [modules, ...current].join(path.delimiter);
  Module.Module._initPaths();
}

function loadUpdateRuntime() {
  const imageRuntime = require('./update-manager');
  const activeRoot = imageRuntime.resolveActiveAppRoot();
  if (path.resolve(activeRoot) === IMAGE_ROOT) return imageRuntime;
  try {
    return require(path.join(activeRoot, 'src', 'update-manager.js'));
  } catch (error) {
    console.error(`Could not load the active update runtime; falling back to the image bootstrap: ${error.message}`);
    return imageRuntime;
  }
}

(async () => {
  exposeImageDependencies();
  const restored = await require('./backup-restore').applyPendingRestore();
  if (restored) console.log(`Restored SHAM data from ${restored.archivePath}.`);
  let applied = null;
  let updateRuntime = loadUpdateRuntime();
  try {
    applied = await updateRuntime.applyPendingUpdate();
    if (applied) {
      console.log(`Activating staged SHAM update ${applied.version} from persistent storage.`);
      // The newly installed release may include a newer compatible update manager.
      updateRuntime = loadUpdateRuntime();
    }
    const activeRoot = updateRuntime.resolveActiveAppRoot();
    const server = require(path.join(activeRoot, 'src', 'server.js'));
    if (server?.ready && typeof server.ready.then === 'function') await server.ready;
    if (applied) {
      await updateRuntime.markAppliedUpdateHealthy(applied);
      console.log(`SHAM update ${applied.version} passed startup validation.`);
    }
  } catch (error) {
    if (applied) {
      try {
        await updateRuntime.rollbackAppliedUpdate(applied, error);
        console.error(`SHAM update ${applied.version} failed startup validation and was rolled back: ${error.message}`);
      } catch (rollbackError) {
        console.error(`SHAM update ${applied.version} failed and rollback also failed: ${rollbackError.message}`);
      }
    } else {
      console.error(error.stack || error.message);
    }
    process.exitCode = 1;
  }
})();
