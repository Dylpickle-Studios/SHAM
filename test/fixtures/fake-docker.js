#!/usr/bin/env node
'use strict';

// Minimal stand-in for the `docker` CLI used by runtime-agent tests. State
// (which container/network names exist, and their labels) is persisted as
// JSON under FAKE_DOCKER_STATE so the agent's `docker run` / `docker
// inspect` / `docker stop` / etc. calls behave consistently across the
// separate child-process invocations the agent makes for each operation.
const fs = require('fs');
const os = require('os');
const path = require('path');

// operatorEnvironment() (src/process-env.js) only forwards an allowlist of
// env vars to spawned tools, which does not include a custom state-file
// pointer. TMPDIR/TMP/TEMP are on that allowlist, so state is derived from
// os.tmpdir() instead, which each test points at a unique directory.
const statePath = path.join(os.tmpdir(), 'sham-fake-docker-state.json');
const args = process.argv.slice(2);

function loadState() {
  try { return JSON.parse(fs.readFileSync(statePath, 'utf8')); }
  catch { return { containers: {}, networks: {} }; }
}
function saveState(state) { fs.writeFileSync(statePath, JSON.stringify(state)); }

function findContainer(state, ref) {
  if (state.containers[ref]) return state.containers[ref];
  return Object.values(state.containers).find((c) => c.Id === ref) || null;
}

const [command] = args;
const state = loadState();

if (command === 'version') {
  process.stdout.write('99.0.0\n');
  process.exit(0);
}

if (command === 'run') {
  const nameIndex = args.indexOf('--name');
  const name = args[nameIndex + 1];
  const labels = {};
  for (let i = 0; i < args.length; i += 1) {
    if (args[i] === '--label') {
      const [k, v] = args[i + 1].split('=');
      labels[k] = v;
    }
  }
  const id = `cid-${name}`;
  state.containers[name] = { Id: id, Config: { Labels: labels } };
  saveState(state);
  process.stdout.write(`${id}\n`);
  process.exit(0);
}

if (command === 'inspect') {
  const ref = args[1];
  const container = findContainer(state, ref);
  if (!container) { process.stderr.write('Error: No such object\n'); process.exit(1); }
  process.stdout.write(`${JSON.stringify([container])}\n`);
  process.exit(0);
}

if (command === 'stop') {
  process.exit(0);
}

if (command === 'rm') {
  const name = args[args.length - 1];
  delete state.containers[name];
  saveState(state);
  process.exit(0);
}

if (command === 'logs') {
  process.stdout.write('log line one\n');
  process.stdout.write('log line two\n');
  process.exit(0);
}

if (command === 'wait') {
  process.stdout.write('0\n');
  process.exit(0);
}

if (command === 'port') {
  process.stdout.write('0.0.0.0:34567\n');
  process.exit(0);
}

if (command === 'network') {
  const sub = args[1];
  if (sub === 'inspect') {
    const name = args[2];
    if (state.networks[name]) { process.stdout.write('[{}]\n'); process.exit(0); }
    process.exit(1);
  }
  if (sub === 'create') {
    const name = args[args.length - 1];
    state.networks[name] = true;
    saveState(state);
    process.stdout.write(`${name}\n`);
    process.exit(0);
  }
  if (sub === 'connect') {
    process.exit(0);
  }
  process.exit(0);
}

if (command === 'build') {
  process.stdout.write('Step 1/1 : FROM scratch\n');
  process.exit(0);
}

if (command === 'stats') {
  process.stdout.write(`${JSON.stringify({ CPUPerc: '1.00%', MemUsage: '10MiB / 100MiB' })}\n`);
  process.exit(0);
}

if (command === 'image') {
  const sub = args[1];
  if (sub === 'rm') process.exit(0);
  if (sub === 'ls') { process.stdout.write(''); process.exit(0); }
  process.exit(0);
}

if (command === 'ps') {
  process.stdout.write('');
  process.exit(0);
}

if (command === 'compose') {
  process.stderr.write('fake docker: compose not supported in this fixture\n');
  process.exit(1);
}

process.stderr.write(`fake docker: unhandled command ${command}\n`);
process.exit(1);
