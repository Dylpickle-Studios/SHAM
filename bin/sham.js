#!/usr/bin/env node
'use strict';


function usage(exitCode = 0) {
  process.stdout.write(`SHAM CLI\n\nUsage:\n  sham sites\n  sham deploy <site-id> [--branch main] [--approve-manifest]\n  sham logs <site-id> [--limit 200]\n  sham restart <site-id>\n  sham stop <site-id>\n  sham start <site-id>\n  sham rollback <site-id> <release-id>\n\nEnvironment:\n  SHAM_URL    Dashboard base URL, e.g. https://sham.example.com\n  SHAM_TOKEN  API token created in Security\n\n`);
  process.exitCode = exitCode;
}

function options(argv) {
  const out = { _: [] };
  for (let i = 0; i < argv.length; i += 1) {
    const item = argv[i];
    if (!item.startsWith('--')) { out._.push(item); continue; }
    const key = item.slice(2);
    if (['approve-manifest'].includes(key)) out[key] = true;
    else out[key] = argv[++i];
  }
  return out;
}

async function api(path, { method = 'GET', body = undefined, timeoutMs = 30_000 } = {}) {
  const base = String(process.env.SHAM_URL || '').replace(/\/+$/, '');
  const token = String(process.env.SHAM_TOKEN || '');
  if (!/^https?:\/\//.test(base)) throw new Error('Set SHAM_URL to the dashboard HTTP(S) URL.');
  if (!/^sham_pat_/.test(token)) throw new Error('Set SHAM_TOKEN to a SHAM API token.');
  const response = await fetch(`${base}${path}`, {
    method,
    headers: { Authorization: `Bearer ${token}`, Accept: 'application/json', ...(body === undefined ? {} : { 'Content-Type': 'application/json' }) },
    body: body === undefined ? undefined : JSON.stringify(body),
    redirect: 'error',
    signal: AbortSignal.timeout(timeoutMs)
  });
  const text = await response.text();
  let payload = null;
  try { payload = text ? JSON.parse(text) : {}; } catch { payload = { raw: text }; }
  if (!response.ok) {
    const error = new Error(payload?.error || `SHAM returned HTTP ${response.status}.`);
    error.payload = payload; error.status = response.status; throw error;
  }
  return payload;
}

async function main() {
  const [command, ...rest] = process.argv.slice(2);
  if (!command || ['help', '-h', '--help'].includes(command)) return usage();
  const args = options(rest);
  if (command === 'sites') {
    const result = await api('/api/sites');
    for (const site of result.sites || []) process.stdout.write(`${site.id}\t${site.runtime?.running ? 'running' : 'stopped'}\t${site.name}\t${site.url || ''}\n`);
    return;
  }
  const siteId = Number(args._[0]);
  if (!Number.isSafeInteger(siteId) || siteId < 1) throw new Error('A numeric site ID is required.');
  if (command === 'logs') {
    const limit = Math.min(Math.max(Number(args.limit) || 200, 1), 2000);
    const result = await api(`/api/runtime-logs?siteId=${siteId}&limit=${limit}`);
    for (const row of (result.logs || []).reverse()) process.stdout.write(`${row.createdAt || ''}\t${row.level || 'info'}\t${row.message || ''}\n`);
    return;
  }
  if (['start', 'stop', 'restart'].includes(command)) {
    const result = await api(`/api/sites/${siteId}/${command}`, { method: 'POST' });
    process.stdout.write(`${result.site?.name || `Site ${siteId}`} ${command} complete.\n`);
    return;
  }
  if (command === 'deploy') {
    const body = {};
    if (args.branch) body.branch = args.branch;
    if (args['approve-manifest']) body.approveManifestChanges = true;
    const result = await api(`/api/sites/${siteId}/deploy/git`, { method: 'POST', body, timeoutMs: 30 * 60_000 });
    process.stdout.write(`Deployment ${result.release?.deploymentId || result.release?.id || ''} active${result.warning ? ` with warning: ${result.warning}` : ''}.\n`);
    return;
  }
  if (command === 'rollback') {
    const releaseId = Number(args._[1]);
    if (!Number.isSafeInteger(releaseId) || releaseId < 1) throw new Error('A numeric release ID is required.');
    const result = await api(`/api/sites/${siteId}/releases/${releaseId}/rollback`, { method: 'POST', body: {}, timeoutMs: 10 * 60_000 });
    process.stdout.write(`Rollback complete${result.warning ? ` with warning: ${result.warning}` : ''}.\n`);
    return;
  }
  usage(1);
}

main().catch((error) => {
  process.stderr.write(`sham: ${error.message}\n`);
  if (error.payload?.code === 'SHAM_MANIFEST_APPROVAL_REQUIRED') process.stderr.write('Re-run with --approve-manifest after reviewing the manifest execution policy.\n');
  process.exitCode = 1;
});
