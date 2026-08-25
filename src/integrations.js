// @ts-nocheck -- not part of this session's checkJs rollout yet.
// This file still has genuine `tsc --noEmit` findings (mostly narrow
// `let x = null`-style inference and untyped Express handlers, the same
// patterns already fixed across most of src/) that need real per-file
// JSDoc work to resolve, not a suppression. Tracked as follow-up work;
// see tsconfig.json and docs/development.md. Do not add more files here
// without a similar comment and a plan to remove it.
const fs = require('node:fs');
const path = require('node:path');
const { spawn } = require('node:child_process');
const { CERTBOT_DIR, CERTBOT_BIN, INTEGRATION_TIMEOUT_MS } = require('./config');
const { operatorEnvironment } = require('./process-env');

const activeProcesses = new Set();

function terminateProcess(child, signal = 'SIGTERM') {
  if (!child || child.exitCode !== null || child.signalCode !== null) return;
  try {
    if (process.platform !== 'win32' && child.pid) process.kill(-child.pid, signal);
    else child.kill(signal);
  } catch {
    try { child.kill(signal); } catch { /* The process already stopped. */ }
  }
}

function terminateAndWait(child, graceMs = 2000) {
  if (!child || child.exitCode !== null || child.signalCode !== null) return Promise.resolve();
  return new Promise((resolve) => {
    let settled = false;
    const finish = () => {
      if (settled) return;
      settled = true;
      clearTimeout(forceTimer);
      clearTimeout(fallbackTimer);
      resolve();
    };
    child.once('exit', finish);
    const forceTimer = setTimeout(() => terminateProcess(child, 'SIGKILL'), graceMs);
    forceTimer.unref?.();
    const fallbackTimer = setTimeout(finish, graceMs + 3000);
    fallbackTimer.unref?.();
    terminateProcess(child, 'SIGTERM');
  });
}

function normalizeCloudflareToken(token, { allowEmpty = false } = {}) {
  const normalized = String(token || '').trim();
  if (!normalized && allowEmpty) return '';
  if (!normalized || normalized.length > 2048 || /[\r\n]/.test(normalized)) {
    throw new Error('Cloudflare API token is invalid.');
  }
  return normalized;
}

async function cloudflareRequest(token, pathname, options = {}) {
  const normalizedToken = normalizeCloudflareToken(token);
  let response;
  try {
    response = await fetch(`https://api.cloudflare.com/client/v4${pathname}`, {
      ...options,
      redirect: 'error',
      signal: options.signal || AbortSignal.timeout(INTEGRATION_TIMEOUT_MS),
      headers: {
        Authorization: `Bearer ${normalizedToken}`,
        'Content-Type': 'application/json',
        ...(options.headers || {})
      }
    });
  } catch (error) {
    if (error.name === 'TimeoutError' || error.name === 'AbortError') throw new Error('Cloudflare API request timed out.');
    throw new Error(`Cloudflare API request failed: ${error.message}`);
  }
  const payload = await response.json().catch(() => ({}));
  if (!response.ok || payload.success === false) {
    const message = payload.errors?.map((item) => item.message).filter(Boolean).join('; ')
      || `Cloudflare API returned HTTP ${response.status}.`;
    const error = new Error(message);
    error.status = response.status;
    error.cloudflareErrors = payload.errors || [];
    throw error;
  }
  return payload.result;
}

async function syncCloudflareRecord({ token, zoneId, domain, targetIp, proxied = true }) {
  if (!token || !zoneId || !targetIp) throw new Error('Cloudflare API token, zone ID, and target IP are required.');
  const records = await cloudflareRequest(
    token,
    `/zones/${encodeURIComponent(zoneId)}/dns_records?type=A&name=${encodeURIComponent(domain)}`
  );
  const body = JSON.stringify({ type: 'A', name: domain, content: targetIp, ttl: 1, proxied: Boolean(proxied) });
  if (!Array.isArray(records)) throw new Error('Cloudflare returned an invalid DNS record list.');
  if (records.length) {
    return cloudflareRequest(token, `/zones/${encodeURIComponent(zoneId)}/dns_records/${encodeURIComponent(records[0].id)}`, {
      method: 'PATCH',
      body
    });
  }
  return cloudflareRequest(token, `/zones/${encodeURIComponent(zoneId)}/dns_records`, { method: 'POST', body });
}

function cloudflareValue(value) {
  return `"${String(value).replaceAll('\\', '\\\\').replaceAll('"', '\\"')}"`;
}

function cloudflareIpSet(values) {
  return `{${values.map((value) => String(value)).join(' ')}}`;
}

function cloudflareCountrySet(values) {
  return `{${values.map(cloudflareValue).join(' ')}}`;
}

function buildCloudflareFirewallExpression(domain, firewall = {}) {
  const rules = [];
  if (firewall.blockedIps?.length) rules.push(`ip.src in ${cloudflareIpSet(firewall.blockedIps)}`);
  if (firewall.allowedIps?.length) rules.push(`not ip.src in ${cloudflareIpSet(firewall.allowedIps)}`);
  if (firewall.blockedCountries?.length) rules.push(`ip.src.country in ${cloudflareCountrySet(firewall.blockedCountries)}`);
  if (firewall.allowedCountries?.length) rules.push(`not ip.src.country in ${cloudflareCountrySet(firewall.allowedCountries)}`);
  if (!rules.length) return '';
  return `(http.host eq ${cloudflareValue(domain)}) and (${rules.map((rule) => `(${rule})`).join(' or ')})`;
}

async function getOrCreateCloudflareEntrypoint(token, zoneId, phase) {
  const base = `/zones/${encodeURIComponent(zoneId)}/rulesets/phases/${encodeURIComponent(phase)}/entrypoint`;
  try {
    return await cloudflareRequest(token, base);
  } catch (error) {
    if (error.status !== 404) throw error;
  }
  return cloudflareRequest(token, `/zones/${encodeURIComponent(zoneId)}/rulesets`, {
    method: 'POST',
    body: JSON.stringify({
      name: `SHAM ${phase}`,
      description: 'Rules managed by Simple Hosting And More',
      kind: 'zone',
      phase
    })
  });
}

async function syncCloudflareFirewall({ token, zoneId, siteId, domain, enabled, firewall }) {
  if (!token || !zoneId) throw new Error('Cloudflare API token and zone ID are required.');
  if (!domain) throw new Error('Configure a domain before syncing a Cloudflare firewall rule.');
  const ruleset = await getOrCreateCloudflareEntrypoint(token, zoneId, 'http_request_firewall_custom');
  const description = `SHAM site ${siteId} firewall`;
  const existing = Array.isArray(ruleset.rules) ? ruleset.rules.find((rule) => rule.description === description) : null;
  const expression = enabled ? buildCloudflareFirewallExpression(domain, firewall) : '';

  if (!enabled || !expression) {
    if (existing) {
      await cloudflareRequest(token, `/zones/${encodeURIComponent(zoneId)}/rulesets/${encodeURIComponent(ruleset.id)}/rules/${encodeURIComponent(existing.id)}`, { method: 'DELETE' });
      return { deleted: true, id: existing.id };
    }
    return { deleted: false, inactive: true };
  }

  const payload = JSON.stringify({
    action: firewall.cloudflareAction === 'block' ? 'block' : 'managed_challenge',
    expression,
    description,
    enabled: true
  });
  const path = existing
    ? `/zones/${encodeURIComponent(zoneId)}/rulesets/${encodeURIComponent(ruleset.id)}/rules/${encodeURIComponent(existing.id)}`
    : `/zones/${encodeURIComponent(zoneId)}/rulesets/${encodeURIComponent(ruleset.id)}/rules`;
  return cloudflareRequest(token, path, { method: existing ? 'PATCH' : 'POST', body: payload });
}

function runProcess(command, args, { timeoutMs = 15 * 60 * 1000, onLine = () => {} } = {}) {
  return new Promise((resolve, reject) => {
    const child = spawn(command, args, {
      env: operatorEnvironment(),
      stdio: ['ignore', 'pipe', 'pipe'],
      detached: process.platform !== 'win32'
    });
    activeProcesses.add(child);
    let output = '';
    let settled = false;
    let timedOut = false;
    let timer;
    let forceTimer;
    let fallbackTimer;
    const append = (text) => {
      output = `${output}${text}`;
      if (output.length > 64 * 1024) output = output.slice(-64 * 1024);
    };
    const finish = (callback, value) => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      clearTimeout(forceTimer);
      clearTimeout(fallbackTimer);
      activeProcesses.delete(child);
      callback(value);
    };
    const consume = (level, chunk) => {
      const text = chunk.toString();
      append(text);
      for (const line of text.split(/\r?\n/).filter(Boolean)) onLine(level, line.slice(0, 2000));
    };
    child.stdout.on('data', (chunk) => consume('info', chunk));
    child.stderr.on('data', (chunk) => consume('error', chunk));
    child.once('error', (error) => finish(reject, new Error(`${command} could not be started: ${error.message}`)));
    child.once('close', (code) => {
      if (timedOut) finish(reject, new Error(`${command} timed out.`));
      else if (code === 0) finish(resolve, output.trim());
      else finish(reject, new Error(`${command} exited with code ${code}. ${output.trim().slice(-1200)}`));
    });
    timer = setTimeout(() => {
      timedOut = true;
      terminateProcess(child, 'SIGTERM');
      forceTimer = setTimeout(() => {
        terminateProcess(child, 'SIGKILL');
        fallbackTimer = setTimeout(() => finish(reject, new Error(`${command} timed out and did not exit after termination.`)), 3000);
        fallbackTimer.unref?.();
      }, 2000);
      forceTimer.unref?.();
    }, timeoutMs);
    timer.unref?.();
  });
}

async function stopIntegrationProcesses() {
  const children = [...activeProcesses];
  await Promise.allSettled(children.map((child) => terminateAndWait(child, 2000)));
}

function certbotPaths(domain) {
  const live = path.join(CERTBOT_DIR, 'config', 'live', domain);
  return { key: path.join(live, 'privkey.pem'), cert: path.join(live, 'fullchain.pem') };
}

function hasCertificate(domain) {
  if (!domain) return false;
  const files = certbotPaths(domain);
  return fs.existsSync(files.key) && fs.existsSync(files.cert);
}


function cloudflareCredentialsPath() {
  return path.join(CERTBOT_DIR, 'credentials', 'cloudflare.ini');
}

function writeCloudflareCredentials(token) {
  const credentials = cloudflareCredentialsPath();
  const normalizedToken = normalizeCloudflareToken(token, { allowEmpty: true });
  if (!normalizedToken) {
    fs.rmSync(credentials, { force: true });
    return '';
  }
  if (normalizedToken.length > 2048 || /[\r\n]/.test(normalizedToken)) {
    throw new Error('Cloudflare API token is invalid.');
  }
  fs.mkdirSync(path.dirname(credentials), { recursive: true });
  const temporary = `${credentials}.tmp-${process.pid}`;
  try {
    fs.writeFileSync(temporary, `dns_cloudflare_api_token = ${normalizedToken}\n`, { mode: 0o600 });
    fs.renameSync(temporary, credentials);
    fs.chmodSync(credentials, 0o600);
  } finally {
    fs.rmSync(temporary, { force: true });
  }
  return credentials;
}

async function issueCertificate({ domain, email, cloudflareToken = '', wildcard = false, onLine }) {
  if (!domain) throw new Error('Configure a domain before requesting a certificate.');
  if (!email) throw new Error('Configure a Certbot contact email first.');

  const common = [
    'certonly', '--non-interactive', '--agree-tos', '--email', email,
    '--config-dir', path.join(CERTBOT_DIR, 'config'),
    '--work-dir', path.join(CERTBOT_DIR, 'work'),
    '--logs-dir', path.join(CERTBOT_DIR, 'logs'),
    '--keep-until-expiring', '-d', domain
  ];

  if (wildcard) {
    if (!cloudflareToken) throw new Error('Wildcard certificates require the Cloudflare DNS challenge.');
    common.push('-d', `*.${domain}`);
  }

  if (cloudflareToken) {
    const credentials = writeCloudflareCredentials(cloudflareToken);
    common.push('--dns-cloudflare', '--dns-cloudflare-credentials', credentials, '--dns-cloudflare-propagation-seconds', '30');
  } else {
    common.push('--standalone');
  }

  await runProcess(CERTBOT_BIN, common, { onLine });
  if (!hasCertificate(domain)) throw new Error('Certbot completed but the certificate files were not found.');
  return certbotPaths(domain);
}


function renewalNeedsPort80() {
  const renewalDirectory = path.join(CERTBOT_DIR, 'config', 'renewal');
  let files;
  try {
    files = fs.readdirSync(renewalDirectory).filter((name) => name.endsWith('.conf'));
  } catch (error) {
    if (error.code === 'ENOENT') return false;
    return true;
  }
  return files.some((name) => {
    try {
      const configuration = fs.readFileSync(path.join(renewalDirectory, name), 'utf8');
      return /^authenticator\s*=\s*standalone\s*$/im.test(configuration)
        || /^installer\s*=\s*standalone\s*$/im.test(configuration);
    } catch {
      return true;
    }
  });
}

async function renewCertificates({ onLine }) {
  return runProcess(CERTBOT_BIN, [
    'renew', '--non-interactive',
    '--config-dir', path.join(CERTBOT_DIR, 'config'),
    '--work-dir', path.join(CERTBOT_DIR, 'work'),
    '--logs-dir', path.join(CERTBOT_DIR, 'logs')
  ], { onLine });
}

module.exports = {
  syncCloudflareRecord,
  syncCloudflareFirewall,
  buildCloudflareFirewallExpression,
  runProcess,
  certbotPaths,
  hasCertificate,
  writeCloudflareCredentials,
  issueCertificate,
  renewalNeedsPort80,
  renewCertificates,
  stopIntegrationProcesses
};
