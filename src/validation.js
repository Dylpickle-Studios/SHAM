const path = require('node:path');
const net = require('node:net');

const BLOCKED_HEADERS = new Set([
  'connection', 'content-length', 'host', 'keep-alive', 'proxy-authenticate',
  'proxy-authorization', 'set-cookie', 'te', 'trailer', 'transfer-encoding', 'upgrade'
]);

function strictInteger(value, label) {
  const raw = String(value ?? '').trim();
  if (!/^-?\d+$/.test(raw)) throw new Error(`${label} must be an integer.`);
  const number = Number(raw);
  if (!Number.isSafeInteger(number)) throw new Error(`${label} must be a safe integer.`);
  return number;
}

function boundedInteger(value, label, fallback, min, max) {
  if (value === undefined || value === null || value === '') return fallback;
  const number = strictInteger(value, label);
  if (number < min || number > max) throw new Error(`${label} must be between ${min} and ${max}.`);
  return number;
}

function bool(value, fallback = false) {
  if (value === undefined || value === null || value === '') return fallback;
  if (value === true || value === 1) return true;
  const normalized = String(value).trim().toLowerCase();
  return normalized === '1' || normalized === 'true' || normalized === 'on' || normalized === 'yes';
}

function safeRelativePath(value, label = 'Path') {
  const raw = String(value || '').replaceAll('\\', '/').trim();
  if (!raw || raw.includes('\0') || raw.startsWith('/') || /^[A-Za-z]:\//.test(raw)) {
    throw new Error(`${label} must be a relative path.`);
  }
  const normalized = path.posix.normalize(raw).replace(/^\.\//, '');
  if (!normalized || normalized === '.' || normalized === '..' || normalized.startsWith('../')) {
    throw new Error(`${label} is not safe.`);
  }
  return normalized;
}

function slugify(value) {
  const slug = String(value || '')
    .normalize('NFKD')
    .toLowerCase()
    .replace(/[^a-z0-9]+/g, '-')
    .replace(/^-+|-+$/g, '')
    .slice(0, 60);
  return slug || 'site';
}

function validateHeaders(input) {
  let parsed = input;
  if (typeof input === 'string') {
    const trimmed = input.trim();
    parsed = trimmed ? JSON.parse(trimmed) : {};
  }
  if (!parsed || Array.isArray(parsed) || typeof parsed !== 'object') {
    throw new Error('Headers must be a JSON object.');
  }
  const entries = Object.entries(parsed);
  if (entries.length > 50) throw new Error('A site can define at most 50 custom headers.');

  const result = {};
  for (const [name, rawValue] of entries) {
    const lower = name.toLowerCase();
    if (!/^[!#$%&'*+.^_`|~0-9A-Za-z-]+$/.test(name) || BLOCKED_HEADERS.has(lower)) {
      throw new Error(`Header “${name}” is not allowed.`);
    }
    const value = String(rawValue);
    if (value.length > 2048 || /[\r\n]/.test(value)) throw new Error(`Header “${name}” has an invalid value.`);
    result[name] = value;
  }
  return result;
}

function validateBindHost(value) {
  const host = String(value || '127.0.0.1').trim();
  if (host === 'localhost' || net.isIP(host)) return host;
  throw new Error('Bind address must be localhost or a valid IPv4/IPv6 address.');
}

function isPrivateListenerHost(host) {
  if (host === 'localhost' || host === '::1' || host.startsWith('127.')) return true;
  if (net.isIP(host) === 4) {
    const parts = host.split('.').map(Number);
    return parts[0] === 10
      || (parts[0] === 172 && parts[1] >= 16 && parts[1] <= 31)
      || (parts[0] === 192 && parts[1] === 168)
      || (parts[0] === 100 && parts[1] >= 64 && parts[1] <= 127);
  }
  return net.isIP(host) === 6 && /^(?:fc|fd)/i.test(host);
}

function validatePrivateListeners(value, { runtimeType, runtimeIsolation, primaryPort, runtimePortEnv }) {
  let entries = value;
  if (typeof entries === 'string') {
    try { entries = entries.trim() ? JSON.parse(entries) : []; }
    catch { throw new Error('Private listeners must be a JSON array.'); }
  }
  if (entries === undefined || entries === null || entries === '') entries = [];
  if (!Array.isArray(entries) || entries.length > 4) throw new Error('A site can define at most four private listeners.');
  if (entries.length && (runtimeType !== 'node' && runtimeType !== 'process')) throw new Error('Private listeners are supported only for Node.js and managed process runtimes.');
  if (entries.length && runtimeIsolation !== 'process') throw new Error('Private listeners require process isolation; Docker and Compose port mappings remain intentionally restricted.');
  const names = new Set();
  const ports = new Set();
  const environments = new Set();
  return entries.map((entry, index) => {
    if (!entry || Array.isArray(entry) || typeof entry !== 'object') throw new Error(`Private listener ${index + 1} must be an object.`);
    for (const key of Object.keys(entry)) {
      if (!['name', 'port', 'bindHost', 'bind_host', 'portEnv', 'port_env'].includes(key)) throw new Error(`Private listener ${index + 1} has an unsupported field: ${key}.`);
    }
    const name = String(entry.name || '').trim().toLowerCase();
    if (!/^[a-z][a-z0-9_-]{0,31}$/.test(name) || name === 'public' || names.has(name)) throw new Error(`Private listener ${index + 1} needs a unique lowercase name.`);
    const port = strictInteger(entry.port, `Private listener ${name} port`);
    if (port < 1 || port > 65535 || port === primaryPort || ports.has(port)) throw new Error(`Private listener ${name} needs a unique port between 1 and 65535 that differs from the public listener.`);
    const bindHost = validateBindHost(entry.bindHost ?? entry.bind_host ?? '127.0.0.1');
    if (!isPrivateListenerHost(bindHost)) throw new Error(`Private listener ${name} must bind to loopback, RFC1918/CGNAT IPv4, or a ULA IPv6 address; public bind addresses are not allowed.`);
    const portEnv = String(entry.portEnv ?? entry.port_env ?? '').trim().toUpperCase();
    if (!/^[A-Z_][A-Z0-9_]{0,127}$/.test(portEnv) || ['PORT', 'HOST'].includes(portEnv) || portEnv.startsWith('SHAM_') || portEnv === runtimePortEnv || environments.has(portEnv)) {
      throw new Error(`Private listener ${name} needs a unique non-reserved port environment-variable name.`);
    }
    names.add(name);
    ports.add(port);
    environments.add(portEnv);
    return { name, port, bindHost, portEnv };
  });
}

function validateDomain(value) {
  const domain = String(value || '').trim().toLowerCase().replace(/\.$/, '');
  if (!domain) return '';
  if (domain.length > 253 || !domain.includes('.') || !/^(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/.test(domain)) {
    throw new Error('Domain must be a valid hostname such as app.example.com.');
  }
  return domain;
}

function splitList(value) {
  if (Array.isArray(value)) return value.map(String);
  return String(value || '').split(/[\s,;]+/);
}

function validateIpOrCidr(value) {
  const normalized = String(value || '').trim();
  if (!normalized) return '';
  const parts = normalized.split('/');
  if (parts.length > 2) throw new Error(`“${normalized}” is not a valid IP address or CIDR range.`);
  const [ip, prefixRaw] = parts;
  const version = net.isIP(ip);
  if (!version) throw new Error(`“${normalized}” is not a valid IP address or CIDR range.`);
  if (prefixRaw === undefined) return ip;
  if (!/^\d+$/.test(prefixRaw)) throw new Error(`“${normalized}” has an invalid CIDR prefix.`);
  const prefix = Number(prefixRaw);
  const maximum = version === 4 ? 32 : 128;
  if (prefix < 0 || prefix > maximum) throw new Error(`“${normalized}” has an invalid CIDR prefix.`);
  return `${ip}/${prefix}`;
}

function validateIpList(value, label) {
  const result = [];
  for (const item of splitList(value)) {
    if (!item.trim()) continue;
    result.push(validateIpOrCidr(item));
    if (result.length > 250) throw new Error(`${label} can contain at most 250 entries.`);
  }
  return [...new Set(result)];
}

function validateCountryList(value, label) {
  const result = splitList(value).map((item) => item.trim().toUpperCase()).filter(Boolean);
  if (result.length > 250) throw new Error(`${label} can contain at most 250 entries.`);
  for (const country of result) {
    if (!/^(?:[A-Z]{2}|T1)$/.test(country)) throw new Error(`${label} must use two-letter country codes such as US, NL, or DE; T1 represents Tor traffic.`);
  }
  return [...new Set(result)];
}

function parseFirewallDefaults(defaults = {}) {
  if (defaults.firewall && typeof defaults.firewall === 'object') return defaults.firewall;
  try { return JSON.parse(defaults.firewall_json || '{}'); }
  catch { return {}; }
}

function validateFirewall(body, defaults = {}) {
  const previous = parseFirewallDefaults(defaults);
  const mode = String(body.firewallMode ?? body.firewall_mode ?? previous.mode ?? 'local').toLowerCase();
  if (!['local', 'cloudflare', 'both'].includes(mode)) throw new Error('Firewall mode must be local, Cloudflare, or both.');
  const cloudflareAction = String(body.firewallCloudflareAction ?? body.firewall_cloudflare_action ?? previous.cloudflareAction ?? 'managed_challenge').toLowerCase();
  if (!['block', 'managed_challenge'].includes(cloudflareAction)) throw new Error('Cloudflare firewall action must be block or managed challenge.');

  return {
    mode,
    cloudflareAction,
    rateLimitPerMinute: boundedInteger(body.firewallRateLimit ?? body.firewall_rate_limit, 'Firewall rate limit', Number(previous.rateLimitPerMinute || 0), 0, 100000),
    maxBodyKb: boundedInteger(body.firewallMaxBodyKb ?? body.firewall_max_body_kb, 'Firewall request-body limit', Number(previous.maxBodyKb || 0), 0, 1048576),
    blockedIps: validateIpList(body.firewallBlockedIps ?? body.firewall_blocked_ips ?? previous.blockedIps ?? [], 'Blocked IP list'),
    allowedIps: validateIpList(body.firewallAllowedIps ?? body.firewall_allowed_ips ?? previous.allowedIps ?? [], 'Allowed IP list'),
    blockedCountries: validateCountryList(body.firewallBlockedCountries ?? body.firewall_blocked_countries ?? previous.blockedCountries ?? [], 'Blocked country list'),
    allowedCountries: validateCountryList(body.firewallAllowedCountries ?? body.firewall_allowed_countries ?? previous.allowedCountries ?? [], 'Allowed country list'),
    blockBots: bool(body.firewallBlockBots ?? body.firewall_block_bots, Boolean(previous.blockBots))
  };
}

function validateHealthPath(value) {
  const raw = String(value || '/').trim();
  if (!raw.startsWith('/') || raw.length > 500 || /[\r\n]/.test(raw)) throw new Error('Health-check path must begin with / and be at most 500 characters.');
  try { return new URL(raw, 'http://localhost').pathname + new URL(raw, 'http://localhost').search; }
  catch { throw new Error('Health-check path is invalid.'); }
}

function validateCsp(value) {
  const raw = String(value || '').trim();
  if (raw.length > 8000 || /[\r\n]/.test(raw)) throw new Error('Custom Content Security Policy is invalid or exceeds 8,000 characters.');
  return raw;
}


function parseJsonValue(value, fallback, label) {
  if (value === undefined || value === null || value === '') return fallback;
  if (typeof value === 'object') return value;
  try { return JSON.parse(String(value)); }
  catch { throw new Error(`${label} must be valid JSON.`); }
}

function validateRedirects(value, defaults = []) {
  const parsed = parseJsonValue(value, defaults, 'Redirect rules');
  if (!Array.isArray(parsed) || parsed.length > 100) throw new Error('Redirect rules must be an array with at most 100 entries.');
  return parsed.map((rule, index) => {
    if (!rule || typeof rule !== 'object' || Array.isArray(rule)) throw new Error(`Redirect rule ${index + 1} is invalid.`);
    const type = rule.type === 'prefix' ? 'prefix' : 'exact';
    const from = String(rule.from || '').trim();
    const to = String(rule.to || '').trim();
    const status = Number(rule.status || 308);
    if (!from.startsWith('/') || from.length > 1000 || !to || to.length > 2000 || /[\r\n]/.test(to) || ![301, 302, 307, 308].includes(status)) throw new Error(`Redirect rule ${index + 1} is invalid.`);
    return { type, from, to, status };
  });
}

function validateErrorPages(value, defaults = {}) {
  const parsed = parseJsonValue(value, defaults, 'Error pages');
  if (!parsed || typeof parsed !== 'object' || Array.isArray(parsed)) throw new Error('Error pages must be a JSON object.');
  const result = {};
  for (const [key, page] of Object.entries(parsed)) {
    if (!/^(?:4\d\d|5\d\d|default)$/.test(key)) throw new Error(`Error page key “${key}” is invalid.`);
    const html = String(page || '');
    if (html.length > 256 * 1024 || html.includes('\0')) throw new Error(`Error page “${key}” is too large or invalid.`);
    result[key] = html;
  }
  return result;
}

function validateCacheRules(value, defaults = []) {
  const parsed = parseJsonValue(value, defaults, 'Cache rules');
  if (!Array.isArray(parsed) || parsed.length > 100) throw new Error('Cache rules must be an array with at most 100 entries.');
  return parsed.map((rule, index) => {
    const type = rule?.type === 'prefix' ? 'prefix' : 'exact';
    const rulePath = String(rule?.path || '').trim();
    const seconds = boundedInteger(rule?.seconds, `Cache rule ${index + 1} duration`, 0, 0, 31_536_000);
    if (!rulePath.startsWith('/') || rulePath.length > 1000) throw new Error(`Cache rule ${index + 1} path is invalid.`);
    return { type, path: rulePath, seconds, immutable: bool(rule?.immutable, false) };
  });
}

function validateContainerImage(value) {
  const image = String(value || 'node:22-alpine').trim();
  if (!/^[a-zA-Z0-9][a-zA-Z0-9._/@:-]{0,255}$/.test(image)) throw new Error('Container image is invalid.');
  return image;
}

function validateOptionalHostname(value, label) {
  const raw = String(value || '').trim().toLowerCase().replace(/\.$/, '');
  if (!raw) return '';
  try { return validateDomain(raw); }
  catch { throw new Error(`${label || 'Hostname'} must be a valid hostname such as app.example.com.`); }
}


function validateProxyTarget(value, runtimeType) {
  const raw = String(value || '').trim();
  if (runtimeType !== 'proxy') return raw.slice(0, 2048);
  if (!raw) throw new Error('Reverse proxy target is required.');
  let target;
  try { target = new URL(raw); }
  catch { throw new Error('Reverse proxy target must be a valid HTTP or HTTPS URL.'); }
  if (!['http:', 'https:'].includes(target.protocol)) throw new Error('Reverse proxy target must use HTTP or HTTPS.');
  if (target.username || target.password) throw new Error('Reverse proxy target must not embed credentials.');
  return target.href.slice(0, 2048);
}

function validateProxyHostHeader(value) {
  const raw = String(value || '').trim();
  if (!raw) return '';
  if (raw.length > 253 || /[\r\n\0\s/]/.test(raw)) throw new Error('Proxy host-header override is invalid.');
  let parsed;
  try { parsed = new URL(`http://${raw}`); }
  catch { throw new Error('Proxy host-header override must be a hostname with an optional port.'); }
  if (!parsed.hostname || parsed.username || parsed.password || parsed.pathname !== '/' || parsed.search || parsed.hash) throw new Error('Proxy host-header override must be a hostname with an optional port.');
  return parsed.host;
}

function validateBuildCommand(value, label) {
  const command = String(value || '').trim();
  if (command.includes('\0') || /[\r\n]/.test(command) || command.length > 2000) throw new Error(`${label} must be a single command up to 2,000 characters.`);
  return command;
}

function validateBuildOutput(value) {
  const raw = String(value || '').replaceAll('\\', '/').trim();
  if (!raw || raw === '.') return '';
  return safeRelativePath(raw, 'Build output directory');
}

function validateRuntimePreset(value) {
  const preset = String(value || '').trim().toLowerCase();
  const allowed = new Set(['', 'static', 'proxy', 'node', 'npm', 'bun', 'deno', 'fastapi', 'django', 'go', 'java', 'custom', 'image', 'dockerfile', 'buildpack', 'nixpacks', 'compose']);
  if (!allowed.has(preset)) throw new Error('Runtime preset is invalid.');
  return preset;
}

function validateRuntimeProbeType(value, label, allowed = ['none', 'tcp', 'http', 'command']) {
  const type = String(value || '').trim().toLowerCase();
  if (!allowed.includes(type)) throw new Error(`${label} type must be ${allowed.join(', ')}.`);
  return type;
}

function validateStatusCode(value, label, fallback) {
  const number = strictInteger(value ?? fallback, label);
  if (!Number.isInteger(number) || number < 100 || number > 599) throw new Error(`${label} must be an HTTP status code between 100 and 599.`);
  return number;
}

function validateComposeService(value) {
  const service = String(value || 'app').trim();
  if (!/^[A-Za-z0-9][A-Za-z0-9_.-]{0,127}$/.test(service)) throw new Error('Compose service name is invalid.');
  return service;
}

function validateSiteInput(body, defaults = {}) {
  const name = String(body.name ?? defaults.name ?? '').trim();
  if (name.length < 1 || name.length > 100) throw new Error('Site name must be 1–100 characters.');

  const port = strictInteger(body.port ?? defaults.port, 'Port');
  if (!Number.isInteger(port) || port < 1 || port > 65535) throw new Error('Port must be between 1 and 65535.');

  const cacheSeconds = strictInteger(body.cacheSeconds ?? body.cache_seconds ?? defaults.cache_seconds ?? 0, 'Cache duration');
  if (!Number.isInteger(cacheSeconds) || cacheSeconds < 0 || cacheSeconds > 31_536_000) {
    throw new Error('Cache duration must be between 0 and 31,536,000 seconds.');
  }

  const runtimeType = String(body.runtimeType ?? body.runtime_type ?? defaults.runtime_type ?? 'static').toLowerCase();
  if (!['static', 'node', 'process', 'container', 'compose', 'proxy'].includes(runtimeType)) throw new Error('Runtime type must be static, node, process, container, compose, or proxy.');
  const containerMode = (() => {
    const mode = String(body.containerMode ?? body.container_mode ?? defaults.container_mode ?? 'image').toLowerCase();
    if (!['image', 'dockerfile', 'buildpack', 'nixpacks'].includes(mode)) throw new Error('Container mode must be image, dockerfile, buildpack, or nixpacks.');
    return mode;
  })();
  const requestedRuntimePreset = validateRuntimePreset(body.runtimePreset ?? body.runtime_preset ?? defaults.runtime_preset ?? '');
  const processPresets = new Set(['node', 'npm', 'bun', 'deno', 'fastapi', 'django', 'go', 'java', 'custom']);
  let runtimePreset;
  if (runtimeType === 'static') runtimePreset = 'static';
  else if (runtimeType === 'proxy') runtimePreset = 'proxy';
  else if (runtimeType === 'node') runtimePreset = 'node';
  else if (runtimeType === 'compose') runtimePreset = 'compose';
  else if (runtimeType === 'container') runtimePreset = containerMode;
  else {
    runtimePreset = requestedRuntimePreset || 'custom';
    if (!processPresets.has(runtimePreset)) throw new Error('Managed process runtime preset is invalid.');
  }
  const securityPreset = String(body.securityPreset ?? body.security_preset ?? defaults.security_preset ?? 'balanced').toLowerCase();
  if (!['off', 'balanced', 'strict', 'custom'].includes(securityPreset)) throw new Error('Security-header preset must be off, balanced, strict, or custom.');
  const restartPolicy = String(body.restartPolicy ?? body.restart_policy ?? defaults.restart_policy ?? 'on-failure').toLowerCase();
  if (!['never', 'on-failure', 'always'].includes(restartPolicy)) throw new Error('Restart policy must be never, on-failure, or always.');

  const domain = validateDomain(body.domain ?? defaults.domain ?? '');
  const domainOnly = bool(body.domainOnly ?? body.domain_only, Boolean(defaults.domain_only));
  if (domainOnly && !domain) throw new Error('Configure a domain before enabling domain-only access.');
  const edgeEnabled = bool(body.edgeEnabled ?? body.edge_enabled, Boolean(defaults.edge_enabled));
  if (edgeEnabled && !domain) throw new Error('Configure a domain before enabling the shared 80/443 edge proxy.');
  const cloudflareEnabled = bool(body.cloudflareEnabled ?? body.cloudflare_enabled, Boolean(defaults.cloudflare_enabled));
  const firewallEnabled = bool(body.firewallEnabled ?? body.firewall_enabled, Boolean(defaults.firewall_enabled));
  const firewall = validateFirewall(body, defaults);
  const usesLocalCountryRules = firewallEnabled
    && ['local', 'both'].includes(firewall.mode)
    && (firewall.allowedCountries.length || firewall.blockedCountries.length);
  if (usesLocalCountryRules && !cloudflareEnabled) {
    throw new Error('Local country rules require a synchronized Cloudflare proxy so SHAM can trust country metadata. Use Cloudflare-only mode first, sync Cloudflare, then enable local + Cloudflare if needed.');
  }

  const obfuscate = bool(body.obfuscate, Boolean(defaults.obfuscate));
  const obfuscationRiskAcknowledged = bool(
    body.obfuscationRiskAcknowledged ?? body.obfuscation_risk_acknowledged,
    Boolean(defaults.obfuscation_risk_acknowledged)
  );
  if (obfuscate && !obfuscationRiskAcknowledged) {
    throw new Error('Confirm that JavaScript obfuscation can change runtime behavior before enabling it. Run the compatibility report when editing an existing site.');
  }

  const runtimeIsolation = String(body.runtimeIsolation ?? body.runtime_isolation ?? defaults.runtime_isolation ?? 'process').toLowerCase();
  if (!['process', 'docker'].includes(runtimeIsolation)) throw new Error('Runtime isolation must be process or docker.');
  if (!['node', 'container'].includes(runtimeType) && runtimeIsolation === 'docker') throw new Error('Docker runtime isolation currently applies to Node.js sites and container runtimes.');
  const anubisEnabled = bool(body.anubisEnabled ?? body.anubis_enabled, Boolean(defaults.anubis_enabled));
  const anubisPreset = String(body.anubisPreset ?? body.anubis_preset ?? defaults.anubis_preset ?? 'balanced').toLowerCase();
  if (!['balanced', 'aggressive', 'search-friendly', 'custom'].includes(anubisPreset)) throw new Error('Anubis preset is invalid.');
  if (anubisEnabled && !edgeEnabled) throw new Error('Anubis requires the shared edge proxy so direct-origin traffic cannot bypass it.');
  const readinessMin = validateStatusCode(body.readinessStatusMin ?? body.readiness_status_min, 'Readiness minimum status', Number(defaults.readiness_status_min || 200));
  const readinessMax = validateStatusCode(body.readinessStatusMax ?? body.readiness_status_max, 'Readiness maximum status', Number(defaults.readiness_status_max || 399));
  if (readinessMin > readinessMax) throw new Error('Readiness minimum status cannot exceed its maximum status.');
  const healthMin = validateStatusCode(body.healthCheckStatusMin ?? body.health_check_status_min, 'Health-check minimum status', Number(defaults.health_check_status_min || 200));
  const healthMax = validateStatusCode(body.healthCheckStatusMax ?? body.health_check_status_max, 'Health-check maximum status', Number(defaults.health_check_status_max || 499));
  if (healthMin > healthMax) throw new Error('Health-check minimum status cannot exceed its maximum status.');
  const requestedStartCommand = validateBuildCommand(body.startCommand ?? body.start_command ?? defaults.start_command ?? '', 'Start command');
  const startCommand = runtimeType === 'process' || (runtimeType === 'container' && containerMode === 'image') ? requestedStartCommand : '';
  const readinessType = validateRuntimeProbeType(body.readinessType ?? body.readiness_type ?? defaults.readiness_type ?? 'tcp', 'Readiness probe');
  const readinessCommand = validateBuildCommand(body.readinessCommand ?? body.readiness_command ?? defaults.readiness_command ?? '', 'Readiness command');
  const healthType = validateRuntimeProbeType(body.healthCheckType ?? body.health_check_type ?? defaults.health_check_type ?? 'http', 'Health check');
  const healthCommand = validateBuildCommand(body.healthCheckCommand ?? body.health_check_command ?? defaults.health_check_command ?? '', 'Health-check command');
  if (runtimeType === 'process' && (!runtimePreset || runtimePreset === 'custom') && !startCommand) throw new Error('Custom process runtimes require a start command.');
  if (readinessType === 'command' && !readinessCommand) throw new Error('Command readiness requires a readiness command.');
  if (healthType === 'command' && !healthCommand) throw new Error('Command health checks require a health-check command.');

  const maintenanceHtml = String(body.maintenanceHtml ?? body.maintenance_html ?? defaults.maintenance_html ?? '');
  if (maintenanceHtml.length > 256 * 1024 || maintenanceHtml.includes('\0')) throw new Error('Maintenance page is too large or invalid.');
  const anubisPolicy = String(body.anubisPolicy ?? body.anubis_policy ?? defaults.anubis_policy ?? '');
  if (anubisPolicy.length > 256 * 1024 || anubisPolicy.includes('\0')) throw new Error('Anubis policy is too large or invalid.');
  if (anubisPolicy && /^metrics\s*:/m.test(anubisPolicy)) throw new Error('The top-level Anubis metrics section is managed by SHAM. Remove it from the custom policy.');
  const runtimePortEnv = (() => { const value = String(body.runtimePortEnv ?? body.runtime_port_env ?? defaults.runtime_port_env ?? 'PORT').trim().toUpperCase(); if (!/^[A-Z_][A-Z0-9_]{0,127}$/.test(value)) throw new Error('Runtime port environment-variable name is invalid.'); return value; })();
  const additionalListeners = validatePrivateListeners(
    body.additionalListeners ?? body.additional_listeners ?? defaults.additional_listeners ?? defaults.additional_listeners_json ?? '[]',
    { runtimeType, runtimeIsolation, primaryPort: port, runtimePortEnv }
  );

  return {
    name,
    slug: slugify(body.slug ?? defaults.slug ?? name),
    bind_host: validateBindHost(body.bindHost ?? body.bind_host ?? defaults.bind_host),
    port,
    runtime_type: runtimeType,
    runtime_preset: runtimePreset,
    proxy_target: validateProxyTarget(body.proxyTarget ?? body.proxy_target ?? defaults.proxy_target ?? '', runtimeType),
    proxy_host_header: validateProxyHostHeader(body.proxyHostHeader ?? body.proxy_host_header ?? defaults.proxy_host_header ?? ''),
    proxy_timeout_ms: boundedInteger(body.proxyTimeoutMs ?? body.proxy_timeout_ms, 'Upstream timeout', Number(defaults.proxy_timeout_ms || 30000), 1000, 300000),
    install_command: validateBuildCommand(body.installCommand ?? body.install_command ?? defaults.install_command ?? '', 'Install command'),
    build_command: validateBuildCommand(body.buildCommand ?? body.build_command ?? defaults.build_command ?? '', 'Build command'),
    build_output_dir: validateBuildOutput(body.buildOutputDir ?? body.build_output_dir ?? defaults.build_output_dir ?? ''),
    entry_file: safeRelativePath(body.entryFile ?? body.entry_file ?? defaults.entry_file ?? 'index.html', 'Entry file'),
    node_entry: safeRelativePath(body.nodeEntry ?? body.node_entry ?? defaults.node_entry ?? 'server.js', 'Node entry file'),
    start_command: startCommand,
    runtime_port_env: runtimePortEnv,
    additional_listeners: additionalListeners,
    working_directory: validateBuildOutput(body.workingDirectory ?? body.working_directory ?? defaults.working_directory ?? ''),
    install_dependencies: bool(body.installDependencies ?? body.install_dependencies, Boolean(defaults.install_dependencies)),
    minify: bool(body.minify, Boolean(defaults.minify)),
    obfuscate,
    obfuscation_risk_acknowledged: obfuscationRiskAcknowledged,
    domain_only: domainOnly,
    spa_fallback: bool(body.spaFallback ?? body.spa_fallback, Boolean(defaults.spa_fallback)),
    cache_seconds: cacheSeconds,
    headers: validateHeaders(body.headers ?? body.headers_json ?? defaults.headers_json ?? '{}'),
    enabled: bool(body.enabled, Boolean(defaults.enabled)),
    domain,
    ssl_enabled: bool(body.sslEnabled ?? body.ssl_enabled, Boolean(defaults.ssl_enabled)),
    cloudflare_enabled: cloudflareEnabled,
    firewall_enabled: firewallEnabled,
    firewall,
    compression: bool(body.compression, defaults.compression === undefined ? true : Boolean(defaults.compression)),
    security_preset: securityPreset,
    csp: validateCsp(body.csp ?? defaults.csp ?? ''),
    health_check_path: validateHealthPath(body.healthCheckPath ?? body.health_check_path ?? defaults.health_check_path ?? '/'),
    health_check_interval: boundedInteger(body.healthCheckInterval ?? body.health_check_interval, 'Health-check interval', Number(defaults.health_check_interval || 30), 5, 3600),
    health_check_type: healthType,
    health_check_command: healthCommand,
    health_check_status_min: healthMin,
    health_check_status_max: healthMax,
    restart_policy: restartPolicy,
    max_restarts: boundedInteger(body.maxRestarts ?? body.max_restarts, 'Maximum automatic restarts', Number(defaults.max_restarts || 5), 0, 100),
    memory_limit_mb: boundedInteger(body.memoryLimitMb ?? body.memory_limit_mb, 'Memory limit', Number(defaults.memory_limit_mb || 0), 0, 1048576),
    max_connections: boundedInteger(body.maxConnections ?? body.max_connections, 'Maximum connections', Number(defaults.max_connections || 0), 0, 1000000),
    edge_enabled: edgeEnabled,
    runtime_isolation: runtimeIsolation,
    container_image: validateContainerImage(body.containerImage ?? body.container_image ?? defaults.container_image ?? 'node:22-alpine'),
    container_mode: containerMode,
    container_port: boundedInteger(body.containerPort ?? body.container_port, 'Container port', Number(defaults.container_port || 3000), 1, 65535),
    dockerfile_path: safeRelativePath(body.dockerfilePath ?? body.dockerfile_path ?? defaults.dockerfile_path ?? 'Dockerfile', 'Dockerfile path'),
    compose_file: safeRelativePath(body.composeFile ?? body.compose_file ?? defaults.compose_file ?? 'compose.yaml', 'Compose file'),
    compose_service: validateComposeService(body.composeService ?? body.compose_service ?? defaults.compose_service ?? 'app'),
    buildpack_builder: (() => { const value = String(body.buildpackBuilder ?? body.buildpack_builder ?? defaults.buildpack_builder ?? '').trim(); if (value.length > 256 || /[\r\n\0]/.test(value)) throw new Error('Buildpack builder is invalid or too long.'); return value; })(),
    readiness_type: readinessType,
    readiness_path: validateHealthPath(body.readinessPath ?? body.readiness_path ?? defaults.readiness_path ?? '/'),
    readiness_command: readinessCommand,
    readiness_status_min: readinessMin,
    readiness_status_max: readinessMax,
    startup_timeout_seconds: boundedInteger(body.startupTimeoutSeconds ?? body.startup_timeout_seconds, 'Startup timeout', Number(defaults.startup_timeout_seconds || 30), 1, 600),
    shutdown_grace_seconds: boundedInteger(body.shutdownGraceSeconds ?? body.shutdown_grace_seconds, 'Shutdown grace period', Number(defaults.shutdown_grace_seconds ?? 10), 0, 300),
    blue_green_drain_seconds: boundedInteger(body.blueGreenDrainSeconds ?? body.blue_green_drain_seconds, 'Blue/green drain period', Number(defaults.blue_green_drain_seconds ?? 5), 0, 300),
    manifest_enabled: bool(body.manifestEnabled ?? body.manifest_enabled, defaults.manifest_enabled === undefined ? true : Boolean(defaults.manifest_enabled)),
    cloudflare_auto_sync: bool(body.cloudflareAutoSync ?? body.cloudflare_auto_sync, Boolean(defaults.cloudflare_auto_sync)),
    cpu_limit: (() => { const value = Number(body.cpuLimit ?? body.cpu_limit ?? defaults.cpu_limit ?? 0); if (!Number.isFinite(value) || value < 0 || value > 256) throw new Error('CPU limit must be between 0 and 256.'); return value; })(),
    pids_limit: boundedInteger(body.pidsLimit ?? body.pids_limit, 'Container process limit', Number(defaults.pids_limit || 128), 16, 65535),
    outbound_network: bool(body.outboundNetwork ?? body.outbound_network, defaults.outbound_network === undefined ? true : Boolean(defaults.outbound_network)),
    anubis_enabled: anubisEnabled,
    anubis_preset: anubisPreset,
    anubis_difficulty: boundedInteger(body.anubisDifficulty ?? body.anubis_difficulty, 'Anubis difficulty', Number(defaults.anubis_difficulty || 4), 1, 10),
    anubis_policy: anubisPolicy,
    maintenance_enabled: bool(body.maintenanceEnabled ?? body.maintenance_enabled, Boolean(defaults.maintenance_enabled)),
    maintenance_html: maintenanceHtml,
    redirects: validateRedirects(body.redirects ?? body.redirects_json, defaults.redirects || (() => { try { return JSON.parse(defaults.redirects_json || '[]'); } catch { return []; } })()),
    error_pages: validateErrorPages(body.errorPages ?? body.error_pages_json, defaults.errorPages || (() => { try { return JSON.parse(defaults.error_pages_json || '{}'); } catch { return {}; } })()),
    cache_rules: validateCacheRules(body.cacheRules ?? body.cache_rules_json, defaults.cacheRules || (() => { try { return JSON.parse(defaults.cache_rules_json || '[]'); } catch { return []; } })()),
    release_mode: bool(body.releaseMode ?? body.release_mode, Boolean(defaults.release_mode)),
    git_url: String(body.gitUrl ?? body.git_url ?? defaults.git_url ?? '').trim().slice(0, 2048),
    git_branch: String(body.gitBranch ?? body.git_branch ?? defaults.git_branch ?? 'main').trim().slice(0, 200) || 'main',
    preview_domain: validateOptionalHostname(body.previewDomain ?? body.preview_domain ?? defaults.preview_domain ?? '', 'Preview domain')
  };
}

module.exports = {
  bool,
  safeRelativePath,
  slugify,
  validateHeaders,
  validateBindHost,
  validateDomain,
  validateIpOrCidr,
  validateIpList,
  validateCountryList,
  validateFirewall,
  validateHealthPath,
  validateCsp,
  validateRedirects,
  validateErrorPages,
  validateCacheRules,
  validateContainerImage,
  validateProxyTarget,
  validateProxyHostHeader,
  validateBuildCommand,
  validateBuildOutput,
  validatePrivateListeners,
  validateSiteInput
};
