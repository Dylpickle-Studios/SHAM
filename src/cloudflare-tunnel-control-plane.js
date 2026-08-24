'use strict';

const {
  validateAccountId,
  validateTunnelId,
  validatePublicHostname,
  validateOriginService
} = require('./cloudflare-tunnel');

const API_BASE = 'https://api.cloudflare.com/client/v4';
const MAX_API_TOKEN_LENGTH = 16 * 1024;

function validateApiToken(value) {
  const token = String(value || '').trim();
  if (!token || token.length > MAX_API_TOKEN_LENGTH || /[\s\0]/.test(token)) {
    throw new Error('Cloudflare Tunnel management API token must be a single value no longer than 16 KiB.');
  }
  return token;
}

function validateTunnelName(value) {
  const name = String(value || '').trim();
  if (!name || name.length > 100 || /[\r\n\0]/.test(name)) throw new Error('Cloudflare Tunnel name must be between 1 and 100 characters.');
  return name;
}

function apiError(payload, status) {
  const errors = Array.isArray(payload?.errors) ? payload.errors : [];
  const message = errors.map((entry) => String(entry?.message || '')).filter(Boolean).join('; ').slice(0, 1000);
  return new Error(message ? `Cloudflare API request failed: ${message}` : `Cloudflare API request failed with HTTP ${status}.`);
}

class CloudflareTunnelControlPlane {
  constructor({ accountId, apiToken, fetchImpl = globalThis.fetch, baseUrl = API_BASE, timeoutMs = 15_000 } = {}) {
    this.accountId = validateAccountId(accountId);
    this.apiToken = validateApiToken(apiToken);
    if (typeof fetchImpl !== 'function') throw new Error('Cloudflare Tunnel control-plane support requires fetch.');
    this.fetchImpl = fetchImpl;
    this.baseUrl = String(baseUrl || API_BASE).replace(/\/$/, '');
    this.timeoutMs = Math.max(1000, Math.min(Number(timeoutMs) || 15_000, 60_000));
  }

  async request(pathname, { method = 'GET', body } = {}) {
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), this.timeoutMs);
    timer.unref?.();
    try {
      const response = await this.fetchImpl(`${this.baseUrl}${pathname}`, {
        method,
        redirect: 'error',
        signal: controller.signal,
        headers: {
          Authorization: `Bearer ${this.apiToken}`,
          Accept: 'application/json',
          ...(body === undefined ? {} : { 'Content-Type': 'application/json' })
        },
        ...(body === undefined ? {} : { body: JSON.stringify(body) })
      });
      let payload = null;
      try { payload = await response.json(); } catch { /* The API can return a non-JSON proxy error. */ }
      if (!response.ok || !payload?.success) throw apiError(payload, response.status);
      return payload.result;
    } finally {
      clearTimeout(timer);
    }
  }

  listTunnels() {
    return this.request(`/accounts/${this.accountId}/cfd_tunnel?per_page=100`);
  }

  getTunnel(tunnelId) {
    const id = validateTunnelId(tunnelId);
    return this.request(`/accounts/${this.accountId}/cfd_tunnel/${id}`);
  }

  async createTunnel(name) {
    const result = await this.request(`/accounts/${this.accountId}/cfd_tunnel`, {
      method: 'POST',
      body: { name: validateTunnelName(name), config_src: 'cloudflare' }
    });
    return { ...result, id: validateTunnelId(result?.id) };
  }

  getToken(tunnelId) {
    const id = validateTunnelId(tunnelId);
    return this.request(`/accounts/${this.accountId}/cfd_tunnel/${id}/token`);
  }

  getConfiguration(tunnelId) {
    const id = validateTunnelId(tunnelId);
    return this.request(`/accounts/${this.accountId}/cfd_tunnel/${id}/configurations`);
  }

  putConfiguration(tunnelId, config) {
    const id = validateTunnelId(tunnelId);
    return this.request(`/accounts/${this.accountId}/cfd_tunnel/${id}/configurations`, { method: 'PUT', body: { config } });
  }

  async reconcileIngress({ tunnelId, publicHostname, originService }) {
    const id = validateTunnelId(tunnelId);
    const hostname = validatePublicHostname(publicHostname);
    const service = validateOriginService(originService);
    if (!service) throw new Error('A loopback origin service is required to reconcile a tunnel route.');
    const current = await this.getConfiguration(id);
    const ingress = Array.isArray(current?.config?.ingress) ? current.config.ingress.filter((entry) => entry && typeof entry === 'object') : [];
    const matching = (entry) => String(entry.hostname || '').toLowerCase() === hostname;
    const fallback = ingress.filter((entry) => !entry.hostname);
    const routes = ingress.filter((entry) => entry.hostname && !matching(entry));
    const next = {
      ...(current?.config && typeof current.config === 'object' ? current.config : {}),
      ingress: [...routes, { hostname, service }, ...(fallback.length ? fallback : [{ service: 'http_status:404' }])]
    };
    const result = await this.putConfiguration(id, next);
    return { tunnelId: id, publicHostname: hostname, originService: service, configVersion: result?.version ?? null };
  }

  async createAndConfigure({ name, publicHostname, originService }) {
    const hostname = validatePublicHostname(publicHostname);
    const service = validateOriginService(originService);
    if (!service) throw new Error('A loopback origin service is required to reconcile a tunnel route.');
    const tunnel = await this.createTunnel(name);
    const token = await this.getToken(tunnel.id);
    const route = await this.reconcileIngress({ tunnelId: tunnel.id, publicHostname: hostname, originService: service });
    return { tunnel, token: String(token || ''), route };
  }
}

module.exports = {
  API_BASE,
  CloudflareTunnelControlPlane,
  validateApiToken,
  validateTunnelName
};
