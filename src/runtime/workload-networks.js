'use strict';

const net = require('node:net');

// Containers on SHAM's runtime networks can reach the control-plane container
// directly (it joins those networks and listens on 0.0.0.0). Requests from
// those subnets must go through the shared edge, never to the dashboard or a
// site's direct listener. The subnet list comes from the Runtime Agent and is
// fail-open until first known, so a missing agent never locks operators out.
const REFRESH_MS = 5 * 60_000;
const RETRY_MS = 30_000;

/** @type {import('node:net').BlockList | null} */
let blockList = null;
// Host side of each bridge (docker-proxy, host-originated connections, published
// ports): never a workload, even though it sits inside the workload subnet.
/** @type {import('node:net').BlockList | null} */
let gatewayList = null;
/** @type {string[]} */
let knownSubnets = [];
let nextRefreshAt = 0;
/** @type {Promise<string[]> | null} */
let inflight = null;
/** @type {() => Promise<{ networks?: Array<{ subnets?: string[], gateways?: string[] }> }>} */
let fetchSubnets = () => require('./client').getRuntimeClient().networkSubnets();

// Docker's default gateway is the subnet's first host address; used when the agent
// does not report one (older agents, or networks without explicit IPAM gateways).
function firstHostAddress(address, prefix, version) {
  if (version === 4) {
    const value = address.split('.').reduce((total, octet) => (total * 256) + Number(octet), 0);
    const host = value - (value % (2 ** (32 - prefix))) + 1;
    return [24, 16, 8, 0].map((shift) => Math.floor(host / (2 ** shift)) % 256).join('.');
  }
  const [head, tail = ''] = address.split('::');
  const left = head ? head.split(':') : [];
  const right = tail ? tail.split(':') : [];
  const groups = [...left, ...Array(8 - left.length - right.length).fill('0'), ...right].map((group) => BigInt(`0x${group || '0'}`));
  const value = groups.reduce((total, group) => (total << 16n) | group, 0n);
  const hostBits = BigInt(128 - prefix);
  const host = ((value >> hostBits) << hostBits) + 1n;
  return Array.from({ length: 8 }, (_unused, index) => ((host >> BigInt(16 * (7 - index))) & 0xffffn).toString(16)).join(':');
}

/** @param {string[]} subnets @param {string[]} [gateways] */
function setWorkloadSubnets(subnets, gateways = []) {
  const list = new net.BlockList();
  const hosts = new net.BlockList();
  const accepted = [];
  const reported = (gateways || []).map(normalizeAddress).filter((address) => net.isIP(address));
  for (const entry of subnets || []) {
    const [address, prefixRaw] = String(entry).split('/');
    const version = net.isIP(address);
    const prefix = Number(prefixRaw);
    if (!version || !Number.isInteger(prefix) || prefix < 0 || prefix > (version === 6 ? 128 : 32)) continue;
    list.addSubnet(address, prefix, version === 6 ? 'ipv6' : 'ipv4');
    const family = version === 6 ? 'ipv6' : 'ipv4';
    const subnet = new net.BlockList();
    subnet.addSubnet(address, prefix, family);
    const hasGateway = reported.some((gateway) => net.isIP(gateway) === version && subnet.check(gateway, family));
    if (!hasGateway && prefix < (version === 6 ? 128 : 31)) hosts.addAddress(firstHostAddress(address, prefix, version), family);
    accepted.push(`${address}/${prefix}`);
  }
  for (const gateway of reported) hosts.addAddress(gateway, net.isIP(gateway) === 6 ? 'ipv6' : 'ipv4');
  knownSubnets = accepted;
  blockList = accepted.length ? list : null;
  gatewayList = accepted.length ? hosts : null;
  return accepted;
}

function refreshWorkloadSubnets() {
  if (inflight) return inflight;
  nextRefreshAt = Date.now() + RETRY_MS;
  inflight = Promise.resolve().then(() => fetchSubnets())
    .then((result) => {
      const networks = result?.networks || [];
      nextRefreshAt = Date.now() + REFRESH_MS;
      return setWorkloadSubnets(networks.flatMap((network) => network?.subnets || []), networks.flatMap((network) => network?.gateways || []));
    })
    .catch(() => knownSubnets)
    .finally(() => { inflight = null; });
  return inflight;
}

function normalizeAddress(value) {
  let address = String(value || '');
  const zone = address.indexOf('%');
  if (zone !== -1) address = address.slice(0, zone);
  if (/^::ffff:/i.test(address) && net.isIP(address.slice(7)) === 4) address = address.slice(7);
  return address;
}

/** @param {string | undefined | null} remoteAddress */
function isWorkloadAddress(remoteAddress) {
  if (Date.now() >= nextRefreshAt) refreshWorkloadSubnets();
  if (!blockList) return false;
  const address = normalizeAddress(remoteAddress);
  const version = net.isIP(address);
  if (!version) return false;
  const family = version === 6 ? 'ipv6' : 'ipv4';
  return blockList.check(address, family) && !gatewayList?.check(address, family);
}

const FORBIDDEN_BODY = 'Runtime workloads cannot reach this listener directly; use the site domain through the shared edge.';

// Express/Connect-compatible: also safe on a bare node:http handler.
function workloadNetworkGuard() {
  return function rejectWorkloadNetworks(req, res, next) {
    if (!isWorkloadAddress(req.socket?.remoteAddress)) return next();
    res.writeHead(403, { 'Content-Type': 'text/plain; charset=utf-8', Connection: 'close' });
    res.end(FORBIDDEN_BODY);
  };
}

/** @param {{ fetch?: typeof fetchSubnets }} [options] Test hook. */
function configureWorkloadNetworks({ fetch } = {}) {
  if (fetch) fetchSubnets = fetch;
  blockList = null;
  gatewayList = null;
  knownSubnets = [];
  nextRefreshAt = 0;
  inflight = null;
}

module.exports = {
  isWorkloadAddress, workloadNetworkGuard, refreshWorkloadSubnets, setWorkloadSubnets, configureWorkloadNetworks,
  workloadSubnets: () => [...knownSubnets], WORKLOAD_FORBIDDEN_BODY: FORBIDDEN_BODY
};
