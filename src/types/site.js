'use strict';

// JSDoc-only module: no runtime exports, just shared domain typedefs so the
// rest of the backend can reference `Site` instead of an anonymous object
// shape. See docs/development.md for how SHAM uses TypeScript/JSDoc.

/**
 * The normalized, in-memory shape of a site row after `hydrateSite()`
 * (src/sites/shared.js) has parsed its JSON columns and applied defaults.
 * Not every column of the `sites` table is listed here — this covers the
 * fields read outside sites/*.js; the rest still flow through via the
 * `[key: string]: any` index signature.
 *
 * @typedef {Object} Site
 * @property {number} id
 * @property {string} name
 * @property {string} slug
 * @property {string} domain
 * @property {number} port
 * @property {string} bind_host
 * @property {boolean} enabled
 * @property {'static' | 'node' | 'container' | 'compose' | 'proxy'} runtime_type
 * @property {'process' | 'docker'} runtime_isolation
 * @property {string} runtime_preset
 * @property {SitePrivateListener[]} additional_listeners
 * @property {boolean} ssl_enabled
 * @property {boolean} edge_enabled
 * @property {boolean} cloudflare_enabled
 * @property {boolean} anubis_enabled
 * @property {string} anubis_preset
 * @property {number} anubis_difficulty
 * @property {boolean} firewall_enabled
 * @property {SiteFirewall} firewall
 * @property {Record<string, string>} headers
 * @property {SiteRedirect[]} redirects
 * @property {Record<string, string>} errorPages
 * @property {SiteCacheRule[]} cacheRules
 * @property {string} readiness_type
 * @property {string} readiness_path
 * @property {string} readiness_command
 * @property {number} readiness_status_min
 * @property {number} readiness_status_max
 * @property {number} startup_timeout_seconds
 * @property {number} shutdown_grace_seconds
 * @property {number} blue_green_drain_seconds
 * @property {string} health_check_type
 * @property {string} health_check_command
 * @property {number} health_check_interval
 * @property {number} health_check_status_min
 * @property {number} health_check_status_max
 * @property {number} max_restarts
 * @property {number} memory_limit_mb
 * @property {number} cpu_limit
 * @property {number} pids_limit
 * @property {number} max_connections
 * @property {string} container_mode
 * @property {number} container_port
 * @property {string} dockerfile_path
 * @property {string} compose_file
 * @property {string} compose_service
 * @property {string} proxy_target
 * @property {string} proxy_host_header
 * @property {number} proxy_timeout_ms
 * @property {boolean} outbound_network
 * @property {boolean} pinned
 * @property {string} git_url
 * @property {string} runtime_manifest_hash
 * @property {string} runtime_manifest_approved_hash
 */

/**
 * A private process listener. SHAM assigns the application-side port through
 * `portEnv` and proxies it only on the private `bindHost:port` listener.
 * @typedef {Object} SitePrivateListener
 * @property {string} name
 * @property {number} port
 * @property {string} bindHost
 * @property {string} portEnv
 */

/**
 * @typedef {Object} SiteFirewall
 * @property {'local' | 'cloudflare'} mode
 * @property {string} cloudflareAction
 * @property {number} rateLimitPerMinute
 * @property {number} maxBodyKb
 * @property {string[]} blockedIps
 * @property {string[]} allowedIps
 * @property {string[]} blockedCountries
 * @property {string[]} allowedCountries
 * @property {boolean} blockBots
 */

/**
 * @typedef {Object} SiteRedirect
 * @property {string} from
 * @property {string} to
 * @property {'prefix' | 'exact'} [type]
 * @property {number} [status]
 */

/**
 * @typedef {Object} SiteCacheRule
 * @property {string} pattern
 * @property {number} seconds
 * @property {boolean} [immutable]
 */

module.exports = {};
