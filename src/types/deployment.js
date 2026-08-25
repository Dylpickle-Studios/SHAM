'use strict';

// JSDoc-only module — see src/types/site.js.

/**
 * A row from the `site_deployments` table (src/db.js), returned by the
 * deployment history/listing endpoints.
 * @typedef {Object} Deployment
 * @property {number} id
 * @property {number} site_id
 * @property {'queued' | 'building' | 'success' | 'failed' | 'rolled-back' | 'superseded'} status
 * @property {string} source
 * @property {string} [branch]
 * @property {string} [commit_sha]
 * @property {string} [commit_message]
 * @property {string} [detail]
 * @property {string} started_at
 * @property {string} [finished_at]
 */

/**
 * A retained, immutable release directory a site can be rolled back to.
 * @typedef {Object} Release
 * @property {number} id
 * @property {number} site_id
 * @property {string} directory_name
 * @property {string} [commit_sha]
 * @property {string} created_at
 * @property {boolean} [active]
 */

module.exports = {};
