'use strict';

const path = require('node:path');
const { BACKUPS_DIR } = require('../config');
const { stageBackupRestore, MARKER: RESTORE_MARKER } = require('../backup-restore');
const { providerStatuses, saveProviderToken, listProviderRepositories } = require('../git-providers');

function registerOperationsRoutes(ctx) {
  const {
    app, requireAuth, requireAdmin, webhookLimiter, serializeSiteMutation, db, crypto, DEPLOY_WEBHOOK_DUMMY_SECRET,
    operationsManager, manager, recordAudit, getSiteOr404, bool, validateSiteInput, uniqueSlug, writeSiteConfig,
    getSecretSetting, setSecretSetting, getSetting, setSetting, cloudflareTunnels, legacyCloudflareTunnel, cloudflareTunnelControlPlane, pangolinTunnel, updateManager, verifyPassword, stepUpLimiter,
    multipart, updateUpload
  } = ctx;

  const tunnelExposureWarning = (site, tunnel) => {
    if (!tunnel?.route?.tunnelOnly) return null;
    if (['0.0.0.0', '::'].includes(String(site.bind_host || ''))) return 'Tunnel-only mode requires the site listener to bind to localhost or a loopback address.';
    if (!site.edge_enabled) return 'Tunnel-only mode is protecting this site listener, but no shared edge route is enabled. Verify that the configured loopback origin service reaches this site.';
    return 'Tunnel-only mode protects the site listener. Also keep host/Docker mappings for the shared edge listener private.';
  };
  const tunnelPayload = (site) => {
    const cloudflareTunnel = cloudflareTunnels.status(site.id);
    return { ...cloudflareTunnel, exposureWarning: tunnelExposureWarning(site, cloudflareTunnel) };
  };
  const assertTunnelDoesNotExposePrivateListener = (site, originService) => {
    if (!originService || !Array.isArray(site.additional_listeners)) return;
    let origin;
    try { origin = new URL(originService); } catch { return; }
    const port = Number(origin.port || (origin.protocol === 'https:' ? 443 : 80));
    if (site.additional_listeners.some((listener) => Number(listener.port) === port)) {
      throw new Error('A private process listener cannot be used as a Cloudflare Tunnel origin. Route the site through its primary listener or the shared edge instead.');
    }
  };

function authenticateDeployWebhook(req, res, next) {
    const site = manager.getSite(Number(req.params.id));
    const configuredSecret = site ? operationsManager.siteEnvironment(site.id, 'build').DEPLOY_WEBHOOK_SECRET : '';
    const verificationSecret = configuredSecret || DEPLOY_WEBHOOK_DUMMY_SECRET;
    const rawSignature = String(
      req.get('x-hub-signature-256') || req.get('x-hub-signature') || req.get('x-gitea-signature') ||
      req.get('x-forgejo-signature') || req.get('x-sham-signature') || ''
    ).trim().toLowerCase();
    const supplied = /^[0-9a-f]{64}$/i.test(rawSignature) ? `sha256=${rawSignature}` : rawSignature;
    const gitlabToken = String(req.get('x-gitlab-token') || '');
    const expected = `sha256=${crypto.createHmac('sha256', verificationSecret).update(req.rawBody || Buffer.alloc(0)).digest('hex')}`;
    const hmacValid = supplied.length === expected.length && crypto.timingSafeEqual(Buffer.from(supplied), Buffer.from(expected));
    const tokenValid = gitlabToken.length === verificationSecret.length && crypto.timingSafeEqual(Buffer.from(gitlabToken), Buffer.from(verificationSecret));
    const valid = hmacValid || tokenValid;
    if (!site || !configuredSecret || !valid) return res.status(401).json({ error: 'Webhook authentication failed.' });
    req.deployWebhookSite = site;
    next();
  }

  app.post('/api/hooks/deploy/:id', webhookLimiter, authenticateDeployWebhook, serializeSiteMutation, async (req, res) => {
    const site = req.deployWebhookSite;
    const bitbucketBranch = Array.isArray(req.body?.push?.changes)
      ? req.body.push.changes.find((change) => change?.new?.type === 'branch')?.new?.name
      : '';
    const requestedBranch = String(req.body?.ref || bitbucketBranch || '').replace(/^refs\/heads\//, '');
    if (requestedBranch && site.git_branch && requestedBranch !== site.git_branch) return res.status(202).json({ ignored: true, reason: 'The push was for another branch.' });
    const deliveryId = String(
      req.get('x-github-delivery') || req.get('x-gitlab-event-uuid') || req.get('x-request-uuid') || req.get('x-hook-uuid') ||
      req.get('x-gitea-delivery') || req.get('x-forgejo-delivery') || req.get('x-sham-delivery') || ''
    ).trim();
    if (!/^[A-Za-z0-9._:{}-]{1,200}$/.test(deliveryId)) return res.status(400).json({ error: 'A valid provider webhook delivery identifier is required.' });
    db.prepare("DELETE FROM deploy_webhook_deliveries WHERE received_at < datetime('now', '-14 days')").run();
    try {
      db.prepare('INSERT INTO deploy_webhook_deliveries (site_id, delivery_id) VALUES (?, ?)').run(site.id, deliveryId);
    } catch (error) {
      if (String(error.code || '').startsWith('SQLITE_CONSTRAINT')) return res.status(202).json({ ignored: true, reason: 'This webhook delivery was already processed.' });
      throw error;
    }
    try {
      const release = await operationsManager.deployGit(site, {
        url: site.git_url,
        branch: site.git_branch,
        installDependencies: site.install_dependencies,
        installCommand: site.install_command,
        buildCommand: site.build_command,
        buildOutputDir: site.build_output_dir
      });
      recordAudit(null, 'site.git.webhook-deploy', { siteId: site.id, releaseId: release.id, branch: site.git_branch, deliveryId });
      res.json({ deployed: true, releaseId: release.id });
    } catch (error) {
      db.prepare('DELETE FROM deploy_webhook_deliveries WHERE site_id = ? AND delivery_id = ?').run(site.id, deliveryId);
      manager.log(site.id, 'error', `Webhook deployment failed: ${error.message}`);
      res.status(500).json({ error: 'Webhook deployment failed. Review the authenticated runtime logs for details.' });
    }
  });

  app.get('/api/sites/:id/deployments', requireAuth, (req, res) => {
    const site = getSiteOr404(req, res);
    if (!site) return;
    res.json({ deployments: operationsManager.listDeployments(site.id, req.query.limit) });
  });


  app.get('/api/sites/:id/deployments/:deploymentId/logs', requireAuth, (req, res) => {
    const site = getSiteOr404(req, res);
    if (!site) return;
    const deploymentId = Number(req.params.deploymentId);
    if (!Number.isInteger(deploymentId) || deploymentId <= 0) return res.status(400).json({ error: 'Deployment ID is invalid.' });
    const exists = db.prepare('SELECT id FROM site_deployments WHERE id = ? AND site_id = ?').get(deploymentId, site.id);
    if (!exists) return res.status(404).json({ error: 'Deployment not found.' });
    res.json({ logs: operationsManager.deploymentLogs(site.id, deploymentId, req.query.limit) });
  });

  app.get('/api/sites/:id/operations', requireAuth, requireAdmin, (req, res) => {
    const site = getSiteOr404(req, res);
    if (!site) return;
    res.json({ site: manager.decorate(site), ...operationsManager.operationsPayload(site.id) });
  });

  app.put('/api/sites/:id/environment', requireAuth, requireAdmin, async (req, res) => {
    const site = getSiteOr404(req, res);
    if (!site) return;
    try {
      const environment = operationsManager.saveEnvironment(site.id, req.body.variables);
      if (manager.statusFor(site.id).running) await manager.restart(site.id);
      recordAudit(req.user.id, 'site.environment.update', { id: site.id, keys: environment.map((item) => item.key) });
      res.json({ environment });
    } catch (error) { res.status(400).json({ error: error.message }); }
  });


  app.post('/api/sites/:id/environment/:key/reveal', requireAuth, requireAdmin, stepUpLimiter, async (req, res) => {
    const site = getSiteOr404(req, res);
    if (!site) return;
    try {
      const user = db.prepare('SELECT password_hash, password_salt FROM users WHERE id = ? AND active = 1').get(req.user.id);
      if (!user || !(await verifyPassword(String(req.body?.password || ''), user.password_salt, user.password_hash))) return res.status(401).json({ error: 'Password confirmation failed.' });
      const revealed = operationsManager.revealEnvironmentSecret(site.id, req.params.key);
      recordAudit(req.user.id, 'site.environment.secret-reveal', { id: site.id, key: revealed.key });
      res.setHeader('Cache-Control', 'no-store');
      res.json(revealed);
    } catch (error) { res.status(400).json({ error: error.message }); }
  });

  app.post('/api/sites/:id/environment/copy', requireAuth, requireAdmin, async (req, res) => {
    const site = getSiteOr404(req, res);
    if (!site) return;
    try {
      const result = operationsManager.copyEnvironment(req.body?.sourceSiteId, site.id);
      if (result.copied && manager.statusFor(site.id).running) await manager.restart(site.id);
      recordAudit(req.user.id, 'site.environment.copy', { id: site.id, sourceSiteId: Number(req.body?.sourceSiteId), copied: result.copied });
      res.json(result);
    } catch (error) { res.status(400).json({ error: error.message }); }
  });

  app.put('/api/sites/:id/database-profiles', requireAuth, requireAdmin, async (req, res) => {
    const site = getSiteOr404(req, res);
    if (!site) return;
    try {
      const databaseProfiles = operationsManager.attachDatabaseProfiles(site.id, req.body.profileIds);
      if (manager.statusFor(site.id).running) await manager.restart(site.id);
      recordAudit(req.user.id, 'site.database-profiles.update', { id: site.id, profileIds: req.body.profileIds || [] });
      res.json({ databaseProfiles });
    } catch (error) { res.status(400).json({ error: error.message }); }
  });

  app.post('/api/sites/:id/jobs', requireAuth, requireAdmin, (req, res) => {
    const site = getSiteOr404(req, res);
    if (!site) return;
    try {
      const id = operationsManager.saveJob(site.id, req.body);
      recordAudit(req.user.id, 'site.job.save', { siteId: site.id, jobId: id });
      res.status(req.body.id ? 200 : 201).json({ jobs: operationsManager.listJobs(site.id), id });
    } catch (error) { res.status(400).json({ error: error.message }); }
  });

  app.delete('/api/sites/:id/jobs/:jobId', requireAuth, requireAdmin, (req, res) => {
    const site = getSiteOr404(req, res);
    if (!site) return;
    try { operationsManager.deleteJob(site.id, Number(req.params.jobId)); recordAudit(req.user.id, 'site.job.delete', { siteId: site.id, jobId: Number(req.params.jobId) }); res.status(204).end(); }
    catch (error) { res.status(400).json({ error: error.message }); }
  });

  app.post('/api/sites/:id/jobs/:jobId/run', requireAuth, requireAdmin, async (req, res) => {
    const site = getSiteOr404(req, res);
    if (!site) return;
    try { const result = await operationsManager.runJob(Number(req.params.jobId), 'manual', site.id); recordAudit(req.user.id, 'site.job.run', { siteId: site.id, jobId: Number(req.params.jobId) }); res.json(result); }
    catch (error) { res.status(400).json({ error: error.message }); }
  });

  app.post('/api/sites/:id/deploy/git', requireAuth, requireAdmin, async (req, res) => {
    const site = getSiteOr404(req, res);
    if (!site) return;
    try {
      const release = await operationsManager.deployGit(site, {
        url: req.body.url || site.git_url,
        branch: req.body.branch || site.git_branch,
        deployKey: String(req.body.deployKey || ''),
        installDependencies: bool(req.body.installDependencies, site.install_dependencies),
        installCommand: req.body.installCommand ?? site.install_command,
        buildCommand: req.body.buildCommand ?? site.build_command,
        buildOutputDir: req.body.buildOutputDir ?? site.build_output_dir,
        approveManifestChanges: bool(req.body.approveManifestChanges, false)
      });
      /** @type {{ action?: string } | null} */
      let webhook = null;
      /** @type {string | null} */
      let webhookWarning = null;
      try { webhook = await operationsManager.configureProviderWebhook(manager.getSite(site.id), getSetting('git_webhook_base_url', '')); }
      catch (error) { const message = error instanceof Error ? error.message : String(error); webhookWarning = message; manager.log(site.id, 'error', `Git provider webhook configuration failed: ${message}`); }
      const warning = [release.warning, webhookWarning].filter(Boolean).join(' ') || null;
      recordAudit(req.user.id, 'site.git.deploy', { siteId: site.id, releaseId: release.id, branch: req.body.branch || site.git_branch, webhook: webhook?.action || null, warning: Boolean(warning) });
      res.json({ release, site: manager.decorate(manager.getSite(site.id)), webhook, warning });
    } catch (error) {
      if (error.code === 'SHAM_MANIFEST_APPROVAL_REQUIRED') return res.status(409).json({ error: error.message, code: error.code, manifest: error.manifest });
      res.status(400).json({ error: error.message });
    }
  });

  app.post('/api/sites/:id/releases/:releaseId/rollback', requireAuth, requireAdmin, async (req, res) => {
    const site = getSiteOr404(req, res);
    if (!site) return;
    try { const result = await operationsManager.rollbackRelease(site, Number(req.params.releaseId)); recordAudit(req.user.id, 'site.release.rollback', { siteId: site.id, releaseId: Number(req.params.releaseId), warning: Boolean(result.warning) }); res.json({ releases: result.releases, deployments: operationsManager.listDeployments(site.id, 50), warning: result.warning }); }
    catch (error) { res.status(400).json({ error: error.message }); }
  });

  app.post('/api/sites/:id/previews', requireAuth, requireAdmin, async (req, res) => {
    const site = getSiteOr404(req, res);
    if (!site) return;
    try { const preview = await operationsManager.createPreview(site, req.body); recordAudit(req.user.id, 'site.preview.create', { siteId: site.id, previewId: preview.id, hostname: preview.hostname }); res.status(201).json({ preview }); }
    catch (error) { res.status(400).json({ error: error.message }); }
  });

  app.delete('/api/sites/:id/previews/:previewId', requireAuth, requireAdmin, async (req, res) => {
    const site = getSiteOr404(req, res);
    if (!site) return;
    try { await operationsManager.deletePreview(Number(req.params.previewId), site.id); recordAudit(req.user.id, 'site.preview.delete', { siteId: site.id, previewId: Number(req.params.previewId) }); res.status(204).end(); }
    catch (error) { res.status(400).json({ error: error.message }); }
  });

  app.get('/api/sites/:id/config/export', requireAuth, requireAdmin, (req, res) => {
    const site = getSiteOr404(req, res);
    if (!site) return;
    const payload = {
      format: 'sham-site-config', version: 1, exportedAt: new Date().toISOString(),
      site: { ...site, id: undefined, directory_name: undefined, created_at: undefined, updated_at: undefined, cloudflare_zone_id: undefined, cloudflare_record_id: undefined, cloudflare_firewall_rule_id: undefined, headers_json: undefined, firewall_json: undefined, redirects_json: undefined, error_pages_json: undefined, cache_rules_json: undefined },
      environment: operationsManager.listEnvironment(site.id).map((item) => ({ key: item.key, secret: item.secret, scope: item.scope, value: item.secret ? null : operationsManager.siteEnvironment(site.id, item.scope)[item.key] })),
      databaseProfiles: operationsManager.listDatabaseProfiles(site.id).filter((item) => item.attached).map((item) => ({ name: item.name, envKey: item.envKey, type: item.type })),
      jobs: operationsManager.listJobs(site.id).map(({ id, site_id, running, last_status, ...job }) => job)
    };
    res.setHeader('Content-Disposition', `attachment; filename="${site.slug}-sham-config.json"`);
    res.json(payload);
  });

  app.post('/api/sites/:id/config/import', requireAuth, requireAdmin, async (req, res) => {
    const site = getSiteOr404(req, res);
    if (!site) return;
    try {
      if (req.body?.format !== 'sham-site-config' || !req.body.site) throw new Error('This is not a supported SHAM site configuration export.');
      const config = validateSiteInput({ ...req.body.site, port: site.port, name: req.body.site.name || site.name }, site);
      config.slug = uniqueSlug(config.slug, site.id);
      writeSiteConfig(site.id, config);
      if (Array.isArray(req.body.environment)) operationsManager.saveEnvironment(site.id, req.body.environment.filter((item) => !item.secret || item.value));
      if (Array.isArray(req.body.jobs)) for (const job of req.body.jobs.slice(0, 100)) operationsManager.saveJob(site.id, job);
      if (manager.statusFor(site.id).running) await manager.restart(site.id);
      recordAudit(req.user.id, 'site.config.import', { siteId: site.id });
      res.json({ site: manager.decorate(manager.getSite(site.id)), warning: 'Secret values and database connection strings are never imported from an export; review them separately.' });
    } catch (error) { res.status(400).json({ error: error.message }); }
  });

  app.get('/api/runtime-logs/search', requireAuth, requireAdmin, (req, res) => {
    const limit = Math.min(Math.max(Number(req.query.limit) || 200, 1), 2000);
    const conditions = [];
    const values = [];
    if (req.query.siteId) { conditions.push('site_id = ?'); values.push(Number(req.query.siteId)); }
    if (req.query.level && ['info', 'error'].includes(req.query.level)) { conditions.push('level = ?'); values.push(req.query.level); }
    if (req.query.query) { conditions.push('message LIKE ? ESCAPE \'\\\''); values.push(`%${String(req.query.query).slice(0, 200).replace(/[\\%_]/g, '\\$&')}%`); }
    if (req.query.since) { conditions.push('created_at >= ?'); values.push(String(req.query.since).slice(0, 30)); }
    const sql = `SELECT id, site_id AS siteId, level, message, context_json AS contextJson, created_at AS createdAt FROM runtime_logs ${conditions.length ? `WHERE ${conditions.join(' AND ')}` : ''} ORDER BY id DESC LIMIT ?`;
    const rows = db.prepare(sql).all(...values, limit).map((row) => ({ ...row, context: (() => { try { return JSON.parse(row.contextJson || 'null'); } catch { return null; } })(), contextJson: undefined }));
    res.json({ logs: rows });
  });

  function savedLogFilters(userId) {
    return db.prepare('SELECT id, name, filter_json AS filterJson, created_at AS createdAt FROM saved_log_filters WHERE user_id = ? ORDER BY name').all(userId).map((row) => {
      let filter = {};
      try {
        const parsed = JSON.parse(row.filterJson || '{}');
        if (parsed && typeof parsed === 'object' && !Array.isArray(parsed)) filter = parsed;
      } catch { /* Ignore a corrupt legacy filter instead of breaking the whole page. */ }
      return { id: row.id, name: row.name, filter, createdAt: row.createdAt };
    });
  }

  app.get('/api/log-filters', requireAuth, (req, res) => {
    res.json({ filters: savedLogFilters(req.user.id) });
  });

  app.post('/api/log-filters', requireAuth, (req, res) => {
    try {
      const name = String(req.body.name || '').trim().slice(0, 80);
      const filter = req.body.filter && typeof req.body.filter === 'object' && !Array.isArray(req.body.filter) ? req.body.filter : {};
      const serialized = JSON.stringify(filter);
      if (!name || serialized.length > 4000) throw new Error('Filter name or value is invalid.');
      db.prepare(`INSERT INTO saved_log_filters (user_id, name, filter_json) VALUES (?, ?, ?) ON CONFLICT(user_id, name) DO UPDATE SET filter_json = excluded.filter_json`).run(req.user.id, name, serialized);
      res.status(201).json({ filters: savedLogFilters(req.user.id) });
    } catch (error) { res.status(400).json({ error: error.message }); }
  });

  app.delete('/api/log-filters/:id', requireAuth, (req, res) => { db.prepare('DELETE FROM saved_log_filters WHERE id = ? AND user_id = ?').run(Number(req.params.id), req.user.id); res.status(204).end(); });

  app.get('/api/admin/git-providers', requireAuth, requireAdmin, (_req, res) => res.json({ providers: providerStatuses(db) }));
  app.put('/api/admin/git-providers/:provider', requireAuth, requireAdmin, (req, res) => {
    try {
      const providers = saveProviderToken(db, req.params.provider, { token: req.body?.token, clearToken: bool(req.body?.clearToken, false), baseUrl: req.body?.baseUrl });
      recordAudit(req.user.id, 'git-provider.configure', { provider: String(req.params.provider || '').toLowerCase(), connected: providers.find((item) => item.provider === String(req.params.provider || '').toLowerCase())?.configured || false });
      res.json({ providers });
    } catch (error) { res.status(400).json({ error: error.message }); }
  });
  app.get('/api/admin/git-providers/:provider/repositories', requireAuth, requireAdmin, async (req, res) => {
    try { res.json({ repositories: await listProviderRepositories(db, req.params.provider) }); }
    catch (error) { res.status(400).json({ error: error.message }); }
  });

  app.get('/api/admin/database-profiles', requireAuth, requireAdmin, (_req, res) => res.json({ profiles: operationsManager.listDatabaseProfiles() }));
  app.post('/api/admin/database-profiles', requireAuth, requireAdmin, (req, res) => { try { const id = operationsManager.saveDatabaseProfile(req.body); recordAudit(req.user.id, 'database-profile.save', { id }); res.status(req.body.id ? 200 : 201).json({ id, profiles: operationsManager.listDatabaseProfiles() }); } catch (error) { res.status(400).json({ error: error.message }); } });
  app.delete('/api/admin/database-profiles/:id', requireAuth, requireAdmin, (req, res) => { try { operationsManager.deleteDatabaseProfile(Number(req.params.id)); recordAudit(req.user.id, 'database-profile.delete', { id: Number(req.params.id) }); res.status(204).end(); } catch (error) { res.status(400).json({ error: error.message }); } });

  app.get('/api/admin/operations', requireAuth, requireAdmin, (_req, res) => {
    const operations = operationsManager.operationsPayload();
    res.json({
      ...operations,
      capabilities: { ...operations.capabilities, cloudflared: cloudflareTunnels.available() || legacyCloudflareTunnel.status().available, newt: pangolinTunnel.status().available },
      siteCloudflareTunnels: cloudflareTunnels.listStatus(),
      cloudflareTunnel: legacyCloudflareTunnel.status(),
      pangolinTunnel: pangolinTunnel.status(),
      gitProviders: providerStatuses(db),
      settings: {
        prometheusEnabled: getSetting('prometheus_enabled', '0') === '1',
        prometheusTokenConfigured: Boolean(getSecretSetting(db, 'prometheus_token', '')),
        otelEndpoint: getSetting('otel_endpoint', ''),
        otelHeadersConfigured: Boolean(getSecretSetting(db, 'otel_headers', '')),
        gitWebhookBaseUrl: getSetting('git_webhook_base_url', ''),
        publicStatusEnabled: getSetting('public_status_enabled', '0') === '1',
        publicStatusTitle: getSetting('public_status_title', 'SHAM service status'),
        locale: getSetting('instance_locale', 'en'),
        setupCompleted: getSetting('setup_completed', '0') === '1',
        updateChannel: getSetting('update_channel', 'stable')
      },
      update: updateManager.status()
    });
  });

  app.put('/api/admin/cloudflare-tunnel', requireAuth, requireAdmin, async (req, res) => {
    try {
      const body = req.body && typeof req.body === 'object' && !Array.isArray(req.body) ? req.body : {};
      const has = (key) => Object.prototype.hasOwnProperty.call(body, key);
      const configuration = { clearToken: bool(body.clearToken, false) };
      if (has('enabled')) configuration.enabled = bool(body.enabled);
      if (has('token')) configuration.token = String(body.token || '');
      if (has('tunnelId')) configuration.tunnelId = String(body.tunnelId || '');
      const result = await legacyCloudflareTunnel.configure(configuration);
      recordAudit(req.user.id, 'cloudflare-tunnel.configure', { enabled: result.enabled, tokenUpdated: Boolean(has('token') && String(body.token || '').trim()), tokenCleared: bool(body.clearToken, false) });
      res.json({ cloudflareTunnel: result });
    } catch (error) { res.status(400).json({ error: error.message }); }
  });

  app.post('/api/admin/cloudflare-tunnel/restart', requireAuth, requireAdmin, async (req, res) => {
    try {
      const result = await legacyCloudflareTunnel.restart();
      recordAudit(req.user.id, 'cloudflare-tunnel.restart');
      res.json({ cloudflareTunnel: result });
    } catch (error) { res.status(400).json({ error: error.message }); }
  });

  app.put('/api/admin/pangolin-tunnel', requireAuth, requireAdmin, async (req, res) => {
    try {
      const body = req.body && typeof req.body === 'object' && !Array.isArray(req.body) ? req.body : {};
      const allowed = new Set(['enabled', 'endpoint', 'newtId', 'secret', 'clearSecret']);
      const unknown = Object.keys(body).filter((key) => !allowed.has(key));
      if (unknown.length) throw new Error(`Unknown Pangolin setting${unknown.length === 1 ? '' : 's'}: ${unknown.join(', ')}.`);
      const has = (key) => Object.prototype.hasOwnProperty.call(body, key);
      const configuration = { clearSecret: bool(body.clearSecret, false) };
      if (has('enabled')) configuration.enabled = bool(body.enabled);
      if (has('endpoint')) configuration.endpoint = String(body.endpoint || '');
      if (has('newtId')) configuration.newtId = String(body.newtId || '');
      if (has('secret')) configuration.secret = String(body.secret || '');
      const result = await pangolinTunnel.configure(configuration);
      recordAudit(req.user.id, 'pangolin-tunnel.configure', { enabled: result.enabled, secretUpdated: Boolean(has('secret') && String(body.secret || '').trim()), secretCleared: bool(body.clearSecret, false) });
      res.json({ pangolinTunnel: result });
    } catch (error) { res.status(400).json({ error: error.message }); }
  });

  app.post('/api/admin/pangolin-tunnel/restart', requireAuth, requireAdmin, async (req, res) => {
    try {
      const result = await pangolinTunnel.restart();
      recordAudit(req.user.id, 'pangolin-tunnel.restart');
      res.json({ pangolinTunnel: result });
    } catch (error) { res.status(400).json({ error: error.message }); }
  });

  app.get('/api/admin/sites/:id/cloudflare-tunnel', requireAuth, requireAdmin, (req, res) => {
    const site = getSiteOr404(req, res);
    if (!site) return;
    res.json({ cloudflareTunnel: tunnelPayload(site) });
  });

  app.put('/api/admin/sites/:id/cloudflare-tunnel', requireAuth, requireAdmin, async (req, res) => {
    const site = getSiteOr404(req, res);
    if (!site) return;
    try {
      const body = req.body && typeof req.body === 'object' && !Array.isArray(req.body) ? req.body : {};
      const has = (key) => Object.prototype.hasOwnProperty.call(body, key);
      const configuration = { clearToken: bool(body.clearToken, false) };
      if (has('enabled')) configuration.enabled = bool(body.enabled);
      if (has('token')) configuration.token = String(body.token || '');
      if (has('tunnelId')) configuration.tunnelId = String(body.tunnelId || '');
      if (has('publicHostname')) configuration.publicHostname = String(body.publicHostname || '');
      if (has('originService')) configuration.originService = String(body.originService || '');
      if (has('managedRoute')) configuration.managedRoute = bool(body.managedRoute, false);
      if (has('tunnelOnly')) configuration.tunnelOnly = bool(body.tunnelOnly, false);
      if (has('connectorMode')) configuration.connectorMode = String(body.connectorMode || '');
      assertTunnelDoesNotExposePrivateListener(site, configuration.originService);
      if (configuration.tunnelOnly && ['0.0.0.0', '::'].includes(String(site.bind_host || ''))) throw new Error('Tunnel-only mode requires this site to bind to localhost or a loopback address.');
      const result = await cloudflareTunnels.configure(site.id, configuration);
      recordAudit(req.user.id, 'site.cloudflare-tunnel.configure', {
        siteId: site.id,
        enabled: result.enabled,
        tokenUpdated: Boolean(has('token') && String(body.token || '').trim()),
        tokenCleared: bool(body.clearToken, false)
      });
      res.json({ cloudflareTunnel: { ...result, exposureWarning: tunnelExposureWarning(site, result) } });
    } catch (error) { res.status(400).json({ error: error.message }); }
  });

  app.post('/api/admin/sites/:id/cloudflare-tunnel/restart', requireAuth, requireAdmin, async (req, res) => {
    const site = getSiteOr404(req, res);
    if (!site) return;
    try {
      const result = await cloudflareTunnels.restart(site.id);
      recordAudit(req.user.id, 'site.cloudflare-tunnel.restart', { siteId: site.id });
      res.json({ cloudflareTunnel: { ...result, exposureWarning: tunnelExposureWarning(site, result) } });
    } catch (error) { res.status(400).json({ error: error.message }); }
  });

  app.get('/api/admin/cloudflare-tunnels/discover', requireAuth, requireAdmin, async (_req, res) => {
    try {
      const tunnels = await cloudflareTunnelControlPlane().listTunnels();
      res.json({ tunnels: (Array.isArray(tunnels) ? tunnels : []).map((tunnel) => ({
        id: String(tunnel.id || ''), name: String(tunnel.name || ''), status: String(tunnel.status || ''), configSource: String(tunnel.config_src || ''),
        activeAt: tunnel.conns_active_at || null, connectionCount: Array.isArray(tunnel.connections) ? tunnel.connections.length : 0
      })) });
    } catch (error) { res.status(400).json({ error: error.message }); }
  });

  app.post('/api/admin/sites/:id/cloudflare-tunnel/provision', requireAuth, requireAdmin, async (req, res) => {
    const site = getSiteOr404(req, res);
    if (!site) return;
    try {
      if (!site.domain || !site.edge_enabled) throw new Error('Provisioning a managed tunnel route requires a site domain and the shared edge proxy.');
      if (['0.0.0.0', '::'].includes(String(site.bind_host || '')) && bool(req.body?.tunnelOnly, true)) throw new Error('Tunnel-only mode requires this site to bind to localhost or a loopback address.');
      const originService = String(req.body?.originService || '').trim();
      assertTunnelDoesNotExposePrivateListener(site, originService);
      const controlPlane = cloudflareTunnelControlPlane();
      const provisioned = await controlPlane.createAndConfigure({ name: `sham-${site.slug}-${site.id}`, publicHostname: site.domain, originService });
      const result = await cloudflareTunnels.configure(site.id, {
        enabled: true,
        token: provisioned.token,
        tunnelId: provisioned.tunnel.id,
        publicHostname: provisioned.route.publicHostname,
        originService: provisioned.route.originService,
        managedRoute: true,
        tunnelOnly: bool(req.body?.tunnelOnly, true)
      });
      recordAudit(req.user.id, 'site.cloudflare-tunnel.provision', { siteId: site.id, tunnelId: provisioned.tunnel.id, publicHostname: provisioned.route.publicHostname });
      res.status(201).json({ cloudflareTunnel: { ...result, exposureWarning: tunnelExposureWarning(site, result) }, route: provisioned.route });
    } catch (error) { res.status(400).json({ error: error.message }); }
  });

  app.post('/api/admin/sites/:id/cloudflare-tunnel/reconcile', requireAuth, requireAdmin, async (req, res) => {
    const site = getSiteOr404(req, res);
    if (!site) return;
    try {
      const tunnel = cloudflareTunnels.status(site.id);
      if (!tunnel.route?.managedRoute) throw new Error('Enable managed routing and save a tunnel ID, public hostname, and origin service first.');
      const route = await cloudflareTunnelControlPlane().reconcileIngress(tunnel.route);
      recordAudit(req.user.id, 'site.cloudflare-tunnel.reconcile', { siteId: site.id, tunnelId: route.tunnelId, publicHostname: route.publicHostname });
      res.json({ cloudflareTunnel: tunnelPayload(site), route });
    } catch (error) { res.status(400).json({ error: error.message }); }
  });

  app.put('/api/admin/operations/settings', requireAuth, requireAdmin, (req, res) => {
    try {
      const body = req.body && typeof req.body === 'object' && !Array.isArray(req.body) ? req.body : {};
      const has = (key) => Object.prototype.hasOwnProperty.call(body, key);
      const clearPrometheusToken = bool(body.clearPrometheusToken, false);
      const incomingPrometheusToken = has('prometheusToken') ? String(body.prometheusToken || '').trim() : '';
      if (incomingPrometheusToken && (incomingPrometheusToken.length > 4096 || /[\s\0]/.test(incomingPrometheusToken))) throw new Error('Metrics token must be a single value no longer than 4096 characters.');
      if (clearPrometheusToken && incomingPrometheusToken) throw new Error('Choose either a new metrics token or clear the saved token.');
      const prometheusEnabled = has('prometheusEnabled') ? bool(body.prometheusEnabled) : getSetting('prometheus_enabled', '0') === '1';
      const nextPrometheusToken = clearPrometheusToken ? '' : incomingPrometheusToken || getSecretSetting(db, 'prometheus_token', '');
      if (prometheusEnabled && !nextPrometheusToken) throw new Error('Set a metrics token before enabling the Prometheus endpoint.');

      let otelEndpoint = has('otelEndpoint') ? String(body.otelEndpoint || '').trim() : null;
      if (otelEndpoint !== null && otelEndpoint.length > 2048) throw new Error('OpenTelemetry endpoint is too long.');
      if (otelEndpoint) {
        let parsedEndpoint;
        try { parsedEndpoint = new URL(otelEndpoint); } catch { throw new Error('OpenTelemetry endpoint must be a valid HTTP or HTTPS URL.'); }
        if (!['http:', 'https:'].includes(parsedEndpoint.protocol) || parsedEndpoint.username || parsedEndpoint.password || parsedEndpoint.search || parsedEndpoint.hash) throw new Error('OpenTelemetry endpoint must use HTTP or HTTPS without credentials, query parameters, or fragments.');
        otelEndpoint = parsedEndpoint.toString();
      }
      const clearOtelHeaders = bool(body.clearOtelHeaders, false);
      /** @type {string | null} */
      let serializedOtelHeaders = null;
      if (has('otelHeaders')) {
        if (!body.otelHeaders || typeof body.otelHeaders !== 'object' || Array.isArray(body.otelHeaders)) throw new Error('OpenTelemetry headers must be a JSON object.');
        const entries = Object.entries(body.otelHeaders);
        if (entries.length > 50) throw new Error('OpenTelemetry can define at most 50 headers.');
        const headers = {};
        const forbiddenHeaders = new Set(['connection', 'content-length', 'host', 'keep-alive', 'proxy-authenticate', 'proxy-authorization', 'te', 'trailer', 'transfer-encoding', 'upgrade']);
        for (const [rawName, rawValue] of entries) {
          const name = String(rawName || '').trim();
          const value = String(rawValue ?? '');
          if (!/^[!#$%&'*+.^_`|~0-9A-Za-z-]{1,200}$/.test(name) || forbiddenHeaders.has(name.toLowerCase()) || /[\0\r\n]/.test(value) || value.length > 4096) throw new Error('OpenTelemetry contains an invalid or unsafe header.');
          headers[name] = value;
        }
        serializedOtelHeaders = JSON.stringify(headers);
        if (serializedOtelHeaders.length > 64 * 1024) throw new Error('OpenTelemetry headers are too large.');
      }
      if (clearOtelHeaders && serializedOtelHeaders && serializedOtelHeaders !== '{}') throw new Error('Choose either new OpenTelemetry headers or clear the saved headers.');

      const locale = has('locale') ? String(body.locale).toLowerCase() : null;
      if (locale !== null && !['en', 'nl', 'de'].includes(locale)) throw new Error('Locale must be English, Dutch, or German.');
      const updateChannel = has('updateChannel') ? String(body.updateChannel) : null;
      if (updateChannel !== null && !['stable', 'preview'].includes(updateChannel)) throw new Error('Update channel is invalid.');
      /** @type {string | null} */
      let gitWebhookBaseUrl = null;
      if (has('gitWebhookBaseUrl')) {
        gitWebhookBaseUrl = String(body.gitWebhookBaseUrl || '').trim();
        if (gitWebhookBaseUrl) {
          let parsed;
          try { parsed = new URL(gitWebhookBaseUrl); } catch { throw new Error('Public SHAM URL must be a valid HTTP or HTTPS origin.'); }
          if (!['http:', 'https:'].includes(parsed.protocol) || parsed.username || parsed.password || parsed.search || parsed.hash || (parsed.pathname && parsed.pathname !== '/')) throw new Error('Public SHAM URL must be an HTTP or HTTPS origin without credentials, path, query, or fragment.');
          gitWebhookBaseUrl = parsed.origin;
        }
      }

      db.transaction(() => {
        if (body.backup) operationsManager.saveBackupSettings(body.backup);
        if (has('prometheusEnabled')) setSetting('prometheus_enabled', prometheusEnabled ? '1' : '0');
        if (incomingPrometheusToken) setSecretSetting(db, 'prometheus_token', incomingPrometheusToken);
        if (clearPrometheusToken) setSecretSetting(db, 'prometheus_token', '');
        if (otelEndpoint !== null) setSetting('otel_endpoint', otelEndpoint);
        if (serializedOtelHeaders !== null) setSecretSetting(db, 'otel_headers', serializedOtelHeaders);
        if (clearOtelHeaders) setSecretSetting(db, 'otel_headers', '');
        if (gitWebhookBaseUrl !== null) setSetting('git_webhook_base_url', gitWebhookBaseUrl);
        if (has('publicStatusEnabled')) setSetting('public_status_enabled', bool(body.publicStatusEnabled) ? '1' : '0');
        if (has('publicStatusTitle')) setSetting('public_status_title', String(body.publicStatusTitle || 'SHAM service status').slice(0, 120));
        if (locale !== null) setSetting('instance_locale', locale);
        if (has('setupCompleted')) setSetting('setup_completed', bool(body.setupCompleted) ? '1' : '0');
        if (updateChannel !== null) setSetting('update_channel', updateChannel);
      })();
      recordAudit(req.user.id, 'operations.settings.update');
      res.json({ saved: true });
    } catch (error) { res.status(400).json({ error: error.message }); }
  });

  app.post('/api/admin/backups/run', requireAuth, requireAdmin, async (req, res) => { try { const backup = await operationsManager.createBackup({ provider: req.body.provider || null }); recordAudit(req.user.id, 'backup.run', backup); res.json({ backup }); } catch (error) { res.status(400).json({ error: error.message }); } });


  app.get('/api/admin/backups/restore-status', requireAuth, requireAdmin, (_req, res) => {
    res.json({ pending: require('node:fs').existsSync(RESTORE_MARKER) });
  });

  app.post('/api/admin/backups/:id/restore', requireAuth, requireAdmin, stepUpLimiter, async (req, res) => {
    try {
      const user = db.prepare('SELECT * FROM users WHERE id = ?').get(req.user.id);
      if (!(await verifyPassword(String(req.body.password || ''), user.password_salt, user.password_hash))) return res.status(401).json({ error: 'Password confirmation failed.' });
      const backup = db.prepare("SELECT id, filename, status FROM backup_runs WHERE id = ?").get(Number(req.params.id));
      if (!backup || backup.status !== 'success') return res.status(404).json({ error: 'A successful backup run with that ID was not found.' });
      if (!/^sham-backup-.*\.tar\.gz$/.test(String(backup.filename || ''))) throw new Error('Backup filename is invalid.');
      const safetyBackup = await operationsManager.createBackup({ provider: 'local', skipRetention: true });
      const staged = await stageBackupRestore(path.join(BACKUPS_DIR, backup.filename), { requestedBy: req.user.id, backupRunId: backup.id });
      recordAudit(req.user.id, 'backup.restore.stage', { backupId: backup.id, filename: backup.filename, safetyBackupId: safetyBackup.id });
      res.json({ restore: staged, safetyBackup, message: 'Restore staged. A fresh safety backup was created first. Restart SHAM to apply the selected backup before the database is opened.' });
    } catch (error) { res.status(400).json({ error: error.message }); }
  });

  app.post('/api/admin/alert-destinations', requireAuth, requireAdmin, (req, res) => { try { const id = operationsManager.saveAlertDestination(req.body); recordAudit(req.user.id, 'alert-destination.save', { id }); res.status(req.body.id ? 200 : 201).json({ id, destinations: operationsManager.listAlertDestinations() }); } catch (error) { res.status(400).json({ error: error.message }); } });
  app.post('/api/admin/alert-destinations/:id/test', requireAuth, requireAdmin, async (req, res) => { try { await operationsManager.testAlertDestination(Number(req.params.id)); res.json({ sent: true }); } catch (error) { res.status(400).json({ error: error.message }); } });
  app.delete('/api/admin/alert-destinations/:id', requireAuth, requireAdmin, (req, res) => { try { operationsManager.deleteAlertDestination(Number(req.params.id)); recordAudit(req.user.id, 'alert-destination.delete', { id: Number(req.params.id) }); res.status(204).end(); } catch (error) { res.status(400).json({ error: error.message }); } });

  app.get('/api/admin/audit/export', requireAuth, requireAdmin, (_req, res) => {
    const rows = db.prepare(`SELECT audit_logs.id, users.username, audit_logs.action, audit_logs.detail, audit_logs.created_at AS createdAt FROM audit_logs LEFT JOIN users ON users.id = audit_logs.user_id ORDER BY audit_logs.id DESC LIMIT 10000`).all();
    res.setHeader('Content-Disposition', 'attachment; filename="sham-audit-log.ndjson"');
    res.type('application/x-ndjson').send(rows.map((row) => JSON.stringify(row)).join('\n') + '\n');
  });

  app.post('/api/admin/update', requireAuth, requireAdmin, multipart(updateUpload.single('archive')), async (req, res) => {
    try {
      if (!req.file?.path) throw new Error('Choose a SHAM update ZIP.');
      const pending = await updateManager.stage(req.file.path, req.file.originalname, { allowUnsigned: bool(req.body.allowUnsigned, false) });
      recordAudit(req.user.id, 'update.stage', { version: pending.version, archiveName: pending.archiveName });
      res.status(201).json({ pending, message: 'Update staged. Restart SHAM to apply it with automatic managed-file rollback.' });
    } catch (error) { res.status(400).json({ error: error.message }); }
  });

  app.delete('/api/admin/update', requireAuth, requireAdmin, async (req, res) => { try { const result = await updateManager.cancel(); recordAudit(req.user.id, 'update.cancel', result); res.json(result); } catch (error) { res.status(400).json({ error: error.message }); } });

  app.get('/api/admin/audit', requireAuth, requireAdmin, (_req, res) => {
    const logs = db.prepare(`
      SELECT audit_logs.*, users.username
      FROM audit_logs
      LEFT JOIN users ON users.id = audit_logs.user_id
      ORDER BY audit_logs.id DESC
      LIMIT 300
    `).all().map((row) => ({
      id: row.id,
      username: row.username || 'system',
      action: row.action,
      detail: row.detail ? (() => { try { return JSON.parse(row.detail); } catch { return { raw: row.detail }; } })() : null,
      createdAt: row.created_at
    }));
    res.json({ logs });
  });
  }

module.exports = { registerOperationsRoutes };
