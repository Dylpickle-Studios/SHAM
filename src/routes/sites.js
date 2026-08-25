// @ts-nocheck -- not part of this session's checkJs rollout yet.
// This file still has genuine `tsc --noEmit` findings (mostly narrow
// `let x = null`-style inference and untyped Express handlers, the same
// patterns already fixed across most of src/) that need real per-file
// JSDoc work to resolve, not a suppression. Tracked as follow-up work;
// see tsconfig.json and docs/development.md. Do not add more files here
// without a similar comment and a plan to remove it.
'use strict';

const { siteRoot, legacySiteRoot } = require('../site-paths');
const { RELEASES_DIR, UPLOAD_LIMIT_BYTES } = require('../config');

function registerSiteRoutes(ctx) {
  const {
    app, requireAuth, requireAdmin, db, manager, cloudflareTunnels, net, recordAudit, performanceMonitor,
    uploadSizeGuard, multipart, receiveWebsite, receiveSingleFile, nextAvailableSitePort, validateSiteInput,
    uniqueSlug, checkPort, installUploadAsync, SITES_DIR, fs, path, operationsManager, bool, writeSiteConfig,
    requiredSiteFile, safeObfuscationWarning, uploadParts, auditObfuscationCompatibility, safeRelativePath,
    listSiteFilesAsync, readTextFileAsync, writeTextFileAsync, replaceSingleFileFromPathAsync, deleteSingleFileAsync,
    stageSingleFileDeletionAsync, snapshotManager, dependencyScanner,
    edgeProxy, getSetting, siteRows, getSiteOr404,
    hasCertificate, realFileInside, cloudflarePortWarning, snapshotLabel
  } = ctx;

  const findActiveEdgeDomain = db.prepare(`
    SELECT id, name FROM sites
    WHERE lower(domain) = lower(?) AND edge_enabled = 1 AND enabled = 1 AND id != ?
    LIMIT 1
  `);
  const assertEdgeDomainAvailable = (config, siteId = 0) => {
    if (!config.edge_enabled || !config.enabled || !config.domain) return;
    const conflict = findActiveEdgeDomain.get(config.domain, Number(siteId) || 0);
    if (conflict) throw new Error(`Domain ${config.domain} is already routed by enabled edge site “${conflict.name}”. Disable its edge route or choose a different domain.`);
  };
  const assertTunnelOnlyBinding = (config, siteId) => {
    if (!['0.0.0.0', '::'].includes(String(config.bind_host || ''))) return;
    const tunnelOnly = db.prepare('SELECT 1 FROM site_cloudflare_tunnels WHERE site_id = ? AND tunnel_only = 1').get(siteId);
    if (tunnelOnly) throw new Error('This site uses tunnel-only origin hardening and must remain bound to localhost or a loopback address. Disable tunnel-only mode before exposing it publicly.');
  };

app.get('/api/sites', requireAuth, (_req, res) => res.json({ sites: siteRows().map((site) => ({ ...site, cloudflareTunnel: cloudflareTunnels.summary(site.id) })) }));


  app.patch('/api/sites/:id/pin', requireAuth, (req, res) => {
    const site = getSiteOr404(req, res);
    if (!site) return;
    const pinned = bool(req.body?.pinned, !site.pinned);
    db.prepare('UPDATE sites SET pinned = ?, updated_at = CURRENT_TIMESTAMP WHERE id = ?').run(pinned ? 1 : 0, site.id);
    recordAudit(req.user.id, pinned ? 'site.pin' : 'site.unpin', { siteId: site.id });
    res.json({ site: manager.decorate(manager.getSite(site.id)) });
  });

  app.post('/api/sites/:id/firewall/ban-ip', requireAuth, (req, res) => {
    const site = getSiteOr404(req, res);
    if (!site) return;
    const ip = String(req.body.ip || '').trim();
    if (!net.isIP(ip)) return res.status(400).json({ error: 'Only a full IPv4 or IPv6 address can be banned. Switch visitor privacy to full IP storage if addresses are masked or hashed.' });
    const existingBlockedIps = site.firewall?.blockedIps || [];
    if (!existingBlockedIps.includes(ip) && existingBlockedIps.length >= 250) return res.status(400).json({ error: 'Blocked IP list can contain at most 250 entries. Remove an address before adding another.' });
    const blockedIps = [...new Set([...existingBlockedIps, ip])];
    const firewall = { ...(site.firewall || {}), blockedIps };
    db.prepare('UPDATE sites SET firewall_enabled = 1, firewall_json = ?, updated_at = CURRENT_TIMESTAMP WHERE id = ?').run(JSON.stringify(firewall), site.id);
    manager.refreshLiveFirewall(site.id);
    recordAudit(req.user.id, 'site.firewall.ip-ban', { siteId: site.id, ip });
    res.json({ site: manager.decorate(manager.getSite(site.id)), banned: ip });
  });

  app.delete('/api/sites/:id/firewall/ban-ip', requireAuth, (req, res) => {
    const site = getSiteOr404(req, res);
    if (!site) return;
    const ip = String(req.body.ip || '').trim();
    if (!net.isIP(ip)) return res.status(400).json({ error: 'A full IPv4 or IPv6 address is required.' });
    const firewall = { ...(site.firewall || {}), blockedIps: (site.firewall?.blockedIps || []).filter((value) => value !== ip) };
    db.prepare('UPDATE sites SET firewall_json = ?, updated_at = CURRENT_TIMESTAMP WHERE id = ?').run(JSON.stringify(firewall), site.id);
    manager.refreshLiveFirewall(site.id);
    recordAudit(req.user.id, 'site.firewall.ip-unban', { siteId: site.id, ip });
    res.json({ site: manager.decorate(manager.getSite(site.id)), unbanned: ip });
  });

  app.get('/api/statistics', requireAuth, (_req, res) => {
    try { manager.flushStats(); } catch (error) { manager.log(null, 'error', `Could not flush statistics before reading them: ${error.message}`); }
    const totals = db.prepare(`
      SELECT
        COUNT(sites.id) AS sites,
        COALESCE(SUM(site_stats.total_requests), 0) AS requests,
        COALESCE(SUM(site_stats.total_bytes), 0) AS bytes,
        COALESCE(SUM(site_stats.total_errors), 0) AS errors,
        COALESCE(SUM(site_stats.total_response_ms), 0) AS response_ms,
        (SELECT COUNT(DISTINCT ip) FROM site_visitor_stats) AS visitors
      FROM sites
      LEFT JOIN site_stats ON site_stats.site_id = sites.id
    `).get();
    const sites = db.prepare(`
      SELECT sites.id, sites.name, sites.runtime_type, sites.runtime_isolation, sites.enabled,
        COALESCE(site_stats.total_requests, 0) AS requests,
        COALESCE(site_stats.total_bytes, 0) AS bytes,
        COALESCE(site_stats.total_errors, 0) AS errors,
        COALESCE(site_stats.total_response_ms, 0) AS response_ms,
        site_stats.last_request_at
      FROM sites
      LEFT JOIN site_stats ON site_stats.site_id = sites.id
      ORDER BY requests DESC, sites.name COLLATE NOCASE
    `).all().map((row) => {
      const runtime = manager.statusFor(row.id, row);
      return { ...row, enabled: Boolean(row.enabled), running: runtime.running, healthStatus: runtime.health?.status || null };
    });
    const daily = db.prepare(`
      SELECT day, SUM(requests) AS requests, SUM(bytes) AS bytes, SUM(errors) AS errors
      FROM site_daily_stats
      WHERE day >= date('now', '-13 days')
      GROUP BY day
      ORDER BY day
    `).all();
    const countries = db.prepare(`
      SELECT country, SUM(requests) AS requests, SUM(bytes) AS bytes,
        COUNT(DISTINCT ip) AS visitors, MAX(last_request_at) AS last_request_at
      FROM site_visitor_stats
      GROUP BY country
      ORDER BY requests DESC, country
      LIMIT 100
    `).all();
    const visitors = db.prepare(`
      SELECT visitor.site_id, sites.name AS site_name, visitor.ip, visitor.country,
        visitor.client_type, visitor.user_agent, visitor.requests, visitor.bytes, visitor.errors, visitor.last_request_at
      FROM site_visitor_stats AS visitor
      JOIN sites ON sites.id = visitor.site_id
      ORDER BY visitor.last_request_at DESC
      LIMIT 100
    `).all().map((visitor) => ({ ...visitor, actionable: net.isIP(String(visitor.ip || '')) > 0 }));
    const clientTypes = db.prepare(`SELECT client_type AS type, SUM(requests) AS requests, COUNT(DISTINCT ip) AS visitors FROM site_visitor_stats GROUP BY client_type ORDER BY requests DESC`).all();
    const failedDeploymentRows = db.prepare(`
      SELECT deployment.id, deployment.site_id AS siteId, sites.name AS siteName, deployment.source,
        deployment.status, deployment.detail, deployment.started_at AS startedAt, deployment.finished_at AS finishedAt
      FROM site_deployments AS deployment
      JOIN sites ON sites.id = deployment.site_id
      WHERE deployment.status = 'failed' AND deployment.started_at >= datetime('now', '-7 days')
      ORDER BY deployment.started_at DESC LIMIT 50
    `).all();
    const unhealthySiteRows = sites.filter((site) => site.enabled && (!site.running || site.healthStatus === 'unhealthy')).map((site) => ({
      id: site.id, name: site.name, runtimeType: site.runtime_type, running: site.running, healthStatus: site.healthStatus || (site.running ? 'starting' : 'stopped')
    }));
    const performance = performanceMonitor.payload();
    const alertRows = (performance.alerts || []).slice(0, 50);
    const automatedTrafficRows = clientTypes.filter((row) => ['llm', 'search', 'crawler'].includes(row.type));
    res.json({
      totals: { ...totals, running: manager.running.size }, sites, daily, countries, visitors, clientTypes,
      attention: { unhealthySites: unhealthySiteRows.length, failedDeployments: failedDeploymentRows.length, activeAlerts: alertRows.length },
      attentionDetails: { unhealthySites: unhealthySiteRows, failedDeployments: failedDeploymentRows, activeAlerts: alertRows, automatedTraffic: automatedTrafficRows }
    });
  });

  app.get('/api/performance', requireAuth, async (req, res) => {
    try {
      if (bool(req.query.refresh, false)) await performanceMonitor.runSample();
      res.json(performanceMonitor.payload());
    } catch (error) {
      res.status(503).json({ error: `Performance sample failed: ${error.message}` });
    }
  });

  app.post('/api/performance/alerts/:id/acknowledge', requireAuth, (req, res) => {
    if (!performanceMonitor.acknowledge(Number(req.params.id))) return res.status(404).json({ error: 'Active alert not found.' });
    recordAudit(req.user.id, 'alert.acknowledge', { id: Number(req.params.id) });
    res.status(204).end();
  });


  app.get('/api/sites/:id/performance/history', requireAuth, (req, res) => {
    const site = getSiteOr404(req, res);
    if (!site) return;
    const limit = Math.min(Math.max(Number(req.query.limit) || 720, 1), 2016);
    const rows = db.prepare(`
      SELECT sampled_at AS sampledAt, cpu_percent AS cpuPercent, rss_bytes AS rssBytes,
        request_rate AS requestRate, error_rate AS errorRate, avg_response_ms AS averageResponseMs,
        p50_response_ms AS p50ResponseMs, p95_response_ms AS p95ResponseMs,
        connections, restarts
      FROM site_performance_samples
      WHERE site_id = ?
      ORDER BY id DESC
      LIMIT ?
    `).all(site.id, limit).reverse();
    res.json({ siteId: site.id, history: rows });
  });

  app.get('/api/sites/:id/alert-rules', requireAuth, (req, res) => {
    const site = getSiteOr404(req, res);
    if (!site) return;
    const rules = db.prepare(`
      SELECT id, kind, threshold, severity, enabled, created_at AS createdAt, updated_at AS updatedAt
      FROM alert_rules WHERE site_id = ? ORDER BY kind
    `).all(site.id).map((row) => ({ ...row, enabled: Boolean(row.enabled) }));
    res.json({ siteId: site.id, rules });
  });

  app.put('/api/sites/:id/alert-rules', requireAuth, requireAdmin, (req, res) => {
    const site = getSiteOr404(req, res);
    if (!site) return;
    const rows = Array.isArray(req.body?.rules) ? req.body.rules : [];
    if (rows.length > 20) return res.status(400).json({ error: 'A site can define at most 20 alert rules.' });
    const allowedKinds = new Set(['cpu_percent', 'error_percent', 'p95_response_ms', 'request_rate', 'memory_percent', 'traffic_multiplier']);
    const allowedSeverity = new Set(['warning', 'critical']);
    const normalized = [];
    const seenKinds = new Set();
    for (const row of rows) {
      const kind = String(row?.kind || '').trim();
      const threshold = Number(row?.threshold);
      const severity = String(row?.severity || 'warning').trim();
      if (!allowedKinds.has(kind)) return res.status(400).json({ error: `Unsupported alert rule: ${kind || 'empty kind'}.` });
      if (seenKinds.has(kind)) return res.status(400).json({ error: `Only one ${kind} alert rule can be configured per site.` });
      seenKinds.add(kind);
      if (!Number.isFinite(threshold) || threshold < 0) return res.status(400).json({ error: `Alert threshold for ${kind} must be a non-negative number.` });
      if (!allowedSeverity.has(severity)) return res.status(400).json({ error: `Alert severity for ${kind} must be warning or critical.` });
      const maximum = kind === 'p95_response_ms' ? 600000 : kind === 'request_rate' ? 1000000 : kind === 'traffic_multiplier' ? 1000 : 1000;
      if (threshold > maximum) return res.status(400).json({ error: `Alert threshold for ${kind} is too large.` });
      normalized.push({ kind, threshold, severity, enabled: row.enabled !== false });
    }
    const replace = db.transaction(() => {
      db.prepare('DELETE FROM alert_rules WHERE site_id = ?').run(site.id);
      const statement = db.prepare('INSERT INTO alert_rules (site_id, kind, threshold, severity, enabled, created_at, updated_at) VALUES (?, ?, ?, ?, ?, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP)');
      for (const row of normalized) statement.run(site.id, row.kind, row.threshold, row.severity, row.enabled ? 1 : 0);
    });
    replace();
    recordAudit(req.user.id, 'site.alert-rules.update', { siteId: site.id, rules: normalized.map(({ kind, threshold, severity, enabled }) => ({ kind, threshold, severity, enabled })) });
    res.json({ siteId: site.id, rules: normalized });
  });

  app.get('/api/runtime-logs', requireAuth, (req, res) => {
    const limit = Math.min(Math.max(Number(req.query.limit) || 200, 1), 2000);
    const siteId = Number(req.query.siteId);
    const rows = Number.isSafeInteger(siteId) && siteId > 0
      ? db.prepare('SELECT id, site_id AS siteId, level, message, context_json AS contextJson, created_at AS createdAt FROM runtime_logs WHERE site_id = ? ORDER BY id DESC LIMIT ?').all(siteId, limit)
      : db.prepare('SELECT id, site_id AS siteId, level, message, context_json AS contextJson, created_at AS createdAt FROM runtime_logs ORDER BY id DESC LIMIT ?').all(limit);
    res.json({ logs: rows.map((row) => ({ ...row, context: (() => { try { return JSON.parse(row.contextJson || 'null'); } catch { return null; } })(), contextJson: undefined })) });
  });

  app.get('/api/admin/logs/export', requireAuth, requireAdmin, (req, res) => {
    const format = req.query.format === 'json' ? 'json' : 'ndjson';
    const rows = db.prepare('SELECT id, site_id AS siteId, level, message, context_json AS contextJson, created_at AS createdAt FROM runtime_logs ORDER BY id DESC LIMIT 10000').all().map((row) => ({
      id: row.id, siteId: row.siteId, level: row.level, message: row.message,
      context: (() => { try { return JSON.parse(row.contextJson || 'null'); } catch { return null; } })(), createdAt: row.createdAt
    }));
    res.setHeader('Content-Disposition', `attachment; filename="sham-runtime-logs.${format === 'json' ? 'json' : 'ndjson'}"`);
    if (format === 'json') return res.type('application/json').send(JSON.stringify(rows, null, 2));
    res.type('application/x-ndjson').send(rows.map((row) => JSON.stringify(row)).join('\n') + '\n');
  });

  app.post('/api/sites', requireAuth, uploadSizeGuard, multipart(receiveWebsite), async (req, res) => {
    let destination = null;
    let createdId = null;
    try {
      const input = { ...req.body, port: req.body.port || nextAvailableSitePort() };
      const config = validateSiteInput(input);
      const source = config.runtime_type === 'proxy' ? 'proxy' : String(req.body.source || 'upload').toLowerCase();
      if (!['upload', 'git', 'image', 'proxy'].includes(source)) throw new Error('Deployment source must be upload, git, image, or proxy.');
      if (source === 'image' && !(config.runtime_type === 'container' && config.container_mode === 'image')) throw new Error('Docker image sources require the Container runtime with Existing OCI image mode.');
      if (source === 'git' && req.user.role !== 'admin') throw new Error('Git deployments require an administrator account.');
      if ((config.runtime_type === 'compose' || config.runtime_type === 'container' || config.runtime_isolation === 'docker' || config.anubis_enabled) && req.user.role !== 'admin') throw new Error('Docker-backed runtimes require an administrator account.');
      if (source === 'git' && !config.git_url) throw new Error('Choose a Git repository before deploying from Git.');
      checkPort(config.port);
      assertEdgeDomainAvailable(config);
      if (config.ssl_enabled && (!config.domain || !hasCertificate(config.domain))) {
        throw new Error('Issue a certificate before enabling SSL.');
      }
      config.slug = uniqueSlug(config.slug);
      const directoryName = `site-${crypto.randomUUID()}`;
      destination = path.join(SITES_DIR, directoryName);
      if (source === 'upload') {
        await installUploadAsync({
          ...uploadParts(req),
          destination,
          entryFile: requiredSiteFile(config),
          maxBytes: UPLOAD_LIMIT_BYTES
        });
      } else {
        await fs.promises.mkdir(destination, { recursive: false });
      }

      const result = db.prepare(`
        INSERT INTO sites (
          name, slug, directory_name, bind_host, port, runtime_type, runtime_preset, start_command, runtime_port_env, working_directory, proxy_target, proxy_host_header, proxy_timeout_ms,
          install_command, build_command, build_output_dir, entry_file, node_entry,
          install_dependencies, minify, obfuscate, obfuscation_risk_acknowledged,
          domain_only, spa_fallback, cache_seconds, headers_json, enabled, domain,
          ssl_enabled, cloudflare_enabled, firewall_enabled, firewall_json, compression,
          security_preset, csp, health_check_path, health_check_interval, health_check_type, health_check_command, health_check_status_min, health_check_status_max, restart_policy,
          max_restarts, memory_limit_mb, max_connections, edge_enabled, runtime_isolation,
          container_image, container_mode, container_port, dockerfile_path, compose_file, compose_service, buildpack_builder,
          readiness_type, readiness_path, readiness_command, readiness_status_min, readiness_status_max, startup_timeout_seconds, shutdown_grace_seconds, blue_green_drain_seconds, manifest_enabled, cloudflare_auto_sync,
          cpu_limit, pids_limit, outbound_network, anubis_enabled,
          anubis_preset, anubis_difficulty, anubis_policy, maintenance_enabled,
          maintenance_html, redirects_json, error_pages_json, cache_rules_json,
          release_mode, git_url, git_branch, preview_domain, created_by
        ) VALUES (
          @name, @slug, @directoryName, @bindHost, @port, @runtimeType, @runtimePreset, @startCommand, @runtimePortEnv, @workingDirectory, @proxyTarget, @proxyHostHeader, @proxyTimeoutMs,
          @installCommand, @buildCommand, @buildOutputDir, @entryFile, @nodeEntry,
          @installDependencies, @minify, @obfuscate, @obfuscationRiskAcknowledged,
          @domainOnly, @spaFallback, @cacheSeconds, @headersJson, 0, @domain,
          @sslEnabled, @cloudflareEnabled, @firewallEnabled, @firewallJson, @compression,
          @securityPreset, @csp, @healthCheckPath, @healthCheckInterval, @healthCheckType, @healthCheckCommand, @healthCheckStatusMin, @healthCheckStatusMax, @restartPolicy,
          @maxRestarts, @memoryLimitMb, @maxConnections, @edgeEnabled, @runtimeIsolation,
          @containerImage, @containerMode, @containerPort, @dockerfilePath, @composeFile, @composeService, @buildpackBuilder,
          @readinessType, @readinessPath, @readinessCommand, @readinessStatusMin, @readinessStatusMax, @startupTimeoutSeconds, @shutdownGraceSeconds, @blueGreenDrainSeconds, @manifestEnabled, @cloudflareAutoSync,
          @cpuLimit, @pidsLimit, @outboundNetwork, @anubisEnabled,
          @anubisPreset, @anubisDifficulty, @anubisPolicy, @maintenanceEnabled,
          @maintenanceHtml, @redirectsJson, @errorPagesJson, @cacheRulesJson,
          @releaseMode, @gitUrl, @gitBranch, @previewDomain, @createdBy
        )
      `).run({
        name: config.name,
        slug: config.slug,
        directoryName,
        bindHost: config.bind_host,
        port: config.port,
        runtimeType: config.runtime_type,
        runtimePreset: config.runtime_preset,
        startCommand: config.start_command,
        runtimePortEnv: config.runtime_port_env,
        workingDirectory: config.working_directory,
        proxyTarget: config.proxy_target,
        proxyHostHeader: config.proxy_host_header,
        proxyTimeoutMs: config.proxy_timeout_ms,
        installCommand: config.install_command,
        buildCommand: config.build_command,
        buildOutputDir: config.build_output_dir,
        entryFile: config.entry_file,
        nodeEntry: config.node_entry,
        installDependencies: Number(config.install_dependencies),
        minify: Number(config.minify),
        obfuscate: Number(config.obfuscate),
        obfuscationRiskAcknowledged: Number(config.obfuscation_risk_acknowledged),
        domainOnly: Number(config.domain_only),
        spaFallback: Number(config.spa_fallback),
        cacheSeconds: config.cache_seconds,
        headersJson: JSON.stringify(config.headers),
        domain: config.domain,
        sslEnabled: Number(config.ssl_enabled),
        cloudflareEnabled: Number(config.cloudflare_enabled),
        firewallEnabled: Number(config.firewall_enabled),
        firewallJson: JSON.stringify(config.firewall),
        compression: Number(config.compression),
        securityPreset: config.security_preset,
        csp: config.csp,
        healthCheckPath: config.health_check_path,
        healthCheckInterval: config.health_check_interval,
        healthCheckType: config.health_check_type,
        healthCheckCommand: config.health_check_command,
        healthCheckStatusMin: config.health_check_status_min,
        healthCheckStatusMax: config.health_check_status_max,
        restartPolicy: config.restart_policy,
        maxRestarts: config.max_restarts,
        memoryLimitMb: config.memory_limit_mb,
        maxConnections: config.max_connections,
        edgeEnabled: Number(config.edge_enabled),
        runtimeIsolation: config.runtime_isolation,
        containerImage: config.container_image,
        containerMode: config.container_mode,
        containerPort: config.container_port,
        dockerfilePath: config.dockerfile_path,
        composeFile: config.compose_file,
        composeService: config.compose_service,
        buildpackBuilder: config.buildpack_builder,
        readinessType: config.readiness_type,
        readinessPath: config.readiness_path,
        readinessCommand: config.readiness_command,
        readinessStatusMin: config.readiness_status_min,
        readinessStatusMax: config.readiness_status_max,
        startupTimeoutSeconds: config.startup_timeout_seconds,
        shutdownGraceSeconds: config.shutdown_grace_seconds,
        blueGreenDrainSeconds: config.blue_green_drain_seconds,
        manifestEnabled: Number(config.manifest_enabled),
        cloudflareAutoSync: Number(config.cloudflare_auto_sync),
        cpuLimit: config.cpu_limit,
        pidsLimit: config.pids_limit,
        outboundNetwork: Number(config.outbound_network),
        anubisEnabled: Number(config.anubis_enabled),
        anubisPreset: config.anubis_preset,
        anubisDifficulty: config.anubis_difficulty,
        anubisPolicy: config.anubis_policy,
        maintenanceEnabled: Number(config.maintenance_enabled),
        maintenanceHtml: config.maintenance_html,
        redirectsJson: JSON.stringify(config.redirects || []),
        errorPagesJson: JSON.stringify(config.error_pages || {}),
        cacheRulesJson: JSON.stringify(config.cache_rules || []),
        releaseMode: Number(config.release_mode),
        gitUrl: config.git_url,
        gitBranch: config.git_branch,
        previewDomain: config.preview_domain,
        createdBy: req.user.id
      });

      const id = Number(result.lastInsertRowid);
      createdId = id;
      let deployment = null;
      if (source === 'git') {
        deployment = await operationsManager.deployGit(manager.getSite(id), {
          url: config.git_url,
          branch: config.git_branch,
          installDependencies: config.install_dependencies,
          installCommand: config.install_command,
          buildCommand: config.build_command,
          buildOutputDir: config.build_output_dir,
          approveManifestChanges: bool(req.body.approveManifestChanges, false)
        });
      } else {
        const deploymentId = operationsManager.recordDeployment(id, {
          source: source === 'proxy' ? 'proxy-config' : source === 'image' ? 'image-config' : 'upload',
          status: 'running',
          detail: source === 'proxy' ? `Proxy target configured: ${config.proxy_target}` : source === 'image' ? `OCI image configured: ${config.container_image}` : 'Initial project upload installed.'
        });
        deployment = operationsManager.listDeployments(id).find((item) => item.id === deploymentId) || null;
      }

      let warning = deployment?.warning || null;
      if (config.enabled) {
        try {
          await manager.start(id);
          try {
            db.prepare('UPDATE sites SET enabled = 1, updated_at = CURRENT_TIMESTAMP WHERE id = ?').run(id);
          } catch (error) {
            await manager.stop(id);
            throw new Error(`The runtime started, but SHAM could not persist its enabled state: ${error.message}`);
          }
        } catch (error) {
          warning = `Site was deployed but could not be started: ${error.message}`;
        }
      }
      if (config.obfuscate) {
        const compatibilityWarning = await safeObfuscationWarning(manager.getSite(id));
        warning = [warning, compatibilityWarning].filter(Boolean).join(' ');
      }
      if (source === 'git') {
        try {
          const webhook = await operationsManager.configureProviderWebhook(manager.getSite(id), getSetting('git_webhook_base_url', ''));
          if (webhook) deployment = { ...deployment, webhook };
        } catch (error) {
          warning = [warning, `Git provider webhook setup failed: ${error.message}`].filter(Boolean).join(' ');
          manager.log(id, 'error', `Git provider webhook configuration failed: ${error.message}`);
        }
      }
      const deploymentRecordId = Number(source === 'git' ? deployment?.deploymentId : deployment?.id);
      if (warning && Number.isSafeInteger(deploymentRecordId) && deploymentRecordId > 0) {
        operationsManager.updateDeploymentStatus(deploymentRecordId, 'deployed-with-warning', warning);
      }
      edgeProxy.invalidateSiteCache();
      recordAudit(req.user.id, 'site.create', { id, name: config.name, port: config.port, runtime: config.runtime_type, source });
      res.status(201).json({ site: manager.decorate(manager.getSite(id)), deployment, warning });
    } catch (error) {
      if (createdId) {
        try { await manager.stop(createdId); } catch { /* Best-effort cleanup. */ }
        try { db.prepare('DELETE FROM sites WHERE id = ?').run(createdId); }
        catch (cleanupError) { manager.log(createdId, 'error', `Could not roll back failed site creation: ${cleanupError.message}`); }
        manager.forgetSite(createdId);
      }
      if (destination) {
        try { await fs.promises.rm(destination, { recursive: true, force: true }); }
        catch (cleanupError) { manager.log(createdId, 'error', `Could not remove failed site deployment: ${cleanupError.message}`); }
      }
      res.status(400).json({ error: error.message });
    }
  });

  app.put('/api/sites/:id', requireAuth, async (req, res) => {
    const site = getSiteOr404(req, res);
    if (!site) return;
    const wasRunning = manager.statusFor(site.id).running;
    try {
      const config = validateSiteInput(req.body, site);
      if ((config.runtime_type === 'compose' || config.runtime_type === 'container' || config.runtime_isolation === 'docker' || config.anubis_enabled) && req.user.role !== 'admin') {
        throw new Error('Docker-backed runtime settings require an administrator account.');
      }
      checkPort(config.port, site.id);
      assertEdgeDomainAvailable(config, site.id);
      assertTunnelOnlyBinding(config, site.id);
      config.slug = uniqueSlug(config.slug, site.id);
      const domainChanged = config.domain !== site.domain;
      if (domainChanged) config.cloudflare_enabled = false;
      if (config.ssl_enabled && (!config.domain || !hasCertificate(config.domain))) {
        throw new Error('Issue a certificate before enabling SSL.');
      }
      const required = requiredSiteFile(config);
      if (required) {
        const root = siteRoot(site);
        const entryPath = path.join(root, ...required.split('/'));
        if (!realFileInside(root, entryPath)) {
          throw new Error(`Required file “${required}” does not exist in this website.`);
        }
      }

      writeSiteConfig(site.id, config);
      try {
        if (wasRunning) await manager.restart(site.id);
        else if (site.enabled) await manager.start(site.id);
      } catch (restartError) {
        writeSiteConfig(site.id, site);
        await manager.stop(site.id);
        let rollbackError = null;
        if (wasRunning || site.enabled) {
          try { await manager.start(site); } catch (error) { rollbackError = error; }
        }
        const suffix = rollbackError ? ` The previous runtime also failed to recover: ${rollbackError.message}` : '';
        throw new Error(`The new settings could not be applied and were rolled back: ${restartError.message}.${suffix}`);
      }

      edgeProxy.invalidateSiteCache();
      recordAudit(req.user.id, 'site.update', { id: site.id });
      const updated = manager.getSite(site.id);
      const warnings = [];
      if (domainChanged && site.cloudflare_enabled) {
        warnings.push('The domain changed, so SHAM marked Cloudflare DNS as unsynchronized. Sync the new hostname and remove any obsolete external DNS record if it is no longer needed.');
      }
      const portWarning = updated.cloudflare_enabled ? cloudflarePortWarning(updated) : null;
      if (portWarning) warnings.push(portWarning);
      if (updated.obfuscate && !site.obfuscate) warnings.push(await safeObfuscationWarning(updated));
      res.json({ site: manager.decorate(updated), warning: warnings.join(' ') || null });
    } catch (error) {
      res.status(400).json({ error: error.message });
    }
  });

  async function setSiteEnabled(site, enabled) {
    const wasRunning = manager.statusFor(site.id).running;
    if (enabled) {
      if (!wasRunning) await manager.start(site.id);
      try {
        db.prepare('UPDATE sites SET enabled = 1, updated_at = CURRENT_TIMESTAMP WHERE id = ?').run(site.id);
      } catch (error) {
        if (!wasRunning) {
          try { await manager.stop(site.id); } catch { /* Preserve the persistence error. */ }
        }
        throw new Error(`The site ${wasRunning ? 'was already running' : 'started'}, but SHAM could not persist its enabled state: ${error.message}`);
      }
    } else {
      if (wasRunning) await manager.stop(site.id);
      try {
        db.prepare('UPDATE sites SET enabled = 0, updated_at = CURRENT_TIMESTAMP WHERE id = ?').run(site.id);
      } catch (error) {
        if (wasRunning) {
          try { await manager.start(site); }
          catch (restoreError) { throw new Error(`SHAM could not persist the stopped state, and the site could not be restored: ${error.message}; ${restoreError.message}`); }
        }
        throw new Error(`The site ${wasRunning ? 'was stopped' : 'was already stopped'}, but SHAM could not persist its disabled state: ${error.message}`);
      }
    }
    edgeProxy.invalidateSiteCache();
    return manager.decorate(manager.getSite(site.id));
  }

  async function respondWithSiteState(req, res, site, enabled) {
    try {
      const updated = await setSiteEnabled(site, enabled);
      recordAudit(req.user.id, enabled ? 'site.start' : 'site.stop', { id: site.id });
      res.json({ site: updated });
    } catch (error) {
      res.status(409).json({ error: error.message, site: manager.decorate(manager.getSite(site.id)) });
    }
  }

  app.patch('/api/sites/:id/toggle', requireAuth, async (req, res) => {
    const site = getSiteOr404(req, res);
    if (!site) return;
    await respondWithSiteState(req, res, site, bool(req.body.enabled, !site.enabled));
  });

  app.post('/api/sites/:id/start', requireAuth, async (req, res) => {
    const site = getSiteOr404(req, res);
    if (!site) return;
    await respondWithSiteState(req, res, site, true);
  });

  app.post('/api/sites/:id/stop', requireAuth, async (req, res) => {
    const site = getSiteOr404(req, res);
    if (!site) return;
    await respondWithSiteState(req, res, site, false);
  });

  app.post('/api/sites/:id/restart', requireAuth, async (req, res) => {
    const site = getSiteOr404(req, res);
    if (!site) return;
    const wasRunning = manager.statusFor(site.id).running;
    try {
      await manager.restart(site.id);
      try {
        db.prepare('UPDATE sites SET enabled = 1, updated_at = CURRENT_TIMESTAMP WHERE id = ?').run(site.id);
      } catch (error) {
        if (!wasRunning) await manager.stop(site.id);
        throw new Error(`The site restarted, but SHAM could not persist its enabled state: ${error.message}`);
      }
      recordAudit(req.user.id, 'site.restart', { id: site.id });
      res.json({ site: manager.decorate(manager.getSite(site.id)) });
    } catch (error) {
      res.status(409).json({ error: error.message, site: manager.decorate(manager.getSite(site.id)) });
    }
  });

  app.post('/api/sites/:id/npm-install', requireAuth, async (req, res) => {
    const site = getSiteOr404(req, res);
    if (!site) return;
    const wasRunning = manager.statusFor(site.id).running;
    let rollbackSnapshot;
    try {
      const npmLikeHostRuntime = (site.runtime_type === 'node' && site.runtime_isolation !== 'docker')
        || (site.runtime_type === 'process' && ['node', 'npm'].includes(site.runtime_preset));
      if (!npmLikeHostRuntime) throw new Error('Host npm install is only available for host-based Node/npm runtimes. Container runtimes install dependencies during their image build.');
      rollbackSnapshot = await snapshotManager.create(site, 'Automatic pre-npm-install rollback');
      if (wasRunning) await manager.stop(site.id);
      try {
        await manager.runInstall(site);
      } catch (error) {
        if (wasRunning && !manager.statusFor(site.id).running) {
          try { await manager.start(site.id); } catch { /* Preserve the install error. */ }
        }
        throw error;
      }

      let warning = null;
      if (wasRunning || site.enabled) {
        try { await manager.start(site.id); }
        catch (error) {
          warning = `Dependencies were installed, but the site could not restart: ${error.message}`;
          manager.log(site.id, 'error', warning);
        }
      }
      recordAudit(req.user.id, 'site.npm.install', { id: site.id, restartWarning: Boolean(warning) });
      res.json({ site: manager.decorate(manager.getSite(site.id)), message: 'npm install completed.', warning, rollbackSnapshot });
    } catch (error) {
      res.status(400).json({ error: error.message });
    }
  });

  app.put('/api/sites/:id/content', requireAuth, uploadSizeGuard, multipart(receiveWebsite), async (req, res) => {
    const site = getSiteOr404(req, res);
    if (!site) return;
    if (site.runtime_type === 'proxy') return res.status(400).json({ error: 'Reverse-proxy sites do not have deployable project files.' });
    const wasRunning = manager.statusFor(site.id).running;
    let rollbackSnapshot;
    try {
      rollbackSnapshot = await snapshotManager.create(site, 'Automatic pre-content-replacement rollback');
      if (wasRunning) await manager.stop(site.id);
      await installUploadAsync({
        ...uploadParts(req),
        destination: siteRoot(site),
        entryFile: requiredSiteFile(site),
        maxBytes: UPLOAD_LIMIT_BYTES
      });
      let warning = null;
      if (wasRunning || site.enabled) {
        try { await manager.start(site.id); }
        catch (error) {
          warning = `Content was replaced, but the site could not restart: ${error.message}`;
          manager.log(site.id, 'error', warning);
        }
      }
      if (site.obfuscate) {
        const compatibilityWarning = await safeObfuscationWarning(manager.getSite(site.id));
        warning = [warning, compatibilityWarning].filter(Boolean).join(' ');
      }
      recordAudit(req.user.id, 'site.content.replace', { id: site.id });
      try {
        operationsManager.recordDeployment(site.id, { source: 'upload', status: warning ? 'deployed-with-warning' : 'running', detail: warning || 'Project files replaced.' });
      } catch (historyError) {
        const historyWarning = `Content is deployed, but SHAM could not record deployment history: ${historyError.message}`;
        warning = [warning, historyWarning].filter(Boolean).join(' ');
        manager.log(site.id, 'error', historyWarning);
      }
      res.json({ site: manager.decorate(manager.getSite(site.id)), warning, rollbackSnapshot });
    } catch (error) {
      if (wasRunning && !manager.statusFor(site.id).running) {
        try { await manager.start(site.id); } catch { /* Original error is more useful. */ }
      }
      res.status(400).json({ error: error.message });
    }
  });

  app.get('/api/sites/:id/obfuscation-report', requireAuth, async (req, res) => {
    const site = getSiteOr404(req, res);
    if (!site) return;
    try { res.json({ report: await auditObfuscationCompatibility(site) }); }
    catch (error) { res.status(400).json({ error: error.message }); }
  });

  app.get('/api/sites/:id/files', requireAuth, async (req, res) => {
    const site = getSiteOr404(req, res);
    if (!site) return;
    try { res.json({ files: await listSiteFilesAsync(site) }); }
    catch (error) { res.status(400).json({ error: error.message }); }
  });

  app.get('/api/sites/:id/files/content', requireAuth, async (req, res) => {
    const site = getSiteOr404(req, res);
    if (!site) return;
    try { res.json(await readTextFileAsync(site, req.query.path)); }
    catch (error) { res.status(400).json({ error: error.message }); }
  });

  app.put('/api/sites/:id/files/content', requireAuth, async (req, res) => {
    const site = getSiteOr404(req, res);
    if (!site) return;
    try {
      const result = await writeTextFileAsync(site, req.body.path, req.body.content);
      recordAudit(req.user.id, 'site.file.write', { id: site.id, path: result.path, size: result.size });
      res.json({ file: result, restartRecommended: ['node', 'process', 'container', 'compose'].includes(site.runtime_type) && manager.statusFor(site.id).running });
    } catch (error) { res.status(400).json({ error: error.message }); }
  });

  app.put('/api/sites/:id/files/upload', requireAuth, uploadSizeGuard, multipart(receiveSingleFile), async (req, res) => {
    const site = getSiteOr404(req, res);
    if (!site) return;
    try {
      if (!req.file) throw new Error('Choose one file to upload.');
      const destination = req.body.path || req.file.originalname;
      const result = await replaceSingleFileFromPathAsync(site, destination, req.file.path, req.file.size);
      recordAudit(req.user.id, 'site.file.replace', { id: site.id, path: result.path, size: result.size });
      res.json({ file: result, restartRecommended: ['node', 'process', 'container', 'compose'].includes(site.runtime_type) && manager.statusFor(site.id).running });
    } catch (error) { res.status(400).json({ error: error.message }); }
  });

  app.delete('/api/sites/:id/files', requireAuth, async (req, res) => {
    const site = getSiteOr404(req, res);
    if (!site) return;
    const wasRunning = manager.statusFor(site.id).running;
    let stagedDeletion = null;
    let rollbackSnapshot = null;
    try {
      const relative = safeRelativePath(req.query.path, 'File path');
      const critical = relative === requiredSiteFile(site);
      if (critical) rollbackSnapshot = await snapshotManager.create(site, 'Automatic pre-entry-file-deletion rollback');
      if (critical && wasRunning) await manager.stop(site.id);
      if (critical) {
        stagedDeletion = await stageSingleFileDeletionAsync(site, relative);
        try {
          db.prepare('UPDATE sites SET enabled = 0, updated_at = CURRENT_TIMESTAMP WHERE id = ?').run(site.id);
        } catch (error) {
          await stagedDeletion.rollback();
          stagedDeletion = null;
          throw new Error(`The file was preserved because SHAM could not persist the disabled state: ${error.message}`);
        }
        await stagedDeletion.commit();
        stagedDeletion = null;
      } else {
        await deleteSingleFileAsync(site, relative);
      }
      recordAudit(req.user.id, 'site.file.delete', { id: site.id, path: relative, critical });
      res.json({ deleted: relative, warning: critical ? 'The required runtime file was deleted, so the site was stopped and disabled. An automatic rollback snapshot was retained.' : null, rollbackSnapshot });
    } catch (error) {
      if (stagedDeletion) {
        try { await stagedDeletion.rollback(); } catch (rollbackError) { manager.log(site.id, 'error', `Could not restore the staged file deletion: ${rollbackError.message}`); }
      }
      if (wasRunning && site.enabled && !manager.statusFor(site.id).running) {
        try { await manager.start(site.id); } catch { /* Preserve the original file error. */ }
      }
      res.status(400).json({ error: error.message });
    }
  });

  app.delete('/api/sites/:id', requireAuth, async (req, res) => {
    const site = getSiteOr404(req, res);
    if (!site) return;
    const wasRunning = manager.statusFor(site.id).running;
    const tunnelWasEnabled = cloudflareTunnels.status(site.id).enabled;
    const root = legacySiteRoot(site);
    const releaseRoot = path.join(RELEASES_DIR, String(site.id));
    const trash = `${root}.delete-${crypto.randomUUID()}`;
    const releaseTrash = `${releaseRoot}.delete-${crypto.randomUUID()}`;
    let filesStaged = false;
    let releasesStaged = false;
    try {
      await manager.stop(site.id);
      await cloudflareTunnels.stop(site.id);
      manager.flushStats();
      manager.flushRuntimeLogs();
      try {
        await fs.promises.rename(root, trash);
        filesStaged = true;
      } catch (error) {
        if (error.code !== 'ENOENT') throw error;
      }
      try {
        await fs.promises.rename(releaseRoot, releaseTrash);
        releasesStaged = true;
      } catch (error) {
        if (error.code !== 'ENOENT') throw error;
      }
      db.prepare('DELETE FROM sites WHERE id = ?').run(site.id);
      manager.forgetSite(site.id);
      edgeProxy.invalidateSiteCache();
      if (filesStaged) {
        fs.rm(trash, { recursive: true, force: true }, (cleanupError) => {
          if (cleanupError) manager.log(null, 'error', `Could not remove deleted site data for ${site.name}: ${cleanupError.message}`, { deletedSiteId: site.id });
        });
      }
      if (releasesStaged) {
        fs.rm(releaseTrash, { recursive: true, force: true }, (cleanupError) => {
          if (cleanupError) manager.log(null, 'error', `Could not remove deleted release data for ${site.name}: ${cleanupError.message}`, { deletedSiteId: site.id });
        });
      }
      recordAudit(req.user.id, 'site.delete', { id: site.id, name: site.name });
      res.status(204).end();
    } catch (error) {
      if (releasesStaged) {
        try { await fs.promises.rename(releaseTrash, releaseRoot); }
        catch (restoreError) { manager.log(site.id, 'error', `Could not restore release files after a failed deletion: ${restoreError.message}`); }
      }
      if (filesStaged) {
        try { await fs.promises.rename(trash, root); }
        catch (restoreError) { manager.log(site.id, 'error', `Could not restore site files after a failed deletion: ${restoreError.message}`); }
      }
      if (wasRunning && !manager.statusFor(site.id).running && manager.getSite(site.id)) {
        try { await manager.start(site); }
        catch (restoreError) { manager.log(site.id, 'error', `Could not restore site runtime after a failed deletion: ${restoreError.message}`); }
      }
      if (tunnelWasEnabled && manager.getSite(site.id)) {
        try { await cloudflareTunnels.start(site.id); }
        catch (restoreError) { manager.log(site.id, 'error', `Could not restore the site's Cloudflare Tunnel after a failed deletion: ${restoreError.message}`); }
      }
      res.status(500).json({ error: error.message });
    }
  });

  app.get('/api/sites/:id/dependency-scan', requireAuth, (req, res) => {
    const site = getSiteOr404(req, res);
    if (!site) return;
    res.json({ result: dependencyScanner.latest(site.id) });
  });

  app.post('/api/sites/:id/dependency-scan', requireAuth, async (req, res) => {
    const site = getSiteOr404(req, res);
    if (!site) return;
    try {
      if (site.runtime_type === 'proxy') throw new Error('Dependency scanning requires a local project directory.');
      const result = await dependencyScanner.scan(site);
      recordAudit(req.user.id, 'site.dependencies.scan', { id: site.id, vulnerabilities: result.vulnerabilities?.total || 0 });
      res.json({ result });
    } catch (error) { res.status(400).json({ error: error.message }); }
  });

  app.get('/api/sites/:id/snapshots', requireAuth, (req, res) => {
    const site = getSiteOr404(req, res);
    if (!site) return;
    res.json({ snapshots: snapshotManager.list(site.id) });
  });

  app.post('/api/sites/:id/snapshots', requireAuth, async (req, res) => {
    const site = getSiteOr404(req, res);
    if (!site) return;
    try {
      const snapshot = await snapshotManager.create(site, snapshotLabel(req.body.label, 'Manual snapshot'));
      recordAudit(req.user.id, 'site.snapshot.create', { id: site.id, snapshotId: snapshot.id });
      res.status(201).json({ snapshot });
    } catch (error) { res.status(400).json({ error: error.message }); }
  });

  app.post('/api/sites/:id/snapshots/:snapshotId/restore', requireAuth, async (req, res) => {
    const site = getSiteOr404(req, res);
    if (!site) return;
    const wasRunning = manager.statusFor(site.id).running;
    let rollbackSnapshot;
    try {
      rollbackSnapshot = await snapshotManager.create(site, 'Automatic pre-restore rollback');
      if (wasRunning) await manager.stop(site.id);
      const restoreResult = await snapshotManager.restore(site, Number(req.params.snapshotId));
      if (wasRunning || site.enabled) await manager.start(site.id);
      manager.invalidateSiteCache?.(site.id);
      recordAudit(req.user.id, 'site.snapshot.restore', { id: site.id, snapshotId: Number(req.params.snapshotId), rollbackSnapshotId: rollbackSnapshot.id });
      res.json({ site: manager.decorate(manager.getSite(site.id)), rollbackSnapshot, warning: restoreResult?.warning || null });
    } catch (error) {
      let rollbackError = null;
      if (rollbackSnapshot) {
        try {
          await manager.stop(site.id);
          await snapshotManager.restore(site, rollbackSnapshot.id);
          if (wasRunning || site.enabled) await manager.start(site.id);
        } catch (restoreError) { rollbackError = restoreError; }
      }
      const suffix = rollbackError ? ` Automatic rollback also failed: ${rollbackError.message}` : '';
      res.status(409).json({ error: `${error.message}${suffix}` });
    }
  });

  app.delete('/api/sites/:id/snapshots/:snapshotId', requireAuth, async (req, res) => {
    const site = getSiteOr404(req, res);
    if (!site) return;
    try {
      await snapshotManager.delete(site.id, Number(req.params.snapshotId));
      recordAudit(req.user.id, 'site.snapshot.delete', { id: site.id, snapshotId: Number(req.params.snapshotId) });
      res.status(204).end();
    } catch (error) { res.status(400).json({ error: error.message }); }
  });
  }

module.exports = { registerSiteRoutes };
