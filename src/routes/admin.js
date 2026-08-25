'use strict';

const { validateManifest } = require('../plugin-manager');

function registerAdminRoutes(ctx) {
  const {
    app, requireAuth, requireAdmin, pluginManager, publicUser, multipart, pluginUpload, validatePluginArchiveFile,
    bool, integrationSettings, securitySettings, oidcSettings, normalizeOidcIssuer, normalizeUsername, getSetting, setSetting,
    setSecretSetting, getSecretSetting, rotateMasterKey, verifyPassword, hashPassword, rotateSessionVersion, stepUpLimiter, writeCloudflareCredentials, recordAudit,
    manager, getSiteOr404, syncCloudflareRecord, cloudflarePortWarning, syncCloudflareFirewall,
    acquireCertificateOperation, releaseCertificateOperation, stopRunningSitesOnPort, renewalNeedsPort80, issueCertificate,
    restoreEnabledSites, renewCertificates, db, activeAdminCount, registrationEnabled, integerSetting,
    net, crypto, edgeProxy, EDGE_HTTP_PORT, DASHBOARD_PORT
  } = ctx;

app.get('/api/plugins', requireAuth, (req, res) => res.json({
    plugins: pluginManager.list()
  }));


  app.post('/api/admin/plugins/playground/validate', requireAuth, requireAdmin, (req, res) => {
    try {
      const raw = req.body?.manifest;
      let manifest = raw;
      if (typeof raw === 'string') {
        if (Buffer.byteLength(raw, 'utf8') > 128 * 1024) throw new Error('Playground manifest may not exceed 128 KB.');
        try { manifest = JSON.parse(raw); } catch { throw new Error('Playground manifest must be valid JSON.'); }
      } else {
        let serialized = '';
        try { serialized = JSON.stringify(raw); } catch { throw new Error('Playground manifest must be valid JSON data.'); }
        if (Buffer.byteLength(serialized || '', 'utf8') > 128 * 1024) throw new Error('Playground manifest may not exceed 128 KB.');
      }
      const normalized = validateManifest(manifest);
      res.json({ valid: true, manifest: normalized });
    } catch (error) { res.status(400).json({ valid: false, error: error.message }); }
  });

  app.get('/api/plugins/:id/client.js', requireAuth, async (req, res) => {
    try {
      res.type('application/javascript').send(await pluginManager.clientScript(req.params.id));
    } catch (error) { res.status(404).type('application/javascript').send(`console.error(${JSON.stringify(error.message)});`); }
  });

  app.all('/api/plugins/:id/actions/:action', requireAuth, async (req, res) => {
    try {
      const result = await pluginManager.handleApi(req.params.id, req.params.action, {
        body: req.body,
        query: req.query,
        user: publicUser(req.user),
        method: req.method
      });
      if (result && typeof result === 'object' && Number.isInteger(result.status) && Object.hasOwn(result, 'body')) {
        return res.status(result.status).json(result.body);
      }
      res.json(result ?? { ok: true });
    } catch (error) { res.status(400).json({ error: error.message }); }
  });

  app.post('/api/admin/plugins', requireAuth, requireAdmin, multipart(pluginUpload.single('plugin')), async (req, res) => {
    try {
      if (!req.file) throw new Error('Choose a plugin ZIP archive.');
      await validatePluginArchiveFile(req.file.path, req.file.originalname);
      const plugin = await pluginManager.installAsync(req.file.path, { allowUnsigned: bool(req.body.allowUnsigned, false) });
      recordAudit(req.user.id, 'plugin.install', { id: plugin.id, type: plugin.type });
      res.status(201).json({ plugin });
    } catch (error) { res.status(400).json({ error: error.message }); }
  });

  app.patch('/api/admin/plugins/:id/toggle', requireAuth, requireAdmin, async (req, res) => {
    try {
      const plugin = await pluginManager.toggle(req.params.id, bool(req.body.enabled, false));
      recordAudit(req.user.id, 'plugin.toggle', { id: plugin.id, enabled: plugin.enabled });
      res.json({ plugin });
    } catch (error) { res.status(400).json({ error: error.message }); }
  });

  app.put('/api/admin/plugins/:id/settings', requireAuth, requireAdmin, (req, res) => {
    try {
      pluginManager.setSettings(req.params.id, req.body.settings || {}, { clearSecrets: req.body.clearSecrets || [] });
      const plugin = pluginManager.list().find((item) => item.id === req.params.id);
      recordAudit(req.user.id, 'plugin.settings', { id: req.params.id });
      res.json({ settings: plugin?.settings || {}, secretConfigured: plugin?.secretConfigured || {} });
    } catch (error) { res.status(400).json({ error: error.message }); }
  });

  app.delete('/api/admin/plugins/:id', requireAuth, requireAdmin, async (req, res) => {
    try {
      await pluginManager.delete(req.params.id);
      recordAudit(req.user.id, 'plugin.delete', { id: req.params.id });
      res.status(204).end();
    } catch (error) { res.status(400).json({ error: error.message }); }
  });

  app.get('/api/admin/settings', requireAuth, requireAdmin, (_req, res) => {
    res.json({ registrationEnabled: registrationEnabled(), integrations: integrationSettings(), security: securitySettings(), oidc: oidcSettings() });
  });

  app.put('/api/admin/settings/security', requireAuth, requireAdmin, (req, res) => {
    try {
      const privacy = String(req.body.visitorPrivacyMode || 'mask');
      if (!['none', 'mask', 'hash'].includes(privacy)) throw new Error('Visitor privacy mode is invalid.');
      let trustedKeys = req.body.pluginTrustedKeys;
      if (typeof trustedKeys === 'string') {
        try { trustedKeys = JSON.parse(trustedKeys || '[]'); } catch { throw new Error('Trusted plugin keys must be valid JSON.'); }
      }
      if (!Array.isArray(trustedKeys) || trustedKeys.length > 100) throw new Error('Trusted plugin keys must be a JSON array with at most 100 entries.');
      for (const entry of trustedKeys) {
        if (!entry || typeof entry !== 'object' || !String(entry.id || '').trim() || !String(entry.publicKey || '').includes('PUBLIC KEY')) throw new Error('Each trusted key needs an id and a PEM publicKey.');
        try { crypto.createPublicKey(String(entry.publicKey)); } catch { throw new Error(`Trusted key “${String(entry.id)}” is not a valid public key.`); }
      }
      const values = {
        allow_unsigned_plugins: bool(req.body.allowUnsignedPlugins, false) ? '1' : '0',
        plugin_trusted_keys_json: JSON.stringify(trustedKeys),
        log_retention_days: String(integerSetting(req.body.logRetentionDays, 'Log retention', 1, 3650)),
        visitor_privacy_mode: privacy,
        alert_cpu_percent: String(integerSetting(req.body.alertCpuPercent, 'CPU alert threshold', 10, 1000)),
        alert_event_loop_ms: String(integerSetting(req.body.alertEventLoopMs, 'Event-loop alert threshold', 10, 10000)),
        alert_disk_percent: String(integerSetting(req.body.alertDiskPercent, 'Disk alert threshold', 10, 100)),
        alert_traffic_multiplier: String(Number(req.body.alertTrafficMultiplier) >= 2 && Number(req.body.alertTrafficMultiplier) <= 100 ? Number(req.body.alertTrafficMultiplier) : (() => { throw new Error('Traffic spike multiplier must be between 2 and 100.'); })()),
        alert_error_percent: String(integerSetting(req.body.alertErrorPercent, 'Error-rate alert threshold', 1, 100))
      };
      db.transaction(() => { for (const [key, value] of Object.entries(values)) setSetting(key, value); })();
      manager.setPrivacyMode(privacy);
      recordAudit(req.user.id, 'settings.security');
      res.json({ security: securitySettings() });
    } catch (error) { res.status(400).json({ error: error.message }); }
  });

  app.post('/api/admin/security/rotate-master-key', requireAuth, requireAdmin, stepUpLimiter, async (req, res) => {
    try {
      const user = db.prepare('SELECT * FROM users WHERE id = ?').get(req.user.id);
      if (!(await verifyPassword(String(req.body.password || ''), user.password_salt, user.password_hash))) return res.status(401).json({ error: 'Password confirmation failed.' });
      const result = rotateMasterKey(db);
      writeCloudflareCredentials(getSecretSetting(db, 'cloudflare_api_token', ''));
      recordAudit(req.user.id, 'security.master-key.rotate');
      res.json(result);
    } catch (error) { res.status(400).json({ error: error.message }); }
  });

  app.put('/api/admin/settings/oidc', requireAuth, requireAdmin, (req, res) => {
    try {
      const enabled = bool(req.body.enabled, false);
      const issuer = String(req.body.issuer || '').trim();
      const clientId = String(req.body.clientId || '').trim();
      if (issuer.length > 2000 || /[\r\n\0]/.test(issuer)) throw new Error('OIDC issuer URL is invalid or too long.');
      if (!clientId || clientId.length > 500 || /[\r\n\0]/.test(clientId)) {
        if (enabled || clientId) throw new Error('OIDC client ID is invalid or too long.');
      }
      const autoProvision = bool(req.body.autoProvision, false);
      const defaultRole = String(req.body.defaultRole || 'user') === 'admin' ? 'admin' : 'user';
      const normalizedIssuer = issuer ? normalizeOidcIssuer(issuer) : '';
      if (enabled && (!normalizedIssuer || !clientId)) throw new Error('OIDC issuer and client ID are required when SSO is enabled.');
      let clientSecret = getSecretSetting(db, 'oidc_client_secret', '');
      if (typeof req.body.clientSecret === 'string' && req.body.clientSecret.trim()) {
        const suppliedSecret = req.body.clientSecret.trim();
        if (suppliedSecret.length > 8192 || /[\r\n\0]/.test(suppliedSecret)) throw new Error('OIDC client secret is invalid or too long.');
        clientSecret = suppliedSecret;
      }
      if (bool(req.body.clearClientSecret, false)) clientSecret = '';
      db.transaction(() => {
        setSetting('oidc_enabled', enabled ? '1' : '0');
        setSetting('oidc_issuer', normalizedIssuer);
        setSetting('oidc_client_id', clientId);
        setSetting('oidc_auto_provision', autoProvision ? '1' : '0');
        setSetting('oidc_default_role', defaultRole);
        setSecretSetting(db, 'oidc_client_secret', clientSecret);
      })();
      recordAudit(req.user.id, 'settings.oidc', { enabled, issuer: normalizedIssuer, autoProvision, defaultRole, secretConfigured: Boolean(clientSecret) });
      res.json({ oidc: oidcSettings() });
    } catch (error) { res.status(400).json({ error: error.message }); }
  });

  app.patch('/api/admin/settings/registration', requireAuth, requireAdmin, (_req, res) => {
    res.status(410).json({ error: 'Public registration cannot be enabled. Create dashboard users from Administration instead.' });
  });

  app.put('/api/admin/settings/integrations', requireAuth, requireAdmin, (req, res) => {
    try {
      const zoneId = String(req.body.cloudflareZoneId || '').trim();
      const tunnelAccountId = String(req.body.cloudflareTunnelAccountId || '').trim().toLowerCase();
      const targetIp = String(req.body.cloudflareTargetIp || '').trim();
      const email = String(req.body.certbotEmail || '').trim();
      const cloudflareReconcileEnabled = bool(req.body.cloudflareReconcileEnabled, false);
      const cloudflareReconcileMinutes = Number(req.body.cloudflareReconcileMinutes || 15);
      if (!Number.isInteger(cloudflareReconcileMinutes) || cloudflareReconcileMinutes < 1 || cloudflareReconcileMinutes > 1440) throw new Error('Cloudflare reconciliation interval must be between 1 and 1440 minutes.');
      if (zoneId && !/^[a-fA-F0-9]{32}$/.test(zoneId)) throw new Error('Cloudflare zone ID must be a 32-character hexadecimal ID.');
      if (tunnelAccountId && !/^[a-f0-9]{32}$/.test(tunnelAccountId)) throw new Error('Cloudflare Tunnel account ID must be a 32-character hexadecimal ID.');
      if (targetIp && net.isIP(targetIp) !== 4) throw new Error('Cloudflare origin must be a valid IPv4 address for the A record.');
      if (email && !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) throw new Error('Certbot email address is not valid.');
      let cloudflareToken = getSecretSetting(db, 'cloudflare_api_token', '');
      if (req.body.cloudflareApiToken) cloudflareToken = String(req.body.cloudflareApiToken).trim();
      if (bool(req.body.clearCloudflareToken, false)) cloudflareToken = '';
      let tunnelApiToken = getSecretSetting(db, 'cloudflare_tunnel_api_token', '');
      if (req.body.cloudflareTunnelApiToken) tunnelApiToken = String(req.body.cloudflareTunnelApiToken).trim();
      if (bool(req.body.clearCloudflareTunnelApiToken, false)) tunnelApiToken = '';
      if (tunnelApiToken && (tunnelApiToken.length > 16 * 1024 || /[\s\0]/.test(tunnelApiToken))) throw new Error('Cloudflare Tunnel management API token must be a single value no longer than 16 KiB.');
      const previousToken = getSecretSetting(db, 'cloudflare_api_token', '');
      writeCloudflareCredentials(cloudflareToken);
      try {
        db.transaction(() => {
          setSecretSetting(db, 'cloudflare_api_token', cloudflareToken);
          setSecretSetting(db, 'cloudflare_tunnel_api_token', tunnelApiToken);
          setSetting('cloudflare_zone_id', zoneId);
          setSetting('cloudflare_tunnel_account_id', tunnelAccountId);
          setSetting('cloudflare_target_ip', targetIp);
          setSetting('certbot_email', email);
          setSetting('cloudflare_reconcile_enabled', cloudflareReconcileEnabled ? '1' : '0');
          setSetting('cloudflare_reconcile_minutes', String(cloudflareReconcileMinutes));
        })();
      } catch (error) {
        try { writeCloudflareCredentials(previousToken); }
        catch (restoreError) { manager.log(null, 'error', `Could not restore Certbot credentials after a settings failure: ${restoreError.message}`); }
        throw error;
      }
      recordAudit(req.user.id, 'settings.integrations');
      res.json({ integrations: integrationSettings() });
    } catch (error) { res.status(400).json({ error: error.message }); }
  });

  app.post('/api/admin/sites/:id/cloudflare', requireAuth, requireAdmin, async (req, res) => {
    const site = getSiteOr404(req, res);
    if (!site) return;
    try {
      if (!site.domain) throw new Error('Configure a domain for this site first.');
      const record = await syncCloudflareRecord({
        token: getSecretSetting(db, 'cloudflare_api_token', ''),
        zoneId: getSetting('cloudflare_zone_id', ''),
        targetIp: getSetting('cloudflare_target_ip', ''),
        domain: site.domain,
        proxied: true
      });
      db.prepare('UPDATE sites SET cloudflare_enabled = 1, updated_at = CURRENT_TIMESTAMP WHERE id = ?').run(site.id);
      recordAudit(req.user.id, 'site.cloudflare.sync', { id: site.id, domain: site.domain, recordId: record.id });
      res.json({
        site: manager.decorate(manager.getSite(site.id)),
        record: { id: record.id, name: record.name, content: record.content, proxied: record.proxied },
        warning: cloudflarePortWarning(site)
      });
    } catch (error) { res.status(400).json({ error: error.message }); }
  });

  app.post('/api/admin/sites/:id/cloudflare-firewall', requireAuth, requireAdmin, async (req, res) => {
    const site = getSiteOr404(req, res);
    if (!site) return;
    try {
      if (!site.domain) throw new Error('Configure a domain for this site first.');
      const cloudflareMode = ['cloudflare', 'both'].includes(site.firewall.mode);
      const rule = await syncCloudflareFirewall({
        token: getSecretSetting(db, 'cloudflare_api_token', ''),
        zoneId: getSetting('cloudflare_zone_id', ''),
        siteId: site.id,
        domain: site.domain,
        enabled: site.firewall_enabled && cloudflareMode,
        firewall: site.firewall
      });
      recordAudit(req.user.id, 'site.cloudflare.firewall.sync', { id: site.id, domain: site.domain, deleted: Boolean(rule.deleted) });
      res.json({
        site: manager.decorate(manager.getSite(site.id)),
        rule: rule.inactive ? null : { id: rule.id || null, action: rule.action || site.firewall.cloudflareAction },
        message: rule.deleted ? 'Cloudflare firewall rule removed.' : rule.inactive ? 'No Cloudflare firewall rule was needed.' : 'Cloudflare firewall rule synchronized.'
      });
    } catch (error) { res.status(400).json({ error: error.message }); }
  });

  app.post('/api/admin/sites/:id/certificate', requireAuth, requireAdmin, async (req, res) => {
    const site = getSiteOr404(req, res);
    if (!site || !acquireCertificateOperation(res)) return;
    const wasRunning = manager.statusFor(site.id).running;
    const stoppedForChallenge = [];
    let edgeHttpPaused = false;
    try {
      if (!site.domain) throw new Error('Configure a domain for this site first.');
      const cloudflareToken = getSecretSetting(db, 'cloudflare_api_token', '');
      const wildcard = bool(req.body?.wildcard, false);
      if (wildcard && !cloudflareToken) throw new Error('Wildcard certificates require a configured Cloudflare API token for DNS validation.');
      if (!cloudflareToken) {
        if (DASHBOARD_PORT === 80) throw new Error('Certbot standalone cannot use port 80 while the SHAM dashboard is bound there. Configure the Cloudflare DNS challenge or move the dashboard port.');
        if (EDGE_HTTP_PORT === 80 && edgeProxy.status().httpRunning) { await edgeProxy.pauseHttp(); edgeHttpPaused = true; }
        stoppedForChallenge.push(...await stopRunningSitesOnPort(80));
      }
      await issueCertificate({
        domain: site.domain,
        email: getSetting('certbot_email', ''),
        cloudflareToken,
        wildcard,
        onLine: (level, line) => manager.log(site.id, level, `certbot: ${line.slice(0, 1000)}`)
      });
      db.prepare('UPDATE sites SET ssl_enabled = 1, updated_at = CURRENT_TIMESTAMP WHERE id = ?').run(site.id);
      /** @type {string | null} */
      let warning = null;
      try { await edgeProxy.reloadTls(); }
      catch (error) {
        warning = `The certificate was installed, but the shared HTTPS proxy could not reload it: ${error.message}`;
        manager.log(site.id, 'error', warning);
      }
      try {
        if (manager.statusFor(site.id).running) await manager.restart(site.id);
        else if (wasRunning || site.enabled) await manager.start(site.id);
      } catch (error) {
        const message = `The certificate was installed, but the site could not start with SSL: ${error.message}`;
        warning = [warning, message].filter(Boolean).join(' ');
        manager.log(site.id, 'error', message);
      }
      if (edgeHttpPaused) {
        try { await edgeProxy.resumeHttp(); }
        catch (error) {
          const message = `The certificate was installed, but the shared HTTP proxy could not resume: ${error.message}`;
          warning = [warning, message].filter(Boolean).join(' ');
          manager.log(null, 'error', message);
        }
        edgeHttpPaused = false;
      }
      const restoreWarnings = await restoreEnabledSites(stoppedForChallenge.filter((id) => id !== site.id));
      if (restoreWarnings.length) {
        warning = [warning, `${restoreWarnings.length} temporarily stopped site${restoreWarnings.length === 1 ? '' : 's'} could not be restored. Review Activity for details.`].filter(Boolean).join(' ');
      }
      recordAudit(req.user.id, 'site.certificate.issue', { id: site.id, domain: site.domain, wildcard, warning: Boolean(warning) });
      res.json({ site: manager.decorate(manager.getSite(site.id)), message: wildcard ? 'Wildcard certificate is installed and SSL is enabled.' : 'Certificate is installed and SSL is enabled.', warning });
    } catch (error) {
      if (edgeHttpPaused) { try { await edgeProxy.resumeHttp(); } catch (resumeError) { manager.log(null, 'error', `Could not resume edge HTTP after certificate failure: ${resumeError.message}`); } edgeHttpPaused = false; }
      await restoreEnabledSites([...stoppedForChallenge, ...(wasRunning ? [site.id] : [])]);
      res.status(400).json({ error: error.message });
    } finally {
      if (edgeHttpPaused) { try { await edgeProxy.resumeHttp(); } catch (error) { manager.log(null, 'error', `Could not resume edge HTTP: ${error.message}`); } }
      releaseCertificateOperation();
    }
  });

  app.post('/api/admin/certificates/renew', requireAuth, requireAdmin, async (req, res) => {
    if (!acquireCertificateOperation(res)) return;
    const stoppedForChallenge = [];
    let edgeHttpPaused = false;
    try {
      if (renewalNeedsPort80()) {
        if (DASHBOARD_PORT === 80) throw new Error('A standalone Certbot renewal needs port 80, but the SHAM dashboard is using it. Configure DNS renewal or move the dashboard port.');
        if (EDGE_HTTP_PORT === 80 && edgeProxy.status().httpRunning) { await edgeProxy.pauseHttp(); edgeHttpPaused = true; }
        stoppedForChallenge.push(...await stopRunningSitesOnPort(80));
      }
      await renewCertificates({ onLine: (level, line) => manager.log(null, level, `certbot: ${line.slice(0, 1000)}`) });
      const restartWarnings = [];
      if (edgeHttpPaused) {
        try { await edgeProxy.resumeHttp(); }
        catch (error) {
          const warning = `Certificates were renewed, but the shared HTTP proxy could not resume: ${error.message}`;
          restartWarnings.push(warning);
          manager.log(null, 'error', warning);
        }
        edgeHttpPaused = false;
      }
      try { await edgeProxy.reloadTls(); }
      catch (error) {
        const warning = `Certificates were renewed, but the shared HTTPS proxy could not reload them: ${error.message}`;
        restartWarnings.push(warning);
        manager.log(null, 'error', warning);
      }
      const runningSslSites = db.prepare('SELECT id FROM sites WHERE ssl_enabled = 1 AND enabled = 1').all();
      for (const site of runningSslSites) {
        if (!manager.statusFor(site.id).running) continue;
        try { await manager.restart(site.id); }
        catch (error) {
          const warning = `Site ${site.id} could not restart after certificate renewal: ${error.message}`;
          restartWarnings.push(warning);
          manager.log(site.id, 'error', warning);
        }
      }
      restartWarnings.push(...await restoreEnabledSites(stoppedForChallenge));
      recordAudit(req.user.id, 'certificates.renew', { restartWarnings: restartWarnings.length });
      res.json({
        message: 'Certificate renewal completed.',
        warning: restartWarnings.length ? `${restartWarnings.length} site${restartWarnings.length === 1 ? '' : 's'} could not restart or be restored. Review Activity for details.` : null
      });
    } catch (error) {
      if (edgeHttpPaused) { try { await edgeProxy.resumeHttp(); } catch (resumeError) { manager.log(null, 'error', `Could not resume edge HTTP after renewal failure: ${resumeError.message}`); } edgeHttpPaused = false; }
      await restoreEnabledSites(stoppedForChallenge);
      res.status(400).json({ error: error.message });
    } finally {
      if (edgeHttpPaused) { try { await edgeProxy.resumeHttp(); } catch (error) { manager.log(null, 'error', `Could not resume edge HTTP: ${error.message}`); } }
      releaseCertificateOperation();
    }
  });

  app.get('/api/admin/users', requireAuth, requireAdmin, (_req, res) => {
    const users = db.prepare('SELECT * FROM users ORDER BY created_at, id').all();
    res.json({ users: users.map(publicUser) });
  });

  app.post('/api/admin/users', requireAuth, requireAdmin, async (req, res) => {
    try {
      const username = normalizeUsername(req.body.username);
      const role = String(req.body.role || 'user');
      if (!['admin', 'user'].includes(role)) return res.status(400).json({ error: 'Role must be admin or user.' });
      const { salt, hash } = await hashPassword(req.body.password);
      const result = db.prepare('INSERT INTO users (username, password_hash, password_salt, role, active, password_configured) VALUES (?, ?, ?, ?, 1, 1)')
        .run(username, hash, salt, role);
      const user = db.prepare('SELECT * FROM users WHERE id = ?').get(Number(result.lastInsertRowid));
      recordAudit(req.user.id, 'user.create', { targetId: user.id, username, role });
      res.status(201).json({ user: publicUser(user) });
    } catch (error) {
      const duplicate = String(error.code || '').includes('SQLITE_CONSTRAINT_UNIQUE');
      res.status(duplicate ? 409 : 400).json({ error: duplicate ? 'That username is already in use.' : error.message });
    }
  });

  app.patch('/api/admin/users/:id', requireAuth, requireAdmin, (req, res) => {
    const targetId = Number(req.params.id);
    const target = db.prepare('SELECT * FROM users WHERE id = ?').get(targetId);
    if (!target) return res.status(404).json({ error: 'User not found.' });
    if (targetId === req.user.id && req.body.active !== undefined && !bool(req.body.active, true)) {
      return res.status(400).json({ error: 'You cannot disable your own account.' });
    }
    const role = req.body.role === undefined ? target.role : String(req.body.role);
    const active = req.body.active === undefined ? Boolean(target.active) : bool(req.body.active, true);
    if (!['admin', 'user'].includes(role)) return res.status(400).json({ error: 'Role must be admin or user.' });
    if (targetId === req.user.id && role !== target.role) return res.status(400).json({ error: 'You cannot change your own role.' });
    if (target.role === 'admin' && target.active && (role !== 'admin' || !active) && activeAdminCount() <= 1) {
      return res.status(400).json({ error: 'SHAM must keep at least one active administrator.' });
    }
    const accessChanged = role !== target.role || Number(active) !== Number(target.active);
    db.prepare('UPDATE users SET role = ?, active = ?, session_version = session_version + ? WHERE id = ?').run(role, Number(active), accessChanged ? 1 : 0, targetId);
    recordAudit(req.user.id, 'user.update', { targetId, role, active, sessionsRevoked: accessChanged });
    const updated = db.prepare('SELECT * FROM users WHERE id = ?').get(targetId);
    res.json({ user: publicUser(updated) });
  });

  app.post('/api/admin/users/:id/revoke-sessions', requireAuth, requireAdmin, (req, res) => {
    const targetId = Number(req.params.id);
    const target = db.prepare('SELECT id, username FROM users WHERE id = ?').get(targetId);
    if (!target) return res.status(404).json({ error: 'User not found.' });
    if (targetId === req.user.id) return res.status(400).json({ error: 'Use Security → Sign out other sessions for your own account.' });
    rotateSessionVersion(targetId);
    recordAudit(req.user.id, 'user.sessions.revoke', { targetId, username: target.username });
    res.status(204).end();
  });

  app.delete('/api/admin/users/:id', requireAuth, requireAdmin, (req, res) => {
    const targetId = Number(req.params.id);
    if (targetId === req.user.id) return res.status(400).json({ error: 'You cannot delete your own account.' });
    const target = db.prepare('SELECT * FROM users WHERE id = ?').get(targetId);
    if (!target) return res.status(404).json({ error: 'User not found.' });
    if (target.role === 'admin' && target.active && activeAdminCount() <= 1) {
      return res.status(400).json({ error: 'SHAM must keep at least one active administrator.' });
    }
    db.prepare('DELETE FROM users WHERE id = ?').run(targetId);
    recordAudit(req.user.id, 'user.delete', { targetId, username: target.username });
    res.status(204).end();
  });
  }

module.exports = { registerAdminRoutes };
