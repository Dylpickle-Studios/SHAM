'use strict';

function operationsSite() {
  const id = Number($('#operations-site')?.value || state.operationsSiteId || 0);
  return state.sites.find((site) => site.id === id) || null;
}

function setOperationsTab(name, { focus = false } = {}) {
  const available = $$('[data-operations-tab]').filter((button) => !button.hidden);
  const requested = available.find((button) => button.dataset.operationsTab === name) || available[0] || $('#operations-tab-appearance');
  const selected = requested?.dataset.operationsTab || 'appearance';
  $$('[data-operations-tab]').forEach((button) => {
    const active = button.dataset.operationsTab === selected && !button.hidden;
    button.classList.toggle('active', active);
    button.setAttribute('aria-selected', String(active));
    button.tabIndex = active ? 0 : -1;
    $(`#operations-${button.dataset.operationsTab}`).hidden = !active;
    if (active && focus) button.focus();
  });
}

$$('[data-operations-tab]').forEach((button) => {
  button.addEventListener('click', () => setOperationsTab(button.dataset.operationsTab));
  button.addEventListener('keydown', (event) => {
    if (!['ArrowLeft', 'ArrowRight', 'Home', 'End'].includes(event.key)) return;
    event.preventDefault();
    const tabs = $$('[data-operations-tab]').filter((tab) => !tab.hidden);
    const current = tabs.indexOf(button);
    const next = event.key === 'Home' ? tabs[0]
      : event.key === 'End' ? tabs.at(-1)
        : tabs[(current + (event.key === 'ArrowRight' ? 1 : -1) + tabs.length) % tabs.length];
    setOperationsTab(next.dataset.operationsTab, { focus: true });
  });
});

function addEnvironmentRow(variable = {}) {
  const row = document.createElement('div');
  row.className = 'config-row env-row';
  row.innerHTML = `<label><span>Key</span><input data-env-key maxlength="128" value="${escapeHtml(variable.key || '')}" placeholder="API_TOKEN"></label>
    <label><span>Value</span><input data-env-value type="${variable.secret ? 'password' : 'text'}" value="${escapeHtml(variable.value || '')}" placeholder="${variable.secret ? 'Leave blank to preserve' : 'Value'}"></label>
    <label><span>Scope</span><select data-env-scope><option value="runtime">Runtime</option><option value="build">Build</option><option value="both">Build + runtime</option></select></label>
    <label class="checkbox-line compact-check"><input data-env-secret type="checkbox" ${variable.secret ? 'checked' : ''}><span>Secret</span></label>
    ${variable.secret && variable.key ? '<button class="button ghost compact-button" data-env-reveal type="button">Reveal</button>' : ''}
    <button class="icon-button danger-text" data-remove-config-row type="button" aria-label="Remove environment variable">×</button>`;
  $('[data-env-scope]', row).value = variable.scope || 'runtime';
  $('[data-env-secret]', row).addEventListener('change', (event) => { $('[data-env-value]', row).type = event.target.checked ? 'password' : 'text'; });
  $('[data-env-reveal]', row)?.addEventListener('click', async (event) => {
    const site = operationsSite();
    const key = $('[data-env-key]', row).value.trim();
    if (!site || !key) return;
    const password = await requestAction({ title: `Reveal ${key}?`, message: 'Confirm your current password. The secret will be returned once and placed in this form field; anyone who can see your screen may read it.', confirmLabel: 'Reveal secret', inputLabel: 'Password', inputType: 'password', autocomplete: 'current-password' });
    if (!password) return;
    setBusy(event.currentTarget, true, 'Revealing…');
    try {
      const result = await api(`/api/sites/${site.id}/environment/${encodeURIComponent(key)}/reveal`, { method: 'POST', body: { password } });
      const input = $('[data-env-value]', row);
      const revealedValue = result.value || '';
      input.value = revealedValue;
      input.type = 'text';
      const remask = () => {
        if (!input.isConnected || input.value !== revealedValue) return;
        input.value = '';
        input.type = 'password';
      };
      input.addEventListener('blur', remask, { once: true });
      setTimeout(remask, 30_000);
      input.focus();
      input.select();
      toast(`${key} revealed temporarily. It will be masked again after 30 seconds or when you leave the field.`,'warning');
    } catch (error) { toast(error.message, 'error'); }
    finally { setBusy(event.currentTarget, false); }
  });
  $('[data-remove-config-row]', row).addEventListener('click', () => row.remove());
  $('#environment-rows').append(row);
}

function clearJobForm() {
  $('#job-form').reset();
  $('#job-id').value = '';
  $('#job-schedule').value = '0 3 * * *';
  $('#job-timeout').value = '900';
  $('#job-enabled').checked = true;
}

function renderOperationsSite(payload) {
  const site = payload?.site;
  if (!site) return;
  $('#release-mode-status').textContent = site.release_mode ? 'Atomic releases' : 'Direct files';
  $('#release-mode-status').className = `badge ${site.release_mode ? 'success' : ''}`;
  $('#git-url').value = site.git_url || '';
  $('#git-branch').value = site.git_branch || 'main';
  $('#git-install-dependencies').checked = Boolean(site.install_dependencies);
  $('#git-install-command').value = site.install_command || '';
  $('#git-build-command').value = site.build_command || '';
  $('#git-build-output').value = site.build_output_dir || '';
  $('#export-site-config').href = `/api/sites/${site.id}/config/export`;

  const releases = payload.releases || [];
  $('#release-list').innerHTML = releases.length ? releases.map((release) => `<div class="event-item"><div><strong>${escapeHtml(release.version)}</strong><span>${escapeHtml(release.source)} · ${escapeHtml(formatDate(release.createdAt))}${release.commitSha ? ` · ${escapeHtml(release.commitSha.slice(0, 12))}` : ''}</span></div>${release.active ? '<span class="badge success">Active</span>' : `<button class="button secondary" data-release-rollback="${release.id}" type="button">Roll back</button>`}</div>`).join('') : '<p class="muted">No atomic releases yet. The first Git deployment creates one.</p>';

  const previews = payload.previews || [];
  $('#preview-list').innerHTML = previews.length ? previews.map((preview) => `<div class="event-item"><div><strong><a href="http://${escapeHtml(preview.hostname)}" target="_blank" rel="noopener">${escapeHtml(preview.hostname)}</a></strong><span>Expires ${escapeHtml(formatDate(preview.expiresAt))} · port ${preview.port}</span></div><button class="button danger" data-preview-delete="${preview.id}" type="button">Remove</button></div>`).join('') : '<p class="muted">No active previews.</p>';

  $('#environment-rows').innerHTML = '';
  for (const variable of payload.environment || []) addEnvironmentRow(variable);
  if (!(payload.environment || []).length) addEnvironmentRow();
  const copySelect = $('#copy-env-site');
  if (copySelect) copySelect.innerHTML = '<option value="">Copy variables from another site…</option>' + state.sites.filter((candidate) => candidate.id !== site.id).map((candidate) => `<option value="${candidate.id}">${escapeHtml(candidate.name)}</option>`).join('');

  $('#site-database-profiles').innerHTML = (payload.databaseProfiles || []).length
    ? payload.databaseProfiles.map((profile) => `<label class="check-card"><input type="checkbox" value="${profile.id}" ${profile.attached ? 'checked' : ''}><span><strong>${escapeHtml(profile.name)}</strong><small>${escapeHtml(profile.type)} → ${escapeHtml(profile.envKey)}</small></span></label>`).join('')
    : '<p class="muted">No instance database profiles are configured.</p>';

  $('#job-list').innerHTML = (payload.jobs || []).length ? payload.jobs.map((job) => `<div class="event-item"><div><strong>${escapeHtml(job.name)}</strong><span><code>${escapeHtml(job.schedule)}</code> · next ${escapeHtml(formatDate(job.next_run_at))} · ${escapeHtml(job.last_status || 'never run')}</span><small>${escapeHtml(job.command)}</small></div><div class="inline-actions"><button class="button secondary" data-job-run="${job.id}" type="button" ${job.running ? 'disabled' : ''}>${job.running ? 'Running…' : 'Run now'}</button><button class="button ghost" data-job-edit="${job.id}" type="button">Edit</button><button class="button danger" data-job-delete="${job.id}" type="button">Delete</button></div></div>`).join('') : '<p class="muted">No scheduled tasks.</p>';
  $('#job-list').dataset.jobs = JSON.stringify(payload.jobs || []);
}

function tunnelStatePresentation(tunnel = {}) {
  return {
    disabled: ['Disabled', ''],
    stopped: ['Stopped', ''],
    'needs-token': ['Token required', 'warning'],
    unavailable: ['Unavailable', 'error'],
    starting: ['Connecting', 'warning'],
    connected: ['Connected', 'success'],
    backoff: ['Restarting', 'warning'],
    'needs-attention': ['Token needs attention', 'error'],
    error: ['Error', 'error']
  }[tunnel.state] || ['Unknown', 'warning'];
}

function tunnelDetail(tunnel = {}) {
  const details = [];
  if (!tunnel.enabled) details.push('The connector is disabled.');
  else if (!tunnel.available) details.push('cloudflared is not installed or executable.');
  else if (tunnel.connected) details.push(`Connected${tunnel.connectedAt ? ` since ${formatDate(tunnel.connectedAt)}` : ''}.`);
  else if (tunnel.running) details.push('The connector process is running and waiting for an edge connection.');
  else details.push('The connector is not running.');
  if (tunnel.restartCount) details.push(`${tunnel.restartCount} supervised restart${tunnel.restartCount === 1 ? '' : 's'} recorded.`);
  if (tunnel.nextRetryAt) details.push(`Next retry ${formatDate(tunnel.nextRetryAt)}.`);
  if (tunnel.origin?.state === 'healthy') details.push(`Loopback origin healthy${tunnel.origin.statusCode ? ` (${tunnel.origin.statusCode})` : ''}.`);
  else if (tunnel.origin?.state === 'unhealthy') details.push(`Loopback origin unhealthy${tunnel.origin.lastError ? `: ${tunnel.origin.lastError}` : ''}.`);
  else if (tunnel.origin?.state === 'not-configured') details.push('No loopback origin health check is configured.');
  if (tunnel.exposureWarning) details.push(tunnel.exposureWarning);
  if (tunnel.lastError) details.push(tunnel.lastError);
  return details.join(' ');
}

function updateSiteTunnelMode() {
  const shared = $('#site-cloudflare-connector-mode').value === 'shared';
  const clearing = $('#site-clear-cloudflare-tunnel-token').checked;
  $('#site-cloudflare-tunnel-token').disabled = shared || clearing;
  $('#site-clear-cloudflare-tunnel-token').disabled = shared;
  $('#provision-site-cloudflare-tunnel').disabled = shared;
  if (shared) {
    $('#site-cloudflare-tunnel-token').value = '';
    $('#site-clear-cloudflare-tunnel-token').checked = false;
  }
}

function renderSiteCloudflareTunnel(tunnel = {}) {
  const [label, badgeClass] = tunnelStatePresentation(tunnel);
  $('#site-cloudflare-tunnel-title').textContent = label;
  $('#site-cloudflare-tunnel-status').textContent = label;
  $('#site-cloudflare-tunnel-status').className = `badge ${badgeClass}`.trim();
  $('#site-cloudflare-tunnel-enabled').checked = Boolean(tunnel.enabled);
  $('#site-cloudflare-connector-mode').value = tunnel.route?.connectorMode === 'shared' ? 'shared' : 'dedicated';
  $('#site-cloudflare-tunnel-token').value = '';
  $('#site-cloudflare-tunnel-token').disabled = false;
  $('#site-clear-cloudflare-tunnel-token').checked = false;
  $('#site-cloudflare-tunnel-id').value = tunnel.route?.tunnelId || '';
  $('#site-cloudflare-tunnel-hostname').value = tunnel.route?.publicHostname || '';
  $('#site-cloudflare-tunnel-origin').value = tunnel.route?.originService || '';
  $('#site-cloudflare-managed-route').checked = Boolean(tunnel.route?.managedRoute);
  $('#site-cloudflare-tunnel-only').checked = Boolean(tunnel.route?.tunnelOnly);
  $('#site-cloudflare-tunnel-token-status').textContent = tunnel.tokenConfigured
    ? tunnel.tokenReadable === false ? 'A token is saved but cannot be decrypted. Replace or clear it.' : 'A tunnel token is saved for this site.'
    : 'No tunnel token is saved for this site.';
  $('#site-cloudflare-tunnel-token-status').dataset.configured = tunnel.tokenConfigured ? '1' : '0';
  $('#site-cloudflare-tunnel-token-status').dataset.readable = tunnel.tokenReadable === false ? '0' : '1';
  $('#site-cloudflare-tunnel-detail').textContent = tunnelDetail(tunnel);
  $('#site-cloudflare-tunnel-detail').className = `notice span-2 ${['error', 'unavailable', 'backoff', 'needs-token', 'needs-attention'].includes(tunnel.state) || tunnel.origin?.state === 'unhealthy' ? 'warning' : ''}`.trim();
  $('#restart-site-cloudflare-tunnel').disabled = !tunnel.enabled || !tunnel.tokenConfigured || !tunnel.available;
  $('#reconcile-site-cloudflare-tunnel').disabled = !tunnel.route?.managedRoute;
  updateSiteTunnelMode();
}

async function loadSiteCloudflareTunnel(siteId, fallbackHostname = '') {
  if (state.user?.role !== 'admin' || !siteId) return;
  const result = await api(`/api/admin/sites/${siteId}/cloudflare-tunnel`);
  renderSiteCloudflareTunnel(result.cloudflareTunnel || {});
  if (!$('#site-cloudflare-tunnel-hostname').value) $('#site-cloudflare-tunnel-hostname').value = fallbackHostname;
}

function updateBackupProviderFields() {
  const provider = $('#backup-provider').value;
  for (const name of ['local', 'restic', 's3', 'sftp']) $(`#backup-${name}-fields`).hidden = provider !== name;
}

function addOtelHeaderRow(header = {}) {
  const row = document.createElement('div');
  row.className = 'config-row otel-header-row';
  row.innerHTML = `<label><span>Header</span><input data-otel-header-name maxlength="200" value="${escapeHtml(header.name || '')}" placeholder="Authorization"></label>
    <label><span>Value</span><input data-otel-header-value type="password" value="${escapeHtml(header.value || '')}" placeholder="Bearer …"></label>
    <button class="icon-button danger-text" data-remove-config-row type="button" aria-label="Remove telemetry header">×</button>`;
  $('[data-remove-config-row]', row).addEventListener('click', () => row.remove());
  $('#otel-header-rows').append(row);
}

function addAlertHeaderRow(header = {}) {
  const row = document.createElement('div');
  row.className = 'config-row alert-header-row';
  row.innerHTML = `<label><span>Header</span><input data-alert-header-name maxlength="200" value="${escapeHtml(header.name || '')}" placeholder="Authorization"></label>
    <label><span>Value</span><input data-alert-header-value type="password" maxlength="4096" value="${escapeHtml(header.value || '')}" placeholder="Bearer …"></label>
    <button class="icon-button danger-text" data-remove-config-row type="button" aria-label="Remove alert header">×</button>`;
  $('[data-remove-config-row]', row).addEventListener('click', () => row.remove());
  $('#alert-header-rows').append(row);
}

function updateAlertDestinationFields() {
  const email = $('#alert-destination-kind').value === 'email';
  $('#alert-destination-webhook-fields').hidden = email;
  $('#alert-destination-email-fields').hidden = !email;
  const target = $('#alert-destination-target');
  target.type = email ? 'email' : 'url';
  target.placeholder = email ? 'ops@example.com' : 'https://hooks.example/…';
  $('#alert-destination-target-label').textContent = email ? 'Recipient address' : 'Webhook URL';
}

function renderOperationsInstance(payload) {
  const settings = payload.settings || {};
  const backup = payload.backupSettings || {};
  const tunnels = payload.siteCloudflareTunnels || [];
  const legacy = payload.cloudflareTunnel || {};
  const connectors = [...tunnels];
  if (legacy.enabled || legacy.tokenConfigured) connectors.push({ ...legacy, name: 'Instance connector', domain: 'Legacy configuration', legacy: true });
  const activeTunnels = connectors.filter((tunnel) => tunnel.enabled);
  const connectedTunnels = connectors.filter((tunnel) => tunnel.connected);
  $('#cloudflare-tunnel-status').textContent = activeTunnels.length ? `${connectedTunnels.length}/${activeTunnels.length} connected` : 'No active tunnels';
  $('#cloudflare-tunnel-status').className = `badge ${activeTunnels.length && connectedTunnels.length === activeTunnels.length ? 'success' : activeTunnels.length ? 'warning' : ''}`.trim();
  $('#cloudflare-tunnel-list').innerHTML = connectors.length
    ? connectors.map((tunnel) => {
      const [label, badgeClass] = tunnelStatePresentation(tunnel);
      const target = tunnel.legacy ? 'Legacy instance-wide connector' : (tunnel.domain || 'No domain configured');
      return `<div class="connector-row"><div class="connector-mark">⇄</div><div><strong>${escapeHtml(tunnel.name)}</strong><span>${escapeHtml(target)}</span></div><span class="badge ${badgeClass}">${escapeHtml(label)}</span></div>`;
    }).join('')
    : '<div class="empty-connector"><strong>No connectors configured</strong><span>Edit a site to configure its Cloudflare Tunnel.</span></div>';
  $('#shared-cloudflare-tunnel-options').hidden = state.user?.role !== 'admin';
  $('#shared-cloudflare-tunnel-enabled').checked = Boolean(legacy.enabled);
  $('#shared-cloudflare-tunnel-id').value = legacy.route?.tunnelId || '';
  $('#shared-cloudflare-tunnel-token').value = '';
  $('#clear-shared-cloudflare-tunnel-token').checked = false;
  $('#shared-cloudflare-tunnel-token').disabled = false;
  $('#shared-cloudflare-tunnel-token-status').textContent = legacy.tokenConfigured ? 'A shared connector token is saved.' : 'No shared connector token is saved.';
  const gitProviders = new Map((payload.gitProviders || []).map((item) => [item.provider, item]));
  for (const row of $$('[data-git-provider-row]')) {
    const provider = row.dataset.gitProviderRow;
    const info = gitProviders.get(provider) || {};
    const configured = Boolean(info.configured);
    const status = $(`#git-provider-${provider}-status`);
    const token = $(`#git-provider-${provider}-token`);
    const base = $(`[data-git-provider-base="${provider}"]`, row);
    const clear = $(`[data-git-provider-clear="${provider}"]`, row);
    if (status) {
      const location = info.configurableBaseUrl && info.baseUrl ? ` · ${info.baseUrl}` : '';
      status.textContent = `${configured ? 'Connected · encrypted token saved' : 'Not connected'}${location}${info.insecureBaseUrl ? ' · HTTP warning' : ''}`;
      status.classList.toggle('warning-text', Boolean(info.insecureBaseUrl));
    }
    if (token) token.value = '';
    if (base && info.baseUrl) base.value = info.baseUrl;
    if (clear) clear.disabled = !configured;
  }
  $('#git-webhook-base-url').value = settings.gitWebhookBaseUrl || '';
  $('#backup-provider').value = backup.provider || 'local';
  $('#backup-schedule').value = backup.schedule || '0 2 * * *';
  $('#backup-enabled').checked = Boolean(backup.enabled);
  const config = backup.config || {};
  $('#backup-retention').value = config.retention || 14;
  $('#backup-local-destination').value = config.destination || '';
  $('#backup-restic-repository').value = config.repository || '';
  $('#backup-restic-password').value = '';
  $('#backup-s3-destination').value = backup.provider === 's3' ? (config.destination || '') : '';
  $('#backup-s3-endpoint').value = config.endpoint || '';
  $('#backup-s3-region').value = config.region || '';
  $('#backup-s3-access-key').value = '';
  $('#backup-s3-secret-key').value = '';
  $('#backup-s3-session-token').value = '';
  $('#backup-sftp-host').value = config.host || '';
  $('#backup-sftp-port').value = config.port || '';
  $('#backup-sftp-user').value = config.user || '';
  $('#backup-sftp-remote-path').value = config.remotePath || '';
  $('#backup-sftp-private-key').value = '';
  $('#backup-clear-secrets').checked = false;
  updateBackupProviderFields();
  $('#backup-secret-status').textContent = (backup.secretFields || []).length ? `Stored encrypted credentials: ${(backup.secretFields || []).join(', ')}. Blank secret fields preserve the saved value.` : 'Credentials entered here are encrypted and are never returned by the API.';
  $('#backup-list').innerHTML = (payload.backups || []).length ? payload.backups.slice(0, 12).map((backupRun) => `<div class="event-item actionable" data-backup-id="${backupRun.id}"><div><strong>${escapeHtml(backupRun.filename || 'Backup')}</strong><span>${escapeHtml(backupRun.destination)} · ${formatBytes(backupRun.bytes)} · ${escapeHtml(formatDate(backupRun.finishedAt || backupRun.startedAt))}</span>${backupRun.detail ? `<small>${escapeHtml(backupRun.detail)}</small>` : ''}</div><div class="inline-actions"><span class="badge ${backupRun.status === 'success' ? 'success' : backupRun.status === 'failed' ? 'error' : 'warning'}">${escapeHtml(backupRun.status)}</span>${backupRun.status === 'success' ? '<button class="button secondary" data-restore-backup type="button">Restore</button>' : ''}</div></div>`).join('') : '<p class="muted">No backup runs recorded.</p>';

  $('#prometheus-enabled').checked = Boolean(settings.prometheusEnabled);
  $('#prometheus-token').value = '';
  $('#prometheus-token').disabled = false;
  $('#clear-prometheus-token').checked = false;
  $('#prometheus-token-status').textContent = settings.prometheusTokenConfigured ? 'A metrics token is currently saved.' : 'No metrics token is saved.';
  $('#prometheus-token-status').dataset.configured = settings.prometheusTokenConfigured ? '1' : '0';
  $('#otel-endpoint').value = settings.otelEndpoint || '';
  $('#otel-header-rows').innerHTML = '';
  $('#add-otel-header').disabled = false;
  $('#clear-otel-headers').checked = false;
  $('#otel-headers-status').textContent = settings.otelHeadersConfigured ? 'Encrypted headers are currently saved. Add rows only to replace them.' : 'No OpenTelemetry headers are saved.';
  $('#public-status-enabled').checked = Boolean(settings.publicStatusEnabled);
  $('#public-status-title').value = settings.publicStatusTitle || 'SHAM service status';
  const statusLink = $('#open-public-status');
  statusLink.classList.toggle('is-disabled', !settings.publicStatusEnabled);
  statusLink.setAttribute('aria-disabled', settings.publicStatusEnabled ? 'false' : 'true');
  statusLink.tabIndex = settings.publicStatusEnabled ? 0 : -1;
  $('#copy-metrics-url').disabled = !settings.prometheusEnabled;
  $('#instance-locale').value = settings.locale || 'en';
  $('#update-channel').value = settings.updateChannel || 'stable';

  $('#alert-destination-list').innerHTML = (payload.alertDestinations || []).length ? payload.alertDestinations.map((destination) => `<div class="event-item"><div><strong>${escapeHtml(destination.name)}</strong><span>${escapeHtml(destination.kind)} · ${destination.enabled ? 'enabled' : 'disabled'}</span></div><div class="inline-actions"><button class="button secondary" data-alert-test="${destination.id}" type="button">Test</button><button class="button danger" data-alert-delete="${destination.id}" type="button">Delete</button></div></div>`).join('') : '<p class="muted">No alert destinations.</p>';

  $('#database-profile-list').innerHTML = (payload.databaseProfiles || []).length ? payload.databaseProfiles.map((profile) => `<div class="event-item"><div><strong>${escapeHtml(profile.name)}</strong><span>${escapeHtml(profile.type)} · ${escapeHtml(profile.envKey)}</span></div><button class="button danger" data-database-delete="${profile.id}" type="button">Delete</button></div>`).join('') : '<p class="muted">No database profiles.</p>';

  const update = payload.update || {};
  const pending = update.pending || update.staged || null;
  $('#update-status').textContent = pending ? 'Restart required' : 'Idle';
  $('#update-status').className = `badge ${pending ? 'warning' : 'success'}`;
  $('#update-detail').textContent = pending ? `Version ${pending.version || 'unknown'} is staged. Restart SHAM to apply it.` : 'No update is staged.';
  $('#cancel-update').disabled = !pending;

  const capabilities = payload.capabilities || {};
  const items = [
    ['Docker isolation', capabilities.docker, capabilities.dockerReason],
    ['Git releases', capabilities.git, capabilities.git ? '' : 'Git executable was not found.'],
    ['Buildpacks', capabilities.buildpacks, capabilities.buildpacks ? '' : 'The pack executable was not found; Dockerfile/image runtimes still work.'],
    ['Nixpacks', capabilities.nixpacks, capabilities.nixpacks ? '' : 'The nixpacks executable was not found; Dockerfile/image runtimes still work.'],
    ['Cloudflare Tunnel', capabilities.cloudflared, capabilities.cloudflared ? '' : 'The cloudflared executable was not found.'],
    ['Anubis', capabilities.anubis, capabilities.anubis ? '' : (capabilities.dockerReason || 'Anubis requires Docker isolation support.')],
    ['External backup', backup.configured, backup.configured ? '' : 'Configure and test an external backup destination.'],
    ['Public status', settings.publicStatusEnabled, settings.publicStatusEnabled ? '' : 'Public status is disabled.']
  ];
  $('#operations-capabilities').innerHTML = items.map(([label, ready, reason]) => `<span class="capability ${ready ? 'ready' : ''}"${reason ? ` title="${escapeHtml(reason)}"` : ''}>${ready ? '✓' : '○'} ${escapeHtml(label)}</span>`).join('');

  const site = operationsSite();
  const checklist = [
    ['Create at least one site', state.sites.length > 0],
    ['Use a domain and shared edge proxy', Boolean(site?.domain && site?.edge_enabled)],
    ['Enable multi-factor authentication', Boolean(state.security?.user?.totpEnabled || (state.security?.passkeys || []).length)],
    ['Configure external backups', Boolean(backup.configured)],
    ['Configure an alert destination', Boolean((payload.alertDestinations || []).length)],
    ['Review isolation for server-side runtimes', !site || ['static', 'proxy'].includes(site.runtime_type) || site.runtime_type === 'container' || site.runtime_type === 'compose' || site.runtime_isolation === 'docker']
  ];
  $('#setup-checklist').innerHTML = `<div class="panel-heading"><div><h2>Readiness checklist</h2><p class="muted">Recommended safeguards before exposing production sites.</p></div><span class="badge">${checklist.filter(([, ready]) => ready).length}/${checklist.length}</span></div><div class="checklist-grid">${checklist.map(([label, ready]) => `<div class="checklist-item ${ready ? 'complete' : ''}"><span>${ready ? '✓' : '○'}</span><strong>${escapeHtml(label)}</strong></div>`).join('')}</div>`;
}

async function loadOperations() {
  if (state.user?.role !== 'admin') return;
  const requestId = ++state.operationsRequest;
  const button = $('#refresh-operations');
  setBusy(button, true, 'Refreshing…');
  const selector = $('#operations-site');
  const previous = Number(selector.value || state.operationsSiteId || state.sites[0]?.id || 0);
  selector.innerHTML = state.sites.length ? state.sites.map((site) => `<option value="${site.id}">${escapeHtml(site.name)}</option>`).join('') : '<option value="">No sites configured</option>';
  if (state.sites.some((site) => site.id === previous)) selector.value = String(previous);
  state.operationsSiteId = Number(selector.value || 0) || null;
  try {
    const [instance, sitePayload, security, filters] = await Promise.all([
      api('/api/admin/operations'),
      state.operationsSiteId ? api(`/api/sites/${state.operationsSiteId}/operations`) : Promise.resolve(null),
      api('/api/security'),
      api('/api/log-filters')
    ]);
    if (requestId !== state.operationsRequest) return;
    state.logFilters = filters.filters || [];
    $('#log-saved-filter').innerHTML = '<option value="">Saved filters…</option>' + state.logFilters.map((filter) => `<option value="${filter.id}">${escapeHtml(filter.name)}</option>`).join('');
    state.security = security;
    state.operations = { instance, site: sitePayload };
    renderOperationsInstance(instance);
    if (sitePayload) renderOperationsSite(sitePayload);
  } catch (error) { if (requestId === state.operationsRequest) toast(error.message, 'error'); }
  finally { if (requestId === state.operationsRequest) setBusy(button, false); }
}

$('#operations-site').addEventListener('change', () => { state.operationsSiteId = Number($('#operations-site').value || 0) || null; loadOperations(); });
$('#refresh-operations').addEventListener('click', loadOperations);
function gitProviderLabel(provider) {
  return ({ github: 'GitHub', gitlab: 'GitLab', bitbucket: 'Bitbucket Cloud', gitea: 'Gitea', forgejo: 'Forgejo' })[provider] || provider;
}

$$('[data-git-provider-save]').forEach((button) => button.addEventListener('click', async (event) => {
  const provider = event.currentTarget.dataset.gitProviderSave;
  const row = event.currentTarget.closest('[data-git-provider-row]');
  const input = $(`#git-provider-${provider}-token`);
  const base = $(`[data-git-provider-base="${provider}"]`, row);
  const token = input?.value.trim() || '';
  if (!token && !base) return toast(`Enter a ${gitProviderLabel(provider)} access token.`, 'error');
  if (base && !base.value.trim()) return toast(`Enter the ${gitProviderLabel(provider)} server URL.`, 'error');
  setBusy(event.currentTarget, true, token ? 'Connecting…' : 'Saving…');
  try {
    await api(`/api/admin/git-providers/${encodeURIComponent(provider)}`, {
      method: 'PUT',
      body: { ...(token ? { token } : {}), ...(base ? { baseUrl: base.value.trim() } : {}) }
    });
    if (input) input.value = '';
    toast(token ? `${gitProviderLabel(provider)} connected.` : `${gitProviderLabel(provider)} server saved.`);
    await loadOperations();
  } catch (error) { toast(error.message, 'error'); }
  finally { setBusy(event.currentTarget, false); }
}));
$$('[data-git-provider-clear]').forEach((button) => button.addEventListener('click', async (event) => {
  const provider = event.currentTarget.dataset.gitProviderClear;
  setBusy(event.currentTarget, true, 'Disconnecting…');
  try {
    await api(`/api/admin/git-providers/${encodeURIComponent(provider)}`, { method: 'PUT', body: { clearToken: true } });
    toast(`${gitProviderLabel(provider)} disconnected.`);
    await loadOperations();
  } catch (error) { toast(error.message, 'error'); }
  finally { setBusy(event.currentTarget, false); }
}));
$('#save-git-webhook-url').addEventListener('click', async (event) => {
  setBusy(event.currentTarget, true, 'Saving…');
  try {
    await api('/api/admin/operations/settings', { method: 'PUT', body: { gitWebhookBaseUrl: $('#git-webhook-base-url').value } });
    toast($('#git-webhook-base-url').value.trim() ? 'Public SHAM URL saved. Provider webhooks will be synchronized after Git deployments.' : 'Automatic provider webhook setup disabled.');
    await loadOperations();
  } catch (error) { toast(error.message, 'error'); }
  finally { setBusy(event.currentTarget, false); }
});
$('#add-env-row').addEventListener('click', () => addEnvironmentRow());
$('#paste-env').addEventListener('click', async () => {
  try {
    const text = await navigator.clipboard.readText();
    const variables = text.split(/\r?\n/).map((line) => line.trim()).filter((line) => line && !line.startsWith('#')).map((line) => { const index = line.indexOf('='); if (index < 1) return null; const key = line.slice(0, index).trim().replace(/^export\s+/, ''); let value = line.slice(index + 1).trim(); if ((value.startsWith('\"') && value.endsWith('\"')) || (value.startsWith("'") && value.endsWith("'"))) value = value.slice(1, -1); return { key, value, scope: 'runtime', secret: /(?:SECRET|TOKEN|PASSWORD|KEY|PRIVATE|CREDENTIAL)/i.test(key) }; }).filter(Boolean);
    if (!variables.length) throw new Error('Clipboard does not contain KEY=VALUE lines.');
    $('#environment-rows').innerHTML = '';
    variables.forEach(addEnvironmentRow);
    toast(`Imported ${variables.length} environment variable${variables.length === 1 ? '' : 's'} from the clipboard.`);
  } catch (error) { toast(error.message || 'Clipboard access was denied.', 'error'); }
});

$('#copy-env').addEventListener('click', async (event) => {
  const site = operationsSite();
  const sourceSiteId = Number($('#copy-env-site').value || 0);
  if (!site || !sourceSiteId) return toast('Choose a source site first.', 'error');
  setBusy(event.currentTarget, true, 'Copying…');
  try {
    const result = await api(`/api/sites/${site.id}/environment/copy`, { method: 'POST', body: { sourceSiteId } });
    toast(`Copied ${result.copied} variable${result.copied === 1 ? '' : 's'} from ${result.source}.`);
    await loadOperations();
  } catch (error) { toast(error.message, 'error'); }
  finally { setBusy(event.currentTarget, false); }
});

$('#environment-form').addEventListener('submit', async (event) => {
  event.preventDefault();
  const site = operationsSite();
  if (!site) return;
  const variables = $$('.env-row', $('#environment-rows')).map((row) => ({
    key: $('[data-env-key]', row).value,
    value: $('[data-env-value]', row).value,
    scope: $('[data-env-scope]', row).value,
    secret: $('[data-env-secret]', row).checked
  })).filter((item) => item.key.trim());
  const button = $('#environment-form button[type="submit"]');
  setBusy(button, true, 'Saving…');
  try { await api(`/api/sites/${site.id}/environment`, { method: 'PUT', body: { variables } }); toast('Environment saved and runtime refreshed.'); await loadOperations(); }
  catch (error) { toast(error.message, 'error'); }
  finally { setBusy(button, false); }
});

$('#save-site-databases').addEventListener('click', async (event) => {
  const site = operationsSite();
  if (!site) return;
  setBusy(event.currentTarget, true, 'Saving…');
  try {
    const profileIds = $$('#site-database-profiles input:checked').map((input) => Number(input.value));
    await api(`/api/sites/${site.id}/database-profiles`, { method: 'PUT', body: { profileIds } });
    toast('Database profile attachments saved.');
    await loadOperations();
  } catch (error) { toast(error.message, 'error'); }
  finally { setBusy(event.currentTarget, false); }
});

$('#import-site-config').addEventListener('click', () => $('#import-site-config-file').click());
$('#import-site-config-file').addEventListener('change', async (event) => {
  const site = operationsSite();
  const file = event.currentTarget.files[0];
  if (!site || !file) return;
  try {
    if (file.size > 1024 * 1024) throw new Error('Configuration files are limited to 1 MB.');
    const payload = JSON.parse(await file.text());
    const result = await api(`/api/sites/${site.id}/config/import`, { method: 'POST', body: payload });
    toast(result.warning || 'Configuration imported.', result.warning ? 'warning' : 'success');
    await Promise.all([loadSites(), loadOperations()]);
  } catch (error) { toast(error.message, 'error'); }
  finally { event.currentTarget.value = ''; }
});

$('#git-deploy-form').addEventListener('submit', async (event) => {
  event.preventDefault();
  const site = operationsSite();
  if (!site) return;
  const button = $('#git-deploy');
  const body = { url: $('#git-url').value, branch: $('#git-branch').value, deployKey: $('#git-deploy-key').value, installDependencies: $('#git-install-dependencies').checked, installCommand: $('#git-install-command').value, buildCommand: $('#git-build-command').value, buildOutputDir: $('#git-build-output').value };
  setBusy(button, true, 'Deploying…');
  try {
    let result;
    try { result = await api(`/api/sites/${site.id}/deploy/git`, { method: 'POST', body }); }
    catch (error) {
      if (error.code !== 'SHAM_MANIFEST_APPROVAL_REQUIRED') throw error;
      const config = error.payload?.manifest?.config || {};
      const runtime = config.runtime || {};
      const build = config.build || {};
      const summary = error.payload?.manifest?.removed
        ? 'This commit removes the repository runtime manifest.'
        : `This commit changes repository-controlled execution policy.${runtime.driver ? ` Runtime: ${runtime.driver}.` : ''}${runtime.command ? ` Start: ${String(runtime.command).slice(0, 180)}.` : ''}${build.install ? ` Install: ${String(build.install).slice(0, 180)}.` : ''}${build.command ? ` Build: ${String(build.command).slice(0, 180)}.` : ''}`;
      const approved = await requestAction({ title: 'Approve repository execution policy?', message: `${summary} Only approve after reviewing the changed sham.yaml/sham.yml/sham.json in the repository.`, confirmLabel: 'Approve and deploy', danger: true });
      if (!approved) return;
      result = await api(`/api/sites/${site.id}/deploy/git`, { method: 'POST', body: { ...body, approveManifestChanges: true } });
    }
    $('#git-deploy-key').value = '';
    toast(result.warning || (result.webhook ? `Git release activated; ${result.webhook.provider} push webhook ${result.webhook.action}.` : 'Git release validated and activated.'), result.warning ? 'warning' : 'success');
    await Promise.all([loadSites(), loadOperations()]);
  } catch (error) { toast(error.message, 'error'); }
  finally { setBusy(button, false); }
});

$('#create-preview').addEventListener('click', async (event) => {
  const site = operationsSite();
  if (!site) return;
  const hostname = await requestAction({ title: 'Create preview', message: 'Use a temporary hostname routed by the shared edge proxy.', confirmLabel: 'Create preview', inputLabel: 'Preview hostname', inputValue: site.preview_domain ? `preview-${site.id}.${site.preview_domain}` : `preview-${site.id}.${site.domain || 'local.invalid'}`, placeholder: 'preview.example.com' });
  if (!hostname) return;
  setBusy(event.currentTarget, true, 'Creating…');
  try { await api(`/api/sites/${site.id}/previews`, { method: 'POST', body: { hostname, ttlHours: 24 } }); toast('Preview created for 24 hours.'); await loadOperations(); }
  catch (error) { toast(error.message, 'error'); }
  finally { setBusy(event.currentTarget, false); }
});

$('#release-list').addEventListener('click', async (event) => {
  const button = event.target.closest('[data-release-rollback]');
  if (!button || !(await requestAction({ title: 'Roll back this release?', message: 'SHAM will atomically replace the active release and restart the site.', confirmLabel: 'Roll back', danger: true }))) return;
  const site = operationsSite();
  setBusy(button, true, 'Rolling back…');
  try { const result = await api(`/api/sites/${site.id}/releases/${button.dataset.releaseRollback}/rollback`, { method: 'POST' }); toast(result.warning || 'Release rolled back.', result.warning ? 'warning' : 'success'); await Promise.all([loadSites(), loadOperations()]); }
  catch (error) { toast(error.message, 'error'); setBusy(button, false); }
});

$('#preview-list').addEventListener('click', async (event) => {
  const button = event.target.closest('[data-preview-delete]');
  if (!button) return;
  const site = operationsSite();
  setBusy(button, true, 'Removing…');
  try { await api(`/api/sites/${site.id}/previews/${button.dataset.previewDelete}`, { method: 'DELETE' }); toast('Preview removed.'); await loadOperations(); }
  catch (error) { toast(error.message, 'error'); setBusy(button, false); }
});

$('#job-form').addEventListener('submit', async (event) => {
  event.preventDefault();
  const site = operationsSite();
  if (!site) return;
  const button = $('#job-form button[type="submit"]');
  setBusy(button, true, 'Saving…');
  try {
    await api(`/api/sites/${site.id}/jobs`, { method: 'POST', body: { id: Number($('#job-id').value || 0) || undefined, name: $('#job-name').value, schedule: $('#job-schedule').value, command: $('#job-command').value, timeoutSeconds: $('#job-timeout').value, enabled: $('#job-enabled').checked, allowOverlap: $('#job-overlap').checked } });
    clearJobForm(); toast('Scheduled task saved.'); await loadOperations();
  } catch (error) { toast(error.message, 'error'); }
  finally { setBusy(button, false); }
});
$('#clear-job').addEventListener('click', clearJobForm);
$('#job-list').addEventListener('click', async (event) => {
  const site = operationsSite();
  const run = event.target.closest('[data-job-run]');
  const edit = event.target.closest('[data-job-edit]');
  const remove = event.target.closest('[data-job-delete]');
  if (edit) {
    const jobs = JSON.parse($('#job-list').dataset.jobs || '[]');
    const job = jobs.find((item) => item.id === Number(edit.dataset.jobEdit));
    if (!job) return;
    $('#job-id').value = job.id; $('#job-name').value = job.name; $('#job-schedule').value = job.schedule; $('#job-command').value = job.command; $('#job-timeout').value = job.timeout_seconds; $('#job-enabled').checked = job.enabled; $('#job-overlap').checked = job.allow_overlap; $('#job-name').focus();
  } else if (run) {
    setBusy(run, true, 'Running…');
    try { await api(`/api/sites/${site.id}/jobs/${run.dataset.jobRun}/run`, { method: 'POST' }); toast('Task completed.'); await loadOperations(); }
    catch (error) { toast(error.message, 'error'); setBusy(run, false); }
  } else if (remove && await requestAction({ title: 'Delete scheduled task?', message: 'Its historical run records will also be removed.', confirmLabel: 'Delete task', danger: true })) {
    try { await api(`/api/sites/${site.id}/jobs/${remove.dataset.jobDelete}`, { method: 'DELETE' }); toast('Task deleted.'); await loadOperations(); }
    catch (error) { toast(error.message, 'error'); }
  }
});

$('#log-saved-filter').addEventListener('change', () => {
  const filter = state.logFilters.find((item) => item.id === Number($('#log-saved-filter').value));
  if (!filter) return;
  $('#log-query').value = filter.filter?.query || '';
  $('#log-level').value = filter.filter?.level || '';
  $('#log-since').value = filter.filter?.since || '';
});
$('#save-log-filter').addEventListener('click', async () => {
  const name = await requestAction({ title: 'Save log filter', message: 'Save the current query for quick reuse.', confirmLabel: 'Save filter', inputLabel: 'Filter name', placeholder: 'Recent errors' });
  if (!name) return;
  try {
    await api('/api/log-filters', { method: 'POST', body: { name, filter: { query: $('#log-query').value, level: $('#log-level').value, since: $('#log-since').value } } });
    toast('Log filter saved.'); await loadOperations();
  } catch (error) { toast(error.message, 'error'); }
});
$('#delete-log-filter').addEventListener('click', async () => {
  const id = Number($('#log-saved-filter').value || 0);
  if (!id) return toast('Choose a saved filter first.', 'warning');
  try { await api(`/api/log-filters/${id}`, { method: 'DELETE' }); toast('Log filter deleted.'); await loadOperations(); }
  catch (error) { toast(error.message, 'error'); }
});

$('#search-runtime-logs').addEventListener('click', async (event) => {
  setBusy(event.currentTarget, true, 'Searching…');
  try {
    const params = new URLSearchParams({ limit: '300' });
    const site = operationsSite();
    if (site) params.set('siteId', String(site.id));
    if ($('#log-query').value) params.set('query', $('#log-query').value);
    if ($('#log-level').value) params.set('level', $('#log-level').value);
    if ($('#log-since').value) params.set('since', new Date($('#log-since').value).toISOString());
    const result = await api(`/api/runtime-logs/search?${params}`);
    $('#operations-log-results').innerHTML = result.logs.length ? result.logs.map((log) => `<div class="event-item ${log.level === 'error' ? 'critical' : ''}"><div><strong>${escapeHtml(log.level)}</strong><span>${escapeHtml(formatDate(log.createdAt))}</span><small>${escapeHtml(log.message)}</small></div></div>`).join('') : '<p class="muted">No matching log records.</p>';
  } catch (error) { toast(error.message, 'error'); }
  finally { setBusy(event.currentTarget, false); }
});


$('#site-clear-cloudflare-tunnel-token').addEventListener('change', (event) => {
  $('#site-cloudflare-tunnel-token').disabled = event.currentTarget.checked;
  if (event.currentTarget.checked) $('#site-cloudflare-tunnel-token').value = '';
});

$('#site-cloudflare-connector-mode').addEventListener('change', updateSiteTunnelMode);

$('#save-site-cloudflare-tunnel').addEventListener('click', async (event) => {
  const siteId = Number($('#site-id').value);
  if (!siteId) return;
  setBusy(event.currentTarget, true, 'Saving…');
  try {
    const enabled = $('#site-cloudflare-tunnel-enabled').checked;
    const clearToken = $('#site-clear-cloudflare-tunnel-token').checked;
    const token = $('#site-cloudflare-tunnel-token').value.trim();
    const tokenConfigured = $('#site-cloudflare-tunnel-token-status').dataset.configured === '1';
    const tokenReadable = $('#site-cloudflare-tunnel-token-status').dataset.readable !== '0';
    const connectorMode = $('#site-cloudflare-connector-mode').value;
    if (connectorMode !== 'shared' && enabled && (clearToken || (!tokenConfigured && !token))) throw new Error('Set a tunnel token before enabling this connector.');
    if (connectorMode !== 'shared' && enabled && tokenConfigured && !tokenReadable && !token) throw new Error('Replace the unreadable tunnel token before enabling this connector.');
    const result = await api(`/api/admin/sites/${siteId}/cloudflare-tunnel`, {
      method: 'PUT',
      body: {
        enabled, token: token || undefined, clearToken, connectorMode,
        tunnelId: $('#site-cloudflare-tunnel-id').value,
        publicHostname: $('#site-cloudflare-tunnel-hostname').value,
        originService: $('#site-cloudflare-tunnel-origin').value,
        managedRoute: $('#site-cloudflare-managed-route').checked,
        tunnelOnly: $('#site-cloudflare-tunnel-only').checked
      }
    });
    renderSiteCloudflareTunnel(result.cloudflareTunnel || {});
    toast('Site tunnel settings saved.');
    await loadSites();
  } catch (error) { toast(error.message, 'error'); }
  finally { setBusy(event.currentTarget, false); }
});

$('#clear-shared-cloudflare-tunnel-token').addEventListener('change', (event) => {
  $('#shared-cloudflare-tunnel-token').disabled = event.currentTarget.checked;
  if (event.currentTarget.checked) $('#shared-cloudflare-tunnel-token').value = '';
});

$('#save-shared-cloudflare-tunnel').addEventListener('click', async (event) => {
  setBusy(event.currentTarget, true, 'Saving…');
  try {
    const enabled = $('#shared-cloudflare-tunnel-enabled').checked;
    const clearToken = $('#clear-shared-cloudflare-tunnel-token').checked;
    const token = $('#shared-cloudflare-tunnel-token').value.trim();
    const configured = Boolean(state.operations?.instance?.cloudflareTunnel?.tokenConfigured);
    if (enabled && (clearToken || (!configured && !token))) throw new Error('Set a shared tunnel token before enabling the connector.');
    const result = await api('/api/admin/cloudflare-tunnel', {
      method: 'PUT',
      body: { enabled, token: token || undefined, clearToken, tunnelId: $('#shared-cloudflare-tunnel-id').value }
    });
    state.operations = { ...(state.operations || {}), instance: { ...(state.operations?.instance || {}), cloudflareTunnel: result.cloudflareTunnel } };
    renderOperationsInstance(state.operations.instance);
    toast('Shared tunnel connector saved.');
  } catch (error) { toast(error.message, 'error'); }
  finally { setBusy(event.currentTarget, false); }
});

$('#restart-shared-cloudflare-tunnel').addEventListener('click', async (event) => {
  setBusy(event.currentTarget, true, 'Restarting…');
  try {
    const result = await api('/api/admin/cloudflare-tunnel/restart', { method: 'POST' });
    state.operations = { ...(state.operations || {}), instance: { ...(state.operations?.instance || {}), cloudflareTunnel: result.cloudflareTunnel } };
    renderOperationsInstance(state.operations.instance);
    toast('Shared tunnel connector restarted.');
  } catch (error) { toast(error.message, 'error'); }
  finally { setBusy(event.currentTarget, false); }
});

$('#restart-site-cloudflare-tunnel').addEventListener('click', async (event) => {
  const siteId = Number($('#site-id').value);
  if (!siteId) return;
  setBusy(event.currentTarget, true, 'Restarting…');
  try {
    const result = await api(`/api/admin/sites/${siteId}/cloudflare-tunnel/restart`, { method: 'POST' });
    renderSiteCloudflareTunnel(result.cloudflareTunnel || {});
    toast('Site tunnel connector restarted.');
    await loadSites();
  } catch (error) { toast(error.message, 'error'); }
  finally { setBusy(event.currentTarget, false); }
});

$('#provision-site-cloudflare-tunnel').addEventListener('click', async (event) => {
  const siteId = Number($('#site-id').value);
  if (!siteId) return;
  setBusy(event.currentTarget, true, 'Provisioning…');
  try {
    const result = await api(`/api/admin/sites/${siteId}/cloudflare-tunnel/provision`, {
      method: 'POST',
      body: { originService: $('#site-cloudflare-tunnel-origin').value, tunnelOnly: $('#site-cloudflare-tunnel-only').checked }
    });
    renderSiteCloudflareTunnel(result.cloudflareTunnel || {});
    toast('Managed Cloudflare Tunnel provisioned and route reconciled.');
    await loadSites();
  } catch (error) { toast(error.message, 'error'); }
  finally { setBusy(event.currentTarget, false); }
});

$('#reconcile-site-cloudflare-tunnel').addEventListener('click', async (event) => {
  const siteId = Number($('#site-id').value);
  if (!siteId) return;
  setBusy(event.currentTarget, true, 'Reconciling…');
  try {
    const result = await api(`/api/admin/sites/${siteId}/cloudflare-tunnel/reconcile`, { method: 'POST' });
    renderSiteCloudflareTunnel(result.cloudflareTunnel || {});
    toast('Cloudflare Tunnel route reconciled.');
  } catch (error) { toast(error.message, 'error'); }
  finally { setBusy(event.currentTarget, false); }
});

$('#backup-provider').addEventListener('change', updateBackupProviderFields);
$('#backup-form').addEventListener('submit', async (event) => {
  event.preventDefault();
  const button = $('#backup-form button[type="submit"]');
  setBusy(button, true, 'Saving…');
  try {
    const provider = $('#backup-provider').value;
    const config = { retention: Number($('#backup-retention').value || 14) };
    if (provider === 'local') config.destination = $('#backup-local-destination').value.trim();
    if (provider === 'restic') {
      config.repository = $('#backup-restic-repository').value.trim();
      config.password = $('#backup-restic-password').value;
    }
    if (provider === 's3') {
      config.destination = $('#backup-s3-destination').value.trim();
      config.endpoint = $('#backup-s3-endpoint').value.trim();
      config.region = $('#backup-s3-region').value.trim();
      config.accessKey = $('#backup-s3-access-key').value;
      config.secretKey = $('#backup-s3-secret-key').value;
      config.sessionToken = $('#backup-s3-session-token').value;
    }
    if (provider === 'sftp') {
      config.host = $('#backup-sftp-host').value.trim();
      config.port = $('#backup-sftp-port').value ? Number($('#backup-sftp-port').value) : undefined;
      config.user = $('#backup-sftp-user').value.trim();
      config.remotePath = $('#backup-sftp-remote-path').value.trim();
      config.privateKey = $('#backup-sftp-private-key').value;
    }
    const clearSecrets = $('#backup-clear-secrets').checked ? ['password', 'accessKey', 'secretKey', 'sessionToken', 'privateKey', 'passphrase'] : [];
    await api('/api/admin/operations/settings', { method: 'PUT', body: { backup: { enabled: $('#backup-enabled').checked, provider, schedule: $('#backup-schedule').value, config, clearSecrets } } });
    toast('Backup settings saved.'); await loadOperations();
  } catch (error) { toast(error.message, 'error'); }
  finally { setBusy(button, false); }
});
$('#run-backup').addEventListener('click', async (event) => {
  setBusy(event.currentTarget, true, 'Backing up…');
  try { await api('/api/admin/backups/run', { method: 'POST', body: { provider: $('#backup-provider').value } }); toast('Backup completed.'); await loadOperations(); }
  catch (error) { toast(error.message, 'error'); }
  finally { setBusy(event.currentTarget, false); }
});

$('#backup-list').addEventListener('click', async (event) => {
  const button = event.target.closest('[data-restore-backup]');
  if (!button) return;
  const item = button.closest('[data-backup-id]');
  const password = await requestAction({ title: 'Stage full SHAM restore?', message: 'This restores the entire SHAM data snapshot on the next process restart. SHAM creates a fresh safety backup before staging the restore. Confirm your password to continue.', confirmLabel: 'Stage restore', danger: true, inputLabel: 'Password', inputType: 'password', autocomplete: 'current-password' });
  if (!password) return;
  setBusy(button, true, 'Staging…');
  try {
    const result = await api(`/api/admin/backups/${item.dataset.backupId}/restore`, { method: 'POST', body: { password } });
    toast(`${result.message} Safety backup: ${result.safetyBackup?.filename || 'created'}.`, 'warning');
    await loadOperations();
  } catch (error) { toast(error.message, 'error'); }
  finally { setBusy(button, false); }
});

$('#clear-prometheus-token').addEventListener('change', (event) => {
  $('#prometheus-token').disabled = event.currentTarget.checked;
  if (event.currentTarget.checked) $('#prometheus-token').value = '';
});
$('#add-otel-header').addEventListener('click', () => addOtelHeaderRow());
$('#clear-otel-headers').addEventListener('change', (event) => {
  $('#add-otel-header').disabled = event.currentTarget.checked;
  $$('#otel-header-rows input').forEach((input) => { input.disabled = event.currentTarget.checked; });
});
$('#copy-metrics-url').addEventListener('click', async () => {
  try {
    await navigator.clipboard.writeText(`${location.origin}/metrics`);
    toast('Metrics URL copied. Configure your scraper with the saved bearer token.');
  } catch { toast(`Metrics URL: ${location.origin}/metrics`, 'warning'); }
});

$('#observability-form').addEventListener('submit', async (event) => {
  event.preventDefault();
  const button = $('#observability-form button[type="submit"]');
  setBusy(button, true, 'Saving…');
  try {
    const clearPrometheusToken = $('#clear-prometheus-token').checked;
    const prometheusToken = $('#prometheus-token').value.trim();
    const tokenConfigured = $('#prometheus-token-status').dataset.configured === '1';
    if ($('#prometheus-enabled').checked && (clearPrometheusToken || (!tokenConfigured && !prometheusToken))) throw new Error('Set a metrics token before enabling the Prometheus endpoint.');
    const clearOtelHeaders = $('#clear-otel-headers').checked;
    const otelHeaders = {};
    if (!clearOtelHeaders) {
      for (const row of $$('.otel-header-row', $('#otel-header-rows'))) {
        const name = $('[data-otel-header-name]', row).value.trim();
        const value = $('[data-otel-header-value]', row).value;
        if (!name && !value) continue;
        if (!name) throw new Error('Each OpenTelemetry header needs a name.');
        otelHeaders[name] = value;
      }
    }
    await api('/api/admin/operations/settings', { method: 'PUT', body: {
      prometheusEnabled: $('#prometheus-enabled').checked,
      prometheusToken: prometheusToken || undefined,
      clearPrometheusToken,
      otelEndpoint: $('#otel-endpoint').value,
      otelHeaders: Object.keys(otelHeaders).length ? otelHeaders : undefined,
      clearOtelHeaders,
      publicStatusEnabled: $('#public-status-enabled').checked,
      publicStatusTitle: $('#public-status-title').value,
      locale: $('#instance-locale').value,
      updateChannel: $('#update-channel').value,
      setupCompleted: true
    } });
    $('#prometheus-token').value = ''; applyLocale($('#instance-locale').value); toast('Observability settings saved.'); await loadOperations();
  } catch (error) { toast(error.message, 'error'); }
  finally { setBusy(button, false); }
});

$('#add-database-profile').addEventListener('click', async () => {
  const name = await requestAction({ title: 'New database profile', message: 'Create an encrypted reusable connection profile.', confirmLabel: 'Next', inputLabel: 'Profile name', placeholder: 'Production PostgreSQL' });
  if (!name) return;
  const connection = await requestAction({ title: 'Connection value', message: 'The value is encrypted at rest and never returned by the API.', confirmLabel: 'Next', inputLabel: 'Connection string', inputType: 'password', autocomplete: 'new-password', placeholder: 'postgres://…' });
  if (!connection) return;
  const envKey = await requestAction({ title: 'Environment variable', message: 'Choose the variable name exposed to attached sites.', confirmLabel: 'Create profile', inputLabel: 'Variable name', inputValue: 'DATABASE_URL' });
  if (!envKey) return;
  try { await api('/api/admin/database-profiles', { method: 'POST', body: { name, type: 'custom', envKey, connection } }); toast('Database profile created.'); await loadOperations(); }
  catch (error) { toast(error.message, 'error'); }
});
$('#database-profile-list').addEventListener('click', async (event) => {
  const button = event.target.closest('[data-database-delete]');
  if (!button || !(await requestAction({ title: 'Delete database profile?', message: 'It will be detached from every site. The hosted databases are not modified.', confirmLabel: 'Delete profile', danger: true }))) return;
  try { await api(`/api/admin/database-profiles/${button.dataset.databaseDelete}`, { method: 'DELETE' }); toast('Database profile deleted.'); await loadOperations(); }
  catch (error) { toast(error.message, 'error'); }
});

$('#add-alert-destination').addEventListener('click', () => {
  $('#alert-destination-form').reset();
  $('#alert-destination-kind').value = 'webhook';
  $('#alert-header-rows').innerHTML = '';
  $('#alert-destination-error').textContent = '';
  updateAlertDestinationFields();
  showModal($('#alert-destination-dialog'));
});
$('#alert-destination-kind').addEventListener('change', updateAlertDestinationFields);
$('#add-alert-header').addEventListener('click', () => addAlertHeaderRow());
$('#alert-destination-form').addEventListener('submit', async (event) => {
  event.preventDefault();
  const form = event.currentTarget;
  const button = $('button[type="submit"]', form);
  const name = $('#alert-destination-name').value.trim();
  const kind = $('#alert-destination-kind').value;
  const target = $('#alert-destination-target').value.trim();
  const config = kind === 'email'
    ? { to: target, from: $('#alert-destination-from').value.trim(), sendmail: $('#alert-destination-sendmail').value.trim() }
    : { url: target, headers: {} };
  if (kind !== 'email') {
    const seen = new Set();
    for (const row of $$('.alert-header-row', $('#alert-header-rows'))) {
      const header = $('[data-alert-header-name]', row).value.trim();
      const value = $('[data-alert-header-value]', row).value;
      if (!header && !value) continue;
      if (!header || !value) { $('#alert-destination-error').textContent = 'Each alert header needs both a name and a value.'; return; }
      const normalized = header.toLowerCase();
      if (seen.has(normalized)) { $('#alert-destination-error').textContent = `Header “${header}” is duplicated.`; return; }
      seen.add(normalized);
      config.headers[header] = value;
    }
  }
  $('#alert-destination-error').textContent = '';
  setBusy(button, true, 'Saving…');
  try {
    await api('/api/admin/alert-destinations', { method: 'POST', body: { name, kind, config, enabled: true } });
    $('#alert-destination-dialog').close();
    toast('Alert destination saved.');
    await loadOperations();
  } catch (error) { $('#alert-destination-error').textContent = error.message; }
  finally { setBusy(button, false); }
});
$('#alert-destination-list').addEventListener('click', async (event) => {
  const test = event.target.closest('[data-alert-test]');
  const remove = event.target.closest('[data-alert-delete]');
  if (test) {
    setBusy(test, true, 'Sending…');
    try { await api(`/api/admin/alert-destinations/${test.dataset.alertTest}/test`, { method: 'POST' }); toast('Test alert sent.'); }
    catch (error) { toast(error.message, 'error'); }
    finally { setBusy(test, false); }
  } else if (remove && await requestAction({ title: 'Delete alert destination?', message: 'Future alerts will no longer be delivered there.', confirmLabel: 'Delete destination', danger: true })) {
    try { await api(`/api/admin/alert-destinations/${remove.dataset.alertDelete}`, { method: 'DELETE' }); toast('Alert destination deleted.'); await loadOperations(); }
    catch (error) { toast(error.message, 'error'); }
  }
});

$('#update-form').addEventListener('submit', async (event) => {
  event.preventDefault();
  const file = $('#update-archive').files[0];
  if (!file) return;
  const formData = new FormData(); formData.append('archive', file, file.name); formData.append('allowUnsigned', String($('#update-allow-unsigned').checked));
  const button = $('#update-form button[type="submit"]');
  setBusy(button, true, 'Validating…');
  try { const result = await api('/api/admin/update', { method: 'POST', body: formData }); toast(result.message, 'warning'); $('#update-archive').value = ''; $('#update-allow-unsigned').checked = false; await loadOperations(); }
  catch (error) { toast(error.message, 'error'); }
  finally { setBusy(button, false); }
});
$('#cancel-update').addEventListener('click', async () => {
  try { await api('/api/admin/update', { method: 'DELETE' }); toast('Staged update cancelled.'); await loadOperations(); }
  catch (error) { toast(error.message, 'error'); }
});

$('#setup-open-security').addEventListener('click', () => { $('#setup-dialog').close(); showSection('security'); });
$('#setup-open-operations').addEventListener('click', () => { $('#setup-dialog').close(); showSection('operations'); });
$('#setup-finish').addEventListener('click', async (event) => {
  setBusy(event.currentTarget, true, 'Saving…');
  try {
    await api('/api/admin/operations/settings', { method: 'PUT', body: { setupCompleted: true } });
    state.bootstrap.setupCompleted = true;
    $('#setup-dialog').close();
    toast('Initial setup marked complete. The readiness checklist remains available under Operations.');
  } catch (error) { toast(error.message, 'error'); }
  finally { setBusy(event.currentTarget, false); }
});
