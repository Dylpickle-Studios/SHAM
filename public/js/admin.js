'use strict';

function addPluginTrustedKeyRow(key = {}) {
  const row = document.createElement('div');
  row.className = 'config-row trusted-key-row';
  row.innerHTML = `<label><span>Publisher ID</span><input data-trusted-key-id maxlength="120" value="${escapeHtml(key.id || '')}" placeholder="publisher"></label>
    <label><span>Name</span><input data-trusted-key-name maxlength="200" value="${escapeHtml(key.name || '')}" placeholder="Publisher name"></label>
    <label class="config-row-wide"><span>Ed25519 public key (PEM)</span><textarea data-trusted-key-pem rows="4" placeholder="-----BEGIN PUBLIC KEY-----…">${escapeHtml(key.publicKey || '')}</textarea></label>
    <button class="icon-button danger-text" data-remove-config-row type="button" aria-label="Remove trusted publisher key">×</button>`;
  $('[data-remove-config-row]', row).addEventListener('click', () => row.remove());
  $('#plugin-trusted-key-rows').append(row);
}

function renderPluginTrustedKeys(keys = []) {
  $('#plugin-trusted-key-rows').innerHTML = '';
  for (const key of keys) addPluginTrustedKeyRow(key);
}

function updateOidcUiState() {
  const enabled = $('#oidc-enabled').checked;
  const autoProvision = $('#oidc-auto-provision').checked;
  $('#oidc-issuer').required = enabled;
  $('#oidc-client-id').required = enabled;
  $('#oidc-auto-provision').disabled = !enabled;
  $('#oidc-default-role').disabled = !enabled || !autoProvision;
}

function collectPluginTrustedKeys() {
  return $$('.trusted-key-row', $('#plugin-trusted-key-rows')).map((row) => ({
    id: $('[data-trusted-key-id]', row).value.trim(),
    name: $('[data-trusted-key-name]', row).value.trim(),
    publicKey: $('[data-trusted-key-pem]', row).value.trim()
  })).filter((key) => key.id || key.name || key.publicKey);
}

async function loadAdmin() {
  if (state.user.role !== 'admin') return;
  const requestId = ++state.adminRequest;
  const button = $('#refresh-users');
  setBusy(button, true, 'Refreshing…');
  try {
    const [settings, users] = await Promise.all([api('/api/admin/settings'), api('/api/admin/users')]);
    if (requestId !== state.adminRequest) return;
    const integrations = settings.integrations;
    $('#cloudflare-zone').value = integrations.cloudflareZoneId || '';
    $('#cloudflare-ip').value = integrations.cloudflareTargetIp || '';
    $('#certbot-email').value = integrations.certbotEmail || '';
    $('#cloudflare-reconcile-enabled').checked = Boolean(integrations.cloudflareReconcileEnabled);
    $('#cloudflare-reconcile-minutes').value = integrations.cloudflareReconcileMinutes || 15;
    $('#cloudflare-tunnel-account').value = integrations.cloudflareTunnelAccountId || '';
    $('#cloudflare-tunnel-api-token').value = '';
    $('#clear-cloudflare-tunnel-api-token').checked = false;
    $('#cloudflare-tunnel-api-token').disabled = false;
    $('#cloudflare-tunnel-api-token-status').textContent = integrations.cloudflareTunnelApiTokenConfigured ? 'A separate Tunnel management token is currently saved.' : 'No Tunnel management token is saved.';
    $('#cloudflare-token').value = '';
    $('#clear-cloudflare-token').checked = false;
    $('#cloudflare-token').disabled = false;
    $('#cloudflare-token-status').textContent = integrations.cloudflareTokenConfigured ? 'A token is currently saved.' : 'No token is saved.';
    const oidc = settings.oidc || {};
    $('#oidc-enabled').checked = Boolean(oidc.enabled);
    $('#oidc-issuer').value = oidc.issuer || '';
    $('#oidc-client-id').value = oidc.clientId || '';
    $('#oidc-client-secret').value = '';
    $('#oidc-clear-secret').checked = false;
    $('#oidc-client-secret').disabled = false;
    $('#oidc-auto-provision').checked = Boolean(oidc.autoProvision);
    $('#oidc-default-role').value = oidc.defaultRole || 'user';
    $('#oidc-secret-status').textContent = oidc.clientSecretConfigured ? 'A client secret is saved.' : 'No client secret is saved (public-client OIDC is allowed).';
    updateOidcUiState();
    const security = settings.security || {};
    $('#visitor-privacy').value = security.visitorPrivacyMode || 'mask';
    $('#log-retention').value = security.logRetentionDays || 30;
    $('#alert-cpu').value = security.alertCpuPercent || 90;
    $('#alert-loop').value = security.alertEventLoopMs || 250;
    $('#alert-disk').value = security.alertDiskPercent || 90;
    $('#alert-traffic').value = security.alertTrafficMultiplier || 5;
    $('#alert-errors').value = security.alertErrorPercent || 25;
    $('#allow-unsigned-plugins').checked = Boolean(security.allowUnsignedPlugins);
    renderPluginTrustedKeys(security.pluginTrustedKeys || []);
    const edge = security.edge || {};
    $('#edge-status').textContent = edge.enabled
      ? `Shared edge proxy: HTTP ${edge.httpRunning ? `listening on ${edge.host}:${edge.httpPort}` : 'not listening'} · HTTPS ${edge.httpsRunning ? `listening on ${edge.host}:${edge.httpsPort}` : edge.httpsNeedsCertificate ? 'waiting for an installed certificate' : 'not configured'}.`
      : 'Shared edge proxy is disabled. Set SHAM_EDGE_HTTP_PORT and/or SHAM_EDGE_HTTPS_PORT to publish domain-routed sites through common ports.';
    $('#rotate-master-key').disabled = Boolean(security.masterKeyExternal);
    $('#rotate-master-key').title = security.masterKeyExternal ? 'Rotation is controlled by SHAM_MASTER_KEY.' : '';
    renderUsers(users.users);
  } catch (error) { if (requestId === state.adminRequest) toast(error.message, 'error'); }
  finally { if (requestId === state.adminRequest) setBusy(button, false); }
}

function renderUsers(users) {
  $('#users-table').innerHTML = users.map((user) => `<tr data-user-id="${user.id}">
    <td><div class="table-user"><span class="table-avatar">${escapeHtml(user.username.slice(0,1).toUpperCase())}</span>${escapeHtml(user.username)}${user.id === state.user.id ? ' (you)' : ''}</div></td>
    <td><select data-field="role" ${user.id === state.user.id ? 'disabled' : ''}><option value="user" ${user.role === 'user' ? 'selected' : ''}>User</option><option value="admin" ${user.role === 'admin' ? 'selected' : ''}>Admin</option></select></td>
    <td><label class="switch-row"><span>${user.active ? 'Active' : 'Disabled'}</span><input data-field="active" type="checkbox" ${user.active ? 'checked' : ''} ${user.id === state.user.id ? 'disabled' : ''}><span class="switch"></span></label></td>
    <td>${escapeHtml(formatDate(user.createdAt))}</td>
    <td><div class="site-actions"><button class="button secondary" data-user-action="save" type="button">Save</button><button class="button ghost" data-user-action="revoke-sessions" type="button" ${user.id === state.user.id ? 'disabled' : ''}>Revoke sessions</button><button class="button danger" data-user-action="delete" type="button" ${user.id === state.user.id ? 'disabled' : ''}>Delete</button></div></td>
  </tr>`).join('');
}

$('#add-plugin-trusted-key').addEventListener('click', () => addPluginTrustedKeyRow());

$('#admin-create-user-form').addEventListener('submit', async (event) => {
  event.preventDefault();
  const button = $('#admin-create-user-form button[type="submit"]');
  setBusy(button, true, 'Creating…');
  try {
    await api('/api/admin/users', { method: 'POST', body: {
      username: $('#admin-create-username').value,
      password: $('#admin-create-password').value,
      role: $('#admin-create-role').value
    } });
    $('#admin-create-user-form').reset();
    $('#admin-create-role').value = 'user';
    toast('Dashboard user created.');
    await loadAdmin();
  } catch (error) { toast(error.message, 'error'); }
  finally {
    $('#admin-create-password').value = '';
    setBusy(button, false);
  }
});

$('#clear-cloudflare-token').addEventListener('change', (event) => {
  $('#cloudflare-token').disabled = event.target.checked;
  if (event.target.checked) $('#cloudflare-token').value = '';
});

$('#clear-cloudflare-tunnel-api-token').addEventListener('change', (event) => {
  $('#cloudflare-tunnel-api-token').disabled = event.target.checked;
  if (event.target.checked) $('#cloudflare-tunnel-api-token').value = '';
});

$('#oidc-enabled').addEventListener('change', updateOidcUiState);
$('#oidc-auto-provision').addEventListener('change', updateOidcUiState);

$('#oidc-clear-secret').addEventListener('change', (event) => {
  $('#oidc-client-secret').disabled = event.target.checked;
  if (event.target.checked) $('#oidc-client-secret').value = '';
});

$('#oidc-form').addEventListener('submit', async (event) => {
  event.preventDefault();
  const button = $('#oidc-form button[type="submit"]');
  setBusy(button, true, 'Saving…');
  try {
    const result = await api('/api/admin/settings/oidc', { method: 'PUT', body: {
      enabled: $('#oidc-enabled').checked,
      issuer: $('#oidc-issuer').value,
      clientId: $('#oidc-client-id').value,
      clientSecret: $('#oidc-client-secret').value,
      clearClientSecret: $('#oidc-clear-secret').checked,
      autoProvision: $('#oidc-auto-provision').checked,
      defaultRole: $('#oidc-default-role').value
    } });
    $('#oidc-client-secret').value = '';
    $('#oidc-clear-secret').checked = false;
    $('#oidc-client-secret').disabled = false;
    $('#oidc-secret-status').textContent = result.oidc.clientSecretConfigured ? 'A client secret is saved.' : 'No client secret is saved (public-client OIDC is allowed).';
    if (state.bootstrap) state.bootstrap.oidcEnabled = Boolean(result.oidc.enabled && result.oidc.issuer && result.oidc.clientId);
    toast('OIDC settings saved.');
  } catch (error) { toast(error.message, 'error'); }
  finally { setBusy(button, false); }
});

$('#integrations-form').addEventListener('submit', async (event) => {
  event.preventDefault();
  const button = $('#integrations-form button[type="submit"]');
  setBusy(button, true, 'Saving…');
  try {
    const result = await api('/api/admin/settings/integrations', {
      method: 'PUT',
      body: {
        cloudflareApiToken: $('#cloudflare-token').value,
        clearCloudflareToken: $('#clear-cloudflare-token').checked,
        cloudflareTunnelAccountId: $('#cloudflare-tunnel-account').value,
        cloudflareTunnelApiToken: $('#cloudflare-tunnel-api-token').value,
        clearCloudflareTunnelApiToken: $('#clear-cloudflare-tunnel-api-token').checked,
        cloudflareZoneId: $('#cloudflare-zone').value,
        cloudflareTargetIp: $('#cloudflare-ip').value,
        certbotEmail: $('#certbot-email').value,
        cloudflareReconcileEnabled: $('#cloudflare-reconcile-enabled').checked,
        cloudflareReconcileMinutes: Number($('#cloudflare-reconcile-minutes').value || 15)
      }
    });
    $('#cloudflare-token').value = '';
    $('#clear-cloudflare-token').checked = false;
    $('#cloudflare-token').disabled = false;
    $('#cloudflare-token-status').textContent = result.integrations.cloudflareTokenConfigured ? 'A token is currently saved.' : 'No token is saved.';
    $('#cloudflare-tunnel-api-token').value = '';
    $('#clear-cloudflare-tunnel-api-token').checked = false;
    $('#cloudflare-tunnel-api-token').disabled = false;
    $('#cloudflare-tunnel-api-token-status').textContent = result.integrations.cloudflareTunnelApiTokenConfigured ? 'A separate Tunnel management token is currently saved.' : 'No Tunnel management token is saved.';
    toast('Integration settings saved.');
  } catch (error) { toast(error.message, 'error'); }
  finally { setBusy(button, false); }
});

$('#renew-certificates').addEventListener('click', async (event) => {
  setBusy(event.target, true, 'Renewing…');
  try {
    const result = await api('/api/admin/certificates/renew', { method: 'POST' });
    toast(result.warning || result.message, result.warning ? 'warning' : 'success');
    await loadSites();
  } catch (error) { toast(error.message, 'error'); }
  finally { setBusy(event.target, false); }
});

$('#users-table').addEventListener('click', async (event) => {
  const button = event.target.closest('[data-user-action]');
  if (!button) return;
  const row = button.closest('[data-user-id]');
  const id = Number(row.dataset.userId);
  const action = button.dataset.userAction;
  if (action === 'delete' && !(await requestAction({ title: 'Delete this user?', message: 'This dashboard account will permanently lose access.', confirmLabel: 'Delete user', danger: true }))) return;
  if (action === 'revoke-sessions' && !(await requestAction({ title: 'Revoke this user’s browser sessions?', message: 'All of this user’s current dashboard sessions will be invalidated. API tokens are not affected.', confirmLabel: 'Revoke sessions', danger: true }))) return;
  setBusy(button, true, action === 'save' ? 'Saving…' : action === 'revoke-sessions' ? 'Revoking…' : 'Deleting…');
  try {
    if (action === 'save') {
      await api(`/api/admin/users/${id}`, { method: 'PATCH', body: { role: $('[data-field="role"]', row).value, active: $('[data-field="active"]', row).checked } });
      toast('User updated. Access changes revoke existing browser sessions.');
    } else if (action === 'revoke-sessions') {
      await api(`/api/admin/users/${id}/revoke-sessions`, { method: 'POST' });
      toast('User browser sessions revoked.');
    } else {
      await api(`/api/admin/users/${id}`, { method: 'DELETE' });
      toast('User deleted.');
    }
    await loadAdmin();
  } catch (error) { toast(error.message, 'error'); setBusy(button, false); }
});

$('#refresh-users').addEventListener('click', loadAdmin);
