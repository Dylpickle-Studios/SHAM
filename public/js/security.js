'use strict';

function showRecoveryCodes(codes) {
  $('#recovery-codes').textContent = (codes || []).join('\n');
  showModal($('#recovery-dialog'));
}

function clearTransientSecuritySecrets() {
  $('#recovery-codes').textContent = '';
  $('#api-token-value').textContent = '';
  $('#current-password').value = '';
  $('#new-password').value = '';
  $('#confirm-new-password').value = '';
  if ($('#totp-content')?.querySelector('.totp-setup')) $('#totp-content').innerHTML = '';
}

function hasLocalSecurityPassword() {
  return state.security?.user?.hasLocalPassword !== false;
}

function focusLocalPasswordSetup() {
  $('#local-password-status')?.scrollIntoView({ behavior: 'smooth', block: 'center' });
  requestAnimationFrame(() => $('#new-password')?.focus());
}

async function requestSecurityPassword(options) {
  if (!hasLocalSecurityPassword()) {
    toast('Set a local password below before using password-confirmed security actions.', 'warning');
    focusLocalPasswordSetup();
    return null;
  }
  return requestAction({ ...options, inputLabel: 'Password', inputType: 'password', autocomplete: 'current-password' });
}

function renderSecurity(data) {
  state.security = data;
  const enabled = Boolean(data.user?.totpEnabled);
  $('#totp-status').textContent = enabled ? 'Enabled' : 'Disabled';
  $('#totp-status').className = `badge ${enabled ? 'success' : ''}`;
  $('#recovery-summary').textContent = enabled ? `${formatNumber(data.recoveryCodesRemaining)} unused recovery code${data.recoveryCodesRemaining === 1 ? '' : 's'} remain.` : 'Enable TOTP to create recovery codes.';
  $('#regenerate-recovery').disabled = !enabled;
  $('#totp-content').innerHTML = enabled
    ? '<p class="muted">Your account requires an authenticator or recovery code after password login.</p><button class="button danger" data-totp-action="disable" type="button">Disable TOTP</button>'
    : '<p class="muted">Compatible with standard authenticator applications.</p><button class="button primary" data-totp-action="setup" type="button">Set up authenticator</button>';
  $('#passkey-list').innerHTML = data.passkeys?.length ? data.passkeys.map((key) => `<div class="event-item actionable" data-passkey-id="${key.id}"><span class="event-icon">⌾</span><div><strong>${escapeHtml(key.name)}</strong><p>${key.lastUsedAt ? `Last used ${escapeHtml(formatDate(key.lastUsedAt))}` : 'Not used yet'} · added ${escapeHtml(formatDate(key.createdAt))}</p></div><button class="button danger" data-delete-passkey type="button">Delete</button></div>`).join('') : '<div class="empty-state compact"><p>No passkeys are registered.</p></div>';
  $('#api-token-list').innerHTML = data.apiTokens?.length ? data.apiTokens.map((token) => `<div class="event-item actionable" data-api-token-id="${token.id}"><span class="event-icon">⌁</span><div><strong>${escapeHtml(token.name)}</strong><p>${escapeHtml((token.scopes || []).join(', '))}${token.expiresAt ? ` · expires ${escapeHtml(formatDate(token.expiresAt))}` : ' · no expiry'}${token.lastUsedAt ? ` · last used ${escapeHtml(formatDate(token.lastUsedAt))}` : ''}</p></div><button class="button danger" data-delete-api-token type="button">Revoke</button></div>`).join('') : '<div class="empty-state compact"><p>No API tokens have been created.</p></div>';
  const hasLocalPassword = data.user?.hasLocalPassword !== false;
  $('#current-password-field').hidden = !hasLocalPassword;
  $('#current-password').required = hasLocalPassword;
  $('#password-change-submit').textContent = hasLocalPassword ? 'Change password' : 'Set local password';
  $('#local-password-status').textContent = hasLocalPassword
    ? 'Change the password used for local sign-in and sensitive confirmations. Changing it signs out other browser sessions.'
    : 'This SSO-provisioned account does not have a usable local password yet. Set one here before password-confirmed security and administration actions.';
}
function passkeyEnrollmentAvailable() {
  return Boolean(window.isSecureContext && window.PublicKeyCredential && navigator.credentials?.create);
}

function updatePasskeyAvailability() {
  const button = $('#add-passkey');
  const available = passkeyEnrollmentAvailable();
  button.disabled = !available;
  button.title = available ? '' : 'Passkeys require a secure HTTPS context and browser WebAuthn support.';
  $('#passkey-context-notice').hidden = available;
}

async function loadSecurity() {
  const requestId = ++state.securityRequest;
  const button = $('#refresh-security');
  setBusy(button, true, 'Refreshing…');
  try {
    const data = await api('/api/security');
    if (requestId === state.securityRequest) {
      renderSecurity(data);
      updatePasskeyAvailability();
    }
  } catch (error) {
    if (requestId === state.securityRequest) toast(error.message, 'error');
  } finally {
    if (requestId === state.securityRequest) setBusy(button, false);
  }
}
$('#refresh-security').addEventListener('click', loadSecurity);
$('#create-api-token').addEventListener('click', async (event) => {
  const eventTarget = event.currentTarget;
  const name = await requestAction({ title: 'Create API token', message: 'Name this token for the machine or workflow that will use it.', confirmLabel: 'Continue', inputLabel: 'Token name', placeholder: 'Deployment CLI' });
  if (!name) return;
  const password = await requestSecurityPassword({ title: 'Confirm API token creation', message: 'Confirm your password. The new token will have read, logs, deployment, and site-control scopes.', confirmLabel: 'Create token' });
  if (!password) return;
  setBusy(eventTarget, true, 'Creating…');
  try {
    const result = await api('/api/security/api-tokens', { method: 'POST', body: { name, password, scopes: ['read', 'logs:read', 'deploy', 'sites:control'] } });
    $('#api-token-value').textContent = result.token;
    showModal($('#api-token-dialog'));
    await loadSecurity();
  } catch (error) { toast(error.message, 'error'); }
  finally { setBusy(eventTarget, false); }
});
$('#api-token-list').addEventListener('click', async (event) => {
  const button = event.target.closest('[data-delete-api-token]');
  if (!button) return;
  const item = button.closest('[data-api-token-id]');
  const password = await requestSecurityPassword({ title: 'Revoke this API token?', message: 'Confirm your password. Any CLI or CI job using this token will immediately lose access.', confirmLabel: 'Revoke token', danger: true });
  if (!password) return;
  try { await api(`/api/security/api-tokens/${item.dataset.apiTokenId}`, { method: 'DELETE', body: { password } }); toast('API token revoked.'); await loadSecurity(); }
  catch (error) { toast(error.message, 'error'); }
});
$('#copy-api-token').addEventListener('click', async () => {
  try { await navigator.clipboard.writeText($('#api-token-value').textContent); toast('API token copied.'); }
  catch { toast('Could not access the clipboard. Copy the token manually.', 'warning'); }
});
$('#totp-content').addEventListener('click', async (event) => {
  const button = event.target.closest('[data-totp-action]');
  if (!button) return;
  try {
    if (button.dataset.totpAction === 'setup') {
      const password = await requestSecurityPassword({ title: 'Set up TOTP', message: 'Confirm your current password before adding a new authenticator.', confirmLabel: 'Continue' });
      if (!password) return;
      const setup = await api('/api/security/totp/setup', { method: 'POST', body: { password } });
      $('#totp-content').innerHTML = `<div class="totp-setup"><label><span>Secret</span><input value="${escapeHtml(setup.secret)}" readonly></label><label><span>Setup URI</span><textarea rows="3" readonly>${escapeHtml(setup.otpauthUrl)}</textarea></label><label><span>Current six-digit code</span><input id="totp-setup-code" inputmode="numeric" autocomplete="one-time-code" maxlength="8"></label><div class="inline-actions"><button class="button primary" data-enable-totp data-setup-id="${escapeHtml(setup.setupId)}" type="button">Verify and enable</button><button class="button ghost" data-cancel-totp type="button">Cancel</button></div></div>`;
      $('#totp-setup-code').focus();
    } else {
      const password = await requestSecurityPassword({ title: 'Disable TOTP?', message: 'Confirm your password. This reduces account protection.', confirmLabel: 'Disable TOTP', danger: true });
      if (!password) return;
      await api('/api/security/totp/disable', { method: 'POST', body: { password } });
      toast('TOTP disabled.', 'warning');
      await loadSecurity();
    }
  } catch (error) { toast(error.message, 'error'); }
});
$('#totp-content').addEventListener('click', async (event) => {
  const enable = event.target.closest('[data-enable-totp]');
  if (event.target.closest('[data-cancel-totp]')) return loadSecurity();
  if (!enable) return;
  setBusy(enable, true, 'Verifying…');
  try {
    const result = await api('/api/security/totp/enable', { method: 'POST', body: { setupId: enable.dataset.setupId, code: $('#totp-setup-code').value } });
    state.user = result.user;
    showRecoveryCodes(result.recoveryCodes);
    await loadSecurity();
  } catch (error) { toast(error.message, 'error'); setBusy(enable, false); }
});
$('#regenerate-recovery').addEventListener('click', async () => {
  const password = await requestSecurityPassword({ title: 'Regenerate recovery codes?', message: 'All existing recovery codes will stop working.', confirmLabel: 'Regenerate', danger: true });
  if (!password) return;
  try { const result = await api('/api/security/recovery-codes/regenerate', { method: 'POST', body: { password } }); showRecoveryCodes(result.recoveryCodes); await loadSecurity(); }
  catch (error) { toast(error.message, 'error'); }
});
$('#copy-recovery-codes').addEventListener('click', async () => {
  try { await navigator.clipboard.writeText($('#recovery-codes').textContent); toast('Recovery codes copied.'); }
  catch { toast('Could not access the clipboard. Copy the codes manually.', 'warning'); }
});
$('#add-passkey').addEventListener('click', async (event) => {
  const eventTarget = event.currentTarget;
  const name = await requestAction({ title: 'Add a passkey', message: 'Choose a recognizable name for this device or security key.', confirmLabel: 'Continue', inputLabel: 'Passkey name', placeholder: 'Laptop, phone, security key' });
  if (!name) return;
  const password = await requestSecurityPassword({ title: 'Confirm passkey enrollment', message: 'Confirm your current password before registering the new passkey.', confirmLabel: 'Register passkey' });
  if (!password) return;
  setBusy(eventTarget, true, 'Waiting…');
  try {
    if (!navigator.credentials?.create) throw new Error('Passkeys require a supported browser and secure context.');
    const challenge = await api('/api/security/passkeys/options', { method: 'POST', body: { password } });
    const credential = await navigator.credentials.create({ publicKey: publicKeyOptions(challenge.options) });
    await api('/api/security/passkeys/register', { method: 'POST', body: { challengeId: challenge.challengeId, name, credential: serializeCredential(credential) } });
    toast('Passkey added.');
    await loadSecurity();
  } catch (error) { toast(error.name === 'NotAllowedError' ? 'Passkey creation was cancelled or timed out.' : error.message, 'error'); }
  finally { setBusy(eventTarget, false); }
});
$('#passkey-list').addEventListener('click', async (event) => {
  const button = event.target.closest('[data-delete-passkey]');
  if (!button) return;
  const item = button.closest('[data-passkey-id]');
  const password = await requestSecurityPassword({ title: 'Delete this passkey?', message: 'Confirm your password. This credential will no longer sign in to SHAM.', confirmLabel: 'Delete passkey', danger: true });
  if (!password) return;
  try { await api(`/api/security/passkeys/${item.dataset.passkeyId}`, { method: 'DELETE', body: { password } }); await loadSecurity(); toast('Passkey deleted.'); }
  catch (error) { toast(error.message, 'error'); }
});

$('#password-change-form').addEventListener('submit', async (event) => {
  event.preventDefault();
  const button = $('#password-change-submit');
  const currentPassword = $('#current-password').value;
  const newPassword = $('#new-password').value;
  const confirmation = $('#confirm-new-password').value;
  $('#password-change-error').textContent = '';
  if (newPassword !== confirmation) {
    $('#password-change-error').textContent = 'New passwords do not match.';
    $('#confirm-new-password').focus();
    return;
  }
  setBusy(button, true, hasLocalSecurityPassword() ? 'Changing…' : 'Setting…');
  try {
    const result = await api('/api/security/password', { method: 'PUT', body: { currentPassword, newPassword } });
    state.user = result.user;
    $('#current-password').value = '';
    $('#new-password').value = '';
    $('#confirm-new-password').value = '';
    toast(result.sessionsRevoked ? 'Password updated. Other browser sessions were signed out.' : 'Password updated.');
    await loadSecurity();
  } catch (error) { $('#password-change-error').textContent = error.message; }
  finally { setBusy(button, false); }
});

$('#revoke-other-sessions').addEventListener('click', async (event) => {
  const eventTarget = event.currentTarget;
  const password = hasLocalSecurityPassword()
    ? await requestSecurityPassword({ title: 'Sign out other sessions?', message: 'Confirm your password. Other browser sessions for this account will be invalidated immediately.', confirmLabel: 'Sign out other sessions', danger: true })
    : '';
  if (hasLocalSecurityPassword() && !password) return;
  setBusy(eventTarget, true, 'Revoking…');
  try {
    const result = await api('/api/security/sessions/revoke-others', { method: 'POST', body: { password } });
    state.user = result.user;
    toast('Other browser sessions signed out.');
  } catch (error) { toast(error.message, 'error'); }
  finally { setBusy(eventTarget, false); }
});

$('#recovery-dialog').addEventListener('close', () => { $('#recovery-codes').textContent = ''; });
$('#api-token-dialog').addEventListener('close', () => { $('#api-token-value').textContent = ''; });

let toolsSite = null;
function siteToolsRequestIsCurrent(site, requestId) {
  return Boolean(site && toolsSite?.id === site.id && requestId === state.siteToolsRequest);
}
function selectSiteTool(name, { focus = false } = {}) {
  const tabs = $$('[data-site-tool-tab]');
  const activeTab = tabs.find((button) => button.dataset.siteToolTab === name) || tabs[0];
  for (const button of tabs) {
    const active = button === activeTab;
    button.classList.toggle('active', active);
    button.setAttribute('aria-selected', String(active));
    button.tabIndex = active ? 0 : -1;
  }
  $('#site-tools-snapshots').hidden = activeTab.dataset.siteToolTab !== 'snapshots';
  $('#site-tools-dependencies').hidden = activeTab.dataset.siteToolTab !== 'dependencies';
  if (focus) activeTab.focus();
}
function renderSnapshots(snapshots) {
  $('#snapshot-list').innerHTML = snapshots.length ? snapshots.map((item) => `<div class="event-item actionable" data-snapshot-id="${item.id}"><span class="event-icon">↶</span><div><strong>${escapeHtml(item.label || `Snapshot ${item.id}`)}</strong><p>${formatBytes(item.bytes)} · ${escapeHtml(formatDate(item.createdAt))}</p></div><div class="inline-actions"><button class="button secondary" data-restore-snapshot type="button">Restore</button><button class="button danger" data-delete-snapshot type="button">Delete</button></div></div>`).join('') : '<div class="empty-state compact"><p>No snapshots yet.</p></div>';
}
async function loadSnapshots(site = toolsSite) {
  if (!site) return;
  const sessionId = state.siteToolsRequest;
  const requestId = ++state.siteToolsSnapshotRequest;
  try {
    const data = await api(`/api/sites/${site.id}/snapshots`);
    if (siteToolsRequestIsCurrent(site, sessionId) && requestId === state.siteToolsSnapshotRequest) renderSnapshots(data.snapshots || []);
  } catch (error) {
    if (siteToolsRequestIsCurrent(site, sessionId) && requestId === state.siteToolsSnapshotRequest) toast(error.message, 'error');
  }
}
function renderDependencyReport(result) {
  if (!result) { $('#dependency-report').innerHTML = '<div class="empty-state compact"><p>No dependency scan has run for this site.</p></div>'; return; }
  const vulnerabilities = result.vulnerabilities || {};
  const findings = result.findings || [];
  $('#dependency-report').innerHTML = `<div class="stats-grid compact-stats"><article class="stat-card"><span>Critical</span><strong>${formatNumber(vulnerabilities.critical)}</strong></article><article class="stat-card"><span>High</span><strong>${formatNumber(vulnerabilities.high)}</strong></article><article class="stat-card"><span>Moderate</span><strong>${formatNumber(vulnerabilities.moderate)}</strong></article><article class="stat-card"><span>Total</span><strong>${formatNumber(vulnerabilities.total)}</strong></article></div><p class="notice ${result.registryAvailable ? '' : 'warning'}">${result.registryAvailable ? `npm audit completed using ${escapeHtml(result.lockfile || 'the lockfile')}.` : `Registry audit was unavailable: ${escapeHtml(result.registryError || 'No lockfile is present.')}`}</p><div class="event-list">${findings.length ? findings.map((finding) => `<div class="event-item ${escapeHtml(finding.severity)}"><span class="event-icon">△</span><div><strong>${escapeHtml(finding.code)}</strong><p>${escapeHtml(finding.message)}</p></div></div>`).join('') : '<div class="empty-state compact"><p>No static dependency warnings.</p></div>'}</div><small class="muted">Scanned ${escapeHtml(formatDate(result.scannedAt))}</small>`;
}
async function openSiteTools(site) {
  toolsSite = site;
  const sessionId = ++state.siteToolsRequest;
  const snapshotRequestId = ++state.siteToolsSnapshotRequest;
  const dependencyRequestId = ++state.siteToolsDependencyRequest;
  $('#site-tools-id').value = site.id;
  $('#site-tools-title').textContent = `${site.name} safety tools`;
  $('#snapshot-list').innerHTML = '<div class="empty-state compact"><p>Loading snapshots…</p></div>';
  $('#dependency-report').innerHTML = '<div class="empty-state compact"><p>Loading the latest scan…</p></div>';
  $('#run-dependency-scan').disabled = site.runtime_type === 'proxy';
  selectSiteTool('snapshots');
  showModal($('#site-tools-dialog'));
  const [snapshots, scan] = await Promise.allSettled([api(`/api/sites/${site.id}/snapshots`), api(`/api/sites/${site.id}/dependency-scan`)]);
  if (!siteToolsRequestIsCurrent(site, sessionId)) return;
  if (snapshotRequestId === state.siteToolsSnapshotRequest) {
    if (snapshots.status === 'fulfilled') renderSnapshots(snapshots.value.snapshots || []);
    else { renderSnapshots([]); toast(snapshots.reason.message, 'error'); }
  }
  if (dependencyRequestId === state.siteToolsDependencyRequest) {
    if (scan.status === 'fulfilled') renderDependencyReport(scan.value.result);
    else { renderDependencyReport(null); toast(scan.reason.message, 'error'); }
  }
}
$$('[data-site-tool-tab]').forEach((button) => {
  button.addEventListener('click', () => selectSiteTool(button.dataset.siteToolTab));
  button.addEventListener('keydown', (event) => {
    if (!['ArrowLeft', 'ArrowRight', 'Home', 'End'].includes(event.key)) return;
    event.preventDefault();
    const tabs = $$('[data-site-tool-tab]');
    const current = tabs.indexOf(button);
    const target = event.key === 'Home' ? tabs[0]
      : event.key === 'End' ? tabs.at(-1)
        : tabs[(current + (event.key === 'ArrowRight' ? 1 : -1) + tabs.length) % tabs.length];
    selectSiteTool(target.dataset.siteToolTab, { focus: true });
  });
});
$('#site-tools-dialog').addEventListener('close', () => {
  state.siteToolsRequest += 1;
  toolsSite = null;
});
$('#create-snapshot').addEventListener('click', async (event) => {
  const eventTarget = event.currentTarget;
  const label = await requestAction({ title: 'Create snapshot', message: 'Choose a short label for this restore point.', confirmLabel: 'Create snapshot', inputLabel: 'Label', placeholder: 'Before deployment' });
  const site = toolsSite;
  if (!label || !site) return;
  setBusy(eventTarget, true, 'Creating…');
  try {
    await api(`/api/sites/${site.id}/snapshots`, { method: 'POST', body: { label } });
    if (toolsSite?.id === site.id) await loadSnapshots(site);
    toast(`Snapshot created for ${site.name}.`);
  } catch (error) { toast(error.message, 'error'); }
  finally { setBusy(eventTarget, false); }
});
$('#snapshot-list').addEventListener('click', async (event) => {
  const item = event.target.closest('[data-snapshot-id]');
  const site = toolsSite;
  if (!item || !site) return;
  if (event.target.closest('[data-restore-snapshot]')) {
    if (!(await requestAction({ title: 'Restore this snapshot?', message: 'SHAM creates an automatic rollback point, replaces the project files, and restarts the runtime.', confirmLabel: 'Restore snapshot', danger: true }))) return;
    try {
      const result = await api(`/api/sites/${site.id}/snapshots/${item.dataset.snapshotId}/restore`, { method: 'POST' });
      toast(result.warning ? `Snapshot restored. ${result.warning}` : `Snapshot restored. Rollback point ${result.rollbackSnapshot.id} was retained.`, result.warning ? 'warning' : 'success');
      await Promise.all([toolsSite?.id === site.id ? loadSnapshots(site) : Promise.resolve(), loadSites()]);
    } catch (error) { toast(error.message, 'error'); }
  } else if (event.target.closest('[data-delete-snapshot]')) {
    if (!(await requestAction({ title: 'Delete this snapshot?', message: 'This restore point will be permanently removed.', confirmLabel: 'Delete snapshot', danger: true }))) return;
    try {
      await api(`/api/sites/${site.id}/snapshots/${item.dataset.snapshotId}`, { method: 'DELETE' });
      if (toolsSite?.id === site.id) await loadSnapshots(site);
    } catch (error) { toast(error.message, 'error'); }
  }
});
$('#run-dependency-scan').addEventListener('click', async (event) => {
  const eventTarget = event.currentTarget;
  const site = toolsSite;
  if (!site) return;
  const sessionId = state.siteToolsRequest;
  const requestId = ++state.siteToolsDependencyRequest;
  setBusy(eventTarget, true, 'Scanning…');
  try {
    const data = await api(`/api/sites/${site.id}/dependency-scan`, { method: 'POST' });
    if (!siteToolsRequestIsCurrent(site, sessionId) || requestId !== state.siteToolsDependencyRequest) return;
    renderDependencyReport(data.result);
    toast('Dependency scan completed.');
  } catch (error) {
    if (siteToolsRequestIsCurrent(site, sessionId) && requestId === state.siteToolsDependencyRequest) toast(error.message, 'error');
  } finally { setBusy(eventTarget, false); }
});

$('#security-settings-form').addEventListener('submit', async (event) => {
  event.preventDefault();
  const button = $('#security-settings-form button[type="submit"]');
  setBusy(button, true, 'Saving…');
  try {
    const result = await api('/api/admin/settings/security', { method: 'PUT', body: {
      visitorPrivacyMode: $('#visitor-privacy').value,
      logRetentionDays: Number($('#log-retention').value),
      alertCpuPercent: Number($('#alert-cpu').value),
      alertEventLoopMs: Number($('#alert-loop').value),
      alertDiskPercent: Number($('#alert-disk').value),
      alertTrafficMultiplier: Number($('#alert-traffic').value),
      alertErrorPercent: Number($('#alert-errors').value),
      allowUnsignedPlugins: $('#allow-unsigned-plugins').checked,
      pluginTrustedKeys: collectPluginTrustedKeys()
    } });
    renderPluginTrustedKeys(result.security.pluginTrustedKeys || []);
    toast('Security settings saved.');
  } catch (error) { toast(error.message, 'error'); }
  finally { setBusy(button, false); }
});
$('#rotate-master-key').addEventListener('click', async () => {
  const password = await requestAction({ title: 'Rotate the encryption key?', message: 'SHAM re-encrypts saved integration, plugin, and TOTP secrets. Keep a storage backup before continuing.', confirmLabel: 'Rotate key', danger: true, inputLabel: 'Password', inputType: 'password', autocomplete: 'current-password' });
  if (!password) return;
  try { await api('/api/admin/security/rotate-master-key', { method: 'POST', body: { password } }); toast('Master encryption key rotated.'); }
  catch (error) { toast(error.message, 'error'); }
});
