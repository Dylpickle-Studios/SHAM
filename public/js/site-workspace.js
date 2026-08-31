'use strict';

function currentWorkspaceSite() {
  return state.sites.find((item) => item.id === Number(state.siteWorkspaceId)) || null;
}

function renderWorkspaceOverview(site) {
  const protocol = site.runtime.protocol || (site.ssl_enabled ? 'https' : 'http');
  const runtimeLabels = { static: 'Static', node: 'Node.js', process: 'Managed process', container: 'OCI container', compose: 'Docker Compose', proxy: 'Reverse proxy' };
  const entry = site.runtime_type === 'proxy' ? site.proxy_target
    : site.runtime_type === 'node' ? site.node_entry
      : site.runtime_type === 'static' ? site.entry_file
        : site.runtime_type === 'compose' ? `${site.compose_file || 'compose.yaml'} · ${site.compose_service || 'app'}`
          : site.start_command || site.container_image || site.runtime_preset || 'Managed runtime';
  $('#site-workspace-overview').innerHTML = `<div class="workspace-overview-grid">
    <article class="workspace-fact"><span>Runtime</span><strong>${escapeHtml(runtimeLabels[site.runtime_type] || site.runtime_type)}</strong></article>
    <article class="workspace-fact"><span>Listener</span><code>${escapeHtml(site.bind_host)}:${site.port}</code></article>
    <article class="workspace-fact"><span>Entry / upstream</span><code>${escapeHtml(entry || '—')}</code></article>
    <article class="workspace-fact"><span>Deployment</span><strong>${site.git_url ? `Git · ${escapeHtml(site.git_branch || 'main')}` : site.runtime_type === 'proxy' ? 'Proxy configuration' : 'Upload'}</strong></article>
    <article class="workspace-fact"><span>Build</span><code>${escapeHtml(site.build_command || 'No build command')}</code></article>
    <article class="workspace-fact"><span>Protection</span><strong>${site.firewall_enabled ? 'Firewall on' : 'Firewall off'} · ${site.ssl_enabled ? 'TLS on' : protocol.toUpperCase()}</strong></article>
  </div><div class="operations-grid"><article class="panel"><h2>Delivery</h2><p class="muted">${site.git_url ? `Repository: ${escapeHtml(site.git_url)}` : 'This site is not connected to a Git repository.'}</p><p>${site.release_mode ? 'Atomic release directories and rollback points are enabled.' : 'Direct deployment mode is enabled.'}</p></article><article class="panel"><h2>Health</h2><p class="muted">${site.runtime.error ? escapeHtml(site.runtime.error) : site.runtime.running ? 'Runtime is running without a reported startup error.' : 'Runtime is stopped.'}</p></article></div>`;
}

function renderWorkspaceNetworking(site) {
  $('#site-workspace-networking').innerHTML = `<div class="operations-grid"><article class="panel"><h2>Listener & domain</h2><div class="workspace-overview-grid"><div class="workspace-fact"><span>Bind</span><code>${escapeHtml(site.bind_host)}:${site.port}</code></div><div class="workspace-fact"><span>Domain</span><strong>${escapeHtml(site.domain || 'Not configured')}</strong></div><div class="workspace-fact"><span>Edge proxy</span><strong>${site.edge_enabled ? 'Enabled' : 'Disabled'}</strong></div></div></article><article class="panel"><h2>Cloudflare & TLS</h2><p>${site.cloudflare_enabled ? 'Cloudflare DNS is enabled.' : 'Cloudflare DNS is not enabled.'}</p><p>${site.cloudflareTunnel?.enabled ? `Tunnel ${site.cloudflareTunnel.connected ? 'is connected' : 'is enabled but offline'}.` : 'No per-site tunnel is enabled.'}</p><button class="button secondary" data-workspace-edit type="button">Edit networking</button></article></div>`;
}

function renderWorkspaceSecurity(site) {
  const blocked = site.firewall?.blockedIps || [];
  $('#site-workspace-security').innerHTML = `<div class="operations-grid"><article class="panel"><div class="panel-heading"><div><h2>Site firewall</h2><p class="muted">Use visitor intelligence on the Dashboard to add abusive scraper or LLM IPs here.</p></div><span class="badge">${site.firewall_enabled ? 'Enabled' : 'Disabled'}</span></div><div class="event-list">${blocked.length ? blocked.map((ip) => `<div class="event-item"><span class="event-icon">⊘</span><div><strong>${escapeHtml(ip)}</strong><p>Blocked locally</p></div><button class="button ghost" data-unban-ip="${escapeHtml(ip)}" type="button">Unban</button></div>`).join('') : '<div class="empty-state compact"><p>No IP addresses are blocked for this site.</p></div>'}</div></article><article class="panel"><h2>Security posture</h2><p>${site.domain_only ? 'Direct requests using other Host headers are rejected.' : 'Domain-only mode is disabled.'}</p><p>${site.security_preset === 'strict' ? 'Strict security headers are enabled.' : `Security header preset: ${escapeHtml(site.security_preset || 'balanced')}.`}</p><button class="button secondary" data-workspace-edit type="button">Edit security</button></article></div>`;
}

function renderWorkspaceDeployments(deployments) {
  const site = currentWorkspaceSite();
  $('#workspace-deployment-list').innerHTML = deployments.length ? deployments.map((item) => {
    const commitLabel = item.commitSha ? `<code>${escapeHtml(String(item.commitSha).slice(0, 9))}</code>` : '';
    const commit = item.commitUrl ? `<a href="${escapeHtml(item.commitUrl)}" target="_blank" rel="noopener" title="Open commit in provider">${commitLabel}</a> ` : commitLabel ? `${commitLabel} ` : '';
    const message = item.commitMessage || item.detail || item.ref || 'Deployment';
    const author = item.commitAuthor ? ` · ${escapeHtml(item.commitAuthor)}` : '';
    const duration = item.durationMs ? ` · ${(Number(item.durationMs) / 1000).toFixed(1)}s` : '';
    const activeStatus = item.status === 'running' || item.status === 'deployed-with-warning';
    const active = item.activeRelease || activeStatus
      ? `<span class="badge ${item.status === 'deployed-with-warning' ? 'warning' : 'success'}">${item.status === 'deployed-with-warning' ? 'Active · warning' : 'Active'}</span>`
      : '';
    const actions = state.user?.role === 'admin' ? `<div class="deployment-actions"><button class="button ghost compact-button" data-deployment-logs type="button">View logs${item.logCount ? ` (${item.logCount})` : ''}</button>${site?.git_url ? '<button class="button ghost compact-button" data-deployment-redeploy type="button">Redeploy</button>' : ''}${item.releaseId ? `<button class="button ghost compact-button" data-deployment-rollback="${item.releaseId}" type="button">Roll back</button>` : ''}</div>` : '';
    return `<article class="deployment-row" data-deployment-id="${item.id}" data-deployment-ref="${escapeHtml(item.ref || '')}"><span class="deployment-status ${escapeHtml(item.status)}" aria-label="${escapeHtml(item.status)}"></span><div class="deployment-main"><strong>${commit}${escapeHtml(message)}</strong><span class="muted">${escapeHtml(item.source || 'deployment')}${author}</span>${actions}</div><div class="deployment-meta">${active}${escapeHtml(formatDate(item.finishedAt || item.startedAt))}${duration}</div></article>`;
  }).join('') : '<div class="empty-state compact"><p>No deployments have been recorded yet.</p></div>';
}

function workspaceRequestIsCurrent(site, requestId, kind) {
  const currentId = kind === 'deployments' ? state.siteWorkspaceDeploymentsRequest : state.siteWorkspaceLogsRequest;
  return Number(state.siteWorkspaceId) === Number(site?.id) && requestId === currentId;
}

async function loadWorkspaceDeployments(site) {
  const requestId = ++state.siteWorkspaceDeploymentsRequest;
  try {
    const data = await api(`/api/sites/${site.id}/deployments?limit=50`);
    if (workspaceRequestIsCurrent(site, requestId, 'deployments')) renderWorkspaceDeployments(data.deployments || []);
  } catch (error) {
    if (workspaceRequestIsCurrent(site, requestId, 'deployments')) $('#workspace-deployment-list').innerHTML = `<p class="form-error">${escapeHtml(error.message)}</p>`;
  }
}

async function loadWorkspaceDeploymentLogs(site, deploymentId) {
  const requestId = ++state.siteWorkspaceLogsRequest;
  $('#workspace-log-list').innerHTML = '<div class="empty-state compact"><p>Loading deployment logs…</p></div>';
  try {
    const data = await api(`/api/sites/${site.id}/deployments/${deploymentId}/logs?limit=1000`);
    if (!workspaceRequestIsCurrent(site, requestId, 'logs')) return;
    $('#workspace-log-list').innerHTML = data.logs?.length ? `<div class="notice">Showing logs attached to deployment #${deploymentId}. Use Refresh logs to return to the complete runtime log.</div>` + data.logs.map((row) => `<div class="event-item ${escapeHtml(row.level || '')}"><span class="event-icon">${row.level === 'error' ? '!' : '·'}</span><div><strong>${escapeHtml(row.message)}</strong><p>${escapeHtml(formatDate(row.createdAt))}</p></div></div>`).join('') : '<div class="empty-state compact"><p>No logs were attached to this deployment.</p></div>';
  } catch (error) {
    if (workspaceRequestIsCurrent(site, requestId, 'logs')) $('#workspace-log-list').innerHTML = `<p class="form-error">${escapeHtml(error.message)}</p>`;
  }
}

async function loadWorkspaceLogs(site) {
  const requestId = ++state.siteWorkspaceLogsRequest;
  $('#workspace-log-list').innerHTML = '<div class="empty-state compact"><p>Loading logs…</p></div>';
  try {
    const data = await api(`/api/runtime-logs?siteId=${site.id}&limit=150`);
    if (!workspaceRequestIsCurrent(site, requestId, 'logs')) return;
    $('#workspace-log-list').innerHTML = data.logs?.length ? data.logs.map((row) => `<div class="event-item ${escapeHtml(row.level || '')}"><span class="event-icon">${row.level === 'error' ? '!' : '·'}</span><div><strong>${escapeHtml(row.message)}</strong><p>${escapeHtml(formatDate(row.createdAt))}</p></div></div>`).join('') : '<div class="empty-state compact"><p>No runtime logs have been recorded.</p></div>';
  } catch (error) {
    if (workspaceRequestIsCurrent(site, requestId, 'logs')) $('#workspace-log-list').innerHTML = `<p class="form-error">${escapeHtml(error.message)}</p>`;
  }
}

function selectWorkspaceTab(tab, { load = true, focus = false } = {}) {
  const site = currentWorkspaceSite();
  if (!site) return;
  state.siteWorkspaceTab = tab;
  $$('[data-site-workspace-tab]').forEach((button) => {
    const active = button.dataset.siteWorkspaceTab === tab;
    button.classList.toggle('active', active);
    button.setAttribute('aria-selected', String(active));
    button.tabIndex = active ? 0 : -1;
    if (active && focus) button.focus();
  });
  $$('.workspace-panel').forEach((panel) => { panel.hidden = panel.id !== `site-workspace-${tab}`; });
  if (load && tab === 'deployments') loadWorkspaceDeployments(site);
  if (load && tab === 'logs') loadWorkspaceLogs(site);
  if (tab === 'networking') renderWorkspaceNetworking(site);
  if (tab === 'security') renderWorkspaceSecurity(site);
}

function openSiteWorkspace(site, tab = 'overview') {
  state.siteWorkspaceDeploymentsRequest += 1;
  state.siteWorkspaceLogsRequest += 1;
  state.siteWorkspaceId = site.id;
  const url = siteDisplayUrl(site);
  $('#site-workspace-title').textContent = site.name;
  $('#site-workspace-url').textContent = url;
  $('#site-workspace-open').dataset.url = url;
  const status = $('#site-workspace-status');
  status.textContent = site.runtime.error ? 'Error' : site.runtime.running ? 'Running' : 'Stopped';
  status.className = `status-pill ${site.runtime.error ? 'error' : site.runtime.running ? 'running' : ''}`;
  $('#site-workspace-restart').hidden = !site.runtime.running || site.runtime_type === 'static';
  $('#site-workspace-install').hidden = !((site.runtime_type === 'node' && site.runtime_isolation !== 'docker') || (site.runtime_type === 'process' && ['node', 'npm'].includes(site.runtime_preset)));
  renderWorkspaceOverview(site);
  showSection('site-workspace', { refresh: false });
  selectWorkspaceTab(tab);
}

$$('[data-site-workspace-tab]').forEach((button) => {
  button.addEventListener('click', () => selectWorkspaceTab(button.dataset.siteWorkspaceTab));
  button.addEventListener('keydown', (event) => {
    if (!['ArrowLeft', 'ArrowRight', 'Home', 'End'].includes(event.key)) return;
    event.preventDefault();
    const tabs = $$('[data-site-workspace-tab]');
    const current = tabs.indexOf(button);
    const next = event.key === 'Home' ? tabs[0]
      : event.key === 'End' ? tabs.at(-1)
        : tabs[(current + (event.key === 'ArrowRight' ? 1 : -1) + tabs.length) % tabs.length];
    selectWorkspaceTab(next.dataset.siteWorkspaceTab, { focus: true });
  });
});
$('#site-workspace-back').addEventListener('click', () => showSection('sites'));
$('#site-workspace-open').addEventListener('click', () => window.open($('#site-workspace-open').dataset.url, '_blank', 'noopener'));
$('#site-workspace-restart').addEventListener('click', async (event) => { const site = currentWorkspaceSite(); if (site) await handleSiteAction(site, 'restart', event.currentTarget); });
$('#site-workspace-install').addEventListener('click', async (event) => { const site = currentWorkspaceSite(); if (site) await handleSiteAction(site, 'install-fresh', event.currentTarget); });
$('#workspace-refresh-logs').addEventListener('click', () => { const site = currentWorkspaceSite(); if (site) loadWorkspaceLogs(site); });
$('#workspace-open-files').addEventListener('click', () => { const site = currentWorkspaceSite(); if (site) openFiles(site); });
$('#workspace-edit-site').addEventListener('click', () => { const site = currentWorkspaceSite(); if (site) openEditSite(site); });
$('#site-workspace-networking').addEventListener('click', (event) => { if (event.target.closest('[data-workspace-edit]')) { const site = currentWorkspaceSite(); if (site) openEditSite(site); } });
$('#site-workspace-security').addEventListener('click', async (event) => {
  const edit = event.target.closest('[data-workspace-edit]');
  if (edit) { const site = currentWorkspaceSite(); if (site) openEditSite(site); return; }
  const button = event.target.closest('[data-unban-ip]');
  const site = currentWorkspaceSite();
  if (!button || !site) return;
  try { await api(`/api/sites/${site.id}/firewall/ban-ip`, { method: 'DELETE', body: { ip: button.dataset.unbanIp } }); await loadSites(); openSiteWorkspace(state.sites.find((item) => item.id === site.id), 'security'); toast(`${button.dataset.unbanIp} unblocked.`); }
  catch (error) { toast(error.message, 'error'); }
});
$('#workspace-deploy').addEventListener('click', async (event) => {
  const site = currentWorkspaceSite();
  if (!site?.git_url) return toast('Connect a Git repository in Site settings first.', 'warning');
  setBusy(event.currentTarget, true, 'Deploying…');
  try { const result = await api(`/api/sites/${site.id}/deploy/git`, { method: 'POST', body: {} }); toast(result.warning || (result.webhook ? `Git deployment activated; ${result.webhook.provider} webhook ${result.webhook.action}.` : 'Git deployment activated.'), result.warning ? 'warning' : 'success'); await Promise.all([loadSites(), loadWorkspaceDeployments(site)]); }
  catch (error) { toast(error.message, 'error'); }
  finally { setBusy(event.currentTarget, false); }
});
$('#workspace-deployment-list').addEventListener('click', async (event) => {
  const site = currentWorkspaceSite();
  if (!site) return;
  const row = event.target.closest('[data-deployment-id]');
  if (!row) return;
  if (event.target.closest('[data-deployment-logs]')) {
    selectWorkspaceTab('logs', { load: false });
    return loadWorkspaceDeploymentLogs(site, Number(row.dataset.deploymentId));
  }
  const redeploy = event.target.closest('[data-deployment-redeploy]');
  if (redeploy) {
    setBusy(redeploy, true, 'Deploying…');
    try {
      const result = await api(`/api/sites/${site.id}/deploy/git`, { method: 'POST', body: { branch: row.dataset.deploymentRef || site.git_branch || 'main' } });
      toast(result.warning || (result.webhook ? `Git deployment activated; ${result.webhook.provider} webhook ${result.webhook.action}.` : 'Git deployment activated.'), result.warning ? 'warning' : 'success');
      await Promise.all([loadSites(), loadWorkspaceDeployments(site)]);
    } catch (error) { toast(error.message, 'error'); }
    finally { setBusy(redeploy, false); }
    return;
  }
  const rollback = event.target.closest('[data-deployment-rollback]');
  if (!rollback) return;
  if (!(await requestAction({ title: 'Roll back this release?', message: 'SHAM will atomically switch this site back to the selected retained release.', confirmLabel: 'Roll back' }))) return;
  setBusy(rollback, true, 'Rolling back…');
  try {
    const result = await api(`/api/sites/${site.id}/releases/${rollback.dataset.deploymentRollback}/rollback`, { method: 'POST' });
    toast(result.warning || 'Release rollback activated.', result.warning ? 'warning' : 'success');
    await Promise.all([loadSites(), loadWorkspaceDeployments(site)]);
  } catch (error) { toast(error.message, 'error'); }
  finally { setBusy(rollback, false); }
});

async function handleSiteAction(site, action, button) {
  if (action === 'workspace') return openSiteWorkspace(site);
  if (action === 'pin') {
    try { await api(`/api/sites/${site.id}/pin`, { method: 'PATCH', body: { pinned: !site.pinned } }); await loadSites(); }
    catch (error) { toast(error.message, 'error'); }
    return;
  }
  if (action === 'edit') return openEditSite(site);
  if (action === 'content') return openContent(site);
  if (action === 'files') return openFiles(site);
  if (action === 'tools') return openSiteTools(site);
  if (action === 'operations') { state.operationsSiteId = site.id; showSection('operations'); return; }
  if (action === 'delete') {
    if (!(await requestAction({ title: `Delete ${site.name}?`, message: 'This permanently removes the site configuration and every stored project file.', confirmLabel: 'Delete site', danger: true }))) return;
    setBusy(button, true, 'Deleting…');
    try {
      await api(`/api/sites/${site.id}`, { method: 'DELETE' });
      toast('Site deleted.');
      await Promise.all([loadSites(), loadOverview()]);
    } catch (error) { toast(error.message, 'error'); setBusy(button, false); }
    return;
  }
  if (action === 'install-fresh' && !(await requestAction({ title: 'Reinstall production dependencies?', message: 'SHAM will stop the site if needed, remove node_modules, run npm ci when a lockfile exists (otherwise npm install), then restart it. A rollback snapshot is created first.', confirmLabel: 'Fresh install', danger: true }))) return;
  const labels = { toggle: site.runtime.running ? 'Stopping…' : 'Starting…', restart: 'Restarting…', 'install-fresh': 'Installing…', cloudflare: 'Syncing DNS…', 'cloudflare-firewall': 'Syncing firewall…', certificate: 'Issuing…', 'certificate-wildcard': 'Issuing wildcard…' };
  setBusy(button, true, labels[action] || 'Working…');
  try {
    if (action === 'toggle') await api(`/api/sites/${site.id}/toggle`, { method: 'PATCH', body: { enabled: !site.runtime.running } });
    if (action === 'restart') await api(`/api/sites/${site.id}/restart`, { method: 'POST' });
    if (action === 'install-fresh') {
      const result = await api(`/api/sites/${site.id}/npm-install`, { method: 'POST', body: { fresh: true } });
      const snapshotNote = result.rollbackSnapshot ? ` Rollback snapshot #${result.rollbackSnapshot.id} was retained.` : '';
      toast(`${result.warning || result.message}${snapshotNote}`, result.warning ? 'warning' : 'success');
    }
    if (action === 'cloudflare') {
      const result = await api(`/api/admin/sites/${site.id}/cloudflare`, { method: 'POST' });
      toast(result.warning || `Cloudflare proxy enabled for ${result.record.name}.`, result.warning ? 'warning' : 'success');
    }
    if (action === 'cloudflare-firewall') {
      const result = await api(`/api/admin/sites/${site.id}/cloudflare-firewall`, { method: 'POST' });
      toast(result.message || 'Cloudflare firewall synchronized.');
    }
    if (action === 'certificate' || action === 'certificate-wildcard') {
      const wildcard = action === 'certificate-wildcard';
      if (wildcard && !(await requestAction({ title: 'Issue wildcard certificate?', message: `This requests both ${site.domain} and *.${site.domain} using Cloudflare DNS validation.`, confirmLabel: 'Issue wildcard' }))) return;
      const result = await api(`/api/admin/sites/${site.id}/certificate`, { method: 'POST', body: { wildcard } });
      toast(result.warning || result.message, result.warning ? 'warning' : 'success');
    }
    await Promise.all([loadSites(), loadOverview()]);
  } catch (error) { toast(error.message, 'error'); }
  finally { setBusy(button, false); }
}

$('#site-grid').addEventListener('click', async (event) => {
  const menuTrigger = event.target.closest('[data-action-menu]');
  if (menuTrigger) {
    const card = menuTrigger.closest('[data-site-id]');
    const site = state.sites.find((item) => item.id === Number(card?.dataset.siteId));
    if (site) openSiteActionMenu(menuTrigger, site);
    return;
  }
  const button = event.target.closest('[data-action]');
  if (!button) return;
  const card = button.closest('[data-site-id]');
  const site = state.sites.find((item) => item.id === Number(card?.dataset.siteId));
  if (site) await handleSiteAction(site, button.dataset.action, button);
});

$('#site-action-menu').addEventListener('click', async (event) => {
  const button = event.target.closest('[data-action]');
  if (!button) return;
  const site = state.sites.find((item) => item.id === Number($('#site-action-menu').dataset.siteId));
  const trigger = siteMenuTrigger;
  closeSiteActionMenu();
  if (site) await handleSiteAction(site, button.dataset.action, trigger || button);
});

$('#site-action-menu').addEventListener('toggle', (event) => {
  if (event.newState === 'closed' && $('#site-action-menu').dataset.open === '1') closeSiteActionMenu();
});

$('#site-action-menu').addEventListener('keydown', (event) => {
  const buttons = $$('[role="menuitem"]', event.currentTarget);
  const index = buttons.indexOf(document.activeElement);
  if (event.key === 'Escape') {
    event.preventDefault();
    closeSiteActionMenu({ restoreFocus: true });
  } else if (event.key === 'ArrowDown' && buttons.length) {
    event.preventDefault();
    buttons[(index + 1 + buttons.length) % buttons.length].focus();
  } else if (event.key === 'ArrowUp' && buttons.length) {
    event.preventDefault();
    buttons[(index - 1 + buttons.length) % buttons.length].focus();
  }
});

document.addEventListener('click', (event) => {
  if (event.target.closest('#site-action-menu, [data-action-menu]')) return;
  closeSiteActionMenu();
});

let siteMenuPositionFrame = null;
function refreshSiteActionMenuPosition() {
  if (!siteMenuTrigger || $('#site-action-menu').dataset.open !== '1') return;
  if (siteMenuPositionFrame) cancelAnimationFrame(siteMenuPositionFrame);
  siteMenuPositionFrame = requestAnimationFrame(() => {
    siteMenuPositionFrame = null;
    if (!siteMenuTrigger?.isConnected) return closeSiteActionMenu();
    const box = siteMenuTrigger.getBoundingClientRect();
    if (box.bottom <= 0 || box.top >= window.innerHeight || box.right <= 0 || box.left >= window.innerWidth) {
      closeSiteActionMenu();
      return;
    }
    positionSiteActionMenu(siteMenuTrigger);
  });
}
window.addEventListener('resize', refreshSiteActionMenuPosition);
$('.workspace').addEventListener('scroll', refreshSiteActionMenuPosition, { passive: true });

$('#site-firewall-enabled').addEventListener('change', (event) => {
  if (event.target.checked) $('#firewall-options').open = true;
  updateFirewallFields();
});
$('#site-firewall-mode').addEventListener('change', updateFirewallFields);

function updateFirewallFields() {
  const enabled = $('#site-firewall-enabled').checked;
  const mode = $('#site-firewall-mode').value;
  const local = enabled && ['local', 'both'].includes(mode);
  const cloudflare = enabled && ['cloudflare', 'both'].includes(mode);
  ['#site-firewall-rate', '#site-firewall-body', '#site-firewall-bots'].forEach((selector) => { $(selector).disabled = !local; });
  $('#site-firewall-action').disabled = !cloudflare;
}
$('#site-domain-only').addEventListener('change', (event) => {
  if (event.target.checked && !$('#site-domain').value.trim()) {
    toast('Enter a domain before enabling domain-only access.', 'warning');
    $('#site-domain').focus();
  }
});
