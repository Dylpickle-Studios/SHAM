'use strict';

async function loadSites() {
  if (!state.user) return;
  const requestId = ++state.siteListRequest;
  const refreshButton = $('#refresh-sites');
  setBusy(refreshButton, true, 'Refreshing…');
  try {
    const result = await api('/api/sites');
    if (requestId !== state.siteListRequest) return;
    state.sites = result.sites;
    renderSites();
  } catch (error) {
    if (requestId === state.siteListRequest) toast(error.message, 'error');
  } finally {
    if (requestId === state.siteListRequest) setBusy(refreshButton, false);
  }
}

function renderSites() {
  closeSiteActionMenu();
  const grid = $('#site-grid');
  const empty = $('#empty-sites');
  empty.hidden = state.sites.length > 0;
  grid.hidden = state.sites.length === 0;
  const running = state.sites.filter((site) => site.runtime.running).length;
  $('#site-summary').textContent = `${state.sites.length} configured · ${running} running`;
  grid.innerHTML = state.sites.map((site) => {
    const statusClass = site.runtime.error ? 'error' : site.runtime.running ? 'running' : '';
    const statusText = site.runtime.error ? 'Error' : site.runtime.running ? 'Running' : 'Stopped';
    const protocol = site.runtime.protocol || (site.ssl_enabled ? 'https' : 'http');
    const displayUrl = siteDisplayUrl(site);
    return `<article class="site-card" data-site-id="${site.id}">
      <div class="site-card-head"><div class="site-title"><div class="site-title-line"><button class="site-title-button" data-action="workspace" type="button"><h2>${escapeHtml(site.name)}</h2></button><button class="pin-button ${site.pinned ? 'active' : ''}" data-action="pin" type="button" aria-pressed="${Boolean(site.pinned)}" aria-label="${site.pinned ? 'Unpin' : 'Pin'} ${escapeHtml(site.name)}" title="${site.pinned ? 'Unpin site' : 'Pin site'}">★</button></div><a href="${escapeHtml(displayUrl)}" target="_blank" rel="noopener">${escapeHtml(displayUrl)}</a></div><span class="status-pill ${statusClass}">${statusText}</span></div>
      <div class="site-meta">
        <div class="meta-cell"><span>Runtime</span><strong>${escapeHtml(({ static: 'Static', node: 'Node.js compatibility', process: 'Managed process', container: 'Container', compose: 'Docker Compose', proxy: 'Reverse proxy' })[site.runtime_type] || site.runtime_type)}${site.runtime_preset ? ` · ${escapeHtml(site.runtime_preset)}` : ''}${site.minify ? ' · Minified' : ''}${site.obfuscate ? ' · Obfuscated' : ''}</strong></div>
        <div class="meta-cell"><span>Listener</span><strong>${escapeHtml(site.bind_host)}:${site.port}</strong></div>
        <div class="meta-cell"><span>Entry</span><strong>${escapeHtml(site.runtime_type === 'node' ? site.node_entry : site.runtime_type === 'proxy' ? site.proxy_target : site.runtime_type === 'static' ? site.entry_file : site.runtime_type === 'compose' ? `${site.compose_file} · ${site.compose_service}` : site.start_command || site.container_image || site.runtime_preset || 'managed runtime')}</strong></div>
        <div class="meta-cell"><span>Protection</span><strong>${site.domain_only ? 'Domain only · ' : ''}${site.firewall_enabled ? `${escapeHtml(site.firewall?.mode || 'local')} firewall · ` : ''}${site.cloudflareTunnel?.enabled ? `Tunnel ${site.cloudflareTunnel.connected ? 'online' : 'enabled'} · ` : ''}${site.cloudflare_enabled ? 'Cloudflare DNS · ' : ''}${site.ssl_enabled ? 'SSL' : protocol.toUpperCase()}</strong></div>
      </div>
      ${site.runtime.error ? `<p class="site-error">${escapeHtml(site.runtime.error)}</p>` : ''}
      <div class="site-actions">
        <button class="button ${site.runtime.running ? 'danger' : 'primary'}" data-action="toggle" type="button">${site.runtime.running ? 'Stop' : 'Start'}</button>
        ${site.runtime_type !== 'static' && site.runtime_type !== 'proxy' && site.runtime.running ? '<button class="button secondary" data-action="restart" type="button">Restart</button>' : ''}
        <button class="button secondary" data-action="files" type="button">Files</button>
        <button class="button secondary site-menu-trigger" data-action-menu type="button" aria-haspopup="menu" aria-expanded="false">More</button>
      </div>
    </article>`;
  }).join('');
}

function siteActionButtons(site) {
  return `<button data-action="workspace" type="button" role="menuitem">Open workspace</button>
    <button data-action="edit" type="button" role="menuitem">Site settings</button>
    <button data-action="content" type="button" role="menuitem">Replace all files</button>
    <button data-action="tools" type="button" role="menuitem">Snapshots & security scan</button>
    ${state.user.role === 'admin' ? '<button data-action="operations" type="button" role="menuitem">Deployment operations</button>' : ''}
    ${((site.runtime_type === 'node' && site.runtime_isolation !== 'docker') || (site.runtime_type === 'process' && ['node', 'npm'].includes(site.runtime_preset))) ? '<button data-action="install-fresh" type="button" role="menuitem">Fresh npm install</button>' : ''}
    ${state.user.role === 'admin' && site.domain ? '<button data-action="cloudflare" type="button" role="menuitem">Sync Cloudflare DNS</button><button data-action="cloudflare-firewall" type="button" role="menuitem">Sync Cloudflare firewall</button><button data-action="certificate" type="button" role="menuitem">Issue / renew SSL</button><button data-action="certificate-wildcard" type="button" role="menuitem">Issue wildcard SSL</button>' : ''}
    <button class="danger-text" data-action="delete" type="button" role="menuitem">Delete site</button>`;
}

let siteMenuTrigger = null;
function closeSiteActionMenu({ restoreFocus = false } = {}) {
  const menu = $('#site-action-menu');
  if (menu.dataset.open !== '1') return;
  menu.dataset.open = '0';
  if (typeof menu.hidePopover === 'function') {
    try { menu.hidePopover(); } catch { menu.hidden = true; }
  } else menu.hidden = true;
  if (siteMenuTrigger) {
    siteMenuTrigger.setAttribute('aria-expanded', 'false');
    if (restoreFocus && siteMenuTrigger.isConnected) siteMenuTrigger.focus();
  }
  siteMenuTrigger = null;
}

function positionSiteActionMenu(trigger) {
  const menu = $('#site-action-menu');
  const triggerBox = trigger.getBoundingClientRect();
  const menuBox = menu.getBoundingClientRect();
  const gap = 8;
  const edge = 10;
  const availableBelow = window.innerHeight - triggerBox.bottom - edge;
  const availableAbove = triggerBox.top - edge;
  const openBelow = availableBelow >= Math.min(menuBox.height, 260) || availableBelow >= availableAbove;
  const top = openBelow
    ? Math.min(triggerBox.bottom + gap, window.innerHeight - menuBox.height - edge)
    : Math.max(edge, triggerBox.top - menuBox.height - gap);
  const left = Math.max(edge, Math.min(triggerBox.right - menuBox.width, window.innerWidth - menuBox.width - edge));
  menu.style.left = `${Math.round(left)}px`;
  menu.style.top = `${Math.round(Math.max(edge, top))}px`;
}

function openSiteActionMenu(trigger, site) {
  closeSiteActionMenu();
  const menu = $('#site-action-menu');
  menu.dataset.siteId = String(site.id);
  menu.innerHTML = siteActionButtons(site);
  menu.hidden = false;
  menu.dataset.open = '1';
  siteMenuTrigger = trigger;
  trigger.setAttribute('aria-expanded', 'true');
  if (typeof menu.showPopover === 'function') {
    try { menu.showPopover(); } catch { /* The fixed-position fallback remains visible. */ }
  }
  requestAnimationFrame(() => {
    positionSiteActionMenu(trigger);
    $('button', menu)?.focus();
  });
}

function nextPort() {
  const used = new Set(state.sites.map((site) => Number(site.port)));
  let port = 4100;
  while (used.has(port)) port += 1;
  return port;
}

function selectedRuntimePreset() {
  const runtime = $('#site-runtime').value;
  if (runtime === 'static' || runtime === 'proxy' || runtime === 'node' || runtime === 'compose') return runtime;
  if (runtime === 'container') return $('#site-container-mode').value || 'image';
  return $('#site-runtime-preset').value || 'custom';
}

function selectedStartCommand() {
  const runtime = $('#site-runtime').value;
  const editable = runtime === 'process' || (runtime === 'container' && $('#site-container-mode').value === 'image');
  return editable ? $('#site-start-command').value : '';
}

function updateProbeFields() {
  const runtime = $('#site-runtime').value;
  const managedRuntime = ['node', 'process', 'container', 'compose'].includes(runtime);
  const healthType = $('#site-health-type').value;
  $('#site-health-path').closest('label').hidden = healthType !== 'http';
  $('#site-health-command').closest('label').hidden = healthType !== 'command';
  $('#site-health-status-min').closest('label').hidden = healthType !== 'http';
  const readinessType = $('#site-readiness-type').value;
  $('#site-readiness-type').closest('label').hidden = !managedRuntime;
  $('#site-readiness-path').closest('label').hidden = !managedRuntime || readinessType !== 'http';
  $('#site-readiness-command').closest('label').hidden = !managedRuntime || readinessType !== 'command';
  $('#site-readiness-status-min').closest('label').hidden = !managedRuntime || readinessType !== 'http';
  $('#site-startup-timeout').closest('label').hidden = !managedRuntime;
  $('#site-readiness-command').required = managedRuntime && readinessType === 'command';
  $('#site-health-command').required = healthType === 'command';
}


function hasRuntimeCapability(name) {
  return Boolean(state.bootstrap?.capabilities?.[name]);
}

function applyRuntimeCapabilities() {
  $$('[data-requires-capability]').forEach((element) => {
    const supported = hasRuntimeCapability(element.dataset.requiresCapability);
    const roleAllowed = !element.classList.contains('admin-only') || state.user?.role === 'admin';
    const available = supported && roleAllowed;
    element.hidden = !available;
    if ('disabled' in element) element.disabled = !available;
  });
  const dockerAvailable = hasRuntimeCapability('docker');
  $('#isolation-options').hidden = !dockerAvailable;
  if (!hasRuntimeCapability('anubis')) {
    $('#site-anubis-enabled').checked = false;
    for (const id of ['site-anubis-enabled', 'site-anubis-preset', 'site-anubis-difficulty', 'site-anubis-policy']) {
      const input = $(`#${id}`);
      if (input) input.disabled = true;
    }
  }
}

function updateRuntimeFields() {
  const runtime = $('#site-runtime').value;
  const node = runtime === 'node';
  const proxy = runtime === 'proxy';
  const generic = ['process', 'container', 'compose'].includes(runtime);
  const container = runtime === 'container';
  const compose = runtime === 'compose';
  const processRuntime = runtime === 'process';
  const mode = $('#site-container-mode').value;
  const imageContainer = container && mode === 'image';
  const sourceManagedBuild = compose || (container && mode !== 'image');

  $('#static-fields').hidden = runtime !== 'static';
  $('#node-fields').hidden = !node;
  $('#generic-runtime-fields').hidden = !generic;
  $('#proxy-fields').hidden = !proxy;
  $('#build-fields').hidden = proxy || (!$('#site-id').value && ($('#site-source').value || 'upload') !== 'git');
  $('#site-entry').required = runtime === 'static';
  $('#site-node-entry').required = node;
  $('#site-proxy-target').required = proxy;
  $('#site-runtime-preset-row').hidden = !processRuntime;
  $('#site-start-command-row').hidden = !(processRuntime || imageContainer);
  $('#site-start-command').required = processRuntime && ($('#site-runtime-preset').value || 'custom') === 'custom';
  $('#site-port-env-row').hidden = !(processRuntime || container || compose);
  $('#site-working-directory-row').hidden = !(processRuntime || imageContainer);
  $('#site-container-mode-row').hidden = !container;
  $('#site-runtime-container-image-row').hidden = !imageContainer;
  $('#site-runtime-container-image').required = imageContainer;
  $('#site-container-port-row').hidden = !(container || compose);
  $('#site-dockerfile-path-row').hidden = !container || mode !== 'dockerfile';
  $('#site-dockerfile-path').required = container && mode === 'dockerfile';
  $('#site-buildpack-builder-row').hidden = !container || mode !== 'buildpack';
  $('#site-compose-file-row').hidden = !compose;
  $('#site-compose-service-row').hidden = !compose;
  $('#site-compose-file').required = compose;
  $('#site-compose-service').required = compose;
  $('#site-port').required = !$('#site-edge').checked;
  $('#site-container-runtime-note').hidden = !(container || compose);
  // Keep this visible for Node/process Docker isolation as well: an existing
  // private-listener configuration must remain editable/clearable before the
  // operator changes isolation. The server enforces process isolation.
  $('#site-private-listener-options').hidden = !(node || processRuntime);
  $('#site-install-command').closest('label').hidden = sourceManagedBuild;
  $('#site-build-command').closest('label').hidden = sourceManagedBuild;
  $('#site-build-output').closest('label').hidden = runtime !== 'static';
  updateIsolationFields();
  updateProbeFields();
}

$('#site-runtime').addEventListener('change', updateRuntimeFields);
$('#site-edge').addEventListener('change', updateRuntimeFields);
$('#site-container-mode').addEventListener('change', updateRuntimeFields);
$('#site-start-command').addEventListener('input', updateRuntimeFields);
$('#site-runtime-preset').addEventListener('change', updateRuntimeFields);
$('#site-runtime-container-image').addEventListener('input', () => {
  if ($('#site-runtime').value === 'container') $('#site-container-image').value = $('#site-runtime-container-image').value;
});
$('#site-container-image').addEventListener('input', () => {
  if ($('#site-runtime').value === 'container') $('#site-runtime-container-image').value = $('#site-container-image').value;
});
$('#site-health-type').addEventListener('change', updateProbeFields);
$('#site-readiness-type').addEventListener('change', updateProbeFields);

function clearUpload(kind) {
  state.uploads[kind] = null;
  const label = kind === 'site' ? $('#upload-label') : $('#content-upload-label');
  label.textContent = kind === 'site' ? 'Drop a ZIP or project folder' : 'Drop a ZIP or project folder';
  const inputs = kind === 'site' ? ['#zip-input', '#folder-input'] : ['#content-zip-input', '#content-folder-input'];
  inputs.forEach((selector) => { $(selector).value = ''; });
}

function setUpload(kind, selection) {
  state.uploads[kind] = selection;
  const label = kind === 'site' ? $('#upload-label') : $('#content-upload-label');
  if (selection.archive) label.textContent = `${selection.archive.name} · ${formatBytes(selection.archive.size)}`;
  else label.textContent = `${selection.files.length} files · ${formatBytes(selection.files.reduce((sum, file) => sum + Number(file.size || 0), 0))}`;
}

async function validatedArchive(file) {
  if (!file) throw new Error('Choose a ZIP archive.');
  if (!file.name.toLowerCase().endsWith('.zip')) throw new Error('Choose a file with a .zip extension.');
  if (!file.size) throw new Error('The selected ZIP archive is empty.');
  const signature = new Uint8Array(await file.slice(0, 4).arrayBuffer());
  const zipSignature = signature.length === 4 && signature[0] === 0x50 && signature[1] === 0x4b
    && ((signature[2] === 0x03 && signature[3] === 0x04)
      || (signature[2] === 0x05 && signature[3] === 0x06)
      || (signature[2] === 0x07 && signature[3] === 0x08));
  if (!zipSignature) throw new Error('The selected file does not appear to be a standard ZIP archive.');
  return file;
}

function commonBrowserTopDirectory(paths) {
  if (!paths.length) return null;
  const first = String(paths[0]).replaceAll('\\', '/').split('/');
  if (first.length < 2) return null;
  return paths.every((item) => String(item).replaceAll('\\', '/').startsWith(`${first[0]}/`)) ? first[0] : null;
}

function folderContainsEntry(selection, entryFile) {
  if (!selection?.files?.length) return false;
  const paths = selection.paths.map((item) => String(item).replaceAll('\\', '/').replace(/^\.\//, ''));
  const stripTop = commonBrowserTopDirectory(paths);
  const normalizedEntry = String(entryFile || '').replaceAll('\\', '/').replace(/^\.\//, '').replace(/^\/+/, '');
  return paths.some((item) => (stripTop && item.startsWith(`${stripTop}/`) ? item.slice(stripTop.length + 1) : item) === normalizedEntry);
}

function folderSelection(fileList) {
  const files = [...fileList];
  if (files.length > MAX_BROWSER_UPLOAD_FILES) throw new Error(`Select at most ${MAX_BROWSER_UPLOAD_FILES} files at once.`);
  return { files, paths: files.map((file) => file.webkitRelativePath || file.name) };
}

async function readDroppedEntry(entry, prefix = '', counter = { count: 0 }) {
  if (entry.isFile) {
    counter.count += 1;
    if (counter.count > MAX_BROWSER_UPLOAD_FILES) throw new Error(`Drop at most ${MAX_BROWSER_UPLOAD_FILES} files at once.`);
    const file = await new Promise((resolve, reject) => entry.file(resolve, reject));
    return [{ file, path: `${prefix}${file.name}` }];
  }
  if (!entry.isDirectory) return [];
  const reader = entry.createReader();
  const entries = [];
  while (true) {
    const batch = await new Promise((resolve, reject) => reader.readEntries(resolve, reject));
    if (!batch.length) break;
    entries.push(...batch);
  }
  const nested = await Promise.all(entries.map((child) => readDroppedEntry(child, `${prefix}${entry.name}/`, counter)));
  return nested.flat();
}

async function dropSelection(dataTransfer) {
  const items = [...(dataTransfer.items || [])];
  if (items.length && items.some((item) => item.webkitGetAsEntry?.())) {
    const entries = items.map((item) => item.webkitGetAsEntry?.()).filter(Boolean);
    const counter = { count: 0 };
    const results = (await Promise.all(entries.map((entry) => readDroppedEntry(entry, '', counter)))).flat();
    if (results.length === 1 && results[0].file.name.toLowerCase().endsWith('.zip')) return { archive: await validatedArchive(results[0].file) };
    return { files: results.map((item) => item.file), paths: results.map((item) => item.path) };
  }
  const files = [...dataTransfer.files];
  if (files.length > MAX_BROWSER_UPLOAD_FILES) throw new Error(`Drop at most ${MAX_BROWSER_UPLOAD_FILES} files at once.`);
  if (files.length === 1 && files[0].name.toLowerCase().endsWith('.zip')) return { archive: await validatedArchive(files[0]) };
  return { files, paths: files.map((file) => file.name) };
}

function bindUploadControls(kind, controls) {
  const zone = $(controls.zone);
  $(controls.zipButton).addEventListener('click', () => $(controls.zipInput).click());
  $(controls.folderButton).addEventListener('click', () => $(controls.folderInput).click());
  $(controls.zipInput).addEventListener('change', async (event) => {
    const file = event.target.files[0];
    if (!file) return;
    try { setUpload(kind, { archive: await validatedArchive(file) }); }
    catch (error) { event.target.value = ''; toast(error.message, 'error'); }
  });
  $(controls.folderInput).addEventListener('change', (event) => {
    try {
      if (event.target.files.length) setUpload(kind, folderSelection(event.target.files));
    } catch (error) {
      event.target.value = '';
      toast(error.message, 'error');
    }
  });
  ['dragenter', 'dragover'].forEach((name) => zone.addEventListener(name, (event) => {
    event.preventDefault();
    zone.classList.add('dragover');
  }));
  ['dragleave', 'drop'].forEach((name) => zone.addEventListener(name, (event) => {
    event.preventDefault();
    zone.classList.remove('dragover');
  }));
  zone.addEventListener('drop', async (event) => {
    try {
      const selection = await dropSelection(event.dataTransfer);
      if (!selection.archive && !selection.files?.length) throw new Error('No files were found in the drop.');
      setUpload(kind, selection);
    } catch (error) { toast(error.message, 'error'); }
  });
}

bindUploadControls('site', { zone: '#drop-zone', zipButton: '#choose-zip', folderButton: '#choose-folder', zipInput: '#zip-input', folderInput: '#folder-input' });
bindUploadControls('content', { zone: '#content-drop-zone', zipButton: '#content-choose-zip', folderButton: '#content-choose-folder', zipInput: '#content-zip-input', folderInput: '#content-folder-input' });

function updateObfuscationFields() {
  const enabled = $('#site-obfuscate').checked;
  $('#site-obfuscation-warning').hidden = !enabled;
  $('#site-obfuscation-scan').disabled = !enabled || !$('#site-id').value;
  if (!enabled) {
    $('#site-obfuscation-report').innerHTML = '';
    $('#site-obfuscation-ack').checked = false;
  }
}

function renderObfuscationReport(report) {
  const target = $('#site-obfuscation-report');
  const severity = report.risk === 'high' ? 'error' : report.risk === 'medium' ? 'warning' : 'success';
  const summary = report.warningCount
    ? `${report.warningCount} compatibility warning${report.warningCount === 1 ? '' : 's'} found in ${report.scannedFiles} scanned files.`
    : `No known compatibility patterns were found in ${report.scannedFiles} scanned files.`;
  const warnings = (report.warnings || []).slice(0, 12).map((warning) => `<li><strong>${escapeHtml(warning.path)}:${warning.line}</strong> — ${escapeHtml(warning.message)}</li>`).join('');
  const skipped = report.skippedFiles?.length ? `<p>${formatNumber(report.skippedFiles.length)} file(s) were skipped, so the report is incomplete.</p>` : '';
  target.innerHTML = `<div class="compatibility-summary ${severity}"><strong>${escapeHtml(summary)}</strong><p>${escapeHtml(report.note || '')}</p>${skipped}${warnings ? `<ul>${warnings}</ul>` : ''}</div>`;
}

$('#site-obfuscate').addEventListener('change', updateObfuscationFields);
$('#site-obfuscation-scan').addEventListener('click', async () => {
  const id = $('#site-id').value;
  if (!id) return;
  const button = $('#site-obfuscation-scan');
  setBusy(button, true, 'Scanning…');
  $('#site-obfuscation-report').innerHTML = '<p class="muted">Scanning project files…</p>';
  try {
    const result = await api(`/api/sites/${id}/obfuscation-report`);
    renderObfuscationReport(result.report);
  } catch (error) {
    $('#site-obfuscation-report').innerHTML = `<p class="form-error">${escapeHtml(error.message)}</p>`;
  } finally { setBusy(button, false); updateObfuscationFields(); }
});

function setWizardStep(step) {
  state.wizardStep = Math.max(1, Math.min(3, Number(step) || 1));
  const form = $('#site-form');
  form.dataset.wizardStep = String(state.wizardStep);
  $$('#site-wizard-progress span').forEach((item, index) => item.classList.toggle('active', index + 1 === state.wizardStep));
  $('#site-wizard-back').hidden = state.wizardStep === 1;
  $('#site-wizard-next').hidden = state.wizardStep === 3;
  $('#site-save').hidden = state.wizardStep !== 3;
}

function setSiteSource(source) {
  let normalized = ['upload', 'git', 'image', 'proxy'].includes(source) ? source : 'upload';
  if (normalized === 'git' && (!hasRuntimeCapability('git') || state.user?.role !== 'admin')) normalized = 'upload';
  if (normalized === 'image' && !hasRuntimeCapability('docker')) normalized = 'upload';
  $('#site-source').value = normalized;
  $$('[data-site-source]').forEach((button) => { const active = button.dataset.siteSource === normalized; button.classList.toggle('active', active); button.setAttribute('aria-checked', String(active)); });
  const templatePicker = $('.template-picker');
  const proxySelected = normalized === 'proxy';
  templatePicker?.classList.toggle('is-disabled', proxySelected);
  $$('[data-site-template]', templatePicker).forEach((button) => {
    button.disabled = proxySelected;
    button.setAttribute('aria-disabled', String(proxySelected));
  });
  $('#drop-zone').hidden = normalized !== 'upload';
  $('#git-source-fields').hidden = normalized !== 'git';
  $('#proxy-source-fields').hidden = normalized !== 'proxy';
  if (normalized === 'proxy') $('#site-runtime').value = 'proxy';
  else if (normalized === 'image') { $('#site-runtime').value = 'container'; $('#site-container-mode').value = 'image'; }
  else if ($('#site-runtime').value === 'proxy') $('#site-runtime').value = 'static';
  updateRuntimeFields();
}

function applySiteTemplate(template) {
  $$('[data-site-template]').forEach((button) => { const active = button.dataset.siteTemplate === template; button.classList.toggle('active', active); button.setAttribute('aria-checked', String(active)); });
  const presets = {
    static: { source: 'upload', runtime: 'static', entry: 'index.html', install: '', build: '', output: '' },
    vite: { source: 'git', runtime: 'static', entry: 'index.html', install: 'npm ci', build: 'npm run build', output: 'dist' },
    astro: { source: 'git', runtime: 'static', entry: 'index.html', install: 'npm ci', build: 'npm run build', output: 'dist' },
    next: { source: 'git', runtime: 'node', nodeEntry: '.next/standalone/server.js', install: 'npm ci', build: 'npm run build', output: '' },
    node: { source: 'git', runtime: 'node', nodeEntry: 'server.js', install: 'npm ci', build: '', output: '' },
    hugo: { source: 'git', runtime: 'static', entry: 'index.html', install: '', build: 'hugo --minify', output: 'public' },
    fastapi: { source: 'git', runtime: 'process', runtimePreset: 'fastapi', startCommand: 'uvicorn app:app --host "$HOST" --port "$PORT"', readiness: 'http', install: 'pip install -r requirements.txt', build: '', output: '' },
    django: { source: 'git', runtime: 'process', runtimePreset: 'django', startCommand: 'gunicorn --bind "$HOST:$PORT" project.wsgi:application', readiness: 'http', install: 'pip install -r requirements.txt', build: '', output: '' },
    bun: { source: 'git', runtime: 'process', runtimePreset: 'bun', startCommand: 'bun run start', readiness: 'http', install: 'bun install --frozen-lockfile', build: '', output: '' },
    deno: { source: 'git', runtime: 'process', runtimePreset: 'deno', startCommand: 'deno task start', readiness: 'http', install: '', build: '', output: '' },
    go: { source: 'git', runtime: 'process', runtimePreset: 'go', startCommand: './app', readiness: 'http', install: '', build: 'go build -o app .', output: '' },
    java: { source: 'git', runtime: 'process', runtimePreset: 'java', startCommand: 'java -jar app.jar', readiness: 'http', install: '', build: '', output: '' },
    dockerimage: { source: 'image', runtime: 'container', containerMode: 'image', containerImage: 'nginx:alpine', readiness: 'http', install: '', build: '', output: '' },
    dockerfile: { source: 'git', runtime: 'container', containerMode: 'dockerfile', readiness: 'http', install: '', build: '', output: '' },
    compose: { source: 'git', runtime: 'compose', composeFile: 'compose.yaml', composeService: 'app', readiness: 'http', install: '', build: '', output: '' },
    custom: { source: 'git', runtime: 'process', runtimePreset: 'custom', startCommand: '', install: '', build: '', output: '' },
    proxy: { source: 'proxy', runtime: 'proxy', install: '', build: '', output: '' }
  };
  const preset = presets[template];
  if (!preset) return;
  if (['dockerimage', 'dockerfile', 'compose'].includes(template) && !hasRuntimeCapability('docker')) return;
  const currentSource = $('#site-source').value || 'upload';
  let source = currentSource;
  if (preset.source === 'image') source = 'image';
  else if (!['upload', 'git'].includes(source)) source = 'upload';
  if (source === 'git' && (!hasRuntimeCapability('git') || state.user?.role !== 'admin')) source = 'upload';
  setSiteSource(source);
  $('#site-runtime').value = preset.runtime;
  if (preset.entry) $('#site-entry').value = preset.entry;
  if (preset.nodeEntry) $('#site-node-entry').value = preset.nodeEntry;
  if (preset.runtimePreset) $('#site-runtime-preset').value = preset.runtimePreset;
  if (preset.startCommand !== undefined) $('#site-start-command').value = preset.startCommand;
  if (preset.containerMode) $('#site-container-mode').value = preset.containerMode;
  if (preset.containerImage) { $('#site-runtime-container-image').value = preset.containerImage; $('#site-container-image').value = preset.containerImage; }
  if (preset.composeFile) $('#site-compose-file').value = preset.composeFile;
  if (preset.composeService) $('#site-compose-service').value = preset.composeService;
  if (preset.readiness) $('#site-readiness-type').value = preset.readiness;
  $('#site-install-command').value = preset.install;
  $('#site-build-command').value = preset.build;
  $('#site-build-output').value = preset.output;
  $('#site-release-mode').checked = source === 'git';
  updateRuntimeFields();
}

$$('[data-site-source]').forEach((button) => button.addEventListener('click', () => setSiteSource(button.dataset.siteSource)));
$$('[data-site-template]').forEach((button) => button.addEventListener('click', () => applySiteTemplate(button.dataset.siteTemplate)));
$('#site-wizard-next').addEventListener('click', () => setWizardStep(state.wizardStep + 1));
$('#site-wizard-back').addEventListener('click', () => setWizardStep(state.wizardStep - 1));
$('#site-create-git-url').addEventListener('input', () => { $('#site-git-url').value = $('#site-create-git-url').value; });
$('#site-create-git-branch').addEventListener('input', () => { $('#site-git-branch').value = $('#site-create-git-branch').value; });
$('#site-create-git-provider').addEventListener('change', () => {
  state.gitRepositories = [];
  $('#site-create-git-repository-row').hidden = true;
  $('#site-create-git-repository').innerHTML = '<option value="">Choose a repository…</option>';
});
$('#site-browse-git-repositories').addEventListener('click', async (event) => {
  const provider = $('#site-create-git-provider').value;
  if (!provider) return toast('Choose a connected Git provider, or paste a repository URL manually.', 'error');
  setBusy(event.currentTarget, true, 'Loading…');
  try {
    const result = await api(`/api/admin/git-providers/${encodeURIComponent(provider)}/repositories`);
    state.gitRepositories = result.repositories || [];
    const select = $('#site-create-git-repository');
    select.innerHTML = '<option value="">Choose a repository…</option>' + state.gitRepositories.map((repository, index) => `<option value="${index}">${escapeHtml(repository.fullName)}${repository.private ? ' · private' : ''}</option>`).join('');
    $('#site-create-git-repository-row').hidden = false;
    if (!state.gitRepositories.length) toast('No repositories were returned for that provider.', 'warning');
  } catch (error) { toast(error.message, 'error'); }
  finally { setBusy(event.currentTarget, false); }
});
$('#site-create-git-repository').addEventListener('change', () => {
  const repository = state.gitRepositories[Number($('#site-create-git-repository').value)];
  if (!repository) return;
  $('#site-create-git-url').value = repository.url;
  $('#site-create-git-branch').value = repository.defaultBranch || 'main';
  $('#site-git-url').value = repository.url;
  $('#site-git-branch').value = repository.defaultBranch || 'main';
});
$('#site-git-url').addEventListener('input', () => { if ($('#site-form').classList.contains('wizard-mode')) $('#site-create-git-url').value = $('#site-git-url').value; });
$('#site-git-branch').addEventListener('input', () => { if ($('#site-form').classList.contains('wizard-mode')) $('#site-create-git-branch').value = $('#site-git-branch').value; });

function openNewSite() {
  applyRuntimeCapabilities();
  $('#site-form').reset();
  $('#site-id').value = '';
  $('#site-dialog-kicker').textContent = 'New deployment';
  $('#site-dialog-title').textContent = 'Add a site';
  $('#site-save').textContent = 'Deploy site';
  $('#site-form').classList.add('wizard-mode');
  $('#upload-section').hidden = false;
  setWizardStep(1);
  setSiteSource('upload');
  $$('[data-site-template]').forEach((button) => { button.classList.remove('active'); button.setAttribute('aria-checked', 'false'); });
  $('[data-site-template="static"]')?.classList.add('active');
  $('[data-site-template="static"]')?.setAttribute('aria-checked', 'true');
  $('#site-enabled').parentElement.hidden = false;
  $('#site-runtime').value = 'static';
  $('#site-port').value = nextPort();
  $('#site-host').value = '127.0.0.1';
  $('#site-entry').value = 'index.html';
  $('#site-node-entry').value = 'server.js';
  $('#site-runtime-preset').value = 'custom';
  $('#site-start-command').value = '';
  $('#site-runtime-port-env').value = 'PORT';
  $('#site-private-listeners').value = '[]';
  $('#site-working-directory').value = '.';
  $('#site-container-mode').value = 'image';
  $('#site-runtime-container-image').value = 'nginx:alpine';
  $('#site-container-port').value = '3000';
  $('#site-dockerfile-path').value = 'Dockerfile';
  $('#site-buildpack-builder').value = '';
  $('#site-compose-file').value = 'compose.yaml';
  $('#site-compose-service').value = 'app';
  $('#site-proxy-target').value = '';
  $('#site-proxy-host-header').value = '';
  $('#site-proxy-timeout').value = '30000';
  $('#site-create-git-provider').value = '';
  $('#site-create-git-repository-row').hidden = true;
  $('#site-create-git-repository').innerHTML = '<option value="">Choose a repository…</option>';
  state.gitRepositories = [];
  $('#site-create-git-url').value = '';
  $('#site-create-git-branch').value = 'main';
  $('#site-install-command').value = '';
  $('#site-build-command').value = '';
  $('#site-build-output').value = '';
  $('#site-cache').value = '0';
  $('#site-headers').value = '{}';
  $('#site-obfuscate').checked = false;
  $('#site-obfuscation-ack').checked = false;
  $('#site-obfuscation-report').innerHTML = '';
  $('#site-domain-only').checked = false;
  $('#site-compression').checked = true;
  $('#site-edge').checked = false;
  $('#site-security-preset').value = 'balanced';
  $('#site-csp').value = '';
  $('#site-health-path').value = '/';
  $('#site-health-interval').value = '30';
  $('#site-health-type').value = 'http';
  $('#site-health-command').value = '';
  $('#site-health-status-min').value = '200';
  $('#site-health-status-max').value = '499';
  $('#site-readiness-type').value = 'tcp';
  $('#site-readiness-path').value = '/';
  $('#site-readiness-command').value = '';
  $('#site-readiness-status-min').value = '200';
  $('#site-readiness-status-max').value = '399';
  $('#site-startup-timeout').value = '30';
  $('#site-shutdown-grace').value = '10';
  $('#site-blue-green-drain').value = '5';
  $('#site-restart-policy').value = 'on-failure';
  $('#site-max-restarts').value = '5';
  $('#site-memory-limit').value = '0';
  $('#site-max-connections').value = '0';
  $('#asset-transform-options').open = false;
  $('#runtime-safety-options').open = false;
  $('#site-firewall-enabled').checked = false;
  $('#site-firewall-mode').value = 'local';
  $('#site-firewall-action').value = 'managed_challenge';
  $('#site-firewall-rate').value = '0';
  $('#site-firewall-body').value = '0';
  $('#site-firewall-blocked-ips').value = '';
  $('#site-firewall-allowed-ips').value = '';
  $('#site-firewall-blocked-countries').value = '';
  $('#site-firewall-allowed-countries').value = '';
  $('#site-firewall-bots').checked = false;
  $('#firewall-options').open = false;
  $('#site-runtime-isolation').value = 'process';
  $('#site-container-image').value = 'node:22-alpine';
  $('#site-runtime-container-image').value = 'nginx:alpine';
  $('#site-cpu-limit').value = '0';
  $('#site-pids-limit').value = '128';
  $('#site-outbound-network').checked = true;
  $('#site-anubis-enabled').checked = false;
  $('#site-anubis-preset').value = 'balanced';
  $('#site-anubis-difficulty').value = '4';
  $('#site-anubis-policy').value = '';
  $('#site-release-mode').checked = false;
  $('#site-manifest-enabled').checked = true;
  $('#site-cloudflare-auto-sync').checked = false;
  $('#site-approve-manifest').checked = false;
  $('#site-git-url').value = '';
  $('#site-git-branch').value = 'main';
  $('#site-preview-domain').value = '';
  $('#site-maintenance-enabled').checked = false;
  $('#site-maintenance-html').value = '';
  $('#site-redirects').value = '[]';
  $('#site-error-pages').value = '{}';
  $('#site-cache-rules').value = '[]';
  $('#isolation-options').open = false;
  $('#delivery-options').open = false;
  $('#site-cloudflare-tunnel-options').hidden = true;
  $('#site-cloudflare-tunnel-options').open = false;
  $('#site-form-error').textContent = '';
  clearUpload('site');
  updateRuntimeFields();
  updateFirewallFields();
  updateObfuscationFields();
  updateIsolationFields();
  showModal($('#site-dialog'));
}

function updateIsolationFields() {
  const runtimeType = $('#site-runtime').value;
  const nodeRuntime = runtimeType === 'node';
  const containerRuntime = runtimeType === 'container';
  const composeRuntime = runtimeType === 'compose';
  const nodeContainer = nodeRuntime && $('#site-runtime-isolation').value === 'docker';
  const managedContainer = containerRuntime || composeRuntime || nodeContainer;
  const imageRelevant = nodeContainer;
  const isolationSelect = $('#site-runtime-isolation');
  isolationSelect.disabled = !nodeRuntime;
  isolationSelect.closest('label').hidden = !nodeRuntime;
  const imageInput = $('#site-container-image');
  imageInput.disabled = !imageRelevant;
  imageInput.closest('label').hidden = !imageRelevant;
  for (const id of ['site-cpu-limit', 'site-pids-limit', 'site-outbound-network']) {
    const input = $(`#${id}`);
    input.disabled = !managedContainer;
    input.closest('label').hidden = !managedContainer;
  }
  const anubisAvailable = hasRuntimeCapability('anubis');
  const anubis = anubisAvailable && $('#site-anubis-enabled').checked;
  $('#site-anubis-enabled').disabled = !anubisAvailable;
  $('#site-anubis-preset').disabled = !anubis;
  $('#site-anubis-difficulty').disabled = !anubis;
  $('#site-anubis-policy').disabled = !anubis || $('#site-anubis-preset').value !== 'custom';
}

$('#site-runtime-isolation').addEventListener('change', updateIsolationFields);
$('#site-anubis-enabled').addEventListener('change', updateIsolationFields);
$('#site-anubis-preset').addEventListener('change', updateIsolationFields);

$('#new-site-button').addEventListener('click', openNewSite);
$$('[data-open-new-site]').forEach((button) => button.addEventListener('click', openNewSite));
$('#refresh-sites').addEventListener('click', loadSites);

function openEditSite(site) {
  $('#site-form').reset();
  $('#site-id').value = site.id;
  $('#site-dialog-kicker').textContent = 'Deployment settings';
  $('#site-dialog-title').textContent = `Edit ${site.name}`;
  $('#site-save').textContent = 'Save settings';
  $('#site-form').classList.remove('wizard-mode');
  $('#site-save').hidden = false;
  $('#upload-section').hidden = true;
  $('#site-enabled').parentElement.hidden = true;
  $('#site-name').value = site.name;
  $('#site-runtime').value = site.runtime_type;
  $('#site-port').value = site.port;
  $('#site-host').value = site.bind_host;
  $('#site-domain').value = site.domain || '';
  $('#site-entry').value = site.entry_file;
  $('#site-node-entry').value = site.node_entry;
  $('#site-runtime-preset').value = site.runtime_preset || (site.runtime_type === 'process' ? 'custom' : site.runtime_type === 'container' ? 'image' : site.runtime_type === 'compose' ? 'compose' : site.runtime_type === 'static' ? 'static' : 'node');
  $('#site-start-command').value = site.start_command || '';
  $('#site-runtime-port-env').value = site.runtime_port_env || 'PORT';
  $('#site-private-listeners').value = JSON.stringify(site.additional_listeners || [], null, 2);
  $('#site-private-listener-options').open = Boolean((site.additional_listeners || []).length);
  $('#site-working-directory').value = site.working_directory || '.';
  $('#site-container-mode').value = site.container_mode || 'image';
  $('#site-container-port').value = site.container_port || 3000;
  $('#site-dockerfile-path').value = site.dockerfile_path || 'Dockerfile';
  $('#site-buildpack-builder').value = site.buildpack_builder || '';
  $('#site-compose-file').value = site.compose_file || 'compose.yaml';
  $('#site-compose-service').value = site.compose_service || 'app';
  $('#site-proxy-target').value = site.proxy_target || '';
  $('#site-proxy-host-header').value = site.proxy_host_header || '';
  $('#site-proxy-timeout').value = site.proxy_timeout_ms || 30000;
  $('#site-install-command').value = site.install_command || '';
  $('#site-build-command').value = site.build_command || '';
  $('#site-build-output').value = site.build_output_dir || '';
  $('#site-create-git-url').value = site.git_url || '';
  $('#site-create-git-branch').value = site.git_branch || 'main';
  $('#site-cache').value = site.cache_seconds;
  $('#site-headers').value = JSON.stringify(site.headers || {}, null, 2);
  $('#site-spa').checked = site.spa_fallback;
  $('#site-minify').checked = site.minify;
  $('#site-obfuscate').checked = site.obfuscate;
  $('#site-obfuscation-ack').checked = Boolean(site.obfuscation_risk_acknowledged);
  $('#site-obfuscation-report').innerHTML = '';
  $('#site-install').checked = site.install_dependencies;
  $('#site-ssl').checked = site.ssl_enabled;
  $('#site-domain-only').checked = site.domain_only;
  $('#site-compression').checked = site.compression !== false;
  $('#site-edge').checked = Boolean(site.edge_enabled);
  $('#site-security-preset').value = site.security_preset || 'balanced';
  $('#site-csp').value = site.csp || '';
  $('#site-health-path').value = site.health_check_path || '/';
  $('#site-health-interval').value = site.health_check_interval || 30;
  $('#site-health-type').value = site.health_check_type || 'http';
  $('#site-health-command').value = site.health_check_command || '';
  $('#site-health-status-min').value = site.health_check_status_min || 200;
  $('#site-health-status-max').value = site.health_check_status_max || 499;
  $('#site-readiness-type').value = site.readiness_type || 'tcp';
  $('#site-readiness-path').value = site.readiness_path || '/';
  $('#site-readiness-command').value = site.readiness_command || '';
  $('#site-readiness-status-min').value = site.readiness_status_min || 200;
  $('#site-readiness-status-max').value = site.readiness_status_max || 399;
  $('#site-startup-timeout').value = site.startup_timeout_seconds || 30;
  $('#site-shutdown-grace').value = site.shutdown_grace_seconds ?? 10;
  $('#site-blue-green-drain').value = site.blue_green_drain_seconds ?? 5;
  $('#site-restart-policy').value = site.restart_policy || 'on-failure';
  $('#site-max-restarts').value = site.max_restarts ?? 5;
  $('#site-memory-limit').value = site.memory_limit_mb || 0;
  $('#site-max-connections').value = site.max_connections || 0;
  $('#asset-transform-options').open = Boolean(site.minify || site.obfuscate);
  $('#runtime-safety-options').open = Boolean(site.edge_enabled || site.memory_limit_mb || site.max_connections || site.security_preset === 'strict' || site.csp);
  $('#site-firewall-enabled').checked = site.firewall_enabled;
  $('#site-firewall-mode').value = site.firewall?.mode || 'local';
  $('#site-firewall-action').value = site.firewall?.cloudflareAction || 'managed_challenge';
  $('#site-firewall-rate').value = site.firewall?.rateLimitPerMinute || 0;
  $('#site-firewall-body').value = site.firewall?.maxBodyKb || 0;
  $('#site-firewall-blocked-ips').value = (site.firewall?.blockedIps || []).join('\n');
  $('#site-firewall-allowed-ips').value = (site.firewall?.allowedIps || []).join('\n');
  $('#site-firewall-blocked-countries').value = (site.firewall?.blockedCountries || []).join(', ');
  $('#site-firewall-allowed-countries').value = (site.firewall?.allowedCountries || []).join(', ');
  $('#site-firewall-bots').checked = Boolean(site.firewall?.blockBots);
  $('#firewall-options').open = site.firewall_enabled;
  $('#site-runtime-isolation').value = site.runtime_isolation || 'process';
  $('#site-container-image').value = site.container_image || 'node:22-alpine';
  $('#site-runtime-container-image').value = site.container_image || 'nginx:alpine';
  $('#site-cpu-limit').value = site.cpu_limit || 0;
  $('#site-pids-limit').value = site.pids_limit || 128;
  $('#site-outbound-network').checked = site.outbound_network !== false;
  $('#site-anubis-enabled').checked = Boolean(site.anubis_enabled);
  $('#site-anubis-preset').value = site.anubis_preset || 'balanced';
  $('#site-anubis-difficulty').value = site.anubis_difficulty || 4;
  $('#site-anubis-policy').value = site.anubis_policy || '';
  $('#site-release-mode').checked = Boolean(site.release_mode);
  $('#site-manifest-enabled').checked = site.manifest_enabled !== false;
  $('#site-cloudflare-auto-sync').checked = Boolean(site.cloudflare_auto_sync);
  $('#site-approve-manifest').checked = false;
  $('#site-git-url').value = site.git_url || '';
  $('#site-git-branch').value = site.git_branch || 'main';
  $('#site-preview-domain').value = site.preview_domain || '';
  $('#site-maintenance-enabled').checked = Boolean(site.maintenance_enabled);
  $('#site-maintenance-html').value = site.maintenance_html || '';
  $('#site-redirects').value = JSON.stringify(site.redirects || [], null, 2);
  $('#site-error-pages').value = JSON.stringify(site.errorPages || site.error_pages || {}, null, 2);
  $('#site-cache-rules').value = JSON.stringify(site.cacheRules || site.cache_rules || [], null, 2);
  $('#isolation-options').open = Boolean(site.runtime_isolation === 'docker' || site.anubis_enabled);
  $('#delivery-options').open = Boolean(site.release_mode || site.git_url || site.preview_domain || site.maintenance_enabled || (site.redirects || []).length || Object.keys(site.errorPages || {}).length || (site.cacheRules || []).length);
  $('#site-form-error').textContent = '';
  updateRuntimeFields();
  updateFirewallFields();
  updateObfuscationFields();
  updateIsolationFields();
  $('#site-cloudflare-tunnel-options').hidden = state.user?.role !== 'admin';
  if (state.user?.role === 'admin') {
    renderSiteCloudflareTunnel(site.cloudflareTunnel || {});
    if (!$('#site-cloudflare-tunnel-hostname').value) $('#site-cloudflare-tunnel-hostname').value = site.domain || '';
    loadSiteCloudflareTunnel(site.id, site.domain || '').catch((error) => { $('#site-cloudflare-tunnel-detail').textContent = error.message; });
  }
  showModal($('#site-dialog'));
}

function appendConfiguration(formData) {
  formData.append('name', $('#site-name').value);
  formData.append('runtimeType', $('#site-runtime').value);
  formData.append('runtimePreset', selectedRuntimePreset());
  formData.append('startCommand', selectedStartCommand());
  formData.append('runtimePortEnv', $('#site-runtime-port-env').value || 'PORT');
  formData.append('additionalListeners', $('#site-private-listeners').value || '[]');
  formData.append('workingDirectory', $('#site-working-directory').value || '.');
  formData.append('containerMode', $('#site-container-mode').value);
  formData.append('containerPort', $('#site-container-port').value || '3000');
  formData.append('dockerfilePath', $('#site-dockerfile-path').value || 'Dockerfile');
  formData.append('buildpackBuilder', $('#site-buildpack-builder').value);
  formData.append('composeFile', $('#site-compose-file').value || 'compose.yaml');
  formData.append('composeService', $('#site-compose-service').value || 'app');
  formData.append('source', $('#site-source').value || 'upload');
  formData.append('proxyTarget', $('#site-proxy-target').value);
  formData.append('proxyHostHeader', $('#site-proxy-host-header').value);
  formData.append('proxyTimeoutMs', $('#site-proxy-timeout').value || '30000');
  formData.append('installCommand', $('#site-install-command').value);
  formData.append('buildCommand', $('#site-build-command').value);
  formData.append('buildOutputDir', $('#site-build-output').value);
  formData.append('port', $('#site-port').value);
  formData.append('bindHost', $('#site-host').value);
  formData.append('domain', $('#site-domain').value);
  formData.append('entryFile', $('#site-entry').value || 'index.html');
  formData.append('nodeEntry', $('#site-node-entry').value || 'server.js');
  formData.append('cacheSeconds', $('#site-cache').value || '0');
  formData.append('headers', $('#site-headers').value || '{}');
  formData.append('spaFallback', String($('#site-spa').checked));
  formData.append('minify', String($('#site-minify').checked));
  formData.append('obfuscate', String($('#site-obfuscate').checked));
  formData.append('obfuscationRiskAcknowledged', String($('#site-obfuscation-ack').checked));
  formData.append('installDependencies', String($('#site-install').checked));
  formData.append('sslEnabled', String($('#site-ssl').checked));
  formData.append('domainOnly', String($('#site-domain-only').checked));
  formData.append('compression', String($('#site-compression').checked));
  formData.append('edgeEnabled', String($('#site-edge').checked));
  formData.append('securityPreset', $('#site-security-preset').value);
  formData.append('csp', $('#site-csp').value);
  formData.append('healthCheckPath', $('#site-health-path').value || '/');
  formData.append('healthCheckInterval', $('#site-health-interval').value || '30');
  formData.append('healthCheckType', $('#site-health-type').value);
  formData.append('healthCheckCommand', $('#site-health-command').value);
  formData.append('healthCheckStatusMin', $('#site-health-status-min').value || '200');
  formData.append('healthCheckStatusMax', $('#site-health-status-max').value || '499');
  formData.append('readinessType', $('#site-readiness-type').value);
  formData.append('readinessPath', $('#site-readiness-path').value || '/');
  formData.append('readinessCommand', $('#site-readiness-command').value);
  formData.append('readinessStatusMin', $('#site-readiness-status-min').value || '200');
  formData.append('readinessStatusMax', $('#site-readiness-status-max').value || '399');
  formData.append('startupTimeoutSeconds', $('#site-startup-timeout').value || '30');
  formData.append('shutdownGraceSeconds', $('#site-shutdown-grace').value || '10');
  formData.append('blueGreenDrainSeconds', $('#site-blue-green-drain').value || '5');
  formData.append('restartPolicy', $('#site-restart-policy').value);
  formData.append('maxRestarts', $('#site-max-restarts').value || '5');
  formData.append('memoryLimitMb', $('#site-memory-limit').value || '0');
  formData.append('maxConnections', $('#site-max-connections').value || '0');
  formData.append('firewallEnabled', String($('#site-firewall-enabled').checked));
  formData.append('firewallMode', $('#site-firewall-mode').value);
  formData.append('firewallCloudflareAction', $('#site-firewall-action').value);
  formData.append('firewallRateLimit', $('#site-firewall-rate').value || '0');
  formData.append('firewallMaxBodyKb', $('#site-firewall-body').value || '0');
  formData.append('firewallBlockedIps', $('#site-firewall-blocked-ips').value);
  formData.append('firewallAllowedIps', $('#site-firewall-allowed-ips').value);
  formData.append('firewallBlockedCountries', $('#site-firewall-blocked-countries').value);
  formData.append('firewallAllowedCountries', $('#site-firewall-allowed-countries').value);
  formData.append('firewallBlockBots', String($('#site-firewall-bots').checked));
  formData.append('runtimeIsolation', $('#site-runtime-isolation').value);
  formData.append('containerImage', $('#site-runtime').value === 'container' && $('#site-container-mode').value === 'image' ? $('#site-runtime-container-image').value : $('#site-container-image').value);
  formData.append('cpuLimit', $('#site-cpu-limit').value || '0');
  formData.append('pidsLimit', $('#site-pids-limit').value || '128');
  formData.append('outboundNetwork', String($('#site-outbound-network').checked));
  formData.append('anubisEnabled', String($('#site-anubis-enabled').checked));
  formData.append('anubisPreset', $('#site-anubis-preset').value);
  formData.append('anubisDifficulty', $('#site-anubis-difficulty').value || '4');
  formData.append('anubisPolicy', $('#site-anubis-policy').value);
  formData.append('releaseMode', String($('#site-release-mode').checked));
  formData.append('manifestEnabled', String($('#site-manifest-enabled').checked));
  formData.append('cloudflareAutoSync', String($('#site-cloudflare-auto-sync').checked));
  formData.append('approveManifestChanges', String($('#site-approve-manifest').checked));
  formData.append('gitUrl', $('#site-git-url').value);
  formData.append('gitBranch', $('#site-git-branch').value || 'main');
  formData.append('previewDomain', $('#site-preview-domain').value);
  formData.append('maintenanceEnabled', String($('#site-maintenance-enabled').checked));
  formData.append('maintenanceHtml', $('#site-maintenance-html').value);
  formData.append('redirects', $('#site-redirects').value || '[]');
  formData.append('errorPages', $('#site-error-pages').value || '{}');
  formData.append('cacheRules', $('#site-cache-rules').value || '[]');
  formData.append('enabled', String($('#site-enabled').checked));
}

function appendUpload(formData, selection) {
  if (selection.archive) formData.append('archive', selection.archive, selection.archive.name);
  else {
    selection.files.forEach((file) => formData.append('files', file, file.name));
    formData.append('relativePaths', JSON.stringify(selection.paths));
  }
}

$('#site-form').addEventListener('submit', async (event) => {
  event.preventDefault();
  const id = $('#site-id').value;
  const button = $('#site-save');
  $('#site-form-error').textContent = '';
  setBusy(button, true, id ? 'Saving…' : 'Uploading…');
  try {
    let result;
    if (id) {
      result = await api(`/api/sites/${id}`, {
        method: 'PUT',
        body: {
          name: $('#site-name').value,
          runtimeType: $('#site-runtime').value,
          runtimePreset: selectedRuntimePreset(),
          startCommand: selectedStartCommand(),
          runtimePortEnv: $('#site-runtime-port-env').value || 'PORT',
          additionalListeners: $('#site-private-listeners').value || '[]',
          workingDirectory: $('#site-working-directory').value || '.',
          containerMode: $('#site-container-mode').value,
          containerPort: $('#site-container-port').value || '3000',
          dockerfilePath: $('#site-dockerfile-path').value || 'Dockerfile',
          buildpackBuilder: $('#site-buildpack-builder').value,
          composeFile: $('#site-compose-file').value || 'compose.yaml',
          composeService: $('#site-compose-service').value || 'app',
          proxyTarget: $('#site-proxy-target').value,
          proxyHostHeader: $('#site-proxy-host-header').value,
          proxyTimeoutMs: $('#site-proxy-timeout').value || '30000',
          installCommand: $('#site-install-command').value,
          buildCommand: $('#site-build-command').value,
          buildOutputDir: $('#site-build-output').value,
          port: $('#site-port').value,
          bindHost: $('#site-host').value,
          domain: $('#site-domain').value,
          entryFile: $('#site-entry').value || 'index.html',
          nodeEntry: $('#site-node-entry').value || 'server.js',
          cacheSeconds: $('#site-cache').value || '0',
          headers: $('#site-headers').value || '{}',
          spaFallback: $('#site-spa').checked,
          minify: $('#site-minify').checked,
          obfuscate: $('#site-obfuscate').checked,
          obfuscationRiskAcknowledged: $('#site-obfuscation-ack').checked,
          installDependencies: $('#site-install').checked,
          sslEnabled: $('#site-ssl').checked,
          domainOnly: $('#site-domain-only').checked,
          compression: $('#site-compression').checked,
          edgeEnabled: $('#site-edge').checked,
          securityPreset: $('#site-security-preset').value,
          csp: $('#site-csp').value,
          healthCheckPath: $('#site-health-path').value || '/',
          healthCheckInterval: $('#site-health-interval').value || '30',
          healthCheckType: $('#site-health-type').value,
          healthCheckCommand: $('#site-health-command').value,
          healthCheckStatusMin: $('#site-health-status-min').value || '200',
          healthCheckStatusMax: $('#site-health-status-max').value || '499',
          readinessType: $('#site-readiness-type').value,
          readinessPath: $('#site-readiness-path').value || '/',
          readinessCommand: $('#site-readiness-command').value,
          readinessStatusMin: $('#site-readiness-status-min').value || '200',
          readinessStatusMax: $('#site-readiness-status-max').value || '399',
          startupTimeoutSeconds: $('#site-startup-timeout').value || '30',
          shutdownGraceSeconds: $('#site-shutdown-grace').value || '10',
          blueGreenDrainSeconds: $('#site-blue-green-drain').value || '5',
          restartPolicy: $('#site-restart-policy').value,
          maxRestarts: $('#site-max-restarts').value || '5',
          memoryLimitMb: $('#site-memory-limit').value || '0',
          maxConnections: $('#site-max-connections').value || '0',
          firewallEnabled: $('#site-firewall-enabled').checked,
          firewallMode: $('#site-firewall-mode').value,
          firewallCloudflareAction: $('#site-firewall-action').value,
          firewallRateLimit: $('#site-firewall-rate').value || '0',
          firewallMaxBodyKb: $('#site-firewall-body').value || '0',
          firewallBlockedIps: $('#site-firewall-blocked-ips').value,
          firewallAllowedIps: $('#site-firewall-allowed-ips').value,
          firewallBlockedCountries: $('#site-firewall-blocked-countries').value,
          firewallAllowedCountries: $('#site-firewall-allowed-countries').value,
          firewallBlockBots: $('#site-firewall-bots').checked,
          runtimeIsolation: $('#site-runtime-isolation').value,
          containerImage: $('#site-runtime').value === 'container' && $('#site-container-mode').value === 'image' ? $('#site-runtime-container-image').value : $('#site-container-image').value,
          cpuLimit: $('#site-cpu-limit').value || '0',
          pidsLimit: $('#site-pids-limit').value || '128',
          outboundNetwork: $('#site-outbound-network').checked,
          anubisEnabled: $('#site-anubis-enabled').checked,
          anubisPreset: $('#site-anubis-preset').value,
          anubisDifficulty: $('#site-anubis-difficulty').value || '4',
          anubisPolicy: $('#site-anubis-policy').value,
          releaseMode: $('#site-release-mode').checked,
          manifestEnabled: $('#site-manifest-enabled').checked,
          cloudflareAutoSync: $('#site-cloudflare-auto-sync').checked,
          gitUrl: $('#site-git-url').value,
          gitBranch: $('#site-git-branch').value || 'main',
          previewDomain: $('#site-preview-domain').value,
          maintenanceEnabled: $('#site-maintenance-enabled').checked,
          maintenanceHtml: $('#site-maintenance-html').value,
          redirects: $('#site-redirects').value || '[]',
          errorPages: $('#site-error-pages').value || '{}',
          cacheRules: $('#site-cache-rules').value || '[]'
        }
      });
    } else {
      const source = $('#site-source').value || 'upload';
      if (source === 'upload') {
        if (!state.uploads.site) throw new Error('Choose a ZIP archive or project folder.');
        const uploadRuntime = $('#site-runtime').value;
        const entryFile = uploadRuntime === 'node' ? ($('#site-node-entry').value || 'server.js') : ($('#site-entry').value || 'index.html');
        if (['static', 'node'].includes(uploadRuntime) && !state.uploads.site.archive && !folderContainsEntry(state.uploads.site, entryFile)) {
          throw new Error(`The selected folder does not contain the configured entry file “${entryFile}” after removing its top-level folder.`);
        }
      }
      if (source === 'git' && !$('#site-create-git-url').value.trim()) throw new Error('Enter a Git repository URL.');
      if (source === 'image' && !$('#site-runtime-container-image').value.trim()) throw new Error('Enter an OCI image name.');
      if (source === 'proxy' && !$('#site-proxy-target').value.trim()) throw new Error('Enter the upstream HTTP(S) URL.');
      const formData = new FormData();
      appendConfiguration(formData);
      if (source === 'git') {
        formData.set('gitUrl', $('#site-create-git-url').value);
        formData.set('gitBranch', $('#site-create-git-branch').value || 'main');
      }
      if (source === 'upload') appendUpload(formData, state.uploads.site);
      result = await api('/api/sites', { method: 'POST', body: formData });
    }
    closeModal($('#site-dialog'));
    toast(result.warning || (id ? 'Site settings saved.' : 'Site deployed.'), result.warning ? 'warning' : 'success');
    await Promise.all([loadSites(), loadOverview()]);
  } catch (error) {
    $('#site-form-error').textContent = error.message;
  } finally { setBusy(button, false); }
});

function openContent(site) {
  state.contentSite = site;
  $('#content-site-id').value = site.id;
  $('#content-title').textContent = `Replace ${site.name}`;
  $('#content-form-error').textContent = '';
  clearUpload('content');
  showModal($('#content-dialog'));
}

$('#content-form').addEventListener('submit', async (event) => {
  event.preventDefault();
  const selection = state.uploads.content;
  const button = $('#content-form button[type="submit"]');
  $('#content-form-error').textContent = '';
  setBusy(button, true, 'Replacing…');
  try {
    if (!selection) throw new Error('Choose a ZIP archive or project folder.');
    const contentRuntime = state.contentSite?.runtime_type;
    const entryFile = contentRuntime === 'node' ? state.contentSite.node_entry : contentRuntime === 'static' ? state.contentSite?.entry_file : '';
    if (!selection.archive && entryFile && !folderContainsEntry(selection, entryFile)) {
      throw new Error(`The selected folder does not contain this site's entry file “${entryFile}” after removing its top-level folder.`);
    }
    const formData = new FormData();
    appendUpload(formData, selection);
    const result = await api(`/api/sites/${$('#content-site-id').value}/content`, { method: 'PUT', body: formData });
    closeModal($('#content-dialog'));
    const snapshotNote = result.rollbackSnapshot ? ` Rollback snapshot #${result.rollbackSnapshot.id} was retained.` : '';
    toast(`${result.warning || 'Project files replaced.'}${snapshotNote}`, result.warning ? 'warning' : 'success');
    await Promise.all([loadSites(), loadOverview()]);
  } catch (error) { $('#content-form-error').textContent = error.message; }
  finally { setBusy(button, false); }
});
