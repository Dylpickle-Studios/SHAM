'use strict';

function chartTimeLabel(value) {
  if (!value) return '';
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return '';
  return date.toLocaleString([], { month: 'short', day: 'numeric', hour: '2-digit', minute: '2-digit' });
}

function chartLaneGeometry(values, maximum, yTop, laneHeight, xStart = 170, xEnd = 880) {
  if (!values.length) return { line: '', area: '' };
  const max = Math.max(1, Number(maximum || Math.max(...values)));
  const points = values.map((raw, index) => {
    const value = Math.max(0, Number(raw || 0));
    const x = xStart + (index / Math.max(1, values.length - 1)) * (xEnd - xStart);
    const y = yTop + (1 - Math.min(max, value) / max) * laneHeight;
    return [x, y];
  });
  const line = points.map(([x, y], index) => `${index ? 'L' : 'M'}${x.toFixed(1)} ${y.toFixed(1)}`).join(' ');
  const bottom = yTop + laneHeight;
  const area = `${line} L${points.at(-1)[0].toFixed(1)} ${bottom.toFixed(1)} L${points[0][0].toFixed(1)} ${bottom.toFixed(1)} Z`;
  return { line, area };
}

function renderMetricLanes(target, series, timestamps = []) {
  const svg = $(target);
  if (!svg) return;
  const count = Math.max(...series.map((item) => item.values.length), 0);
  if (!count) {
    svg.innerHTML = '<text x="450" y="150" text-anchor="middle" class="chart-empty">No performance samples yet.</text>';
    return;
  }
  const laneHeight = 58;
  const laneGap = 23;
  const yStart = 16;
  const rows = series.map((item, index) => {
    const yTop = yStart + index * (laneHeight + laneGap);
    const maximum = Math.max(1, Number(item.max || Math.max(...item.values, 1)));
    const latest = Number(item.values.at(-1) || 0);
    const geometry = chartLaneGeometry(item.values, maximum, yTop, laneHeight);
    return `<g class="chart-lane-group ${item.className}">
      <rect class="chart-lane" x="165" y="${yTop - 5}" width="720" height="${laneHeight + 10}" rx="10"/>
      <line class="chart-lane-grid" x1="170" y1="${(yTop + laneHeight / 2).toFixed(1)}" x2="880" y2="${(yTop + laneHeight / 2).toFixed(1)}"/>
      <path class="metric-area ${item.className}" d="${geometry.area}"/>
      <path class="metric-line ${item.className}" d="${geometry.line}"/>
      <text class="chart-series-label ${item.className}" x="18" y="${yTop + 19}">${item.label}</text>
      <text class="chart-series-value" x="18" y="${yTop + 41}">${item.format(latest)}</text>
      <text class="chart-series-max" x="878" y="${yTop + 13}" text-anchor="end">max ${item.format(maximum)}</text>
    </g>`;
  }).join('');
  const startLabel = chartTimeLabel(timestamps[0]);
  const endLabel = chartTimeLabel(timestamps.at(-1));
  svg.innerHTML = `${rows}<g class="chart-time-axis"><text x="170" y="286">${escapeHtml(startLabel)}</text><text x="880" y="286" text-anchor="end">${escapeHtml(endLabel)}</text></g>`;
}

function renderPerformance(payload) {
  state.performance = payload;
  const current = payload.current;
  if (!current) return;
  $('#perf-cpu').textContent = `${Number(current.cpuPercent || 0).toFixed(1)}%`;
  $('#perf-load').textContent = `load ${Number(current.load?.one || 0).toFixed(2)}`;
  $('#perf-memory').textContent = formatBytes(current.memory?.rssBytes);
  $('#perf-heap').textContent = `heap ${formatBytes(current.memory?.heapUsedBytes)} / ${formatBytes(current.memory?.heapTotalBytes)}`;
  $('#perf-loop').textContent = `${Number(current.eventLoopP99Ms || 0).toFixed(0)} ms`;
  $('#perf-disk').textContent = `${Number(current.disk?.percent || 0).toFixed(1)}%`;
  $('#perf-disk-bytes').textContent = `${formatBytes(current.disk?.used)} of ${formatBytes(current.disk?.total)}`;
  $('#perf-sites').textContent = formatNumber(current.runningSites);
  $('#perf-traffic').textContent = `${Number(current.traffic?.requestsPerSecond || 0).toFixed(1)} req/s`;
  $('#perf-throughput').textContent = `${formatBytes(current.traffic?.bytesPerSecond || 0)}/s · ${Number(current.traffic?.errorRate || 0).toFixed(1)}% errors`;
  const queued = Object.values(current.queues || {}).reduce((sum, value) => sum + Number(value || 0), 0);
  $('#perf-queues').textContent = `${formatNumber(queued)} queued job${queued === 1 ? '' : 's'}`;

  const history = payload.history || [];
  renderMetricLanes('#performance-chart', [
    { label: 'CPU', className: 'cpu', values: history.map((sample) => Number(sample.cpuPercent || 0)), max: 100, format: (value) => `${Number(value).toFixed(1)}%` },
    { label: 'Memory', className: 'memory', values: history.map((sample) => Number(sample.memory?.rssBytes || 0)), format: (value) => formatBytes(value) },
    { label: 'Event loop', className: 'loop', values: history.map((sample) => Number(sample.eventLoopP99Ms || 0)), format: (value) => `${Number(value).toFixed(0)} ms` }
  ], history.map((sample) => sample.sampledAt || sample.sampled_at));

  $('#performance-alerts').innerHTML = payload.alerts?.length ? payload.alerts.map((alert) => `<div class="event-item actionable ${escapeHtml(alert.severity)}" data-alert-id="${alert.id}"><span class="event-icon">${alert.severity === 'critical' ? '!' : '△'}</span><div><strong>${escapeHtml(alert.title)}</strong><p>${escapeHtml(alert.detail)}</p><small>${escapeHtml(formatDate(alert.lastSeenAt))}</small></div><button class="button ghost" data-ack-alert type="button">Acknowledge</button></div>`).join('') : '<div class="empty-state compact"><p>No active performance alerts.</p></div>';
  $('#performance-sites').innerHTML = (current.sites || []).map((site) => `<tr><td>${escapeHtml(site.name)}</td><td>${escapeHtml(site.runtimeType)} · ${escapeHtml(site.isolation || 'process')}${site.anubis ? ' · Anubis' : ''}${site.pid ? ` · PID ${site.pid}` : ''}</td><td>${Number(site.cpuPercent || 0).toFixed(1)}%</td><td>${Number(site.traffic?.requestsPerSecond || 0).toFixed(1)} req/s<br><small>${formatNumber(site.traffic?.requestDelta || 0)} sampled · ${formatBytes(site.traffic?.bytesPerSecond || 0)}/s</small></td><td>${Number(site.traffic?.p50ResponseMs || 0).toFixed(0)} ms p50<br><small>${Number(site.traffic?.p95ResponseMs || 0).toFixed(0)} ms p95 · ${Number(site.traffic?.averageResponseMs || 0).toFixed(0)} ms avg</small></td><td><span class="badge ${Number(site.traffic?.errorRate || 0) >= 25 ? 'error' : ''}">${Number(site.traffic?.errorRate || 0).toFixed(1)}%</span></td><td>${site.memory ? formatBytes(site.memory.rssBytes) : 'Unavailable'}${site.memoryLimitBytes ? ` / ${formatBytes(site.memoryLimitBytes)}` : ''}</td><td><span class="badge ${site.health?.status || ''}">${escapeHtml(site.health?.status || 'starting')}</span>${site.health?.latencyMs ? ` ${site.health.latencyMs} ms` : ''}</td><td>${formatNumber(site.connections)}</td><td>${formatNumber(site.restarts)}</td></tr>`).join('') || '<tr><td colspan="10" class="muted">No hosted runtime is currently running.</td></tr>';
  syncPerformanceSiteSelector(current.sites || []);
}

let performanceHistorySiteId = null;
let performanceRules = [];
let performanceRuleEditIndex = null;
let performanceRulesSaveRequest = 0;
let performanceRulesSaveTail = Promise.resolve();

const PERFORMANCE_RULE_KINDS = {
  cpu_percent: { label: 'CPU', unit: '%', help: 'Alert when CPU reaches or exceeds this percentage.' },
  memory_percent: { label: 'Memory', unit: '% of limit', help: 'Alert when memory reaches this percentage of the configured site memory limit.' },
  p95_response_ms: { label: 'p95 latency', unit: 'ms', help: 'Alert when p95 response latency reaches or exceeds this many milliseconds.' },
  request_rate: { label: 'Request rate', unit: 'req/s', help: 'Alert when sampled request rate reaches or exceeds this value.' },
  error_percent: { label: 'Error rate', unit: '%', help: 'Alert when the sampled HTTP error rate reaches or exceeds this percentage.' },
  traffic_multiplier: { label: 'Traffic spike', unit: '× baseline', help: 'Alert when traffic is this multiple of the recent baseline.' }
};

function syncPerformanceSiteSelector(sites) {
  const select = $('#performance-site-history-select');
  const previous = Number(select.value || performanceHistorySiteId || 0);
  select.innerHTML = sites.map((site) => `<option value="${site.id}">${escapeHtml(site.name)}</option>`).join('');
  const next = sites.some((site) => Number(site.id) === previous) ? previous : Number(sites[0]?.id || 0);
  if (!next) {
    performanceHistorySiteId = null;
    performanceRules = [];
    $('#performance-site-chart').innerHTML = '';
    $('#performance-site-history-detail').textContent = 'No managed runtime has performance history yet.';
    $('#performance-alert-rules').innerHTML = '<p class="muted">Choose a site to configure alert rules.</p>';
    $('#performance-add-rule').disabled = true;
    $('#performance-rules-status').textContent = '';
    return;
  }
  $('#performance-add-rule').disabled = false;
  select.value = String(next);
  if (Number(performanceHistorySiteId) !== next) {
    performanceHistorySiteId = next;
    loadSelectedSitePerformance().catch((error) => toast(error.message, 'error'));
  }
}

function renderSiteHistory(history) {
  const latencyMax = Math.max(1, ...history.map((row) => Number(row.p95ResponseMs || 0)), ...history.map((row) => Number(row.p50ResponseMs || 0)));
  renderMetricLanes('#performance-site-chart', [
    { label: 'CPU', className: 'cpu', values: history.map((row) => Number(row.cpuPercent || 0)), max: 100, format: (value) => `${Number(value).toFixed(1)}%` },
    { label: 'p50 latency', className: 'memory', values: history.map((row) => Number(row.p50ResponseMs || 0)), max: latencyMax, format: (value) => `${Number(value).toFixed(0)} ms` },
    { label: 'p95 latency', className: 'loop', values: history.map((row) => Number(row.p95ResponseMs || 0)), max: latencyMax, format: (value) => `${Number(value).toFixed(0)} ms` }
  ], history.map((row) => row.sampledAt || row.sampled_at));
  const latest = history.at(-1);
  $('#performance-site-history-detail').textContent = latest ? `${history.length} samples · latest ${Number(latest.cpuPercent || 0).toFixed(1)}% CPU · ${Number(latest.p50ResponseMs || 0).toFixed(0)} ms p50 · ${Number(latest.p95ResponseMs || 0).toFixed(0)} ms p95` : 'No persisted samples for this site yet.';
}

function formatRuleThreshold(rule) {
  const value = Number(rule.threshold || 0);
  if (rule.kind === 'traffic_multiplier') return `${value.toFixed(1)}× baseline`;
  if (rule.kind === 'request_rate') return `${value.toFixed(1)} req/s`;
  if (rule.kind === 'p95_response_ms') return `${value.toFixed(0)} ms`;
  return `${value.toFixed(1)}%`;
}

function renderAlertRules(rules = performanceRules) {
  performanceRules = (rules || []).map((rule) => ({
    kind: PERFORMANCE_RULE_KINDS[rule.kind] ? rule.kind : 'cpu_percent',
    threshold: Math.max(0, Number(rule.threshold || 0)),
    severity: rule.severity === 'critical' ? 'critical' : 'warning',
    enabled: rule.enabled !== false
  }));
  const target = $('#performance-alert-rules');
  const admin = state.user?.role === 'admin';
  target.classList.add('performance-rule-list');
  target.innerHTML = performanceRules.length ? performanceRules.map((rule, index) => {
    const meta = PERFORMANCE_RULE_KINDS[rule.kind];
    return `<article class="performance-rule-card ${rule.enabled ? '' : 'is-disabled'}" data-performance-rule-index="${index}">
      <div class="performance-rule-summary"><span class="performance-rule-icon">⌁</span><div><strong>${escapeHtml(meta.label)}</strong><small>${escapeHtml(meta.help)}</small></div></div>
      <div class="performance-rule-threshold"><span>Threshold</span><strong>${escapeHtml(formatRuleThreshold(rule))}</strong></div>
      <div class="performance-rule-state"><span class="badge ${rule.severity === 'critical' ? 'critical' : 'warning'}">${rule.severity === 'critical' ? 'Critical' : 'Warning'}</span><span class="badge ${rule.enabled ? 'success' : ''}">${rule.enabled ? 'Enabled' : 'Disabled'}</span></div>
      ${admin ? '<div class="performance-rule-actions"><button class="button ghost compact" data-edit-performance-rule type="button">Edit</button><button class="button danger compact" data-remove-performance-rule type="button">Remove</button></div>' : ''}
    </article>`;
  }).join('') : '<div class="empty-state compact performance-rule-empty"><p>No site-specific rules. Global thresholds still apply.</p></div>';
  $('#performance-add-rule').hidden = !admin;
}

async function persistPerformanceRules(siteId, rulesSnapshot) {
  const requestId = ++performanceRulesSaveRequest;
  const status = $('#performance-rules-status');
  if (status) status.textContent = 'Saving changes…';
  try {
    await api(`/api/sites/${siteId}/alert-rules`, { method: 'PUT', body: { rules: rulesSnapshot } });
    if (requestId === performanceRulesSaveRequest && Number($('#performance-site-history-select').value || 0) === siteId && status) status.textContent = 'Saved.';
  } catch (error) {
    if (requestId === performanceRulesSaveRequest && status) status.textContent = 'Save failed.';
    toast(error.message, 'error');
    if (Number($('#performance-site-history-select').value || 0) === siteId) await loadSelectedSitePerformance();
  }
}

function saveCurrentPerformanceRules() {
  const siteId = Number($('#performance-site-history-select').value || 0);
  if (!siteId) return Promise.resolve();
  const snapshot = performanceRules.map((rule) => ({ ...rule }));
  performanceRulesSaveTail = performanceRulesSaveTail.catch(() => {}).then(() => persistPerformanceRules(siteId, snapshot));
  return performanceRulesSaveTail;
}

function updatePerformanceRuleHelp() {
  const meta = PERFORMANCE_RULE_KINDS[$('#performance-rule-kind').value] || PERFORMANCE_RULE_KINDS.cpu_percent;
  $('#performance-rule-threshold-help').textContent = meta.help;
}

function openPerformanceRuleEditor(index = null) {
  performanceRuleEditIndex = Number.isInteger(index) ? index : null;
  const rule = performanceRuleEditIndex === null ? { kind: 'cpu_percent', threshold: 90, severity: 'warning', enabled: true } : performanceRules[performanceRuleEditIndex];
  if (!rule) return;
  $('#performance-rule-title').textContent = performanceRuleEditIndex === null ? 'Add alert rule' : 'Edit alert rule';
  $('#performance-rule-submit').textContent = performanceRuleEditIndex === null ? 'Add rule' : 'Save rule';
  $('#performance-rule-kind').value = rule.kind;
  $('#performance-rule-threshold').value = String(rule.threshold);
  $('#performance-rule-severity').value = rule.severity;
  $('#performance-rule-enabled').checked = rule.enabled !== false;
  $('#performance-rule-error').textContent = '';
  updatePerformanceRuleHelp();
  showModal($('#performance-rule-dialog'));
  requestAnimationFrame(() => $('#performance-rule-kind').focus());
}

async function loadSelectedSitePerformance() {
  const siteId = Number($('#performance-site-history-select').value || performanceHistorySiteId || 0);
  if (!siteId) return;
  performanceHistorySiteId = siteId;
  const [history, rules] = await Promise.all([
    api(`/api/sites/${siteId}/performance/history?limit=2016`),
    api(`/api/sites/${siteId}/alert-rules`)
  ]);
  if (siteId !== performanceHistorySiteId) return;
  renderSiteHistory(history.history || []);
  renderAlertRules(rules.rules || []);
  $('#performance-rules-status').textContent = '';
}

$('#performance-site-history-select').addEventListener('change', () => {
  performanceHistorySiteId = Number($('#performance-site-history-select').value || 0);
  loadSelectedSitePerformance().catch((error) => toast(error.message, 'error'));
});
$('#performance-add-rule').addEventListener('click', () => openPerformanceRuleEditor());
$('#performance-rule-kind').addEventListener('change', updatePerformanceRuleHelp);
$('#performance-rule-form').addEventListener('submit', (event) => {
  event.preventDefault();
  const threshold = Number($('#performance-rule-threshold').value);
  if (!Number.isFinite(threshold) || threshold < 0) {
    $('#performance-rule-error').textContent = 'Enter a threshold of zero or greater.';
    $('#performance-rule-threshold').focus();
    return;
  }
  const rule = {
    kind: $('#performance-rule-kind').value,
    threshold,
    severity: $('#performance-rule-severity').value === 'critical' ? 'critical' : 'warning',
    enabled: $('#performance-rule-enabled').checked
  };
  if (performanceRuleEditIndex === null) performanceRules.push(rule);
  else performanceRules[performanceRuleEditIndex] = rule;
  renderAlertRules(performanceRules);
  closeModal($('#performance-rule-dialog'));
  performanceRuleEditIndex = null;
  saveCurrentPerformanceRules();
});
$('#performance-rule-dialog').addEventListener('close', () => { performanceRuleEditIndex = null; });
$('#performance-alert-rules').addEventListener('click', (event) => {
  const card = event.target.closest('[data-performance-rule-index]');
  if (!card) return;
  const index = Number(card.dataset.performanceRuleIndex);
  if (event.target.closest('[data-edit-performance-rule]')) openPerformanceRuleEditor(index);
  if (event.target.closest('[data-remove-performance-rule]')) {
    performanceRules.splice(index, 1);
    renderAlertRules(performanceRules);
    saveCurrentPerformanceRules();
  }
});

let performanceRequest = null;
let performanceController = null;
let performanceRequestId = 0;
async function loadPerformance({ force = false } = {}) {
  if (performanceRequest && !force) return performanceRequest;
  if (force) performanceController?.abort();
  const requestId = ++performanceRequestId;
  const controller = new AbortController();
  performanceController = controller;
  const button = $('#refresh-performance');
  button?.setAttribute('aria-busy', 'true');
  button?.classList.add('is-loading');
  if (button) button.disabled = true;
  const pending = (async () => {
    try {
      const payload = await api(force ? '/api/performance?refresh=1' : '/api/performance', { signal: controller.signal });
      if (requestId === performanceRequestId) renderPerformance(payload);
      return payload;
    } catch (error) {
      if (error.name !== 'AbortError' && requestId === performanceRequestId) toast(error.message, 'error');
      return null;
    } finally {
      if (requestId === performanceRequestId) {
        performanceRequest = null;
        performanceController = null;
        button?.removeAttribute('aria-busy');
        button?.classList.remove('is-loading');
        if (button) button.disabled = false;
      }
    }
  })();
  performanceRequest = pending;
  return pending;
}
function startPerformancePolling() {
  if (state.performanceTimer) return;
  loadPerformance();
  state.performanceTimer = setInterval(() => { if (state.currentSection === 'performance') loadPerformance(); }, 5000);
}
function stopPerformancePolling() {
  clearInterval(state.performanceTimer);
  state.performanceTimer = null;
  performanceController?.abort();
  performanceRequestId += 1;
  performanceRequest = null;
  performanceController = null;
  const button = $('#refresh-performance');
  button?.removeAttribute('aria-busy');
  button?.classList.remove('is-loading');
  if (button) button.disabled = false;
}
$('#refresh-performance').addEventListener('click', () => loadPerformance({ force: true }));
$('#performance-alerts').addEventListener('click', async (event) => {
  const button = event.target.closest('[data-ack-alert]');
  if (!button) return;
  const item = button.closest('[data-alert-id]');
  try { await api(`/api/performance/alerts/${item.dataset.alertId}/acknowledge`, { method: 'POST' }); await loadPerformance(); }
  catch (error) { toast(error.message, 'error'); }
});
