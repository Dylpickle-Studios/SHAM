const fs = require('node:fs');
const os = require('node:os');
const { monitorEventLoopDelay } = require('node:perf_hooks');
const { DATA_DIR, PERFORMANCE_INTERVAL_MS, PERFORMANCE_HISTORY_SAMPLES, PERFORMANCE_SITE_CONCURRENCY } = require('./config');
const { uploadQueueStats } = require('./upload-utils');
const { getRuntimeClient } = require('./runtime/client');

function safeNumber(value, fallback = 0) {
  const number = Number(value);
  return Number.isFinite(number) ? number : fallback;
}

async function diskUsage(target) {
  try {
    const stats = await fs.promises.statfs(target);
    const blockSize = Number(stats.bsize || stats.frsize || 0);
    const total = Number(stats.blocks || 0) * blockSize;
    const free = Number(stats.bavail || stats.bfree || 0) * blockSize;
    return { total, free, used: Math.max(0, total - free), percent: total ? ((total - free) / total) * 100 : 0 };
  } catch {
    return { total: 0, free: 0, used: 0, percent: 0 };
  }
}

async function processMemory(pid) {
  if (!pid || process.platform !== 'linux') return null;
  try {
    const status = await fs.promises.readFile(`/proc/${pid}/status`, 'utf8');
    const rss = /VmRSS:\s+(\d+)\s+kB/i.exec(status);
    const swap = /VmSwap:\s+(\d+)\s+kB/i.exec(status);
    return { rssBytes: safeNumber(rss?.[1]) * 1024, swapBytes: safeNumber(swap?.[1]) * 1024 };
  } catch { return null; }
}

async function processUsage(pid, previousTicks, elapsedSeconds) {
  if (!pid || process.platform !== 'linux') return { memory: null, cpuPercent: 0, ticks: null };
  try {
    const [memory, stat] = await Promise.all([processMemory(pid), fs.promises.readFile(`/proc/${pid}/stat`, 'utf8')]);
    const close = stat.lastIndexOf(')');
    const fields = stat.slice(close + 2).trim().split(/\s+/);
    const ticks = safeNumber(fields[11]) + safeNumber(fields[12]);
    const cpuPercent = previousTicks == null || elapsedSeconds <= 0 ? 0 : Math.max(0, ((ticks - previousTicks) / 100 / elapsedSeconds) * 100);
    return { memory, cpuPercent, ticks };
  } catch { return { memory: null, cpuPercent: 0, ticks: null }; }
}

async function dockerUsage(containerId) {
  if (!containerId) return { memory: null, cpuPercent: 0 };
  try {
    const row = await getRuntimeClient().containerStats({ id: String(containerId) });
    const cpuPercent = safeNumber(String(row?.CPUPerc || row?.CPU || '0').replace('%', ''));
    const memoryText = String(row?.MemUsage || row?.Mem || '').split('/')[0].trim();
    const match = /([\d.]+)\s*(B|KiB|MiB|GiB|KB|MB|GB)/i.exec(memoryText);
    const units = { b: 1, kib: 1024, mib: 1024 ** 2, gib: 1024 ** 3, kb: 1000, mb: 1000 ** 2, gb: 1000 ** 3 };
    const rssBytes = match ? safeNumber(match[1]) * (units[String(match[2]).toLowerCase()] || 1) : 0;
    return { memory: { rssBytes, swapBytes: 0 }, cpuPercent };
  } catch { return { memory: null, cpuPercent: 0 }; }
}

function percentile(samples, p) {
  if (!samples?.length) return 0;
  const sorted = samples.slice().sort((a, b) => a - b);
  const index = Math.min(sorted.length - 1, Math.max(0, Math.ceil((p / 100) * sorted.length) - 1));
  return safeNumber(sorted[index]);
}

function mergeCounters(row, pending = {}) {
  return {
    requests: safeNumber(row?.totalRequests) + safeNumber(pending.requests),
    bytes: safeNumber(row?.totalBytes) + safeNumber(pending.bytes),
    errors: safeNumber(row?.totalErrors) + safeNumber(pending.errors),
    responseMs: safeNumber(row?.totalResponseMs) + safeNumber(pending.responseMs)
  };
}

function counterDelta(current, previous, key) {
  if (!previous) return 0;
  return Math.max(0, safeNumber(current[key]) - safeNumber(previous[key]));
}

async function mapWithConcurrency(items, limit, mapper) {
  const results = new Array(items.length);
  let nextIndex = 0;
  const workers = Array.from({ length: Math.min(Math.max(limit, 1), items.length) }, async () => {
    while (nextIndex < items.length) {
      const index = nextIndex;
      nextIndex += 1;
      results[index] = await mapper(items[index], index);
    }
  });
  await Promise.all(workers);
  return results;
}

class PerformanceMonitor {
  constructor({ db, manager, snapshotManager = null, dependencyScanner = null }) {
    this.db = db;
    this.manager = manager;
    this.snapshotManager = snapshotManager;
    this.dependencyScanner = dependencyScanner;
    this.samples = [];
    this.previousCpu = process.cpuUsage();
    this.previousTime = process.hrtime.bigint();
    this.previousSiteCounters = new Map();
    this.previousProcessTicks = new Map();
    this.trafficBaselines = new Map();
    this.loop = monitorEventLoopDelay({ resolution: 20 });
    this.loop.enable();
    this.activeAlerts = new Map();
    this.sampleCount = 0;
    this.currentSamplePromise = null;
    this.readSiteStats = db.prepare(`
      SELECT site_id AS siteId, total_requests AS totalRequests, total_bytes AS totalBytes,
             total_errors AS totalErrors, total_response_ms AS totalResponseMs
      FROM site_stats
    `);
    this.readSiteMetadata = db.prepare('SELECT id, name, memory_limit_mb AS memoryLimitMb, runtime_isolation FROM sites');
    this.readAlertRules = db.prepare('SELECT site_id AS siteId, kind, threshold, severity FROM alert_rules WHERE enabled = 1');
    this.writeSiteSample = db.prepare(`INSERT INTO site_performance_samples (site_id, sampled_at, cpu_percent, rss_bytes, request_rate, error_rate, avg_response_ms, p50_response_ms, p95_response_ms, connections, restarts) VALUES (?, CURRENT_TIMESTAMP, ?, ?, ?, ?, ?, ?, ?, ?, ?)`);
    this.pruneSiteSamples = db.prepare("DELETE FROM site_performance_samples WHERE sampled_at < datetime('now', '-7 days')");
    this.readSetting = db.prepare('SELECT value FROM settings WHERE key = ?');
    this.pruneSamples = db.prepare("DELETE FROM performance_samples WHERE sampled_at < datetime('now', '-7 days')");
    this.writeSample = db.prepare(`
      INSERT INTO performance_samples (sampled_at, cpu_percent, rss_bytes, heap_bytes, event_loop_ms, disk_percent, load_1m, running_sites)
      VALUES (CURRENT_TIMESTAMP, ?, ?, ?, ?, ?, ?, ?)
    `);
    this.insertAlert = db.prepare(`
      INSERT INTO alerts (kind, severity, title, detail, site_id, fingerprint, created_at, last_seen_at)
      VALUES (?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP)
      ON CONFLICT(fingerprint, acknowledged) DO UPDATE SET detail = excluded.detail, last_seen_at = CURRENT_TIMESTAMP
    `);
    this.timer = setInterval(() => this.runSample().catch((error) => this.manager.log(null, 'error', `Performance monitor failed: ${error.message}`)), PERFORMANCE_INTERVAL_MS);
    this.timer.unref?.();
    this.runSample().catch((error) => this.manager.log(null, 'error', `Performance monitor failed: ${error.message}`));
  }

  runSample() {
    if (this.currentSamplePromise) return this.currentSamplePromise;
    const tracked = Promise.resolve().then(() => this.sample());
    this.currentSamplePromise = tracked;
    tracked.finally(() => {
      if (this.currentSamplePromise === tracked) this.currentSamplePromise = null;
    }).catch(() => {});
    return tracked;
  }

  threshold(key, fallback) {
    const row = this.readSetting.get(key);
    const value = Number(row?.value);
    return Number.isFinite(value) ? value : fallback;
  }

  raise(kind, severity, title, detail, siteId = null) {
    const fingerprint = `${kind}:${siteId || 'instance'}`;
    const previous = this.activeAlerts.get(fingerprint);
    if (previous && Date.now() - previous < 60_000) return;
    this.activeAlerts.set(fingerprint, Date.now());
    if (this.activeAlerts.size > 10_000) {
      const oldest = [...this.activeAlerts.entries()].sort((a, b) => a[1] - b[1]).slice(0, this.activeAlerts.size - 10_000);
      for (const [key] of oldest) this.activeAlerts.delete(key);
    }
    try { this.insertAlert.run(kind, severity, title, detail, siteId, fingerprint); }
    catch (error) { this.manager.log(siteId, 'error', `Could not store alert: ${error.message}`); }
  }

  updateTrafficBaseline(id, requestsPerSecond) {
    const current = this.trafficBaselines.get(id) || { samples: 0, requestsPerSecond: 0 };
    const next = {
      samples: current.samples + 1,
      requestsPerSecond: current.samples ? (current.requestsPerSecond * 0.85) + (requestsPerSecond * 0.15) : requestsPerSecond
    };
    this.trafficBaselines.set(id, next);
    return current;
  }

  async sampleSites(elapsedSeconds, thresholds) {
    const rows = new Map(this.readSiteStats.all().map((row) => [Number(row.siteId), row]));
    const metadata = new Map(this.readSiteMetadata.all().map((site) => [Number(site.id), site]));
    const rules = new Map();
    for (const row of this.readAlertRules.all()) {
      const key = `${row.siteId == null ? 'global' : Number(row.siteId)}:${row.kind}`;
      rules.set(key, { threshold: safeNumber(row.threshold), severity: row.severity || 'warning' });
    }
    const rule = (id, kind, fallback = 0) => rules.get(`${id}:${kind}`) || rules.get(`global:${kind}`) || { threshold: fallback, severity: 'warning' };
    const running = [...this.manager.running];
    const activeIds = new Set(running.map(([id]) => Number(id)));
    const sites = await mapWithConcurrency(running, PERFORMANCE_SITE_CONCURRENCY, async ([rawId, runtime]) => {
      const id = Number(rawId);
      const site = metadata.get(id);
      const status = this.manager.statusFor(id, site);
      const backend = runtime.backend || runtime;
      let usage;
      if (['container', 'compose'].includes(backend.driver)) usage = await dockerUsage(backend.containerId);
      else {
        usage = await processUsage(backend.child?.pid, this.previousProcessTicks.get(id), elapsedSeconds);
        if (usage.ticks != null) this.previousProcessTicks.set(id, usage.ticks);
      }
      const memory = usage.memory;
      const totals = mergeCounters(rows.get(id), this.manager.pendingStats?.get(id));
      const previous = this.previousSiteCounters.get(id);
      const requestDelta = counterDelta(totals, previous, 'requests');
      const byteDelta = counterDelta(totals, previous, 'bytes');
      const errorDelta = counterDelta(totals, previous, 'errors');
      const responseDelta = counterDelta(totals, previous, 'responseMs');
      this.previousSiteCounters.set(id, totals);
      const requestsPerSecond = requestDelta / elapsedSeconds;
      const bytesPerSecond = byteDelta / elapsedSeconds;
      const errorRate = requestDelta ? (errorDelta / requestDelta) * 100 : 0;
      const averageResponseMs = requestDelta ? responseDelta / requestDelta : 0;
      const latencySamples = this.manager.takeLatencySamples?.(id) || [];
      const p50ResponseMs = percentile(latencySamples, 50);
      const p95ResponseMs = percentile(latencySamples, 95);
      const priorBaseline = this.updateTrafficBaseline(id, requestsPerSecond);
      const trafficRule = rule(id, 'traffic_multiplier', thresholds.trafficMultiplier);
      if (priorBaseline.samples >= 12 && requestsPerSecond >= 2 && trafficRule.threshold > 0 && requestsPerSecond > Math.max(5, priorBaseline.requestsPerSecond * trafficRule.threshold)) this.raise('traffic-spike', trafficRule.severity, `${site?.name || `Site ${id}`} traffic increased sharply`, `${requestsPerSecond.toFixed(1)} requests/s is more than ${trafficRule.threshold.toFixed(1)}× its recent baseline of ${priorBaseline.requestsPerSecond.toFixed(1)} requests/s.`, id);
      const errorRule = rule(id, 'error_percent', thresholds.errorPercent);
      if (requestDelta >= 20 && errorRule.threshold > 0 && errorRate >= errorRule.threshold) this.raise('site-error-rate', errorRate >= 50 ? 'critical' : errorRule.severity, `${site?.name || `Site ${id}`} has a high error rate`, `${errorRate.toFixed(1)}% of ${requestDelta} recent requests failed.`, id);
      const cpuRule = rule(id, 'cpu_percent', 0);
      if (cpuRule.threshold > 0 && usage.cpuPercent >= cpuRule.threshold) this.raise('site-cpu', cpuRule.severity, `${site?.name || `Site ${id}`} has high CPU usage`, `${usage.cpuPercent.toFixed(1)}% CPU exceeds the ${cpuRule.threshold.toFixed(1)}% site threshold.`, id);
      const p95Rule = rule(id, 'p95_response_ms', 0);
      if (p95Rule.threshold > 0 && p95ResponseMs >= p95Rule.threshold && latencySamples.length >= 5) this.raise('site-latency', p95Rule.severity, `${site?.name || `Site ${id}`} has high p95 latency`, `${p95ResponseMs.toFixed(0)} ms p95 exceeds the ${p95Rule.threshold.toFixed(0)} ms threshold.`, id);
      const requestRule = rule(id, 'request_rate', 0);
      if (requestRule.threshold > 0 && requestsPerSecond >= requestRule.threshold) this.raise('site-request-rate', requestRule.severity, `${site?.name || `Site ${id}`} has high request volume`, `${requestsPerSecond.toFixed(1)} requests/s exceeds the ${requestRule.threshold.toFixed(1)} requests/s threshold.`, id);
      const item = {
        id, name: site?.name || `Site ${id}`, runtimeType: backend.driver || runtime.type,
        isolation: status.isolation || 'process', anubis: Boolean(status.anubis), webSockets: Number(status.webSockets || 0),
        pid: backend.child?.pid || null, cpuPercent: usage.cpuPercent || 0, memory,
        memoryLimitBytes: site?.memoryLimitMb ? site.memoryLimitMb * 1024 * 1024 : 0,
        health: status.health || null, restarts: status.restarts || 0, connections: runtime.server?._connections || 0,
        traffic: { requestDelta, byteDelta, errorDelta, requestsPerSecond, bytesPerSecond, errorRate, averageResponseMs, p50ResponseMs, p95ResponseMs, latencySamples: latencySamples.length }
      };
      const memoryRule = rule(id, 'memory_percent', 110);
      if (memory?.rssBytes && item.memoryLimitBytes && memoryRule.threshold > 0 && memory.rssBytes > item.memoryLimitBytes * (memoryRule.threshold / 100)) {
        this.raise('site-memory', memoryRule.severity === 'warning' && memoryRule.threshold <= 100 ? 'critical' : memoryRule.severity, `${item.name} exceeded its memory threshold`, `${Math.round(memory.rssBytes / 1024 / 1024)} MB used; configured limit ${site.memoryLimitMb} MB.`, id);
        if (memory.rssBytes > item.memoryLimitBytes * 1.1) this.manager.handleResourceLimit?.(id, 'memory').catch(() => {});
      }
      try { this.writeSiteSample.run(id, item.cpuPercent, memory?.rssBytes || 0, requestsPerSecond, errorRate, averageResponseMs, p50ResponseMs, p95ResponseMs, item.connections, item.restarts); }
      catch (error) { this.manager.log(id, 'error', `Could not persist site performance sample: ${error.message}`); }
      return item;
    });
    for (const id of this.previousSiteCounters.keys()) if (!activeIds.has(Number(id))) this.previousSiteCounters.delete(id);
    for (const id of this.previousProcessTicks.keys()) if (!activeIds.has(Number(id))) this.previousProcessTicks.delete(id);
    for (const id of this.trafficBaselines.keys()) if (!activeIds.has(Number(id))) this.trafficBaselines.delete(id);
    return sites;
  }

  async sample() {
    const nowTime = process.hrtime.bigint();
    const elapsedMicros = Number(nowTime - this.previousTime) / 1000;
    const elapsedSeconds = Math.max(elapsedMicros / 1_000_000, 0.001);
    const currentCpu = process.cpuUsage();
    const cpuDelta = (currentCpu.user - this.previousCpu.user) + (currentCpu.system - this.previousCpu.system);
    this.previousCpu = currentCpu;
    this.previousTime = nowTime;
    const cpuPercent = elapsedMicros > 0 ? Math.min(100 * os.cpus().length, (cpuDelta / elapsedMicros) * 100) : 0;
    const memory = process.memoryUsage();
    const eventLoopMs = this.loop.mean ? this.loop.mean / 1e6 : 0;
    const eventLoopP99Ms = safeNumber(this.loop.percentile(99) / 1e6);
    this.loop.reset();
    const disk = await diskUsage(DATA_DIR);
    const load = os.loadavg();
    const thresholds = {
      cpuPercent: this.threshold('alert_cpu_percent', 90),
      eventLoopMs: this.threshold('alert_event_loop_ms', 250),
      diskPercent: this.threshold('alert_disk_percent', 90),
      trafficMultiplier: this.threshold('alert_traffic_multiplier', 5),
      errorPercent: this.threshold('alert_error_percent', 25)
    };
    const sites = await this.sampleSites(elapsedSeconds, thresholds);
    const traffic = sites.reduce((total, site) => {
      total.requestsPerSecond += site.traffic.requestsPerSecond;
      total.bytesPerSecond += site.traffic.bytesPerSecond;
      total.requests += site.traffic.requestDelta;
      total.errors += site.traffic.errorDelta;
      return total;
    }, { requestsPerSecond: 0, bytesPerSecond: 0, requests: 0, errors: 0 });
    traffic.errorRate = traffic.requests ? (traffic.errors / traffic.requests) * 100 : 0;
    const uploads = uploadQueueStats();
    const sample = {
      timestamp: new Date().toISOString(),
      intervalSeconds: elapsedSeconds,
      cpuPercent,
      memory: { rssBytes: memory.rss, heapUsedBytes: memory.heapUsed, heapTotalBytes: memory.heapTotal, externalBytes: memory.external },
      eventLoopMs,
      eventLoopP99Ms,
      disk,
      load: { one: load[0], five: load[1], fifteen: load[2] },
      uptimeSeconds: process.uptime(),
      systemUptimeSeconds: os.uptime(),
      runningSites: this.manager.running.size,
      traffic,
      queues: {
        transformations: this.manager.minifyQueue?.length || 0,
        compressions: (this.manager.compressionQueue?.length || 0) + (this.manager.compressionActive || 0),
        dependencyInstalls: this.manager.installQueue?.length || 0,
        uploads: uploads.queued,
        activeUploads: uploads.active,
        dependencyScans: this.dependencyScanner?.queueLength?.() || 0,
        snapshots: this.snapshotManager?.queueLength?.() || 0
      },
      sites
    };
    this.samples.push(sample);
    if (this.samples.length > PERFORMANCE_HISTORY_SAMPLES) this.samples.splice(0, this.samples.length - PERFORMANCE_HISTORY_SAMPLES);
    this.sampleCount += 1;
    try {
      this.writeSample.run(cpuPercent, memory.rss, memory.heapUsed, eventLoopP99Ms, disk.percent, load[0], this.manager.running.size);
      if (this.sampleCount % 60 === 0) { this.pruneSamples.run(); this.pruneSiteSamples.run(); }
    } catch (error) { this.manager.log(null, 'error', `Could not persist performance sample: ${error.message}`); }

    if (cpuPercent > thresholds.cpuPercent) this.raise('instance-cpu', 'warning', 'High SHAM CPU usage', `${cpuPercent.toFixed(1)}% CPU used by the dashboard process.`);
    if (eventLoopP99Ms > thresholds.eventLoopMs) this.raise('event-loop', 'warning', 'Dashboard event loop is delayed', `99th percentile delay is ${eventLoopP99Ms.toFixed(0)} ms.`);
    if (disk.percent > thresholds.diskPercent) this.raise('disk', 'critical', 'Storage is nearly full', `${disk.percent.toFixed(1)}% of the configured storage filesystem is used.`);
    return sample;
  }

  current() { return this.samples[this.samples.length - 1] || null; }
  history(limit = 120) { return this.samples.slice(-Math.min(Math.max(Number(limit) || 120, 1), PERFORMANCE_HISTORY_SAMPLES)); }

  payload() {
    return {
      current: this.current(),
      history: this.history(),
      alerts: this.db.prepare(`SELECT id, kind, severity, title, detail, site_id AS siteId, created_at AS createdAt, last_seen_at AS lastSeenAt FROM alerts WHERE acknowledged = 0 ORDER BY last_seen_at DESC LIMIT 100`).all()
    };
  }

  acknowledge(alertId) {
    const transaction = this.db.transaction(() => {
      const row = this.db.prepare('SELECT id, fingerprint FROM alerts WHERE id = ? AND acknowledged = 0').get(alertId);
      if (!row) return false;
      this.db.prepare('DELETE FROM alerts WHERE fingerprint = ? AND acknowledged = 1').run(row.fingerprint);
      this.db.prepare('UPDATE alerts SET acknowledged = 1, acknowledged_at = CURRENT_TIMESTAMP WHERE id = ?').run(row.id);
      return true;
    });
    return transaction();
  }

  async stop() {
    clearInterval(this.timer);
    this.loop.disable();
    await this.currentSamplePromise?.catch(() => {});
  }
}

module.exports = { PerformanceMonitor, diskUsage, processMemory, processUsage, dockerUsage, percentile, mergeCounters, counterDelta };
