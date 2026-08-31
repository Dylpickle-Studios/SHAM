// @ts-nocheck -- not part of this session's checkJs rollout yet.
// This file still has genuine `tsc --noEmit` findings (mostly narrow
// `let x = null`-style inference and untyped Express handlers, the same
// patterns already fixed across most of src/) that need real per-file
// JSDoc work to resolve, not a suppression. Tracked as follow-up work;
// see tsconfig.json and docs/development.md. Do not add more files here
// without a similar comment and a plan to remove it.
'use strict';

const { ConfigurationOperations } = require('./configuration');
const { applyGitProviderCredentials, providerForRepositoryUrl, providerCommitUrl, normalizeWebhookBaseUrl, ensureProviderWebhook } = require('../git-providers');
const { readManifest, resolveRuntimeSpec, executionPolicyHash } = require('../runtime-spec');
const { createEnvFile } = require('../runtime-engine');
const { getRuntimeClient } = require('../runtime/client');
const { fs, path, net, crypto, DATA_DIR, SITES_DIR, RELEASES_DIR, PREVIEWS_DIR, SITE_DATA_DIR, GIT_BIN, GIT_TIMEOUT_MS, PREVIEW_TTL_HOURS, safeRelativePath, terminateAndWait, runProcess, runConfiguredCommand, safeName, freePort, closeServer, siteRoot, ensureRequiredFile, validateGitUrl, validateBranch } = require('./shared');

class DeploymentOperations extends ConfigurationOperations {
  async runContainerBuildCommand(site, stage, command, environment, label, deploymentId, imageRef) {
    const image = String(imageRef || '').trim();
    if (!/^[a-zA-Z0-9][a-zA-Z0-9._/@:-]{0,255}$/.test(image)) throw new Error('Container image is invalid.');
    const envFile = await createEnvFile(site.id, environment);
    try {
      await getRuntimeClient().sandboxRun({
        image, envFile, workspaceSource: stage, command, timeoutMs: GIT_TIMEOUT_MS,
        onLine: (level, line) => this.manager.logOutput(site.id, level, `${label}: ${line}`, { deploymentId })
      });
    } finally { await fs.promises.rm(envFile, { force: true }).catch(() => {}); }
  }

  runtimeManifestForStage(site, stage, approveManifestChanges = false) {
    const manifestRecord = site.manifest_enabled === false ? null : readManifest(stage);
    const manifestHash = manifestRecord ? crypto.createHash('sha256').update(manifestRecord.raw).digest('hex') : '';
    const spec = resolveRuntimeSpec(site, stage, { manifestRecord });
    const policyHash = executionPolicyHash(spec);
    const previousManifestHash = String(site.runtime_manifest_hash || '');
    const previousApprovedPolicy = String(site.runtime_manifest_approved_hash || '');
    const manifestChanged = manifestHash !== previousManifestHash;
    const executionChanged = manifestRecord
      ? (previousApprovedPolicy ? policyHash !== previousApprovedPolicy : manifestChanged)
      : Boolean(previousManifestHash);
    if (manifestChanged && executionChanged && !approveManifestChanges) {
      const error = new Error(manifestRecord
        ? 'This commit changes sham.yaml runtime/build execution policy. Review and explicitly approve the manifest before deploying.'
        : 'This commit removes the active sham.yaml execution policy. Review and explicitly approve the removal before deploying.');
      error.code = 'SHAM_MANIFEST_APPROVAL_REQUIRED';
      error.manifest = manifestRecord
        ? { filename: manifestRecord.filename, hash: manifestHash, policyHash, config: manifestRecord.manifest }
        : { removed: true, previousHash: previousManifestHash };
      throw error;
    }
    return { manifestRecord, manifestHash, policyHash: manifestRecord ? policyHash : '', spec };
  }

  async configureProviderWebhook(site, baseUrl) {
    if (!site?.git_url) return null;
    const provider = providerForRepositoryUrl(site.git_url, this.db);
    const origin = normalizeWebhookBaseUrl(baseUrl);
    if (!provider || !origin) return null;
    const secret = this.ensureDeployWebhookSecret(site.id);
    const callbackUrl = new URL(`/api/hooks/deploy/${site.id}`, `${origin}/`).toString();
    return ensureProviderWebhook(this.db, site.git_url, callbackUrl, secret);
  }

  async cloneRepository(site, { url, branch, deployKey = '', installDependencies = false, installCommand = '', buildCommand = '', buildOutputDir = '', deploymentId = null, approveManifestChanges = false }) {
    const repository = validateGitUrl(url);
    const ref = validateBranch(branch);
    const privateKey = String(deployKey || '');
    if (privateKey.length > 128 * 1024 || privateKey.includes('\0')) throw new Error('Deploy key is too large or invalid.');
    let stage = path.join(SITES_DIR, `${site.directory_name}.git-${crypto.randomUUID()}`);
    const environment = this.siteEnvironment(site.id, 'build');
    let keyPath = '';
    try {
      if (!privateKey) applyGitProviderCredentials(this.db, repository, environment);
      if (privateKey) {
        keyPath = path.join(DATA_DIR, 'tmp', `git-key-${crypto.randomUUID()}`);
        await fs.promises.writeFile(keyPath, privateKey, { mode: 0o600 });
        environment.GIT_SSH_COMMAND = `ssh -i ${JSON.stringify(keyPath)} -o IdentitiesOnly=yes -o StrictHostKeyChecking=accept-new`;
      }
      const cloneOptions = this.trackedProcessOptions({ timeoutMs: GIT_TIMEOUT_MS, env: environment, environmentMode: 'build', onLine: (level, line) => this.manager.logOutput(site.id, level, `git: ${line}`, { deploymentId }) });
      try {
        await runProcess(GIT_BIN, ['clone', '--depth', '1', '--branch', ref, '--single-branch', '--', repository, stage], cloneOptions);
      } catch (error) {
        // Dumb HTTP is still a supported Git transport but cannot advertise
        // shallow-clone capabilities. Retry without --depth rather than
        // rejecting an otherwise valid, credential-free repository.
        if (!/dumb http transport does not support shallow capabilities/i.test(String(error.message || ''))) throw error;
        this.manager.log(site.id, 'info', 'Git remote does not support shallow clones; retrying a full clone.', { deploymentId });
        await fs.promises.rm(stage, { recursive: true, force: true });
        await runProcess(GIT_BIN, ['clone', '--branch', ref, '--single-branch', '--', repository, stage], cloneOptions);
      }
      const commitSha = (await runProcess(GIT_BIN, ['rev-parse', 'HEAD'], this.trackedProcessOptions({ cwd: stage, timeoutMs: 30_000, env: environment, environmentMode: 'build' }))).output.trim();
      const metadata = (await runProcess(GIT_BIN, ['log', '-1', '--format=%an%x00%s'], this.trackedProcessOptions({ cwd: stage, timeoutMs: 30_000, env: environment, environmentMode: 'build' }))).output.split('\0');
      const commitAuthor = String(metadata[0] || '').trim().slice(0, 200);
      const commitMessage = String(metadata.slice(1).join(' ').trim() || '').slice(0, 500);
      await fs.promises.rm(path.join(stage, '.git'), { recursive: true, force: true });

      const manifest = this.runtimeManifestForStage(site, stage, Boolean(approveManifestChanges));
      const spec = manifest.spec;
      const configuredInstall = String(installCommand || spec.installCommand || '').trim();
      const configuredBuild = String(buildCommand || spec.buildCommand || '').trim();
      const outputDirectory = String(buildOutputDir || spec.buildOutputDir || '').trim();
      const sourceManagedBuild = spec.driver === 'compose' || (spec.driver === 'container' && spec.container.mode !== 'image');
      if (sourceManagedBuild && (configuredInstall || configuredBuild)) {
        throw new Error(spec.driver === 'compose'
          ? 'Docker Compose deployments must define build/install steps in the Compose service or its Dockerfile; SHAM install/build commands are not applied to Compose projects.'
          : `${spec.container.mode} deployments must define build/install steps in their image build configuration; SHAM install/build commands are only supported for existing-image container deployments.`);
      }
      const isolatedBuild = spec.driver === 'container' && spec.container.mode === 'image';
      if (configuredInstall) {
        if (isolatedBuild) await this.runContainerBuildCommand(site, stage, configuredInstall, environment, 'install', deploymentId, spec.container.image);
        else await runConfiguredCommand(configuredInstall, this.trackedProcessOptions({ cwd: stage, timeoutMs: GIT_TIMEOUT_MS, env: environment, environmentMode: 'build', onLine: (level, line) => this.manager.logOutput(site.id, level, `install: ${line}`, { deploymentId }) }));
      } else if (installDependencies && site.runtime_type === 'node' && !(site.runtime_isolation === 'docker')) {
        const npm = process.platform === 'win32' ? 'npm.cmd' : 'npm';
        await runProcess(npm, ['install', '--omit=dev', '--no-audit', '--no-fund'], this.trackedProcessOptions({ cwd: stage, timeoutMs: GIT_TIMEOUT_MS, env: environment, environmentMode: 'build', onLine: (level, line) => this.manager.logOutput(site.id, level, `npm: ${line}`, { deploymentId }) }));
      }
      if (configuredBuild) {
        if (isolatedBuild) await this.runContainerBuildCommand(site, stage, configuredBuild, environment, 'build', deploymentId, spec.container.image);
        else await runConfiguredCommand(configuredBuild, this.trackedProcessOptions({ cwd: stage, timeoutMs: GIT_TIMEOUT_MS, env: environment, environmentMode: 'build', onLine: (level, line) => this.manager.logOutput(site.id, level, `build: ${line}`, { deploymentId }) }));
      }
      if (outputDirectory && spec.driver === 'static') {
        const output = path.join(stage, ...safeRelativePath(outputDirectory, 'Build output directory').split('/'));
        const stageReal = await fs.promises.realpath(stage);
        const outputReal = await fs.promises.realpath(output).catch(() => '');
        if (!outputReal.startsWith(`${stageReal}${path.sep}`) || !(await fs.promises.stat(outputReal).catch(() => null))?.isDirectory()) throw new Error(`Build output directory “${outputDirectory}” was not produced.`);
        const deployStage = `${stage}.output`;
        await fs.promises.rename(outputReal, deployStage);
        await fs.promises.rm(stage, { recursive: true, force: true });
        stage = deployStage;
      }
      await ensureRequiredFile(site, stage);
      return { stage, repository, ref, commitSha, commitAuthor, commitMessage, manifestHash: manifest.manifestHash, policyHash: manifest.policyHash, runtimeSpec: spec };
    } catch (error) {
      await fs.promises.rm(stage, { recursive: true, force: true }).catch(() => {});
      throw error;
    } finally {
      if (keyPath) await fs.promises.rm(keyPath, { force: true }).catch(() => {});
    }
  }

  async activateRelease(site, stage, { source, version, commitSha = null, deploymentId = null, manifestHash = '', policyHash = '', runtimeSpec = null }) {
    await ensureRequiredFile(site, stage);
    const releaseBase = path.join(RELEASES_DIR, String(site.id));
    await fs.promises.mkdir(releaseBase, { recursive: true });
    const releaseDirectory = `release-${Date.now()}-${crypto.randomUUID()}`;
    const releaseRoot = path.join(releaseBase, releaseDirectory);
    const legacyRoot = path.join(SITES_DIR, site.directory_name);
    const wasRunning = this.manager.statusFor(site.id).running;
    const shouldRun = wasRunning || site.enabled;
    let candidate = null;
    let promoted = false;
    let releasePlaced = false;
    let legacyArchiveDirectory = '';
    let legacyArchiveRoot = '';
    let databaseActivated = false;
    try {
      // Releases must run from a pathname that never changes while the process/container is alive.
      // Moving an already-started cwd can break lazy module/config loading in Node, Python and other runtimes.
      await fs.promises.rename(stage, releaseRoot);
      releasePlaced = true;

      const current = this.db.prepare('SELECT id, directory_name FROM site_releases WHERE site_id = ? AND active = 1').get(site.id);
      const knownCurrentDirectory = String(current?.directory_name || site.active_release_directory || '').trim();
      if (!knownCurrentDirectory) {
        const legacyStat = await fs.promises.stat(legacyRoot).catch(() => null);
        if (legacyStat?.isDirectory()) {
          legacyArchiveDirectory = `release-${Date.now()}-${crypto.randomUUID()}`;
          legacyArchiveRoot = path.join(releaseBase, legacyArchiveDirectory);
          await fs.promises.cp(legacyRoot, legacyArchiveRoot, { recursive: true, force: false, errorOnExist: true });
        }
      }

      if (shouldRun) {
        this.manager.log(site.id, 'info', 'Starting release candidate from its stable release path and waiting for readiness before traffic switch.', { deploymentId });
        candidate = await this.manager.prepareCandidate(site, releaseRoot, runtimeSpec ? { spec: runtimeSpec } : {});
        await this.manager.promoteCandidate(site, candidate, { root: releaseRoot, deferCleanup: true });
        promoted = true;
      }

      const transaction = this.db.transaction(() => {
        const active = this.db.prepare('SELECT id, directory_name FROM site_releases WHERE site_id = ? AND active = 1').get(site.id);
        const previousDirectory = String(active?.directory_name || site.active_release_directory || legacyArchiveDirectory || '').trim();
        if (active) {
          if (previousDirectory) this.db.prepare("UPDATE site_releases SET active = 0, status = 'ready', directory_name = ? WHERE id = ?").run(previousDirectory, active.id);
          else this.db.prepare("UPDATE site_releases SET active = 0, status = 'ready' WHERE id = ?").run(active.id);
        } else if (previousDirectory) {
          this.db.prepare("INSERT INTO site_releases (site_id, version, source, directory_name, status, active) VALUES (?, ?, 'existing', ?, 'ready', 0)").run(site.id, `pre-${Date.now()}`, previousDirectory);
        }
        this.db.prepare('UPDATE site_releases SET active = 0 WHERE site_id = ?').run(site.id);
        this.db.prepare("INSERT INTO site_releases (site_id, version, source, directory_name, commit_sha, deployment_id, status, active) VALUES (?, ?, ?, ?, ?, ?, 'active', 1)").run(site.id, version, source, releaseDirectory, commitSha, deploymentId ? Number(deploymentId) : null);
        this.db.prepare('UPDATE sites SET release_mode = 1, active_release_directory = ?, runtime_manifest_hash = ?, runtime_manifest_approved_hash = ?, updated_at = CURRENT_TIMESTAMP WHERE id = ?').run(releaseDirectory, String(manifestHash || ''), String(policyHash || ''), site.id);
      });
      transaction();
      databaseActivated = true;
      if (candidate) await this.manager.finalizePromotion(candidate);

      // Once the old backend has drained, the legacy mutable site directory is no longer authoritative.
      // Its rollback copy (when present) lives under releases/ and all future file operations resolve the active release path.
      if (legacyArchiveDirectory) await fs.promises.rm(legacyRoot, { recursive: true, force: true }).catch((error) => this.manager.log(site.id, 'error', `Could not remove migrated legacy release directory: ${error.message}`));
    } catch (error) {
      if (promoted && candidate && !databaseActivated) await this.manager.rollbackPromotion(site, candidate).catch(() => {});
      else if (candidate && !databaseActivated) await this.manager.discardCandidate(candidate).catch(() => {});
      if (!databaseActivated && releasePlaced) await fs.promises.rm(releaseRoot, { recursive: true, force: true }).catch(() => {});
      if (!databaseActivated && legacyArchiveRoot) await fs.promises.rm(legacyArchiveRoot, { recursive: true, force: true }).catch(() => {});
      throw error;
    } finally {
      await fs.promises.rm(stage, { recursive: true, force: true }).catch(() => {});
    }
    await this.pruneReleases(site.id, 8).catch((error) => this.manager.log(site.id, 'error', `Could not prune old releases: ${error.message}`));
    return this.listReleases(site.id)[0];
  }

  beginDeployment(siteId, source, ref = '') {
    const result = this.db.prepare("INSERT INTO site_deployments (site_id, source, status, ref) VALUES (?, ?, 'queued', ?)").run(Number(siteId), String(source || 'manual').slice(0, 50), String(ref || '').slice(0, 500));
    return Number(result.lastInsertRowid);
  }

  updateDeploymentStatus(id, status, detail = null) {
    const normalized = String(status || '').trim().toLowerCase();
    const activeStatuses = new Set(['running', 'deployed-with-warning']);
    if (!['queued', 'building', 'running', 'failed', 'rolled-back', 'superseded', 'deployed-with-warning', 'success'].includes(normalized)) throw new Error('Deployment status is invalid.');
    const row = this.db.prepare('SELECT site_id AS siteId FROM site_deployments WHERE id = ?').get(Number(id));
    const transaction = this.db.transaction(() => {
      if (activeStatuses.has(normalized) && row?.siteId) {
        this.db.prepare("UPDATE site_deployments SET status = 'superseded' WHERE site_id = ? AND id != ? AND status IN ('running', 'deployed-with-warning')").run(row.siteId, Number(id));
      }
      if (detail === null) this.db.prepare('UPDATE site_deployments SET status = ? WHERE id = ?').run(normalized, Number(id));
      else this.db.prepare('UPDATE site_deployments SET status = ?, detail = ? WHERE id = ?').run(normalized, String(detail).slice(0, 4000), Number(id));
    });
    transaction();
    if (activeStatuses.has(normalized) && row?.siteId) this.manager.activeDeploymentIds?.set(Number(row.siteId), Number(id));
  }

  finishDeployment(id, status, detail = '', metadata = {}) {
    const row = this.db.prepare('SELECT site_id AS siteId, started_at AS startedAt FROM site_deployments WHERE id = ?').get(Number(id));
    const started = row?.startedAt ? Date.parse(`${String(row.startedAt).replace(' ', 'T')}Z`) : Date.now();
    const duration = Math.max(0, Date.now() - (Number.isFinite(started) ? started : Date.now()));
    const normalizedStatus = String(status || 'failed').slice(0, 30);
    const activeStatuses = new Set(['running', 'deployed-with-warning']);
    const transaction = this.db.transaction(() => {
      if (activeStatuses.has(normalizedStatus) && row?.siteId) this.db.prepare("UPDATE site_deployments SET status = 'superseded' WHERE site_id = ? AND id != ? AND status IN ('running', 'deployed-with-warning')").run(row.siteId, Number(id));
      this.db.prepare(`UPDATE site_deployments SET status = ?, commit_sha = ?, commit_author = ?, commit_message = ?, detail = ?, duration_ms = ?, finished_at = CURRENT_TIMESTAMP WHERE id = ?`).run(
        normalizedStatus, String(metadata.commitSha || '').slice(0, 100), String(metadata.commitAuthor || '').slice(0, 200), String(metadata.commitMessage || '').slice(0, 500), String(detail || '').slice(0, 4000), duration, Number(id)
      );
    });
    transaction();
    if (activeStatuses.has(normalizedStatus) && row?.siteId) this.manager.activeDeploymentIds?.set(Number(row.siteId), Number(id));
  }

  recordDeployment(siteId, { source = 'manual', status = 'running', ref = '', detail = '', commitSha = '', commitAuthor = '', commitMessage = '' } = {}) {
    const id = this.beginDeployment(siteId, source, ref);
    this.finishDeployment(id, status, detail, { commitSha, commitAuthor, commitMessage });
    return id;
  }

  listDeployments(siteId, limit = 50) {
    const bounded = Math.min(Math.max(Number(limit) || 50, 1), 200);
    const site = this.manager.getSite(Number(siteId));
    return this.db.prepare(`SELECT d.id, d.source, d.status, d.ref, d.commit_sha AS commitSha, d.commit_author AS commitAuthor, d.commit_message AS commitMessage, d.detail, d.started_at AS startedAt, d.finished_at AS finishedAt, d.duration_ms AS durationMs,
      (SELECT r.id FROM site_releases r WHERE r.site_id = d.site_id AND r.active = 0 AND (r.deployment_id = d.id OR (r.deployment_id IS NULL AND d.commit_sha <> '' AND r.commit_sha = d.commit_sha)) ORDER BY r.deployment_id = d.id DESC, r.id DESC LIMIT 1) AS releaseId,
      EXISTS(SELECT 1 FROM site_releases active WHERE active.site_id = d.site_id AND active.active = 1 AND (active.deployment_id = d.id OR (active.deployment_id IS NULL AND d.commit_sha <> '' AND active.commit_sha = d.commit_sha))) AS activeRelease,
      (SELECT COUNT(*) FROM runtime_logs logs WHERE logs.deployment_id = d.id) AS logCount
      FROM site_deployments d WHERE d.site_id = ? ORDER BY d.id DESC LIMIT ?`).all(Number(siteId), bounded)
      .map((row) => ({ ...row, activeRelease: Boolean(row.activeRelease), commitUrl: site?.git_url ? providerCommitUrl(site.git_url, row.commitSha, this.db) : '' }));
  }

  deploymentLogs(siteId, deploymentId, limit = 500) {
    const bounded = Math.min(Math.max(Number(limit) || 500, 1), 2000);
    this.manager.flushRuntimeLogs?.();
    return this.db.prepare(`SELECT id, level, message, context_json AS contextJson, created_at AS createdAt FROM runtime_logs WHERE site_id = ? AND deployment_id = ? ORDER BY id ASC LIMIT ?`).all(Number(siteId), Number(deploymentId), bounded)
      .map((row) => ({ ...row, context: (() => { try { return JSON.parse(row.contextJson || 'null'); } catch { return null; } })(), contextJson: undefined }));
  }

  async deployGit(site, input) {
    const deploymentId = this.beginDeployment(site.id, 'git', input.branch || site.git_branch || 'main');
    const previousDeploymentId = this.manager.activeDeploymentIds?.get(Number(site.id)) || null;
    this.manager.log(site.id, 'info', 'Deployment queued.', { deploymentId });
    try {
      this.updateDeploymentStatus(deploymentId, 'building', 'Cloning repository and running the configured build pipeline.');
      const cloned = await this.cloneRepository(site, { ...input, deploymentId });
      const version = `${safeName(cloned.ref)}-${new Date().toISOString().slice(0, 19).replace(/[:T]/g, '-')}`;
      this.manager.log(site.id, 'info', `Build completed for ${cloned.commitSha.slice(0, 9)}; activating release.`, { deploymentId });
      // Runtime stop/start output during activation belongs to the deployment being activated,
      // not the previously-active release.
      this.manager.activeDeploymentIds?.set(Number(site.id), deploymentId);
      const release = await this.activateRelease(site, cloned.stage, { source: 'git', version, commitSha: cloned.commitSha, deploymentId, manifestHash: cloned.manifestHash, policyHash: cloned.policyHash, runtimeSpec: cloned.runtimeSpec });
      let warning = null;
      try {
        this.db.prepare('UPDATE sites SET git_url = ?, git_branch = ?, updated_at = CURRENT_TIMESTAMP WHERE id = ?').run(cloned.repository, cloned.ref, site.id);
        this.finishDeployment(deploymentId, 'running', 'Git deployment is the active release.', cloned);
      } catch (error) {
        warning = `Release activated, but SHAM could not finalize all deployment metadata: ${error.message}`;
        this.manager.activeDeploymentIds?.set(Number(site.id), deploymentId);
        try { this.finishDeployment(deploymentId, 'deployed-with-warning', warning, cloned); }
        catch (historyError) { this.manager.log(site.id, 'error', `Could not persist deployment warning state: ${historyError.message}`, { deploymentId }); }
        this.manager.log(site.id, 'error', warning, { deploymentId });
      }
      this.manager.log(site.id, 'info', warning ? 'Deployment activated with a metadata warning.' : 'Deployment activated successfully.', { deploymentId });
      return { ...release, deploymentId, commitAuthor: cloned.commitAuthor, commitMessage: cloned.commitMessage, commitUrl: providerCommitUrl(cloned.repository, cloned.commitSha, this.db), warning };
    } catch (error) {
      try { this.finishDeployment(deploymentId, 'failed', error.message); }
      catch (historyError) { this.manager.log(site.id, 'error', `Could not persist failed deployment state: ${historyError.message}`, { deploymentId }); }
      this.manager.log(site.id, 'error', `Deployment failed: ${error.message}`, { deploymentId });
      if (previousDeploymentId) this.manager.activeDeploymentIds?.set(Number(site.id), previousDeploymentId);
      else this.manager.activeDeploymentIds?.delete(Number(site.id));
      throw error;
    }
  }

  listReleases(siteId) {
    return this.db.prepare('SELECT id, version, source, commit_sha AS commitSha, deployment_id AS deploymentId, status, active, created_at AS createdAt FROM site_releases WHERE site_id = ? ORDER BY active DESC, id DESC').all(siteId)
      .map((row) => ({ ...row, active: Boolean(row.active) }));
  }

  async rollbackRelease(site, releaseId) {
    const selected = this.db.prepare('SELECT * FROM site_releases WHERE id = ? AND site_id = ? AND active = 0').get(Number(releaseId), site.id);
    if (!selected?.directory_name) throw new Error('Rollback release not found.');
    const selectedPath = path.join(RELEASES_DIR, String(site.id), selected.directory_name);
    await ensureRequiredFile(site, selectedPath);
    const rollbackManifest = this.runtimeManifestForStage(site, selectedPath, true);
    const wasRunning = this.manager.statusFor(site.id).running;
    const shouldRun = wasRunning || site.enabled;
    let candidate = null;
    let promoted = false;
    let databaseActivated = false;
    try {
      // Retained releases are stable directories. Start the selected one in place, prove readiness,
      // then switch traffic and metadata without renaming either the old or new runtime directory.
      if (shouldRun) {
        candidate = await this.manager.prepareCandidate(site, selectedPath, { spec: rollbackManifest.spec });
        await this.manager.promoteCandidate(site, candidate, { root: selectedPath, deferCleanup: true });
        promoted = true;
      }
      const transaction = this.db.transaction(() => {
        const current = this.db.prepare('SELECT id, directory_name FROM site_releases WHERE site_id = ? AND active = 1').get(site.id);
        if (current) this.db.prepare("UPDATE site_releases SET active = 0, status = 'ready' WHERE id = ?").run(current.id);
        this.db.prepare("UPDATE site_releases SET active = 1, status = 'active' WHERE id = ?").run(selected.id);
        this.db.prepare('UPDATE sites SET active_release_directory = ?, runtime_manifest_hash = ?, runtime_manifest_approved_hash = ?, updated_at = CURRENT_TIMESTAMP WHERE id = ?').run(selected.directory_name, rollbackManifest.manifestHash, rollbackManifest.policyHash, site.id);
      });
      transaction();
      databaseActivated = true;
      if (candidate) await this.manager.finalizePromotion(candidate);
      let historyWarning = null;
      try {
        const currentDeployment = this.db.prepare("SELECT id FROM site_deployments WHERE site_id = ? AND status IN ('running', 'deployed-with-warning') ORDER BY id DESC LIMIT 1").get(site.id);
        let activatedDeployment = selected.deployment_id ? this.db.prepare('SELECT id FROM site_deployments WHERE site_id = ? AND id = ?').get(site.id, selected.deployment_id) : null;
        if (!activatedDeployment && selected.commit_sha) activatedDeployment = this.db.prepare('SELECT id FROM site_deployments WHERE site_id = ? AND commit_sha = ? AND id != COALESCE(?, 0) ORDER BY id DESC LIMIT 1').get(site.id, selected.commit_sha, currentDeployment?.id || 0);
        if (activatedDeployment) this.manager.activeDeploymentIds?.set(Number(site.id), Number(activatedDeployment.id));
        if (currentDeployment) this.db.prepare("UPDATE site_deployments SET status = 'rolled-back' WHERE id = ?").run(currentDeployment.id);
        if (activatedDeployment) this.updateDeploymentStatus(activatedDeployment.id, 'running', 'This deployment was reactivated by rollback.');
        else this.manager.activeDeploymentIds?.set(Number(site.id), this.recordDeployment(site.id, { source: 'rollback', status: 'running', ref: String(selected.id), detail: `Rollback activated release ${selected.version}.`, commitSha: selected.commit_sha || '' }));
      } catch (historyError) {
        historyWarning = `Release rollback is active, but SHAM could not finalize deployment history: ${historyError.message}`;
        this.manager.log(site.id, 'error', historyWarning);
      }
      return { releases: this.listReleases(site.id), warning: historyWarning };
    } catch (error) {
      if (promoted && candidate && !databaseActivated) await this.manager.rollbackPromotion(site, candidate).catch(() => {});
      else if (candidate && !databaseActivated) await this.manager.discardCandidate(candidate).catch(() => {});
      throw error;
    }
  }

  async pruneReleases(siteId, keep = 8) {
    const rows = this.db.prepare('SELECT * FROM site_releases WHERE site_id = ? AND active = 0 ORDER BY id DESC').all(siteId);
    for (const row of rows.slice(keep)) {
      if (row.directory_name) await fs.promises.rm(path.join(RELEASES_DIR, String(siteId), row.directory_name), { recursive: true, force: true }).catch(() => {});
      this.db.prepare('DELETE FROM site_releases WHERE id = ?').run(row.id);
    }
  }

  async createPreview(site, { hostname = '', ttlHours = PREVIEW_TTL_HOURS } = {}) {
    const root = siteRoot(site);
    const idToken = crypto.randomUUID();
    const directoryName = `preview-${idToken}`;
    const previewRoot = path.join(PREVIEWS_DIR, directoryName);
    await fs.promises.cp(root, previewRoot, { recursive: true, force: false, filter: (source) => { const relative = path.relative(root, source); return relative !== '.sham' && !relative.startsWith(`.sham${path.sep}`); } });
    const previewHostname = String(hostname || `preview-${site.id}.${site.domain || 'local.invalid'}`).trim().toLowerCase();
    if (!/^(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/.test(previewHostname)) {
      await fs.promises.rm(previewRoot, { recursive: true, force: true });
      throw new Error('Preview hostname is invalid.');
    }
    const expires = new Date(Date.now() + Math.min(Math.max(Number(ttlHours) || PREVIEW_TTL_HOURS, 1), 720) * 3600_000).toISOString();
    let runtime;
    try {
      runtime = await this.manager.startPreviewRuntime(site, previewRoot);
      const port = Number(runtime.internalPort || (() => { try { return new URL(runtime.target).port; } catch { return 0; } })());
      const result = this.db.prepare("INSERT INTO preview_deployments (site_id, hostname, port, directory_name, status, expires_at) VALUES (?, ?, ?, ?, 'running', ?)").run(site.id, previewHostname, port, directoryName, expires);
      const id = Number(result.lastInsertRowid);
      runtime.hostname = previewHostname;
      runtime.expiresAt = expires;
      this.previewRuntimes.set(id, runtime);
      this.previewHostnames.set(previewHostname, id);
      return { id, hostname: previewHostname, port, expiresAt: expires, status: 'running', isolation: runtime.isolation || 'process' };
    } catch (error) {
      if (runtime?.stop) await runtime.stop().catch(() => {});
      else {
        if (runtime?.server) await closeServer(runtime.server);
        if (runtime?.child) await terminateAndWait(runtime.child);
      }
      await fs.promises.rm(previewRoot, { recursive: true, force: true });
      throw error;
    }
  }

  listPreviews(siteId = null) {
    const rows = siteId == null
      ? this.db.prepare('SELECT * FROM preview_deployments ORDER BY id DESC').all()
      : this.db.prepare('SELECT * FROM preview_deployments WHERE site_id = ? ORDER BY id DESC').all(siteId);
    return rows.map((row) => ({ id: row.id, siteId: row.site_id, hostname: row.hostname, port: row.port, status: row.status, expiresAt: row.expires_at, createdAt: row.created_at }));
  }

  previewForHostname(hostname) {
    const key = String(hostname || '').trim().toLowerCase();
    const id = this.previewHostnames.get(key);
    const runtime = id && this.previewRuntimes.get(id);
    if (!runtime) { if (id) this.previewHostnames.delete(key); return null; }
    if (Date.parse(runtime.expiresAt || '') <= Date.now()) return null;
    return { preview: true, id, hostname: key, target: runtime.target };
  }

  async deletePreview(id, expectedSiteId = null) {
    const numericId = Number(id);
    const numericSiteId = expectedSiteId == null ? null : Number(expectedSiteId);
    const row = numericSiteId == null
      ? this.db.prepare('SELECT * FROM preview_deployments WHERE id = ?').get(numericId)
      : this.db.prepare('SELECT * FROM preview_deployments WHERE id = ? AND site_id = ?').get(numericId, numericSiteId);
    if (!row) throw new Error('Preview not found.');
    const runtime = this.previewRuntimes.get(row.id);
    if (runtime?.stop) await runtime.stop().catch(() => {});
    else {
      if (runtime?.server) await closeServer(runtime.server);
      if (runtime?.child) await terminateAndWait(runtime.child);
    }
    this.previewRuntimes.delete(row.id);
    this.previewHostnames.delete(String(row.hostname || '').toLowerCase());
    this.db.prepare('DELETE FROM preview_deployments WHERE id = ?').run(row.id);
    await fs.promises.rm(path.join(PREVIEWS_DIR, row.directory_name), { recursive: true, force: true });
  }

  async cleanupExpiredPreviews() {
    for (const row of this.db.prepare("SELECT id FROM preview_deployments WHERE expires_at <= CURRENT_TIMESTAMP").all()) {
      await this.deletePreview(row.id).catch((error) => this.manager.log(null, 'error', `Could not clean preview ${row.id}: ${error.message}`));
    }
  }

  anubisTarget(siteId) {
    return this.anubisRuntimes.get(Number(siteId))?.target || null;
  }

  anubisPolicy(site, metricsPort = null) {
    const addMetrics = (policy) => {
      const normalized = String(policy || '').trim();
      if (!metricsPort) return `${normalized}\n`;
      return `${normalized}\nmetrics:\n  bind: "127.0.0.1:${metricsPort}"\n  network: tcp\n`;
    };
    if (site.anubis_policy?.trim()) return addMetrics(site.anubis_policy);
    const difficulty = Number(site.anubis_difficulty || 4);
    const common = `bots:
  - name: sham-health
    user_agent_regex: ^SHAM-Health/
    action: ALLOW
  - name: well-known
    path_regex: ^/.well-known/.*$
    action: ALLOW
  - name: favicon
    path_regex: ^/favicon\\.ico$
    action: ALLOW
  - name: robots
    path_regex: ^/robots\\.txt$
    action: ALLOW
`;
    if (site.anubis_preset === 'search-friendly') {
      return addMetrics(`${common}  - name: recognized-indexers
    user_agent_regex: (?i:Googlebot|Bingbot|DuckDuckBot|Applebot|InternetArchive)
    action: ALLOW
  - name: generic-browser
    user_agent_regex: Mozilla|Opera
    action: CHALLENGE
    challenge:
      algorithm: fast
      difficulty: ${difficulty}
`);
    }
    if (site.anubis_preset === 'aggressive') {
      return addMetrics(`${common}  - name: automated-client
    user_agent_regex: (?i:bot|crawler|spider|scrape|curl|wget|python|httpclient)
    action: DENY
  - name: generic-client
    user_agent_regex: .+
    action: CHALLENGE
    challenge:
      algorithm: fast
      difficulty: ${Math.min(10, difficulty + 1)}
`);
    }
    return addMetrics(`${common}  - name: generic-browser
    user_agent_regex: Mozilla|Opera
    action: CHALLENGE
    challenge:
      algorithm: fast
      difficulty: ${difficulty}
`);
  }

  async startAnubis(site) {
    if (!site.anubis_enabled || !site.edge_enabled) return null;
    if (this.anubisRuntimes.has(site.id)) return this.anubisRuntimes.get(site.id);
    const port = await freePort();
    let metricsPort = await freePort();
    while (metricsPort === port) metricsPort = await freePort();
    const configDir = path.join(SITE_DATA_DIR, String(site.id), 'anubis');
    await fs.promises.mkdir(configDir, { recursive: true });
    const policyPath = path.join(configDir, 'botPolicy.yaml');
    await fs.promises.writeFile(policyPath, this.anubisPolicy(site, metricsPort), { mode: 0o600 });
    const name = `sham-anubis-${site.id}`;
    const networkMode = fs.existsSync('/.dockerenv') && process.env.HOSTNAME ? `container:${process.env.HOSTNAME}` : 'host';
    const client = getRuntimeClient();
    try {
      await client.sidecarRun({
        name, networkMode, policyFile: policyPath, port, targetPort: site.port,
        difficulty: Number(site.anubis_difficulty || 4), domain: site.domain
      });
    } catch (error) { throw new Error(`Could not start Anubis Docker runtime: ${error.message}`); }
    const waitHandle = await client.waitContainer({
      name,
      onExit: () => { if (this.anubisRuntimes.get(site.id) === runtime) this.anubisRuntimes.delete(site.id); }
    }).catch(() => null);
    await new Promise((resolve, reject) => {
      const started = Date.now();
      const check = () => {
        const socket = net.connect({ host: '127.0.0.1', port });
        socket.once('connect', () => { socket.destroy(); resolve(); });
        socket.once('error', () => {
          socket.destroy();
          if (Date.now() - started > 30_000) reject(new Error('Anubis did not become ready within 30 seconds.'));
          else setTimeout(check, 200).unref?.();
        });
      };
      check();
    }).catch(async (error) => { waitHandle?.stop(); await client.sidecarRemove({ name }).catch(() => {}); throw error; });
    const runtime = { name, waitHandle, port, metricsPort, target: `http://127.0.0.1:${port}`, metrics: `http://127.0.0.1:${metricsPort}/metrics` };
    this.anubisRuntimes.set(site.id, runtime);
    this.manager.log(site.id, 'info', `Anubis protection started with ${site.anubis_preset} policy.`);
    return runtime;
  }

  async stopAnubis(siteId) {
    const runtime = this.anubisRuntimes.get(Number(siteId));
    if (!runtime) return;
    this.anubisRuntimes.delete(Number(siteId));
    runtime.waitHandle?.stop();
    await getRuntimeClient().sidecarRemove({ name: runtime.name || `sham-anubis-${siteId}` }).catch(() => {});
  }

  async afterSiteStart(site) {
    if (site.anubis_enabled) await this.startAnubis(site);
  }

  async beforeSiteStop(site) {
    await this.stopAnubis(site.id);
  }

}

module.exports = { DeploymentOperations };
