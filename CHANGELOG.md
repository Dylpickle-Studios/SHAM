# Changelog

All notable public changes to SHAM are documented here. The project follows Semantic Versioning.

## [Unreleased]

## [1.2.0] — 2026-08-31

### Added

- Node.js and managed-process sites can declare up to four explicit private
  HTTP listeners. SHAM supplies an internal application port through a named
  environment variable, verifies its readiness, and preserves the listener
  through deploys, rollbacks, and runtime lifecycle operations.

### Security

- Private process listeners are limited to loopback, RFC1918/CGNAT IPv4, or
  ULA IPv6 bindings and cannot be selected as Cloudflare Tunnel origins,
  preventing an accidental VPN-only administration endpoint from being
  published through the shared edge or Tunnel.

### Changed

- The upgrade compatibility drill now uses the unmodified `v1.1.2` public
  release as its required stable baseline for this release line.

## [1.1.2] — 2026-08-27

### Security

- Runtime Agent RPC now rejects unknown request properties before any Docker
  operation runs, preventing privileged Docker options from being silently
  ignored or smuggled through the control-plane boundary.

### Changed

- Added the supported `/api/v1` automation namespace with structured errors,
  an OpenAPI 3.1 contract, and documented compatibility policy. Existing
  `/api` endpoints remain compatibility aliases.
- Upgrade verification now uses the latest predecessor stable release tag (or
  `SHAM_UPGRADE_FROM`) and installs that release's locked dependencies before
  testing migration, reconciliation, secret preservation, and rollback.
- Integration, browser, Compose, backup/restore, and release-hygiene checks
  now provide stronger failure diagnostics and deterministic fixture setup.

## [1.1.1] — 2026-08-14

### Added

- Generic runtime drivers for static content, host processes, OCI containers, Docker Compose projects, and reverse proxies, with presets for Node/npm, Bun, Deno, FastAPI, Django, Go, Java, Dockerfile, Buildpacks, and Nixpacks.
- Repository-level `sham.yaml`/`sham.yml`/`sham.json` deployment manifests with explicit execution-policy approval when Git changes commands or runtime permissions.
- Readiness/liveness probes, graceful drain/shutdown controls, stable-path blue/green release activation, runtime reconciliation, and shared production/preview runtime lifecycle handling.
- OIDC Authorization Code + PKCE single sign-on, hashed scoped API tokens, and a `sham` CLI for sites, deploys, logs, lifecycle control, and rollback.
- Per-site CPU/request/error/latency history with p50/p95 latency and configurable per-site alert rules.
- Automated Cloudflare DNS/firewall reconciliation for opted-in sites.
- Staged full-instance backup restore with archive validation, SQLite validation, atomic data-directory swap, preserved backup/update stores, and rollback on failed restore.
- Supervised remotely managed Cloudflare Tunnel support with encrypted token storage, administrator controls, bounded restart backoff, and Docker packaging.
- First-class Docker image source deployments plus broader Git provider connections for Bitbucket Cloud, Gitea, and Forgejo alongside GitHub and GitLab.
- Dashboard attention-card drilldowns, a primary Performance navigation item, deeper command-palette search, and a sandboxed plugin-development playground.
- Categorized operator/developer documentation covering the dashboard/UI, runtimes and Docker/Compose, Git/CI/CD, API/CLI, a grouped API reference, operations/security, environment configuration, plugins, and troubleshooting.

### Changed

- Docker-isolated legacy Node deployments now install dependencies inside the compatible runtime image instead of reusing host-installed native modules.
- Managed container secrets are passed through the Docker client environment instead of embedding secret values in command-line arguments.
- Git releases now start from stable retained release paths so running process/container working directories are never renamed during activation or rollback.
- Health checks use bounded concurrency and runtime logging preserves lines split across stream chunks.
- Runtime promotion, Docker/Compose startup, scheduled container jobs, and backup restore now clean up/roll back partial failures more defensively.
- Compose validation blocks unmanaged external resources, host bind mounts/namespace escapes, auxiliary host ports, and unsafe Dockerfile paths while preserving private service networking.
- Folder uploads have bounded multipart-field headroom for the expanded site wizard instead of failing with `Too many fields`.
- Dashboard themes, administration settings, environment/Git-provider layouts, logout/license controls, tooltips, and toast stacking were aligned for consistent responsive behavior.
- The CLI now has explicit idempotent start/stop API endpoints and operation-appropriate request timeouts.
- Tests provide an explicit JWT secret so release checks cannot generate `data/.jwt-secret` in the source tree.
- The root README is now a concise product/quick-start overview, while detailed reference material lives under `docs/`; in-app updates now carry `docs/` and `bin/` so the manual and CLI stay aligned with the active SHAM release.

## [1.0.0] — 2026-08-05

First public stable release.

### Added

- Static-site and managed Node.js hosting from one self-hosted dashboard.
- Atomic Git deployments, signed webhooks, previews, releases, and rollback.
- File management, snapshots, dependency scanning, scheduled jobs, and external backups.
- Multi-user authentication, administrator/user roles, TOTP, recovery codes, and WebAuthn passkeys.
- Encrypted secret storage, security controls, observability, alerts, public status, and performance monitoring.
- Optional Docker-isolated site runtimes and Anubis anti-bot sidecars.
- Theme-consistent responsive dashboard, built-in documentation, and accessibility improvements.
- GitHub Actions for CI, Docker build validation, GHCR publishing, lockfile preparation, and tagged releases.

### Security

- Hardened upload archive handling and worker-safe multipart temporary storage.
- Uniform deployment-webhook authentication failures and replay protection.
- Authentication before mutation-queue admission.
- Owner-only permissions for sensitive local files where supported.
- Redirect rejection for credential-bearing outbound integrations.
- Minimal unauthenticated health and optional public-status responses.

### Notes

Earlier version labels were internal development identifiers. Version 1.0.0 starts the public release history.
