# Changelog

All notable public changes to SHAM are documented here. The project follows Semantic Versioning.

## [Unreleased]

## [1.5.0] — 2026-10-27

### Added

- First-run setup token. While no account exists, `POST /api/auth/register`
  requires a one-time token that SHAM prints in its log and stores in
  `SHAM_DATA_PATH/.setup-token` (or `SHAM_SETUP_TOKEN`, at least 16
  characters). The first-run form asks for it.
- **Operations → External backups → Export recovery key** (`POST
  /api/admin/security/recovery-key`, browser session and password required)
  downloads the master keyring for offline storage.
- Dedicated trusted keys for SHAM core updates, managed under **Operations →
  Safe SHAM update → Trusted update signing keys** (`GET`/`POST
  /api/admin/update-trusted-keys`, `DELETE
  /api/admin/update-trusted-keys/:id`).
- **Allow reinstall or downgrade** acknowledgement for staged updates
  (`allowDowngrade`).

### Changed

- Compose sites are hardened by default: every service runs with
  `cap_drop: [ALL]`, a compatibility capability set (`CHOWN`, `DAC_OVERRIDE`,
  `FOWNER`, `FSETID`, `KILL`, `SETGID`, `SETUID`, `SETPCAP`,
  `NET_BIND_SERVICE`) and `no-new-privileges:true`. The Runtime Agent runs
  Compose from the exact normalized model it validated, held in its private
  temporary directory.
- `cloudflared` connectors start with `--metrics 127.0.0.1:0`.
- Restoring a backup keeps the host's own master keyring, JWT secret, setup
  token and active SHAM application release. Rotating the master key keeps up
  to 16 retired keys for decryption instead of discarding them.

### Security

- Updated the bundled `cloudflared` to 2026.10.4 (from 2026.7.3). This picks up
  VULN-176088 (debug endpoints on the connector's loopback metrics server are
  now allowlisted, so managed-process sites sharing the SHAM container's
  loopback can no longer reach them), VULN-141859 (request path normalization
  with Access rules), stripping of authentication data before forwarding to
  origins, and Go toolchain fixes including GO-2026-6600. Releases 2026.8.0 and
  2026.8.1 had origin path regressions and are skipped.
- Updated `multer` to 2.5.0 (GHSA-q7qp-rjg7-q26m: denial of service via a
  pending asynchronous `fileFilter` after request teardown).
- Updated transitive dependencies: `proxy-addr` 2.0.8 (GHSA-jqcg-44mw-7w3h:
  client IP spoofing through an IPv4-mapped IPv6 trusted-proxy subnet),
  `body-parser` 2.4.0 (GHSA-27r3-jxmh-p828: denial of service via trailing
  bytes after a compressed request body), and `follow-redirects` 1.16.2
  (GHSA-q3jh-wrc6-jgq8, GHSA-8r9p-f939-6h3c: credential headers forwarded
  across origins on redirect).
- The Runtime Agent's container-run operation now accepts only the configured
  SHAM runtime networks, matching network ensure/connect. Previously any valid
  network name, including `host`, was accepted from an agent-token holder.
- Deploy webhooks sent to `/api/v1/hooks/deploy/:id` now verify the HMAC over
  the request body. The raw body was captured only for the legacy path, so v1
  signatures were computed over an empty body and real provider deliveries
  failed verification.
- Accounts with the `user` role can no longer cause SHAM to execute code.
  Process, Node, container and Compose runtimes; start, install, build,
  readiness and health commands; dependency installation; Git source settings;
  `sham.yaml` manifests; and file changes on sites that run code now require an
  administrator. Previously a `user` could create a process site whose command
  ran as the SHAM service account, read the JWT secret and master keyring, and
  take over an administrator account.
- Hosted Compose policy is now an allowlist of top-level, service, build,
  deploy, logging, network, volume, config and secret keys. It rejects keys
  that the previous denylist missed, including `device_cgroup_rules`,
  `cgroup_parent`, `runtime`, `isolation`, `sysctls`, `userns_mode`,
  `pid`/`ipc` namespace sharing, `security_opt` beyond `no-new-privileges`,
  `build.additional_contexts` outside the project, and remote build contexts.
  Build contexts, Dockerfiles, `env_file`, and config/secret files must stay
  inside the project after symlinks are resolved, checked by the Runtime Agent.
  Compose no longer re-reads project files after validation, which closes a
  swap-after-check race.
- Containers on SHAM's runtime networks receive 403 from the dashboard and from
  sites' direct and private listeners, so they can no longer bypass the shared
  edge and its access rules. The Runtime Agent reports the networks' subnets
  through a new operation.
- `CF-Connecting-IP` and `CF-IPCountry` from loopback are trusted only when
  the connection belongs to a cloudflared process supervised by SHAM (Linux).
  Every SHAM proxy path rewrites or removes these headers, so a proxy site
  cannot be used to forge a visitor's IP or country.
- Proxy targets may no longer point at link-local or cloud metadata addresses
  (`169.254.0.0/16`, `fe80::/10`, `fd00:ec2::254`) or at the SHAM dashboard
  port.
- Sign-in brute-force protection: rate-limit buckets group IPv6 clients by
  /64; an account allows 10 failed password or second-factor attempts per
  client network and 100 in total per 15 minutes, so a stranger who knows a
  username cannot lock its owner out; MFA login tokens become invalid after 5
  failures and are single-use; a TOTP code cannot be accepted twice.
- API token scopes are now assigned per route. Logs, the audit log and
  runtime events (and their exports) require `logs:read`. Site file contents, configuration export and
  plugin actions require full access. `deploy` and `sites:control` cover only
  the site lifecycle routes.
- Staging a SHAM update requires password confirmation. Core updates are
  verified only against trusted update keys (plugin publisher keys no longer
  count), and an update that is not newer than the running version requires an
  explicit acknowledgement.
- Backups no longer contain the master keyring, JWT secret or setup token, so
  a copy in S3, SFTP or an external directory can no longer decrypt itself.
  Symlinks that cannot be archived safely (absolute or escaping) are skipped
  with a warning instead of failing every backup.
- JavaScript plugins run in a sandbox that exposes no host-realm objects, and
  a plugin's uncaught exception or unhandled rejection stops its worker
  without SHAM formatting the thrown value. This closes two confirmed escapes
  to the SHAM process.
  Plugin SQL, both declarative and JavaScript, is checked with SQLite `EXPLAIN`:
  - **Reads:** an allowlist of non-sensitive core tables and columns, plus the
    plugin's own tables.
  - **Writes and schema changes:** only the plugin's own `plugin_<id>_` tables.
- Dependency scans run `npm audit` on a temporary copy of the manifest and
  lockfile, so a site's `.npmrc` can no longer redirect SHAM's requests. The
  operator's `NPM_CONFIG_REGISTRY` and user/global npm config still apply.

### Upgrade notes

- Upgrade the control plane and Runtime Agent together with the same pinned
  `SHAM_IMAGE`. An older agent leaves the workload-network guard inactive.
- **After upgrading, export the recovery key** (Operations → External
  backups) and store it offline, separate from backups. New backups cannot be decrypted on a replacement host without it,
  or without the `SHAM_MASTER_KEY` you supply. Export it again after every
  master key rotation. After a restore, users sign in again.
- Re-add the SHAM release signing key under **Trusted update signing keys**.
  Plugin publisher keys are not copied over. Until a key is added, signed
  updates are treated as unsigned.
- Accounts with the `user` role can no longer create or change code-running
  sites. On first start, SHAM turns off `sham.yaml` support for static and
  proxy sites that contain no manifest, which changes nothing at runtime.
  Users cannot change the files of a static or proxy site that does contain a
  manifest until an administrator reviews it or disables manifests for that
  site. Review sites created by non-admin accounts for an unexpected
  `sham.yaml`, and for process runtimes created before this release.
- Compose files that use keys outside the allowlist, `include`, `extends` with
  `file`, symlinked paths, build `tags`/`ssh`/`cache_to`, remote build contexts
  or `secrets` with `environment:` are rejected. `image:` next to `build:` is
  renamed to the project-scoped `<project>-<service>`, and other services
  that used the same tag follow the rename without pulling. Config and
  secret files must be UTF-8 and at most 1 MiB. Services lose `MKNOD`,
  `NET_RAW`, `SETFCAP`, `SYS_CHROOT` and `AUDIT_WRITE`, and setuid escalation
  such as `sudo` stops working.
- Workloads must reach other SHAM sites by domain through the shared edge, not
  through `sham:8080` or a site's direct port.
- Plugins that read sensitive tables, select all columns from `sites`, write
  core tables, use `BEGIN`/`COMMIT` (plugins share SHAM's database
  connection), or `require` modules other than `crypto` are rejected or
  disabled at startup. Plugin results pass through JSON, so `Date` values
  become strings.
- API tokens limited to `read` lose access to site file contents, and log
  exports now need `logs:read`. Replace narrow tokens where scripts depend on
  those routes.
- A fresh install needs the setup token from the server log
  (`docker logs sham`) to create the first administrator.
- MFA sign-ins that are in progress during the upgrade must be restarted.

## [1.4.0] — 2026-09-28

### Added

- `SHAM_PLUGIN_MEMORY_MB` caps the heap of each enabled plugin's worker
  isolate (default 64 MB).
- `GET /api/performance` (and `/api/v1/performance`) accepts
  `compactHistory=1` to return history entries with only the charted fields.

### Changed

- In-memory performance history keeps full samples only for the 120-sample
  window the API serves and compacts older samples, reducing memory use that
  previously grew with history length × running sites. The API response shape
  is unchanged. The dashboard requests compact history, shrinking each
  Performance poll from roughly 1.2 MB to 30 KB with 20 running sites.
- The dashboard stats view reads active alerts directly instead of building
  the full performance payload.
- The Performance page pauses polling while its browser tab is hidden.
- Phone layouts: performance charts render at the device width with readable
  labels, status badges no longer stretch across panels, empty-state
  placeholders are shorter, and site templates, workspace details, theme
  presets, and the color-mode switch use compact multi-column layouts.

### Fixed

- Resource-history chart time labels were always blank.
- Health and readiness status-range inputs had no spacing between them.
- Form fields in multi-column dialogs (for example the alert-rule dialog)
  stretched to the height of a neighbouring field's hint text.
- Modals reserved an empty scrollbar gutter, which made right padding uneven
  and cut header/footer dividers short; sticky modal headers and footers are
  now opaque so scrolled content no longer shows through.
- Observability header actions now span the full width on phones like other
  page headers.

### Security

- Updated `adm-zip` to 0.6.1 (GHSA-vwc7-r8mq-g2x9 symlink-following
  extraction overwrite; GHSA-7q85-xj36-vmfc declared-size memory exhaustion).
- Updated `multer` to 2.4.0 (GHSA-wc9g-mqfw-jrwm, GHSA-qfvm-cv95-jqjf,
  GHSA-qvfw-j98x-7q72, GHSA-535w-7cp7-47q4: multipart denial-of-service and
  file-size limit bypass). This restores the production dependency audit gate
  used by CI and the Docker build.

### Upgrade notes

- Enabled plugins now run with a 64 MB worker heap limit. A plugin that needs
  more memory is stopped and marked failed after upgrading; set
  `SHAM_PLUGIN_MEMORY_MB` to a higher value before upgrading if you run
  memory-heavy plugins.
- No database migration or Runtime Agent protocol change is included. Upgrade
  the control plane and Runtime Agent together with the same pinned
  `SHAM_IMAGE`, as for 1.3.0, and take a verified backup first.
- The upgrade compatibility drill now uses the unmodified `v1.3.0` public
  stable release as its baseline.

## [1.3.0] — 2026-09-06

### Added

- System Health panel with operational checks, including backup health.

### Changed

- Runtime stdout/stderr is batched into bounded multi-line workspace events
  instead of creating one log event per output line.
- Shared-edge site creation can allocate the private listener port
  automatically when the port field is left blank.
- Host-based Node/npm sites can perform a snapshotted fresh production
  dependency install from the dashboard.
- Enabled SHAM-managed Cloudflare Tunnel routes now preserve visitor IP and
  country headers through the shared edge proxy without requiring a broad
  trusted-proxy setting.
- Uploading a ZIP or folder now detects a root `sham.yaml`/`sham.yml` manifest
  and prefills supported runtime/build settings before deployment.
- Documented public-plus-VPN-only process listeners and a LinuxServer
  WireGuard deployment pattern for keeping the SHAM dashboard private.

### Fixed

- Backup restores now replace entries inside the mounted data directory,
  preserving the mount, with a journal for interrupted-restore recovery.
- Restores quiesce managed Docker workloads through the Runtime Agent before
  replacing data. Agent credentials and local backup/update storage survive.
- Backups preserve safe in-tree dependency links and executable permissions.
  Creation and restore share archive validation, and restored SQLite databases
  are checked before activation.
- Backup health recognizes persisted success, running, and failure states.

### Security

- Workload variables are passed through private environment files instead of
  altering the Runtime Agent's Docker/Compose CLI environment.
- Docker and Compose reject host-backed or unmanaged named volumes; Compose
  rejects reserved CLI environment variables and disables implicit repository
  `.env` loading.
- Hidden static assets are blocked before compression, minification, and SPA
  fallback handling.
- OIDC login state is bound to the initiating browser and consumed once.
- Updated the locked `qs` dependency to 6.16.0 and added the pinned `tar`
  parser for structured archive validation.

### Upgrade notes

- Upgrade the control plane and Runtime Agent together to 1.3.0. Restore
  coordination requires the new agent operation.
- Before upgrading, keep a verified backup and review Compose configurations:
  use ordinary project-scoped local volumes without driver options, SHAM
  environment settings instead of implicit `.env`, and no `DOCKER_*` or
  `COMPOSE_*` workload variables. Multiline environment values remain unsupported.
- Existing archives with unsafe paths, link targets, special files, or invalid
  databases are rejected. If interrupted recovery cannot complete, preserve
  `.restore-work` and follow the recovery instructions in
  [Operations and security](docs/operations-and-security.md).

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
