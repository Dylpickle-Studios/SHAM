# Configuration reference

SHAM loads `.env` from the project root. Existing process environment variables take precedence over values loaded from the file.

Use `.env.example` as the machine-readable template for the current release. This guide explains what each group controls.

## Dashboard listener and proxy trust

| Variable | Default | Purpose |
|---|---|---|
| `SHAM_HOST` | `127.0.0.1` | Dashboard bind address. |
| `SHAM_PORT` | `8080` | Dashboard TCP port. |
| `SHAM_PUBLIC_ORIGIN` | empty | Canonical browser-facing dashboard origin, for example `https://sham.example.com`. Recommended behind a reverse proxy; used for WebAuthn/OIDC origin handling, secure-cookie decisions, and CSRF validation. |
| `SHAM_SELF_SIGNED_HTTPS` | `false` | Direct/local installs: generate a self-signed certificate and serve the dashboard over HTTPS. Trust the generated `dashboard-tls/cert.pem` on client devices. |
| `SHAM_OPENSSL_BIN` | `openssl` | OpenSSL executable used to generate the local self-signed dashboard certificate. |
| `SHAM_TRUST_PROXY` | `loopback` | Express trust-proxy setting. Keep this narrow unless you fully control the proxy path. |
| `SHAM_TRUSTED_EDGE_PROXIES` | empty | Explicit reverse-proxy peers allowed to supply Cloudflare visitor identity headers. |

Do not broadly trust private address ranges merely because SHAM sits behind a reverse proxy. Origin access and trusted proxy peers should be designed together.

When SHAM is published behind a reverse proxy, set `SHAM_PUBLIC_ORIGIN` to the exact origin users open in their browser. This prevents proxy `Host` rewriting from producing mismatched WebAuthn RP IDs or OIDC callback URLs.

`SHAM_SELF_SIGNED_HTTPS` is intended for running SHAM itself directly on a local host, for example `https://192.168.1.25:8080`. With `SHAM_HOST=0.0.0.0` (or a concrete LAN address), SHAM includes detected LAN IPs in the generated certificate and stores the key/certificate under `SHAM_DATA_PATH/dashboard-tls/`. Import the generated certificate into client trust stores before relying on WebAuthn/passkeys. Use a normal publicly trusted or internally managed certificate for production ingress.

## Persistent data

| Variable | Default | Purpose |
|---|---|---|
| `SHAM_DATA_PATH` | `./data` | SQLite database, site/release data, plugins, backups, certificates, generated secret/key material, and update/runtime state. Docker commonly uses `/data`. |

Keep this path outside the source tree for production and back it up independently.

## Uploads and editor

| Variable | Default | Purpose |
|---|---:|---|
| `SHAM_UPLOAD_LIMIT_MB` | `100` | Uploaded/uncompressed project-size bound. |
| `SHAM_EDITOR_LIMIT_MB` | `2` | Maximum text-file size accepted by the browser editor. |
| `SHAM_UPLOAD_WORKERS` | `2` | Concurrent extraction/install workers. |
| `SHAM_UPLOAD_QUEUE_LIMIT` | `16` | Maximum queued/active upload jobs before SHAM rejects additional work temporarily. |
| `SHAM_REQUEST_TIMEOUT_SECONDS` | `300` | HTTP request receive timeout, including uploads. |

The multipart site form also uses an internal bounded field-count limit with enough headroom for the expanded runtime configuration. It is not intended to be unlimited.

## Legacy Node/dependency installation

| Variable | Default | Purpose |
|---|---:|---|
| `SHAM_NODE_START_TIMEOUT_SECONDS` | `30` | Legacy startup default used by Node-compatible flows. New runtime specs also carry explicit startup timeouts. |
| `SHAM_NPM_INSTALL_TIMEOUT_SECONDS` | `600` | Maximum managed npm-install duration. |
| `SHAM_NPM_INSTALL_WORKERS` | `2` | Concurrent dependency installations. |
| `SHAM_NPM_INSTALL_QUEUE_LIMIT` | `32` | Waiting dependency-install bound. |

## Static delivery and traffic accounting

| Variable | Default | Purpose |
|---|---:|---|
| `SHAM_STATS_FLUSH_SECONDS` | `2` | Batch interval for request-statistics writes. |
| `SHAM_MINIFY_MAX_MB` | `5` | Largest single static asset SHAM will transform for minification. |
| `SHAM_MINIFY_CACHE_MB` | `32` | Approximate transformed-content memory cache bound. |
| `SHAM_MINIFY_WORKERS` | `2` | Concurrent minification workers. |
| `SHAM_MINIFY_QUEUE_LIMIT` | `64` | Transformation queue/active bound before original content is served. |
| `SHAM_COMPRESSION_WORKERS` | `4` | Concurrent on-demand compression work. |
| `SHAM_COMPRESSION_QUEUE_LIMIT` | `128` | Compression queue bound before SHAM serves an uncompressed response. |
| `SHAM_VISITOR_RETENTION_DAYS` | `90` | Retention for detailed visitor-IP records. |
| `SHAM_VISITOR_PENDING_BUCKETS` | `50000` | Maximum pending visitor identities before statistics flush. |
| `SHAM_AUTH_RATE_LIMIT_BUCKETS` | `10000` | Authentication rate-limit identity bound. |
| `SHAM_FIREWALL_RATE_LIMIT_BUCKETS` | `50000` | Per-site firewall rate-limit identity bound. |

## Authentication and secret encryption

| Variable | Default | Purpose |
|---|---|---|
| `SHAM_JWT_SECRET` | generated if absent | JWT/session signing secret. Supply at least 32 random characters in production. Generated values belong under `SHAM_DATA_PATH`, never in source. |
| `SHAM_MASTER_KEY` | generated keyring if absent | Optional external 32-byte key (hex/base64url accepted by the implementation) used to protect saved integration/plugin/TOTP secrets. |
| `NODE_ENV` | `development` | Runtime mode. Production affects security behavior such as cookies. |

Prefer external/container secret injection for production credentials.

## Performance and background work

| Variable | Default | Purpose |
|---|---:|---|
| `SHAM_PERFORMANCE_INTERVAL_SECONDS` | `5` | Live performance sampling interval. |
| `SHAM_PERFORMANCE_HISTORY_SAMPLES` | `720` | In-memory performance chart sample bound. |
| `SHAM_PERFORMANCE_SITE_CONCURRENCY` | `8` | Concurrent per-site runtime usage samples. |
| `SHAM_HEALTH_CHECK_CONCURRENCY` | `8` | Concurrent site liveness checks in one sweep. |
| `SHAM_DEPENDENCY_SCAN_TIMEOUT_SECONDS` | `120` | npm-audit/dependency-scan timeout. |
| `SHAM_DEPENDENCY_SCAN_WORKERS` | `1` | Concurrent dependency scans. |
| `SHAM_DEPENDENCY_SCAN_QUEUE_LIMIT` | `16` | Dependency-scan queue bound. |
| `SHAM_SNAPSHOT_RETENTION` | `10` | Retained snapshots per site. |
| `SHAM_SNAPSHOT_WORKERS` | `1` | Concurrent snapshot/archive workers. |
| `SHAM_SNAPSHOT_QUEUE_LIMIT` | `8` | Snapshot-operation queue bound. |
| `SHAM_PLUGIN_ACTION_TIMEOUT_SECONDS` | `15` | Plugin startup/action timeout. |
| `SHAM_PLUGIN_MAX_PENDING_ACTIONS` | `32` | Pending actions allowed per isolated plugin. |

## Shared edge listener

| Variable | Default | Purpose |
|---|---|---|
| `SHAM_EDGE_HOST` | `0.0.0.0` | Shared edge-listener address. |
| `SHAM_EDGE_HTTP_PORT` | `0` | Shared HTTP edge port; `0` disables it. Use `80` when SHAM owns conventional HTTP. |
| `SHAM_EDGE_HTTPS_PORT` | `0` | Shared HTTPS/SNI edge port; `0` disables it. Use `443` when SHAM owns conventional HTTPS. |

## External executables

| Variable | Default executable | Used for |
|---|---|---|
| `SHAM_CERTBOT_BIN` | `certbot` | Certificate issuance/renewal. |
| `SHAM_CLOUDFLARED_BIN` | `cloudflared` | Cloudflare Tunnels. |
| `SHAM_DOCKER_BIN` | `docker` | Runtime Agent only: containers, Dockerfile builds, Compose, Docker isolation, Anubis. |
| `SHAM_PACK_BIN` | `pack` | Cloud Native Buildpacks. |
| `SHAM_NIXPACKS_BIN` | `nixpacks` | Nixpacks source-to-image builds. |
| `SHAM_GIT_BIN` | `git` | Git deployments. |
| `SHAM_TAR_BIN` | `tar` | Backup/archive operations. |
| `SHAM_RESTIC_BIN` | `restic` | Restic backup repositories. |
| `SHAM_AWS_BIN` | `aws` | S3-compatible transfers through the AWS CLI workflow. |
| `SHAM_SFTP_BIN` | `sftp` | SFTP backup transfer. |

SHAM reports optional runtime/build capabilities in the Operations/Instance area where applicable. Missing optional executables should disable/fail only the corresponding feature, not the base dashboard.

## Docker when SHAM itself is containerized

| Variable | Default | Purpose |
|---|---|---|
| `SHAM_DOCKER_HOST_DATA_PATH` | unset | Absolute host-side directory corresponding to `SHAM_DATA_PATH`; required when host Docker needs to mount staged/release paths. |
| `SHAM_DOCKER_INTERNAL_NETWORK` | `sham-runtime-internal` | Shared internal/no-egress runtime network. |
| `SHAM_DOCKER_EGRESS_NETWORK` | `sham-runtime-egress` | Shared egress-capable runtime network. |

The supplied isolation Compose overlay configures Docker access/network plumbing. The base Compose file deliberately does not mount the Docker socket, and with the Runtime Agent split the `sham` service never mounts it even under the isolation overlay — only `sham-runtime-agent` does. `SHAM_DOCKER_HOST_DATA_PATH` must be set on the agent service, not on `sham`.

## Runtime Agent (control plane → agent RPC)

| Variable | Default | Purpose |
|---|---|---|
| `SHAM_RUNTIME_AGENT_SOCKET` | `<SHAM_DATA_PATH>/runtime-agent/agent.sock` | Unix socket the control plane connects to and the agent listens on. Must resolve to the same path inside both containers (the shared `/data` volume makes this automatic). |
| `SHAM_RUNTIME_AGENT_TOKEN_PATH` | `<SHAM_DATA_PATH>/runtime-agent/agent.token` | Shared authentication token file. Generated automatically by the agent on first start (mode `0600`); never log or expose its contents. |
| `SHAM_RUNTIME_AGENT_TIMEOUT_SECONDS` | `120` | Control-plane request timeout when calling the agent (build/Compose operations can legitimately take a while). |

These apply to both the control plane and the agent process — set them identically on both (or leave them at their defaults, since both default from the same `SHAM_DATA_PATH`). See [Runtimes and Docker](runtimes-and-docker.md#runtime-agent-architecture) for the architecture and [Troubleshooting](troubleshooting.md#runtime-agent) for failure modes.

## Automation and long-running operations

| Variable | Default | Purpose |
|---|---:|---|
| `SHAM_JOB_POLL_SECONDS` | `15` | Scheduled-job poll interval. |
| `SHAM_JOB_TIMEOUT_SECONDS` | `900` | Maximum scheduled-job runtime. |
| `SHAM_BACKUP_TIMEOUT_SECONDS` | `3600` | Maximum backup runtime. |
| `SHAM_GIT_TIMEOUT_SECONDS` | `600` | Maximum Git stage/tool operation duration. |
| `SHAM_PREVIEW_TTL_HOURS` | `24` | Default preview expiration. |
| `SHAM_INTEGRATION_TIMEOUT_SECONDS` | `20` | Integration HTTP timeout (for example Cloudflare API calls). |

## Optional Anubis image

| Variable | Default | Purpose |
|---|---|---|
| `SHAM_ANUBIS_IMAGE` | pinned release in `.env.example` | Container image for optional Anubis anti-bot sidecars. Review changes before updating the pin. |

## Deploy webhook secret

`DEPLOY_WEBHOOK_SECRET` is normally a per-site encrypted environment value generated/managed by SHAM for deployment webhooks rather than a global `.env` setting. If you explicitly provide it to a site, treat it as a secret and scope it to build/both as needed by the webhook workflow.

## Production checklist

- Supply `SHAM_JWT_SECRET` through a secret store.
- Persist and back up `SHAM_DATA_PATH`.
- Put the dashboard behind HTTPS.
- Configure `SHAM_TRUST_PROXY`/`SHAM_TRUSTED_EDGE_PROXIES` narrowly.
- Enable Docker socket access only when Docker-managed features are required.
- Set `SHAM_DOCKER_HOST_DATA_PATH` correctly for containerized-control-plane builds.
- Ensure only required shared/site ports are published by the host/container runtime.
- Run `npm run release:check` before source/update packaging.
