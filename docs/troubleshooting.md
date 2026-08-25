# Troubleshooting

Start with the error message in the dashboard/runtime/deployment log, then use the sections below. Also check **Observability**, **Performance**, and the individual site's Logs/Deployments workspace.

## Folder upload: `Upload rejected: Too many fields`

Older builds capped the site multipart field count below the expanded site's runtime/configuration form.

The current build uses a dedicated bounded `SITE_FORM_FIELD_LIMIT` with enough headroom for the full site wizard. Upgrade before changing proxy settings.

If the error persists on the current build, check whether an upstream reverse proxy/WAF imposes its own multipart field/part limit.

## Upload rejected for file count or size

SHAM intentionally bounds multipart fields, files, field names, aggregate upload size, archive/file counts, and staging work.

For very large content trees:

- Use a Git deployment.
- Build/run a container image.
- Split assets appropriately.
- Check reverse-proxy request-size and timeout limits.

## Uploaded folder has the wrong root

SHAM removes one common enclosing directory. If the browser sends `project/public/index.html`, the installed path can become `public/index.html` after stripping `project/`.

Set the site entry/build-output path relative to that installed root.

## Process starts but never becomes ready

Check:

- Application binds the injected `HOST` and port variable.
- Readiness path is correct.
- Expected HTTP status min/max is correct.
- Startup timeout is long enough.
- Database/cache dependencies are reachable.
- Runtime logs show startup failure rather than only a readiness timeout.

For host-process runtimes, avoid `0.0.0.0` unless direct exposure is intentional; normal generated presets should use SHAM's injected loopback `HOST`.

## `EADDRINUSE` during process startup

SHAM retries internal-port allocation for managed process starts, but persistent collisions can indicate another local service is aggressively binding ports or a custom command ignores the injected port.

Confirm the application actually uses `PORT`/configured port variable.

## Docker capability is unavailable

Docker-backed features go through the separate **Runtime Agent** process (see [Runtimes and Docker](runtimes-and-docker.md#runtime-agent-architecture)). Check `capabilities` in the Operations payload (or **Settings → Instance**) for `agentReachable`, `agentAuthenticated`, and `dockerAvailable`, and see [Runtime Agent](#runtime-agent) below.

If SHAM itself runs in Docker, the base Compose file does not mount the Docker socket into `sham`, and never does even under the isolation overlay — only `sham-runtime-agent` does. Use the optional isolation overlay only when you intend to grant Docker-daemon control to the agent.

## Runtime Agent

Symptoms map to `capabilities.dockerReason` in the dashboard/API:

**"Runtime agent unavailable" (`agentReachable: false`)**
- The `sham-runtime-agent` container/process is not running, or `SHAM_RUNTIME_AGENT_SOCKET` does not point at the same path in both processes.
- With the isolation overlay: `docker compose ps sham-runtime-agent` and check its logs.
- Direct installs: run `npm run runtime-agent` (or `node runtime-agent/index.js`) alongside `npm start`.
- Confirm both processes share the same `SHAM_DATA_PATH` — the socket lives at `<SHAM_DATA_PATH>/runtime-agent/agent.sock` by default, so a mismatched data path looks identical to "agent not running."

**"Runtime agent authentication failed" (`agentAuthenticated: false`)**
- `SHAM_RUNTIME_AGENT_TOKEN_PATH` differs between the two processes, or one side has a stale token file from a previous, separately-provisioned data directory.
- Fix: ensure both processes read `<SHAM_DATA_PATH>/runtime-agent/agent.token` from the same shared volume/filesystem; do not copy the token file manually between hosts.

**"Docker daemon is unreachable from the runtime agent" (agent reachable, `dockerAvailable: false`)**
- The agent itself cannot reach Docker: socket not mounted into the agent container, `DOCKER_GID` mismatch, or the daemon is down. Run `docker version` **inside the `sham-runtime-agent` container**, not the `sham` container — it no longer has Docker access at all.

**Control-plane/agent version mismatch**
- Both ship in the same image and are updated together; if you build a custom agent image separately from the control plane, requests fail with a `PROTOCOL_VERSION_MISMATCH` error until both sides run matching versions.

**Permission denied on the Docker socket**
- `DOCKER_GID` must match the actual GID of `/var/run/docker.sock` on the host running the agent: `stat -c '%g' /var/run/docker.sock`.

## Existing Docker image fails

Check:

```bash
docker pull ghcr.io/dylpickle-studios/sham:latest
docker image inspect ghcr.io/dylpickle-studios/sham:latest
```

Then verify:

- CPU architecture.
- Application container port.
- Required environment variables.
- Entrypoint/CMD.
- Readiness path.
- Image registry authentication at the Docker daemon level if required.

Existing-image mode preserves the image filesystem and does not mount empty site source over it.

## Dockerfile build fails

Check:

- Build context is inside the immutable release.
- Dockerfile path is inside its context/release.
- `SHAM_DOCKER_HOST_DATA_PATH` is correct when SHAM is containerized and uses the host daemon.
- Docker can reach required registries/package mirrors.
- The final stage actually contains/runs the application.
- Runtime container port matches SHAM configuration.

## Buildpacks/Nixpacks unavailable

Check the Operations capabilities and:

```bash
pack --version
nixpacks --version
```

Configure `SHAM_PACK_BIN`/`SHAM_NIXPACKS_BIN` when binaries are installed in a nonstandard location.

## Compose rejected

SHAM rejects unsafe/unmanaged Compose features by design. Remove or redesign:

- Host bind mounts.
- Privileged mode.
- Host network/PID/IPC namespaces.
- Added capabilities.
- Devices.
- Docker socket mounts.
- Host-gateway mappings.
- External networks/volumes/configs/secrets.
- Unsafe security-profile overrides covered by policy validation.
- Published host ports on support services.

Use named volumes and private Compose networks.

## Compose application is reachable directly on the host

Only the selected application service should receive the SHAM-managed publication needed for routing. Support services should not use `ports:`.

Prefer `expose:` for service documentation/internal intent without publishing a host port.

## Compose app works on host SHAM but not containerized SHAM

When SHAM itself is a container, `127.0.0.1` inside SHAM is not the host or sibling application container.

Use the supplied Docker isolation/network configuration and ensure `SHAM_DOCKER_HOST_DATA_PATH`, internal/egress network names, and Docker socket access are correct.

## Git repository is not discovered

Check:

- Provider token is still valid.
- Token has repository-list/read permission.
- Gitea/Forgejo base URL is correct.
- Repository origin matches the expected provider instance.
- Multiple self-hosted connections are not ambiguous.

Direct Git URLs remain an alternative when discovery is unnecessary.

## Private Git clone fails

Do not embed credentials in the repository URL. SHAM rejects URLs containing user/password or query-string credentials.

Use a provider connection or dedicated SSH deploy key.

## Webhook does not deploy

Check:

1. Public webhook base URL is reachable over HTTPS.
2. Provider connection can manage/read the repository as required.
3. Signature/token secret is correct.
4. Push is for the configured branch.
5. Delivery/event headers are present.
6. The delivery has not already been processed/replayed.
7. Deployment logs do not show a manifest approval/build/readiness failure.

## Manifest approval required

A changed `sham.yaml`, `sham.yml`, or `sham.json` changed execution policy.

Review the diff, then intentionally approve it only when trusted:

```bash
sham deploy SITE_ID --branch main --approve-manifest
```

Never automatically approve manifest changes from untrusted pull requests.

## Deployment switched traffic but metadata failed

Current candidate promotion attempts to restore the previous backend/traffic target if activation bookkeeping fails. Check deployment/runtime logs for a `deployed-with-warning` or promotion error and verify active release state before retrying.

## Restore is rejected before restart

A backup restore fails closed when archive paths/types/counts, staged tree shape, SQLite integrity, or core database tables fail validation.

The live data directory should remain in place until the staged backup validates.

## Restore succeeded but old backup files are missing

The restore workflow preserves the backup/update stores required by SHAM's recovery/update design. If files are unexpectedly absent, check the selected provider/path and restore/audit logs before running another restore.

## License/info button fails

The information button opens `/LICENSE`. Verify the deployed application package contains the repository `LICENSE` file and that a reverse proxy is not intercepting that path.

## Tooltip or notification appears behind a modal

Current SHAM mounts top-layer tooltips/toast regions into the active dialog/popover context when required.

After upgrading:

- Hard-refresh the dashboard.
- Clear a stale service-worker/proxy cache if present externally.
- Confirm custom/plugin CSS is not forcing a lower z-index/stacking context.

## Environment-variable controls overlap

Current layouts use responsive grid/wrapping rules. Clear cached `styles.css`/browser assets after upgrading. If the issue exists only with a plugin/theme override, disable that override to isolate it.

## Git-provider controls overlap

Provider token/base-URL/action rows are responsive in the current dashboard. The same stale-asset/plugin-CSS checks apply.

## CI fails: generated JWT secret

A generated `data/.jwt-secret` must not appear in source/release archives.

Tests that load configuration should supply a test secret instead of causing config initialization to generate one in the repository.

Run:

```bash
npm run release:check
git status --short
```

The release check must leave the source tree free of generated credentials.

## CLI hangs or times out

Verify `SHAM_URL`, DNS, TLS, authentication, and reverse-proxy connectivity.

Current CLI bounds:

- Ordinary/control requests: 30 seconds.
- Deploy: up to 30 minutes.
- Rollback: up to 10 minutes.

A reverse proxy with a shorter timeout can still terminate a long deployment request.

## API returns `401`/`403`

Confirm:

- `Authorization: Bearer ...` is present.
- Token has not been revoked/expired.
- Token scope includes the action.
- The owning user still has the required role.
- Administrator endpoints are not being called with an ordinary user token.

## OIDC login fails

Check:

- OIDC is enabled.
- Issuer/client ID/client secret (if required) are correct.
- Redirect URI exactly matches the SHAM callback configured at the identity provider.
- Issuer/JWKS endpoints are reachable from SHAM.
- User auto-provisioning policy permits the identity when the user does not already exist.
- Server clock is accurate enough for token time validation.

## Plugin playground preview cannot call an API

Expected behavior. The playground preview is sandboxed and network-blocked. It validates manifests and previews browser UI without granting real server/network authority.

Install/test the plugin on a development SHAM instance for real server actions.

## In-app update changed code but docs/CLI look old

Current update releases manage `docs/` and `bin/` alongside application source/assets. If an older active update predates this behavior, perform one normal reviewed upgrade to the current release so later in-app updates keep docs and CLI aligned.

## More diagnostics

- **Dashboard quick views** — unhealthy sites, failed deployments, active alerts, automated traffic.
- **Sites → workspace** — runtime, files, logs, releases/deployments, networking/security/settings.
- **Observability** — runtime/audit events and logs.
- **Performance** — CPU/memory/request/error/latency/connection/restart data.
- **Settings → Instance** — runtime capabilities, Git providers, backups/observability.
- **Settings → Administration** — users/OIDC/Cloudflare/Certbot/persistent policy.
