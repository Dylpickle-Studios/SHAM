# Runtimes and Docker

SHAM deliberately separates **runtime drivers** from **framework presets**. Adding support for another language usually means supplying a process/container preset rather than adding another orchestration implementation.

## Runtime driver matrix

| Driver | SHAM manages | Typical use |
|---|---|---|
| `static` | HTTP file serving | HTML/CSS/JS, Vite/Astro/Hugo build output |
| `process` | Local child process + internal port | Node/npm, Bun, Deno, Python, Go, Java, custom server |
| `container` | Docker container + internal/published routing | Existing images, Dockerfile, Buildpacks, Nixpacks |
| `compose` | Constrained Docker Compose project | App + private supporting services |
| `proxy` | Public listener only | Existing upstream app managed outside SHAM |

Legacy `node` records remain compatible and resolve through the generalized process/container runtime implementation.

## Process runtimes

Current presets:

| Preset | Default command |
|---|---|
| Node | `node server.js` |
| npm | `npm run start` |
| Bun | `bun run start` |
| Deno | `deno run --allow-net --allow-env --allow-read server.ts` |
| FastAPI | `uvicorn app:app --host "$HOST" --port "$PORT"` |
| Django | `gunicorn app.wsgi:application --bind "$HOST:$PORT"` |
| Go | `./app` |
| Java | `java -jar app.jar` |
| Custom | operator-supplied command/argv |

These are starting presets, not framework installers. Your release/build stage must provide the executable/dependencies the command needs.

### Environment and internal binding

SHAM allocates an internal application port and supplies:

- `HOST`.
- `PORT`.
- The configured custom port-variable name when one is used.
- Site environment values allowed for the runtime scope.

Server applications should bind the injected host/port. Do not casually bind generated host-process applications to `0.0.0.0`, because that can make the internal backend directly reachable outside SHAM's public listener boundary.

### Custom process commands

Use Custom when a server can run as a normal foreground process. Repository manifests can provide either a command string or a structured argv array. Structured arrays are safer for arguments containing whitespace because SHAM does not need to reconstruct shell quoting.

## Container runtimes

Container mode supports four sources.

### Existing Docker/OCI image

Choose **Docker image**, provide an image reference and the application container port.

SHAM lets Docker pull the image if it is not already present. Existing-image mode preserves the image filesystem and does not overlay uploaded source over the application by default.

Prefer immutable version tags or image digests for reproducible deployment.

### Dockerfile

Choose **Dockerfile** for source that contains its own image definition.

Important rules:

- Dockerfile/build context must remain inside the immutable release.
- Dockerfile paths are validated as safe relative paths.
- The image is built before candidate activation.
- Startup/readiness failure cleans up the candidate container/image resources managed for that attempt.
- If SHAM itself runs in Docker, `SHAM_DOCKER_HOST_DATA_PATH` must map SHAM's internal data path to the corresponding host path so the host daemon can see build context/release files.

A minimal example:

```dockerfile
FROM node:22-alpine
WORKDIR /app
COPY package*.json ./
RUN npm ci --omit=dev
COPY . .
ENV HOST=0.0.0.0
EXPOSE 3000
CMD ["node", "server.js"]
```

The container can listen on `0.0.0.0` **inside the container**; SHAM controls how that port is exposed/routed.

### Cloud Native Buildpacks

Buildpack mode uses the configured `SHAM_PACK_BIN` executable. The default builder can be configured per runtime/spec.

If `pack` is unavailable, SHAM reports the capability as missing; other container modes continue to work.

### Nixpacks

Nixpacks mode uses `SHAM_NIXPACKS_BIN`. It similarly requires the Nixpacks executable on the SHAM host/control-plane image.

## Docker Compose

Compose mode is intended for an application service plus private supporting services. SHAM does **not** treat arbitrary Compose files as unrestricted host administration.

The selected application service is routed through SHAM. Supporting services should stay private on the Compose network.

Example:

```yaml
services:
  app:
    build: .
    environment:
      PORT: 3000
    expose:
      - "3000"
    depends_on:
      - redis

  redis:
    image: redis:7-alpine
    volumes:
      - cache-data:/data

volumes:
  cache-data: {}
```

Configure the SHAM Compose service as `app` and container port `3000`.

### Compose restrictions

SHAM rejects common host/container escape or unmanaged-publication features, including:

- Privileged containers.
- Host networking/PID/IPC namespaces.
- Added Linux capabilities.
- Devices.
- Docker socket mounts.
- Host bind mounts; use named volumes instead.
- Host-gateway mappings.
- Disabled/unsafe security-profile settings covered by policy validation.
- External/unmanaged networks, volumes, configs, or secrets.
- Published host ports on supporting services.

The selected application service may receive the SHAM-managed loopback publication needed for routing when SHAM runs directly on the host. When SHAM itself is containerized, runtime networking uses the configured shared Docker network so the control plane does not incorrectly route to its own container-local `127.0.0.1`.

### No-egress Compose/runtime networks

When a site's outbound-network setting disallows internet access, SHAM can place managed Docker workloads on an internal Docker network. Configure `SHAM_DOCKER_INTERNAL_NETWORK` and the container isolation overlay appropriately.

## Docker-isolated legacy Node

Legacy Node sites can still select Docker isolation. Dependencies are installed inside a runtime-compatible image rather than on the SHAM host and then executed under a different libc/base image. This avoids host-built native addons being reused in an incompatible container environment.

## Readiness, liveness, and shutdown

### Readiness

Readiness determines when a candidate is safe to receive traffic.

Supported types include:

- TCP.
- HTTP.
- Command.
- Disabled/none where allowed.

HTTP readiness supports a path and expected status range. Prefer an endpoint that represents application readiness rather than only process existence.

### Liveness

Liveness supervises an active runtime and can trigger restart policy behavior.

### Startup timeout

A candidate must become ready within the configured startup timeout. Failure leaves/removes the candidate rather than promoting it.

### Graceful shutdown and blue/green drain

On replacement/stop, SHAM gives the backend a configurable shutdown grace period before force termination. During successful release replacement, the old backend can remain alive for a configurable drain period after the traffic switch.

## Candidate-first immutable releases

Git deployments keep release paths immutable. A running application is not started from a directory that will later be renamed underneath it.

Candidate promotion is designed so persistence/protection failure restores the previous runtime target where possible. First-start failure tears down the candidate instead of leaving an untracked backend running.

## Runtime reconciliation

Managed runtime identity is persisted/labelled sufficiently for SHAM to reconcile stale managed processes/containers after control-plane restart. The desired site state and observed backend state are treated separately.

## `sham.yaml`, `sham.yml`, and `sham.json`

Repository manifests can override build/runtime execution policy.

Example:

```yaml
build:
  install: npm ci
  command: npm run build

runtime:
  driver: process
  command: ["npm", "run", "start"]
  workingDirectory: .
  portEnv: PORT

readiness:
  type: http
  path: /health
  statusMin: 200
  statusMax: 399
  timeoutSeconds: 45

shutdown:
  graceSeconds: 10
  drainSeconds: 5
```

The YAML parser intentionally supports a small mapping/scalar subset. Unsupported YAML constructs fail closed. JSON manifests can be used when you need unambiguous structured arrays/objects.

Execution-relevant policy is hashed. A changed/removed manifest policy requires explicit approval before a Git deployment may activate it.

## Runtime Agent architecture

SHAM's web/API/dashboard process (the **control plane**) never touches the Docker socket directly. All Docker/Compose/buildpack/nixpacks execution happens in a separate, privileged **SHAM Runtime Agent** process:

```text
Internet
   |
SHAM Control Plane / Dashboard / API
   |  authenticated, narrowly scoped local RPC (Unix socket)
   v
SHAM Runtime Agent
   |
   v
Docker socket / Docker daemon
```

This exists because the control plane is the internet-facing process (dashboard, deployment webhooks, uploads). If it were compromised while holding `/var/run/docker.sock`, an attacker would have effectively unrestricted host access. Moving that socket to a separate agent process means a control-plane compromise no longer implies direct Docker/root-level host access — the attacker is left with whatever the agent's narrow RPC surface allows (create/stop/remove SHAM-labeled containers, build SHAM-tagged images, and similar scoped operations), not arbitrary Docker or shell commands. Mounting the socket into the agent still grants substantial host authority; the agent is a privileged component and should be operated with the same care Docker socket access has always required.

The agent exposes a small allowlisted set of typed operations (container run/stop/remove/port/logs/exec, image build/remove, network ensure/connect, Compose config/up/ps/port/down/exec, and SHAM-owned resource cleanup) over a local, token-authenticated Unix domain socket — never a generic `docker`/shell passthrough. Requests are authenticated with a randomly generated shared token (`SHAM_RUNTIME_AGENT_TOKEN_PATH`, mode `0600`), and mutating operations require the target container/Compose project to carry SHAM's own `sham.managed=true` (or `com.docker.compose.project=sham-...`) labels — the agent refuses to touch containers it did not create, even if the control plane asks it to.

When the agent is unavailable (not started, wrong token, Docker daemon down), Docker-dependent features fail with a clear "Docker runtime unavailable" message instead of hanging; everything else in SHAM (static sites, process runtimes, Git, TLS, dashboard) keeps working normally. Capability flags (`GET /api/admin/operations` → `capabilities.agentReachable`/`agentAuthenticated`/`dockerAvailable`) report agent reachability, authentication status, and Docker daemon reachability without exposing the token or any host paths.

## Docker-host path mapping

The Runtime Agent — not the control plane — is the process that ever calls `docker run -v ...`, so it is the one that needs a host-visible path for bind mounts (the daemon resolves `-v` sources on the host, regardless of which container's CLI issued the command). When the agent itself runs in a container:

```bash
SHAM_DOCKER_HOST_DATA_PATH=/absolute/host/path/to/sham-data
```

must be set **on the `sham-runtime-agent` service**, so it can translate release/build paths into host-visible paths for Docker mounts. The `sham` control-plane service no longer needs this variable at all.

## Docker isolation overlay

The base `docker-compose.yml` intentionally avoids the Docker socket entirely — that remains true, and now applies permanently to the `sham` service itself, not just to the base compose file. Use the isolation overlay only when you need daemon-managed application features (Docker/Compose runtimes, image builds, Anubis); it now starts a second `sham-runtime-agent` container that owns the socket instead of adding it to `sham`:

```bash
export SHAM_DOCKER_HOST_DATA_PATH="$(pwd)/sham-data"
export DOCKER_GID="$(stat -c '%g' /var/run/docker.sock)"

docker compose -f docker-compose.yml -f docker-compose.isolation.yml up -d --build
```

`sham` and `sham-runtime-agent` communicate over a Unix socket created under the `/data` volume they both already mount — no extra port or network is published for the agent, and it does not join SHAM's public-facing network.

Docker daemon access is effectively host-administration access. Do not treat a single Docker daemon as a hostile multi-tenant sandbox, and run the Runtime Agent only on a host/VM you trust with that authority.

### Migrating an existing installation

If you previously ran the isolation overlay with the Docker socket mounted directly into the `sham` service:

1. Pull/build the updated image (it now includes `runtime-agent/`).
2. Replace your `docker-compose.isolation.yml` with the current version (it now defines `sham-runtime-agent`).
3. Keep `SHAM_DOCKER_HOST_DATA_PATH` and `DOCKER_GID` exported the same way as before — they now apply to the agent service.
4. Run `docker compose -f docker-compose.yml -f docker-compose.isolation.yml up -d --build`. Compose will recreate `sham` without the socket and start `sham-runtime-agent` alongside it.
5. No database, site, or release data changes are required. Running sites will restart their runtime instances once, since the exit-detection process (`docker wait`) is now supplied by the agent instead of the control plane.

## Reliability checklist

- Use HTTP readiness for applications with initialization dependencies.
- Prefer immutable image tags/digests.
- Keep state in managed volumes/external services rather than ephemeral container layers.
- Keep supporting Compose services private.
- Set CPU, memory, PID, connection, startup, and shutdown bounds appropriate to the application.
- Keep Dockerfile/Compose/repository-manifest changes in code review.
- Test rollback before relying on it during an incident.
- Monitor disk usage for images/releases/backups even though SHAM cleans up candidate resources it creates for failed attempts.
