# Getting started

This guide gets a new SHAM instance running and deploys a first site.

> [!TIP]
> **Use Docker Compose unless you specifically want to run SHAM directly from source.**
> The repository ships a production Dockerfile and Compose configuration, and the stock SHAM image includes the common infrastructure tools used by SHAM and its optional Runtime Agent.

## What is running where?

SHAM is a control plane. The recommended setup runs **SHAM itself inside a Docker container**:

```text
Docker host
└── SHAM container
    ├── dashboard/API        :8080
    ├── shared HTTP edge     :80
    ├── shared HTTPS edge    :443
    └── persistent state     /data
         ↕
       ./sham-data on the host
```

There are two Docker modes:

| Mode | Use it when | Docker socket? |
|---|---|---|
| **Base Compose** | You want to run SHAM and use features that do not require Docker-managed workloads. | Not mounted |
| **Compose + isolation overlay** | You need Docker images, Dockerfile builds, Compose apps, Docker-isolated runtimes, or Anubis. | Runtime Agent only |

The second mode is **not Docker-in-Docker**. It adds a separate
`sham-runtime-agent` container: the internet-facing `sham` control plane never
gets the Docker socket. The Runtime Agent's Docker CLI talks to the **host
Docker daemon** through `/var/run/docker.sock` over a narrow, authenticated
Unix-socket RPC boundary.

> [!IMPORTANT]
> Mounting the Docker socket gives the Runtime Agent substantial control over
> the Docker host. Enable the overlay only when you need Docker-managed
> workloads and only on infrastructure where that trust boundary is acceptable.

## 1. Requirements

For the recommended installation:

- Docker Engine.
- Docker Compose v2 (`docker compose`).
- Git, if you are cloning the SHAM repository instead of using an already-downloaded source tree.

For the optional Docker-management mode, the host must also expose a usable Docker socket at `/var/run/docker.sock`.

The stock image includes Node.js, Git, the Docker CLI (used by the Runtime
Agent), Certbot, Cloudflared, Restic, AWS CLI, and OpenSSH tooling. **Cloud
Native Buildpacks (`pack`) and Nixpacks are not bundled**; if you want those
build modes, extend the Runtime Agent image or otherwise make the configured
executable available to that process.

If you run SHAM directly from source instead, you need Node.js 22 or newer, npm, and a platform supported by `better-sqlite3`. OpenSSL is additionally required if you enable SHAM's local self-signed HTTPS option.

## 2. Start SHAM with Docker Compose

From the repository root:

```bash
mkdir -p sham-data
docker compose pull
docker compose up -d
```

This uses `docker-compose.yml`, pulls `ghcr.io/dylpickle-studios/sham:latest`, starts the control plane, and persists mutable instance state in `./sham-data`.

Check that it started:

```bash
docker compose ps
docker compose logs -f sham
```

Then open:

```text
http://127.0.0.1:8080
```

If SHAM is running on another server, replace `127.0.0.1` with that server's address.

The first successfully created account becomes the administrator. SHAM then locks ordinary public registration unless an administrator explicitly changes the registration policy.

### What the base Compose file exposes

The supplied Compose file publishes:

- `8080` — SHAM dashboard/API.
- `80` — shared HTTP edge listener.
- `443` — shared HTTPS edge listener.
- `4100-4199` — host port mappings reserved for per-site listeners; whether a site is reachable directly on one of these ports depends on its bind/routing configuration.

It mounts:

```text
./sham-data  →  /data
```

The base Compose file deliberately **does not** mount `/var/run/docker.sock`.

> [!NOTE]
> The container runs as a non-root user. If a Linux host reports permission errors for `/data`, make sure `./sham-data` is writable by the container user. Avoid solving this by making the directory world-writable.

## 3. Enable Docker-managed application workloads

Skip this section if you do not need SHAM to launch containers or Compose projects.

When SHAM itself runs in Docker, the host Docker daemon cannot see paths such as `/data/sites/...` inside the SHAM container. SHAM therefore needs the **host-side path** that corresponds to `/data`.

Set the host data path and Docker socket group. On a typical Linux Docker host:

```bash
export SHAM_DOCKER_HOST_DATA_PATH="$(pwd)/sham-data"
export DOCKER_GID="$(stat -c '%g' /var/run/docker.sock)"
```

If your platform uses a different `stat` syntax, set `DOCKER_GID` to the group ID that owns the Docker socket.

Then start SHAM with both Compose files:

```bash
docker compose \
  -f docker-compose.yml \
  -f docker-compose.isolation.yml \
  pull
docker compose \
  -f docker-compose.yml \
  -f docker-compose.isolation.yml \
  up -d
```

The resulting layout is:

```text
Docker host
├── sham control-plane container
│   └── /data → ./sham-data
│        │ authenticated local Unix socket
│        ▼
├── sham-runtime-agent container
│   ├── /data → ./sham-data
│   └── /var/run/docker.sock ─────────┐
│                                     │
│              Docker CLI inside Runtime Agent
│                                     │
└── host Docker daemon ◀──────────────┘
    ├── managed app container A
    ├── managed app container B
    └── managed Compose project
```

`SHAM_DOCKER_HOST_DATA_PATH` must be an **absolute host path**. It is set on
the Runtime Agent and lets it translate a container-internal path such as:

```text
/data/sites/12/releases/abc123
```

into the host-visible equivalent, for example:

```text
/srv/sham/sham-data/sites/12/releases/abc123
```

That translation is required when the host daemon needs a build context or bind mount.

See [Runtimes and Docker](runtimes-and-docker.md) for container restrictions, networks, image modes, Dockerfile builds, Buildpacks, Nixpacks, and Compose behavior.

## 4. Production basics before exposing the dashboard

Before making the instance public:

1. Put the dashboard behind HTTPS or otherwise restrict administrative ingress.
2. Keep `./sham-data` persistent and back it up independently.
3. Supply a strong `SHAM_JWT_SECRET` through your secret-management/deployment mechanism if you do not want SHAM to persist a generated signing secret under the data path.
4. Configure `SHAM_TRUST_PROXY` and trusted edge proxies narrowly.
5. Publish only the ports you actually need.
6. Mount the Docker socket into `sham-runtime-agent` only if Docker-managed application features are required.
7. Treat anyone who can deploy trusted runtime/build/plugin code as having meaningful authority over the host.

See [Operations and security](operations-and-security.md) and [Configuration reference](configuration-reference.md) before exposing a production instance.

## 5. Understand persistent data

`SHAM_DATA_PATH` contains private mutable instance state, including:

- SQLite state.
- Site content.
- Immutable releases/previews.
- Generated JWT/master-key material when not supplied externally.
- Plugin packages/settings.
- Certificates.
- Backups and update state.
- Runtime metadata.

In the supplied Docker Compose setup, `SHAM_DATA_PATH` is `/data`, backed by `./sham-data` on the host.

Do not commit this directory. A generated `.jwt-secret` under the data path is instance state, not source code.

## 6. Create your first site

Open **Sites** in the dashboard and create a site. The wizard offers four primary source choices.

### Upload

Upload a normal ZIP or select a folder from the browser. Use this for static sites or source trees you want SHAM to run directly.

SHAM strips one common enclosing directory. For example, a selected folder containing `my-site/index.html` is installed with `index.html` at the site root.

### Git repository

Choose a connected Git provider or paste a direct HTTPS/SSH Git URL. Supported connected providers are GitHub, GitLab, Bitbucket Cloud, Gitea, and Forgejo.

Git sites support install/build commands, immutable releases, previews, webhooks, and repository manifests. See [Git and CI/CD](git-and-cicd.md).

### Docker image

Supply an existing OCI image and the container port the application listens on.

This requires Docker daemon access when SHAM itself is containerized, so start SHAM with the isolation overlay described above.

### Reverse proxy

Use this when the application lifecycle is managed outside SHAM. Configure the upstream host/port and let SHAM provide the public listener/domain/policy layer.

## 7. Choose a runtime

SHAM has five runtime drivers:

- **Static** — serve files directly.
- **Process** — execute a managed process in the SHAM runtime environment.
- **Container** — run an OCI container from an existing image or source-to-image build.
- **Compose** — run a constrained Docker Compose application.
- **Proxy** — route to an external upstream.

Process presets currently include Node, npm, Bun, Deno, FastAPI, Django, Go, Java, and Custom. The required executable/runtime must exist in the environment where that process driver executes.

Container presets include Existing image, Dockerfile, Buildpacks, and Nixpacks. Container and Compose modes require Docker daemon access.

## 8. Make server applications listen correctly

Managed application servers should use the host/port values SHAM injects rather than hard-coding a public listener.

Example Node/Express:

```js
const express = require('express');
const app = express();

app.get('/health', (_req, res) => res.sendStatus(204));
app.get('/', (_req, res) => res.send('Hello from SHAM'));

app.listen(Number(process.env.PORT), process.env.HOST || '127.0.0.1');
```

For framework-specific presets, use the generated/default command as a starting point and adjust module names and paths for your application.

## 9. Configure readiness

A process opening a socket does not always mean the application is ready to serve production traffic.

Prefer an HTTP readiness endpoint that confirms critical initialization is complete. SHAM supports TCP, HTTP, command, and disabled readiness types where appropriate.

A release deployment generally follows this flow:

1. Clone/build into staging.
2. Read and validate repository policy.
3. Move the candidate to its immutable release path.
4. Start the candidate runtime.
5. Wait for readiness.
6. Switch traffic to the candidate.
7. Drain the previous backend.
8. Stop the previous backend.
9. Persist active-release metadata.

A candidate that fails before traffic switching does not replace the existing backend.

## 10. Useful Docker commands

Update and start SHAM:

```bash
docker compose pull
docker compose up -d
```

View status:

```bash
docker compose ps
```

Follow logs:

```bash
docker compose logs -f sham
```

Restart the control plane:

```bash
docker compose restart sham
```

Stop the stack without deleting `./sham-data`:

```bash
docker compose down
```

If you use the isolation overlay, include both `-f` arguments in later `docker compose` commands as well so Compose evaluates the same project definition.

## Run SHAM directly from source instead

Direct Node execution is supported, but it is best treated as the development/manual-install path rather than the default getting-started path.

```bash
cp .env.example .env
npm ci
npm start
```

The default source configuration listens on `127.0.0.1:8080` and stores mutable state under `./data` unless you change the environment.

For Docker-managed sites, run the Runtime Agent separately with the same data
path; the control plane itself must not receive Docker-socket access:

```bash
SHAM_DATA_PATH=./data npm run runtime-agent
# In another terminal:
SHAM_DATA_PATH=./data npm start
```

The account that starts `runtime-agent` needs permission to access the host
Docker daemon. Do not expose its Unix socket or token over the network.

To open a direct host install from another device on your LAN while retaining a secure browser context, set these values in `.env`:

```dotenv
SHAM_HOST=0.0.0.0
SHAM_SELF_SIGNED_HTTPS=true
```

SHAM generates `data/dashboard-tls/key.pem` and `data/dashboard-tls/cert.pem`, including the host's detected LAN addresses in the certificate SANs, then serves `https://<LAN-IP>:8080`. Import/trust `cert.pem` on each client device before using the dashboard. This is especially important for WebAuthn/passkeys, which require a secure context outside localhost. Set `SHAM_OPENSSL_BIN` if `openssl` is not on the normal executable path.

When running directly on the host, optional features depend on the corresponding host executables being installed: Docker, Git, Certbot, `pack`, `nixpacks`, Restic, AWS CLI, SFTP, and so on. OpenSSL is required when the self-signed HTTPS option is enabled.

Before distributing source, run:

```bash
npm run release:check
```

## Next steps

- Read [Runtimes and Docker](runtimes-and-docker.md) before enabling Docker-managed sites.
- Add an HTTP readiness/liveness probe to server applications.
- Connect a Git provider and configure verified deployment webhooks.
- Configure environment variables and secrets.
- Configure backups and test a restore.
- Enable OIDC, passkeys, or TOTP according to your identity model.
- Configure Cloudflare/Certbot if needed, or follow [Cloudflare Tunnels](cloudflare-tunnels.md) for outbound-only per-site ingress.
- Create a scoped API token for CI/CD.

## Updating SHAM

The in-app update workflow is for reviewed SHAM update archives and persists application releases beneath `SHAM_DATA_PATH`. Updates that change runtime dependencies require a reviewed image/manual upgrade rather than silently installing new server dependencies.

The managed update payload includes the application source, dashboard assets, `docs/`, and the bundled CLI so documentation and automation tooling stay aligned with the active release.
