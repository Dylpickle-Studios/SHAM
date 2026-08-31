<p align="center">
  <img src="public/logo.svg" width="96" height="96" alt="SHAM logo">
</p>

<h1 align="center">SHAM — Simple Hosting And More</h1>

<p align="center"><strong>A self-hosted deployment, runtime, and operations control plane for websites and application servers.</strong></p>
<p align="center"><strong>Current release: 1.2.0</strong> · <strong>AGPL-3.0-or-later</strong></p>

SHAM provides one browser dashboard for deploying applications, routing traffic, managing releases, operating runtimes, inspecting performance, and handling common infrastructure tasks on servers you control.

It can serve static projects directly, supervise arbitrary server processes, run OCI/Docker images, build Dockerfiles, operate constrained Docker Compose applications, and reverse-proxy services that already exist elsewhere.

> [!IMPORTANT]
> SHAM is an infrastructure control plane. Process runtimes, Docker access, Compose projects, deployment commands, and server-side plugins can execute trusted code on your host. Use a dedicated host/VM where appropriate, run SHAM with minimal OS privileges, protect the Docker socket, and review code before deploying it.

> [!NOTE]
> **Architecture:** the internet-facing SHAM control plane never holds the Docker socket. All Docker/Compose/build execution is delegated over an authenticated local Unix socket to a separate **SHAM Runtime Agent** process, which is the only component with `/var/run/docker.sock` access. See [Runtime Agent architecture](docs/runtimes-and-docker.md#runtime-agent-architecture).

## Highlights

| Area | Current capabilities |
|---|---|
| **Sources** | Folder/ZIP upload, Git repository, existing Docker/OCI image, reverse proxy |
| **Runtime drivers** | Static, managed process, container, Docker Compose, proxy |
| **Process presets** | Node.js, npm start, Bun, Deno, FastAPI/Uvicorn, Django/Gunicorn, Go, Java JAR, custom command |
| **Container sources** | Existing image, Dockerfile, Cloud Native Buildpacks, Nixpacks |
| **Git providers** | GitHub, GitLab, Bitbucket Cloud, Gitea, Forgejo, plus direct HTTPS/SSH Git URLs |
| **Deployments** | Immutable releases, previews, readiness-first candidate activation, rollback, build/install commands, `sham.yaml` policy approval |
| **Routing** | Per-site listeners, private Node/process listeners for VPN-only services, shared 80/443 edge routing, reverse proxying, domains, WebSockets, redirects, headers, SPA fallback |
| **Security** | Local firewall policy, CSP/security presets, TOTP, recovery codes, WebAuthn, OIDC SSO, encrypted secrets, scoped API tokens |
| **Observability** | Runtime logs, traffic analytics, country/automated-client intelligence, health checks, CPU/memory/request/error/latency metrics, p50/p95 history, alert rules |
| **Operations** | Environment variables, database profiles, jobs, snapshots, dependency scans, backups/restore, Cloudflare, Certbot, tunnels, signed updates |
| **Extensibility** | Signed/permissioned plugins, optional worker isolation, browser plugin API, administrator plugin playground |
| **Automation** | HTTP API, scoped bearer tokens, bundled `sham` CLI, signed deployment webhooks |

## Documentation

The root README is intentionally an overview. The detailed manual is split by task:

- **[Documentation index](docs/README.md)** — choose a guide by what you are trying to do.
- **[Getting started](docs/getting-started.md)** — install SHAM, create the first administrator, and deploy a first site.
- **[Dashboard and UI](docs/dashboard-and-ui.md)** — navigation, dashboard drilldowns, Performance, command palette, settings layout, themes, and notifications.
- **[Runtimes and Docker](docs/runtimes-and-docker.md)** — process/container/Compose drivers, existing images, Dockerfiles, Buildpacks, Nixpacks, health probes, and runtime security.
- **[Git and CI/CD](docs/git-and-cicd.md)** — GitHub/GitLab/Bitbucket/Gitea/Forgejo, private repositories, webhooks, previews, releases, and manifest approval.
- **[API and CLI](docs/api-and-cli.md)** — tokens, CLI usage, CI examples, error handling, and compatibility guidance.
- **[API reference](docs/api-reference.md)** — endpoint inventory and `/api/v1` OpenAPI contract.
- **[Operations and security](docs/operations-and-security.md)** — environment values, backups/restore, monitoring, Cloudflare, Certbot, OIDC, recovery, and trust boundaries.
- **[Cloudflare Tunnels](docs/cloudflare-tunnels.md)** — per-site connector setup, public-hostname routing, Docker origin targets, connector states, and troubleshooting.
- **[Configuration reference](docs/configuration-reference.md)** — `.env` options and external executable/network requirements.
- **[Plugin development](docs/plugin-development.md)** — manifests, permissions, browser/server extensions, signing, and the plugin playground.
- **[Troubleshooting](docs/troubleshooting.md)** — uploads, runtimes, Docker/Compose, Git/webhooks, CI secret checks, UI layering, and restore failures.
- **[Roadmap](next-additions.md)** — completed platform milestones and the highest-value remaining work.

The dashboard includes a shorter categorized copy of the most common documentation. Press **Ctrl/Cmd+K** to search documentation, settings, websites, performance destinations, logs, and common actions.

For a site published through the shared edge proxy, the site listener port is
optional: SHAM will allocate a private internal port while the domain remains
available through the shared 80/443 edge. Host-based Node/npm sites also offer
**Fresh npm install**, which snapshots the site, removes `node_modules`, and
installs production dependencies from the lockfile before restarting it.

## Quick start

> [!TIP]
> **Docker Compose is the recommended way to run SHAM.** SHAM itself runs in a container; an optional Compose overlay lets that container manage Docker workloads on the host when you need container/Compose features.

### 1. Start the base control plane

Requirements: Docker Engine and Docker Compose v2.

```bash
mkdir -p sham-data
docker compose pull
docker compose up -d
```

Open `http://127.0.0.1:8080` (or port `8080` on the server running SHAM). The first account becomes the administrator.

The default stack persists `/data` to `./sham-data` and publishes the dashboard/API on `8080`, shared HTTP/HTTPS edge listeners on `80`/`443`, and host mappings for the per-site listener range `4100-4199`.

The base Compose file intentionally **does not mount the Docker socket**.

### 2. Enable Docker-managed workloads only when needed

Existing OCI images, Dockerfile builds, Docker Compose projects, Docker-isolated runtimes, and Anubis require access to the host Docker daemon. The overlay below starts a second, separate **`sham-runtime-agent`** container that owns that access — the main `sham` container never mounts the Docker socket, in this mode or any other:

```bash
export SHAM_DOCKER_HOST_DATA_PATH="$(pwd)/sham-data"
export DOCKER_GID="$(stat -c '%g' /var/run/docker.sock)"

docker compose \
  -f docker-compose.yml \
  -f docker-compose.isolation.yml \
  pull
docker compose \
  -f docker-compose.yml \
  -f docker-compose.isolation.yml \
  up -d
```

This is **not Docker-in-Docker**: the Docker CLI inside the `sham-runtime-agent` container talks to the host daemon through `/var/run/docker.sock`. That socket grants substantial authority over the host, so enable the overlay only where that trust boundary is acceptable. `sham` reaches `sham-runtime-agent` only over a local, authenticated Unix socket inside the shared `/data` volume — the agent publishes no port and joins no public network.

`SHAM_DOCKER_HOST_DATA_PATH` is required because the host daemon must receive host-visible paths for build contexts and mounts; it cannot directly see SHAM's container-internal `/data/...` paths.

### 3. Harden before public exposure

Persist and back up `./sham-data`, put the administrative dashboard behind HTTPS/restricted ingress, configure proxy trust narrowly, publish only needed ports, and use externally managed secrets where appropriate.

For the complete walkthrough—including Docker architecture, first deployment, readiness, and the direct-Node alternative—read **[Getting started](docs/getting-started.md)**.

### Direct Node installation

Running directly from source is supported for development/manual installations:

```bash
cp .env.example .env
npm ci
npm start
```

When a reverse proxy publishes SHAM at a different browser-facing host or scheme, set `SHAM_PUBLIC_ORIGIN` to that exact origin (for example `https://sham.example.com`). SHAM uses it for WebAuthn, OIDC callbacks, secure-cookie decisions, and CSRF origin validation.

For direct LAN access with a browser secure context (including passkeys), set `SHAM_HOST=0.0.0.0` and `SHAM_SELF_SIGNED_HTTPS=true`. SHAM uses OpenSSL to generate `data/dashboard-tls/cert.pem` and serves the dashboard at `https://<LAN-IP>:8080`. Trust that certificate on each client device before signing in; clicking through an untrusted-certificate warning is not a reliable WebAuthn setup. `SHAM_OPENSSL_BIN` can point to a non-default OpenSSL executable.

This is no longer the recommended first-run path. Host installations must provide any optional executables used by enabled features, such as Docker, Git, Certbot, `pack`, `nixpacks`, Restic, AWS CLI, or SFTP. OpenSSL is also required when `SHAM_SELF_SIGNED_HTTPS=true`.

For Docker-managed sites in a direct source installation, start the privileged
Runtime Agent separately and give Docker-socket access only to that process.
It must share `SHAM_DATA_PATH` with the control plane so they share the local
agent socket and token:

```bash
SHAM_DATA_PATH=./data npm run runtime-agent
# In another terminal, with the same SHAM_DATA_PATH:
SHAM_DATA_PATH=./data npm start
```

## Create a site

The site wizard supports four primary source paths:

1. **Upload** — a ZIP archive or browser-selected folder.
2. **Git repository** — a connected provider or direct Git URL.
3. **Docker image** — an existing OCI image whose filesystem is preserved as the application source.
4. **Reverse proxy** — an application already running on another host/port.

Git and uploaded source can then use static, process, container, or Compose runtime drivers as appropriate.

### Example: managed Node process

Your application should use the host/port SHAM provides instead of hard-coding a public listener:

```js
const express = require('express');
const app = express();

app.get('/health', (_req, res) => res.sendStatus(204));
app.get('/', (_req, res) => res.send('Hello from SHAM'));

app.listen(Number(process.env.PORT), process.env.HOST || '127.0.0.1');
```

Configure an HTTP readiness probe such as `/health`. SHAM starts a candidate backend, waits for readiness, switches traffic, drains the old backend, and then completes activation.

### Example: public app plus VPN-only admin listener

A Node.js or managed-process site can expose a small number of additional **private HTTP listeners**. This is useful when one process serves a public application and an administration endpoint that must stay reachable only over a VPN or host-local network. Configure the extra listeners in **Site settings → Advanced → Private process listeners**:

```json
[
  { "name": "admin", "port": 4101, "bindHost": "10.8.0.1", "portEnv": "ADMIN_PORT" }
]
```

SHAM injects `ADMIN_PORT` with an internal port for the application and proxies `10.8.0.1:4101` to it; the normal `PORT` listener remains the site's public listener. Extra listeners may bind only to loopback, RFC1918/CGNAT IPv4, or ULA IPv6 addresses. They are deliberately not routed through the shared edge or Cloudflare Tunnel, and SHAM rejects using one as a Tunnel origin. Restrict the listener with your VPN and host firewall—SHAM does not provide VPN authentication—and use HTTPS or an encrypted VPN where the private network is not already trusted. SHAM does not auto-detect application ports: declare each private listener explicitly so it can validate readiness and keep exposure predictable. Docker and Compose sites do not support this feature.

### Example: repository manifest

A repository can carry its build/runtime policy in `sham.yaml`, `sham.yml`, or `sham.json`:

```yaml
build:
  command: npm ci && npm run build

runtime:
  driver: process
  command: ["npm", "run", "start"]
  portEnv: PORT

health:
  type: http
  path: /health
  startupTimeout: 45
```

Execution-relevant manifest changes are hashed. Git deployments require explicit approval when that policy changes.

## Docker deployment details

Docker Compose is the recommended deployment path shown above and in [Getting started](docs/getting-started.md). If you need to run the same image without Compose, the equivalent base setup is:

```bash
mkdir -p sham-data
docker pull ghcr.io/dylpickle-studios/sham:latest

docker run -d \
  --name sham \
  --restart unless-stopped \
  -p 8080:8080 \
  -p 80:80 \
  -p 443:443 \
  -p 4100-4199:4100-4199 \
  -v "$PWD/sham-data:/data" \
  -e SHAM_HOST=0.0.0.0 \
  -e SHAM_DATA_PATH=/data \
  -e SHAM_EDGE_HOST=0.0.0.0 \
  -e SHAM_EDGE_HTTP_PORT=80 \
  -e SHAM_EDGE_HTTPS_PORT=443 \
  ghcr.io/dylpickle-studios/sham:latest
```

If `SHAM_JWT_SECRET` is not supplied, SHAM generates signing material beneath the persistent data path. Production operators may instead inject their own long random secret through their deployment/secret-management system.

The manual command above does **not** mount the Docker socket. For Docker image, Dockerfile, Compose, Docker-isolated runtime, or Anubis features, use the documented `docker-compose.isolation.yml` flow rather than casually adding the socket to an ad-hoc command.

See **[Getting started](docs/getting-started.md)** for the two Docker modes and **[Runtimes and Docker](docs/runtimes-and-docker.md)** for runtime details and restrictions.

## Git and CI/CD

Connected providers:

- GitHub
- GitLab
- Bitbucket Cloud
- Gitea
- Forgejo

Gitea and Forgejo support custom self-hosted base URLs. Direct HTTPS/SSH Git URLs remain available without provider discovery.

Git deployments support:

- Shallow branch clone.
- Private provider credentials or SSH deploy keys.
- Configurable install/build steps.
- Repository manifests.
- Deployment-specific logs/history.
- Signed/provider-verified push webhooks with replay protection.
- Temporary previews using the same runtime specification as production.
- Immutable retained releases and rollback.

CI can use scoped API tokens instead of browser credentials:

```bash
export SHAM_URL="https://sham.example.com"
export SHAM_TOKEN="sham_pat_..."

sham deploy 12 --branch main
```

See **[Git and CI/CD](docs/git-and-cicd.md)** and **[API and CLI](docs/api-and-cli.md)**.

## Dashboard and administration

The main navigation includes:

- **Dashboard** — request/visitor overview plus four clickable attention views for unhealthy sites, failed deployments, active alerts, and automated traffic.
- **Sites** — application inventory and per-site workspace.
- **Observability** — runtime/audit activity and logs.
- **Performance** — live host/site metrics, history, and alert rules.
- **Security** — TOTP, recovery codes, passkeys, and API tokens.
- **Extensions** — installed plugins and the administrator plugin playground.
- **Settings** — personal Appearance for every user, plus administrator-only Delivery, Configuration, Automation, Instance, and Administration categories.

**Administration** contains account creation/session controls, OIDC, Cloudflare, Certbot, and persistent instance policy. Public signup is available only for the first bootstrap administrator; later accounts are created by an administrator. Appearance is independent of the color palette: choose **System / Light / Dark**, then choose Purple, Midnight, Emerald, or a Custom palette.

## API and CLI

The versioned JSON API lives under `/api/v1`. Existing `/api` routes remain
compatibility aliases. Automation should use a scoped bearer token created
under **Security → API Tokens**; see [API compatibility](docs/api-compatibility.md).

Common endpoints include:

```text
GET  /api/sites
GET  /api/performance
POST /api/sites/:id/start
POST /api/sites/:id/stop
POST /api/sites/:id/restart
POST /api/sites/:id/deploy/git
POST /api/sites/:id/releases/:releaseId/rollback
GET  /api/runtime-logs
```

Bundled CLI commands:

```bash
sham sites
sham deploy <site-id> [--branch main] [--approve-manifest]
sham logs <site-id> [--limit 200]
sham start <site-id>
sham stop <site-id>
sham restart <site-id>
sham rollback <site-id> <release-id>
```

See **[API and CLI](docs/api-and-cli.md)** for usage and **[API reference](docs/api-reference.md)** for the broader endpoint inventory.

## Backups and recovery

SHAM supports local/off-host backup providers and a staged restore workflow. Restore validates the complete archive structure, rejects unsafe paths/entry types, extracts into an isolated staging directory, runs SQLite `PRAGMA quick_check`, verifies core tables, and only then swaps the live data directory with rollback protection.

Snapshots are useful per-site restore points; they are not a replacement for full instance backups.

## Plugins and plugin playground

Plugins can provide declarative dashboard features or JavaScript-backed actions, subject to manifest validation, permissions, action timeouts, signing policy, and optional worker isolation.

Administrators can open **Extensions → Plugin playground** to:

- Validate `plugin.json` with SHAM's real manifest validator.
- Edit an optional `client.js`.
- Preview browser UI code inside a sandboxed, network-blocked iframe.
- Inspect the normalized manifest.

The playground intentionally does **not** execute server plugin code.

See **[Plugin development](docs/plugin-development.md)**.

## Security and integration reference notes

A few deployment-sensitive details are intentionally kept visible in the root README because they affect secure installation and CI expectations:

- Enabled SHAM-managed site or instance/shared Cloudflare Tunnel origins on loopback automatically preserve `CF-Connecting-IP`/country through the shared edge proxy. Use `SHAM_TRUSTED_EDGE_PROXIES` only for separately operated reverse-proxy peers, and keep it narrower than an entire private network.
- Managed Docker networking uses `SHAM_DOCKER_INTERNAL_NETWORK` for no-egress workloads and `SHAM_DOCKER_EGRESS_NETWORK` for workloads allowed outbound access.
- Docker/Compose/build execution goes through the Runtime Agent, authenticated with `SHAM_RUNTIME_AGENT_TOKEN_PATH` over `SHAM_RUNTIME_AGENT_SOCKET`; only the agent process ever needs `/var/run/docker.sock`.
- Deployment-webhook authentication recognizes provider signatures/tokens plus SHAM's own HMAC header. GitHub-style HMAC uses `X-Hub-Signature-256`; SHAM-native HMAC uses `X-SHAM-Signature`. See [Git and CI/CD](docs/git-and-cicd.md) for provider-specific behavior.
- The release currently pins `jsonwebtoken` 9.0.3, Multer 2.2.0, and the committed lockfile; the Docker build runs `npm audit --omit=dev --audit-level=high`. Dependency versions remain source-controlled release policy and should be reviewed whenever the lockfile changes.

For the full environment table, see [Configuration reference](docs/configuration-reference.md).

## Persistent data and release hygiene

`SHAM_DATA_PATH` contains private mutable instance data such as:

- SQLite state.
- Generated JWT/master-key material when not supplied externally.
- Site content and immutable releases.
- Plugins.
- Certificates.
- Backups and update state.
- Runtime metadata.

Do not commit it.

Before distributing source or creating a release archive:

```bash
npm run release:check
git status --short
```

`release:check` runs the recursive syntax check, the test suite, and source-tree hygiene checks such as generated-secret detection. A generated `data/.jwt-secret` is instance state and must never be shipped in source.

## Development

```bash
npm ci
npm run check       # syntax + ESLint + tsc --noEmit (JSDoc type checking)
npm test
npm run release:check
npm run dev
```

`npm run check` runs `check:syntax`, `lint`, and `typecheck` together. SHAM stays a plain JavaScript/CommonJS project — TypeScript is used only as a static analyzer over JSDoc comments (`allowJs`/`checkJs`/`noEmit`), never as a compiler. See [Development workflow](docs/development.md) for details, including which files are still being brought under type checking.

`npm run dev` uses Node's watch mode. See [CONTRIBUTING.md](CONTRIBUTING.md), [SECURITY.md](SECURITY.md), and [RELEASING.md](RELEASING.md) before submitting or publishing changes.

For the real deployment, Docker Compose, and Chromium browser suites, see [Integration and browser testing](docs/integration-testing.md). They are separate from `npm test` so ordinary local unit-test runs remain fast.

## Project structure

```text
bin/                 bundled CLI
public/              dashboard HTML/CSS/browser JavaScript
src/                 server, routes, runtime engine, operations, integrations
src/routes/          site/admin/operations HTTP routes
src/sites/           site serving and runtime implementations
docs/                task-oriented manual and API/configuration reference
scripts/             syntax/release validation
test/                regression/security/runtime/UI source tests
```

## License

SHAM is licensed under the **GNU Affero General Public License v3.0 or later**. See [LICENSE](LICENSE).
