# SHAM documentation

This manual documents the current SHAM feature set. The root [README](../README.md) identifies the current release; use these guides for operating and automating the application.

## Choose a guide by task

### Install or deploy something

- [Getting started](getting-started.md) — recommended Docker Compose install, optional Docker-daemon access, first administrator, persistent data, and the first deployment.
- [Runtimes and Docker](runtimes-and-docker.md) — static/process/container/Compose/proxy runtimes, Docker images, Dockerfiles, Buildpacks, Nixpacks, ports, probes, and runtime security.
- [Git and CI/CD](git-and-cicd.md) — GitHub, GitLab, Bitbucket Cloud, Gitea, Forgejo, direct Git URLs, webhooks, releases, previews, and `sham.yaml` approval.

### Use the dashboard

- [Dashboard and UI](dashboard-and-ui.md) — navigation, quick-view drilldowns, site workspaces, Performance, command palette, Settings organization, themes, modals, tooltips, and notifications.
- [Operations and security](operations-and-security.md) — environment variables, database profiles, jobs, backups/restore, monitoring, Cloudflare, Certbot, OIDC, local authentication, API tokens, and trust boundaries.
- [Cloudflare Tunnels](cloudflare-tunnels.md) — per-site `cloudflared` connectors, Zero Trust public-hostname routing, Docker/service targets, security, and troubleshooting.
- [Troubleshooting](troubleshooting.md) — common upload, runtime, Docker, Compose, Git, restore, UI, CLI, and release failures.

### Automate or integrate SHAM

- [API and CLI](api-and-cli.md) — token authentication, scopes, CLI commands, CI examples, errors, timeouts, and compatibility policy.
- [API reference](api-reference.md) — endpoint inventory and the versioned `/api/v1` contract.
- [API compatibility](api-compatibility.md) — `/api/v1` compatibility and legacy-alias policy.
- [Configuration reference](configuration-reference.md) — `.env` variables, optional executables, Docker networks, persistent paths, and production configuration notes.
- [Integration and browser testing](integration-testing.md) — isolated deployment lifecycle, Docker Compose, and Chromium CI suites.

### Extend SHAM

- [Plugin development](plugin-development.md) — plugin manifests, browser/server behavior, permissions, signing, packaging, worker isolation, and the built-in plugin playground.
- [Roadmap](../next-additions.md) — what has already landed and the remaining platform priorities.

## Feature map

| Feature | Primary guide |
|---|---|
| Upload ZIP/folder | [Getting started](getting-started.md) |
| Existing Docker image | [Runtimes and Docker](runtimes-and-docker.md) |
| Dockerfile | [Runtimes and Docker](runtimes-and-docker.md) |
| Docker Compose | [Runtimes and Docker](runtimes-and-docker.md) |
| Bun/Deno/Python/Go/Java/custom process | [Runtimes and Docker](runtimes-and-docker.md) |
| GitHub/GitLab/Bitbucket/Gitea/Forgejo | [Git and CI/CD](git-and-cicd.md) |
| `sham.yaml` | [Git and CI/CD](git-and-cicd.md) |
| CI/CD API token | [API and CLI](api-and-cli.md) |
| Endpoint lookup | [API reference](api-reference.md) |
| Dashboard quick views | [Dashboard and UI](dashboard-and-ui.md) |
| Performance metrics/alerts | [Dashboard and UI](dashboard-and-ui.md) and [Operations and security](operations-and-security.md) |
| Environment variables/secrets | [Operations and security](operations-and-security.md) |
| Backup restore | [Operations and security](operations-and-security.md) |
| Cloudflare Tunnel | [Cloudflare Tunnels](cloudflare-tunnels.md) |
| Cloudflare DNS/WAF, Certbot, OIDC | [Operations and security](operations-and-security.md) |
| Theme customization | [Dashboard and UI](dashboard-and-ui.md) |
| Plugin playground | [Plugin development](plugin-development.md) |
| Environment configuration | [Configuration reference](configuration-reference.md) |

## Documentation inside the dashboard

The **Documentation** view contains concise operational versions of these topics. The repository manual is more detailed and should be treated as the source for configuration/API reference material.

Press **Ctrl/Cmd+K** in the dashboard to search documentation categories, settings, sites, site files/logs/settings, Performance, and common runtime/deployment actions.

## API versioning

Use `/api/v1` for new automation. Existing `/api` routes remain compatibility
aliases; the exact stability policy is in [API compatibility](api-compatibility.md).

## Security language used in these docs

- **Public** means no SHAM session/token is required by the application route. Network/reverse-proxy controls can still restrict access.
- **Authenticated** means a valid browser session or accepted API-token context is required.
- **Administrator** means the route/action additionally requires the SHAM administrator role.
- **Trusted code** means code that can execute with some portion of the SHAM host/container authority and should not be treated as a hostile-code sandbox.
