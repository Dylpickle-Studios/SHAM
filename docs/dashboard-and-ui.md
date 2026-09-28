# Dashboard and UI

This guide describes where the major SHAM features live and how the dashboard behaves after the platform/runtime expansion.

## Main navigation

The left navigation contains:

- **Dashboard** — traffic overview, request/visitor summaries, sites, and attention drilldowns.
- **Sites** — all configured websites/applications and their workspaces.
- **Observability** — runtime events, logs, and audit-oriented activity.
- **Performance** — live host/site metrics, historical site samples, active alerts, and alert rules.
- **Security** — TOTP, recovery readiness, passkeys, and API tokens.
- **Extensions** — installed plugins and the administrator-only plugin playground.
- **Settings** — operational and administrator configuration.

The bottom-left controls open Documentation, the command palette, Appearance, the AGPL license, and Sign out.

## Dashboard quick views

The four attention cards at the top of Dashboard are clickable. They open the data represented by the summary rather than acting as decorative counters:

1. **Unhealthy sites** — configured sites currently reporting unhealthy runtime/health state.
2. **Failed deployments** — recent deployment failures and their affected sites.
3. **Active alerts** — currently active performance/operational alerts.
4. **Automated traffic** — detected crawler, search, LLM, and other automated-client activity.

Use these views as shortcuts; detailed runtime and deployment logs remain available in the site workspace and Observability.

## Site workspace

Opening a site gives access to the relevant site tools, including runtime state, files, logs, deployment/release history, networking/security, and settings. Availability depends on the site type; for example, static sites do not expose process restart controls.

The command palette also indexes each site's workspace destinations such as Files, Logs, Settings, Restart, and Git Deploy where applicable.

## Performance

Performance has a dedicated navigation item. It displays both SHAM-level and per-site health information.

Typical host metrics include:

- CPU.
- RSS/heap memory.
- Event-loop delay.
- Disk use.
- Worker/operation pressure.
- Running-site count.

Per-site metrics include:

- CPU and memory where the runtime exposes them.
- Request rate.
- Error rate.
- Average response time.
- p50/p95 latency history.
- Connections.
- Restart activity.
- Health state.

Historical per-site samples are retained for seven days by the current implementation. Administrators can configure per-site alert thresholds.

The resource-history chart covers the most recent in-memory samples (`SHAM_PERFORMANCE_HISTORY_SAMPLES`, one per `SHAM_PERFORMANCE_INTERVAL_SECONDS`). Only the latest sample carries the per-site breakdown shown in the hosted-runtimes table; older samples keep just the CPU, memory, and event-loop values the chart plots, so memory use does not grow with the number of running sites. Charts lay out against their rendered width, so labels stay readable on phones. The page stops polling while its browser tab is hidden and refreshes when the tab becomes visible again.

## Settings organization

Administrator Settings are grouped into five categories:

### Delivery

Git releases, previews, deployment behavior, and delivery-oriented controls.

### Configuration

Per-site environment variables/secrets and database/service configuration.

### Automation

Scheduled jobs and runtime-log workflows.

### Instance

Git provider connections, backups, observability/export settings, and runtime integrations that apply to the SHAM instance.

### Administration

Accounts/users, registration policy, OIDC, Cloudflare, Certbot, and persistent administrative policy.

This separation keeps identity/infrastructure administration out of ordinary site configuration.

## Environment variables UI

Environment variables support runtime/build/both scopes and encrypted secret values. The copy-from-site control can copy selected environment entries between sites without requiring manual re-entry.

On narrow layouts the variable rows and copy controls collapse responsively rather than allowing action buttons or input groups to overlap.

## Git provider connections UI

Git provider rows support GitHub, GitLab, Bitbucket Cloud, Gitea, and Forgejo. Gitea/Forgejo show the custom base-URL field needed for self-hosted instances.

The layout is designed to wrap tokens, URLs, status text, and actions without overlapping on narrow screens.

## Appearance

Appearance has two independent choices:

1. **Mode:** System, Light, or Dark.
2. **Palette:** Purple, Midnight, Emerald, or Custom.

System follows the browser/OS preference. A palette changes SHAM's colors without changing the selected mode.

The Custom palette exposes accent, secondary accent, background, panel, text, and radius controls. Invalid saved custom values fall back to a valid preset while preserving the selected light/dark/system mode where possible.

## Command palette

Open the command palette with **Ctrl/Cmd+K** or its bottom-left button.

The index includes:

- Main navigation sections.
- Settings categories.
- Documentation categories.
- Sites.
- Site Files/Logs/Settings.
- Runtime restart actions where valid.
- Git deploy actions for Git-backed sites.
- Performance and common metric keywords such as CPU, memory, latency, p50, p95, errors, throughput, event loop, disk, and queues.

The palette intentionally returns only a bounded number of matches to keep keyboard navigation fast.

## Modals, tooltips, and notifications

SHAM uses native dialogs/popovers for top-layer UI. Tooltips and toast/notification regions are attached to the active top-layer surface when necessary so they do not render behind modal blur/backdrop layers.

Modal headers and footers stay pinned and opaque while long dialog bodies scroll between them. On screens narrower than about 620px, dialogs fill the viewport and short choice lists (site templates, workspace details, theme presets) use two columns, falling back to one column below 360px.

If a browser still shows old layering behavior after an upgrade, hard-refresh or clear cached static assets before diagnosing the new build.

## License and information button

The information button opens `/LICENSE` in a separate tab. SHAM serves the repository `LICENSE` file as plain text and returns a useful error if an installation is missing that file.

## Accessibility notes

The dashboard uses labeled controls, keyboard-operable tabs/command palette, dialog labels, and unique element IDs. Theme mode controls and documentation tabs are keyboard navigable.
