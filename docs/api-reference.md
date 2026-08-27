# API reference

This is an endpoint inventory for the current SHAM release. It complements [API and CLI](api-and-cli.md), which focuses on automation patterns and stable CLI-oriented use.

The API currently uses `/api` rather than a versioned `/api/v1` namespace. Pin SHAM versions for important automation.

## Authentication legend

- **Public** — no SHAM session/token required.
- **Auth** — authenticated SHAM user/session or accepted API-token context.
- **Admin** — authenticated administrator.
- **Step-up** — an authenticated action that additionally requires recent password/step-up verification.
- **Webhook** — provider/HMAC deployment-webhook authentication rather than a user session.

API-token scopes are enforced by the authentication middleware on supported automation routes. Role requirements still apply.

## Public/bootstrap/authentication

| Method | Path | Access | Purpose |
|---|---|---|---|
| GET | `/api/health` | Public | Basic SHAM process health. |
| GET | `/api/bootstrap` | Public/optional auth | Bootstrap/login/UI initialization metadata. |
| GET | `/api/public/status` | Public | Public status data for sites configured for status exposure. |
| GET | `/api/auth/oidc/start` | Public | Start configured OIDC Authorization Code + PKCE login. |
| GET | `/api/auth/oidc/callback` | Public | OIDC callback. |
| POST | `/api/auth/register` | Public, first-run only | Create the initial administrator when no users exist. Public signup is disabled afterward. |
| POST | `/api/auth/login` | Public | Password login. |
| POST | `/api/auth/login/totp` | Public flow | Complete TOTP login challenge. |
| POST | `/api/auth/login/passkey/options` | Public flow | Create passkey-login challenge options. |
| POST | `/api/auth/login/passkey/verify` | Public flow | Verify passkey login. |
| POST | `/api/auth/logout` | Optional auth | End browser session. |
| GET | `/api/auth/me` | Auth | Return current public user profile. |

The public HTML license route is `/LICENSE`, not an API endpoint.

## Security and personal credentials

| Method | Path | Access | Purpose |
|---|---|---|---|
| GET | `/api/security` | Auth | Security posture, local-password state, passkeys, TOTP/recovery summary, API-token metadata. |
| PUT | `/api/security/password` | Browser session | Set/bootstrap or change the local password; rotates browser-session version. |
| POST | `/api/security/sessions/revoke-others` | Browser session + step-up when local password exists | Invalidate other browser sessions and issue a fresh current session. |
| POST | `/api/security/api-tokens` | Auth + step-up | Create a scoped bearer token; plaintext token is returned once. |
| DELETE | `/api/security/api-tokens/:id` | Auth + step-up | Revoke one of the current user's API tokens. |
| POST | `/api/security/totp/setup` | Auth + step-up | Begin TOTP enrollment. |
| POST | `/api/security/totp/enable` | Auth | Complete TOTP enrollment. |
| POST | `/api/security/totp/disable` | Auth + step-up | Disable TOTP. |
| POST | `/api/security/recovery-codes/regenerate` | Auth + step-up | Replace recovery codes. |
| POST | `/api/security/passkeys/options` | Auth + step-up | Begin passkey registration. |
| POST | `/api/security/passkeys/register` | Auth | Complete passkey registration. |
| DELETE | `/api/security/passkeys/:id` | Auth + step-up | Remove passkey. |

Available API-token scopes in this release are `read`, `logs:read`, `deploy`, `sites:control`, and `*`.

## Sites and dashboard data

| Method | Path | Access | Purpose |
|---|---|---|---|
| GET | `/api/sites` | Auth | List sites with runtime/tunnel summaries. |
| POST | `/api/sites` | Auth | Create/upload a site using multipart form data. |
| PUT | `/api/sites/:id` | Auth | Update site configuration. |
| DELETE | `/api/sites/:id` | Auth | Delete site. |
| PATCH | `/api/sites/:id/pin` | Auth | Pin/unpin site in dashboard. |
| PATCH | `/api/sites/:id/toggle` | Auth | Legacy UI-style start/stop toggle. Prefer explicit start/stop for automation. |
| POST | `/api/sites/:id/start` | Auth | Idempotently start site. |
| POST | `/api/sites/:id/stop` | Auth | Idempotently stop site. |
| POST | `/api/sites/:id/restart` | Auth | Restart managed runtime. |
| POST | `/api/sites/:id/npm-install` | Auth | Run managed legacy Node dependency installation. |
| GET | `/api/statistics` | Auth | Dashboard traffic/visitor/attention summaries. |
| GET | `/api/runtime-events` | Auth | Runtime event stream/history used by Observability. |

## Firewall

| Method | Path | Access | Purpose |
|---|---|---|---|
| POST | `/api/sites/:id/firewall/ban-ip` | Auth | Add a site IP/CIDR ban. |
| DELETE | `/api/sites/:id/firewall/ban-ip` | Auth | Remove a site IP/CIDR ban. |

## Performance and alerts

| Method | Path | Access | Purpose |
|---|---|---|---|
| GET | `/api/performance` | Auth | Live SHAM/site performance snapshot and alerts. |
| POST | `/api/performance/alerts/:id/acknowledge` | Auth | Acknowledge an alert. |
| GET | `/api/sites/:id/performance/history` | Auth | Persisted per-site performance history. |
| GET | `/api/sites/:id/alert-rules` | Auth | Read site-specific alert thresholds. |
| PUT | `/api/sites/:id/alert-rules` | Admin | Replace/update site alert rules. |

## Runtime logs

| Method | Path | Access | Purpose |
|---|---|---|---|
| GET | `/api/runtime-logs` | Auth | Query structured runtime logs. |
| GET | `/api/runtime-logs/search` | Admin | Advanced runtime-log search used by Operations. |
| GET | `/api/admin/logs/export` | Admin | Export logs. |
| GET | `/api/log-filters` | Auth | List current user's saved log filters. |
| POST | `/api/log-filters` | Auth | Save log filter. |
| DELETE | `/api/log-filters/:id` | Auth | Delete current user's saved filter. |

## Site files/content

| Method | Path | Access | Purpose |
|---|---|---|---|
| PUT | `/api/sites/:id/content` | Auth | Replace site content using multipart upload. |
| GET | `/api/sites/:id/files` | Auth | List site files. |
| GET | `/api/sites/:id/files/content` | Auth | Read one editable text file. |
| PUT | `/api/sites/:id/files/content` | Auth | Save one editable text file. |
| PUT | `/api/sites/:id/files/upload` | Auth | Upload/replace one file. |
| DELETE | `/api/sites/:id/files` | Auth | Delete one file. |
| GET | `/api/sites/:id/obfuscation-report` | Auth | Static JavaScript obfuscation compatibility report. |

## Dependency scans and snapshots

| Method | Path | Access | Purpose |
|---|---|---|---|
| GET | `/api/sites/:id/dependency-scan` | Auth | Read last dependency-scan result. |
| POST | `/api/sites/:id/dependency-scan` | Auth | Run dependency scan. |
| GET | `/api/sites/:id/snapshots` | Auth | List site snapshots. |
| POST | `/api/sites/:id/snapshots` | Auth | Create snapshot. |
| POST | `/api/sites/:id/snapshots/:snapshotId/restore` | Auth | Restore snapshot. |
| DELETE | `/api/sites/:id/snapshots/:snapshotId` | Auth | Delete snapshot. |

## Deployments, releases, previews, and site operations

| Method | Path | Access | Purpose |
|---|---|---|---|
| POST | `/api/hooks/deploy/:id` | Webhook | Signed/provider-authenticated Git push deployment hook. |
| GET | `/api/sites/:id/deployments` | Auth | Deployment history. |
| GET | `/api/sites/:id/deployments/:deploymentId/logs` | Auth | Deployment-specific logs. |
| GET | `/api/sites/:id/operations` | Admin | Site Operations workspace data. |
| POST | `/api/sites/:id/deploy/git` | Admin | Run Git deployment. |
| POST | `/api/sites/:id/releases/:releaseId/rollback` | Admin | Reactivate retained release. |
| POST | `/api/sites/:id/previews` | Admin | Create preview deployment. |
| DELETE | `/api/sites/:id/previews/:previewId` | Admin | Delete preview. |
| GET | `/api/sites/:id/config/export` | Admin | Export site configuration without ordinary secret plaintext. |
| POST | `/api/sites/:id/config/import` | Admin | Import site configuration. |

## Environment variables, database profiles, and jobs

| Method | Path | Access | Purpose |
|---|---|---|---|
| PUT | `/api/sites/:id/environment` | Admin | Save per-site environment variables/secrets/scopes. |
| POST | `/api/sites/:id/environment/:key/reveal` | Admin + step-up | Reveal one stored site secret. |
| POST | `/api/sites/:id/environment/copy` | Admin | Copy selected environment values from another site. |
| PUT | `/api/sites/:id/database-profiles` | Admin | Attach/update site database-profile references. |
| POST | `/api/sites/:id/jobs` | Admin | Create scheduled job. |
| DELETE | `/api/sites/:id/jobs/:jobId` | Admin | Delete job. |
| POST | `/api/sites/:id/jobs/:jobId/run` | Admin | Run job immediately. |
| GET | `/api/admin/database-profiles` | Admin | List reusable database profiles. |
| POST | `/api/admin/database-profiles` | Admin | Create/update database profile. |
| DELETE | `/api/admin/database-profiles/:id` | Admin | Delete database profile. |

## Git provider administration

| Method | Path | Access | Purpose |
|---|---|---|---|
| GET | `/api/admin/git-providers` | Admin | Connection status for GitHub/GitLab/Bitbucket/Gitea/Forgejo. |
| PUT | `/api/admin/git-providers/:provider` | Admin | Save/update provider token and provider-specific settings. |
| GET | `/api/admin/git-providers/:provider/repositories` | Admin | Discover repositories available through provider connection. |

Valid provider identifiers are `github`, `gitlab`, `bitbucket`, `gitea`, and `forgejo`.

## Plugins

| Method | Path | Access | Purpose |
|---|---|---|---|
| GET | `/api/plugins` | Auth | List visible installed plugins/UI contributions. |
| GET | `/api/plugins/:id/client.js` | Auth | Serve installed plugin browser client. |
| POST | `/api/admin/plugins/playground/validate` | Admin | Validate/normalize playground manifest. No server plugin code executes. |
| POST | `/api/admin/plugins` | Admin | Upload/install plugin ZIP. |
| PATCH | `/api/admin/plugins/:id/toggle` | Admin | Enable/disable plugin. |
| PUT | `/api/admin/plugins/:id/settings` | Admin | Save plugin settings. |
| DELETE | `/api/admin/plugins/:id` | Admin | Uninstall plugin. |

Plugins can register additional routes/actions according to their manifest and permissions; those plugin-specific APIs are not covered by this core endpoint inventory.

## Administrator security/settings

| Method | Path | Access | Purpose |
|---|---|---|---|
| GET | `/api/admin/settings` | Admin | Administrative settings state. |
| PUT | `/api/admin/settings/security` | Admin | Security/trust settings. |
| POST | `/api/admin/security/rotate-master-key` | Admin + step-up | Rotate encrypted-secret master key. |
| PUT | `/api/admin/settings/oidc` | Admin | OIDC configuration. |
| PATCH | `/api/admin/settings/registration` | Admin | Deprecated; returns `410` because public signup cannot be re-enabled after bootstrap. |
| PUT | `/api/admin/settings/integrations` | Admin | Integration credentials/settings. |
| GET | `/api/admin/users` | Admin | User list. |
| POST | `/api/admin/users` | Admin | Create a dashboard account with an initial local password. |
| PATCH | `/api/admin/users/:id` | Admin | Change user role/state; access changes revoke existing browser sessions. |
| POST | `/api/admin/users/:id/revoke-sessions` | Admin | Revoke another user's browser sessions. |
| DELETE | `/api/admin/users/:id` | Admin | Delete user subject to safety rules. |

## Cloudflare, Certbot, and tunnels

| Method | Path | Access | Purpose |
|---|---|---|---|
| POST | `/api/admin/sites/:id/cloudflare` | Admin | Cloudflare DNS operation for site. |
| POST | `/api/admin/sites/:id/cloudflare-firewall` | Admin | Synchronize site firewall/WAF policy. |
| POST | `/api/admin/sites/:id/certificate` | Admin | Issue/configure certificate. |
| POST | `/api/admin/certificates/renew` | Admin | Renew certificates. |
| PUT | `/api/admin/cloudflare-tunnel` | Admin | Legacy/global tunnel configuration. |
| POST | `/api/admin/cloudflare-tunnel/restart` | Admin | Restart legacy/global connector. |
| GET | `/api/admin/sites/:id/cloudflare-tunnel` | Admin | Read per-site tunnel state. |
| PUT | `/api/admin/sites/:id/cloudflare-tunnel` | Admin | Save per-site tunnel configuration. |
| POST | `/api/admin/sites/:id/cloudflare-tunnel/restart` | Admin | Restart per-site tunnel. |

## Backups, alerts, audit, and updates

| Method | Path | Access | Purpose |
|---|---|---|---|
| GET | `/api/admin/operations` | Admin | Instance Operations state/capabilities. |
| PUT | `/api/admin/operations/settings` | Admin | Save Operations/backup/observability settings. |
| POST | `/api/admin/backups/run` | Admin | Run backup. |
| GET | `/api/admin/backups/restore-status` | Admin | Read staged/restore status. |
| POST | `/api/admin/backups/:id/restore` | Admin + step-up | Restore selected backup through staged validation/swap. |
| POST | `/api/admin/alert-destinations` | Admin | Create/update alert destination. |
| POST | `/api/admin/alert-destinations/:id/test` | Admin | Test alert destination. |
| DELETE | `/api/admin/alert-destinations/:id` | Admin | Delete alert destination. |
| GET | `/api/admin/audit` | Admin | Read audit history. |
| GET | `/api/admin/audit/export` | Admin | Export audit data. |
| POST | `/api/admin/update` | Admin | Stage signed/acknowledged SHAM update archive. |
| DELETE | `/api/admin/update` | Admin | Cancel staged update. |

## Metrics/status outside JSON API

SHAM can expose conventional machine-oriented/public routes when enabled/configured, including the Prometheus text endpoint and public status page. Treat those as deployment/integration surfaces rather than part of the stable JSON automation API and protect them according to your network policy.

## Error handling

Expect standard HTTP semantics:

- `400` invalid input/configuration.
- `401` authentication required/invalid.
- `403` authenticated but not authorized.
- `404` missing resource/disabled public flow.
- `409` state/policy conflict such as unapproved manifest execution-policy changes.
- `413` request/upload bounds exceeded.
- `429` rate/queue limit reached.

Prefer a structured `code` field when supplied. Human-readable `error` text is intended for diagnostics and can change between releases.
