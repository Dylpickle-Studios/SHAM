# API and CLI

SHAM's dashboard uses the same HTTP API that is available for automation. This guide focuses on safe automation patterns. For a broader endpoint list, see [API reference](api-reference.md).

## Base URL

The JSON API lives under:

```text
/api
```

Use `/api/v1` for new automation. Existing `/api` routes remain compatibility
aliases for the current major release line. The machine-readable contract is
[OpenAPI 3.1](openapi.json), and the compatibility policy is documented in
[API compatibility](api-compatibility.md).

## Authentication

### Browser sessions

Interactive users authenticate through SHAM's session/login flow. Browser requests also participate in same-origin/security controls used by the dashboard.

### API tokens

Create a token under **Security → API Tokens**.

The plaintext token is shown once. SHAM stores a hash, not the reusable plaintext value.

Use:

```http
Authorization: Bearer sham_pat_...
Accept: application/json
```

Never place bearer tokens in query parameters, repository files, shell history intended for sharing, or build logs.

## API-token scopes

Available scopes:

| Scope | Intended use |
|---|---|
| `read` | General read access supported by token middleware. |
| `logs:read` | Runtime-log reads. |
| `deploy` | Deployment/rollback automation covered by token authorization. |
| `sites:control` | Start/stop/restart site runtimes. |
| `*` | Unrestricted token scope; reserve for tightly controlled administration. |

Role checks still apply. A token cannot turn a non-administrator identity into an administrator.

## Stable automation examples

### List sites

```http
GET /api/sites
```

```bash
curl --fail-with-body \
  -H "Authorization: Bearer $SHAM_TOKEN" \
  -H "Accept: application/json" \
  "$SHAM_URL/api/sites"
```

### Start a site

```http
POST /api/sites/:id/start
```

This is idempotent; calling start for an already-running site should not be used as a restart mechanism.

### Stop a site

```http
POST /api/sites/:id/stop
```

Idempotent for an already-stopped site.

### Restart a site

```http
POST /api/sites/:id/restart
```

### Deploy Git

```http
POST /api/sites/:id/deploy/git
Content-Type: application/json

{
  "branch": "main",
  "approveManifestChanges": false
}
```

A changed execution policy can return `409` with a structured manifest-approval code. Review the manifest before retrying with approval.

### Roll back

```http
POST /api/sites/:id/releases/:releaseId/rollback
```

### Runtime logs

```http
GET /api/runtime-logs?siteId=12&limit=200
```

Administrator advanced search:

```http
GET /api/runtime-logs/search?siteId=12&q=timeout
```

### Performance

```http
GET /api/performance
GET /api/sites/:id/performance/history
GET /api/sites/:id/alert-rules
PUT /api/sites/:id/alert-rules
```

### Deployments

```http
GET /api/sites/:id/deployments
GET /api/sites/:id/deployments/:deploymentId/logs
```

## Bundled CLI

The npm package exposes the `sham` executable from `bin/sham.js`.

Environment:

```bash
export SHAM_URL="https://sham.example.com"
export SHAM_TOKEN="sham_pat_..."
```

Commands:

```bash
sham sites
sham deploy <site-id> [--branch main] [--approve-manifest]
sham logs <site-id> [--limit 200]
sham start <site-id>
sham stop <site-id>
sham restart <site-id>
sham rollback <site-id> <release-id>
```

The CLI exits non-zero when the request fails and prints API error detail when available.

## CLI timeouts

Current client bounds:

- Ordinary/control requests: 30 seconds.
- Git deploy: 30 minutes.
- Rollback: 10 minutes.

Deploy/rollback are longer because the server endpoint can synchronously wait for build/readiness work. Configure reverse-proxy timeouts consistently if you use synchronous CI calls.

## CI example

```bash
set -euo pipefail
export SHAM_URL="https://sham.example.com"
export SHAM_TOKEN="$SHAM_DEPLOY_TOKEN"

sham deploy 12 --branch main
```

Use a narrowly scoped CI token and a dedicated automation user where separation of duties matters.

## Common response/error behavior

Typical status codes:

- `400` — invalid input/configuration.
- `401` — missing/invalid authentication.
- `403` — authenticated but not authorized.
- `404` — missing resource/disabled route.
- `409` — state/policy conflict, including manifest approval requirements.
- `413` — request/upload bounds exceeded.
- `429` — rate limit or bounded work queue is full.

JSON errors generally include an `error` message. Prefer a structured `code` field when present; do not make brittle automation depend on exact human-readable error wording.

## Request limits

SHAM intentionally bounds:

- JSON body size.
- Multipart field/file count.
- Upload size.
- Archive entry/path counts.
- Log/process output capture.
- Search/list limits.
- Several worker queues/concurrency groups.

Treat `400`, `413`, and `429` as input/capacity signals. Do not blindly retry non-idempotent operations.

## API groups beyond the CLI

The dashboard API also covers:

- Site files/content replacement.
- Dependency scans and snapshots.
- Environment variables/secrets and copy/reveal flows.
- Database profiles.
- Scheduled jobs.
- Previews and release history.
- Git provider connections.
- Backups and staged restore.
- Alert destinations/audit exports.
- Cloudflare DNS/WAF/Tunnels.
- Certbot.
- Plugins and the plugin playground.
- OIDC/users/registration administration.
- TOTP/recovery/passkeys/API tokens.

See [API reference](api-reference.md) for method/path/access details.

## Compatibility guidance

For automation that must survive upgrades:

1. Pin SHAM versions.
2. Use documented endpoints only.
3. Avoid depending on undocumented response fields.
4. Check HTTP status and structured error codes.
5. Test upgrades in staging.
6. Treat repository-manifest changes as code-execution policy changes, not routine metadata.
