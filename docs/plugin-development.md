# Plugin development

SHAM supports declarative JSON plugins and JavaScript plugins. Plugins can extend dashboard UI and, when explicitly permitted, server-side behavior.

Server-side plugin code is trusted code. Develop on a non-production SHAM instance and review permissions/source before installation.

## Start with the Plugin playground

Open **Extensions → Plugin playground** as an administrator.

The playground lets you:

- Edit `plugin.json`.
- Validate it with SHAM's real server-side manifest validator.
- Inspect the normalized manifest.
- Add optional browser `client.js` code.
- Preview browser UI registration in a sandboxed iframe.

The manifest payload is bounded to 128 KiB.

The preview iframe:

- Uses `sandbox="allow-scripts"`.
- Has no same-origin access to the SHAM dashboard.
- Blocks network access through its preview CSP.
- Provides development stubs rather than real privileged server APIs.

**Server plugin code is never executed in the playground.** Build/test server actions on a dedicated development SHAM instance instead.

## Minimal manifest

A plugin archive contains `plugin.json` at its root.

Conceptual example:

```json
{
  "id": "example-status",
  "name": "Example status",
  "version": "1.0.0",
  "type": "json",
  "permissions": [],
  "ui": {
    "dashboardCards": [
      {
        "id": "example-card",
        "title": "Example"
      }
    ]
  }
}
```

Use the playground's generated/default example as the authoritative starting shape for the exact SHAM release you are targeting.

## JSON/declarative plugins

Declarative plugins can expose permitted data/actions/UI without arbitrary server module execution.

SQL/data declarations are validated and deliberately restricted from sensitive internal tables/operations. Do not design plugins around bypassing those boundaries.

## Plugin SQL policy

The same policy applies to declarative `queries` and to `data.all`/`data.get`/`data.run` in JavaScript plugins. SHAM compiles each statement and inspects the tables SQLite will actually open, so the rules hold however the SQL is written:

- **Readable core tables:** `sites` (columns `id`, `name`, `slug`, `directory_name`, `port`, `bind_host`, `runtime_type`, `enabled`, `domain`, `domain_only`, `preview_domain`, `ssl_enabled`, `cloudflare_enabled`, `edge_enabled`, `release_mode`, `maintenance_enabled`, `pinned`, `runtime_isolation`, `entry_file`, `spa_fallback`, `cache_seconds`, `compression`, `health_check_path`, `git_branch`, `created_at`, `updated_at`), `site_stats`, `site_daily_stats`, `site_performance_samples`, and `performance_samples`. `SELECT *` from `sites` is rejected; name the columns.
- **Plugin-owned tables:** tables named `plugin_<id>_<name>`, where `<id>` is the plugin ID with `-` replaced by `_` (plugin `site-notes` owns `plugin_site_notes_*`). A plugin can read, write, `CREATE TABLE`, `CREATE [UNIQUE] INDEX`, `DROP TABLE`/`DROP INDEX`, and `ALTER TABLE` only for its own tables. Writes and schema changes need `data:write`; a statement that modifies data is rejected under `data:read` alone.
- **Rejected:** writes to any core table, `ATTACH`/`DETACH`, `PRAGMA` and `pragma_*` functions, `VACUUM`, `BEGIN`/`COMMIT`/savepoints, triggers, views, virtual tables and table-valued functions such as `json_each`, `TEMP` objects, SQLite internal tables, and `load_extension`/`readfile`/`writefile`/`fts3_tokenizer`.

Create plugin tables from `activate()` or an admin action, for example `await data.run('CREATE TABLE IF NOT EXISTS plugin_site_notes_notes (site_id INTEGER, body TEXT)')`. Declarative plugins can read their own tables but cannot create them.

## Browser client

A plugin can ship `client.js` and register through the SHAM browser plugin API.

Production helpers depend on the plugin context/permissions. The playground provides only safe stubs, so a method visible in the preview should not be interpreted as authorization to perform that action in production.

Client guidelines:

- Keep dashboard startup work small/asynchronous.
- Avoid global CSS that breaks SHAM layout.
- Use SHAM-provided UI helpers where available for dialogs/toasts/tooltips so top-layer behavior remains consistent.
- Escape untrusted strings before inserting HTML.
- Do not store secrets in browser plugin code.

## Server actions

JavaScript plugins can define server actions when the manifest/permissions allow them.

SHAM applies:

- Explicit permission validation.
- Action timeouts.
- Bounded pending work.
- Lifecycle tracking during shutdown.
- Optional worker isolation.

Each enabled plugin keeps its own worker isolate running. Its heap is capped by `SHAM_PLUGIN_MEMORY_MB` (default 64 MB); a plugin that exceeds the cap is stopped and marked failed instead of growing the SHAM process without bound. Raise the limit only for plugins that genuinely need more memory.

Worker threads share the same OS process authority. They are a fault-containment mechanism, not a hostile-code sandbox.

Worker-isolated plugins run in a V8 context that contains no Node.js or SHAM host objects. Inside it, plugin code can use:

- The `activate(context)` API (`id`, `manifest`, `permissions`, `data`, `settings`, `runtime`, `log`) and the request passed to each action (`body`, `query`, `user`, `method`, `data`, `settings`). Host operations return promises.
- `console`, `setTimeout`/`setInterval`/`clearTimeout`/`clearInterval` (which return numeric IDs), and `queueMicrotask`.
- `fetch(url, { method, headers, body })` with the `network:outbound` permission. It returns `{ ok, status, statusText, url, headers.get(), text(), json() }`; bodies are strings and responses are limited to 8 MB.
- `require('crypto')` with `randomUUID()`, `randomBytes(n)`, `createHash(algorithm)` and `createHmac(algorithm, key)` (`update()` takes strings or `Uint8Array`; `digest()` takes `'hex'`, `'base64'`, `'base64url'`, or nothing for a `Uint8Array`).

Values crossing the boundary (arguments, action results, settings) are converted to JSON, so return plain data. `Buffer`, `URL`, `TextEncoder`, and requiring any other module are not available. Plugins that need them must use in-process isolation, which runs with the full authority of SHAM and should be reserved for code you would run as part of SHAM itself.

## Permissions

Request only the permissions the plugin actually needs.

Plugin installation should be treated like installing server software:

1. Review publisher/signature.
2. Review manifest permissions.
3. Review server/browser source.
4. Test on development/staging.
5. Enable in production only after expected behavior is understood.

## Packaging

Create a normal ZIP containing `plugin.json` at the expected archive root plus declared files.

Avoid:

- Extra enclosing directory levels unless the plugin archive format explicitly expects them.
- Embedded secrets.
- Large/generated dependency trees that are unnecessary.
- Host-path assumptions.
- Undeclared network/data access.

## Signing

SHAM supports signed plugin verification and trusted signing keys. Sign distributable plugins when possible.

Unsigned installation requires explicit administrator acknowledgement; do not train operators to ignore that warning.

## Recommended development loop

1. Draft the manifest in Plugin playground.
2. Validate until SHAM accepts it.
3. Preview small browser UI code.
4. Create server-side actions outside the playground.
5. Add the minimum permissions required.
6. Package the ZIP.
7. Install on a development SHAM instance.
8. Test enable/disable/reload/shutdown/error cases.
9. Test any site/runtime interactions with disposable applications.
10. Sign the release artifact.
11. Run SHAM's test/release checks when developing inside the SHAM source repository.

## Plugin API route

Administrators can validate a playground manifest through:

```text
POST /api/admin/plugins/playground/validate
```

Installed plugin management endpoints are listed in [API reference](api-reference.md).

## Debugging

Use:

- Browser developer console for `client.js`.
- Plugin/runtime logs for server-side behavior.
- Observability/audit events for lifecycle/administrative actions.

When browser UI appears behind a modal/backdrop, first ensure the plugin uses current SHAM UI helpers rather than hard-coded low z-index layers.
