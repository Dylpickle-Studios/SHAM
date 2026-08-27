# Development workflow

SHAM is, and remains, a plain JavaScript/CommonJS project. Static analysis is layered on top without any build step or TypeScript compilation:

```bash
npm run check:syntax   # node --check on every src/public/runtime-agent file
npm run lint           # ESLint — correctness rules (no-undef, no-unused-vars, ...)
npm run typecheck      # tsc --noEmit — TypeScript used only to check JSDoc-typed JS
npm run check          # all three of the above
npm test               # node --test
npm run security       # npm audit (production dependencies)
npm run verify         # check + test + security in one command
```

Run `npm run check` (or `npm run verify` before something you intend to ship) before opening a PR; CI runs the same checks via `npm run release:check`.

## ESLint

Configured in `eslint.config.js` (flat config). It targets real defects — unused/undefined variables, unreachable code, loose equality, dead assignments — not formatting; there is no house style enforced here. Backend (`src/`, `bin/`, `runtime-agent/`, `scripts/`) and test files get Node globals; `public/**` gets browser globals. `no-undef`/`no-unused-vars` are turned off specifically for `public/js/**`, because those files are classic (non-module) `<script>` tags that deliberately share one global scope across files — ESLint can only see one file at a time, so those two rules produce false positives there (verified: an early pass of this config nearly deleted a real, cross-file-used constant). Every other correctness rule still applies to browser code.

## TypeScript / JSDoc type checking

`tsconfig.json` sets `allowJs: true, checkJs: true, noEmit: true` — TypeScript never compiles or emits anything; it only reads JSDoc comments in `.js` files and reports type errors. Add types with ordinary JSDoc:

```js
/**
 * @param {import('./types/site').Site} site
 * @returns {Promise<void>}
 */
async function startSite(site) { /* ... */ }
```

`strictNullChecks` is on (the highest-value check for this codebase — it catches real "this can be null/undefined" bugs on annotated code); `noImplicitAny` is off, so untyped functions stay implicitly `any` rather than erroring — add JSDoc to a function and it starts getting real protection.

Shared domain types live in `src/types/` (`site.js`, `runtime.js`, `deployment.js`) as JSDoc-only modules — reference them with `@type {import('../types/site').Site}` rather than repeating an anonymous object shape.

### Staged rollout

Most of `src/`, `bin/`, `runtime-agent/`, and `scripts/` type-check cleanly. A subset of the largest, highest-churn files (`src/server.js`, `src/sites/{runtime,core,delivery}.js`, `src/security.js`, `src/cloudflare-tunnel*.js`, `src/routes/sites.js`, `src/operations/{deployments,shared}.js`, `src/plugin-manager.js`, `src/git-providers.js`, `src/backup-restore.js`, `src/performance-monitor.js`, `src/edge-proxy.js`, `src/bootstrap.js`, `src/integrations.js`, `src/dependency-scanner.js`) still has real `tsc` findings and carries a `// @ts-nocheck` with a comment explaining that it's temporary, not a hidden problem. `test/` and `public/js/` are not type-checked yet (JS test files need less typing value; `public/js/**` has the same cross-file-global-scope issue described above for ESLint, and would need a shared ambient `.d.ts` first). Removing a `@ts-nocheck` should come with actually fixing what `tsc` then reports for that file, in the same change.

## Nullability and errors

- Prefer modeling a function's real return type (`T | null`) over hiding it, and handle the `null` case at call sites rather than asserting it away.
- `catch (error)` blocks are not narrowed to `unknown` (see `tsconfig.json`'s `useUnknownInCatchVariables` comment) — SHAM has hundreds of existing `catch (error) { ...error.message... }` blocks, and retrofitting `instanceof Error` narrowing everywhere would be pure churn. New code touching an untrusted caught value should still prefer `error instanceof Error ? error.message : String(error)`.
- Prefer `unknown` over `any` for genuinely-untrusted input (parsed JSON, request bodies, plugin/provider responses); use a real type or a narrow, documented suppression when the shape is actually known but awkward to express.
