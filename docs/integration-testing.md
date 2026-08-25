# Integration and browser testing

SHAM's unit suite is intentionally fast. The deployment suite starts real
SHAM processes with an empty temporary data directory, bootstraps an admin via
the public API, serves a local Git fixture over HTTP, and drives the normal
Git-release, readiness, gateway, rollback, and startup reconciliation paths.

```bash
npm run test:integration
```

The suite is serial because it owns process listeners, Git repositories,
temporary data, and (when available) Docker. It cleans each temporary data
directory and Git fixture after the scenario, including site deletion in the
Compose lifecycle test. Docker scenarios automatically skip only when a Docker
daemon is unavailable; on CI they use the runner daemon through SHAM's runtime
agent rather than mocking the Docker command layer.

The release lifecycle fixture verifies version 1 routing, version 2 traffic
switching, failed-readiness safety, rollback, stop/start/restart, runtime logs,
and SHAM process restart reconciliation. The Compose fixture verifies a web
service plus an internal-only dependency, proxy routing, reconciliation, site
cleanup, and rejection of prohibited host-level Compose features.

Browser tests use Playwright Chromium and the same isolated harness:

```bash
npx playwright install --with-deps chromium
npm run test:e2e
```

They capture screenshots, traces, and video on failure. Browser binaries are
not committed; GitHub Actions installs Chromium in its browser job.
