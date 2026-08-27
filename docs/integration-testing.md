# Integration and browser testing

SHAM's unit suite is intentionally fast. The integration suite starts a real
SHAM child process with an empty temporary data directory, bootstraps an admin
through the public API, serves a local Git fixture over HTTP, and drives normal
Git-release, readiness, gateway, rollback, and startup reconciliation paths.
Docker scenarios also start a real Runtime Agent child process. The suite does
not import the server or write deployment state directly.

## Commands

```bash
npm run test:integration
```

`test:integration` requires Node.js 22+ and Git. Docker scenarios additionally
require a reachable Docker Engine and Compose v2. The process/Git lifecycle
test always runs; Compose tests report as skipped when Docker is unavailable.
They are not silently replaced with mocks.

The suite is serial because it owns process listeners, Git repositories,
temporary data, and (when available) Docker. It uses dynamically allocated
dashboard, edge, and site ports. Each test cleans its temporary data directory
and Git fixture after the scenario, including site deletion in the Compose
lifecycle test. On CI, Docker scenarios use the GitHub runner daemon through
SHAM's Runtime Agent, never a mocked Docker command layer.

## What is exercised

The release lifecycle fixture verifies version 1 routing, version 2 traffic
switching, failed-readiness safety, rollback, stop/start/restart, runtime logs,
and SHAM process restart reconciliation. The Compose fixture verifies a web
service plus an internal-only dependency, proxy routing, reconciliation, site
cleanup, and rejection of prohibited host-level Compose features.

The same serial suite also runs two recovery drills. The upgrade drill archives
the preceding pre-Runtime-Agent source revision, starts it with isolated data,
deploys a Git application and secret, then starts current SHAM against that
same data. It verifies database startup/migrations, Runtime Agent token
creation, running traffic, encrypted environment data, release history, and
rollback. CI fetches the parent revision for this purpose. The restore drill
creates a local archive through the authenticated API, validates it with the
production archive verifier, deletes the site, stages the authenticated
restore, restarts SHAM, checks SQLite, release files, secret decryption,
traffic, and rollback.

Compose validation is performed against Docker's normalized Compose
configuration before `compose up`. Privileged services, namespace overrides,
added capabilities, host bind mounts, Docker socket mounts, host devices, and
auxiliary published ports are rejected as invalid deployment input. SHAM cleans
up the attempted site record and release staging rather than retaining a site
with a startup warning.

When a scenario fails, the harness appends bounded SHAM output, site state, and
runtime logs to the failure. The CI job also prints Docker containers,
networks, and images. Fixtures must not contain real credentials because the
harness output is diagnostic data, not a secret-redaction boundary.

Browser tests use Playwright Chromium and the same isolated harness:

```bash
npx playwright install --with-deps chromium
npm run test:e2e
```

They capture screenshots, traces, and video on failure. Browser binaries are
not committed; GitHub Actions installs Chromium in its browser job. The serial
suite covers the unauthenticated access gate, first-run setup, invalid login,
session refresh, Git-backed Node deployment, workspace logs, stop/start/restart,
version switching, rollback, and a failed candidate preserving the active
release. It uses the UI for the behavior under test and the harness only for
the local fixture repository, edge assertion, and fixture revision changes.

## CI layout

The GitHub Actions workflow keeps static/unit checks separate from slower
environment tests:

- **Test and audit** runs syntax, lint, JSDoc checking, unit/regression tests,
  release hygiene, and the production dependency audit.
- **Docker smoke build** verifies the published image can start and answer its
  health endpoint.
- **Deployment and Compose integration** runs `npm run test:integration` with
  the runner Docker daemon.
- **Chromium critical workflows** installs Playwright Chromium and runs
  `npm run test:e2e`, preserving a Playwright report on failure.
