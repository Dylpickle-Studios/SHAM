# Contributing to SHAM

Thank you for helping improve SHAM.

## Development setup

Requirements: Node.js 22 or newer (the `package.json` engine requirement is
authoritative), npm, and a compiler toolchain when `better-sqlite3` has no
matching prebuilt binary. Docker is required for `npm run test:integration`
and Docker-managed runtime tests; Playwright's Chromium install is required
for `npm run test:e2e`.

```bash
cp .env.example .env
npm install
npm run check
npm test
npm run test:integration
npm run test:e2e
npm start
```

The first local account becomes the administrator. Never use production secrets or production data in development.

## Before opening a pull request

```bash
npm run release:check
npm audit --omit=dev --audit-level=high
```

Also verify affected screens at desktop and narrow viewport widths. New controls must use existing semantic theme variables, keyboard-accessible labels, and the shared component patterns. New API routes must explicitly declare authentication and authorization behavior and include negative tests for unauthenticated and non-administrator access where applicable.

## Pull requests

- Keep changes focused and explain the user-visible effect.
- Add or update tests for fixes and regressions.
- Update README, built-in documentation, CHANGELOG, and `.env.example` when behavior or configuration changes.
- Do not commit `.env`, databases, generated keys, backups, uploads, logs, `node_modules`, or other runtime data.
- Do not weaken dependency pins, archive validation, permission checks, queue bounds, timeouts, or secret masking without a documented security review.

## Vulnerabilities

Do not disclose vulnerabilities in an issue or pull request. Follow [SECURITY.md](SECURITY.md).

## License

By contributing, you agree that your contribution is licensed under AGPL-3.0-or-later, the same license as the project.
