# GitHub CI/CD and release guide

SHAM includes four workflows:

- `ci.yml`: syntax, lint, type checks, unit and browser tests, production dependency audit, deployment/upgrade integration tests, and an amd64 Docker build with a mounted-volume restore smoke test.
- `docker-publish.yml`: publishes multi-platform images to GitHub Container Registry on `main`, semantic-version tags, or manual dispatch.
- `release.yml`: requires a committed lockfile, validates a `vX.Y.Z` tag, creates release archives and checksums, and creates the GitHub Release using the matching changelog entry.
- `prepare-lockfile.yml`: creates a pull request containing `package-lock.json` when the source archive was produced in an environment without npm registry access.

## 1. Create and configure the repository

1. Create an empty GitHub repository.
2. Upload or push the contents of this project directory, not the containing ZIP directory.
3. Open **Settings → Actions → General**.
4. Under **Workflow permissions**, select **Read and write permissions**. The workflows also declare narrow job-level permissions.
5. Keep **Allow GitHub Actions to create and approve pull requests** enabled only when you plan to use the manual lockfile workflow.
6. Open **Settings → Actions → General → Fork pull request workflows** and retain the secure defaults; no repository secrets are required for ordinary pull-request CI.
7. Protect `main` and require `Test and audit`, `Docker smoke build`, `Deployment and Compose integration`, and `Chromium critical workflows` before merging.

## 2. Commit the lockfile

A committed lockfile is strongly recommended. After the repository is online, use either method:

```bash
npm install
npm run release:check
git add package-lock.json
git commit -m "chore: add npm lockfile"
git push
```

Or run **Actions → Prepare lockfile → Run workflow**. It creates a branch and pull request containing the generated lockfile. Review and merge it before tagging the first release.

## 3. Container publishing

The Docker publishing workflow authenticates to `ghcr.io` with the repository-scoped `GITHUB_TOKEN`. No separate registry password is required.

Images are published as:

```text
ghcr.io/<owner>/<repository>:edge          # main branch
ghcr.io/<owner>/<repository>:<version>     # v<version> tag
ghcr.io/<owner>/<repository>:<major>.<minor>
ghcr.io/<owner>/<repository>:<major>
ghcr.io/<owner>/<repository>:latest
```

The workflow builds `linux/amd64` and `linux/arm64`, uses GitHub Actions build cache, and attaches OCI labels, an SBOM, and provenance information.

After the first publish, open the package under your GitHub profile or organization, connect it to the repository if GitHub did not do so automatically, and change package visibility to **Public** when the image should be publicly pullable.

Pull and run the image:

```bash
docker pull ghcr.io/<owner>/<repository>:<version>

docker run -d \
  --name sham \
  --restart unless-stopped \
  -p 8080:8080 \
  -p 80:80 \
  -p 443:443 \
  -p 4100-4199:4100-4199 \
  -v "$PWD/sham-data:/data" \
  ghcr.io/<owner>/<repository>:<version>
```

Or use the supplied Compose file:

```bash
SHAM_IMAGE=ghcr.io/<owner>/<repository>:<version> docker compose pull
SHAM_IMAGE=ghcr.io/<owner>/<repository>:<version> docker compose up -d
```

## 4. Create a release

Update the version in `package.json`, both root version fields in
`package-lock.json`, `README.md`, and `docs/openapi.json`. Update the supported
minor line in `SECURITY.md`, and move the unreleased changes into a dated
`CHANGELOG.md` section. Include upgrade requirements: the matching changelog
section becomes the public release notes.

Set the previous stable upgrade baseline in both
`test/integration/upgrade-recovery.integration.test.js` and `ci.yml`, and keep
`docs/integration-testing.md` aligned. The 1.3.0 release uses the unmodified
`v1.2.0` tag. Fetch that tag before running the required upgrade drill; missing
tags or unavailable Docker must not count as release verification.

Confirm all release changes and the lockfile are committed, the working tree
is clean, and all four CI checks passed on the exact commit being tagged.
The publishing workflows validate source independently; they do not wait for
the browser, upgrade, or Docker smoke jobs. Then create and push the matching tag:

```bash
git switch main
git pull --ff-only
npm run release:check
npm audit --omit=dev --audit-level=high
npm run test:e2e
SHAM_REQUIRE_UPGRADE_BASELINE=1 SHAM_UPGRADE_FROM=v1.2.0 npm run test:integration
git tag -s v<version> -m "SHAM <version>"
git push origin v<version>
```

Use an unsigned annotated tag when GPG signing is not configured:

```bash
git tag -a v<version> -m "SHAM <version>"
git push origin v<version>
```

The tag triggers both container publishing and GitHub Release creation. The release contains `.zip` and `.tar.gz` source archives plus SHA-256 checksum files. GitHub also provides its automatically generated source archives.

## 5. Release verification

- For 1.3.0, upgrade the control plane and Runtime Agent together. With Docker-backed sites, use both Compose files and the same pinned `SHAM_IMAGE` for both services:

  ```bash
  export SHAM_IMAGE=ghcr.io/<owner>/<repository>:<version>
  docker compose -f docker-compose.yml -f docker-compose.isolation.yml pull
  docker compose -f docker-compose.yml -f docker-compose.isolation.yml up -d
  ```

  Keep the existing `SHAM_DOCKER_HOST_DATA_PATH` and `DOCKER_GID` settings. Take a verified backup before upgrading and review the compatibility notes in `CHANGELOG.md`.
- Confirm the GitHub Release is published and its version matches `package.json`.
- Download the release archive and verify its checksum.
- Pull `ghcr.io/<owner>/<repository>:<version>` on a clean host.
- Confirm `/api/health` responds and complete first-admin setup.
- Verify the image package is public when public distribution is intended.
- Perform a backup and restore drill before describing a deployment as production-ready.

## Optional Docker Hub publishing

GHCR is the default because it requires no additional secret. To publish to Docker Hub as well, add repository secrets for a Docker Hub username and access token, then add a second `docker/login-action` login and an additional image name to the metadata workflow. Use an access token, not the account password.
