# Operations and security

This guide covers administrator workflows and the security/recovery boundaries around them.

## Settings categories

SHAM groups Settings into five categories.

| Category | Contains |
|---|---|
| **Delivery** | Git release/deployment behavior, previews, release controls |
| **Configuration** | Environment variables/secrets, database profiles/service attachments |
| **Automation** | Scheduled jobs, runtime-log workflows/search |
| **Instance** | Git provider connections, backups, observability/export and runtime integrations |
| **Administration** | Accounts/users, registration, OIDC, Cloudflare, Certbot, persistent administrative policy |

See [Dashboard and UI](dashboard-and-ui.md) for navigation/layout behavior.

## Environment variables and secrets

Environment values are per-site and can be scoped to:

- Runtime.
- Build.
- Both.

Secret values are encrypted at rest and masked in normal browser/API responses. Revealing a stored secret requires an elevated administrator flow.

The environment-variable UI can copy selected values from another site. The source/target controls use the same responsive layout conventions as the rest of Settings.

Build/runtime subprocesses receive purpose-specific environment allowlists. SHAM does not intentionally forward its own JWT/master-key material into hosted applications.

For containers, SHAM avoids placing secret plaintext into visible Docker CLI `KEY=value` argument strings.

## Database profiles

Reusable database connection profiles can be defined at the administrator level and attached to sites. Treat database credentials as secrets and grant application users the minimum database privileges required.

## Scheduled jobs

Jobs can be created per site and run on schedule or manually.

For container/Compose applications, jobs target the actual active runtime backend rather than relying on a fixed legacy container name. This matters after candidate-first release activation where container identifiers change between releases.

Apply job timeout limits and avoid using scheduled jobs as an unbounded general-purpose queue.

## Backups

SHAM supports configured local/off-host backup destinations including workflows for Restic, S3-compatible transfer through AWS CLI, and SFTP depending on instance configuration.

Back up the full SHAM data directory independently of per-site snapshots.

## Restore safety

Restore is intentionally staged:

1. Identify the selected backup archive.
2. Stream-inspect the complete archive structure.
3. Enforce entry/path/count bounds.
4. Reject absolute/traversal paths, links, and special files before extraction.
5. Extract into an isolated staging directory.
6. Validate the staged tree.
7. Open/check the staged SQLite database.
8. Run `PRAGMA quick_check`.
9. Verify core SHAM tables.
10. Atomically swap the live data directory.
11. Preserve backup/update stores as required by the restore workflow.
12. Roll back the directory swap if activation fails.

The live data directory is not deleted first and then "hoped" to restore successfully.

## Snapshots vs backups

Snapshots are per-site restore points and are useful before risky content/deployment changes. They do not replace a complete instance backup containing the database, configuration, secrets/key material, plugins, certificates, and releases.

## Monitoring and Performance

The dedicated **Performance** page reports live host/control-plane and site metrics.

Host/control-plane metrics include CPU, memory, event-loop delay, disk use, and operational queue/worker information.

Site metrics include request/error rate, latency, memory/CPU where available, connections, health, and restart activity. SHAM persists per-site CPU/latency history including p50/p95 values for seven days in the current implementation.

Administrators can define per-site alert rules. Active alerts also appear in the Dashboard quick-view drilldown.

Health checks, performance sampling, Cloudflare Tunnel bulk lifecycle operations, and runtime shutdown use bounded concurrency to avoid avoidable synchronized bursts on larger instances.

## Runtime logs and privacy

Runtime output is line-buffered so arbitrary stdout/stderr chunk boundaries do not create fragmented log records. Log output capture and persisted/history workflows are bounded.

Visitor-detail retention is configurable; aggregate statistics can remain useful after detailed visitor-IP records expire.

## Cloudflare

SHAM can manage optional:

- DNS records.
- Hostname-scoped WAF/firewall synchronization.
- Per-site Cloudflare Tunnels.
- Periodic reconciliation for opted-in DNS/firewall configuration.

Cloudflare credentials are encrypted. Scope API tokens to the smallest required zone/account privileges.

Do not assume a proxied Cloudflare DNS record makes a publicly reachable origin private. Protect the origin listener/network separately.

For the complete per-site Tunnel workflow—including the difference between Tunnel tokens and API tokens, Docker origin targets, connector states, and 502 troubleshooting—see [Cloudflare Tunnels](cloudflare-tunnels.md).

## Certbot

SHAM can coordinate certificate issuance/renewal through the configured Certbot executable, including Cloudflare DNS workflows where configured.

When using standalone HTTP validation, ensure port 80/routing is compatible with the shared edge listener and that DNS points to the correct host.

## OIDC

OIDC SSO uses Authorization Code + PKCE with:

- State validation.
- Nonce validation.
- JWKS signature verification.
- Issuer/audience checks.
- `azp` handling where relevant.
- Token time checks.
- Optional controlled auto-provisioning.

Client secrets are encrypted at rest. Keep issuer endpoints HTTPS and carefully review automatic role/user provisioning policy.

Local authentication remains available unless you intentionally place an external access policy around SHAM.

## VPN-only SHAM dashboard example

The dashboard/API is an administrative control plane. If public access is not
needed, do not publish its port; expose only the VPN UDP port and reach SHAM
through a private Docker network. Public site traffic can still use the shared
edge or Cloudflare Tunnel independently.

The following is a topology example using
[LinuxServer.io WireGuard](https://docs.linuxserver.io/images/docker-wireguard/).
It is not a replacement for reviewing LinuxServer's current image
documentation, WireGuard peer configuration, and your host firewall policy.

```text
administrator device ── WireGuard UDP/51820 ── wireguard container
                                              │ private Docker network
                                              └── sham:8080
```

Start from a copy of SHAM's Compose file and **remove** its host mapping for
`8080:8080`. Keep `80`/`443` only if you need direct shared-edge traffic. Give
the SHAM and WireGuard containers a dedicated network with stable addresses:

```yaml
services:
  sham:
    # Do not publish 8080 on the host.
    ports:
      - "80:80"       # omit if all public traffic uses Cloudflare Tunnel
      - "443:443"     # omit if all public traffic uses Cloudflare Tunnel
    networks:
      sham_vpn:
        ipv4_address: 172.30.0.10

  wireguard:
    image: lscr.io/linuxserver/wireguard:latest
    container_name: sham-wireguard
    cap_add:
      - NET_ADMIN
      - SYS_MODULE
    environment:
      - PUID=1000
      - PGID=1000
      - TZ=Europe/Amsterdam
      - SERVERURL=vpn.example.example
      - SERVERPORT=51820
      - PEERS=admin
      - INTERNAL_SUBNET=10.13.13.0
      # Include SHAM's private Docker subnet in generated peer routes.
      - ALLOWEDIPS=172.30.0.0/24
    volumes:
      - ./wireguard-config:/config
      - /lib/modules:/lib/modules:ro
    ports:
      - "51820:51820/udp"
    sysctls:
      - net.ipv4.conf.all.src_valid_mark=1
    networks:
      sham_vpn:
        ipv4_address: 172.30.0.2

networks:
  sham_vpn:
    ipam:
      config:
        - subnet: 172.30.0.0/24
```

Import the generated `admin` peer configuration, then browse to
`http://172.30.0.10:8080` only after the VPN connects. Configure TLS with an
internal CA or a VPN-reachable reverse proxy if plaintext HTTP on the tunnel is
not acceptable. Do not expose the dashboard through `0.0.0.0:8080`, a broad
Docker port mapping, or a Cloudflare Tunnel merely because the login page has
authentication.

Before relying on this topology, verify all of the following from a machine
outside the VPN: UDP/51820 is the only intended administrative ingress,
`http://SERVER_PUBLIC_IP:8080` fails, and the dashboard is reachable through
the WireGuard peer. Docker-network forwarding behavior can vary with host
firewall rules; if peers cannot reach `172.30.0.10`, add a narrow forwarding
rule for `wg0` to `172.30.0.0/24` instead of opening port 8080 publicly.

## Local account security

SHAM supports:

- Password login.
- TOTP.
- Single-use recovery codes.
- WebAuthn/passkeys.
- Administrator-managed user/account policy.

Store recovery codes offline. Removing a second factor should require the same care as changing a password.

## API tokens

API tokens are personal, independently revocable bearer credentials intended for CLI/CI automation.

Available scopes are `read`, `logs:read`, `deploy`, `sites:control`, and `*`.

Prefer narrow scopes and a dedicated automation identity. The token plaintext is displayed once and only its hash is retained.

See [API and CLI](api-and-cli.md).

## Docker trust boundary

Docker daemon access is effectively host-administration access. SHAM validates hosted Compose/runtime configurations to block common escape paths, but that does not turn one Docker daemon into a hostile multi-tenant security boundary.

The Docker socket is held only by the separate **Runtime Agent** process, never by the internet-facing control plane (dashboard/API/webhooks). The agent authenticates every request from the control plane with a locally generated, timing-safe-compared token over a Unix socket, exposes only a small allowlist of typed operations (no generic Docker/shell passthrough), and independently re-validates every privileged invariant (SHAM-managed resource labels, mount paths confined to SHAM's data directory, no privileged/host-network/host-PID/host-IPC containers, no Docker-socket or arbitrary host bind mounts) rather than trusting that the control plane already checked. This means a compromise of the control plane no longer directly implies Docker/root-level host access — but mounting the socket into the agent still grants it that authority, so the agent remains a privileged component and the recommendations below still apply to it.

Recommendations:

- Keep SHAM's control plane itself minimally privileged; it no longer needs the Docker socket at all.
- Mount the Docker socket into the Runtime Agent only when required, and treat that host/VM as trusted infrastructure.
- Never expose the Runtime Agent's Unix socket or token beyond the local host; it is not designed to be reachable over a network.
- Review Dockerfiles, Compose files, and repository manifests.
- Keep supporting services private.
- Use named volumes instead of host bind mounts.
- Use dedicated infrastructure/VM boundaries for mutually untrusted tenants.

## Plugin trust boundary

Server-side JavaScript plugins are trusted code. Worker isolation helps contain event-loop failure/blocking but is not an OS sandbox.

Only install reviewed plugins. Use signatures/trusted signing keys where appropriate.

The Plugin playground validates manifests and previews browser code in a sandboxed iframe; it intentionally never executes server plugin code.

## SHAM update trust boundary

The in-app updater accepts reviewed update archives, supports publisher signature verification, and keeps active application releases beneath persistent data storage.

Updates that change runtime dependency declarations are rejected by the in-app code update path and should be delivered through a reviewed image/manual dependency-aware upgrade.

The managed update paths include application source/assets, `docs/`, and `bin/` so documentation and CLI behavior stay aligned with the active release.

## Release hygiene

Before packaging/publishing source:

```bash
npm run release:check
git status --short
```

The release check runs syntax/tests and source-tree safety checks including generated-secret detection.

Never ship:

- `.env` with real credentials.
- `node_modules`.
- `data/.jwt-secret`.
- Master-key files/runtime keyring material.
- Live SQLite database/WAL files.
- Backup payloads.
- Git credentials/deploy keys.
- Other instance-runtime state.
