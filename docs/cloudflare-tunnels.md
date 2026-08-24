# Cloudflare Tunnels

SHAM can supervise a dedicated remotely managed `cloudflared` connector per site, or one instance shared connector for several site routes. The connector makes an outbound connection to Cloudflare, so a site can be published without exposing its origin listener directly to the Internet.

This feature is separate from SHAM's Cloudflare DNS/WAF integration:

- **Cloudflare Tunnel token** — authorizes `cloudflared` to run one remotely managed tunnel. Store this in the site's **Cloudflare Tunnel** settings.
- **Cloudflare API token + zone ID** — used by SHAM for DNS record reconciliation, WAF synchronization, and Cloudflare-assisted Certbot DNS challenges. A Tunnel connector does not require these values.
- **Cloudflare Tunnel management API token + account ID** — optional, separate credentials used only to discover, create, and reconcile remotely managed Tunnel routes. Do not reuse the DNS/Certbot token unless its permissions are deliberately scoped for both jobs.

## Prerequisites

1. A Cloudflare account with the hostname/domain you want to publish.
2. A remotely managed Cloudflare Tunnel created in Cloudflare Zero Trust.
3. `cloudflared` available to SHAM.

For managed route provisioning, also configure a separate Cloudflare account ID and API token under **Administration → Cloudflare and Certbot**. The token needs Tunnel/Connector read and write permissions; SHAM keeps it encrypted and never returns it to the browser.

The published SHAM Docker image includes `cloudflared`. For a direct source install, install `cloudflared` on the host or point `SHAM_CLOUDFLARED_BIN` at the executable.

Check **Settings → Instance → Cloudflare Tunnel connectors**. If the capability reports that `cloudflared` is unavailable, SHAM cannot start a connector until the executable is installed or configured.

## Configure a site tunnel

### 1. Prepare the SHAM site

Create or edit the site first. For domain-routed traffic, set the site's **Domain** to the hostname you will publish and enable the shared edge route.

The Docker Compose defaults run the shared HTTP edge listener on port 80 inside the SHAM container. If you run SHAM directly from source, `SHAM_EDGE_HTTP_PORT` defaults to `0`, so either configure an edge listener or route the tunnel to the site's own listener.

### 2. Create or select a remotely managed tunnel

Create a Cloudflared Tunnel in Cloudflare Zero Trust and paste its token into SHAM, or use **Provision managed tunnel** after configuring the separate Tunnel management API token. Provisioning creates a remotely managed Tunnel, stores its connector token encrypted, and reconciles the hostname route to the selected loopback origin service.

Treat the tunnel token as a credential. Anyone with it can run a connector for that tunnel.

### 3. Create or reconcile the public hostname route

Without managed routing, Cloudflare continues to own the public-hostname-to-origin mapping. With managed routing enabled, SHAM uses Cloudflare's remote Tunnel configuration API to reconcile only this site's hostname entry while preserving unrelated routes and the fallback rule.

For the standard Docker Compose setup with a domain-routed site, a typical service target is:

```text
http://localhost:80
```

`cloudflared` is running inside the SHAM container, so `localhost` in that configuration is the SHAM container. The shared edge listener then selects the correct SHAM site from the incoming hostname.

For a direct host install without the shared edge listener, point the route at the site's reachable listener instead, for example:

```text
http://127.0.0.1:4100
```

Use the actual site port shown in SHAM. If you route several sites through the shared edge listener, give each Cloudflare public hostname the hostname configured on its matching SHAM site.

### 4. Save the connector in SHAM

Open:

**Sites → select the site → Site settings → Cloudflare Tunnel**

Then:

1. Enter the new tunnel token.
2. Enable **Enable this site's connector**.
3. Select **Save tunnel**.
4. Check the connector status.

The token is encrypted at rest and is not returned to the browser after it is saved. SHAM accepts only credential-free HTTP(S) loopback origin services for managed routes, which prevents the connector configuration from becoming a general network pivot.

### 5. Verify the connector

Open **Settings → Instance → Cloudflare Tunnel connectors**. A healthy connector should reach **Connected** and report a healthy **Loopback origin**. These are separate signals: a connector can reach Cloudflare while its local target is unavailable or misrouted.

Then request the public hostname through Cloudflare and confirm that it reaches the intended SHAM site.

## Connector states

| State | Meaning |
|---|---|
| **Disabled** | The site's connector is not enabled. |
| **Starting** | `cloudflared` was launched and is registering connections. |
| **Connected** | `cloudflared` reported a registered Tunnel connection. |
| **Backoff** | The connector exited and SHAM is waiting before restarting it. |
| **Unavailable** | The configured `cloudflared` executable cannot be run. |
| **Error** | Startup, token decryption, or connector execution failed. |
| **Token needs attention** | An authentication failure was detected; retries pause until the token is replaced or an administrator explicitly restarts it. |
| **Stopped** | The connector is not currently running. |

SHAM supervises enabled connectors, uses jittered bounded restart backoff, rechecks an unavailable executable, and starts `cloudflared` with `--no-autoupdate`. Upgrade `cloudflared` by upgrading the SHAM image/package rather than allowing the child process to self-update.

## Dedicated versus shared connectors

Use a **dedicated connector** when a site should own its Tunnel token and lifecycle. Use the **instance shared connector** when several sites are configured as routes on the same remote Tunnel: configure the shared token once under **Settings → Instance → Cloudflare Tunnel connectors**, then select **Instance shared connector** for each site. SHAM does not start another `cloudflared` process for those sites.

The shared connector is best for many related hostnames. A site route remains individually visible and can still be reconciled through the optional control-plane API.

## Docker and origin exposure

A Tunnel is outbound-only, but publishing a site through a Tunnel does not automatically close ports you separately publish from Docker or the host firewall.

If Cloudflare Tunnel is the exclusive ingress path, enable **tunnel-only origin hardening**, bind the site listener to loopback, and remove unnecessary public Docker port mappings. SHAM rejects tunnel-only mode for `0.0.0.0`/`::` site listeners and warns that the shared edge listener itself must also remain private at the host/firewall layer.

Keep the dashboard itself separately protected. A site Tunnel token is for that site's connector; it is not a dashboard access-control mechanism.

## DNS/WAF synchronization versus Tunnel routing

These features can coexist, but they solve different problems:

- **Tunnel public hostname** routes Cloudflare traffic through `cloudflared` to an origin service.
- **DNS reconciliation** creates/updates a proxied DNS record using the Cloudflare API.
- **WAF synchronization** mirrors supported SHAM firewall entries into a hostname-scoped Cloudflare WAF custom rule.
- **Certbot DNS validation** uses Cloudflare API credentials to create DNS challenge records.

Do not enable DNS reconciliation just because you use a Tunnel. Use the Cloudflare configuration that matches how the public hostname is managed in your account.

## Troubleshooting

### `cloudflared` is unavailable

- Docker image: verify you are running the published/current SHAM image.
- Direct source install: install `cloudflared` and confirm the SHAM process can execute it.
- Custom location: set `SHAM_CLOUDFLARED_BIN=/absolute/path/to/cloudflared`.

### Connector enters Backoff or Error

Open the site's Tunnel settings and read the last connector error. Common causes are an invalid/revoked token, unreadable encrypted token after key/storage changes, or a missing executable.

Replace the token if needed, save, then use **Restart connector**.

### Connector says Connected but the hostname returns 502/Bad Gateway

The Cloudflare side is connected, but the configured service target is not reachable from the `cloudflared` process.

- Docker Compose shared edge: use the internal SHAM edge address such as `http://localhost:80`, not the host's public address.
- Direct install: verify the selected site/edge port is listening and reachable by the SHAM user.
- Confirm the Cloudflare public hostname exactly matches the domain configured on the SHAM site when using domain-based shared-edge routing.

### The wrong SHAM site answers

When a Tunnel route targets the shared edge listener, SHAM routes by the HTTP `Host` header. Confirm that each Cloudflare public hostname matches the intended site's configured Domain and that duplicate domains are not configured.

### Token was exposed

Rotate the Tunnel token in Cloudflare, paste the replacement token into the site, save it, and restart the connector. Clearing the token in SHAM removes the encrypted local copy but does not revoke the token in Cloudflare.

## API

Tunnel management is administrator-only. The current site endpoints are:

```text
GET  /api/admin/sites/:id/cloudflare-tunnel
PUT  /api/admin/sites/:id/cloudflare-tunnel
POST /api/admin/sites/:id/cloudflare-tunnel/restart
POST /api/admin/sites/:id/cloudflare-tunnel/provision
POST /api/admin/sites/:id/cloudflare-tunnel/reconcile
GET  /api/admin/cloudflare-tunnels/discover
```

The instance operations payload also exposes connector summaries so the dashboard can show all site connector states without returning token plaintext.

The instance-wide connector is now the supported shared-connector mode. Prefer dedicated connectors for isolation and shared mode when multiple site hostnames intentionally belong to one remote Tunnel.
