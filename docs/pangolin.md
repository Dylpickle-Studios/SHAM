# Pangolin support

SHAM supports Pangolin through a supervised, instance-wide [Newt connector](https://github.com/fosrl/newt). Newt creates an outbound userspace WireGuard connection to Pangolin; no inbound public port is required for the connector itself.

```text
Internet
   ↓
Pangolin / Gerbil
   ↓ encrypted tunnel
Newt (supervised by SHAM)
   ↓
SHAM shared edge listener
   ↓ hostname routing
Site primary listener
```

## Configure it

1. In Pangolin, create a **Site** using a Newt connector and copy its endpoint, Newt ID, and Newt secret.
2. In SHAM, open **Settings → Instance → Pangolin connector**.
3. Enter the Pangolin endpoint (for example `https://pangolin.example.com`), ID, and secret, enable the connector, and save.
4. Wait for SHAM to report **Connected**. Newt logs are also written to the SHAM instance log with secrets redacted.
5. In Pangolin, create a public resource for the site. Target SHAM's shared HTTP edge listener and configure the resource to send the site's hostname as its HTTP Host header.

For a source installation, install Newt and ensure it is on SHAM's `PATH`, or set `SHAM_NEWT_BIN=/absolute/path/to/newt`. The published SHAM container includes Newt.

## Resource targets

With the standard Compose deployment, SHAM and Newt run in the same control-plane container. A Pangolin HTTP resource can therefore target the shared edge listener at `http://127.0.0.1:80` (or the configured `SHAM_EDGE_HTTP_PORT`). The Host header must equal the site's configured domain, because SHAM's edge proxy routes by hostname.

One Newt connector can serve several Pangolin resources and SHAM sites. Create one Pangolin resource per public hostname. Pangolin also supports TCP/UDP resources, but SHAM's web edge is HTTP(S); target a deliberately configured private listener directly only when you want raw TCP/UDP forwarding and have reviewed that exposure.

SHAM intentionally does not use Pangolin's Docker discovery and does not mount the Docker socket into Newt. It also does not create or edit Pangolin resources automatically. Those choices keep the privileged boundary explicit and avoid coupling SHAM to Pangolin's control-plane API.

## Secrets and process isolation

- The Newt secret is encrypted with SHAM's normal secret store and is never returned by the API.
- SHAM supplies `PANGOLIN_ENDPOINT`, `NEWT_ID`, and `NEWT_SECRET` through the child environment, not command-line arguments.
- Connector output is bounded and the configured secret is redacted before it reaches SHAM logs.
- Newt runs without Docker-socket access. Do not add a socket mount merely for automatic target discovery.
- The tunnel is an ingress path. Continue to use SHAM authentication, firewall rules, and Pangolin access controls as appropriate.

## Operations and API

The connector starts on SHAM startup, is restarted with bounded exponential backoff after an unexpected exit, and stops cleanly with SHAM. Administrators can save or restart it in the Instance settings.

```text
GET  /api/admin/operations
PUT  /api/admin/pangolin-tunnel
POST /api/admin/pangolin-tunnel/restart
```

The versioned aliases under `/api/v1` are also supported. The PUT body accepts only `enabled`, `endpoint`, `newtId`, `secret`, and `clearSecret`; unknown fields are rejected.

## Troubleshooting

- **Newt unavailable:** install it or set `SHAM_NEWT_BIN`. For containers, update to a SHAM image that includes Newt.
- **Credentials required:** regenerate/copy the site connector values from Pangolin, then replace the saved secret.
- **Newt runs but the resource is unavailable:** verify the Pangolin resource target is reachable from the SHAM container and that its Host header matches the SHAM site domain.
- **Wrong site or SHAM 404:** the shared edge received a missing or incorrect hostname.
- **Repeated restarts:** inspect the bounded connector log in Instance settings and the SHAM instance logs; verify DNS/TLS connectivity from SHAM to the Pangolin endpoint.

Newt is a separate upstream project. Pin and upgrade it with the SHAM image rather than allowing a child process to self-update.
