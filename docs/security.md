# Security Notes

## Local Daemon V1

The first client-server implementation runs a local daemon bound to:

```text
127.0.0.1:7998
```

The daemon is intentionally local-only in v1. Hosted mode, user accounts, orgs,
and remote authorization are out of scope for this release.

Known v1 tradeoffs:

- The daemon relies on loopback binding for local access control.
- There is no local bearer token between CLI/proxy and daemon yet.
- Browser-rendered input forms do not include a per-session CSRF/form token yet.
- Active auth sessions are stored in daemon memory and are lost on daemon restart.
- Proxy-resolved credentials are cached only in memory for the lifetime of
  `authsome run`.

Secrets remain encrypted at rest through the Authsome vault. The server API does
not expose raw vault endpoints in v1.

Future hosted/server releases must add real authentication, authorization,
browser session protection, and stronger local daemon hardening where needed.
