# Architecture

Authsome is a local credential layer for AI agents. The CLI resolves the right flow per provider, manages token refresh transparently, and persists credentials in a per-profile encrypted store.

```text
┌─────────────────┐     ┌──────────────┐     ┌────────────────────┐
│   Agent / Tool  │────▶│     CLI      │────▶│  Provider Registry  │
│                 │     │              │     │  (bundled + local)  │
└─────────────────┘     └──────┬───────┘     └────────────────────┘
                               │
                        ┌──────┴───────┐
                        │  Auth Flows  │
                        ├──────────────┤
                        │ • PKCE       │  ← browser OAuth2 setup
                        │ • Device Code│  ← setup without callback
                        │ • DCR + PKCE │  ← dynamic client reg
                        │ • API Key    │  ← browser bridge or env import
                        └──────┬───────┘
                               │
                        ┌──────┴───────┐
                        │   Storage    │
                        ├──────────────┤
                        │ SQLite KV    │  ← per-profile credential store
                        │ AES-256-GCM  │  ← encrypted at rest
                        └──────────────┘
```

## Auth Flows

| Flow | When to use |
|------|-------------|
| `pkce` | Browser-capable setup with a pre-registered OAuth client |
| `device_code` | Setup from SSH, CI, or environments without local browser callback |
| `dcr_pkce` | Services supporting Dynamic Client Registration |
| `api_key` | API key providers, using browser bridge, masked prompt, or environment import |

After setup, agents can run without a browser or human in the loop. They ask Authsome for credentials at runtime and receive a fresh token or API key.

## Storage Layout

```text
~/.authsome/
  config.json          # global settings, encryption mode, active profile
  master.key           # encryption key, chmod 0600
  providers/           # user-defined provider definitions
  profiles/
    default/
      store.db         # credential store, SQLite with AES-256-GCM values
      lock             # advisory write lock
```

Profiles let you isolate credential sets, such as personal, work, or a specific agent.

## Environment Variables

| Variable | Purpose |
|----------|---------|
| `AUTHSOME_HOME` | Override the default `~/.authsome` directory |
