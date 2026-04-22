# CLI Reference

All commands support `--json` for machine-readable output and `--profile` to switch between credential sets, such as personal, work, or a specific agent.

## Setup

```bash
authsome init                          # initialize ~/.authsome
authsome doctor                        # verify installation health
```

## Authentication

```bash
authsome login github                  # OAuth2 browser flow (PKCE)
authsome login github --flow device    # Device Code flow for setup without local browser callback
authsome login github --force          # overwrite existing connection if it exists
authsome login openai                  # secure API key entry via browser bridge
authsome logout github                 # log out of connection + revoke remotely
authsome revoke github                 # remove all connections and client secrets
authsome remove github                 # uninstall local provider or reset bundled
```

Setup can use browser PKCE, device code, or a browser bridge for secure API key entry. After setup, agents can run headlessly in CI, SSH, cron, background workers, or parallel pipelines.

## Inspect

```bash
authsome list                          # all connections + token status
authsome get github                    # connection metadata, secrets redacted
authsome get github --show-secret      # reveal token
authsome get github --field status     # extract one field
```

## Export And Inject

```bash
authsome export github --format shell  # export GITHUB_TOKEN=...
authsome run --provider openai -- python my_agent.py
```

## Multiple Connections

Same provider, multiple accounts:

```bash
authsome login openai --connection personal
authsome login openai --connection work

authsome get openai --connection work --show-secret
authsome run --provider openai --connection work -- python my_agent.py
```
