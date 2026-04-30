# authsome

[![PyPI version](https://img.shields.io/pypi/v/authsome.svg)](https://pypi.org/project/authsome/)
[![Python 3.13+](https://img.shields.io/pypi/pyversions/authsome.svg)](https://pypi.org/project/authsome/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![PyPI downloads](https://img.shields.io/pypi/dm/authsome.svg)](https://pypi.org/project/authsome/)
[![Tests](https://github.com/manojbajaj95/authsome/actions/workflows/test.yml/badge.svg)](https://github.com/manojbajaj95/authsome/actions/workflows/test.yml)
[![codecov](https://codecov.io/gh/manojbajaj95/authsome/branch/main/graph/badge.svg)](https://codecov.io/gh/manojbajaj95/authsome)

```text
              __  __
  ____ ___  _/ /_/ /_  _________  ____ ___  ___
 / __ `/ / / / __/ __ \/ ___/ __ \/ __ `__ \/ _ \
/ /_/ / /_/ / /_/ / / (__  ) /_/ / / / / / /  __/
\__,_/\__,_/\__/_/ /_/____/\____/_/ /_/ /_/\___/
```

**Local auth for AI agents.**

Log in once via OAuth2/API Key. Authsome keeps the credentials fresh for every AI agent.

---

## Why Agents Are Different

Agents need API access that survives outside an interactive app:

- agents run without interactive sessions
- tokens expire, rotate, and need refresh
- tool access must work in scripts, cron, CI, SSH, background workers, and parallel pipelines

Hardcoded env tokens leak or go stale. DIY auth means rebuilding flow logic, token storage, refresh handling, expiry checks, and per-provider config for every project.

Authsome is the local credential layer agents can call at runtime.

- **No credential sprawl.** One encrypted store — every provider, every agent, one place.
- **No SaaS, no privacy trade-off.** Credentials never leave your machine. No third-party cloud dependency.
- **No browser required at runtime.** Setup can use browser PKCE, device code, or a browser bridge for secure API key entry. After that, agents run headlessly in CI, SSH, cron, workers, or parallel pipelines.

---

## How It Works

The CLI is the agent's interface: setup once, then inject fresh credentials whenever a tool runs.

```text
┌──────────┐        authsome         ┌──────────────┐
│  Agent   │ ──────────────────────▶ │ Local Vault  │
└──────────┘                         └──────┬───────┘
     ▲                                      │
     │       fresh token / API key          │ encrypted
     └──────────────────────────────────────┘
```

Authenticate once:

```bash
authsome login github
```

Then agents get valid credentials on demand:

```bash
authsome get github --field access_token --show-secret
# → ghu_...

authsome export github --format env
# → Successfully exported credentials to environment.

authsome run python my_agent.py
# runs behind a local auth proxy that injects headers at request time
# without exposing secrets in the child process environment.
# matched automatically via provider host_url (e.g. api.openai.com)
```

Credentials are stored locally, encrypted at rest, and refreshed before expiry. No server. No account. No cloud.

---

## Why Authsome

| | authsome | Hardcoded env tokens | DIY |
|--|:--------:|:--------------------:|:---:|
| Automatic token refresh | ✅ | ❌ | build it |
| OAuth2 + API keys | ✅ | ❌ | build it |
| Runtime headless use | ✅ | ✅ | varies |
| Local — no SaaS dependency | ✅ | ✅ | ✅ |
| Built-in providers, zero config | ✅ | ❌ | ❌ |
| Multi-account per provider | ✅ | ❌ | build it |

Authsome gives agents one command for a valid token, without scattering long-lived secrets across every project.

---

## Quick Start

```bash
pip install authsome
authsome init
authsome login github                  # opens browser, completes PKCE flow
authsome login github --flow device_code  # headless: Device Code, works over SSH and CI
authsome login openai                  # secure API key entry via browser bridge
authsome list                          # all connections + token status
```

## Docs

- [CLI reference](docs/cli.md)
- [Providers](docs/providers.md)
- [Architecture](docs/architecture.md)
- [Manual testing guide](docs/manual-testing.md)

## Specs

- [Authsome v1](specs/authsome-v1.md)

## License

MIT — see [LICENSE](LICENSE).
