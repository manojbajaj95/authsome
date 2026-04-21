# authsome

[![PyPI version](https://img.shields.io/pypi/v/authsome.svg)](https://pypi.org/project/authsome/)
[![Python 3.13+](https://img.shields.io/pypi/pyversions/authsome.svg)](https://pypi.org/project/authsome/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![PyPI downloads](https://img.shields.io/pypi/dm/authsome.svg)](https://pypi.org/project/authsome/)

**OAuth2 and API key management for agents. Local. Headless. Portable.**

Authenticate once. Get valid headers anywhere. No server, no account, no cloud.

---

## The Problem

Agents and developer tools need to call APIs. Authentication keeps getting in the way:

- OAuth2 flows are stateful — browsers, callbacks, token exchange
- Tokens expire — refresh logic gets reinvented in every project
- API keys get hardcoded or lost in shell profiles
- There's no standard answer to: *"give me a valid GitHub token right now"*

Authsome is a local authentication layer that handles login, logout, and token refresh for your agents and scripts. You ask for headers. You get headers. It's the agent's job to call APIs — it's authsome's job to keep the credentials fresh.

---

## What It Does

- **Login flows** — PKCE, Device Code, Dynamic Client Registration, API key prompt
- **Automatic token refresh** — tokens are refreshed before expiry, transparently
- **One call for valid headers** — always returns a usable `Authorization` header
- **Subprocess injection** — run any command with credentials in its environment
- **Headless-friendly** — Device Code flow works in CI, SSH sessions, and remote agents
- **35 bundled providers** — GitHub, Google, OpenAI, Linear, Slack, and more, zero config
- **Portable** — follows your `~/.authsome` directory; works on any machine you're on

---

## Quick Start

```bash
pip install authsome
authsome init
authsome login github      # opens browser, completes OAuth2 PKCE flow
authsome login openai      # prompts for API key
authsome list              # all authenticated services and token status
```

```python
from authsome import AuthClient

client = AuthClient()

# Always returns a valid, refreshed Authorization header
headers = client.get_auth_headers("github")
# → {"Authorization": "Bearer ghu_..."}

headers = client.get_auth_headers("openai")
# → {"Authorization": "Bearer sk-..."}

# Inject credentials into any subprocess — no env files needed
client.run(["python", "script.py"], providers=["github", "openai"])
```

---

## Why Authsome

Your agent should call APIs, not manage auth state. Authsome is the authentication layer between your agent and the services it uses — local, offline-capable, and zero-dependency on external infrastructure.

| | Authsome | Manual `.env` | Roll your own |
|--|----------|--------------|--------------|
| OAuth2 flows (PKCE, Device, DCR) | ✅ | ❌ | build it |
| Automatic token refresh | ✅ | ❌ | build it |
| 35 providers, zero config | ✅ | ❌ | build it |
| Headless / CI / SSH | ✅ | ✅ | varies |
| Multi-account per provider | ✅ | ❌ | build it |
| No server, no account | ✅ | ✅ | ✅ |

---

## CLI Reference

```bash
# Setup
authsome init                          # initialize ~/.authsome
authsome doctor                        # verify installation health

# Authentication
authsome login github                  # OAuth2 browser flow (PKCE)
authsome login github --flow device    # headless Device Code flow
authsome login openai                  # API key prompt
authsome logout github                 # revoke token remotely + remove locally
authsome remove github                 # remove local state only

# Inspect
authsome list                          # all connections + token status
authsome get github                    # connection metadata (secrets redacted)
authsome get github --show-secret      # reveal token
authsome get github --field status     # extract one field

# Export & run
authsome export github --format shell  # → export GITHUB_TOKEN=...
authsome run --provider openai -- python script.py
```

All commands support `--json` for machine-readable output and `--profile` to switch between credential sets (e.g., personal vs. work).

---

## Bundled Providers

35 providers, ready to use with zero configuration:

**Developer & Productivity**
`github` · `google` · `linear` · `okta` · `zapier` · `calendly` · `savvycal` · `typeform` · `buffer`

**AI & Data**
`openai` · `clearbit` · `ahrefs` · `semrush` · `g2` · `keywords-everywhere`

**Marketing & Email**
`mailchimp` · `klaviyo` · `brevo` · `sendgrid` · `postmark` · `resend` · `beehiiv` · `instantly` · `lemlist`

**Sales & CRM**
`apollo` · `hunter` · `intercom` · `mention-me` · `rewardful` · `tolt`

**Media & Analytics**
`wistia` · `livestorm` · `optimizely` · `x` · `dub`

Add your own by dropping a JSON file in `~/.authsome/providers/<name>.json`.

---

## Technical Deep Dive

### Architecture

```
┌─────────────────┐     ┌──────────────┐     ┌────────────────────┐
│   Agent / Tool  │────▶│  AuthClient  │────▶│  Provider Registry  │
│                 │     │              │     │  (bundled + local)  │
└─────────────────┘     └──────┬───────┘     └────────────────────┘
                               │
                        ┌──────┴───────┐
                        │  Auth Flows  │
                        ├──────────────┤
                        │ • PKCE       │  ← browser OAuth2
                        │ • Device Code│  ← headless / CI
                        │ • DCR + PKCE │  ← dynamic client reg
                        │ • API Key    │  ← prompt or env import
                        └──────┬───────┘
                               │
                        ┌──────┴───────┐
                        │   Storage    │
                        ├──────────────┤
                        │ SQLite KV    │  ← per-profile credential store
                        │ AES-256-GCM  │  ← encrypted at rest
                        └──────────────┘
```

`AuthClient` is the single entry point. It resolves the right flow per provider, manages token refresh transparently, and delegates persistence to a per-profile SQLite store. Profiles let you isolate credential sets (e.g., personal, work, a specific agent).

### Auth Flows

| Flow | When to Use |
|------|------------|
| `pkce` | Browser-capable environments with a pre-registered OAuth client |
| `device_code` | Headless servers, CI, SSH sessions — no browser required |
| `dcr_pkce` | Services supporting Dynamic Client Registration — no pre-registration needed |
| `api_key_prompt` | Interactive terminal, prompts securely via `getpass` |
| `api_key_env` | Import a key already present in an environment variable |

### Custom Providers

**Via JSON** (`~/.authsome/providers/my-service.json`):
```json
{
  "name": "my-service",
  "display_name": "My Service",
  "auth_type": "api_key",
  "flow": "api_key_prompt",
  "api_key": {
    "header_name": "X-API-Key",
    "header_prefix": "",
    "env_var": "MY_SERVICE_KEY"
  }
}
```

**Via Python:**
```python
from authsome import ProviderDefinition, AuthType, FlowType
from authsome.models.provider import ApiKeyConfig

client.register_provider(ProviderDefinition(
    name="my-service",
    display_name="My Service",
    auth_type=AuthType.API_KEY,
    flow=FlowType.API_KEY_PROMPT,
    api_key=ApiKeyConfig(header_name="X-API-Key", header_prefix="", env_var="MY_SERVICE_KEY"),
))
```

### Multiple Connections

Same provider, multiple accounts:

```python
client.login("openai", connection_name="personal")
client.login("openai", connection_name="work")

headers = client.get_auth_headers("openai", connection="work")
```

### Storage Layout

```
~/.authsome/
  config.json          # global settings (encryption mode, active profile)
  master.key           # encryption key (chmod 0600)
  providers/           # user-defined provider definitions
  config.json          # global settings (encryption mode, active profile)
  master.key           # encryption key (chmod 0600)
  providers/           # user-defined provider definitions
  profiles/
    default/
      store.db         # credential store (SQLite, values AES-256-GCM encrypted)
      store.db         # credential store (SQLite, values AES-256-GCM encrypted)
      lock             # advisory write lock
```

### Environment Variables

| Variable | Purpose |
|----------|---------|
| `AUTHSOME_HOME` | Override the default `~/.authsome` directory |

---

---

## License

MIT — see [LICENSE](LICENSE).
