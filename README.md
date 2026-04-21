# authsome

[![PyPI version](https://img.shields.io/pypi/v/authsome.svg)](https://pypi.org/project/authsome/)
[![Python 3.13+](https://img.shields.io/pypi/pyversions/authsome.svg)](https://pypi.org/project/authsome/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![PyPI downloads](https://img.shields.io/pypi/dm/authsome.svg)](https://pypi.org/project/authsome/)

**OAuth2 and API key management for agents. Local. Headless. No SaaS.**

Your agent calls APIs. Authsome keeps the credentials fresh.

---

## The Problem

Agents need to call APIs. The current answers are all wrong for agents:

- **Hardcode a PAT in `.env`** — works until the token expires, rotates, or leaks
- **Write OAuth2 yourself** — ~200 lines of flow logic, token storage, and refresh handling per project, using authlib or requests-oauthlib, reinvented every time
- **Nango** — full OAuth infrastructure, but it's a SaaS service with a server you have to run or pay for

None of these are designed for agents. They assume a browser, a web server, or a human in the loop at runtime.

Authsome is a local credential layer your agent invokes at runtime. Authenticate once, headlessly. After that, your agent asks for headers and gets them.

---

## How It Works

The CLI is the agent's interface — for setup and for runtime use.

Authenticate once:

```bash
authsome login github
```

Then the agent gets a valid, automatically-refreshed token on demand:

```bash
authsome get github --field access_token
# → ghu_...

authsome export github --format shell
# → export GITHUB_TOKEN=ghu_...

authsome run --provider github --provider openai -- python my_agent.py
# runs the script with GITHUB_TOKEN and OPENAI_API_KEY injected
```

Credentials are stored locally, encrypted at rest (AES-256-GCM), and refreshed before expiry. No server. No account. No cloud.

---

## Why Authsome

| | authsome | Hardcoded env tokens | DIY (authlib) | Nango |
|--|:--------:|:--------------------:|:-------------:|:-----:|
| OAuth2 flows (PKCE, Device Code, DCR) | ✅ | ❌ | build it | ✅ |
| Automatic token refresh | ✅ | ❌ | build it | ✅ |
| Headless (CI, SSH, no browser) | ✅ | ✅ | varies | ⚠️ |
| Local — no SaaS dependency | ✅ | ✅ | ✅ | ❌ |
| 35 providers, zero config | ✅ | ❌ | ❌ | ✅ |
| Multi-account per provider | ✅ | ❌ | build it | ✅ |
| One call for valid token | ✅ | ❌ | build it | ✅ |

**vs. DIY (authlib / requests-oauthlib):** authlib handles the HTTP exchange, but you still write the token store, refresh logic, expiry handling, and per-provider config — then repeat it for every project. Authsome eliminates that boilerplate entirely.

**vs. Nango:** Nango is the closest conceptual peer — it manages OAuth for you across many providers. The difference: Nango requires a hosted server (or their SaaS). Authsome runs locally, follows your `~/.authsome` directory, and has no external dependencies. It's the right choice when your agent runs on machines you control and you don't want infrastructure you don't own in the auth path.

---

## Quick Start

```bash
pip install authsome
authsome init
authsome login github                  # opens browser, completes PKCE flow
authsome login github --flow device    # headless: Device Code, works over SSH and CI
authsome login openai                  # prompts for API key
authsome list                          # all connections + token status
```

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

# Export & inject
authsome export github --format shell  # → export GITHUB_TOKEN=...
authsome run --provider openai -- python my_agent.py
```

All commands support `--json` for machine-readable output and `--profile` to switch between credential sets (e.g., personal vs. work vs. a specific agent).

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
│   Agent / Tool  │────▶│     CLI      │────▶│  Provider Registry  │
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

The CLI resolves the right flow per provider, manages token refresh transparently, and persists credentials in a per-profile SQLite store. Profiles let you isolate credential sets (e.g., personal, work, a specific agent).

### Auth Flows

| Flow | When to Use |
|------|------------|
| `pkce` | Browser-capable environments with a pre-registered OAuth client |
| `device_code` | Headless servers, CI, SSH sessions — no browser required |
| `dcr_pkce` | Services supporting Dynamic Client Registration — no pre-registration needed |
| `api_key_prompt` | Interactive terminal, prompts securely |
| `api_key_env` | Import a key already present in an environment variable |

### Custom Providers

Drop a JSON file at `~/.authsome/providers/my-service.json`:

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

Then use it like any bundled provider:

```bash
authsome login my-service
authsome get my-service --show-secret
```

### Multiple Connections

Same provider, multiple accounts:

```bash
authsome login openai --connection personal
authsome login openai --connection work

authsome get openai --connection work --show-secret
authsome run --provider openai --connection work -- python my_agent.py
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
