# Authsome

[![PyPI version](https://img.shields.io/pypi/v/authsome.svg)](https://pypi.org/project/authsome/)
[![Python 3.13+](https://img.shields.io/pypi/pyversions/authsome.svg)](https://pypi.org/project/authsome/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![PyPI downloads](https://img.shields.io/pypi/dm/authsome.svg)](https://pypi.org/project/authsome/)

**OAuth2 and API key management for agents. Local. Headless. Portable.**

Authenticate once. Get valid headers anywhere. No server, no account, no cloud.

Authsome is a portable local authentication library for AI agents and developer tools. Manage third-party credentials locally with encrypted storage, supporting OAuth2 and API key flows.

Built for agents making tool calls to MCP URLs — Authsome handles the credential lifecycle so your code just asks for headers.

---

## The Problem

Agents and developer tools need to call APIs. Authentication keeps getting in the way:

- OAuth2 flows are stateful — browsers, callbacks, token exchange
- Tokens expire — refresh logic gets reinvented in every project
- API keys get hardcoded or lost in shell profiles
- There's no standard answer to: *"give me a valid GitHub token right now"*

Authsome is a local authentication layer that handles login, logout, and token refresh for your agents and scripts. You ask for headers. You get headers. It's the agent's job to call APIs — it's Authsome's job to keep the credentials fresh.

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

## Installation

```bash
# Recommended: Use via uvx without installing
uvx authsome <cmd>

# Or install globally via pipx
pipx install authsome

# Or install as a Python library
pip install authsome
```

---

## Quick Start

```bash
# Initialize Authsome
authsome init

# Login to providers
authsome login github      # opens browser, completes OAuth2 PKCE flow
authsome login openai      # prompts for API key

# Verify your connections
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

## The Authsome Workflow

Every credential request in Authsome follows three simple phases in order:
**SEARCH** → **LOGIN** → **USE**

### Phase 1 — SEARCH

**Goal:** Find the provider and check for existing connections.

Before authenticating, you should check what providers are available and whether you already have an active connection.

```bash
authsome list
```

This returns arrays of `bundled` and `custom` providers, each detailing its `name`, `auth_type`, and existing `connections`.

**Decision Paths:**
- **Provider found with a connected connection:** You're ready to go. Skip directly to **Phase 3 — USE**.
- **Provider found, no connections:** You need to authenticate. Proceed to **Phase 2 — LOGIN**.
- **Provider NOT found:** You must create and register a custom provider (see the Custom Providers section below).

### Phase 2 — LOGIN

**Goal:** Authenticate and store credentials securely. 

Authsome automatically handles the complexity of OAuth2 browser flows, dynamic client registration, and API key prompts.

#### Step 2.1: Determine the Auth Flow
Providers often support multiple authentication methods. You can inspect a provider to see what flows it supports:
```bash
authsome inspect <provider>
```
Look for `oauth.supports_dcr`, `oauth.supports_device_flow`, and the default `flow`. If a provider supports Dynamic Client Registration (`dcr_pkce`), it's the path of least resistance because no pre-registered `client_id` is needed. Otherwise, you may choose between `pkce` (browser) and `device_code` (headless).

#### Step 2.2: Choose a Connection Name
If you plan to use multiple accounts for the same provider (e.g., a `work` account and a `personal` account), you can specify a connection name using the `--connection` flag. Otherwise, it defaults to `"default"`.

#### Step 2.3: Run Login
```bash
# Default flow (browser PKCE or interactive API key prompt)
authsome login github

# Specify a custom connection name
authsome login openai --connection work

# Override flow to device code
authsome login github --flow device_code

# First-time login for provider requiring client credentials
authsome login github --client-id "my_client_id" --client-secret "my_client_secret"

# API key provider (bypass interactive prompt by passing key)
authsome login openai --api-key "sk-..."
```

**Note on Credentials:** Authsome stores client IDs and secrets securely in your profile. If you are logging in with an OAuth provider that doesn't use Dynamic Client Registration, you MUST pass your own app credentials via `--client-id` and `--client-secret`. Authsome saves them so you don't need to provide them again on subsequent logins.

#### Step 2.4: Verify
Confirm your status is `"connected"`:
```bash
authsome get <provider>
```

### Phase 3 — USE

**Goal:** Export credentials so your applications or agents can make authenticated tool calls.

#### Option A: Run a Command with Injected Credentials (Recommended)
This is the most secure method because credentials are injected directly into the subprocess environment and are completely ephemeral.
```bash
authsome run --provider github -- curl -H "Authorization: Bearer $GITHUB_ACCESS_TOKEN" https://api.github.com/user
```
You can inject multiple providers at once:
```bash
authsome run --provider github --provider openai -- python my_script.py
```

#### Option B: Export to Current Shell
Credentials become environment variables (e.g., `GITHUB_ACCESS_TOKEN`, `OPENAI_API_KEY`) as defined in the provider's `export.env` mapping.
```bash
eval "$(authsome export openai --format shell)"
```

#### Option C: Retrieve a Single Field
Extract a specific value (like a raw token) to use in scripts.
```bash
TOKEN=$(authsome get github --field access_token --show-secret)
```

#### Option D: Use in Python
If you're building an agent or app, use Authsome programmatically to fetch headers automatically.
```python
from authsome import AuthClient

client = AuthClient()

# Initialize the store (creates ~/.authsome) if needed
client.init()

# Prompt for login if connection doesn't exist
if not client.get_connection("github"):
    client.login("github")

# Get formatted headers for your HTTP requests
headers = client.get_auth_headers("github")
# → {"Authorization": "Bearer ..."}
```

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

Add your own custom providers when the target service is not bundled natively.

---

## 🛠 CLI Reference

Full command and flag reference for the `authsome` CLI. All commands support `--profile` to switch between credential sets (e.g., personal vs. work).

### Global Flags

| Flag | Description |
|------|-------------|
| `--quiet` | Suppress non-essential output. |
| `--no-color` | Disable ANSI colors. |

### Commands

| Command | Description |
|---------|-------------|
| `init` | Initialize `~/.authsome` directory and default profile. |
| `whoami` | Show home directory and encryption mode. |
| `doctor` | Run health checks on directory layout and encryption. |
| `list` | List all providers (bundled + custom) and their connection states. |
| `inspect <provider>` | Show the full provider definition schema. |
| `login <provider>` | Authenticate with a provider using its configured flow. |
| `get <provider>` | Get connection metadata (secrets redacted by default). |
| `export <provider>` | Export credentials in `env`, `shell`, or `json` format. |
| `run --provider <p> -- <cmd>` | Run a subprocess with injected credentials. |
| `revoke <provider>` | Revoke credentials remotely (if supported) and remove locally. |
| `remove <provider>` | Remove local credentials without remote revocation. |
| `register <path>` | Register a custom provider from a JSON file. |

### Command Details

#### `login`
```bash
authsome login <provider> [OPTIONS]
```
| Option | Description |
|--------|-------------|
| `--connection <name>` | Connection name (default: `default`). |
| `--flow <type>` | Override the auth flow (`pkce`, `device_code`, `dcr_pkce`, `api_key_prompt`, `api_key_env`). |
| `--scopes <s1,s2>` | Comma-separated scopes to request. |
| `--client-id <id>` | OAuth client ID. |
| `--client-secret <secret>` | OAuth client secret. |
| `--api-key <key>` | API key to bypass interactive prompt. |

#### `get`
```bash
authsome get <provider> [OPTIONS]
```
| Option | Description |
|--------|-------------|
| `--connection <name>` | Connection name (default: `default`). |
| `--field <field>` | Return only a specific field. |
| `--show-secret` | Reveal encrypted secrets. |

#### `export`
```bash
authsome export <provider> [OPTIONS]
```
| Option | Description |
|--------|-------------|
| `--connection <name>` | Connection name (default: `default`). |
| `--format <fmt>` | Output format: `env` (default), `shell`, or `json`. |

#### `run`
```bash
authsome run --provider <p1> [--provider <p2>] -- <command>
```
Runs `<command>` as a subprocess with credentials from the specified providers injected into its environment. Multiple `--provider` flags can be used.

#### `register`
```bash
authsome register <path/to/provider.json> [OPTIONS]
```
| Option | Description |
|--------|-------------|
| `--force` | Overwrite an existing provider with the same name. |

#### `revoke` / `remove`
```bash
authsome revoke <provider> [--connection <name>]
authsome remove <provider> [--connection <name>]
```
`revoke` attempts remote revocation first (if supported), then removes locally. `remove` only deletes local state.

---

## 🧩 Custom Providers

You can register custom providers when the target service is not bundled natively by Authsome.

### Step 1: Research the Service
Determine what authentication methods the target service supports:
- **OAuth2**: Find the `authorization_url`, `token_url`, supported `scopes`, and whether it supports PKCE, device flow, or DCR (Dynamic Client Registration).
- **API keys / personal access tokens**: Find the header format and relevant environment variable conventions.

### Step 2: Choose the Right Flow

> **Priority rule for OAuth2:** When a service supports DCR, **always prefer `dcr_pkce`**. It requires no pre-registered OAuth app or `client_id` — the path of least resistance.

| `flow` value | `auth_type` | When to use |
|--------------|-------------|-------------|
| `dcr_pkce` | `oauth2` | **Preferred.** Dynamic Client Registration, then PKCE. No `client_id` needed. |
| `pkce` | `oauth2` | Standard OAuth2 with PKCE. Opens a browser. Needs `client_id`. |
| `device_code` | `oauth2` | Headless OAuth2. User enters a code on a separate device. Needs `client_id`. |
| `api_key_prompt` | `api_key` | Interactively prompts the user to paste an API key. |
| `api_key_env` | `api_key` | Reads the API key from an environment variable (`api_key.env_var`). |

### Step 3: Write the Provider JSON

Use `"env:VAR_NAME"` syntax in the `"client"` block to avoid hardcoding secrets.
The `"export"` → `"env"` block controls how credentials map to environment variables for `authsome export --format shell` and `authsome run`.

#### Template A — OAuth2 Provider (PKCE)
```json
{
  "schema_version": 1,
  "name": "x",
  "display_name": "X (Twitter)",
  "auth_type": "oauth2",
  "flow": "pkce",
  "oauth": {
    "authorization_url": "https://twitter.com/i/oauth2/authorize",
    "token_url": "https://api.twitter.com/2/oauth2/token",
    "scopes": ["tweet.read", "tweet.write", "users.read", "offline.access"],
    "pkce": true,
    "supports_device_flow": false,
    "supports_dcr": false
  },
  "client": {
    "client_id": "env:X_CLIENT_ID",
    "client_secret": null
  },
  "export": {
    "env": {
      "access_token": "X_ACCESS_TOKEN",
      "refresh_token": "X_REFRESH_TOKEN"
    }
  }
}
```

#### Template B — API Key Provider
```json
{
  "schema_version": 1,
  "name": "my_service",
  "display_name": "My Service",
  "auth_type": "api_key",
  "flow": "api_key_prompt",
  "api_key": {
    "input_mode": "prompt",
    "header_name": "Authorization",
    "header_prefix": "Bearer",
    "env_var": "SERVICE_API_KEY"
  },
  "export": {
    "env": {
      "api_key": "SERVICE_API_KEY"
    }
  }
}
```

### Step 4: Register the Provider

```bash
authsome register /path/to/provider.json
```
Use `--force` to overwrite an existing configuration. You can also register providers dynamically using the Python Client API.

---

## 🏗 Architecture & Storage

### How It Works

```
┌─────────────┐     ┌──────────────┐     ┌───────────────────┐
│  Your App /  │────▶│  AuthClient  │────▶│  Provider Registry │
│    Agent     │     │              │     │  (bundled + local) │
└─────────────┘     └──────┬───────┘     └───────────────────┘
                           │
                    ┌──────┴───────┐
                    │  Auth Flows  │
                    ├──────────────┤
                    │ • PKCE       │  ← browser-based OAuth
                    │ • Device Code│  ← headless OAuth
                    │ • DCR + PKCE │  ← dynamic client reg
                    │ • API Key    │  ← prompt or env import
                    └──────┬───────┘
                           │
                    ┌──────┴───────┐
                    │   Storage    │
                    ├──────────────┤
                    │ SQLite KV    │  ← per-profile store
                    │ AES-256-GCM  │  ← field-level encryption
                    │ OS Keyring   │  ← master key storage
                    └──────────────┘
```

`AuthClient` is the single entry point. It resolves the right flow per provider, manages token refresh transparently, and delegates persistence to a per-profile SQLite store. Profiles let you isolate credential sets (e.g., personal, work, a specific agent).

### Storage Layout

```
~/.authsome/
  version              # store format version
  config.json          # global settings (incl. encryption.mode)
  master.key           # encryption key (only in local_key mode)
  providers/           # user-registered provider definitions
  profiles/
    default/
      store.db         # encrypted credential store (SQLite)
      metadata.json    # profile metadata
      lock             # advisory write lock
```

### Encryption Modes

Authsome uses AES-256-GCM for field-level encryption. You choose where the master key lives via `config.json`:

```json
{
  "encryption": { "mode": "local_key" }
}
```

| Mode | Master Key Location | Best For |
|------|-------------------|----------|
| `local_key` | `~/.authsome/master.key` (file, 0600 permissions) | Headless servers, CI, containers |
| `keyring` | OS credential manager (macOS Keychain, GNOME Keyring, etc.) | Desktop environments |

Default is `local_key` for maximum compatibility.

---

## 🔒 Security

- All tokens and API keys are **encrypted at rest** with AES-256-GCM
- Master key is stored in the **OS keyring** or **local file** — user's choice
- Secrets are **never printed** unless explicitly requested
- `authsome run` injects credentials into subprocess env **without logging**

## Environment Variables

| Variable | Purpose |
|----------|---------|
| `AUTHSOME_HOME` | Override the default `~/.authsome` directory |

## License

MIT — see [LICENSE](LICENSE).