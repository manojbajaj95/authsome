# authsome

A portable local authentication library for AI agents and developer tools. Manage third-party credentials locally with encrypted storage, supporting OAuth2 and API key flows.

Built for agents making tool calls to MCP URLs — authsome handles the credential lifecycle so your code just asks for headers.

## Install

```bash
pip install -e .
```

## Quick Start

```python
from authsome import AuthClient

client = AuthClient()
client.init()  # creates ~/.authsome/ directory structure

# --- API Key provider ---
client.login("openai")  # securely prompts for your key
headers = client.get_auth_headers("openai")
# → {"Authorization": "Bearer sk-..."}

# --- OAuth2 provider (PKCE) ---
client.login("github")  # opens browser for authorization
token = client.get_access_token("github")  # auto-refreshes if expired

# --- Export for shell usage ---
print(client.export("openai", format="shell"))
# → export OPENAI_API_KEY=sk-...

# --- Run a command with injected credentials ---
client.run(["curl", "https://api.github.com/user"], providers=["github"])
```

## CLI Usage

Authsome provides a powerful command-line interface to manage your credentials without writing any code. All commands support the `--json` flag for machine-readable output.

### Basic Commands
```bash
# Initialize the store (creates ~/.authsome)
authsome init

# Check the health of your installation
authsome doctor

# List all connected providers and their status
authsome list
```

### Authentication
```bash
# Start an authentication flow (will prompt or open browser)
authsome login github

# Revoke your token remotely and remove it locally
authsome revoke github

# Just remove the local credential state
authsome remove github
```

### Retrieving Credentials
```bash
# Inspect your local connection metadata (secrets are redacted by default)
authsome get github

# Reveal the secret
authsome get github --show-secret

# Extract a specific field
authsome get github --field status
```

### Exporting and Running
```bash
# Output environment variables for your shell
authsome export github --format shell

# Execute a command with injected credentials
authsome run --provider openai -- python script.py
```

## How It Works

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

## Key Concepts

| Concept | Description |
|---------|-------------|
| **Provider** | A third-party service definition (e.g., `github`, `openai`) |
| **Connection** | A named credential instance (e.g., `personal`, `work`) |

## Supported Flows

| Flow | Type | Use Case |
|------|------|----------|
| `pkce` | OAuth2 | Browser-capable environments with pre-registered clients |
| `device_code` | OAuth2 | Headless/remote environments |
| `dcr_pkce` | OAuth2 | Dynamic client registration + PKCE |
| `api_key_prompt` | API Key | Interactive secure key input |
| `api_key_env` | API Key | Import from environment variable |

## Bundled Providers

**OAuth2:** GitHub, Google, Slack, Notion, Linear

**API Key:** OpenAI, Anthropic, Tavily, SerpAPI, Resend, Stripe

## Multiple Connections

```python
# Same provider, different accounts
client.login("openai", connection_name="personal")
client.login("openai", connection_name="work")

# Retrieve specific connection
headers = client.get_auth_headers("openai", connection="work")
```

## Custom Providers

```python
from authsome import ProviderDefinition, AuthType, FlowType
from authsome.models.provider import ApiKeyConfig

client.register_provider(ProviderDefinition(
    name="my-service",
    display_name="My Service",
    auth_type=AuthType.API_KEY,
    flow=FlowType.API_KEY_PROMPT,
    api_key=ApiKeyConfig(
        header_name="X-API-Key",
        header_prefix="",
        env_var="MY_SERVICE_KEY",
    ),
))
```

## Storage Layout

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

## Encryption Modes

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

## Security

- All tokens and API keys are **encrypted at rest** with AES-256-GCM
- Master key stored in **OS keyring** or **local file** — user's choice
- Secrets are **never printed** unless explicitly requested
- `run` injects credentials into subprocess env **without logging**

## Environment

| Variable | Purpose |
|----------|---------|
| `AUTHSOME_HOME` | Override the default `~/.authsome` directory |

## License

MIT
