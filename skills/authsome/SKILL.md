---
name: authsome
version: 0.1.2
description: This skill should be used when the user wants to "login to GitHub", "store an API key", "get authentication headers", "export credentials to the shell", "run a command with API keys injected", "register a custom OAuth provider", "manage tool tokens", or "authenticate to a third-party application". Also triggers for requests involving authenticating AI agents or securely storing/retrieving credentials using the authsome CLI.
---

# Authsome CLI Skill

Manage the credential lifecycle for tools and applications using the `authsome` CLI.

> **Agent Flow:** Every credential request follows three phases in order:
> **SEARCH** → **LOGIN** → **USE**

---

## Prerequisites

Before running any `authsome` command, determine how to invoke it:

1. **`uvx` (preferred)** — `uvx authsome <cmd>`. No install needed.
2. **`pipx`** — `pipx run authsome <cmd>`.
3. **Installed in PATH** — `authsome <cmd>`.
4. **Not found** — inform the user. Recommend `pip install uv` then `uvx authsome`.

> **Detection snippet** (run once per session):
> ```bash
> if command -v uvx &>/dev/null; then
>   AUTHSOME="uvx authsome"
> elif command -v pipx &>/dev/null; then
>   AUTHSOME="pipx run authsome"
> elif command -v authsome &>/dev/null; then
>   AUTHSOME="authsome"
> else
>   echo "authsome not found — please install it"
> fi
> ```

Ensure authsome is initialized before any operation:
```bash
$AUTHSOME init
```

---

## Phase 1 — SEARCH

**Goal:** Find the provider and check for existing connections.

```bash
$AUTHSOME list --json
```

This returns `bundled` and `custom` provider arrays, each with `name`, `auth_type`, and `connections`.

**Decision:**

- **Provider found with a connected connection** → Ask the user which connection to use (or if they want a new one). If using an existing connection, skip to **Phase 3 — USE**.
- **Provider found, no connections** → Proceed to **Phase 2 — LOGIN**.
- **Provider NOT found** → You must create and register a custom provider. Read [REGISTER_PROVIDER.md](./REGISTER_PROVIDER.md) for the full guide, then return here for Phase 2.

---

## Phase 2 — LOGIN

**Goal:** Authenticate and store credentials.

### Step 2.1: Determine the auth flow

If the provider supports multiple OAuth2 flows, choose one:

1. **`supports_dcr: true`** → **Use `dcr_pkce`**. This is the path of least resistance — no pre-registered `client_id` needed.
2. **Multiple flows available (no DCR)** → Ask the user: PKCE (browser) vs Device Code (headless).
3. **Only one flow** → Use the provider's default.
4. **API key provider** → Flow is already determined (`api_key`).

Use `$AUTHSOME inspect <provider> --json` to check `oauth.supports_dcr`, `oauth.supports_device_flow`, and the default `flow`.

### Step 2.2: Choose a connection name

If the user already has a `"default"` connection for this provider, ask for a name (e.g., `work`, `personal`). Otherwise use `"default"`.

### Step 2.3: Run login

```bash
$AUTHSOME login <provider> [--connection <name>] [--flow <flow_type>] [--scopes <scope1,scope2>] [--force]
```

**Note on Credentials:** `authsome` stores client IDs and secrets securely in the profile store. If this is the first time logging in with a specific provider that doesn't use Dynamic Client Registration (DCR), `authsome` will securely prompt the user for these credentials via a local browser bridge. Agents MUST NEVER ask for or pass these secrets directly. They will be securely saved and reused for subsequent logins. Use the `--force` flag to overwrite an existing connection if it already exists.

**Note on Redirect URIs:** If the provider requires you to register an OAuth App manually (e.g., standard PKCE flow without DCR), make sure to configure the callback/redirect URI in the provider's developer console to exactly `http://127.0.0.1:7999/callback`.

**Examples:**
```bash
# Default flow (if credentials are saved or provider supports DCR)
$AUTHSOME login github

# First-time login for provider requiring client credentials (prompts user via secure browser bridge)
$AUTHSOME login github

# Override flow to device code
$AUTHSOME login github --flow device_code

# API key provider (prompts user via secure browser bridge)
$AUTHSOME login openai
```

### Step 2.4: Verify

```bash
$AUTHSOME get <provider> --json
```

Confirm `status` is `"connected"`.

---

## Phase 3 — USE

**Goal:** Export credentials so the agent can make authenticated tool calls.

### Option A: Export to current shell (recommended)

```bash
eval "$($AUTHSOME export <provider> --format shell)"
```

Credentials become environment variables (e.g., `GITHUB_ACCESS_TOKEN`, `OPENAI_API_KEY`) as defined in the provider's `export.env` mapping.

### Option B: Run a command with injected credentials

```bash
$AUTHSOME run --provider github -- curl -H "Authorization: Bearer $GITHUB_ACCESS_TOKEN" https://api.github.com/user
```

Multiple providers:
```bash
$AUTHSOME run --provider github --provider openai -- python my_script.py
```

### Option C: Get a single field

```bash
TOKEN=$($AUTHSOME get <provider> --field access_token)
```

---

## Additional Resources

| Topic | File |
|-------|------|
| Creating & registering custom providers | [REGISTER_PROVIDER.md](./REGISTER_PROVIDER.md) |
| Full CLI command & flag reference | [CLI_REFERENCE.md](./CLI_REFERENCE.md) |

---

## Best Practices

- **Always use `--json`** when parsing CLI output programmatically.
- **Prefer `authsome run`** over exporting secrets — it is more secure and ephemeral.
- **Never log or echo secrets** unless the user explicitly asks.
- **Re-use existing connections** — always check before starting a new login.
