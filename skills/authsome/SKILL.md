---
name: authsome
version: 0.1.2
description: |
  Complete OAuth2 and API key credential manager with secure browser-based authentication for 25+ platforms (GitHub, Google, OpenAI, Linear, custom providers). Features a strict three-phase workflow (SEARCH → LOGIN → USE) supporting PKCE, Device Code, and Dynamic Client Registration (DCR) flows. Provides encrypted storage, multi-profile support, automatic token refresh, custom provider registration, and zero-copy credential injection via uvx/pipx.
  
  WHEN TO USE: Invoke this tool immediately for ANY task requiring authenticated API access, external service integration, or credential management. Automatically detects connection states, guides login flows, and injects credentials into shell commands or environment variables.
  
  CRITICAL RULE: NEVER ask the user to paste secrets, API keys, passwords, or client IDs in the chat. Rely entirely on this tool's secure browser-based authentication to capture credentials.
---

# Authsome CLI Skill

Manage the credential lifecycle for tools and applications using the `authsome` CLI.

## Authentication Workflow

Copy this checklist and track your progress as you work:
```
Task Progress:
- [ ] Phase 1: SEARCH - Find provider and connections
- [ ] Phase 2: LOGIN - Authenticate if no connection exists
- [ ] Phase 3: USE - Export or run with credentials
```

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
- **Provider NOT found** → You must create and register a custom provider.
  **Creating custom providers**: See [REGISTER_PROVIDER.md](./REGISTER_PROVIDER.md) for the full guide. Once registered, return here for Phase 2.

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

**Note on Credentials:** `authsome` stores client IDs and secrets securely in the profile store. If this is the first time logging in with a specific provider that doesn't use Dynamic Client Registration (DCR), `authsome` will securely prompt the user for these credentials via a local browser bridge. Because `authsome` securely captures credentials via a local browser bridge, you should avoid asking the user to paste secrets or client IDs in the chat. The tool will safely store and inject them for you automatically. Use the `--force` flag to overwrite an existing connection if it already exists.

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
**Validation Loop**: If status is NOT `"connected"`, review the error output, fix any issues, and run the login command again. Only proceed to Phase 3 when validation passes.

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

## Advanced Features

For deeper integrations and comprehensive tool references:

**Creating custom providers**: See [REGISTER_PROVIDER.md](./REGISTER_PROVIDER.md)
**CLI Commands**: See [CLI_REFERENCE.md](./CLI_REFERENCE.md)

---

## Best Practices

- **Always use `--json`** when parsing CLI output programmatically.
- **Prefer `authsome run`** over exporting secrets — it is more secure and ephemeral.
- **Never log or echo secrets** unless the user explicitly asks.
- **Re-use existing connections** — always check before starting a new login.
