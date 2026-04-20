---
name: authsome
description: Manage third-party credentials (API keys, OAuth2 tokens) locally using the authsome CLI. Use this skill when the user wants to login to a service (GitHub, OpenAI, Google, etc.), retrieve authentication headers, export credentials to the shell, or run commands with injected authentication environment variables. Trigger this for any request involving authenticating AI agents, managing tool tokens, or securely storing/retrieving API keys.
---

# Authsome CLI Skill

This skill enables the autonomous management of the credential lifecycle for tools and applications using the `authsome` CLI.

## Installation & Invocation

Before running any `authsome` command, determine how to invoke it using this priority order:

1. **`uvx` (preferred)** — if `uvx` is available, invoke as `uvx authsome <cmd>`. No install needed; uvx runs it in an isolated environment.
   ```bash
   uvx authsome whoami
   ```

2. **`pipx`** — if `uvx` is not found but `pipx` is available, invoke as `pipx run authsome <cmd>`.
   ```bash
   pipx run authsome whoami
   ```

3. **Installed in PATH** — if `authsome` is already installed and available directly (e.g., via `pip install authsome` in the active venv or globally), invoke it as `authsome <cmd>`.

4. **Not found — ask the user** — if none of the above work, do not guess. Inform the user and suggest one of these options:
   - **Recommended (isolated):** `pip install uv` then use `uvx authsome`
   - **Global install:** `pipx install authsome` (requires pipx)
   - **Local venv:** `pip install authsome` inside the project's virtual environment, then activate it

> **Detection snippet** (run once per session to set `AUTHSOME_CMD`):
> ```bash
> if command -v uvx &>/dev/null; then
>   AUTHSOME_CMD="uvx authsome"
> elif command -v pipx &>/dev/null; then
>   AUTHSOME_CMD="pipx run authsome"
> elif command -v authsome &>/dev/null; then
>   AUTHSOME_CMD="authsome"
> else
>   echo "authsome not found — please install it (see skill instructions)"
> fi
> ```
> Use `$AUTHSOME_CMD` in place of `authsome` in all commands below.

## Core Workflow

Always ensure `authsome` is initialized before performing other operations.

1. **Initialize**: If it's a first-time setup, run `authsome init`.
2. **Login**: To connect a new account, use `authsome login <provider>`.
3. **Retrieve/Export**: To use credentials, use `authsome get` or `authsome export`.
4. **Execute**: To run a task with credentials, use `authsome run`.

## Comprehensive Command Reference

The `authsome` CLI provides the following commands for managing credentials. All commands support the `--json` flag for machine-readable output and `--quiet` to suppress non-essential output.

### Setup and Health
- `authsome init`: Initializes the authsome root directory (`~/.authsome`) and default profile.
- `authsome whoami`: Shows the home directory and encryption mode.
- `authsome doctor`: Runs health checks on the directory layout and encryption status.

### Authentication Lifecycle
- `authsome login <provider>`: Starts the authentication flow for a provider. 
  - Supports `--connection <name>` to manage multiple accounts for the same provider.
  - Supports `--flow <flow_type>` to override the default flow.
  - Supports `--scopes <scope1,scope2>` to request specific permissions.
- `authsome revoke <provider>`: Revokes credentials remotely (if supported by the provider) and removes them locally.
- `authsome remove <provider>`: Removes the local credential state without attempting remote revocation.

### Inspecting State
- `authsome list`: Lists all configured providers (bundled and custom) and their connection states.
- `authsome get <provider>`: Returns provider connection metadata.
  - Secrets are redacted by default. Use `--show-secret` to reveal encrypted secrets.
  - Use `--field <field_name>` to return only a specific field.
- `authsome inspect <provider>`: Returns the provider definition schema and local connection summary.

### Using Credentials
- `authsome export <provider>`: Exports credential material. 
  - Use `--format shell` to output environment variable exports (e.g., `export KEY=VAL`).
  - Use `--format json` or `--format env` for other output styles.
- `authsome run --provider <p1> [--provider <p2>] -- <command>`: Runs a subprocess with exported credentials injected into its environment. This is the most secure way to pass credentials to a script.

### Custom Providers
- `authsome register <path/to/provider.json>`: Registers a custom provider definition from a local JSON file. Use `--force` to overwrite existing configurations.

#### Custom Provider JSON Format
When creating a new custom provider JSON file, ensure it adheres to the strict authsome JSON schema.

A provider definition JSON file must contain the following core fields:
- `"schema_version"`: `1`
- `"name"`: The internal identifier (e.g., `"github"`)
- `"display_name"`: The human-readable name (e.g., `"GitHub"`)
- `"auth_type"`: Either `"oauth2"` or `"api_key"`
- `"flow"`: The authentication flow to use (e.g., `"pkce"`, `"device_code"`, `"dcr_pkce"`, `"api_key_prompt"`, `"api_key_env"`)

**Configuration Nuances:**
- **Environment Variables**: For `"client_id"` and `"client_secret"` within the `"client"` block, you can use the `"env:VAR_NAME"` syntax to dynamically resolve credentials from the environment instead of hardcoding them.
- **Export Mapping**: The `"export"` block with the `"env"` object dictates how credentials map to environment variables when using `authsome export --format shell` or `authsome run` (e.g., `"access_token": "GITHUB_TOKEN"`).
- **OAuth2**: Requires the `"oauth"` block (defining `authorization_url`, `token_url`, `scopes`, `pkce`, etc.).
- **API Key**: Requires the `"api_key"` block (defining `header_name`, `header_prefix`, `env_var`, etc.).

**Example: OAuth2 Provider (PKCE)**
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

## Best Practices
- **Prefer `authsome run`** over manually exporting secrets into the environment if possible, as it is more secure and ephemeral.
- **Use JSON output** (`--json` flag) when parsing results in scripts for more reliable automation.
- **Redact secrets** in your own output unless the user specifically asks to see them.
