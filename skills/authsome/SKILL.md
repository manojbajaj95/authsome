---
name: authsome
version: 0.1.2
description: This skill should be used when the user wants to "login to GitHub", "store an API key", "get authentication headers", "export credentials to the shell", "run a command with API keys injected", "register a custom OAuth provider", "manage tool tokens", or "authenticate to a third-party application". Also triggers for requests involving authenticating AI agents or securely storing/retrieving credentials using the authsome CLI.
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

See `references/custom-providers.md` for the full JSON schema, configuration nuances, and examples.

## Best Practices
- **Prefer `authsome run`** over manually exporting secrets into the environment — it is more secure and ephemeral.
- **Use JSON output** (`--json` flag) when parsing results in scripts for more reliable automation.
- **Redact secrets** in output unless the user specifically asks to see them.

## Additional Resources

### Reference Files

- **`references/custom-providers.md`** — Full custom provider JSON schema, `env:VAR_NAME` syntax, OAuth2/API key block details, and working examples.
