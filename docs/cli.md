# CLI Reference

All commands support `--json` for machine-readable output.

---

## Commands

| Command | Description |
|---------|-------------|
| `whoami` | Show home directory and encryption mode. |
| `doctor` | Run health checks on directory layout and encryption. |
| `list` | List all providers (bundled + custom) and their connection states. |
| `inspect <provider>` | Show the full provider definition schema. |
| `login <provider>` | Authenticate with a provider using its configured flow. |
| `get <provider>` | Get connection metadata (secrets redacted by default). |
| `export <provider>` | Export credentials in `env`, `shell`, or `json` format. |
| `run -- <cmd>` | Run a subprocess behind the local auth injection proxy. |
| `logout <provider>` | Log out of a connection and remove local state. |
| `revoke <provider>` | Complete reset of the provider, removing all connections and client secrets. |
| `remove <provider>` | Uninstall a local provider or reset a bundled provider. |
| `register <path>` | Register a custom provider from a JSON file. |

---

## Global Flags

| Flag | Description |
|------|-------------|
| `--json` | Machine-readable JSON output. |
| `--quiet` | Suppress non-essential output. |
| `--no-color` | Disable ANSI colors. |

---

## Command Details

### `doctor` / `whoami`

```bash
authsome doctor    # verify installation health
authsome whoami    # show home directory and encryption mode
```

### `list` / `inspect`

```bash
authsome list                   # all connections + token status
authsome inspect github --json  # full provider schema
```

### `login`

```bash
authsome login <provider> [OPTIONS]
```

| Option | Description |
|--------|-------------|
| `--flow <type>` | Override the auth flow. Valid values: `pkce`, `device_code`, `dcr_pkce`, `api_key`. |
| `--connection <name>` | Connection name (default: `default`). |
| `--scopes <s1,s2>` | Comma-separated scopes to request. |
| `--base-url <url>` | Override the base URL for the provider. |
| `--force` | Overwrite an existing connection. |

```bash
authsome login github                    # OAuth2 browser flow (PKCE)
authsome login github --flow device_code # headless / no local browser
authsome login openai                    # secure API key entry via browser bridge
```

Setup can use browser PKCE, device code, or a browser bridge for secure API key entry. After setup, agents can run headlessly in CI, SSH, cron, background workers, or parallel pipelines.

### `get`

```bash
authsome get <provider> [OPTIONS]
```

| Option | Description |
|--------|-------------|
| `--connection <name>` | Connection name (default: `default`). |
| `--field <field>` | Return only a specific field. |
| `--show-secret` | Reveal encrypted secret values in output. |

```bash
authsome get github               # connection metadata, secrets redacted
authsome get github --field status
```

### `export`

```bash
authsome export <provider> [OPTIONS]
```

| Option | Description |
|--------|-------------|
| `--connection <name>` | Connection name (default: `default`). |
| `--format <fmt>` | Output format: `env` (default), `shell`, or `json`. |

```bash
authsome export github --format shell   # export GITHUB_TOKEN=...
```

### `run`

```bash
authsome run -- <command> [args...]
```

Runs `<command>` behind a local auth proxy that injects provider auth headers into matched HTTP(S) requests at request time. This is the most secure way to run agents as it avoids exporting raw secrets into the child process environment.

The proxy automatically matches outbound requests to known provider hosts (e.g. `api.openai.com`, `api.github.com`) using the `host_url` field in provider definitions and injects the appropriate auth headers (OAuth Bearer tokens or API keys). Unmatched traffic is forwarded unchanged.

```bash
authsome run -- python my_agent.py
authsome run -- curl https://api.openai.com/v1/models
```

**How it works:**

1. Starts a local proxy on an ephemeral port.
2. Launches the child command with `HTTP_PROXY` / `HTTPS_PROXY` / `NO_PROXY` set.
3. Sets placeholder environment variables (e.g. `OPENAI_API_KEY=authsome-proxy-managed`) so SDKs initialize correctly.
4. Intercepts matched requests and injects the real auth headers.
5. Stops the proxy when the child exits.
6. Returns the child's exit code.

### `register`

```bash
authsome register <path/to/provider.json> [--force]
```

Registers a custom provider. Use `--force` to overwrite an existing provider with the same name. See the [provider registration guide](./register-provider.md) for JSON templates and field reference.

### `logout` / `revoke` / `remove`

```bash
authsome logout <provider> [--connection <name>]   # log out + revoke remotely
authsome revoke <provider>                          # reset all connections and client secrets
authsome remove <provider>                          # uninstall local provider or reset bundled
```
