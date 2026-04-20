# CLI Reference

Full command and flag reference for the `authsome` CLI.

---

## Commands

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

---

## Global Flags

| Flag | Description |
|------|-------------|
| `--json` | Machine-readable JSON output. |
| `--quiet` | Suppress non-essential output. |
| `--no-color` | Disable ANSI colors. |

---

## Command Details

### `login`

```
authsome login <provider> [OPTIONS]
```

| Option | Description |
|--------|-------------|
| `--connection <name>` | Connection name (default: `default`). |
| `--flow <type>` | Override the auth flow (`pkce`, `device_code`, `dcr_pkce`, `api_key_prompt`, `api_key_env`). |
| `--scopes <s1,s2>` | Comma-separated scopes to request. |

### `get`

```
authsome get <provider> [OPTIONS]
```

| Option | Description |
|--------|-------------|
| `--connection <name>` | Connection name (default: `default`). |
| `--field <field>` | Return only a specific field. |
| `--show-secret` | Reveal encrypted secrets. |

### `export`

```
authsome export <provider> [OPTIONS]
```

| Option | Description |
|--------|-------------|
| `--connection <name>` | Connection name (default: `default`). |
| `--format <fmt>` | Output format: `env` (default), `shell`, or `json`. |

### `run`

```
authsome run --provider <p1> [--provider <p2>] -- <command>
```

Runs `<command>` as a subprocess with credentials from the specified providers injected into its environment. Multiple `--provider` flags can be used.

### `register`

```
authsome register <path/to/provider.json> [OPTIONS]
```

| Option | Description |
|--------|-------------|
| `--force` | Overwrite an existing provider with the same name. |

### `revoke` / `remove`

```
authsome revoke <provider> [--connection <name>]
authsome remove <provider> [--connection <name>]
```

`revoke` attempts remote revocation first (if supported), then removes locally. `remove` only deletes local state.
