# Custom Provider Reference

## Registering a Custom Provider

```bash
authsome register <path/to/provider.json>
# Use --force to overwrite an existing configuration
```

## Required JSON Fields

| Field | Description |
|-------|-------------|
| `"schema_version"` | Always `1` |
| `"name"` | Internal identifier (e.g., `"github"`) |
| `"display_name"` | Human-readable name (e.g., `"GitHub"`) |
| `"auth_type"` | `"oauth2"` or `"api_key"` |
| `"flow"` | `"pkce"`, `"device_code"`, `"dcr_pkce"`, `"api_key_prompt"`, or `"api_key_env"` |

## Configuration Details

### Client Credentials from Environment

Use `"env:VAR_NAME"` syntax in the `"client"` block to avoid hardcoding secrets:

```json
"client": {
  "client_id": "env:MY_CLIENT_ID",
  "client_secret": "env:MY_CLIENT_SECRET"
}
```

### Export Mapping

The `"export"` → `"env"` block controls how credentials map to environment variables for `authsome export --format shell` and `authsome run`:

```json
"export": {
  "env": {
    "access_token": "MY_SERVICE_TOKEN"
  }
}
```

### OAuth2 Block (required for `auth_type: oauth2`)

Must include: `authorization_url`, `token_url`, `scopes`, `pkce`, `supports_device_flow`, `supports_dcr`.

### API Key Block (required for `auth_type: api_key`)

Must include: `header_name`, `header_prefix`, `env_var`.

## Example: OAuth2 Provider (PKCE)

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
