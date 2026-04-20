# Registering a Custom Provider

This guide covers creating and registering a new provider definition when the target service is not bundled with authsome.

---

## Step 1: Research the service

Perform a **web search** to determine what authentication methods the target service supports:

- **OAuth2?** Find the `authorization_url`, `token_url`, supported `scopes`, and whether it supports PKCE, device flow, or DCR (Dynamic Client Registration).
- **API keys / personal access tokens?** Find the header format and relevant environment variable conventions.
- **Both?** Ask the user which method they prefer:
  - *OAuth2* — scoped, time-limited access with auto-refresh.
  - *API key* — simpler, paste a token and go.

---

## Step 2: Write the provider JSON

Create a `.json` file using one of the templates below.

### Template A — OAuth2 Provider

```json
{
  "schema_version": 1,
  "name": "<service_name_lowercase>",
  "display_name": "<Service Display Name>",
  "auth_type": "oauth2",
  "flow": "dcr_pkce",
  "oauth": {
    "authorization_url": "https://example.com/oauth/authorize",
    "token_url": "https://example.com/oauth/token",
    "revocation_url": null,
    "device_authorization_url": null,
    "scopes": ["read", "write"],
    "pkce": true,
    "supports_device_flow": false,
    "supports_dcr": true,
    "registration_endpoint": "https://example.com/oauth/register"
  },
  "client": {
    "client_id": "env:SERVICE_CLIENT_ID",
    "client_secret": null
  },
  "export": {
    "env": {
      "access_token": "SERVICE_ACCESS_TOKEN",
      "refresh_token": "SERVICE_REFRESH_TOKEN"
    }
  }
}
```

> **Note:** When DCR is available, set `"flow": "dcr_pkce"` and `"supports_dcr": true` with a `"registration_endpoint"`. The `client.client_id` is not needed — DCR handles it automatically. If DCR is not available, set `"flow": "pkce"` and provide the `client_id` (use `"env:VAR_NAME"` to read from environment).

### Template B — API Key Provider

```json
{
  "schema_version": 1,
  "name": "<service_name_lowercase>",
  "display_name": "<Service Display Name>",
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

---

## Step 3: Understand the fields

### Required top-level fields

| Field | Description |
|-------|-------------|
| `schema_version` | Always `1`. |
| `name` | Internal identifier, lowercase (e.g., `"github"`). |
| `display_name` | Human-readable name (e.g., `"GitHub"`). |
| `auth_type` | `"oauth2"` or `"api_key"`. |
| `flow` | Default flow. See flow selection guide below. |

### OAuth2 fields (`oauth` block)

| Field | Required | Description |
|-------|----------|-------------|
| `authorization_url` | Yes | URL the user is redirected to for authorization. |
| `token_url` | Yes | Endpoint to exchange auth codes for tokens. |
| `revocation_url` | No | Endpoint for remote token revocation. |
| `device_authorization_url` | No | Required if `supports_device_flow` is `true`. |
| `scopes` | Yes | Default scopes to request. |
| `pkce` | Yes | Whether PKCE is supported/required. |
| `supports_device_flow` | No | Set `true` if device code flow is available. |
| `supports_dcr` | No | Set `true` if Dynamic Client Registration is available. |
| `registration_endpoint` | No | Required if `supports_dcr` is `true`. |

### Client fields (`client` block)

| Field | Required | Description |
|-------|----------|-------------|
| `client_id` | Depends | OAuth client ID. Use `"env:VAR_NAME"` to read from environment. Required for `pkce` and `device_code`. Not needed for `dcr_pkce`. |
| `client_secret` | No | OAuth client secret. Use `"env:VAR_NAME"` syntax. |

### API Key fields (`api_key` block)

| Field | Required | Description |
|-------|----------|-------------|
| `input_mode` | No | `"prompt"` (interactive) or `"env"` (from environment variable). Defaults to `"prompt"`. |
| `header_name` | No | HTTP header name. Defaults to `"Authorization"`. |
| `header_prefix` | No | Prefix before the key value. Defaults to `"Bearer"`. |
| `env_var` | No | Environment variable to read the key from (used with `api_key_env` flow). |

### Export fields (`export` block)

The `export.env` object maps credential fields to environment variable names used by `authsome export` and `authsome run`.

---

## Step 4: Choose the right flow

> **Priority rule for OAuth2:** When a service supports DCR, **always prefer `dcr_pkce`**. It requires no pre-registered OAuth app or `client_id` — the path of least resistance for the user.

| `flow` value | `auth_type` | When to use |
|--------------|-------------|-------------|
| `dcr_pkce` | `oauth2` | **Preferred.** Dynamic Client Registration, then PKCE. No `client_id` needed. |
| `pkce` | `oauth2` | Standard OAuth2 with PKCE. Opens a browser. Needs `client_id`. |
| `device_code` | `oauth2` | Headless OAuth2. User enters a code on a separate device. Needs `client_id`. |
| `api_key_prompt` | `api_key` | Interactively prompts the user to paste an API key. |
| `api_key_env` | `api_key` | Reads the API key from an environment variable (`api_key.env_var`). |

---

## Step 5: Register the provider

```bash
$AUTHSOME register /path/to/provider.json
```

Use `--force` to overwrite an existing provider with the same name.

After registration, return to [SKILL.md](./SKILL.md) **Phase 2 — LOGIN**.
