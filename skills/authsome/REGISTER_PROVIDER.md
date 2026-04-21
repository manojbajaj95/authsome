# Registering a Custom Provider

This guide covers creating and registering a new provider definition when the target service is not bundled with authsome.

---

## Step 1: Research the service

Perform a **web search** to determine what authentication methods the target service supports:

- **OAuth2?** Find the `authorization_url`, `token_url`, supported `scopes`, and whether it supports PKCE, device flow, or DCR (Dynamic Client Registration).
- **API keys / personal access tokens?** Find the header format.
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
  },
  "export": {
    "env": {
      "access_token": "SERVICE_ACCESS_TOKEN",
      "refresh_token": "SERVICE_REFRESH_TOKEN"
    }
  }
}
```

> **Note:** When DCR is available, set `"flow": "dcr_pkce"` and `"supports_dcr": true` with a `"registration_endpoint"`. For standard OAuth2 (`pkce` or `device_code`), you must provide the `client_id` (and `client_secret` if needed) during the login process using CLI flags: `--client-id` and `--client-secret`. These will be securely saved to your profile and reused for future logins. Do NOT include them in the provider JSON.

### Template B — API Key Provider

```json
{
  "schema_version": 1,
  "name": "<service_name_lowercase>",
  "display_name": "<Service Display Name>",
  "auth_type": "api_key",
  "flow": "api_key",
  "api_key": {
    "header_name": "Authorization",
    "header_prefix": "Bearer"
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

### Credential Storage

Authsome stores all client credentials (`client_id`, `client_secret`, `api_key`) securely at the **profile level** in its internal database. 

1. **OAuth2:** Pass credentials once using `--client-id` and `--client-secret` during `authsome login`.
2. **API Keys:** Pass the key once using `--api-key` during `authsome login`, or enter it interactively during the prompt.

Once saved, these credentials are never read from environment variables or plain-text JSON files. This ensures portability and security across different environments.

### API Key fields (`api_key` block)

| Field | Required | Description |
|-------|----------|-------------|
| `header_name` | No | HTTP header name. Defaults to `"Authorization"`. |
| `header_prefix` | No | Prefix before the key value. Defaults to `"Bearer"`. |

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
| `api_key` | `api_key` | Prompts the user to paste an API key or accepts it via the `--api-key` flag. |

---

## Step 5: Register the provider

```bash
$AUTHSOME register /path/to/provider.json
```

Use `--force` to overwrite an existing provider with the same name.

After registration, return to [SKILL.md](./SKILL.md) **Phase 2 — LOGIN**.
