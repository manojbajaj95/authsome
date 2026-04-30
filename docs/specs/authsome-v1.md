# Portable Specification: Local Auth Library + CLI

## 1. Purpose

This document defines a portable, language-agnostic specification for a local authentication library and CLI that lets humans, agents, and developer tools manage third-party credentials in a consistent way.

The system is designed so that:

- a Python implementation and a JavaScript implementation can follow the same logic,
- both implementations can read and write the same credential store,
- providers can be registered in a shared format,
- credentials can be retrieved, refreshed, revoked, exported, and injected consistently,
- the system remains local-first and embeddable.

This spec describes the behavioral contract, filesystem layout, data models, provider schema, CLI contract, and library contract.

It does not prescribe one specific framework, database, HTTP client, or encryption library.

---

## 2. Product Definition

The product consists of two surfaces.

### 2.1 Library
A language SDK that allows applications, CLIs, agents, servers, and tools to:

- discover registered providers,
- initiate authentication,
- retrieve credentials,
- refresh tokens,
- revoke connections,
- remove local credentials,
- export credentials into runtime environments,
- build authenticated request headers.

### 2.2 CLI
A terminal interface that allows humans and agents to:

- list providers,
- log in to a provider,
- revoke provider credentials,
- remove local provider credentials,
- inspect provider metadata,
- export credentials,
- run commands with injected credentials,
- register new providers.

Profile management is optional because the default operating mode uses profile `default` unless explicitly specified.

---

## 3. Design Principles

1. **Portable**  
   Multiple implementations in different languages must be able to interoperate using the same local store and schemas.

2. **Local-first**  
   The default mode is local storage and local execution. Hosted sync is out of scope for this spec.

3. **Provider-aware**  
   Authentication is modeled per provider rather than as generic secret blobs.

4. **Safe by default**  
   Commands should return metadata by default, not raw secrets.

5. **Machine-friendly**  
   All CLI commands should support structured output.

6. **Human-friendly**  
   Common tasks should have simple verbs and predictable semantics.

7. **Extensible**  
   New auth types, providers, and metadata should be addable without breaking compatibility.

---

## 4. Core Concepts

### 4.1 Provider
A provider defines how to authenticate against a third-party system.

Examples:
- github
- google
- slack
- notion
- openai
- anthropic

A provider definition includes:
- provider identity and display metadata,
- auth type,
- flow configuration,
- endpoint metadata,
- default scopes,
- export behavior.

### 4.2 Profile
A profile is a local credential namespace.

The default profile name is always:
- `default`

Implementations MUST assume profile `default` unless the caller explicitly specifies another profile.

Examples of non-default profiles:
- work
- personal
- agent-prod

A profile contains provider metadata, provider state, OAuth client credentials, and zero or more named connections per provider.

### 4.3 OAuth Client Config
An OAuth client config is the saved OAuth client credentials for a provider within a profile.

There is one client config per provider per profile.

An OAuth client config contains:
- `client_id`
- `client_secret`
- optional redirect URI or registration metadata

OAuth client credentials are sensitive provider configuration and MUST be stored encrypted at rest.

### 4.4 Connection
A connection is a named credential instance for a provider within a profile.

A single provider MAY have multiple connections inside the same profile.

Examples:
- profile `default` with provider `github` and connection `default`
- profile `default` with provider `github` and connection `work`
- profile `work` with provider `google` and connection `corp-admin`

A connection is uniquely identified by:
- `profile_name`
- `provider_name`
- `connection_name`

### 4.5 Credential Record
A credential record is the normalized local state associated with one named connection.

### 4.6 Auth Type
The auth mechanism used by a provider.

Initial auth types in this spec:
- `oauth2`
- `api_key`

### 4.7 Flow Type
The specific authentication flow.

Initial flow types in this spec:
- `pkce` — browser-based OAuth2 with PKCE
- `device_code` — headless OAuth2 device authorization
- `dcr_pkce` — dynamic client registration followed by PKCE
- `api_key` — collect and store an API key

For `api_key`, the method of collection (environment variable, masked terminal input, or secure browser form) is determined at runtime by the Sensitive Input Pipeline (see section 27). The flow type in the provider definition is always `api_key` regardless of how the key is collected.

---

## 5. Provider State Model

Every provider within a profile has exactly one of three states. The state is derived at runtime from what is stored — it is not persisted as a separate field.

| State | Meaning |
|---|---|
| `available` | Provider definition exists (bundled or registered). No credentials stored for this profile. |
| `configured` | OAuth2 client credentials (`client_id` and `client_secret`) are saved for this profile. The user has not yet logged in. API key providers skip this state. |
| `connected` | A valid connection record exists with an access token or API key. |

### 5.1 State Transitions

```
available → configured   authsome login (collects client credentials for oauth2 providers)
configured → connected   authsome login (completes auth flow)
available → connected    authsome login (api_key providers go directly to connected)
connected → available    authsome revoke or authsome remove
```

### 5.2 Re-login Rule

If a provider is already `connected`, calling `authsome login <provider>` MUST exit with an error:

```
Error: already connected to <provider>. Run 'authsome revoke <provider>' to disconnect, then login again.
```

Silent overwrite of an existing connection is not permitted.

### 5.3 `authsome list` Output

`authsome list` shows ALL known providers (bundled and registered), not only connected ones. This allows discovery of what is available to connect.

Human-readable example:

```
PROVIDER      TYPE     STATE
github        oauth2   connected   (expires 2026-05-01)
google        oauth2   configured
openai        api_key  connected
linear        oauth2   available
klaviyo       api_key  available
```

---

## 6. Filesystem Layout

The default root directory is:

```text
~/.authsome/
```

Portable implementations MUST support overriding this root with an environment variable and/or explicit configuration.

Recommended override environment variable:

```text
AUTHSOME_HOME
```

### 6.1 Directory Structure

```text
~/.authsome/
  version
  config.json
  master.key
  providers/
    github.json
    google.json
    slack.json
    custom-acme.json
  profiles/
    default/
      store.db
      metadata.json
      lock
```

### 6.2 Required Files

#### `version`
A plain text file containing the store format version integer.

Current store format version: `1`

Implementations reading a `version` file with an unknown value SHOULD surface a clear error rather than silently misreading records.

Example:

```text
1
```

#### `config.json`
Global implementation-independent settings.

#### `master.key`
The local encryption master key, base64-encoded, created on first `init`. File permissions MUST be set to `0600` (owner read/write only). This file is used by the `local_key` encryption mode. See section 11.5.

#### `providers/*.json`
Portable provider definitions.

#### `profiles/<name>/store.db`
The credential store backing a profile.

This may be implemented using a key-value engine, SQLite-backed KV layer, or equivalent, as long as behavior and serialization remain compatible.

#### `profiles/<name>/metadata.json`
Profile metadata.

#### `profiles/<name>/lock`
Optional lock file used to coordinate concurrent writes.

---

## 7. Data Serialization Rules

To ensure cross-language compatibility:

1. All structured metadata MUST be serialized as UTF-8 JSON.
2. Timestamps MUST use RFC 3339 / ISO 8601 in UTC.
3. Binary encrypted payloads MUST be encoded as base64 when embedded in JSON.
4. Unknown fields MUST be preserved when possible.
5. Implementations MUST ignore unknown fields they do not understand.

This allows forward-compatible upgrades across implementations.

---

## 8. Global Configuration Schema

### 8.1 `config.json`

```json
{
  "spec_version": 1,
  "default_profile": "default",
  "encryption": {
    "mode": "local_key"
  }
}
```

### 8.2 Required Fields

- `spec_version`: integer
- `default_profile`: string

### 8.3 Optional Fields

- `encryption`
- `telemetry`
- `ui`
- `experimental`

Implementations MAY add fields.

---

## 9. Profile Metadata Schema

### 9.1 `profiles/<name>/metadata.json`

```json
{
  "name": "default",
  "created_at": "2026-04-16T09:00:00Z",
  "updated_at": "2026-04-16T09:00:00Z",
  "description": "Default local profile"
}
```

### 9.2 Required Fields

- `name`
- `created_at`
- `updated_at`

---

## 10. Provider Definition Schema

Provider definitions MUST be stored as JSON files so multiple implementations can consume them directly.

Bundled providers ship only provider definitions. Implementations MUST NOT assume bundled OAuth app credentials are available.

### 10.1 OAuth Client Credentials

For `oauth2` providers, client credentials are distinct from user connection credentials.

There is one client config per provider per profile. Client credentials include:
- `client_id` — public identifier, safe to pass as a CLI argument or env var
- `client_secret` — sensitive, MUST be collected via the Sensitive Input Pipeline (see section 16.5), MUST NOT be accepted as a CLI argument
- optional redirect URI or registration metadata

Client credentials are sensitive configuration and MUST be stored encrypted at rest when persisted locally.

Provider definitions SHOULD declare env var names for automated collection:

```json
"client": {
  "client_id_env": "GITHUB_CLIENT_ID",
  "client_secret_env": "GITHUB_CLIENT_SECRET"
}
```

When these fields are present, the Sensitive Input Pipeline checks the named env vars before prompting interactively.

Recommended logical key:

```text
profile:<profile_name>:<provider_name>:client
```

### 10.2 Example OAuth Provider

```json
{
  "schema_version": 1,
  "name": "github",
  "display_name": "GitHub",
  "auth_type": "oauth2",
  "flow": "pkce",
  "oauth": {
    "authorization_url": "https://github.com/login/oauth/authorize",
    "token_url": "https://github.com/login/oauth/access_token",
    "revocation_url": null,
    "device_authorization_url": null,
    "scopes": ["repo", "read:user"],
    "pkce": true,
    "supports_device_flow": false,
    "supports_dcr": false
  },
  "client": {
    "client_id_env": "GITHUB_CLIENT_ID",
    "client_secret_env": "GITHUB_CLIENT_SECRET"
  },
  "export": {
    "env": {
      "access_token": "GITHUB_TOKEN"
    }
  }
}
```

Only the `access_token` is exported. Refresh tokens are internal — authsome handles refresh transparently and MUST NOT expose refresh tokens via export or `run`.

### 10.3 Example API Key Provider

```json
{
  "schema_version": 1,
  "name": "openai",
  "display_name": "OpenAI",
  "auth_type": "api_key",
  "flow": "api_key",
  "api_key": {
    "header_name": "Authorization",
    "header_prefix": "Bearer",
    "env_var": "OPENAI_API_KEY"
  },
  "export": {
    "env": {
      "api_key": "OPENAI_API_KEY"
    }
  }
}
```

### 10.4 Required Top-Level Fields

- `schema_version`
- `name`
- `display_name`
- `auth_type`
- `flow`

### 10.5 Auth-Type-Specific Sections

#### For `oauth2`
Required section: `oauth`

#### For `api_key`
Required section: `api_key`

The `api_key` section SHOULD include:
- `header_name`: HTTP header used to send the key
- `header_prefix`: optional prefix (e.g. `Bearer`)
- `env_var`: environment variable name to check before prompting

### 10.6 Provider Resolution Rules

When a provider is requested by name:

1. The implementation MUST look for `providers/<name>.json`.
2. If not found, it MAY search built-in bundled providers.
3. If both exist, local file overrides built-in definition.

---

## 11. Credential Store Contract

The credential store is logically a namespaced key-value store.

Implementations may use:
- py-key-value-aio,
- SQLite-backed KV,
- LevelDB,
- LMDB,
- equivalent local KV store.

Interoperability matters more than backend choice.

### 11.1 Key Namespace

Required logical keys for per-profile runtime data:

```text
profile:<profile_name>:<provider_name>:metadata
profile:<profile_name>:<provider_name>:state
profile:<profile_name>:<provider_name>:client
profile:<profile_name>:<provider_name>:connection:<connection_name>
```

This layout allows one provider to own multiple named connections within the same profile.

Provider definitions are NOT stored in the credential store. They are resolved from the filesystem:
- `~/.authsome/providers/<name>.json` (user-registered, takes precedence)
- bundled provider files shipped with the implementation

The key `provider:<provider_name>:definition` MUST NOT be used for persistent storage. Implementations that cache a resolved provider definition in memory during a session MAY use this as a logical label, but MUST NOT persist it to the store.

### 11.2 Value Encoding

Values MUST be JSON payloads, optionally encrypted before persistence.

### 11.3 Encryption Requirement

Sensitive credential fields MUST be encrypted at rest.

Sensitive fields include:
- access tokens
- refresh tokens
- api keys
- client secrets
- ID tokens when stored
- provider-issued secrets

### 11.4 Encryption Portability Rule

The spec requires field-level confidentiality, not one exact crypto implementation.

To support multi-language compatibility, implementations MUST support at least one shared envelope format.

Recommended portable envelope:

```json
{
  "enc": 1,
  "alg": "AES-256-GCM",
  "kid": "local",
  "nonce": "base64...",
  "ciphertext": "base64...",
  "tag": "base64..."
}
```

The exact local key management strategy is implementation-defined, but implementations that want cross-language read/write compatibility on the same machine SHOULD use the same master key source.

### 11.5 Master Key Recommendation

Recommended options, in order:

1. OS keychain / credential manager storing a local master key
2. A local wrapped key stored under `~/.authsome/master.key`
3. A passphrase-derived key for headless environments

Implementations MUST document which mode they use.

---

## 12. Provider Metadata Record Schema

The provider metadata record stores non-secret metadata about the provider within a profile.

Examples:
- default connection name
- list of known connection names
- preferred account label
- last selected connection

Example:

```json
{
  "schema_version": 1,
  "profile": "default",
  "provider": "github",
  "default_connection": "default",
  "connection_names": ["default", "work"],
  "last_used_connection": "work",
  "metadata": {}
}
```

---

## 13. OAuth Client Config Schema

The OAuth client config stores saved client credentials for a provider. There is at most one per provider per profile.

### 13.1 Example OAuth Client Config

```json
{
  "schema_version": 1,
  "profile": "default",
  "provider": "github",
  "client_id": "abc123",
  "client_secret": {
    "enc": 1,
    "alg": "AES-256-GCM",
    "kid": "local",
    "nonce": "...",
    "ciphertext": "...",
    "tag": "..."
  },
  "source": "user_supplied",
  "metadata": {}
}
```

### 13.2 Required Fields

- `schema_version`
- `profile`
- `provider`
- `client_id`
- `client_secret`
- `source`
- `metadata`

### 13.3 Recommended Source Values

- `user_supplied`
- `env_imported`
- `dcr_generated`

---

## 14. Connection Record Schema

### 14.1 Example OAuth Connection Record

```json
{
  "schema_version": 1,
  "provider": "github",
  "profile": "default",
  "connection_name": "default",
  "auth_type": "oauth2",
  "status": "connected",
  "scopes": ["repo", "read:user"],
  "access_token": {
    "enc": 1,
    "alg": "AES-256-GCM",
    "kid": "local",
    "nonce": "...",
    "ciphertext": "...",
    "tag": "..."
  },
  "refresh_token": {
    "enc": 1,
    "alg": "AES-256-GCM",
    "kid": "local",
    "nonce": "...",
    "ciphertext": "...",
    "tag": "..."
  },
  "token_type": "Bearer",
  "expires_at": "2026-04-16T15:40:22Z",
  "obtained_at": "2026-04-16T14:40:22Z",
  "account": {
    "id": "12345",
    "label": "manojbajaj95"
  },
  "metadata": {}
}
```

### 14.2 Example API Key Connection Record

```json
{
  "schema_version": 1,
  "provider": "openai",
  "profile": "default",
  "connection_name": "default",
  "auth_type": "api_key",
  "status": "connected",
  "api_key": {
    "enc": 1,
    "alg": "AES-256-GCM",
    "kid": "local",
    "nonce": "...",
    "ciphertext": "...",
    "tag": "..."
  },
  "account": {
    "id": null,
    "label": null
  },
  "metadata": {}
}
```

### 14.3 Required Fields

- `schema_version`
- `provider`
- `profile`
- `connection_name`
- `auth_type`
- `status`
- `metadata`

### 14.4 Allowed Status Values

- `not_connected`
- `connected`
- `expired`
- `revoked`
- `invalid`

---

## 15. Provider State Record Schema

The provider state record stores transient or non-secret state.

Examples:
- last refresh attempt time
- last refresh error
- cached discovered endpoints
- PKCE verifier during login session
- device flow polling state

Example:

```json
{
  "schema_version": 1,
  "provider": "github",
  "profile": "default",
  "last_refresh_at": "2026-04-16T15:10:00Z",
  "last_refresh_error": null,
  "metadata": {}
}
```

---

## 16. Authentication Flows

The initial portable spec supports both human-assisted bootstrap and runtime reuse.

### 16.1 OAuth 2 PKCE

Used for browser-capable local environments.

#### Required Behavior

1. Resolve provider definition.
2. Resolve app credentials for the provider.
3. Generate PKCE code verifier and challenge.
4. Start a temporary localhost callback listener, OR allow manual code entry fallback.
5. Open authorization URL in the user’s browser.
6. Receive authorization code.
7. Exchange code for token set.
8. Persist normalized connection record.

#### Expected Result

A connected OAuth credential record with tokens, scopes, app reference, and expiry metadata.

### 16.2 OAuth 2 Device Code Flow

Used for headless or remote environments.

#### Required Behavior

1. Resolve provider definition.
2. Resolve app credentials for the provider.
3. Request device code.
4. Display verification URL and user code.
5. Poll token endpoint according to provider rules.
6. Persist normalized connection record.

### 16.3 DCR + PKCE

Used when the provider supports Dynamic Client Registration.

#### Required Behavior

1. Register client dynamically.
2. Store generated app metadata securely if needed.
3. Continue with PKCE flow.

DCR support MAY be optional in some implementations, but the provider model must support it.

### 16.4 API Key

A single unified flow for `api_key` providers. The key is never accepted as a CLI argument — it is collected via the Sensitive Input Pipeline (see section 27).

#### Required Behavior

1. Check the env var named in `api_key.env_var` (if present in provider definition). If set and non-empty, use it directly — no prompt shown.
2. Otherwise, collect via the Sensitive Input Pipeline: browser bridge if a display is available, otherwise masked terminal input via `getpass`.
3. Validate non-empty input.
4. Store encrypted.
5. Mark connection as `connected`.

API keys have no refresh mechanism. If a stored key becomes invalid, the user must revoke and login again.

### 16.5 OAuth2 Client Credential Collection

Before running any OAuth2 flow, if client credentials are not yet stored for the provider:

1. Resolve `client_id`:
   - Accept `--client-id <value>` CLI argument, OR
   - Check env var named in `client.client_id_env` (if present in provider definition).
   - If neither is available, prompt for `client_id` as plain text input (it is not sensitive).
2. Resolve `client_secret`:
   - Check env var named in `client.client_secret_env` (if present in provider definition). If set and non-empty, use it.
   - Otherwise, collect via the Sensitive Input Pipeline.
   - `client_secret` MUST NOT be accepted as a CLI argument.
3. Save both to the profile's client config. `client_secret` MUST be stored encrypted.
4. Proceed with the configured OAuth2 flow.

If `--reset` is passed, re-collect client credentials even if already stored, overwriting the existing config.

---

## 17. Refresh Semantics

Refresh logic applies to `oauth2` providers with refresh token capability.

### 17.1 Required Library Behavior

When a caller requests a usable access token:

1. If token is valid and not near expiry, return it.
2. If token is expired or near expiry, attempt refresh.
3. Refresh MUST resolve the saved OAuth client credentials for the provider.
4. If refresh succeeds, update the record.
5. If refresh fails, set state appropriately and surface an error.

### 17.2 Near-Expiry Window

Implementations SHOULD refresh within a configurable window before expiry.

Recommended default:
- 300 seconds before `expires_at`

### 17.3 Refresh Failure Status

Recommended transitions:
- refreshable failure: remain `expired`
- non-recoverable failure: transition to `invalid`

---

## 18. Revoke vs Remove Semantics

These operations MUST be distinct.

### 18.1 Revoke
`revoke(provider)` means:

1. attempt remote credential revocation if the provider supports it,
2. remove or invalidate local credential material,
3. mark status as revoked or remove the record.

### 18.2 Remove
`remove(provider)` means:

1. delete local credential material,
2. do not contact remote provider,
3. unregister only the local connection state.

---

## 19. Export Semantics

Export converts stored credentials into runtime-friendly output.

### 19.1 Supported Formats

Implementations SHOULD support:
- `env`
- `shell`
- `json`

### 19.2 Provider Export Map

Provider definitions specify canonical environment variable names for credential fields.

Only the `access_token` (OAuth2) or `api_key` is exported. Refresh tokens are internal — authsome handles refresh transparently and MUST NOT export them.

Example:

```json
{
  "export": {
    "env": {
      "access_token": "GITHUB_TOKEN"
    }
  }
}
```

For `api_key` providers:

```json
{
  "export": {
    "env": {
      "api_key": "OPENAI_API_KEY"
    }
  }
}
```

### 19.3 Safe Defaults

- `get` returns metadata by default; use `--show-secret` to reveal a specific credential value.
- `export` explicitly reveals runtime values — treat its output as sensitive.
- `run` injects values directly into the subprocess environment without printing them.
- Default export format is `env` when `--format` is not specified.

---

## 20. CLI Specification

The Python implementation uses the executable name `authsome`. This spec uses `authsome` in all examples.

### 20.1 Global Flags

All commands SHOULD support:

- `--profile <name>`
- `--json`
- `--quiet`
- `--no-color`

### 20.2 Commands

#### `authsome init`
Initialize `~/.authsome/`, generate `master.key`, write `config.json` and `version`, create the `default` profile directory.

#### `authsome list`
Show all known providers (bundled and registered) with their current state for the active profile. See section 5.3 for output format.

#### `authsome login <provider>`
Authenticate with the provider using its configured flow.

Optional flags:
- `--flow <flow>` — override the provider's default flow (e.g. `device_code` instead of `pkce`)
- `--scopes <csv>` — request specific scopes
- `--connection <name>` — target a named connection (default: `default`)
- `--client-id <value>` — supply `client_id` directly (OAuth2 only; not sensitive)
- `--reset` — re-collect and overwrite stored client credentials before running the flow

Behavior rules:
- Profile defaults to `default`, connection defaults to `default`
- If the provider is already `connected`, exit with an error instructing the user to revoke first
- `client_secret` is NEVER accepted as a CLI argument; it is always collected via the Sensitive Input Pipeline (see section 27)
- If client credentials are already stored and `--reset` is not passed, reuse them without prompting
- Bundled providers do not imply bundled OAuth client credentials

#### `authsome revoke <provider>`
Revoke credentials remotely if the provider supports it, then delete local credential state.

Optional flags:
- `--connection <name>`

#### `authsome remove <provider>`
Delete local credential state without contacting the remote provider.

Optional flags:
- `--connection <name>`

#### `authsome get <provider>`
Return connection metadata. Safe by default — no secrets shown.

Optional flags:
- `--connection <name>`
- `--field <field>` — return a specific field value
- `--show-secret` — allow a secret field to be revealed (must be combined with `--field`)

#### `authsome inspect <provider>`
Return the provider definition and local connection summary.

Optional flags:
- `--connection <name>`

#### `authsome export <provider>`
Export credential material in the selected format. Default format is `env`.

Optional flags:
- `--connection <name>`
- `--format env|shell|json`
- `--prefix <prefix>` — prepend a string to all exported variable names

#### `authsome run --provider <provider> -- <command...>`
Run a subprocess with access tokens injected as environment variables. Tokens are refreshed before injection if near expiry. If any specified provider is not `connected`, exit with an error before spawning the subprocess.

Flags:
- `--provider <provider>` — repeatable; inject credentials for each named provider
- `--connection <provider=name>` — repeatable; specify a non-default connection for a provider

Injected values follow each provider's `export.env` map (access token only — refresh tokens are never injected).

#### `authsome register <path>`
Register a provider definition from a local JSON file.

Optional flags:
- `--force` — overwrite if provider already exists

#### `authsome whoami`
Show the active profile name and basic local context.

#### `authsome doctor`
Run health checks on directory layout, encryption availability, provider parsing, and store access.

### 20.3 Profile Commands

Optional advanced commands:

#### `authsome profile list`
List local profiles.

#### `authsome profile create <name>`
Create a new profile.

#### `authsome profile use <name>`
Set the global default profile.

---

## 21. CLI Output Contract

### 21.1 Human Output
Human-readable output may vary, but should preserve command semantics.

### 21.2 JSON Output
Structured output MUST be stable enough for machine use.

Example for `authsome list --json` — all three states represented:

```json
{
  "profile": "default",
  "providers": [
    {
      "name": "github",
      "auth_type": "oauth2",
      "state": "connected",
      "scopes": ["repo", "read:user"],
      "expires_at": "2026-05-01T12:00:00Z"
    },
    {
      "name": "google",
      "auth_type": "oauth2",
      "state": "configured"
    },
    {
      "name": "openai",
      "auth_type": "api_key",
      "state": "connected"
    },
    {
      "name": "linear",
      "auth_type": "oauth2",
      "state": "available"
    }
  ]
}
```

Note: the field is `state` (not `status`) at the list level. `status` remains the field name inside a connection record (section 14.3).

### 21.3 Exit Codes

Recommended exit code semantics:

- `0` success
- `1` generic failure
- `2` invalid usage
- `3` provider not found
- `4` authentication failed
- `5` credential missing
- `6` refresh failed
- `7` store unavailable

---

## 22. Library Interface Contract

Each implementation should expose native APIs idiomatic to its language, but the following conceptual operations MUST exist.

### 22.1 Core Operations

- `listProviders()`
- `getProvider(name)`
- `registerProvider(definition)`
- `listConnections(profile, provider?)`
- `getConnection(provider, profile, connectionName)`
- `getDefaultConnection(provider, profile)`
- `setDefaultConnection(provider, profile, connectionName)`
- `login(provider, options)`
- `getAccessToken(provider, profile, connectionName)`
- `getAuthHeaders(provider, profile, connectionName)`
- `revoke(provider, profile, connectionName)`
- `remove(provider, profile, connectionName)`
- `export(provider, profile, connectionName, format)`
- `run(command, providers, profile)`

### 22.2 OAuth Client Config Operations

- `getClientConfig(profile, provider)`
- `setClientConfig(profile, provider, config)`
- `removeClientConfig(profile, provider)`

### 22.3 Expected Error Categories

- provider not found
- unsupported auth type
- unsupported flow
- credential missing
- app credentials missing
- token expired and refresh failed
- encryption unavailable
- store unavailable
- invalid provider schema

---

## 23. Auth Header Construction Rules

### 23.1 OAuth2
For OAuth2 providers, `getAuthHeaders()` SHOULD produce:

```json
{
  "Authorization": "Bearer <access_token>"
}
```

unless the provider definition specifies otherwise.

### 23.2 API Key
For API key providers, header construction follows provider config.

Examples:

```json
{
  "Authorization": "Bearer <api_key>"
}
```

or

```json
{
  "X-API-Key": "<api_key>"
}
```

---

## 24. Provider Registration Contract

`register` adds or updates a provider definition in `providers/<name>.json`.

### 24.1 Required Validation

Implementations MUST validate:
- required fields exist,
- `name` is filesystem-safe,
- `auth_type` is recognized,
- flow is valid for auth type,
- URLs are syntactically valid where required.

### 24.2 Update Behavior

If a provider already exists:
- implementations MAY overwrite only with explicit confirmation or force mode,
- library APIs SHOULD expose replace/update semantics explicitly.

---

## 25. Built-In Providers

Implementations MAY ship bundled provider definitions.

Recommended initial providers:

### OAuth2
- github
- google
- slack
- notion
- linear

### API key
- openai
- anthropic
- tavily
- serpapi
- resend
- stripe

Bundled providers MUST follow the same provider schema as local registered providers.

Bundled providers MUST NOT imply bundled OAuth app credentials.

---

## 26. Security Requirements

### 26.1 Sensitive Values

The following values MUST be treated as sensitive at all times:
- `client_secret`
- `access_token`
- `refresh_token`
- `api_key`
- any provider-issued credential

`client_id` is not sensitive and may appear in CLI arguments, logs, and output.

### 26.2 No Secrets as CLI Arguments

Sensitive values MUST NOT be accepted as CLI arguments. This prevents secrets from appearing in shell history and process listings.

- `--client-secret` flag MUST NOT exist
- API key collection via CLI flag MUST NOT exist
- All sensitive values are collected via the Sensitive Input Pipeline (section 27)

### 26.3 Encrypted Storage

All sensitive fields MUST be encrypted at rest using the envelope format defined in section 11.4. Implementations MUST NOT write plaintext secrets to disk.

### 26.4 Default Secret Handling

Implementations MUST avoid printing raw secrets in normal output. Secrets are only revealed when the user explicitly passes `--show-secret` combined with `--field`.

### 26.5 Process Injection

`authsome run` MUST inject access tokens into the subprocess environment without printing them to stdout or logging them. Only access tokens (or api keys) are injected — refresh tokens are never exposed.

### 26.6 Logging

Secret material MUST NOT appear in logs or error messages. Errors SHOULD identify the failed provider and operation without leaking credential values.

### 26.7 Local Access Assumption

This spec assumes the local machine and user account are trusted relative to remote services. Encryption at rest protects against offline file access, not a compromised running process.

---

## 27. Sensitive Input Pipeline

The Sensitive Input Pipeline is the standard mechanism for collecting any secret value interactively. It auto-detects the appropriate collection method in this order:

### 27.1 Collection Order

1. **Environment variable** — if the provider definition specifies an env var for the value (e.g. `client.client_secret_env`, `api_key.env_var`), check it first. If set and non-empty, use it with no user interaction.

2. **Secure browser bridge** — if a graphical display is available (macOS: always; Linux: if `DISPLAY` or `WAYLAND_DISPLAY` is set; CI/headless: never). Spins up a temporary localhost HTTP server, opens a local form in the browser, collects the secret, and shuts down. The value never appears in the terminal, shell history, or process list.

3. **Masked terminal input** — fallback when no display is available (SSH, CI, Docker). Uses `getpass` or equivalent. Input is not echoed.

### 27.2 What Uses the Pipeline

- `client_secret` during `authsome login` for OAuth2 providers
- API key during `authsome login` for `api_key` providers

### 27.3 Rules

- Implementations MUST use this pipeline for all sensitive collection — no alternative paths
- The collected value MUST be encrypted immediately before any storage or further processing
- The value MUST NOT be written to any log, temp file, or shell history

---

## 28. Concurrency and Locking

Implementations SHOULD guard write operations with profile-level locking.

Recommended behavior:

1. acquire profile lock,
2. read current record,
3. apply update,
4. write updated record,
5. release lock.

Locks MAY be advisory.

---

## 29. Compatibility Rules

### 29.1 Backward Compatibility

Implementations reading older schema versions SHOULD migrate in memory where possible.

### 29.2 Forward Compatibility

Implementations MUST ignore unknown fields.

### 29.3 Cross-Language Compatibility Goal

A Python and JavaScript implementation are considered compatible if they can:

- read the same provider definitions,
- locate the same profile directories,
- interpret the same JSON records,
- decrypt records using the same shared keying mode,
- perform the same command semantics.

---

## 30. Minimum Viable Compliance

An implementation is minimally compliant with spec version 1 if it supports:

- local root resolution,
- implicit profile `default`,
- implicit connection `default`,
- JSON provider definitions,
- encrypted OAuth client config and connection storage,
- `oauth2` with browser-capable PKCE flow,
- `api_key` flow (env var first, prompt fallback),
- `list`, `login`, `get`, `remove`, `export`, `run`,
- stable JSON command output.

---

## 31. Deferred Scope / Future Extensions

The following areas are intentionally out of scope for the initial local-first spec, but are reasonable future extensions once the core local model is stable.

### 31.1 Remote Sync

Remote sync allows the local credential store to project selected records into external secret managers or secure remote backends.

Remote sync MUST treat the local store as canonical. Remote systems are sync targets, not the primary source of truth.

Possible sync targets:
- Doppler
- 1Password
- Vault KV
- cloud secret managers
- encrypted file/object storage

Recommended future sync modes:
- `flattened_env`
- `flattened_json_map`
- `json_blob`
- provider-specific sync adapters

Future remote sync work should define:
- export/import semantics
- conflict resolution rules
- selective sync by profile/provider/connection
- secret rotation and remote overwrite policies
- encryption and trust boundary requirements
- one-way vs two-way sync behavior

### 31.2 Secret References and Broker Mode

A future version may support secret references or runtime handles instead of returning raw secret material.

Examples:
- process-local secret injection handles
- opaque references that are resolved only at runtime
- brokered access for agents without direct secret exposure

### 31.3 HTTP Client and Framework Adapters

Future implementations may define standard adapters for:
- HTTP clients
- web frameworks
- MCP servers
- subprocess runners
- background workers

These adapters should remain thin wrappers over the core provider and connection model.

### 31.4 Token Introspection and Validation Hooks

Future versions may define provider hooks for:
- token validation
- account lookup
- scope inspection
- connection health checks
- provider-specific refresh or revocation semantics

### 31.5 Team / Shared Profiles

The initial spec is single-user local-first. A future version may define:
- shared profile layouts
- delegated access to shared connections
- imported connection bundles
- collaboration-safe locking and audit metadata

### 31.6 Runtime Authorization and Approval Layers

The initial spec focuses on credential lifecycle, not runtime authorization.

Future layers may define:
- purpose-scoped approvals
- action-level policy checks
- delegated identity chains
- human-in-the-loop confirmations
- approval-bound temporary credentials

### 31.7 Audit and Event Stream

A future version may define a portable event model for:
- login events
- refresh events
- export events
- revoke/remove events
- sync events
- runtime access events

### 31.8 Compliance Principle for Future Extensions

Future extensions SHOULD avoid breaking:
- local portability
- profile/provider/connection identity
- JSON serialization rules
- encrypted record compatibility

---

## 32. Non-Goals

The following are explicitly out of scope for spec version 1:

- hosted sync service
- multi-user team sharing
- distributed secret replication
- enterprise policy engine
- runtime approval workflows
- organization-wide RBAC
- MCP gateway behavior
- remote execution control plane

These may be layered later, but are not required for interoperability.

---

## 33. Example End-to-End Behavior

### 33.1 OAuth2 Provider Login (PKCE)

1. User runs `authsome login github --client-id abc123`
2. CLI resolves bundled provider definition for `github`
3. `client_id` is taken from the `--client-id` flag; `client_secret` is collected via the Sensitive Input Pipeline (browser bridge or getpass)
4. CLI saves encrypted client credentials under profile `default`, provider `github`
5. CLI generates PKCE challenge and starts a temporary localhost callback server
6. User authorizes in browser
7. CLI exchanges authorization code for token set
8. CLI stores encrypted connection record under profile `default`, provider `github`, connection `default`
9. `authsome list` now shows `github` as `connected`

### 33.2 Re-login Attempt (Error Case)

1. User runs `authsome login github` while already connected
2. CLI exits with error: `already connected to github. Run 'authsome revoke github' to disconnect, then login again.`

### 33.3 Multiple Connections for the Same Provider

1. User runs `authsome login sendgrid` → stores connection `default`
2. User runs `authsome login sendgrid --connection bulk` → stores a second connection `bulk`
3. `authsome export sendgrid --connection bulk` exports the `bulk` connection's API key
4. `authsome run --provider sendgrid --connection sendgrid=bulk -- python send.py` injects the `bulk` credentials

### 33.4 API Key Provider Login (Automated via Env Var)

1. User sets `OPENAI_API_KEY=sk-...` in their environment
2. User runs `authsome login openai`
3. CLI detects `api_key.env_var = "OPENAI_API_KEY"` in the provider definition
4. CLI reads the key from the environment — no prompt shown
5. CLI stores encrypted key; connection state becomes `connected`

### 33.5 Registered Custom Provider

1. User runs `authsome register ./acmecrm.json`
2. User runs `authsome login acmecrm --client-id abc123`
3. `client_secret` is collected via the Sensitive Input Pipeline
4. CLI saves client credentials, runs PKCE flow, stores connection record

### 33.6 Agent Runtime Usage

1. Agent script needs GitHub and OpenAI credentials
2. Agent runs: `authsome run --provider github --provider openai -- python agent.py`
3. CLI checks both providers are `connected` — exits with error if either is not
4. CLI refreshes tokens if near expiry
5. CLI spawns `python agent.py` with `GITHUB_TOKEN` and `OPENAI_API_KEY` injected into the environment
6. Agent uses the env vars directly; no credential management code needed

### 33.7 Library Usage (Python)

1. Python app calls `client.get_auth_headers("github")`
2. Library reads stored connection record for profile `default`, connection `default`
3. Library checks token expiry — refreshes if within 300 seconds of `expires_at`
4. Library returns `{"Authorization": "Bearer <access_token>"}`

---

## 34. Naming Recommendations

The following naming is standardized across implementations:

- spec name: `authsome spec`
- root env var: `AUTHSOME_HOME`
- default root dir: `~/.authsome`
- default profile: `default`
- default connection: `default`

Language-specific package names:
- Python package: `authsome`
- JavaScript package: `@authsome/core`
- CLI executable: `authsome`

---

## 35. Summary

This spec defines a portable local auth substrate with:

- provider-aware local auth with a three-state model (`available → configured → connected`),
- portable provider definitions shared across implementations,
- per-provider OAuth client config (one per provider per profile),
- multiple named connections per provider,
- a Sensitive Input Pipeline that collects secrets safely (env var → browser bridge → getpass),
- no secrets accepted as CLI arguments,
- cross-language credential compatibility via portable encryption envelopes,
- local encrypted storage with AES-256-GCM,
- normalized CLI semantics with `authsome` as the reference executable,
- embeddable library semantics.

It is intended to be the smallest shared foundation that multiple implementations can build on without fragmenting behavior or storage.

