# Ubiquitous Language

## Architecture Layers

| Term | Definition | Aliases to avoid |
| --- | --- | --- |
| **Vault** | The secure credential store. Owns the master key and SQLite storage. Exposes a generic encrypted key-value interface (`get`/`put`/`delete`/`list`). Encrypts full record blobs at rest. Does not know about credential types or token lifecycle. | Store, keystore, secret store |
| **AuthLayer** | The authentication and credential lifecycle layer. Owns OAuth flows, token refresh, login/logout/revoke. Receives Vault and ProviderRegistry as dependencies. | Auth client, auth service |
| **AuthsomeContext** | The runtime wiring container assembled once per CLI invocation. Holds Vault, AuthLayer, and ProxyRunner as attributes. No business logic of its own. | Client, session, app |
| **Sensitive** | A field annotation (`Annotated[str, Sensitive()]`) marking fields that contain secret values and must be redacted before display or logging. The `redact()` utility in `utils.py` inspects this annotation to replace values with `"***REDACTED***"`. | Secret field, encrypted field |

## Identity & Authentication

| Term | Definition | Aliases to avoid |
| --- | --- | --- |
| **Provider** | An external service (GitHub, Google, OpenAI, etc.) identified by a unique name and described by a `ProviderDefinition` | Service, integration, app |
| **AuthType** | The authentication mechanism a provider uses — either `oauth2` or `api_key` | Auth method, auth strategy |
| **Flow** | The specific protocol executed to obtain credentials for a provider (PKCE, Device Code, DCR+PKCE, API Key) | Auth flow, login flow, grant type |
| **Connection** | A named, authenticated session binding a Profile to a Provider; holds credentials | Credential, token, session, auth |
| **ConnectionStatus** | The lifecycle state of a Connection: `connected`, `expired`, `revoked`, `invalid`, `not_connected` | Status, state |
| **Profile** | A named identity context that groups Connections (e.g., `work`, `personal`, `default`). Currently the proxy for Identity — the profile slug scopes all credentials within the Vault. Future: replaced by cryptographic agent identity (Ed25519 + SPIFFE URI). | Environment, workspace, account |
| **Scope** | An OAuth2 permission requested from a Provider during a Flow | Permission, role |

## Provider Configuration

| Term | Definition | Aliases to avoid |
| --- | --- | --- |
| **ProviderDefinition** | The complete JSON schema describing a provider's AuthType, Flow, OAuth endpoints, and export mapping | Provider config, provider spec |
| **BundledProvider** | A ProviderDefinition shipped inside the library package | Built-in provider, default provider |
| **ProviderRegistry** | The system that resolves a provider name to its ProviderDefinition, checking local overrides before bundled definitions | Provider loader, provider resolver |
| **OAuthConfig** | The OAuth2-specific section of a ProviderDefinition (authorization URL, token URL, PKCE support, etc.) | OAuth settings |
| **ApiKeyConfig** | The API-key-specific section of a ProviderDefinition (header name and prefix) | API key settings |
| **ClientCredentials** | The OAuth2 `client_id` and `client_secret` configured for a Provider within a Profile, stored in a `ProviderClientRecord` | OAuth client, app credentials |

## Storage & Credentials

| Term | Definition | Aliases to avoid |
| --- | --- | --- |
| **ConnectionRecord** | The persisted credential record for a Connection: plaintext tokens or API key (encrypted at rest by the Vault), scopes, expiry, and account info. `schema_version = 2`. | Token record, credential record |
| **ProviderMetadataRecord** | Non-secret per-profile record tracking which Connections exist for a Provider and which is the default | Provider metadata |
| **ProviderStateRecord** | Transient per-profile record tracking the last refresh attempt and any errors for a Provider | Provider state |
| **AccountInfo** | The identity fields (id, label) returned by a Provider and stored on a ConnectionRecord | User info, identity |
| ~~**EncryptedField**~~ | *Removed.* No longer part of the public model layer. Encryption is now handled entirely within the Vault. Tokens are stored as plaintext `str` on `ConnectionRecord` and marked with the `Sensitive` annotation for display safety. | — |
| ~~**CredentialStore**~~ | *Deprecated.* Internal implementation detail of the Vault. Do not use in documentation or code outside `vault/`. | — |
| ~~**CryptoBackend**~~ | *Deprecated.* Internal implementation detail of the Vault. Do not use in documentation or code outside `vault/`. | — |

## Flows

| Term | Definition | Aliases to avoid |
| --- | --- | --- |
| **PKCE Flow** | Browser-based OAuth2 authorization code grant with PKCE; spins up a local callback server | OAuth flow, browser flow |
| **Device Code Flow** | Headless OAuth2 via device authorization endpoint; polls until the user authorizes on another device | Headless flow, device flow |
| **DCR PKCE Flow** | Dynamic Client Registration followed immediately by a PKCE Flow; used when providers require per-client registration | Dynamic registration flow |
| **API Key Flow** | Collects an API key from the user via a Browser Bridge and stores it as a ConnectionRecord | Key flow |
| **Browser Bridge** | A short-lived local HTTP server that presents a secure form to collect secrets (API keys) from the user interactively | Secure input, form server |

## Proxy

| Term | Definition | Aliases to avoid |
| --- | --- | --- |
| **AuthProxy** | A local mitmproxy-based HTTP proxy that intercepts outgoing requests and injects auth headers from active Connections | Proxy, HTTP proxy |
| **RunningProxy** | A handle to an AuthProxy running in a background thread, with a `shutdown()` method | Proxy handle, proxy instance |

## Relationships

- A **Profile** contains zero or more **Connections**, each scoped to one **Provider**.
- A **Connection** is created by exactly one **Flow**; the FlowType is determined by the **ProviderDefinition**.
- A **ConnectionRecord** belongs to exactly one **Connection** and one **Profile**. Tokens are plaintext on the record; the **Vault** handles encryption transparently at write time.
- A **ProviderRegistry** resolves a provider name by checking local `~/.authsome/providers/` overrides before **BundledProviders**.
- The **Vault** encrypts full **ConnectionRecord** blobs using the master key it manages (file-based or OS keyring). The **AuthLayer** reads and writes records through the Vault without knowing the encryption details.
- An **AuthProxy** draws credentials from **Connections** in the active **Profile** via the **AuthLayer** and injects them as request headers.
- **AuthsomeContext** wires **Vault**, **AuthLayer**, and **ProxyRunner** together; the CLI creates one context per invocation.

## Example dialogue

> **Dev:** "If I call `authsome login github`, does it create a new **Profile**?"
>
> **Domain expert:** "No — `login` adds a **Connection** to the currently active **Profile**. A **Profile** is created automatically if it doesn't exist. The `login` command runs the **Flow** specified in the GitHub **ProviderDefinition** and stores the result as a **ConnectionRecord** via the **Vault**."
>
> **Dev:** "So the **Connection** is what I query later to get the access token?"
>
> **Domain expert:** "Exactly. When you call `get_access_token`, the **AuthLayer** looks up the **ConnectionRecord** for that **Provider** + **Profile** combination through the **Vault** (which decrypts transparently) and returns the plaintext token."
>
> **Dev:** "And if the token is expired, does it auto-refresh?"
>
> **Domain expert:** "Yes — the **ConnectionStatus** will show `expired`, and the **ConnectionRecord** holds the `refresh_token` so the **AuthLayer** can exchange it without re-running the **Flow**. The outcome is a new **ConnectionRecord** with updated tokens and `status = connected`."
>
> **Dev:** "What if I need to connect to two GitHub accounts?"
>
> **Domain expert:** "Use two **Profiles** — one per identity context. Each **Profile** has its own scoped keys in the **Vault**, so the two **Connections** to the `github` **Provider** are completely isolated."

## Flagged ambiguities

- **"client"** previously referred to `AuthClient` (the old SDK entry point). In v2, the entry point is **AuthsomeContext**. Avoid the phrase "auth client" — use **AuthLayer** for the authentication logic and **AuthsomeContext** for the assembled runtime. **ClientCredentials** / `ProviderClientRecord` remain valid for the OAuth2 `client_id`/`client_secret` pair.
- **"flow"** is used as both a `FlowType` enum value (a string like `"pkce"`) and an `AuthFlow` instance (the object that executes the protocol). Distinguish by saying **flow type** for the enum and **flow** or **flow handler** for the runtime object.
- **"provider"** can mean a provider name string (`"github"`), a `ProviderDefinition` object, or a row in the ProviderRegistry. Prefer **Provider** (capitalized) for the concept, **ProviderDefinition** for the JSON schema, and **provider name** for the identifier string.
- **"credential"** was used loosely in early documentation to mean both a **Connection** (the full authenticated session) and a specific secret (the token). Use **Connection** for the session and **access token** / **API key** for the individual secret values.
- **"encryption"** previously surfaced in doctor output and user-facing messages as a CredentialStore concern. In v2 it is a **Vault** concern. Prefer "vault encryption" or simply describe the mode (`local_key`, `keyring`) rather than referencing the removed CryptoBackend term.
