# Authsome Client-Server Refactor Design Notes

This document captures the shared design decisions from reviewing PR #142 and
planning the client-server refactor.

## Goal

Authsome should move toward a client-server architecture so the local daemon can
serve as the first implementation of the server boundary, and a hosted version
can be introduced in a later release.

For this refactor, the goal is a boundary refactor only. Do not rewrite working
OAuth protocol mechanics except where daemon/session support strictly requires
it.

## High-Level Package Shape

Target module ownership:

```text
authsome/
  auth/       # auth flows, sessions, providers, token lifecycle, resolution
  vault/      # encrypted secret storage
  server/     # FastAPI HTTP API over AuthService
  cli/        # Click commands, daemon control, HTTP API client
  proxy/      # short-lived request interception and credential injection
  identity/   # current local identity; multi-profile later
  audit/      # later; skipped for this refactor
```

Avoid a vague `runtime` package. Delete the current `context.py` style central
wiring container. Wiring should be explicit in server and CLI modules.

## CLI And Daemon

- All normal CLI commands require the daemon.
- Commands such as `authsome login github`, `authsome logout`, `authsome list`,
  and `authsome run ...` should call `ensure_daemon()` first.
- If the daemon is healthy, reuse it.
- If not running, start it automatically.
- If unhealthy, restart it automatically, as long as it is identifiable as the
  current user's Authsome daemon.
- Unknown processes on the fixed daemon port must not be killed.
- Daemon startup/readiness failures should have a distinct CLI exit code.
- Startup errors should show a focused daemon error, daemon log path, and useful
  commands such as `authsome daemon status` and `authsome daemon restart`.

CLI should become a package:

```text
cli/
  __init__.py
  main.py
  client.py
  daemon_control.py
  output.py
```

`cli/client.py` owns the internal HTTP API client. Do not expose it as a public
Python SDK yet. Do not keep a generic runtime client abstraction or in-process
transport.

Daemon CLI UX:

```text
authsome daemon start
authsome daemon stop
authsome daemon restart
authsome daemon status
authsome daemon logs
authsome daemon serve
```

`serve` is the foreground/debug entrypoint and background subprocess target.

## Local Daemon Settings

- V1 is local-only. No hosted/server mode config yet.
- Fixed daemon bind address and port:

```text
127.0.0.1:7998
```

- No dynamic fallback port.
- Keep existing `AUTHSOME_HOME`-style data location override.
- Daemon state/log files should live under the Authsome home, for example:

```text
~/.authsome/
  daemon/
    daemon.pid
    daemon.log
    daemon.json
```

The daemon should be a long-lived background process with a proper PID file.
The CLI should be able to stop/restart it.

## Health And Readiness

Expose both:

```text
GET /health
GET /ready
```

`/health` proves the HTTP process is alive and is Authsome.

`/ready` proves dependencies are usable:

- config
- storage
- vault/crypto
- provider registry

CLI should use `/health` for daemon detection and `/ready` before executing
user-facing commands.

## Server

Use FastAPI for the server.

Server should be a first-class package:

```text
server/
  __init__.py
  app.py
  daemon.py
  dependencies.py
  schemas.py
  routes/
    __init__.py
    health.py
    auth.py
    connections.py
    providers.py
    proxy.py
```

- `server/app.py` creates the FastAPI app.
- `server/daemon.py` handles local daemon process serving concerns.
- `server/dependencies.py` wires concrete local dependencies.
- Route handlers should map HTTP requests/responses to `AuthService` calls.
- Server routes should depend on `AuthService` only.
- Server should not call `Vault` directly in v1.
- Store the singleton `AuthService` on `app.state.auth_service`.
- Avoid module-level globals for the service.

Server dependencies such as FastAPI and uvicorn may become optional later. For
now they are acceptable while local daemon is required.

## Auth Service

Rename/reframe `AuthLayer` as `AuthService`. A temporary compatibility alias
can remain while downstream imports migrate.

`AuthService` is the main auth domain entrypoint and owns:

- login/logout/revoke
- auth sessions
- provider registry access
- token refresh
- credential/header resolution
- connection metadata/default connection behavior

Internal structure should be deeper inside `auth`, not spread across tiny top
level modules:

```text
auth/
  service.py
  sessions.py
  input.py
  connections.py
  flows/
  providers/
  models/
```

`AuthService` should receive dependencies, not construct them:

```python
class AuthService:
    def __init__(self, *, vault, provider_registry, identity):
        ...
```

Concrete construction belongs in `server/dependencies.py`.

One `AuthService` instance should be created at daemon startup and reused for
all requests.

## Identity

Create an `identity` module.

V1 identity is local-only and hardcoded to the current default identity:

```text
identity.current()
```

Do not implement multi-profile, user accounts, or organizations now.

Remove profile parameters from CLI/server API calls. Internally use
`identity.current()` wherever the previous profile/default profile was needed.
Multi-profile support can be designed later.

## Provider Registry

Provider registry belongs inside `auth`.

Provider definitions describe auth behavior, host routing, API-key validation,
OAuth URLs, scopes, and proxy matching. Therefore bundled/custom provider
resolution is an auth concern, not a generic store concern.

Provider management API:

```text
GET    /providers
GET    /providers/{provider}
POST   /providers
DELETE /providers/{provider}
```

Only custom providers are deletable. Bundled providers are not deleted.
Revoking/resetting credentials is a separate connection/auth operation.

## Vault

Preserve existing vault behavior for this refactor.

- Vault remains responsible for secure encrypted secret storage.
- Do not redesign encryption/storage behavior.
- Do not introduce broad generic storage abstractions such as a mega `AppStore`.
- Do not expose raw vault endpoints in v1.
- Server calls auth; auth calls vault internally.

Raw vault API is out of scope.

## Audit

Skip audit redesign for this refactor. It will be tackled later.

## Server API Scope

Initial server API exposes only auth-side operations, not raw vault operations.

Suggested API surface:

```text
GET  /health
GET  /ready

POST /auth/sessions
GET  /auth/sessions/{id}
POST /auth/sessions/{id}/resume
GET  /auth/callback/oauth

GET  /auth/sessions/{id}/input
POST /auth/sessions/{id}/input

GET  /connections
GET  /connections/{provider}/{connection}
POST /connections/{provider}/{connection}/logout
POST /connections/{provider}/revoke
POST /connections/{provider}/{connection}/default

GET    /providers
GET    /providers/{provider}
POST   /providers
DELETE /providers/{provider}

GET  /proxy/routes
POST /credentials/resolve
POST /credentials/export
```

`POST /credentials/export` remains an explicit CLI export path for raw secrets.
The proxy should use `/credentials/resolve`.

## API Schemas

Use separate server request/response schemas for HTTP boundaries.

Do not expose internal auth/vault models directly unless they are explicitly
public-safe. This avoids leaking secrets, OAuth state, PKCE verifiers, device
codes, or internal vault fields.

## Auth Sessions

Auth sessions are owned by `auth`, not server.

V1 sessions are in memory only. This is acceptable because sessions are short
lived. Persistent/distributed sessions can be designed later for hosted scale.

Use typed session models, not loose payload dictionaries.

Public session responses should expose only relevant fields:

- id
- provider
- connection
- status
- message/error
- timestamps
- `next_action`

Hide protocol internals such as:

- OAuth state
- PKCE verifier
- provider device code
- secrets

All session endpoints should return the same public `AuthSessionResponse`
schema:

```text
GET  /auth/sessions/{id}
POST /auth/sessions/{id}/resume
```

Use typed/tagged `next_action` objects instead of loose dicts.

Example action types:

```text
open_url
device_code
poll
done
none
```

Example:

```json
{
  "id": "sess_123",
  "provider": "github",
  "connection": "default",
  "status": "waiting_for_user",
  "next_action": {
    "type": "open_url",
    "url": "https://github.com/login/oauth/authorize?..."
  }
}
```

## OAuth Callback

All local OAuth browser flows use one fixed registered callback URL:

```text
http://127.0.0.1:7998/auth/callback/oauth
```

Session lookup happens through the opaque OAuth `state` value.

Use the simplest v1 state design:

- Generate high-entropy random state.
- Store it on the in-memory auth session.
- Maintain an in-memory `state -> session_id` index.
- Callback looks up the session by state and validates it.

Do not put the session id in the callback path because provider redirect URIs
must be stable and registered.

## API Key Browser Flow

API-key login uses browser-based input, not CLI prompt, for normal flow.

Flow:

1. CLI starts auth session.
2. Server/auth returns `next_action.open_url` pointing to:

```text
http://127.0.0.1:7998/auth/sessions/{session_id}/input
```

3. CLI opens the browser and polls session status.
4. Browser form posts the API key directly to the daemon/server.
5. Auth validates provider-specific API-key rules, stores encrypted secret in
   vault, and marks the session completed.
6. CLI never receives the API key.

Input field definitions and validation are owned by `auth`.
HTML rendering is owned by `server`.

Use simple server-rendered HTML for v1.

No per-session form token/CSRF protection is required in v1, but this must be
documented in `docs/security.md` as a known local-daemon tradeoff.

## Device-Code Flow

Use CLI-driven polling for v1. Device-code is the exception to non-blocking
login because the flow cannot complete without polling the provider token
endpoint.

Flow:

1. CLI starts a device-code auth session.
2. Auth requests a device code from the provider.
3. Session response includes a `device_code` next action with:
   - verification URI
   - optional complete URI
   - user code
   - interval
4. CLI displays instructions and repeatedly calls session resume/status.
5. Auth polls provider during those calls.

No daemon background polling task in v1.

## Login CLI Semantics

`authsome login` starts an auth session and exits successfully after the session
is created and the next action is opened/displayed.

For browser OAuth and API-key input flows, success means "login started", not
"provider is connected". Users can run:

```text
authsome list
```

to verify completion.

Device-code flow may block and poll because device-code support is required in
v1 and no daemon background polling task is planned.

## Connections

Keep named connections.

Connection listings should include provider-level default connection metadata.
CLI resolves omitted connection names to the provider default.

Default connection is auth-owned provider/connection metadata, not CLI-only
state.

Add API:

```text
POST /connections/{provider}/{connection}/default
```

CLI command:

```text
authsome connection set-default <provider> <connection>
```

Credential resolution accepts optional `connection`:

```json
{
  "provider": "openai",
  "connection": "work"
}
```

If omitted, auth resolves the provider's default connection.

## Proxy

Proxy remains short-lived and scoped to `authsome run`.

Flow:

1. `authsome run <cmd>` ensures daemon is running/ready.
2. CLI starts short-lived proxy.
3. Proxy asks daemon for route table.
4. Proxy runs child process with proxy environment variables.
5. Proxy lazily resolves credentials from daemon and caches them in memory.
6. Child exits.
7. Proxy exits and drops cache.

The daemon is long-lived. The proxy is not.

## Proxy Routes

Provider definitions already carry routing signals via `host_url`.

Examples:

```json
"host_url": "api.openai.com"
"host_url": "regex:.*googleapis.*"
```

Proxy should not manually configure routes. It should get routes from daemon:

```text
GET /proxy/routes
```

`/proxy/routes` should include only connected providers.

Proxy passes through requests for unconnected known providers unchanged.

`/proxy/routes` should include provider auth endpoint exclusions so proxy does
not inject credentials into OAuth endpoints:

- authorization URL
- token URL
- revocation URL
- device authorization URL
- registration endpoint

Keep existing `host_url` behavior:

- exact host
- regex host
- path-prefix support

No larger route DSL in v1.

Ambiguous matches:

- Use first matching route.
- Log a warning if multiple routes matched.
- Keep v1 code simple.

Route ordering should be deterministic from the daemon response; exact hosts
can come before regex hosts, then provider name.

`RouteMatch.connection` should be optional internally. `None` means resolve the
provider default connection instead of hardcoding `"default"`.

## Proxy Credential Cache

Proxy should not hit the daemon on every network request.

It should maintain an in-memory credential cache for the lifetime of
`authsome run`.

Cache key:

```text
(provider, connection/default)
```

Daemon credential resolution response:

```json
{
  "provider": "github",
  "connection": "default",
  "headers": {
    "Authorization": "Bearer ..."
  },
  "expires_at": "2026-05-05T12:00:00Z"
}
```

For API keys:

```json
{
  "provider": "openai",
  "connection": "default",
  "headers": {
    "Authorization": "Bearer sk-..."
  },
  "expires_at": null
}
```

No `cacheable` field. No `refresh_after` field.

Proxy logic:

- If missing cache, call daemon.
- If `expires_at` is null, use cache.
- If now is within 5 minutes of `expires_at`, evict and resolve again.
- Otherwise use cache.

Near-expiry window is fixed at 5 minutes, not configurable in v1.

The daemon/auth handles refresh internally during `/credentials/resolve`.

If refresh fails, return a typed error such as `reauth_required` or
`refresh_failed`. Auto-login from proxy is out of scope for v1.

## Proxy Header Injection

Proxy injection is headers-only for v1.

Single provider-specific header is sufficient.

Proxy should overwrite the provider-specific configured auth header. This is
intentional because applications/SDKs may send fake credentials to initialize.

Only overwrite headers known for the matched provider. Do not strip broad
credential-looking headers.

No query parameter or body injection in v1.

## Local Security Tradeoffs

V1 local daemon security:

- Bind only to `127.0.0.1`.
- No local bearer token in v1.
- No API-key input form token/CSRF protection in v1.
- Secrets are encrypted at rest in the vault.
- Proxy credential cache is in memory and scoped to `authsome run`.

Document these assumptions and future hardening items in:

```text
docs/security.md
```

## OAuth Library Migration

Using Authlib for OAuth mechanics is desirable, but it is out of scope for this
refactor.

Tracked separately:

```text
https://github.com/manojbajaj95/authsome/issues/145
```

Do not mix Authlib migration into the client-server boundary refactor.
