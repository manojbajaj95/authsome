# authsome — Design

_Status: Canonical · v1 · 2026-04-26_
_Supersedes: agent-sso-design.md, authsome-sidecar-design.md_

---

## What This Is

authsome is the local auth layer for AI agents. It answers the question no existing credential tool answers:

> **Which agent, acting on behalf of whom, accessed what credential — and was that allowed?**

Two deployment modes:

- **Sidecar**: `authsome run -- python agent.py` — transparent credential injection via HTTP proxy. No auth code in the agent.
- **Library**: `from authsome import AuthLayer; layer.get_access_token("github")` — direct programmatic API.

Both modes share the same layered architecture. The sidecar orchestrates the layers explicitly for proxy mode. The library exposes them through `AuthLayer`, a higher-level stateful orchestrator that can depend on a vault interface. The low-level primitives are always accessible independently.

---

## Architecture

Five internal layers plus explicit orchestrators. Each layer has one bounded responsibility.

**Rule: layers do not reach sideways into other layers. Explicit orchestrators compose them.**

This constraint makes every layer independently testable and independently swappable. In proxy mode, the sidecar is the orchestrator. In library mode, `AuthLayer` is the orchestrator and may accept any implementation of the vault interface.

```
authsome run -- <agent>
       │
       ▼
   [ sidecar ]            ← proxy-mode orchestrator
       │
       ├──▶ identity      ← who is acting, on whose behalf
       ├──▶ policy        ← is this allowed
       ├──▶ vault         ← retrieve encrypted credential
       ├──▶ auth          ← refresh if expired
       └──▶ audit         ← record everything
```

Library mode uses the same primitives without the proxy:

```python
auth_layer = AuthLayer(vault=my_vault, registry=providers, identity=agent_or_profile)
token = auth_layer.get_access_token("github", connection="main")
```

`AuthLayer` owns the library lifecycle: read from vault, refresh if needed, write back, and return a usable credential.

---

## Current Alpha Implementation

The alpha implementation intentionally covers the first useful slice:

- Auth layer with provider registry, OAuth/API-key acquisition flows, token refresh, and provider metadata.
- Vault layer with encrypted local storage.
- CLI commands for init, login, list, get, export, register, revoke/remove, doctor, whoami, and proxy-backed `run`.
- Host-based proxy injection using provider `host_url`.

Identity, Policy, and Audit are planned layers. They are part of the long-term architecture described in this document, but they are not required to understand the current alpha implementation.

---

## Layer Specifications

### Sidecar

**Owns**: process lifecycle, subprocess management, proxy wiring, full pipeline orchestration, vault write-back after token refresh.

Starts the HTTP proxy on a random local port. Spawns the agent as a subprocess with `HTTP_PROXY` set to the local proxy address. Intercepts outgoing HTTP requests from the agent. Calls Identity → Policy → Vault → Auth in sequence. Injects the resolved credential into the `Authorization` header. Forwards the authenticated request to the external API. After a token refresh, writes the fresh credential back to the vault. Tears down cleanly when the agent exits.

Does not store credentials. Does not make access decisions. Does not know about encryption.

**Known v1 limitations**:
- HTTPS interception requires TLS certificate trust (mitmproxy CA must be installed on the machine)
- Non-HTTP protocols (WebSockets, gRPC, database connections) are not intercepted
- Host-based routing is fragile if two providers share a base URL

**v1 routing contract**:
- Provider definitions may declare `host_url`.
- The proxy matches outbound requests by exact host.
- Ambiguous matches are not injected; the request is forwarded unchanged.
- The default connection is used for injected credentials.
- Path matching, header matching, priorities, and per-request connection selection are future work.

---

### Identity

**Owns**: agent identity, principal chain token.

Generates an Ed25519 key pair on first run. Stores the private key in the OS keychain. Registers the public key in a local identity registry. Receives the user token from the caller — never self-asserts the user identity. Combines the agent actor token and the user subject token into a single signed principal chain (actor=agent, subject=user).

**v1 — local-only:**
- Agent URIs use `agent://local/<name>` (e.g., `agent://local/cold_email`). This is a SPIFFE-inspired format, not actual SPIFFE compliance.
- User token is derived from the OS session (current user, machine ID). No explicit user login step is required for single-user local mode.

**Later:**
- Migrate agent URIs to real SPIFFE format: `spiffe://trust-domain/path`
- Migrate principal chain token to full RFC 8693 Token Exchange for multi-user and cross-boundary federation

Does not store credentials. Does not make access decisions. Does not know about token expiry.

---

### Policy

**Owns**: access control, allow/deny decisions.

Evaluates every credential request before the vault is touched. Receives the resolved principal chain (agent identity, user identity) from the sidecar as a parameter — it does not look up identities itself. Answers one question:

```
can(agent, on_behalf_of=user, operation, resource) → allow | deny
```

If deny, the request stops here. Nothing else runs. The audit layer records the denial.

**v1 — single-user default:**
An explicit default-allow policy covers fresh single-user installs. Without it, a new install with no policy config denies everything and is unusable. The default: `can(any_agent, on_behalf_of=local_user, any_operation, any_resource) → allow`. This is the same security posture as not having a policy layer — no regression, but the enforcement infrastructure is in place for when it matters.

**Later:** Cedar (Amazon's policy language) for full rule evaluation. TOML rules map to Cedar policies on migration.

Does not store credentials. Does not refresh tokens. Does not know about encryption.

---

### Vault

**Owns**: minimal credential storage interface.

Vault is intentionally small. It exposes only:

```python
vault.init()
vault.health()
vault.get(key)
vault.put(key, value)
vault.delete(key)
vault.list(prefix)
```

Vault does not know about OAuth, providers, token expiry, refresh, policy, audit, or principal-chain semantics. It stores and retrieves credential records by key. Orchestrators decide which keys to read, whether access is allowed, whether a token must be refreshed, and what should be audited.

**Backends**:
- Dev/test: simple JSON or file-backed vault.
- Local: encrypted SQLite key-value vault.
- Production/self-managed: Postgres or another durable backend.

The logical credential address is independent of physical storage. Conceptually, a credential is addressed by profile/user, provider/service, connection, and credential kind. A file backend may map that to nested directories. A KV backend may map it to a key such as `profile:<profile>:<provider>:connection:<name>`. A Postgres backend may map it to columns and indexes. The vault interface stays the same.

**Encryption guidance**:
- Agent identity gates access to the vault.
- The agent identity key should not directly be the symmetric data encryption key.
- Vault data should use a separate data encryption key (DEK).
- The DEK is wrapped or unwrapped by agent identity material, OS keychain material, or backend-specific key management.
- This allows identity rotation, recovery, and future multi-agent sharing without changing the vault API.

For the local encrypted backend, the expected primitive remains AES-256-GCM with a 256-bit random data key and a 96-bit random nonce per encryption.

Does not make access decisions. Does not refresh tokens. Does not know about the agent beyond whatever backend-specific key unwrapping is required to open the vault.

---

### Auth

**Owns**: token refresh, OAuth acquisition flows.

**Two levels — this is the key design decision.**

The tension: the sidecar needs a stateless, pure refresh function it can call as part of its pipeline. Library users need a stateful convenience wrapper that manages vault read/write for them. These are different things and should not be the same class.

**Low level — stateless refresh (`auth.flows`)**

A pure function. Receives expired credentials and refresh material. Calls the external token endpoint. Returns fresh credentials and updated expiry. No vault access. No side effects. Independently testable.

```python
# Called by the sidecar
fresh_token, expires_at = auth.flows.refresh(
    refresh_token=...,
    client_id=...,
    client_secret=...,
    token_url=...,
)
```

**High level — stateful client (`AuthLayer`)**

A convenience orchestrator with a vault dependency. Reads the credential from the vault, calls the stateless refresh if expired, writes the result back to the vault, returns a usable token. This is what library users call. The vault dependency lives here, not in the low-level flow.

```python
# Called by library users
token = auth_layer.get_access_token("github", connection="main")
```

**In sidecar mode**: the sidecar calls the low-level stateless refresh directly and handles vault write-back itself, keeping all orchestration in one place.

**In library mode**: `AuthLayer` calls the low-level refresh internally and handles vault write-back through its injected vault. The caller does not think about it.

**Acquisition flows**: PKCE (RFC 7636), Device Authorization Grant (RFC 8628), Dynamic Client Registration + PKCE, API Key.

Auth does not store credentials permanently. Auth does not make access decisions.

---

### Audit

**Owns**: append-only event log.

Records every request through the stack: timestamp, agent, user, operation, resource, outcome. Captures policy decisions (allow and deny) and auth events (token refreshed, acquired, refresh failed). Does not make decisions. Does not store credentials. Does not participate in the request flow — it only observes and records.

```
2026-04-26T10:32:01Z | agent=cold_email | user=manoj | policy=allow | resource=manoj/gmail/access-token | outcome=token_refreshed
2026-04-26T10:32:01Z | agent=web_scraper | user=manoj | policy=deny  | resource=manoj/gmail/access-token | outcome=denied
```

---

## Target Call Graph (Sidecar Mode)

```
agent
  ↓  plain HTTP request (HTTP_PROXY=localhost:<port>)
sidecar
  ↓
identity  →  signed principal chain (actor=agent, subject=user)
  ↓
policy    →  allow / deny
  ↓  deny: 403 to agent; audit records denial; stop
vault     →  encrypted credential + expiry metadata
  ↓  if expired:
auth (low-level)  →  calls external token endpoint → fresh credential
  ↓
sidecar   →  vault.write(fresh credential)       ← sidecar owns write-back
  ↓
sidecar injects Authorization header
  ↓
external API
  ↓
audit     ←  append-only log entry at every step
```

## Who Calls What

| Component | Calls | Called by |
|-----------|-------|-----------|
| Sidecar | Identity, Policy, Vault, Auth (low-level), Audit | Agent (via HTTP_PROXY) |
| Identity | OS keychain | Sidecar |
| Policy | Nothing (receives identity as parameter) | Sidecar |
| Vault | Backend-specific storage and key management | Sidecar, AuthLayer |
| Auth (low-level) | External token endpoint | Sidecar |
| Auth (AuthLayer) | Vault, Auth (low-level) | Library callers |
| Audit | Nothing | Sidecar |

---

## Library API and Vault Dependency

When authsome is used as a pure library and the caller does not want to bring the vault as a dependency — because they manage credentials themselves, run in a context without a local filesystem, or embed authsome in a larger system with its own secret store — the right API surface is not yet decided.

Three options:

**Option A — Caller manages vault I/O, calls stateless refresh directly**
```python
record = my_store.get("github/access-token")
fresh = authsome.flows.refresh(record.refresh_token, ...)
my_store.put("github/access-token", fresh)
```
Maximally composable. Vault is not a dependency at all. The caller owns orchestration. Burden shifts to the caller.

**Option B — AuthLayer accepts an injectable vault interface**
```python
auth_layer = AuthLayer(vault=my_vault)  # vault satisfies the minimal protocol
token = auth_layer.get_access_token("github")
```
AuthLayer keeps its lifecycle management. The local encrypted vault is one implementation of the vault protocol. Callers can bring their own. This is the most ergonomic option for embedding.

**Option C — AuthLayer operates on tokens, not a store; returns refreshed tokens to caller**
```python
fresh = auth_layer.refresh_if_needed(record)  # caller decides where to write
```
Stateless at the AuthLayer level. Caller decides storage. Requires the caller to understand the record model.

**The tension**: Option A is maximally composable but moves complexity to the caller. Option B keeps the lifecycle managed and is the most natural library API. Option C is a middle ground that avoids the vault dependency but still requires the caller to manage write-back.

**Decision direction**: Option B is the preferred long-term shape. `AuthLayer` should accept an injectable vault interface. Option A remains available through low-level primitives for callers that want to own orchestration themselves.

---

## Package Structure

```
authsome/
├── pyproject.toml
├── src/
│   └── authsome/
│       ├── __init__.py
│       ├── cli.py                  # init, login, run, status, audit
│       ├── context.py              # dependency injection
│       ├── errors.py
│       ├── utils.py
│       │
│       ├── sidecar/                # process lifecycle, subprocess, proxy wiring (planned name)
│       ├── proxy/                  # alpha proxy implementation
│       ├── identity/               # key generation, principal chain token (planned)
│       ├── policy/                 # allow/deny evaluation (planned)
│       ├── vault/                  # minimal storage interface + backends
│       ├── auth/                   # token refresh, OAuth flows, AuthLayer
│       └── audit/                  # append-only event log (planned)
│
└── tests/
    ├── proxy/
    ├── auth/
    ├── vault/
    ├── common/
    ├── identity/                 # planned
    ├── policy/                   # planned
    └── audit/                    # planned
```

---

## CLI

```bash
authsome init              # initialize local config, profile, and vault
authsome login <provider>  # OAuth acquisition (PKCE / Device Code / DCR+PKCE / API Key)
authsome run -- <command>  # start sidecar + agent, wire HTTP_PROXY automatically
authsome doctor            # vault/provider/profile health checks
authsome whoami            # show local authsome context
authsome status            # planned: sidecar state, registered identities, vault health
authsome audit             # planned: tail the audit log
```

---

## Standards

| Concern | v1 | Later |
|---------|-----|-------|
| Agent identity format | `agent://local/<name>` (SPIFFE-inspired) | `spiffe://trust-domain/path` |
| Key pair | Ed25519 | — |
| Principal chain token | Local signed JWT, actor+subject claims | RFC 8693 Token Exchange |
| Access control | TOML default-allow | Cedar (Amazon) |
| Credential storage | Vault interface; local backend uses SQLite/WAL | JSON/file dev backend, Postgres backend |
| Encryption at rest | AES-256-GCM, 256-bit key, 96-bit nonce | — |
| Key access | Agent identity gates vault access; backend unwraps DEK | Multi-agent sharing and key rotation |
| Token refresh | OAuth 2.0 (RFC 6749) | — |
| Browser-less OAuth | Device Authorization Grant (RFC 8628) | — |
| PKCE | RFC 7636 | — |

---

## What authsome Is Not

- Not a SaaS secrets manager — fully local, no cloud sync, no vendor dependency
- Not an enterprise identity platform — foundational layer; federation is roadmap
- Not a network-level identity system — complements SPIFFE/SPIRE at the credential layer
- Not a replacement for rotate-on-use secret stores — credentials are refreshed, not rotated on every use

---

## Open Questions

1. **Vault protocol shape** — The intended public surface is `init`, `health`, `get`, `put`, `delete`, and `list`. The exact Python protocol types, sync/async split, error contract, and health-check shape still need to be finalized before broad public API use.

2. **User token for multi-user** — OS-session derivation works for single-user local. Multi-user needs an explicit token mechanism. Not designed yet.

3. **Cedar migration from TOML** — How do TOML default-allow rules map to Cedar entities when migrating? No migration plan yet.

4. **Policy identity bootstrap** — Policy evaluates `can(agent, ...)` but needs to know the valid set of agent identities. The candidate answer: the sidecar resolves identity first, then passes it to policy as a parameter (not a lookup). This preserves the "layers do not reach sideways" rule. Not confirmed.

5. **Credential address mapping** — The logical credential address should be stable across vault backends, but the physical key/path/schema is backend-specific. The current KV storage uses `profile:<id>:<provider>:connection:<name>` and remains valid for KV-style backends. The canonical logical address model and migration strategy are not finalized.
