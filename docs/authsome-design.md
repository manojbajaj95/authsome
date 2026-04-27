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

Both modes share the same layered architecture. The sidecar orchestrates the layers explicitly. The library exposes them through a higher-level stateful API. The low-level primitives are always accessible independently.

---

## Architecture

Five internal layers plus a sidecar orchestrator. Each layer has one bounded responsibility.

**Rule: no layer calls another layer directly. Only the sidecar calls layers.**

This constraint makes every layer independently testable and independently swappable.

```
authsome run -- <agent>
       │
       ▼
   [ sidecar ]            ← the only orchestrator
       │
       ├──▶ identity      ← who is acting, on whose behalf
       ├──▶ policy        ← is this allowed
       ├──▶ vault         ← retrieve encrypted credential
       ├──▶ auth          ← refresh if expired
       └──▶ audit         ← record everything
```

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

**Owns**: encrypted credential storage, expiry metadata.

Verifies the signed principal chain token before serving any credential. Retrieves the credential from SQLite. Decrypts it in memory using the master key. Returns the plaintext value plus expiry metadata. Accepts write-back of refreshed credentials from the sidecar.

Credential paths are user-scoped: `{user}/service/credential-name` (e.g., `manoj/gmail/access-token`). Isolation is enforced by the key itself, not only by code logic.

**Encryption**: AES-256-GCM. 256-bit random master key. 96-bit random nonce per encryption. Authenticated encryption.

**Master key storage**:
- Primary: OS keychain (macOS Keychain, Linux Secret Service, Windows Credential Manager). Never written to disk.
- Fallback: Local file at `~/.authsome/master.key` (mode 0600). Supported for CI and Docker environments where a keychain daemon is not available.

**Storage backend**: SQLite with WAL mode. Per-user credential stores.

Does not make access decisions. Does not refresh tokens. Does not know about the agent beyond verifying the token signature.

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

A convenience wrapper with vault dependency. Reads the credential from the vault, calls the stateless refresh if expired, writes the result back to the vault, returns a usable token. This is what library users call. The vault dependency lives here, not in the low-level flow.

```python
# Called by library users
token = auth_layer.get_access_token("github", connection="main")
```

**In sidecar mode**: the sidecar calls the low-level stateless refresh directly and handles vault write-back itself, keeping all orchestration in one place.

**In library mode**: `AuthLayer` calls the low-level refresh internally and handles vault write-back. The caller does not think about it.

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

## Call Graph (Sidecar Mode)

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
| Vault | OS keychain (master key) | Sidecar |
| Auth (low-level) | External token endpoint | Sidecar |
| Auth (AuthLayer) | Vault, Auth (low-level) | Library callers |
| Audit | Nothing | Sidecar |

---

## Open Question: Library API Without Vault Dependency

When authsome is used as a pure library and the caller does not want to bring the vault as a dependency — because they manage credentials themselves, run in a context without a local filesystem, or embed authsome in a larger system with its own secret store — the right API surface is not yet decided.

Three options:

**Option A — Caller manages vault I/O, calls stateless refresh directly**
```python
record = my_store.get("github/access-token")
fresh = authsome.flows.refresh(record.refresh_token, ...)
my_store.put("github/access-token", fresh)
```
Maximally composable. Vault is not a dependency at all. The caller owns orchestration. Burden shifts to the caller.

**Option B — AuthLayer accepts an injectable store interface**
```python
auth_layer = AuthLayer(store=my_store)  # store satisfies a protocol
token = auth_layer.get_access_token("github")
```
AuthLayer keeps its lifecycle management. The vault is one implementation of the store protocol. Callers can bring their own. This is the most ergonomic option for embedding.

**Option C — AuthLayer operates on tokens, not a store; returns refreshed tokens to caller**
```python
fresh = auth_layer.refresh_if_needed(record)  # caller decides where to write
```
Stateless at the AuthLayer level. Caller decides storage. Requires the caller to understand the record model.

**The tension**: Option A is maximally composable but moves complexity to the caller. Option B keeps the lifecycle managed and is the most natural library API. Option C is a middle ground that avoids the vault dependency but still requires the caller to manage write-back.

**This is unresolved.** The decision should be made before the public library API is published. Option B is the current working hypothesis.

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
│       ├── sidecar/                # process lifecycle, subprocess, proxy wiring
│       ├── identity/               # key generation, principal chain token
│       ├── policy/                 # allow/deny evaluation
│       ├── vault/                  # encrypted storage, keychain integration
│       ├── auth/                   # token refresh, OAuth flows, AuthLayer
│       └── audit/                  # append-only event log
│
└── tests/
    ├── test_sidecar.py
    ├── test_identity.py
    ├── test_policy.py
    ├── test_vault.py
    ├── test_auth.py
    └── test_audit.py
```

---

## CLI

```bash
authsome init              # generate identity keys, set up vault, store master key
authsome login <provider>  # OAuth acquisition (PKCE / Device Code / DCR+PKCE / API Key)
authsome run -- <command>  # start sidecar + agent, wire HTTP_PROXY automatically
authsome status            # sidecar state, registered identities, vault health
authsome audit             # tail the audit log
```

---

## Standards

| Concern | v1 | Later |
|---------|-----|-------|
| Agent identity format | `agent://local/<name>` (SPIFFE-inspired) | `spiffe://trust-domain/path` |
| Key pair | Ed25519 | — |
| Principal chain token | Local signed JWT, actor+subject claims | RFC 8693 Token Exchange |
| Access control | TOML default-allow | Cedar (Amazon) |
| Credential storage | SQLite, WAL mode | — |
| Encryption at rest | AES-256-GCM, 256-bit key, 96-bit nonce | — |
| Master key storage | OS keychain (primary), local file (fallback) | — |
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

1. **Library API without vault dependency** — see dedicated section above. Option B (injectable store protocol) is the working hypothesis. Unresolved before public library API is published.

2. **User token for multi-user** — OS-session derivation works for single-user local. Multi-user needs an explicit token mechanism. Not designed yet.

3. **Cedar migration from TOML** — How do TOML default-allow rules map to Cedar entities when migrating? No migration plan yet.

4. **Policy identity bootstrap** — Policy evaluates `can(agent, ...)` but needs to know the valid set of agent identities. The candidate answer: the sidecar resolves identity first, then passes it to policy as a parameter (not a lookup). This preserves the "no component calls another" rule. Not confirmed.

5. **Credential path migration** — Current storage uses `profile:<id>:<provider>:connection:<name>`. The canonical design uses `{user}/service/credential-name`. Migration strategy not yet written.
