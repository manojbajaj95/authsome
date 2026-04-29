# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Commands

Always use `uv run` to execute commands — do not use `python`, `python3`, `pip`, or bare tool names directly.

```bash
# Install in editable mode (required before running anything)
uv pip install -e ".[dev]"

# Run all tests
uv run pytest

# Run a single test file
uv run pytest tests/test_client.py

# Run a single test by name
uv run pytest tests/test_client.py::test_login_pkce -v

# Run tests with coverage
uv run pytest --cov=authsome
```

Run linting and type checks:
```bash
# Lint and auto-fix
uv run ruff check --fix src/ tests/

# Format
uv run ruff format src/ tests/

# Type check
uv run ty check src/
```

The CLI entry point after install:
```bash
uv run authsome init
uv run authsome login github
uv run authsome list
```

## Conventions

**Commits and PRs:** Use [Conventional Commits](https://www.conventionalcommits.org/) style — `feat:`, `fix:`, `chore:`, `docs:`, `refactor:`. Mark breaking changes with `!` (e.g., `feat!:`) or a `BREAKING CHANGE:` footer.

**Branches:** Use Gitflow-style branch names with a short kebab-case description. Prefer `feature/<description>` for new capabilities, `bugfix/<description>` for non-urgent fixes, `hotfix/<description>` for urgent production fixes, `release/<version>` for release preparation, and `support/<description>` for maintenance lines.

**Pre-commit:** This repo uses `pre-commit` with ruff for lint and format. Run `pre-commit run --all-files` before finishing any change. The hook runs automatically on `git commit`.

**Available skills:** `ruff`, `uv`, `ty`, `uv-trusted-publish-github-action`, `release-please-changelog` are installed in `.claude/skills/`.

## Architecture

**`AuthClient` (`src/authsome/client.py`)** is the single entry point for all SDK operations. It lazily initializes four sub-systems: `GlobalConfig`, `CryptoBackend`, `ProviderRegistry`, and per-profile `CredentialStore`. All public methods accept an optional `profile` parameter that overrides `active_profile`.

**Flows (`src/authsome/flows/`)** implement the `AuthFlow.authenticate()` interface. Each flow returns a `ConnectionRecord` with secrets already encrypted. The mapping from `FlowType` enum to handler class lives in `_FLOW_HANDLERS` in `client.py`.

| Flow | Class | Notes |
|------|-------|-------|
| `pkce` | `PkceFlow` | Spins up an HTTP server on port **7999** for the OAuth callback |
| `device_code` | `DeviceCodeFlow` | Polls token endpoint; no browser needed |
| `dcr_pkce` | `DcrPkceFlow` | Dynamic Client Registration then PKCE |
| `api_key` | `ApiKeyFlow` | Prompts via secure browser bridge |

**Provider Registry (`src/authsome/providers/registry.py`)** resolves providers in this order: local `~/.authsome/providers/<name>.json` overrides bundled JSON in `src/authsome/bundled_providers/`. Bundled providers (GitHub, Google, Okta, Linear, OpenAI) are loaded via `importlib.resources`.

**Storage (`src/authsome/store/sqlite_store.py`)** is a SQLite KV store per profile at `~/.authsome/profiles/<name>/store.db`. Writes use `fcntl.flock` advisory locking via a `lock` file. Store keys follow the pattern:
```
profile:<profile>:<provider>:connection:<connection_name>
profile:<profile>:<provider>:metadata
profile:<profile>:<provider>:state
```

**Crypto (`src/authsome/crypto/`)** provides AES-256-GCM field-level encryption. `LocalFileCryptoBackend` stores the master key at `~/.authsome/master.key` (mode `0600`). `KeyringCryptoBackend` uses the OS keyring. Secrets are stored as `EncryptedField` Pydantic models (`nonce`, `ciphertext`, `tag` all base64-encoded). The active backend is selected by `config.encryption.mode`.

**Models (`src/authsome/models/`)** are all Pydantic v2 models:
- `ProviderDefinition` — provider JSON schema with `OAuthConfig`, `ClientConfig`, `ApiKeyConfig`
- `ConnectionRecord` — per-connection credential record; sensitive fields are `EncryptedField`
- `GlobalConfig` — loaded from `~/.authsome/config.json`

`ClientConfig` supports `env:VAR_NAME` syntax so client credentials can come from environment variables without hardcoding them in the provider JSON.

**CLI (`src/authsome/cli.py`)** is Click-based. All commands support `--json` for machine-readable output.
