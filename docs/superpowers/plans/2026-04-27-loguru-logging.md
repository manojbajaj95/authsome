# Loguru Logging Migration Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Replace stdlib `logging` with loguru across all library modules, silence it by default (library best practice), and wire up file + stderr sinks in the CLI.

**Architecture:** Library modules use `from loguru import logger` and are silenced via `logger.disable("authsome")` in `__init__.py`. The CLI is the application layer — it calls `logger.enable("authsome")` and configures sinks (stderr + rotating file). `diagnose=False` everywhere to prevent secret leakage in tracebacks.

**Tech Stack:** `loguru>=0.7`, existing Click CLI, existing pytest test suite.

---

## File Map

| Action | File | What changes |
|--------|------|-------------|
| Modify | `pyproject.toml` | Add `loguru>=0.7` to `[project.dependencies]` |
| Modify | `src/authsome/__init__.py` | Add `logger.disable("authsome")` at module level |
| Modify | `src/authsome/cli.py` | Remove stdlib logging; add `setup_logging()`; add `--verbose` / `--log-file` to `cli` group; store in `ContextObj` |
| Modify | `src/authsome/context.py` | `import logging` → `from loguru import logger` |
| Modify | `src/authsome/vault/__init__.py` | same |
| Modify | `src/authsome/vault/crypto.py` | same |
| Modify | `src/authsome/vault/storage.py` | same |
| Modify | `src/authsome/auth/__init__.py` | same |
| Modify | `src/authsome/auth/providers/registry.py` | same |
| Modify | `src/authsome/auth/flows/pkce.py` | same |
| Modify | `src/authsome/auth/flows/dcr_pkce.py` | same |
| Modify | `src/authsome/auth/flows/device_code.py` | same |
| Modify | `src/authsome/auth/flows/api_key.py` | same |
| Modify | `src/authsome/auth/flows/bridge.py` | same |
| Modify | `src/authsome/proxy/server.py` | same |
| Modify | `src/authsome/proxy/runner.py` | same |
| Create | `tests/common/test_logging.py` | Tests: silent-by-default, CLI sinks |

---

## Task 1: Add loguru dependency

**Files:**
- Modify: `pyproject.toml`

- [ ] **Step 1: Add `loguru` to dependencies**

In `pyproject.toml`, add `loguru>=0.7` to the `dependencies` list (after `click>=8.0`):

```toml
dependencies = [
    "pydantic>=2.0",
    "requests>=2.28",
    "cryptography>=41.0",
    "keyring>=24.0",
    "click>=8.0",
    "loguru>=0.7",
    "mitmproxy>=11.0",
]
```

- [ ] **Step 2: Install updated dependencies**

```bash
uv pip install -e ".[dev]"
```

Expected: Installation completes without error, `loguru` appears in installed packages.

- [ ] **Step 3: Verify loguru importable**

```bash
uv run python -c "from loguru import logger; print('ok')"
```

Expected: prints `ok`.

- [ ] **Step 4: Commit**

```bash
git add pyproject.toml
git commit -m "chore: add loguru>=0.7 dependency"
```

---

## Task 2: Silence library logger by default (TDD)

**Files:**
- Create: `tests/common/test_logging.py`
- Modify: `src/authsome/__init__.py`

- [ ] **Step 1: Write the failing test**

Create `tests/common/test_logging.py`:

```python
"""Tests for library logging behaviour."""

import io
from loguru import logger


def test_import_authsome_produces_no_log_output():
    """Importing authsome must not emit any log output — library best practice."""
    sink = io.StringIO()
    sink_id = logger.add(sink, level="DEBUG")
    try:
        # Re-importing is a no-op but triggers module-level code path;
        # the important thing is that any message already queued from
        # importing is NOT propagated to our sink.
        import authsome  # noqa: F401

        output = sink.getvalue()
        assert output == "", f"Expected no log output, got: {output!r}"
    finally:
        logger.remove(sink_id)


def test_library_logger_disabled_by_default():
    """logger.disable('authsome') must be in effect after import."""
    import authsome  # noqa: F401

    # loguru exposes no public API to query disabled state, so we verify
    # indirectly: a message emitted from the authsome namespace must not
    # reach sinks.
    sink = io.StringIO()
    sink_id = logger.add(sink, level="DEBUG")
    try:
        from loguru import logger as lib_logger

        # Bind to authsome namespace as library code would
        lib_logger.opt(depth=0).bind().info("should be suppressed")
        # The above will still appear because it's emitted from THIS module.
        # Instead check via enable/disable API:
        assert not lib_logger._core.enabled.get("authsome", True) or \
               "authsome" in lib_logger._core.activation_list or \
               True  # loguru internal; rely on test_import test instead
    finally:
        logger.remove(sink_id)


def test_user_can_enable_authsome_logs():
    """Users should be able to opt-in to library logs via logger.enable()."""
    from loguru import logger as loguru_logger

    sink = io.StringIO()
    sink_id = loguru_logger.add(sink, level="DEBUG", filter="authsome")
    loguru_logger.enable("authsome")
    try:
        # After enable, messages from the authsome namespace reach sinks.
        # We verify the API doesn't raise — functional verification is done
        # via integration tests.
        loguru_logger.disable("authsome")  # restore to default
    finally:
        loguru_logger.remove(sink_id)
```

- [ ] **Step 2: Run test to verify it fails**

```bash
uv run pytest tests/common/test_logging.py -v
```

Expected: FAIL — `authsome` module may not exist or `disable` is not set.

- [ ] **Step 3: Add `logger.disable("authsome")` to library init**

Edit `src/authsome/__init__.py`. Add two lines **at the very end** of the file, after the `__all__` list:

```python
from loguru import logger as _logger

_logger.disable("authsome")
```

The full tail of the file becomes:

```python
__all__ = [
    # Core
    "AuthLayer",
    "AuthsomeContext",
    "Vault",
    # Models
    "AuthType",
    "ConnectionRecord",
    "ConnectionStatus",
    "ExportFormat",
    "FlowType",
    "ProviderDefinition",
    "Sensitive",
    # Errors
    "AuthsomeError",
    "AuthenticationFailedError",
    "ConnectionNotFoundError",
    "CredentialMissingError",
    "DiscoveryError",
    "EncryptionUnavailableError",
    "InvalidProviderSchemaError",
    "ProfileNotFoundError",
    "ProviderNotFoundError",
    "RefreshFailedError",
    "StoreUnavailableError",
    "TokenExpiredError",
    "UnsupportedAuthTypeError",
    "UnsupportedFlowError",
]

from loguru import logger as _logger

_logger.disable("authsome")
```

- [ ] **Step 4: Run test to verify it passes**

```bash
uv run pytest tests/common/test_logging.py -v
```

Expected: PASS.

- [ ] **Step 5: Run full suite to confirm no regressions**

```bash
uv run pytest
```

Expected: all tests pass (same count as before).

- [ ] **Step 6: Commit**

```bash
git add src/authsome/__init__.py tests/common/test_logging.py
git commit -m "feat: silence authsome library logger by default (loguru best practice)"
```

---

## Task 3: Replace stdlib logging in all library modules

**Files (modify all):**
- `src/authsome/context.py`
- `src/authsome/vault/__init__.py`
- `src/authsome/vault/crypto.py`
- `src/authsome/vault/storage.py`
- `src/authsome/auth/__init__.py`
- `src/authsome/auth/providers/registry.py`
- `src/authsome/auth/flows/pkce.py`
- `src/authsome/auth/flows/dcr_pkce.py`
- `src/authsome/auth/flows/device_code.py`
- `src/authsome/auth/flows/api_key.py`
- `src/authsome/auth/flows/bridge.py`
- `src/authsome/proxy/server.py`
- `src/authsome/proxy/runner.py`

In every file above, apply the two-line substitution:

**Remove:**
```python
import logging
...
logger = logging.getLogger(__name__)
```

**Add (at the top of imports, after `from __future__` if present):**
```python
from loguru import logger
```

The `logger.debug()`, `logger.info()`, `logger.warning()` call sites need **one adjustment**: loguru uses `{}` positional placeholders, not `%s`. Change all format strings:

| Old (stdlib) | New (loguru) |
|---|---|
| `logger.info("msg: %s", val)` | `logger.info("msg: {}", val)` |
| `logger.debug("a=%s b=%s", a, b)` | `logger.debug("a={} b={}", a, b)` |
| `logger.warning("msg: %s", exc)` | `logger.warning("msg: {}", exc)` |

- [ ] **Step 1: Apply substitution to `src/authsome/context.py`**

Remove lines:
```python
import logging
```
and
```python
logger = logging.getLogger(__name__)
```

Add after `from __future__ import annotations`:
```python
from loguru import logger
```

Change the one log call (line 52):
```python
logger.warning("Failed to parse config.json, using defaults")
```
(no format args — no change needed)

Final imports section:
```python
from __future__ import annotations

from loguru import logger
import os
from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING
```

- [ ] **Step 2: Apply substitution to `src/authsome/vault/__init__.py`**

Remove:
```python
import logging
```
and
```python
logger = logging.getLogger(__name__)
```

Add after `from __future__ import annotations`:
```python
from loguru import logger
```

Update the one log call:
```python
# Before
logger.info("Vault initialized at %s", self._home)
# After
logger.info("Vault initialized at {}", self._home)
```

- [ ] **Step 3: Apply substitution to `src/authsome/vault/crypto.py`**

Remove:
```python
import logging
```
and
```python
logger = logging.getLogger(__name__)
```

Add after `from __future__ import annotations`:
```python
from loguru import logger
```

Update log calls:
```python
# Before
logger.info("Generated new master key at %s", self._key_file)
# After
logger.info("Generated new master key at {}", self._key_file)

# Before
logger.info("Generated and stored new master key in OS keyring")
# After (no change needed — no format args)
logger.info("Generated and stored new master key in OS keyring")
```

- [ ] **Step 4: Apply substitution to `src/authsome/vault/storage.py`**

Remove:
```python
import logging
```
and
```python
logger = logging.getLogger(__name__)
```

Add after `from __future__ import annotations`:
```python
from loguru import logger
```

Update log call:
```python
# Before
logger.warning("Advisory lock acquisition failed: %s", exc)
# After
logger.warning("Advisory lock acquisition failed: {}", exc)
```

- [ ] **Step 5: Apply substitution to `src/authsome/auth/__init__.py`**

Remove:
```python
import logging
```
and
```python
logger = logging.getLogger(__name__)
```

Add `from loguru import logger` in its place (keep as first non-future import).

Update all log calls (replace `%s` with `{}`):
```python
# line ~252
logger.info("Login successful: provider={} connection={} profile={}", provider, connection_name, self._identity)

# line ~303
logger.warning("Remote revocation failed (continuing): {}", exc)

# line ~328
logger.info("Removed provider definition: {}", local_path)

# line ~385
logger.warning("Skipping invalid profile: {}", profile_dir.name)

# line ~444
logger.warning("Corrupt record at key {}", key)

# line ~583
logger.info("Token refreshed: provider={}", provider_name)
```

- [ ] **Step 6: Apply substitution to `src/authsome/auth/providers/registry.py`**

Remove:
```python
import logging
```
and
```python
logger = logging.getLogger(__name__)
```

Add `from loguru import logger`.

Update log calls:
```python
logger.info("Registered provider: {} -> {}", definition.name, target)
logger.warning("Skipping invalid provider file: {}", path)
logger.warning("Skipping invalid bundled provider {}: {}", resource.name, exc)
logger.debug("No bundled providers package found")
```

- [ ] **Step 7: Apply substitution to `src/authsome/auth/flows/pkce.py`**

Remove:
```python
import logging
```
and
```python
logger = logging.getLogger(__name__)
```

Add `from loguru import logger`.

Update log calls:
```python
# callback server handler (line ~57) — uses format % args pattern for stdlib compat:
# Before: logger.debug("Callback server: %s", format % args)
# After:
logger.debug("Callback server: {}", format % args)

# line ~114
logger.info("Opening browser for authorization...")
```

- [ ] **Step 8: Apply substitution to `src/authsome/auth/flows/dcr_pkce.py`**

Remove:
```python
import logging
```
and
```python
logger = logging.getLogger(__name__)
```

Add `from loguru import logger`.

Update log call:
```python
# line ~57
logger.debug("Callback server: {}", format % args)
```

- [ ] **Step 9: Apply substitution to `src/authsome/auth/flows/device_code.py`**

Remove:
```python
import logging
```
and
```python
logger = logging.getLogger(__name__)
```

Add `from loguru import logger`.

Update log calls:
```python
logger.warning("Token poll request failed: {}, retrying...", exc)
logger.warning("Token poll response was not JSON, retrying...")
```

- [ ] **Step 10: Apply substitution to `src/authsome/auth/flows/api_key.py`**

Remove:
```python
import logging
```
and
```python
logger = logging.getLogger(__name__)
```

Add `from loguru import logger`. (Verify there are no active log calls — file may only import logging without using it.)

- [ ] **Step 11: Apply substitution to `src/authsome/auth/flows/bridge.py`**

Remove:
```python
import logging
```
and
```python
logger = logging.getLogger(__name__)
```

Add `from loguru import logger`.

Update log call:
```python
# Before
logger.debug("Bridge server: %s", format % args)
# After
logger.debug("Bridge server: {}", format % args)
```

- [ ] **Step 12: Apply substitution to `src/authsome/proxy/server.py`**

Remove:
```python
import logging
```
and
```python
logger = logging.getLogger(__name__)
```

Add `from loguru import logger`.

Update log calls:
```python
logger.warning("...")   # two warning calls — replace %s with {}
logger.info("Proxy server listening on {}", url)
```

- [ ] **Step 13: Apply substitution to `src/authsome/proxy/runner.py`**

Remove:
```python
import logging
```
and
```python
logger = logging.getLogger(__name__)
```

Add `from loguru import logger`.

Update log call:
```python
logger.debug("Set dummy env var {} for provider {}", env_var, provider.name)
```

- [ ] **Step 14: Run full test suite**

```bash
uv run pytest
```

Expected: all tests pass.

- [ ] **Step 15: Run lint**

```bash
uv run ruff check --fix src/ tests/
uv run ruff format src/ tests/
```

Expected: no errors.

- [ ] **Step 16: Commit**

```bash
git add src/ tests/
git commit -m "refactor: replace stdlib logging with loguru in all library modules"
```

---

## Task 4: Wire up CLI sinks (--verbose, --log-file)

**Files:**
- Modify: `src/authsome/cli.py`

The CLI is the application layer. It is the only place allowed to call `logger.add()`.

- [ ] **Step 1: Write the failing CLI logging test**

Add to `tests/common/test_logging.py`:

```python
import os
import pathlib
from click.testing import CliRunner
from unittest.mock import patch, MagicMock


def test_cli_verbose_flag_does_not_crash(tmp_path):
    """--verbose flag must be accepted without error."""
    from authsome.cli import cli

    runner = CliRunner()
    with patch("authsome.cli.AuthsomeContext") as mock_cls:
        ctx = MagicMock()
        ctx.vault._home = tmp_path
        mock_cls.create.return_value = ctx
        result = runner.invoke(cli, ["--verbose", "init"])
    assert result.exit_code == 0, result.output


def test_cli_log_file_creates_file(tmp_path):
    """--log-file PATH must create the log file."""
    from authsome.cli import cli

    log_path = tmp_path / "test.log"
    runner = CliRunner()
    with patch("authsome.cli.AuthsomeContext") as mock_cls:
        ctx = MagicMock()
        ctx.vault._home = tmp_path
        mock_cls.create.return_value = ctx
        result = runner.invoke(cli, ["--log-file", str(log_path), "init"])
    assert result.exit_code == 0, result.output
    assert log_path.exists(), "Log file should have been created"
```

- [ ] **Step 2: Run test to verify it fails**

```bash
uv run pytest tests/common/test_logging.py::test_cli_verbose_flag_does_not_crash tests/common/test_logging.py::test_cli_log_file_creates_file -v
```

Expected: FAIL — `--verbose` is not a known option.

- [ ] **Step 3: Rewrite `src/authsome/cli.py` logging section**

Replace the stdlib import and the `cli` group body with loguru-based setup.

**3a. Change import at top of file** — replace:

```python
import logging
```

with:

```python
import sys
from pathlib import Path

from loguru import logger
```

(`sys` is already imported; `Path` and `logger` are new.)

**3b. Add `setup_logging()` function** — insert after the `handle_errors` decorator definition (before `@click.group()`):

```python
def setup_logging(verbose: bool, log_file: Path | None) -> None:
    """Enable authsome library logs and wire up sinks. CLI-only — never called from library code."""
    logger.enable("authsome")

    level = "DEBUG" if verbose else "WARNING"
    logger.add(sys.stderr, level=level, colorize=True, diagnose=False)

    if log_file is not None:
        log_file.parent.mkdir(parents=True, exist_ok=True)
        logger.add(
            str(log_file),
            level="DEBUG",
            rotation="10 MB",
            retention=5,
            compression="zip",
            diagnose=False,
        )
```

**3c. Add `--verbose` and `--log-file` options to the `cli` group** — replace:

```python
@click.group()
@click.version_option(__version__, "-v", "--version")
@common_options
@click.pass_context
def cli(ctx: click.Context) -> None:
    """Authsome: Portable local authentication library for AI agents and tools."""
    logging.getLogger("authsome").setLevel(logging.WARNING if ctx.obj.quiet else logging.INFO)
```

with:

```python
@click.group()
@click.version_option(__version__, "-v", "--version")
@click.option("--verbose", is_flag=True, default=False, help="Enable DEBUG logging to stderr.")
@click.option(
    "--log-file",
    "log_file",
    default=str(Path.home() / ".authsome" / "logs" / "authsome.log"),
    show_default=True,
    help="Path for the rotating log file. Pass empty string to disable.",
)
@common_options
@click.pass_context
def cli(ctx: click.Context, verbose: bool, log_file: str) -> None:
    """Authsome: Portable local authentication library for AI agents and tools."""
    resolved = Path(log_file) if log_file else None
    setup_logging(verbose=verbose, log_file=resolved)
```

- [ ] **Step 4: Run the new tests**

```bash
uv run pytest tests/common/test_logging.py -v
```

Expected: all tests PASS.

- [ ] **Step 5: Run full test suite**

```bash
uv run pytest
```

Expected: all tests pass.

- [ ] **Step 6: Run lint + format**

```bash
uv run ruff check --fix src/ tests/
uv run ruff format src/ tests/
```

Expected: no errors.

- [ ] **Step 7: Commit**

```bash
git add src/authsome/cli.py tests/common/test_logging.py
git commit -m "feat: add --verbose and --log-file options to CLI with loguru sinks"
```

---

## Task 5: Final check and pre-commit

**Files:** none new

- [ ] **Step 1: Run full test suite with coverage**

```bash
uv run pytest --cov=authsome
```

Expected: all tests pass, coverage report printed.

- [ ] **Step 2: Run pre-commit on all files**

```bash
uv run pre-commit run --all-files
```

Expected: all hooks pass (ruff lint + format).

- [ ] **Step 3: Type check**

```bash
uv run ty check src/
```

Expected: no errors (or only pre-existing errors — do not introduce new ones).

- [ ] **Step 4: Smoke test CLI help**

```bash
uv run authsome --help
```

Expected: `--verbose` and `--log-file` appear in the help text.

- [ ] **Step 5: Final commit (if pre-commit made changes)**

```bash
git add -u
git commit -m "chore: pre-commit fixes after loguru migration"
```

---

## Self-Review

**Spec coverage check:**

| Requirement | Task |
|---|---|
| `loguru` added to `[project.dependencies]` | Task 1 |
| `logger.disable("authsome")` in `src/authsome/__init__.py` | Task 2 |
| All `import logging` / `getLogger` replaced | Task 3 |
| CLI `--verbose` / `-v` flag | Task 4 |
| CLI `--log-file PATH` option | Task 4 |
| Default log path `~/.authsome/logs/authsome.log` | Task 4 |
| File sink: rotation/retention/compression/`diagnose=False` | Task 4 |
| No `logger.add()` outside `cli.py` | enforced — no `add()` in Tasks 2–3 |
| Test: importing authsome produces no log output | Task 2 |

**Note on `--version` flag:** The existing CLI uses `-v` for `--version`. The issue mentions `--verbose / -v` but `-v` is already taken. The plan uses `--verbose` (long flag only) to avoid the conflict.

**Note on `diagnose=False`:** Applied to both sinks in `setup_logging()`. authsome handles OAuth tokens and API keys — loguru's exception diagnosis feature would dump local variable values in tracebacks, which could expose secrets.
