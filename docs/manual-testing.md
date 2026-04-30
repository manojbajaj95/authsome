# Manual Testing Guide

This guide covers end-to-end manual validation for authsome. Run it after user-facing CLI changes, auth flow changes, storage or crypto changes, provider schema changes, and release candidates.

Use `uv run` for every command in this repository.

## Evaluation Criteria

A manual test pass means:

- Commands use the documented CLI shape and return the expected exit codes.
- Successful login flows create usable connections without printing raw secrets unless `--show-secret` or an explicit export format requests them.
- Failed operations fail clearly, leave existing credentials intact, and return the expected non-zero exit code.
- JSON output is valid JSON and includes actionable error payloads when `--json` is passed.
- Local storage, encryption, audit logging, and provider registration behave consistently after process restarts.
- `authsome run` injects credentials through the proxy without exposing the real secret in the child process environment.

Record each run with:

- authsome version from `uv run authsome --version`
- operating system and shell
- browser used for interactive flows
- provider account used
- test date
- any skipped cases and why

## Prerequisites

Install the package in editable mode before testing:

```bash
uv pip install -e ".[dev]"
uv run authsome --version
uv run authsome --help
```

For full coverage, have these ready:

- A valid OpenAI API key for API key login and proxy tests.
- A GitHub account that can authorize OAuth apps.
- A browser that can open local callback pages.
- Network access to GitHub and OpenAI.

Use an isolated authsome home for destructive testing when possible:

```bash
export AUTHSOME_HOME="$(mktemp -d)"
```

If you intentionally test against the default home, leave `AUTHSOME_HOME` unset and back up `~/.authsome` before running destructive cases.

---

## 1. Fresh Install and Health Check

### Happy Path

```bash
# Destructive if AUTHSOME_HOME is unset because this falls back to ~/.authsome.
rm -rf "${AUTHSOME_HOME:-$HOME/.authsome}"

uv run authsome whoami
uv run authsome doctor
uv run authsome list
```

**Expected:**

- `whoami` prints the home directory, active profile, version, encryption mode, and connected provider count.
- `doctor` exits `0` and prints `OK` for directory, profile, provider, and encryption checks.
- `list` shows bundled providers and marks providers with no connection as `not_connected`.
- `${AUTHSOME_HOME:-$HOME/.authsome}/master.key` exists with mode `0600`.
- `${AUTHSOME_HOME:-$HOME/.authsome}/profiles/default/` exists.

### Evaluation Criteria

- Fresh startup does not require an explicit `init` command.
- No command prints a traceback.
- Health checks remain stable across two consecutive invocations.

---

## 2. API Key Login: OpenAI

### Happy Path

```bash
uv run authsome login openai
uv run authsome list
uv run authsome get openai
uv run authsome get openai --field status
uv run authsome get openai --show-secret
uv run authsome export openai --format env
uv run authsome export openai --format json
```

**Expected:**

- `login` starts a secure local browser bridge, accepts the API key, and prints `Successfully logged in to openai (default).`
- `list` shows OpenAI with the `default` connection and `connected` status.
- `get openai` redacts secret material.
- `get openai --field status` prints `connected`.
- `get openai --show-secret` reveals the real secret only for that explicit command.
- `export --format env` prints shell-style environment assignments.
- `export --format json` prints JSON containing exported credential material.

### Additional Test Cases

```bash
uv run authsome login openai
uv run authsome login openai --force
uv run authsome login openai --connection secondary
uv run authsome get openai --connection secondary
```

**Expected:**

- Re-running `login openai` without `--force` reports an existing connection instead of overwriting it.
- `--force` warns before replacing the existing default connection.
- A named connection is stored separately and can be fetched by name.

### Evaluation Criteria

- Raw API keys do not appear in normal `list`, `get`, `doctor`, or `whoami` output.
- Multiple connections do not overwrite each other unless `--force` targets the same connection.
- Cancelling the browser form leaves any existing connection unchanged.

---

## 3. OAuth Login: GitHub PKCE

### Happy Path

```bash
uv run authsome login github
uv run authsome get github
uv run authsome inspect github
uv run authsome export github --format env
```

**Expected:**

- `login` opens the GitHub authorization page.
- After authorization, the terminal prints `Successfully logged in to github (default).`
- `get github` shows `status: connected` and redacts token fields.
- `inspect github` prints the provider definition and connection summary.
- Export output contains GitHub credential environment data.

### Additional Test Cases

```bash
uv run authsome login github --scopes repo,read:user --connection repo-test
uv run authsome get github --connection repo-test
uv run authsome login github --base-url https://github.com --connection base-url-test
```

**Expected:**

- Requested scopes are reflected in the stored connection when the provider returns them.
- Named OAuth connections can coexist with the default connection.
- `--base-url` does not break bundled provider resolution for the public GitHub host.

### Evaluation Criteria

- The callback completes without leaving a hanging local server.
- Authorization failures or denied consent return a clear error and do not create a connected record.
- Token values are redacted unless explicitly revealed.

---

## 4. OAuth Login: GitHub Device Code

### Happy Path

```bash
uv run authsome login github --flow device_code --connection device-test
uv run authsome get github --connection device-test
```

**Expected:**

- The terminal prints a verification URL and user code.
- After completing authorization in the browser, login succeeds.
- The `device-test` connection is visible and connected.

### Evaluation Criteria

- The command is usable without a local callback browser flow.
- Polling handles the waiting period without noisy output or premature timeout.
- Expired or denied device codes produce clear failures and do not create connected records.

---

## 5. Credential Lifecycle: Logout, Revoke, Remove

### Happy Path

```bash
uv run authsome login openai --force
uv run authsome logout openai
uv run authsome list
uv run authsome get openai
```

**Expected:**

- `logout` removes the local OpenAI default connection.
- `list` shows OpenAI as `not_connected` unless another OpenAI connection exists.
- `get openai` exits non-zero and reports that no connection exists.

```bash
uv run authsome login github --force
uv run authsome revoke github
uv run authsome list
```

**Expected:**

- `revoke` removes all local GitHub connections and client state.
- `list` shows GitHub as `not_connected`.

```bash
uv run authsome login openai --force
uv run authsome remove openai
uv run authsome list
```

**Expected:**

- For a bundled provider, `remove` resets local records while the provider remains listed as bundled.
- OpenAI no longer has a connected default connection.

### Evaluation Criteria

- Lifecycle commands are idempotent enough to fail clearly when there is nothing to remove.
- Removing one provider does not affect connections for other providers.
- Revoking a provider with multiple named connections removes all of that provider's local records.

---

## 6. Proxy Run

### Happy Path

```bash
uv run authsome login openai --force
uv run authsome run -- env
```

Inspect the `env` output.

**Expected:**

- `HTTP_PROXY`, `HTTPS_PROXY`, `http_proxy`, and `https_proxy` point to a local proxy address.
- `OPENAI_API_KEY=authsome-proxy-managed` is present.
- The real OpenAI API key is not present in the child process environment.

Make a real API call through the proxy:

```bash
uv run authsome run -- curl -s https://api.openai.com/v1/models
```

**Expected:** OpenAI returns a JSON response, not an authentication error.

### Additional Test Cases

```bash
uv run authsome run -- curl -s https://example.com
uv run authsome run -- sh -c 'exit 17'
```

**Expected:**

- Unmatched hosts are forwarded without auth injection.
- The `run` command exits with the child command's exit code.

### Evaluation Criteria

- Proxy startup and shutdown do not leave a lingering process.
- Real secrets are injected into matched outbound requests only.
- The proxy does not break ordinary non-provider HTTP traffic.

---

## 7. Custom Provider Registration

### Happy Path

Create a temporary API key provider:

```bash
cat > /tmp/authsome-test-provider.json << 'EOF'
{
  "name": "test-custom",
  "display_name": "Test Custom",
  "auth_type": "api_key",
  "flow": "api_key",
  "host_url": "api.example.test",
  "api_key": {
    "header_name": "X-Test-Key",
    "header_prefix": "",
    "env_var": "TEST_CUSTOM_API_KEY"
  }
}
EOF

uv run authsome register /tmp/authsome-test-provider.json
uv run authsome inspect test-custom
uv run authsome list
```

**Expected:**

- Registration succeeds and writes a custom provider definition.
- `inspect` prints the provider schema.
- `list` shows `test-custom` with source `custom`.

### Additional Test Cases

```bash
uv run authsome register /tmp/authsome-test-provider.json
uv run authsome register /tmp/authsome-test-provider.json --force
uv run authsome remove test-custom
uv run authsome list
```

**Expected:**

- Registering the same provider twice without `--force` fails clearly.
- `--force` overwrites the custom definition.
- `remove` deletes the custom provider so it no longer appears in `list`.

### Evaluation Criteria

- Invalid provider JSON fails validation and is not partially installed.
- Custom providers override bundled providers only when explicitly intended.
- Registered providers survive a new shell process.

---

## 8. JSON Output Mode

### Happy Path

```bash
uv run authsome --json whoami
uv run authsome --json doctor
uv run authsome --json list
uv run authsome --json inspect openai
uv run authsome --json get openai
uv run authsome --json export openai --format json
```

Pipe each command to `uv run python -m json.tool` if you want strict validation:

```bash
uv run authsome --json list | uv run python -m json.tool
```

**Expected:** Every command emits valid JSON. For `export --format json`, validate the exported credential JSON printed by the command.

### Error Cases

```bash
uv run authsome --json login doesnotexist
uv run authsome --json get openai --field doesnotexist
```

**Expected:**

- Provider lookup failures return JSON with `error` and `message` fields and exit code `3`.
- Missing fields return a non-zero exit code and a clear error message.

### Evaluation Criteria

- `--json` output contains no progress text or ANSI color codes.
- Error payloads are machine-readable.
- Secrets remain redacted in JSON unless `--show-secret` or explicit export requests them.

---

## 9. Error Handling and Exit Codes

### Test Cases

```bash
uv run authsome login doesnotexist
echo $?

uv run authsome get openai
echo $?

uv run authsome register /tmp/does-not-exist.json
echo $?

uv run authsome get openai --field doesnotexist
echo $?
```

**Expected:**

- Unknown provider exits `3` and mentions that the provider was not found.
- Missing credentials exit `5` and explain that no connection exists.
- Missing provider file exits non-zero and prints `File not found`.
- Missing fields exit non-zero and identify the field name.

### Evaluation Criteria

- Errors do not include Python tracebacks in normal mode.
- Exit codes are stable enough for scripts to rely on.
- Failed commands do not create or corrupt config, provider, or credential records.

---

## 10. Audit Log

### Happy Path

```bash
uv run authsome login openai --force
uv run authsome get openai --show-secret
uv run authsome export openai --format env
uv run authsome log -n 20
uv run authsome --json log -n 20
```

**Expected:**

- `log` shows recent audit events for login, secret reveal, and export.
- JSON log output is parseable.
- Audit entries include operation names, provider names, connection names where applicable, and status.

### Evaluation Criteria

- Audit logging records sensitive operations without logging secret values.
- Missing or empty logs are handled without failing unrelated commands.
- The log command respects the requested line count.

---

## 11. Persistence and Restart

### Happy Path

```bash
uv run authsome login openai --force
uv run authsome get openai

# Start a new shell, then run:
uv run authsome get openai
uv run authsome list
uv run authsome doctor
```

**Expected:**

- Connections survive a new shell process.
- The master key can decrypt previously stored records.
- `doctor` still passes after credentials have been stored.

### Evaluation Criteria

- Stored secrets remain encrypted at rest.
- Restarting the process does not require re-login.
- Corrupt or missing storage files produce clear `doctor` failures.

---

## 12. Multi-Connection Isolation

### Happy Path

```bash
uv run authsome login openai --connection first
uv run authsome login openai --connection second
uv run authsome list
uv run authsome get openai --connection first
uv run authsome get openai --connection second
uv run authsome logout openai --connection first
uv run authsome get openai --connection second
```

**Expected:**

- Both named connections appear under OpenAI.
- Logging out of `first` does not remove `second`.
- `second` remains connected and retrievable.

### Evaluation Criteria

- Connection names are respected by `login`, `get`, and `logout`.
- Provider-level commands such as `revoke` and `remove` clearly affect all provider connections.
- The default connection remains independent from named connections.

---

## 13. Security Checks

### Test Cases

```bash
uv run authsome login openai --force
uv run authsome get openai
uv run authsome list
uv run authsome whoami
uv run authsome doctor
uv run authsome run -- env
```

Inspect local files:

```bash
ls -la "${AUTHSOME_HOME:-$HOME/.authsome}"
find "${AUTHSOME_HOME:-$HOME/.authsome}" -maxdepth 3 -type f -print
```

**Expected:**

- Normal CLI output redacts secret material.
- `master.key` has mode `0600`.
- Stored credential files or SQLite rows do not contain the plain API key.
- `authsome run -- env` exposes only placeholder provider variables.

### Evaluation Criteria

- Any raw secret exposure outside explicit reveal/export commands is a failure.
- File permissions protect local key material.
- Secret reveal commands are audited.

---

## Cleanup

Remove temporary providers and test connections:

```bash
uv run authsome remove test-custom
uv run authsome revoke github
uv run authsome remove openai
```

If you used a disposable authsome home, remove it:

```bash
test -n "$AUTHSOME_HOME" && rm -rf "$AUTHSOME_HOME"
```

If you tested against the real home directory and intentionally want a full reset:

```bash
rm -rf ~/.authsome
```
