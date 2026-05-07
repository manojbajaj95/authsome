# Manual Testing Guide

This guide walks through the full CLI surface. Run these after any significant change to verify that commands, flows, and output modes work end-to-end.

## Prerequisites

```bash
uv pip install -e ".[dev]"
uv run authsome --version
```

---

## 1. Initialization

```bash
# Start fresh (optional — skip to keep existing config)
rm -rf ~/.authsome

uv run authsome whoami
```

**Expected:** Home directory, active identity (`default`), encryption mode, and connected provider count.

```bash
uv run authsome whoami --json
```

**Expected:** Same data as structured JSON.

```bash
uv run authsome doctor
```

**Expected:** Exit code `0`; `OK` printed for `config`, `providers`, `vault`.

```bash
uv run authsome doctor --json
```

**Expected:** `{"status": "ready", "checks": {"config": "ok", ...}}`.

---

## 2. Login — API Key

Uses Resend (or any `api_key` provider):

```bash
uv run authsome login resend
```

**Expected:**
- Browser opens a local form at `http://127.0.0.1:7999`
- After submitting a valid API key, terminal prints success

```bash
uv run authsome list
```

**Expected:** `resend` listed with status `connected`.

---

## 3. Login — OAuth2 PKCE

```bash
uv run authsome login github
```

**Expected:**
- Browser opens `https://github.com/login/oauth/authorize?...`
- After authorizing, terminal prints success

```bash
uv run authsome list
```

**Expected:** `github` listed with status `connected`.

---

## 4. Login — Device Code (headless)

```bash
uv run authsome login github --flow device_code
```

**Expected:**
- Terminal prints a URL and a user code (no browser opens)
- After authorizing on GitHub, terminal prints success

---

## 5. List

```bash
uv run authsome list
```

**Expected:** Table of all providers; connected ones show connection name and status.

```bash
uv run authsome list --json
```

**Expected:** JSON with `bundled` and `custom` arrays; each connected provider has a non-empty `connections` array.

---

## 6. Get

```bash
uv run authsome get github
```

**Expected:** Connection metadata; sensitive fields show `***REDACTED***`.

```bash
uv run authsome get github --show-secret
```

**Expected:** Actual token value printed; warning about shell history printed to stderr.

```bash
uv run authsome get github --field status
```

**Expected:** Prints `connected`.

```bash
uv run authsome get github --field scopes
```

**Expected:** Prints the scope list.

```bash
uv run authsome get github --json
```

**Expected:** Connection record as JSON.

---

## 7. Inspect

```bash
uv run authsome inspect github
```

**Expected:** Full provider definition (URLs, flow config, scopes) plus connection summary as JSON.

```bash
uv run authsome inspect resend
```

**Expected:** Provider definition with `api_key` config block and connection summary.

---

## 8. Export

```bash
uv run authsome export github --format env
```

**Expected:** `GITHUB_ACCESS_TOKEN=<value>` printed; warning about shell history.

```bash
uv run authsome export github --format shell
```

**Expected:** `export GITHUB_ACCESS_TOKEN=<value>`.

```bash
uv run authsome export github --format json
```

**Expected:** `{"GITHUB_ACCESS_TOKEN": "<value>"}`.

---

## 9. Proxy Run

```bash
# Verify proxy env vars are injected
uv run authsome run -- env | grep -E 'HTTP_PROXY|HTTPS_PROXY|AUTHSOME_PROXY_MODE'
```

**Expected:**
- `HTTP_PROXY` and `HTTPS_PROXY` set to the local proxy address
- `AUTHSOME_PROXY_MODE=true`

```bash
# Verify dummy credential placeholders are set
uv run authsome run -- env | grep -E 'GITHUB_ACCESS_TOKEN|RESEND_API_KEY'
```

**Expected:** Both set to `authsome-proxy-managed` (real credentials are never in the child environment).

```bash
# Make a real API call through the proxy
uv run authsome run --quiet curl -s https://api.github.com/user
```

**Expected:** JSON response from GitHub with `login` field; no proxy log noise (suppressed by `--quiet`).

```bash
# Multi-provider: both providers injected in one session
uv run authsome run --quiet curl -s https://api.resend.com/domains
```

**Expected:** Valid JSON response from Resend.

---

## 10. Log

```bash
uv run authsome log
```

**Expected:** Recent audit entries as newline-delimited JSON objects with `timestamp`, `event`, `provider`, `status`.

```bash
uv run authsome log -n 5
```

**Expected:** Last 5 entries only.

```bash
uv run authsome log -n 5 --json
```

**Expected:** Same entries as a JSON array.

---

## 11. Connection Management

```bash
uv run authsome connection set-default github default
```

**Expected:** Confirmation that `default` is now the default connection for `github`.

---

## 12. Custom Provider Registration

```bash
cat > /tmp/test-provider.json << 'EOF'
{
  "name": "test-custom",
  "display_name": "Test Custom",
  "auth_type": "api_key",
  "flow": "api_key",
  "api_key": {
    "header_name": "X-Test-Key"
  }
}
EOF

uv run authsome register /tmp/test-provider.json
```

**Expected:** Confirmation prompt → provider registered. No `host_url` means no reachability check.

```bash
uv run authsome inspect test-custom
```

**Expected:** Provider definition printed as JSON; `connections` is empty.

```bash
uv run authsome list | grep test-custom
```

**Expected:** Listed under `custom` source, `not_connected`.

```bash
# Register again to test --force
uv run authsome register /tmp/test-provider.json --force
```

**Expected:** Overwrites existing without prompting for overwrite confirmation.

```bash
uv run authsome remove test-custom
```

**Expected:** `Removed provider test-custom.`

```bash
uv run authsome list | grep test-custom
```

**Expected:** No output (provider gone).

---

## 13. Logout and Revoke

```bash
# Logout removes local record only
uv run authsome logout github
uv run authsome list  # github → not_connected

# Re-login
uv run authsome login github

# Revoke removes local record and calls provider revocation endpoint
uv run authsome revoke github
uv run authsome list  # github → not_connected
```

---

## 14. Daemon

```bash
uv run authsome daemon status
```

**Expected:** JSON showing `running: true`, health checks all `ok`, PID, and log file path.

```bash
uv run authsome daemon stop
uv run authsome daemon status
```

**Expected:** `running: false` after stop.

```bash
uv run authsome daemon start
uv run authsome daemon status
```

**Expected:** `running: true` after start.

---

## 15. Global Flags

```bash
# Quiet: suppress informational output
uv run authsome --quiet list
```

**Expected:** Provider table only; no banners or notes.

```bash
# No color: plain text output
uv run authsome --no-color list
```

**Expected:** Same table without ANSI color codes.

```bash
# Verbose: debug logging to stderr
uv run authsome --verbose get github
```

**Expected:** DEBUG log lines on stderr in addition to normal stdout output.

---

## 16. Error Handling

```bash
# Non-existent provider
uv run authsome login doesnotexist 2>&1; echo "exit: $?"
```

**Expected:** `ProviderNotFoundError`, exit code `3`.

```bash
uv run authsome inspect doesnotexist 2>&1; echo "exit: $?"
```

**Expected:** `ProviderNotFoundError`, exit code `3`.

```bash
uv run authsome logout doesnotexist 2>&1; echo "exit: $?"
```

**Expected:** `ProviderNotFoundError`, exit code `3`.

```bash
# Missing required argument
uv run authsome get 2>&1; echo "exit: $?"
```

**Expected:** Usage error, exit code `2`.

```bash
# Get on a disconnected provider
uv run authsome logout resend
uv run authsome get resend 2>&1; echo "exit: $?"
```

**Expected:** Non-zero exit; message indicates no connection found.

---

## Cleanup

```bash
rm -rf ~/.authsome
```
