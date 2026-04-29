# Manual Testing Guide

This guide walks through the full authsome workflow by hand, covering the most important paths. Run these after any significant change to verify that the CLI and core flows work end-to-end.

## Prerequisites

```bash
pip install -e ".[dev]"
authsome --version
```

---

## 1. Initialization

```bash
# Start fresh (optional — skip if you want to keep existing config)
rm -rf ~/.authsome

# No explicit init required (auto-initialized on first run)
```

**Expected:**
- Output includes the path to `~/.authsome`
- `~/.authsome/master.key` is created (mode `0600`)
- `~/.authsome/profiles/default/` directory exists

```bash
authsome whoami
```

**Expected:** Shows home directory and encryption mode (`local_key` by default).

```bash
authsome doctor
```

**Expected:** All checks pass (exit code 0, `OK` printed for each item).

---

## 2. API Key Login (OpenAI)

```bash
authsome login openai
```

**Expected:**
- Browser opens a local form at `http://127.0.0.1:7999`
- After entering a valid API key and submitting, the terminal prints `Successfully logged in to openai`

```bash
authsome list
```

**Expected:** `openai` is listed with status `connected`.

```bash
authsome get openai
```

**Expected:** Connection metadata is shown; the API key field shows `***REDACTED***`.

```bash
authsome get openai --show-secret
```

**Expected:** The actual API key value is printed.

```bash
authsome get openai --field status
```

**Expected:** Prints `connected`.

```bash
authsome export openai --format env
```

**Expected:** Prints `Successfully exported credentials to environment.` and the key is now present in `os.environ`.

---

## 3. OAuth2 Login (GitHub — PKCE)

```bash
authsome login github
```

**Expected:**
- Browser opens `https://github.com/login/oauth/authorize?...`
- After authorizing, the terminal prints `Successfully logged in to github`

```bash
authsome get github
```

**Expected:** Shows access token as `***REDACTED***`, status `connected`.

```bash
authsome export github --format env
```

**Expected:** Prints `Successfully exported credentials to environment.`

---

## 4. OAuth2 Login — Device Code (headless)

```bash
authsome login github --flow device_code
```

**Expected:**
- Terminal prints a URL and a user code
- After authorizing on GitHub, prints `Successfully logged in to github`

---

## 5. Logout, Revoke, Remove

```bash
# Logout (clears local record, does not call provider revocation endpoint)
authsome logout github
authsome list  # github should show 'not_connected'

# Re-login before testing revoke
authsome login github

# Revoke (calls GitHub's token revocation endpoint and removes local record)
authsome revoke github
authsome list  # github should show 'not_connected'

# Remove (deletes all records for the provider without revoking)
authsome login openai
authsome remove openai
authsome list  # openai should be gone
```

---

## 6. Proxy Run

Log in to at least one provider before testing:

```bash
authsome login openai
```

Then run a command under the proxy:

```bash
# Verify proxy environment variables are set
authsome run -- env | grep -E 'PROXY|OPENAI'
```

**Expected:**
- `HTTP_PROXY` and `HTTPS_PROXY` are set to the local proxy address
- `OPENAI_API_KEY=authsome-proxy-managed` (the real key is never exposed)

```bash
# Make a real API call through the proxy (requires valid OpenAI key)
authsome run -- curl -s https://api.openai.com/v1/models | head -5
```

**Expected:** JSON response from OpenAI (not an auth error).

---

## 7. Custom Provider Registration

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

authsome register /tmp/test-provider.json
authsome inspect test-custom
```

**Expected:** Provider definition is printed as JSON.

---

## 8. JSON Output Mode

Every command supports `--json` for machine-readable output:

```bash
authsome list --json | python3 -m json.tool
authsome get openai --json | python3 -m json.tool
authsome whoami --json | python3 -m json.tool
authsome doctor --json | python3 -m json.tool
```

**Expected:** Valid JSON output in all cases. Error conditions should also produce JSON with an `"error"` key when `--json` is passed.

---

## 9. Error Handling

```bash
# Non-existent provider
authsome login doesnotexist
```

**Expected:** Exit code `3`, message mentions provider not found.

```bash
# Get on a provider with no connection
authsome logout openai
authsome get openai
```

**Expected:** Exit code non-zero, message indicates no connection.

---

## 10. Multi-profile

Multiple profiles can be created programmatically. The active profile is the `default_profile` set in `~/.authsome/config.json`. To manually test profile isolation:

```bash
# Create a second profile via the SDK or by editing config
python3 -c "
from authsome.vault import Vault
from authsome.auth import AuthLayer
from authsome.auth.providers.registry import ProviderRegistry
from pathlib import Path

home = Path.home() / '.authsome'
vault = Vault(home)
registry = ProviderRegistry(home)
layer = AuthLayer(vault=vault, registry=registry, identity='default')
layer.create_profile('work', description='Work profile')
print('Profile work created')
"

authsome list   # shows connections in default profile
```

**Expected:** Each profile keeps its own isolated set of Connections in the Vault.

> **Note:** CLI-level `--profile` flag is not yet implemented. Profile selection is a planned addition.

---

## Cleanup

```bash
rm -rf ~/.authsome
```
