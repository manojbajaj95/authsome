"""Browser-based secure input bridge.

Provides a mechanism to collect sensitive inputs from the user via a local
web browser instead of the terminal. This prevents secrets from being exposed
in environments where agents or scripts might intercept standard I/O.

Also provides a display-only bridge for the OAuth2 device authorization flow:
device codes are surfaced in a browser window so the human user can see them
even when an agent or non-interactive parent process is holding the CLI's
stdout.
"""

import http.server
import re
import socket
import threading
import urllib.parse
import webbrowser
from html import escape
from typing import Any

from loguru import logger

from authsome.errors import InputCancelledError


def _find_free_port() -> int:
    """Find a free TCP port on localhost."""
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


_BRIDGE_STYLE = """
:root {
  color-scheme: light;
  --bg: #f6f7f9;
  --panel: #ffffff;
  --text: #16181d;
  --muted: #626a76;
  --line: #d8dde5;
  --line-strong: #b8c0cc;
  --focus: #2f6feb;
  --danger: #b42318;
  --danger-bg: #fff4f2;
  --success-bg: #f0fdf4;
  --cancel-bg: #f8fafc;
}
* { box-sizing: border-box; }
body {
  margin: 0;
  min-height: 100vh;
  background: var(--bg);
  color: var(--text);
  font-family: ui-sans-serif, system-ui, -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif;
  line-height: 1.45;
}
.page {
  width: min(100% - 32px, 520px);
  margin: 0 auto;
  padding: 48px 0;
}
.brand {
  margin-bottom: 14px;
  color: var(--muted);
  font-size: 13px;
  font-weight: 700;
  letter-spacing: 0.08em;
  text-transform: uppercase;
}
.panel {
  background: var(--panel);
  border: 1px solid var(--line);
  border-radius: 8px;
  box-shadow: 0 18px 45px rgba(22, 24, 29, 0.08);
  padding: 28px;
}
h1 {
  margin: 0;
  font-size: 24px;
  line-height: 1.2;
  letter-spacing: 0;
}
.subtitle {
  margin: 8px 0 24px;
  color: var(--muted);
  font-size: 14px;
}
form { margin: 0; }
.field { margin-bottom: 18px; }
.label-row {
  display: flex;
  align-items: center;
  justify-content: space-between;
  gap: 12px;
  margin-bottom: 7px;
}
label {
  display: block;
  font-size: 14px;
  font-weight: 650;
}
.optional-chip {
  border: 1px solid var(--line);
  border-radius: 999px;
  color: var(--muted);
  flex: none;
  font-size: 12px;
  font-weight: 600;
  padding: 2px 8px;
}
input {
  width: 100%;
  min-height: 42px;
  border: 1px solid var(--line-strong);
  border-radius: 6px;
  color: var(--text);
  font: inherit;
  padding: 9px 11px;
}
input:focus {
  border-color: var(--focus);
  box-shadow: 0 0 0 3px rgba(47, 111, 235, 0.16);
  outline: none;
}
input.has-error {
  border-color: var(--danger);
  background: var(--danger-bg);
}
input.has-error:focus {
  border-color: var(--danger);
  box-shadow: 0 0 0 3px rgba(180, 35, 24, 0.14);
}
.field-error {
  color: var(--danger);
  font-size: 13px;
  margin-top: 7px;
}
.form-error {
  background: var(--danger-bg);
  border: 1px solid #ffd0cb;
  border-radius: 6px;
  color: var(--danger);
  font-size: 14px;
  margin-bottom: 18px;
  padding: 11px 12px;
}
.secret-wrap,
.static-wrap {
  display: flex;
  gap: 8px;
  align-items: stretch;
}
.secret-wrap input,
.static-wrap input[readonly] {
  flex: 1;
  min-width: 0;
}
.static-wrap input[readonly] {
  background: #f8fafc;
  color: #303641;
  cursor: default;
}
button,
.button {
  min-height: 42px;
  border: 1px solid transparent;
  border-radius: 6px;
  cursor: pointer;
  font: inherit;
  font-weight: 700;
  padding: 9px 13px;
}
.primary-button {
  width: 100%;
  background: #1f2937;
  color: #fff;
}
.primary-button:hover { background: #111827; }
.secondary-button {
  background: #fff;
  border-color: var(--line-strong);
  color: #303641;
  flex: none;
}
.secondary-button:hover { background: #f8fafc; }
.actions {
  display: grid;
  gap: 10px;
  margin-top: 24px;
}
.cancel-button {
  width: 100%;
  background: transparent;
  border-color: transparent;
  color: var(--muted);
}
.cancel-button:hover {
  background: #f8fafc;
  color: var(--text);
}
.instructions {
  background: #f8fafc;
  border: 1px solid var(--line);
  border-radius: 6px;
  margin-bottom: 18px;
  padding: 13px 14px;
}
.instructions-title {
  margin: 0 0 8px;
  font-size: 14px;
  font-weight: 700;
}
.instructions-links {
  margin: 0;
  padding-left: 18px;
}
.instructions-links li { margin-bottom: 4px; }
a { color: var(--focus); font-weight: 650; }
.status-panel {
  text-align: center;
}
.status-mark {
  display: inline-grid;
  width: 42px;
  height: 42px;
  margin-bottom: 14px;
  place-items: center;
  border-radius: 999px;
  font-weight: 800;
}
.status-mark.success { background: var(--success-bg); color: #15803d; }
.status-mark.cancelled { background: var(--cancel-bg); color: #475569; }
@media (max-width: 520px) {
  .page {
    width: min(100% - 24px, 520px);
    padding: 24px 0;
  }
  .panel { padding: 22px; }
}
"""

_BRIDGE_SCRIPT = """
<script>
document.addEventListener("click", function (event) {
  var button = event.target.closest("[data-toggle-secret]");
  if (!button) return;
  var target = document.getElementById(button.getAttribute("data-toggle-secret"));
  if (!target) return;
  var revealing = target.type === "password";
  target.type = revealing ? "text" : "password";
  button.textContent = revealing ? "Hide" : "Show";
  button.setAttribute("aria-label", (revealing ? "Hide " : "Show ") + target.getAttribute("data-label"));
});
</script>
"""


def _validate_bridge_submission(fields: list[dict[str, Any]], submitted: dict[str, str]) -> dict[str, str]:
    """Return ``{field_name: error_message}`` for any pattern violations.

    Only fields that declare a ``pattern`` are checked, and only when the user
    actually submitted a non-empty value (emptiness/required-ness is enforced
    by the HTML ``required`` attribute and the receiving flow).
    """
    errors: dict[str, str] = {}
    for field in fields:
        if field.get("type") in ("instructions", "static"):
            continue
        pattern = field.get("pattern")
        if not pattern:
            continue
        name = field.get("name")
        if not name:
            continue
        value = submitted.get(name, "")
        if value and re.fullmatch(pattern, value) is None:
            errors[name] = field.get("pattern_hint") or f"{field.get('label', name)} doesn't match the expected format."
    return errors


class _BridgeHandler(http.server.BaseHTTPRequestHandler):
    """HTTP handler that renders a form and captures input."""

    title: str = "Secure Input"
    fields: list[dict[str, Any]] = []
    result: dict[str, str] | None = None
    cancelled: bool = False

    def do_GET(self) -> None:
        """Serve the HTML form."""
        self._render_form(values={}, errors={})

    def _send_html(self, html: str) -> None:
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(html.encode("utf-8"))

    def _page_shell(self, body: list[str], *, title: str | None = None, include_script: bool = False) -> str:
        page_title = escape(title or self.title)
        script = _BRIDGE_SCRIPT if include_script else ""
        return "\n".join(
            [
                "<!DOCTYPE html>",
                f"<html><head><title>Authsome - {page_title}</title>",
                f"<style>{_BRIDGE_STYLE}</style>",
                "</head><body><main class='page'>",
                "<div class='brand'>Authsome</div>",
                *body,
                "</main>",
                script,
                "</body></html>",
            ]
        )

    def _render_form(self, values: dict[str, str], errors: dict[str, str]) -> None:
        html = [
            "<section class='panel'>",
            f"<h1>{escape(self.title)}</h1>",
            "<p class='subtitle'>Enter credentials in this local browser window.</p>",
            "<form method='POST' novalidate>",
        ]

        if errors:
            html.append(
                "<div class='form-error' role='alert'>"
                "Please fix the highlighted field"
                f"{'s' if len(errors) > 1 else ''} below."
                "</div>"
            )

        for field in self.fields:
            label = field["label"]
            if field.get("type") == "instructions":
                url = field.get("url")
                if url:
                    html.append("<div class='instructions'>")
                    html.append(f"<p class='instructions-title'>{escape(label)}</p>")
                    url_esc = escape(url, quote=True)
                    html.append(
                        "<ul class='instructions-links'>"
                        f"<li><a href='{url_esc}' target='_blank' rel='noopener noreferrer'>Read setup docs</a></li>"
                        "</ul></div>"
                    )
                continue
            if field.get("type") == "static":
                val = field.get("value", "")
                val_esc = escape(val, quote=True)
                html.append("<div class='field'>")
                html.append("<div class='label-row'>")
                html.append(f"<label>{escape(label)}</label>")
                html.append("</div>")
                html.append(
                    "<div class='static-wrap'>"
                    f"<input type='text' readonly value='{val_esc}' aria-readonly='true'>"
                    "<button type='button' class='secondary-button' "
                    'onclick="navigator.clipboard.writeText(this.previousElementSibling.value)">'
                    "Copy</button></div></div>"
                )
                continue
            name = field["name"]
            input_type = field.get("type", "text")
            is_required = field.get("required", True)
            required = "required" if is_required else ""
            # Don't echo back password values on re-render — force the user to retype.
            display_value = "" if input_type == "password" else values.get(name, field.get("value", ""))
            val_esc = escape(display_value, quote=True) if display_value else ""
            pattern = field.get("pattern")
            pattern_attr = f" pattern='{escape(pattern, quote=True)}'" if pattern else ""
            hint = field.get("pattern_hint")
            title_attr = f" title='{escape(hint, quote=True)}'" if hint else ""
            error = errors.get(name)
            cls_attr = " class='has-error'" if error else ""
            label_esc = escape(label)
            html.append("<div class='field'>")
            html.append("<div class='label-row'>")
            html.append(f"<label for='{name}'>{label_esc}</label>")
            if not is_required:
                html.append("<span class='optional-chip'>Optional</span>")
            html.append("</div>")
            input_html = (
                f"<input type='{input_type}' id='{name}' name='{name}' value='{val_esc}'"
                f" data-label='{escape(label, quote=True)}'"
                f"{pattern_attr}{title_attr}{cls_attr} {required}>"
            )
            if input_type == "password":
                html.append(
                    "<div class='secret-wrap'>"
                    f"{input_html}"
                    f"<button type='button' class='secondary-button' data-toggle-secret='{name}' "
                    f"aria-label='Show {escape(label, quote=True)}'>Show</button></div>"
                )
            else:
                html.append(input_html)
            if error:
                html.append(f"<div class='field-error' id='{name}-error'>{escape(error)}</div>")
            html.append("</div>")

        html.append(
            "<div class='actions'>"
            "<button type='submit' class='primary-button' name='_action' value='submit'>Save credentials</button>"
            "<button type='submit' class='cancel-button' name='_action' value='cancel' formnovalidate>"
            "Cancel</button>"
            "</div>"
        )
        html.append("</form></section>")

        self._send_html(self._page_shell(html, include_script=True))

    def _render_terminal_page(self, *, status: str) -> None:
        if status == "cancelled":
            mark = "-"
            title = "Credential entry cancelled"
            message = "No credentials were saved. You can close this window and return to the terminal."
            mark_class = "cancelled"
        else:
            mark = "OK"
            title = "Credentials received"
            message = "You can close this window and return to the terminal."
            mark_class = "success"
        body = [
            "<section class='panel status-panel'>",
            f"<div class='status-mark {mark_class}' aria-hidden='true'>{escape(mark)}</div>",
            f"<h1>{escape(title)}</h1>",
            f"<p class='subtitle'>{escape(message)}</p>",
            "</section>",
        ]
        self._send_html(self._page_shell(body, title=title))

    def do_POST(self) -> None:
        """Process the submitted form data."""
        content_length = int(self.headers.get("Content-Length", 0))
        post_data = self.rfile.read(content_length).decode("utf-8")
        parsed = urllib.parse.parse_qs(post_data)

        submitted = {k: v[0] for k, v in parsed.items() if v}
        if submitted.get("_action") == "cancel":
            _BridgeHandler.cancelled = True
            _BridgeHandler.result = None
            self._render_terminal_page(status="cancelled")

            def kill_server():
                self.server.shutdown()

            threading.Thread(target=kill_server, daemon=True).start()
            return

        submitted.pop("_action", None)
        errors = _validate_bridge_submission(self.fields, submitted)
        if errors:
            # Keep the server running and re-render the form with the inline error banner.
            self._render_form(values=submitted, errors=errors)
            return

        _BridgeHandler.result = submitted

        self._render_terminal_page(status="success")

        def kill_server():
            self.server.shutdown()

        threading.Thread(target=kill_server, daemon=True).start()

    def log_message(self, format: str, *args: Any) -> None:
        logger.debug("Bridge server: {}", format % args)


def secure_input_bridge(title: str, fields: list[dict[str, Any]]) -> dict[str, str]:
    """
    Start a local server and open the browser to collect sensitive inputs securely.

    Args:
        title: The heading to display on the form.
        fields: A list of dicts, each representing an input field.
                Expected keys: 'name', 'label', 'type' (default: text), 'required' (default: True).

    Returns:
        A dictionary mapping field names to user input values.
    """
    port = _find_free_port()

    # Reset state
    _BridgeHandler.title = title
    _BridgeHandler.fields = fields
    _BridgeHandler.result = None
    _BridgeHandler.cancelled = False

    server = http.server.HTTPServer(("127.0.0.1", port), _BridgeHandler)
    server_thread = threading.Thread(target=server.serve_forever, daemon=True)
    server_thread.start()

    url = f"http://127.0.0.1:{port}"
    print(f"\nRequires secure input for: {title}")
    print(f"Opening browser for secure input...\nIf the browser doesn't open, visit:\n{url}\n")
    webbrowser.open(url)

    # Wait for the server to shutdown (triggered by do_POST)
    server_thread.join(timeout=300)  # 5 minute timeout

    if _BridgeHandler.cancelled:
        raise InputCancelledError()
    if _BridgeHandler.result is None:
        raise RuntimeError("Secure input bridge timed out.")

    return _BridgeHandler.result


# ── Device authorization (display-only) bridge ────────────────────────────────


class _DeviceBridgeHandler(http.server.BaseHTTPRequestHandler):
    """HTTP handler that renders the device-flow URL + user code."""

    title: str = "Device Authorization"
    user_code: str = ""
    verification_uri: str = ""
    verification_uri_complete: str | None = None

    def do_GET(self) -> None:
        title_esc = escape(self.title)
        code_esc = escape(self.user_code, quote=True)
        verify_url = self.verification_uri_complete or self.verification_uri
        verify_url_esc = escape(verify_url, quote=True)
        verify_label = escape(self.verification_uri)

        html = f"""<!DOCTYPE html>
<html><head><title>Authsome — {title_esc}</title>
<style>
body {{ font-family: system-ui, sans-serif; max-width: 480px; margin: 40px auto; padding: 20px; }}
h2 {{ margin-bottom: 8px; }}
.subtitle {{ color: #555; margin-bottom: 20px; }}
.code-wrap {{ display: flex; gap: 8px; align-items: center; margin-bottom: 16px; }}
.code-wrap input {{ flex: 1; font-size: 22px; font-family: ui-monospace, SFMono-Regular, Menlo, monospace;
  padding: 12px; border: 1px solid #ccc; border-radius: 6px; background: #f5f5f5;
  text-align: center; letter-spacing: 2px; }}
.copybtn {{ padding: 10px 14px; font-size: 14px; border: 1px solid #ccc;
  background: #fff; border-radius: 6px; cursor: pointer; }}
.copybtn:hover {{ background: #f0f0f0; }}
a.verify {{ display: inline-block; margin-bottom: 16px; padding: 10px 16px;
  background: #0066cc; color: #fff; text-decoration: none; border-radius: 6px; }}
a.verify:hover {{ background: #0052a3; }}
.verify-url {{ color: #666; font-size: 12px; word-break: break-all; margin-bottom: 24px; }}
.label {{ font-weight: 600; margin-bottom: 6px; display: block; }}
</style></head>
<body>
  <h2>{title_esc}</h2>
  <p class='subtitle'>Authorize this device to continue.</p>

  <span class='label'>1. Open the verification page</span>
  <a class='verify' href="{verify_url_esc}" target='_blank' rel='noopener noreferrer'>Open verification page</a>
  <p class='verify-url'>{verify_label}</p>

  <span class='label'>2. Enter this code when prompted</span>
  <div class='code-wrap'>
    <input id='user-code' type='text' readonly value="{code_esc}" aria-readonly='true'>
    <button class='copybtn' type='button'
      onclick="navigator.clipboard.writeText(document.getElementById('user-code').value)">Copy</button>
  </div>
</body></html>
"""

        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(html.encode("utf-8"))

    def log_message(self, format: str, *args: Any) -> None:
        logger.debug("Device bridge: {}", format % args)


class DeviceCodeBridgeHandle:
    """Handle for a running device-code bridge server."""

    def __init__(self, server: http.server.HTTPServer, thread: threading.Thread, url: str) -> None:
        self._server = server
        self._thread = thread
        self._shutdown_started = False
        self.url = url

    def shutdown(self) -> None:
        """Stop the bridge server."""
        if self._shutdown_started:
            return
        self._shutdown_started = True
        try:
            self._server.shutdown()
            self._server.server_close()
        except Exception:
            logger.debug("Device bridge shutdown raised", exc_info=True)


def device_code_bridge(
    title: str,
    user_code: str,
    verification_uri: str,
    verification_uri_complete: str | None = None,
    *,
    open_browser: bool = True,
) -> DeviceCodeBridgeHandle:
    """Start a local bridge that displays a device-authorization code in the browser.

    Returns a handle whose ``shutdown()`` stops the server once polling completes.
    """
    _DeviceBridgeHandler.title = title
    _DeviceBridgeHandler.user_code = user_code
    _DeviceBridgeHandler.verification_uri = verification_uri
    _DeviceBridgeHandler.verification_uri_complete = verification_uri_complete

    port = _find_free_port()
    server = http.server.HTTPServer(("127.0.0.1", port), _DeviceBridgeHandler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()

    url = f"http://127.0.0.1:{port}"
    print(f"\nOpening browser to display device authorization: {url}")
    if open_browser:
        try:
            webbrowser.open(url)
        except Exception as exc:
            logger.debug("webbrowser.open failed for device bridge: {}", exc)

    return DeviceCodeBridgeHandle(server=server, thread=thread, url=url)
