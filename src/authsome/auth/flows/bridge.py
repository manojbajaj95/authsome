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
import socket
import threading
import urllib.parse
import webbrowser
from html import escape
from typing import Any

from loguru import logger


def _find_free_port() -> int:
    """Find a free TCP port on localhost."""
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


class _BridgeHandler(http.server.BaseHTTPRequestHandler):
    """HTTP handler that renders a form and captures input."""

    title: str = "Secure Input"
    fields: list[dict[str, Any]] = []
    result: dict[str, str] | None = None

    def do_GET(self) -> None:
        """Serve the HTML form."""
        html = [
            "<!DOCTYPE html>",
            "<html><head><title>Authsome Secure Input</title>",
            "<style>",
            "body { font-family: system-ui, sans-serif; max-width: 400px; margin: 40px auto; padding: 20px; }",
            "label { display: block; margin-bottom: 8px; font-weight: bold; }",
            "input { width: 100%; padding: 8px; margin-bottom: 16px; border: 1px solid #ccc; ",
            "border-radius: 4px; box-sizing: border-box; }",
            ".static-wrap { display: flex; gap: 8px; margin-bottom: 16px; align-items: center; }",
            ".static-wrap input[readonly] { margin-bottom: 0; flex: 1; background: #f5f5f5; cursor: default; }",
            "button { width: 100%; padding: 10px; background-color: #0066cc; color: white; border: none; ",
            "border-radius: 4px; cursor: pointer; font-size: 16px; }",
            "button:hover { background-color: #0052a3; }",
            "button.copybtn { width: auto; padding: 8px 12px; font-size: 14px; flex-shrink: 0; }",
            ".instructions { margin-bottom: 16px; padding: 12px; border: 1px solid #ddd; border-radius: 8px; }",
            ".instructions-title { margin: 0 0 8px; font-weight: 600; }",
            ".instructions-links { margin: 0; padding-left: 20px; }",
            ".instructions-links li { margin-bottom: 6px; }",
            "</style>",
            "</head><body>",
            f"<h2>{self.title}</h2>",
            "<form method='POST'>",
        ]

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
                html.append(f"<label>{label}</label>")
                html.append(
                    "<div class='static-wrap'>"
                    f"<input type='text' readonly value='{val_esc}' aria-readonly='true'>"
                    "<button type='button' class='copybtn' "
                    'onclick="navigator.clipboard.writeText(this.previousElementSibling.value)">'
                    "Copy</button></div>"
                )
                continue
            name = field["name"]
            input_type = field.get("type", "text")
            required = "required" if field.get("required", True) else ""
            value = field.get("value", "")
            val_esc = escape(value, quote=True) if value else ""
            html.append(f"<label for='{name}'>{label}</label>")
            html.append(f"<input type='{input_type}' id='{name}' name='{name}' value='{val_esc}' {required}>")

        html.append("<button type='submit'>Submit Securely</button>")
        html.append("</form></body></html>")

        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.end_headers()
        self.wfile.write("\n".join(html).encode("utf-8"))

    def do_POST(self) -> None:
        """Process the submitted form data."""
        content_length = int(self.headers.get("Content-Length", 0))
        post_data = self.rfile.read(content_length).decode("utf-8")
        parsed = urllib.parse.parse_qs(post_data)

        # Flatten the parse_qs output (which returns lists)
        _BridgeHandler.result = {k: v[0] for k, v in parsed.items() if v}

        # Send success page
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.end_headers()
        success_html = (
            "<!DOCTYPE html><html><head><title>Success</title></head>"
            "<body style='font-family: sans-serif; text-align: center; margin-top: 50px;'>"
            "<h2>Success!</h2><p>You can close this window and return to the terminal.</p>"
            "</body></html>"
        )
        self.wfile.write(success_html.encode("utf-8"))

        # Notify that we are done
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

    server = http.server.HTTPServer(("127.0.0.1", port), _BridgeHandler)
    server_thread = threading.Thread(target=server.serve_forever, daemon=True)
    server_thread.start()

    url = f"http://127.0.0.1:{port}"
    print(f"\nRequires secure input for: {title}")
    print(f"Opening browser for secure input...\nIf the browser doesn't open, visit:\n{url}\n")
    webbrowser.open(url)

    # Wait for the server to shutdown (triggered by do_POST)
    server_thread.join(timeout=300)  # 5 minute timeout

    if _BridgeHandler.result is None:
        raise RuntimeError("Secure input bridge timed out or was cancelled.")

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
