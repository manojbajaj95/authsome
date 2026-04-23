"""Browser-based secure input bridge.

Provides a mechanism to collect sensitive inputs from the user via a local
web browser instead of the terminal. This prevents secrets from being exposed
in environments where agents or scripts might intercept standard I/O.
"""

import http.server
import logging
import socket
import threading
import urllib.parse
import webbrowser
from html import escape
from typing import Any

logger = logging.getLogger(__name__)


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
            "</style>",
            "</head><body>",
            f"<h2>{self.title}</h2>",
            "<form method='POST'>",
        ]

        for field in self.fields:
            label = field["label"]
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
        logger.debug("Bridge server: %s", format % args)


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
