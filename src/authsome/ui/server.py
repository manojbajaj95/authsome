"""Zero-dependency local HTTP server for Authsome UI."""

import http.server
import json
import socketserver
import threading
import time
import webbrowser
from pathlib import Path
from typing import Any

from authsome.context import AuthsomeContext


def get_all_data(actx: AuthsomeContext) -> dict[str, Any]:
    """Gather all required information for the dashboard."""
    # 1. Diagnostics
    diagnostics = actx.doctor()

    # 2. Providers & Connections
    by_source = actx.auth.list_providers_by_source()
    raw_list = actx.auth.list_connections()

    connected_map: dict[str, list[dict]] = {}
    for provider_group in raw_list:
        connected_map[provider_group["name"]] = provider_group["connections"]

    def build_provider_entry(provider: Any, source: str) -> dict:
        conns = connected_map.get(provider.name, [])
        connections_out = []
        for conn in conns:
            c: dict = {
                "connection_name": conn["connection_name"],
                "auth_type": conn.get("auth_type"),
                "status": conn.get("status"),
            }
            if conn.get("scopes"):
                c["scopes"] = conn["scopes"]
            if conn.get("expires_at"):
                c["expires_at"] = conn["expires_at"]
            connections_out.append(c)
        return {
            "name": provider.name,
            "display_name": provider.display_name,
            "auth_type": provider.auth_type.value,
            "source": source,
            "connections": connections_out,
        }

    bundled_out = [build_provider_entry(p, "bundled") for p in by_source.get("bundled", [])]
    custom_out = [build_provider_entry(p, "custom") for p in by_source.get("custom", [])]

    all_providers = bundled_out + custom_out

    # Calculate connected count
    connected_providers_count = sum(1 for p in all_providers if len(p["connections"]) > 0)
    total_connections_count = sum(len(p["connections"]) for p in all_providers)

    return {
        "diagnostics": diagnostics,
        "providers": all_providers,
        "stats": {
            "connected_providers": connected_providers_count,
            "total_connections": total_connections_count,
        },
    }


def serve_dashboard(port: int = 8000) -> None:
    """Start a local server and open the browser."""
    static_dir = Path(__file__).parent / "static"

    class AuthsomeUIHandler(http.server.BaseHTTPRequestHandler):
        def log_message(self, format: str, *args: Any) -> None:
            # Suppress HTTP logging for a cleaner CLI
            pass

        def do_GET(self) -> None:
            if self.path == "/":
                try:
                    self.send_response(200)
                    self.send_header("Content-type", "text/html")
                    self.end_headers()

                    with AuthsomeContext.create() as actx:
                        data = get_all_data(actx)

                    html = (static_dir / "index.html").read_text(encoding="utf-8")
                    data_json = json.dumps(data)
                    script_tag = f"<script>\nwindow.AUTHSOME_DATA = {data_json};\n</script>"
                    html = html.replace("<!-- DATA_INJECTION -->", script_tag)

                    self.wfile.write(html.encode("utf-8"))
                except Exception as e:
                    self.send_response(500)
                    self.send_header("Content-type", "text/plain")
                    self.end_headers()
                    self.wfile.write(f"Internal Server Error: {str(e)}".encode())

            elif self.path == "/style.css":
                css_path = static_dir / "style.css"
                if css_path.exists():
                    self.send_response(200)
                    self.send_header("Content-type", "text/css")
                    self.end_headers()
                    self.wfile.write(css_path.read_text(encoding="utf-8").encode("utf-8"))
                else:
                    self.send_response(404)
                    self.end_headers()

            elif self.path == "/app.js":
                js_path = static_dir / "app.js"
                if js_path.exists():
                    self.send_response(200)
                    self.send_header("Content-type", "application/javascript")
                    self.end_headers()
                    self.wfile.write(js_path.read_text(encoding="utf-8").encode("utf-8"))
                else:
                    self.send_response(404)
                    self.end_headers()

            else:
                self.send_response(404)
                self.end_headers()

    class ThreadedHTTPServer(socketserver.ThreadingMixIn, http.server.HTTPServer):
        daemon_threads = True

    # Try to find an open port
    max_retries = 10
    current_port = port
    server = None
    for _ in range(max_retries):
        try:
            server = ThreadedHTTPServer(("127.0.0.1", current_port), AuthsomeUIHandler)
            break
        except OSError:
            current_port += 1

    if server is None:
        print("Error: Could not find an open port to start the UI server.")
        return

    url = f"http://127.0.0.1:{current_port}"
    print(f"Starting Authsome UI at {url}")
    print("Press Ctrl+C to stop.")

    server_thread = threading.Thread(target=server.serve_forever)
    server_thread.daemon = True
    server_thread.start()

    time.sleep(0.5)
    webbrowser.open(url)

    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        print("\nStopping Authsome UI...")
        server.shutdown()
        server.server_close()
