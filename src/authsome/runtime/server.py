"""Localhost runtime server for API routes, callback endpoints, and operator UI.

Provides a versioned JSON API around :class:`AuthRuntimeService` and serves
the operator console HTML.  In milestone 1 this runs locally; the typed
client abstraction makes it possible to move the service to a hosted HTTPS
endpoint later.
"""

from __future__ import annotations

import json
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer
from typing import TYPE_CHECKING, Any

from loguru import logger

from authsome.runtime.ui import (
    render_connections_page,
    render_dashboard_page,
    render_session_page,
)

if TYPE_CHECKING:
    from authsome.runtime.service import AuthRuntimeService


class RuntimeServer:
    """Localhost daemon host for the Auth runtime API and operator UI.

    The server exposes:
    - ``/v1/sessions`` — create and list sessions
    - ``/v1/sessions/<id>`` — get session status
    - ``/v1/connections`` — list connections
    - ``/v1/credentials/resolve`` — resolve auth headers
    - ``/ui/`` — operator console pages
    """

    def __init__(self, service: AuthRuntimeService) -> None:
        self._service = service

    @property
    def service(self) -> AuthRuntimeService:
        return self._service

    # ── JSON API ──────────────────────────────────────────────────────────

    def handle_json(self, method: str, path: str, body: dict | None = None) -> dict[str, Any]:
        """Dispatch an API request and return a JSON-serialisable dict.

        Used by :class:`RuntimeClient` for in-process requests and by
        the HTTP handler for network requests.
        """
        # Sessions
        if method == "GET" and path == "/v1/sessions":
            sessions = self._service.list_sessions()
            return {"sessions": [s.model_dump(mode="json") for s in sessions]}

        if method == "GET" and path.startswith("/v1/sessions/"):
            session_id = path.rsplit("/", 1)[-1]
            session = self._service.get_session(session_id)
            return session.model_dump(mode="json")

        if method == "POST" and path == "/v1/sessions":
            body = body or {}
            session = self._service.start_login_session(
                provider=body["provider"],
                profile=body.get("profile", "default"),
                connection_name=body.get("connection_name", "default"),
                flow_type=body.get("flow_type", "pkce"),
                scopes=body.get("scopes"),
                force=body.get("force", False),
                base_url=body.get("base_url"),
            )
            return session.model_dump(mode="json")

        if (
            method == "POST"
            and path.startswith("/v1/sessions/")
            and (path.endswith("/complete") or path.endswith("/resume"))
        ):
            session_id = path.split("/")[3]
            body = body or {}
            input_provider = body.pop("input_provider", None)
            callback_data = body.pop("callback_data", None) or body
            return self._service.complete_login_session(
                session_id,
                input_provider=input_provider,
                callback_data=callback_data,
                **body,
            )

        # Connections
        if method == "GET" and path == "/v1/connections":
            return self._service.list_connections()

        # Credential resolution
        if method == "POST" and path == "/v1/credentials/resolve":
            body = body or {}
            headers = self._service.resolve_request_credentials(
                provider=body["provider"],
                connection_name=body.get("connection_name", "default"),
                profile=body.get("profile"),
            )
            return {"headers": headers}

        # CLI Operations
        if method == "GET" and path == "/v1/whoami":
            return self._service.whoami()

        if method == "GET" and path == "/v1/doctor":
            return self._service.doctor()

        if method == "GET" and path.startswith("/v1/providers/"):
            provider = path.rsplit("/", 1)[-1]
            return self._service.get_provider(provider)

        if method == "POST" and path == "/v1/providers":
            body = body or {}
            self._service.register_provider(body["definition"], force=body.get("force", False))
            return {"status": "ok"}

        if method == "DELETE" and path.startswith("/v1/providers/"):
            provider = path.rsplit("/", 1)[-1]
            self._service.remove(provider)
            return {"status": "ok"}

        if path.startswith("/v1/connections/"):
            parts = path.strip("/").split("/")
            if len(parts) >= 4:
                provider = parts[2]
                connection = parts[3]

                if len(parts) == 4 and method == "GET":
                    return self._service.get_connection(provider, connection)

                if len(parts) == 5:
                    action = parts[4]
                    if action == "logout" and method == "POST":
                        self._service.logout(provider, connection)
                        return {"status": "ok"}
                    if action == "revoke" and method == "POST":
                        self._service.revoke(provider, connection)
                        return {"status": "ok"}
                    if action.startswith("export") and method == "GET":
                        # The query string was stripped in do_GET, so we need a way to pass query params.
                        # Actually, let's just pass body for export via POST, or pass query params in body.
                        # We will use POST for export to easily pass JSON body instead of parsing query strings.
                        pass

        # We will use POST /v1/connections/export for export to pass format easily
        if method == "POST" and path == "/v1/connections/export":
            body = body or {}
            output = self._service.export(
                provider=body["provider"],
                connection_name=body.get("connection_name", "default"),
                format=body.get("format", "env"),
            )
            return {"output": output}

        raise KeyError(f"Unknown route: {method} {path}")

    # ── HTML UI ───────────────────────────────────────────────────────────

    def handle_ui(self, path: str) -> str:
        """Return operator console HTML for the given path."""
        if path == "/ui/" or path == "/ui":
            return render_dashboard_page(self._service)

        if path.startswith("/ui/sessions/"):
            session_id = path.rsplit("/", 1)[-1]
            session = self._service.get_session(session_id)
            return render_session_page(session)

        if path == "/ui/connections":
            return render_connections_page(self._service)

        return "<html><body><h1>404 Not Found</h1></body></html>"

    # ── HTTP server lifecycle ─────────────────────────────────────────────

    def start(self, host: str = "127.0.0.1", port: int = 7998) -> RunningRuntimeServer:
        """Start the runtime HTTP server in a background thread."""
        handler_factory = _make_handler(self)
        server = HTTPServer((host, port), handler_factory)

        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()

        url = f"http://{host}:{port}"
        logger.info("Runtime server listening on {}", url)
        return RunningRuntimeServer(url=url, server=server, thread=thread)


class RunningRuntimeServer:
    """Handle for a runtime server running in a background thread."""

    def __init__(self, url: str, server: HTTPServer, thread: threading.Thread) -> None:
        self.url = url
        self.server = server
        self.thread = thread

    def shutdown(self) -> None:
        self.server.shutdown()
        self.thread.join(timeout=5)


def _make_handler(runtime_server: RuntimeServer) -> type[BaseHTTPRequestHandler]:
    """Create an HTTP request handler class bound to the runtime server."""

    class _Handler(BaseHTTPRequestHandler):
        def do_GET(self) -> None:
            try:
                import urllib.parse

                parsed = urllib.parse.urlparse(self.path)
                path = parsed.path
                if path in ("/v1/callbacks/pkce", "/v1/callbacks/dcr_pkce"):
                    query = urllib.parse.parse_qs(parsed.query)
                    callback_data = {k: v[0] for k, v in query.items()}

                    # We need to find the session that has this state!
                    sessions = runtime_server.service.list_sessions()
                    matching_session = None
                    for s in sessions:
                        if s.payload.get("internal_state") == callback_data.get("state"):
                            matching_session = s
                            break

                    if not matching_session:
                        self._send(400, "<h1>Invalid state</h1><p>No matching session found.</p>", "text/html")
                        return

                    # Resume the flow!
                    runtime_server.service.resume_login_session(matching_session.session_id, callback_data)
                    self._send(
                        200,
                        "<h1>Authentication Successful</h1><p>You can close this window now.</p>",
                        "text/html",
                    )
                    return

                if path.startswith("/ui"):
                    html = runtime_server.handle_ui(path)
                    self._send(200, html, "text/html")
                elif path.startswith("/v1/"):
                    data = runtime_server.handle_json("GET", path)
                    self._send(200, json.dumps(data), "application/json")
                else:
                    self._send(404, '{"error": "Not Found"}', "application/json")
            except KeyError as exc:
                self._send(404, json.dumps({"error": str(exc)}), "application/json")
            except Exception as exc:
                logger.warning("Runtime server error: {}", exc)
                self._send(500, json.dumps({"error": str(exc)}), "application/json")

        def do_POST(self) -> None:
            try:
                path = self.path.split("?")[0]
                content_length = int(self.headers.get("Content-Length", 0))
                body = json.loads(self.rfile.read(content_length)) if content_length > 0 else {}
                data = runtime_server.handle_json("POST", path, body)
                self._send(200, json.dumps(data), "application/json")
            except KeyError as exc:
                self._send(404, json.dumps({"error": str(exc)}), "application/json")
            except Exception as exc:
                logger.warning("Runtime server error: {}", exc)
                self._send(500, json.dumps({"error": str(exc)}), "application/json")

        def do_DELETE(self) -> None:
            try:
                path = self.path.split("?")[0]
                data = runtime_server.handle_json("DELETE", path)
                self._send(200, json.dumps(data), "application/json")
            except KeyError as exc:
                self._send(404, json.dumps({"error": str(exc)}), "application/json")
            except Exception as exc:
                logger.warning("Runtime server error: {}", exc)
                self._send(500, json.dumps({"error": str(exc)}), "application/json")

        def _send(self, status: int, body: str, content_type: str) -> None:
            self.send_response(status)
            self.send_header("Content-Type", f"{content_type}; charset=utf-8")
            self.end_headers()
            self.wfile.write(body.encode("utf-8"))

        def log_message(self, format: str, *args: Any) -> None:
            logger.debug("Runtime HTTP: {}", format % args)

    return _Handler
