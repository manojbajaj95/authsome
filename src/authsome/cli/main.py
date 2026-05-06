"""Command-line interface for authsome."""

import functools
import ipaddress
import json as json_lib
import os
import pathlib
import sys
import urllib.parse
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import click
import requests
from loguru import logger

from authsome import FlowType, __version__, audit
from authsome.auth.models.enums import ExportFormat
from authsome.auth.models.provider import ProviderDefinition
from authsome.cli.client import AuthsomeApiClient
from authsome.cli.daemon_control import (
    DaemonUnavailableError,
    daemon_status,
    ensure_daemon,
    start_daemon,
    stop_daemon,
)
from authsome.errors import AuthsomeError
from authsome.proxy.runner import ProxyRunner
from authsome.utils import redact


class CliRuntime:
    """CLI-local wiring around the daemon API client."""

    def __init__(self, client: AuthsomeApiClient) -> None:
        self.runtime_client = client
        self.home = Path(os.environ.get("AUTHSOME_HOME", str(Path.home() / ".authsome")))

    def doctor(self) -> dict[str, Any]:
        return self.runtime_client.doctor()

    def require_local_proxy(self) -> ProxyRunner:
        return ProxyRunner(client=self.runtime_client)


class ContextObj:
    """Context object passed to all commands."""

    def __init__(self, json_output: bool, quiet: bool, no_color: bool):
        self.json_output = json_output
        self.quiet = quiet
        self.no_color = no_color
        self._ctx: CliRuntime | None = None

    def initialize(self) -> CliRuntime:
        if self._ctx is None:
            self._ctx = CliRuntime(ensure_daemon())
            audit.setup(self._ctx.home / "audit.log")
        return self._ctx

    def print_json(self, data: Any) -> None:
        click.echo(json_lib.dumps(data, indent=2))

    def echo(self, message: str, err: bool = False, color: str | None = None, nl: bool = True) -> None:
        if self.quiet:
            return
        if self.no_color:
            color = None
        click.secho(message, err=err, fg=color, nl=nl)


pass_ctx = click.make_pass_decorator(ContextObj)


def common_options(f):
    @click.option("--json", "json_output", is_flag=True, help="Output in machine-readable JSON format.")
    @click.option("--quiet", is_flag=True, help="Suppress non-essential output.")
    @click.option("--no-color", is_flag=True, help="Disable ANSI colors.")
    @functools.wraps(f)
    def wrapper(*args, **kwargs):
        json_output = kwargs.pop("json_output", False)
        quiet = kwargs.pop("quiet", False)
        no_color = kwargs.pop("no_color", False)
        ctx = click.get_current_context()
        if getattr(ctx, "obj", None) is None:
            ctx.obj = ContextObj(json_output, quiet, no_color)
        else:
            if json_output:
                ctx.obj.json_output = True
            if quiet:
                ctx.obj.quiet = True
            if no_color:
                ctx.obj.no_color = True
        return f(*args, **kwargs)

    return wrapper


def format_error_code(exc: Exception) -> int:
    if isinstance(exc, DaemonUnavailableError):
        return 9
    if not isinstance(exc, AuthsomeError):
        return 1
    exc_name = exc.__class__.__name__
    if exc_name == "ProviderNotFoundError":
        return 3
    if exc_name == "AuthenticationFailedError":
        return 4
    if exc_name == "CredentialMissingError":
        return 5
    if exc_name == "InputCancelledError":
        return 8
    if exc_name == "RefreshFailedError":
        return 6
    if exc_name == "StoreUnavailableError":
        return 7
    return 1


def handle_errors(func):
    @functools.wraps(func)
    def wrapper(ctx_obj: ContextObj, *args, **kwargs):
        try:
            return func(ctx_obj, *args, **kwargs)
        except Exception as exc:
            if ctx_obj.json_output:
                ctx_obj.print_json({"error": exc.__class__.__name__, "message": str(exc)})
            else:
                ctx_obj.echo(f"Error: {exc}", err=True, color="red")
            sys.exit(format_error_code(exc))

    return wrapper


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


def format_expires_at(expires_at: str | None) -> str | None:
    """Return a compact relative expiry label for CLI output."""
    if not expires_at:
        return None
    try:
        expiry = datetime.fromisoformat(expires_at.replace("Z", "+00:00"))
    except ValueError:
        return f"expires at {expires_at}"
    if expiry.tzinfo is None:
        expiry = expiry.replace(tzinfo=UTC)

    total_seconds = int((expiry - datetime.now(UTC)).total_seconds())
    if total_seconds < 0:
        label = _format_duration(-total_seconds)
        return f"expired {label} ago"
    label = _format_duration(total_seconds)
    return f"expires in {label}"


def connection_is_active(connection: dict[str, Any]) -> bool:
    """Return whether a connection should count as actively connected."""
    if connection.get("status") != "connected":
        return False

    expires_at = connection.get("expires_at")
    if not expires_at:
        return True
    try:
        expiry = datetime.fromisoformat(str(expires_at).replace("Z", "+00:00"))
    except ValueError:
        return True
    if expiry.tzinfo is None:
        expiry = expiry.replace(tzinfo=UTC)
    return datetime.now(UTC) < expiry


def _format_duration(total_seconds: int) -> str:
    if total_seconds < 60:
        return f"{total_seconds}s"
    minutes = total_seconds // 60
    if minutes < 60:
        return f"{minutes}m"
    hours = minutes // 60
    if hours < 48:
        return f"{hours}h"
    days = hours // 24
    return f"{days}d"


def _validate_provider_endpoints(definition: Any, ctx_obj: ContextObj) -> list[tuple[str, str, bool]]:
    """Extract and validate provider endpoints for security."""
    endpoints_to_check: list[tuple[str, str, bool]] = []
    if definition.oauth:
        if definition.oauth.authorization_url:
            endpoints_to_check.append(("authorization_url", definition.oauth.authorization_url, False))
        if definition.oauth.token_url:
            endpoints_to_check.append(("token_url", definition.oauth.token_url, False))
        if definition.oauth.revocation_url:
            endpoints_to_check.append(("revocation_url", definition.oauth.revocation_url, False))
        if definition.oauth.device_authorization_url:
            endpoints_to_check.append(("device_authorization_url", definition.oauth.device_authorization_url, False))
        if definition.oauth.registration_endpoint:
            endpoints_to_check.append(("registration_endpoint", definition.oauth.registration_endpoint, False))
    if definition.host_url:
        endpoints_to_check.append(("host_url", definition.host_url, True))

    for name, val, is_host in endpoints_to_check:
        if "://" in val:
            parsed = urllib.parse.urlparse(val)
            if parsed.scheme != "https":
                ctx_obj.echo(f"Error: {name} must use HTTPS scheme ({val})", err=True, color="red")
                sys.exit(1)
            host = parsed.hostname
        else:
            host = val

        if host in ("localhost", "127.0.0.1", "::1"):
            ctx_obj.echo(f"Error: {name} cannot be localhost ({val})", err=True, color="red")
            sys.exit(1)

        if host:
            try:
                ipaddress.ip_address(host)
                ctx_obj.echo(f"Error: {name} cannot be a bare IP address ({val})", err=True, color="red")
                sys.exit(1)
            except ValueError:
                pass

    return endpoints_to_check


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


@cli.command(name="list")
@common_options
@pass_ctx
@handle_errors
def list_cmd(ctx_obj: ContextObj) -> None:
    """List providers and connection states."""
    actx = ctx_obj.initialize()
    data = actx.runtime_client.list_connections()
    raw_list = data["connections"]
    by_source = data["by_source"]

    connected: dict[str, list[dict]] = {}
    for provider_group in raw_list:
        connected[provider_group["name"]] = provider_group["connections"]

    def build_provider_entry(provider_data, source: str) -> dict:
        provider = ProviderDefinition.model_validate(provider_data)
        conns = connected.get(provider.name, [])
        connections_out = []
        for conn in conns:
            c: dict = {
                "connection_name": conn["connection_name"],
                "is_default": conn.get("is_default", False),
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

    bundled_out = [build_provider_entry(p, "bundled") for p in by_source["bundled"]]
    custom_out = [build_provider_entry(p, "custom") for p in by_source["custom"]]

    if ctx_obj.json_output:
        ctx_obj.print_json({"bundled": bundled_out, "custom": custom_out})
        return

    rows: list[dict[str, Any]] = []
    for p in bundled_out + custom_out:
        provider_label = f"{p['display_name']} [{p['name']}]"
        if p["connections"]:
            for conn in p["connections"]:
                rows.append(
                    {
                        "provider_id": p["name"],
                        "provider": provider_label,
                        "source": p["source"],
                        "auth": p["auth_type"],
                        "connection": (
                            f"{conn['connection_name']} (default)"
                            if conn.get("is_default")
                            else conn["connection_name"]
                        ),
                        "status": conn["status"],
                        "expires_at": conn.get("expires_at"),
                        "expires": format_expires_at(conn.get("expires_at")) or "-",
                    }
                )
        else:
            rows.append(
                {
                    "provider_id": p["name"],
                    "provider": provider_label,
                    "source": p["source"],
                    "auth": p["auth_type"],
                    "connection": "-",
                    "status": "not_connected",
                    "expires_at": None,
                    "expires": "-",
                }
            )

    if not rows:
        ctx_obj.echo("No providers configured.")
        return

    connected_provider_ids = {row["provider_id"] for row in rows if connection_is_active(row)}
    connected_count = len(connected_provider_ids)
    ctx_obj.echo(f"Providers: {len(bundled_out) + len(custom_out)} total, {connected_count} connected")

    headers = {
        "provider": "Provider",
        "source": "Source",
        "auth": "Auth",
        "connection": "Connection",
        "status": "Status",
        "expires": "Expires",
    }
    widths = {
        key: max(len(headers[key]), *(len(row[key]) for row in rows))
        for key in ("provider", "source", "auth", "connection", "status", "expires")
    }

    def render_row(row: dict[str, Any]) -> str:
        return (
            f"{row['provider']:<{widths['provider']}}  "
            f"{row['source']:<{widths['source']}}  "
            f"{row['auth']:<{widths['auth']}}  "
            f"{row['connection']:<{widths['connection']}}  "
            f"{row['status']:<{widths['status']}}  "
            f"{row['expires']:<{widths['expires']}}"
        ).rstrip()

    ctx_obj.echo(render_row(headers))
    ctx_obj.echo(
        render_row(
            {key: "-" * widths[key] for key in ("provider", "source", "auth", "connection", "status", "expires")}
        )
    )
    for row in rows:
        ctx_obj.echo(render_row(row))


@cli.command(name="log")
@click.option("-n", "--lines", default=50, help="Number of lines to show.")
@common_options
@pass_ctx
@handle_errors
def log_cmd(ctx_obj: ContextObj, lines: int) -> None:
    """View the authsome audit log."""
    actx = ctx_obj.initialize()
    audit_file = actx.home / "audit.log"
    if not audit_file.exists():
        if ctx_obj.json_output:
            ctx_obj.print_json([])
        else:
            ctx_obj.echo("No audit log found.", err=True, color="yellow")
        sys.exit(0)

    try:
        with open(audit_file, encoding="utf-8") as f:
            log_lines = f.readlines()

        target_lines = [line.strip() for line in log_lines[-lines:] if line.strip()]

        if ctx_obj.json_output:
            parsed_lines = [json_lib.loads(line) for line in target_lines]
            ctx_obj.print_json(parsed_lines)
        else:
            for line in target_lines:
                ctx_obj.echo(line)
    except Exception as e:
        if ctx_obj.json_output:
            ctx_obj.print_json({"error": str(e)})
        else:
            ctx_obj.echo(f"Error reading audit log: {e}", err=True, color="red")
        sys.exit(1)


@cli.command()
@click.argument("provider")
@click.option("--connection", default="default", help="Connection name.")
@click.option("--flow", help="Authentication flow override.")
@click.option("--scopes", help="Comma-separated scopes to request.")
@click.option("--base-url", help="Base URL for the provider (e.g. for GitHub Enterprise).")
@click.option("--force", is_flag=True, help="Overwrite an existing connection if it already exists.")
@common_options
@pass_ctx
@handle_errors
def login(
    ctx_obj: ContextObj,
    provider: str,
    connection: str,
    flow: str | None,
    scopes: str | None,
    base_url: str | None,
    force: bool,
) -> None:
    """Authenticate with a provider using its configured flow."""
    actx = ctx_obj.initialize()
    flow_value = FlowType(flow).value if flow else None
    scope_list = [s.strip() for s in scopes.split(",")] if scopes else None

    if force and not ctx_obj.quiet:
        ctx_obj.echo("Warning: Forcing login will overwrite any existing connection.", color="yellow")
    if not ctx_obj.json_output:
        ctx_obj.echo(f"Starting login for {provider}...", color="cyan")

    try:
        session_info = actx.runtime_client.start_login(
            provider=provider,
            connection=connection,
            flow=flow_value,
            scopes=scope_list,
            base_url=base_url,
            force=force,
        )
        session_id = session_info["id"]
        login_result = {"status": "success"}

        next_action = session_info.get("next_action", {"type": "none"})
        action_type = next_action.get("type")
        if action_type == "open_url":
            auth_url = next_action["url"]
            if not ctx_obj.quiet:
                ctx_obj.echo("Opening browser to continue login...", color="cyan")
                ctx_obj.echo(f"If the browser doesn't open, visit: {auth_url}", color="cyan")
            import webbrowser

            try:
                webbrowser.open(auth_url)
            except Exception:
                pass
            login_result = {"status": "started"}
        elif action_type == "device_code":
            if not ctx_obj.quiet:
                verification = next_action.get("verification_uri_complete") or next_action.get("verification_uri")
                ctx_obj.echo(f"Visit: {verification}", color="cyan")
                ctx_obj.echo(f"Code: {next_action.get('user_code')}", color="cyan")
            import time

            interval = int(next_action.get("interval", 5))
            while True:
                time.sleep(interval)
                s_state = actx.runtime_client.resume_login_session(session_id)
                if s_state.get("status") in ("completed", "failed", "expired", "cancelled"):
                    login_result = {
                        "status": "success" if s_state.get("status") == "completed" else s_state.get("status"),
                        "record_status": s_state.get("status"),
                    }
                    if s_state.get("status") != "completed":
                        raise AuthsomeError(s_state.get("error") or "Device-code login did not complete")
                    break
        else:
            login_result = {"status": "started"}

        audit.log("login", provider=provider, connection=connection, flow=flow or "unknown", status="success")
    except Exception:
        audit.log("login", provider=provider, connection=connection, status="failure")
        raise

    if ctx_obj.json_output:
        ctx_obj.print_json(
            {
                "status": login_result.get("status", "success"),
                "provider": provider,
                "connection": connection,
                "record_status": login_result.get("record_status", "valid"),
            }
        )
    elif login_result.get("status") == "already_connected":
        ctx_obj.echo(f"Already logged in to {provider} ({connection}).", color="green")
    elif login_result.get("status") == "started":
        ctx_obj.echo(
            f"Login started for {provider} ({connection}). Run 'authsome list' to verify completion.",
            color="green",
        )
    else:
        ctx_obj.echo(f"Successfully logged in to {provider} ({connection}).", color="green")


@cli.command()
@click.argument("provider")
@click.option("--connection", default="default", help="Connection name.")
@common_options
@pass_ctx
@handle_errors
def logout(ctx_obj: ContextObj, provider: str, connection: str) -> None:
    """Log out of a connection and remove local state."""
    actx = ctx_obj.initialize()
    actx.runtime_client.logout(provider, connection)
    audit.log("logout", provider=provider, connection=connection)

    if ctx_obj.json_output:
        ctx_obj.print_json({"status": "logged_out", "provider": provider, "connection": connection})
    else:
        ctx_obj.echo(f"Logged out of {provider} ({connection}).", color="green")


@cli.group(name="connection")
def connection_group() -> None:
    """Manage provider connections."""


@connection_group.command(name="set-default")
@click.argument("provider")
@click.argument("connection")
@common_options
@pass_ctx
@handle_errors
def set_default_connection(ctx_obj: ContextObj, provider: str, connection: str) -> None:
    """Set the default connection for a provider."""
    actx = ctx_obj.initialize()
    actx.runtime_client.set_default_connection(provider, connection)
    if ctx_obj.json_output:
        ctx_obj.print_json({"status": "ok", "provider": provider, "default_connection": connection})
    else:
        ctx_obj.echo(f"Default connection for {provider} set to {connection}.", color="green")


@cli.command()
@click.argument("provider")
@common_options
@pass_ctx
@handle_errors
def revoke(ctx_obj: ContextObj, provider: str) -> None:
    """Complete reset of the provider, removing all connections and client secrets."""
    actx = ctx_obj.initialize()
    actx.runtime_client.revoke(provider)
    audit.log("revoke", provider=provider, connection="all")

    if ctx_obj.json_output:
        ctx_obj.print_json({"status": "revoked", "provider": provider})
    else:
        ctx_obj.echo(f"Revoked all credentials for {provider}.", color="green")


@cli.command()
@click.argument("provider")
@common_options
@pass_ctx
@handle_errors
def remove(ctx_obj: ContextObj, provider: str) -> None:
    """Delete a custom provider definition."""
    actx = ctx_obj.initialize()
    actx.runtime_client.remove(provider)
    audit.log("remove", provider=provider, connection="all")

    if ctx_obj.json_output:
        ctx_obj.print_json({"status": "removed", "provider": provider})
    else:
        ctx_obj.echo(f"Removed provider {provider}.", color="green")


@cli.command()
@click.argument("provider")
@click.option("--connection", default="default", help="Connection name.")
@click.option("--field", help="Return only a specific field.")
@click.option("--show-secret", is_flag=True, help="Reveal encrypted secrets.")
@common_options
@pass_ctx
@handle_errors
def get(ctx_obj: ContextObj, provider: str, connection: str, field: str | None, show_secret: bool) -> None:
    """Return provider connection metadata by default."""
    actx = ctx_obj.initialize()
    record_dict = actx.runtime_client.get_connection(provider, connection)
    from authsome.auth.models.connection import ConnectionRecord

    record = ConnectionRecord.model_validate(record_dict)

    if show_secret:
        from authsome.utils import require_os_auth

        if not require_os_auth("reveal secrets"):
            ctx_obj.echo("Authentication failed or cancelled.", err=True, color="red")
            sys.exit(1)
        audit.log("get", provider=provider, connection=connection, field=field or "all")

    data = redact(record) if not show_secret else record.model_dump(mode="json")

    if field:
        if field in data:
            if show_secret:
                ctx_obj.echo(
                    "WARNING: Secret printed to stdout. Run: history -d <n> to remove from shell history.",
                    err=True,
                    color="yellow",
                )
            if ctx_obj.json_output:
                ctx_obj.print_json({field: data[field]})
            else:
                ctx_obj.echo(str(data[field]))
        else:
            ctx_obj.echo(f"Field '{field}' not found.", err=True, color="red")
            sys.exit(1)
        return

    if show_secret:
        ctx_obj.echo(
            "WARNING: Secret printed to stdout. Run: history -d <n> to remove from shell history.",
            err=True,
            color="yellow",
        )

    if ctx_obj.json_output:
        ctx_obj.print_json(data)
    else:
        for k, v in data.items():
            ctx_obj.echo(f"{k}: {v}")


@cli.command()
@click.argument("provider")
@common_options
@pass_ctx
@handle_errors
def inspect(ctx_obj: ContextObj, provider: str) -> None:
    """Return provider definition and local connection summary."""
    actx = ctx_obj.initialize()
    definition_dict = actx.runtime_client.get_provider(provider)
    data = definition_dict
    data["connections"] = []
    connections_data = actx.runtime_client.list_connections()
    for provider_group in connections_data["connections"]:
        if provider_group["name"] == provider:
            data["connections"] = provider_group["connections"]
            break

    if ctx_obj.json_output:
        ctx_obj.print_json(data)
    else:
        ctx_obj.echo(json_lib.dumps(data, indent=2))


@cli.command()
@click.argument("provider", required=False)
@click.option("--connection", default="default", help="Connection name.")
@click.option("--format", "export_format", type=click.Choice(["env", "json", "shell"]), default="env")
@common_options
@pass_ctx
@handle_errors
def export(ctx_obj: ContextObj, provider: str | None, connection: str, export_format: str) -> None:
    """Export credential material in selected format."""
    ctx_obj.echo(
        "Note: secrets are now in your shell environment for this session. Prefer 'authsome run' for scoped injection.",
        err=True,
        color="yellow",
    )
    actx = ctx_obj.initialize()
    fmt = ExportFormat(export_format)
    output = actx.runtime_client.export(provider, connection, format=fmt.value)
    audit.log("export", provider=provider, connection=connection, format=fmt.value)
    if output:
        click.echo(output)


@cli.command(context_settings=dict(ignore_unknown_options=True))
@click.argument("command", nargs=-1, required=True)
@common_options
@pass_ctx
@handle_errors
def run(ctx_obj: ContextObj, command: tuple[str]) -> None:
    """Run a subprocess behind the local auth proxy."""
    actx = ctx_obj.initialize()
    result = actx.require_local_proxy().run(list(command))
    sys.exit(result.returncode)


@cli.command()
@click.argument("path")
@click.option("--force", is_flag=True, help="Force overwrite if provider exists.")
@common_options
@pass_ctx
@handle_errors
def register(ctx_obj: ContextObj, path: str, force: bool) -> None:
    """Register a provider definition from a local JSON file path."""

    actx = ctx_obj.initialize()
    filepath = pathlib.Path(path)
    if not filepath.exists():
        ctx_obj.echo(f"File not found: {path}", err=True, color="red")
        sys.exit(1)

    try:
        data = json_lib.loads(filepath.read_text(encoding="utf-8"))
        from authsome.auth.models.provider import ProviderDefinition

        definition = ProviderDefinition.model_validate(data)

        # 1. Extract and validate endpoints
        endpoints_to_check = _validate_provider_endpoints(definition, ctx_obj)

        # 3. Confirmation prompt
        if not ctx_obj.json_output and not ctx_obj.quiet and not force:
            ctx_obj.echo(f"Registering '{definition.name}' provider:")
            for name, val, _ in endpoints_to_check:
                ctx_obj.echo(f"  - {name}: {val}")

            if definition.oauth and definition.oauth.token_url:
                prompt_msg = f"Register '{definition.name}' with token endpoint {definition.oauth.token_url}? [y/N]"
            elif definition.host_url:
                prompt_msg = f"Register '{definition.name}' with host {definition.host_url}? [y/N]"
            else:
                prompt_msg = f"Register '{definition.name}' provider? [y/N]"

            if not click.confirm(prompt_msg, default=False):
                ctx_obj.echo("Registration aborted.", color="yellow")
                sys.exit(0)

        actx.runtime_client.register_provider(definition.model_dump(mode="json"), force=force)

        endpoints = [ep for _, ep, _ in endpoints_to_check]
        audit.log("register", provider=definition.name, endpoints=endpoints)

        if ctx_obj.json_output:
            ctx_obj.print_json({"status": "registered", "provider": definition.name})
        else:
            ctx_obj.echo(f"Provider {definition.name} registered.", color="green")

        # 4. Post-registration connectivity check

        warnings = []
        for name, val, is_host in endpoints_to_check:
            if name not in ("host_url", "authorization_url"):
                continue

            target = val
            if is_host and "://" not in target:
                target = f"https://{target}"

            if not ctx_obj.quiet:
                ctx_obj.echo(f"Testing reachability for {name}...", color="cyan")
            try:
                requests.head(target, timeout=5, allow_redirects=True)
            except requests.RequestException as e:
                warnings.append(f"{name} ({val}) is unreachable: {e}")

        if warnings and not ctx_obj.quiet:
            for w in warnings:
                ctx_obj.echo(f"Warning: {w}", color="yellow")

    except Exception as exc:
        ctx_obj.echo(f"Failed to register provider: {exc}", err=True, color="red")
        sys.exit(1)


@cli.command()
@common_options
@pass_ctx
@handle_errors
def whoami(ctx_obj: ContextObj) -> None:
    """Show basic local context."""
    actx = ctx_obj.initialize()

    # Get info from daemon
    whoami_data = actx.runtime_client.whoami()
    doctor_results = actx.doctor()

    vault_status = "OK" if doctor_results.get("checks", {}).get("vault") == "ok" else "ERROR"

    # Connected providers with counts
    connected_providers = []
    connections_data = actx.runtime_client.list_connections()
    for provider_group in connections_data["connections"]:
        active_conns = [c["connection_name"] for c in provider_group["connections"] if connection_is_active(c)]
        if active_conns:
            connected_providers.append(
                {
                    "name": provider_group["name"],
                    "count": len(active_conns),
                    "connections": active_conns,
                }
            )

    data = {
        "authsome_version": whoami_data["version"],
        "home_directory": whoami_data["home"],
        "active_identity": whoami_data["active_identity"],
        "encryption_backend": whoami_data["encryption_backend"],
        "vault_status": vault_status,
        "connected_providers_count": len(connected_providers),
        "connected_providers": connected_providers,
    }

    if ctx_obj.json_output:
        ctx_obj.print_json(data)
    else:
        ctx_obj.echo(f"Authsome Version:  {data['authsome_version']}")
        ctx_obj.echo(f"Home Directory:    {data['home_directory']}")
        ctx_obj.echo(f"Active Identity:   {data['active_identity']}")
        status_color = "green" if vault_status == "OK" else "red"
        ctx_obj.echo(f"Encryption:        {data['encryption_backend']} [", nl=False)
        ctx_obj.echo(vault_status, color=status_color, nl=False)
        ctx_obj.echo("]")

        ctx_obj.echo(f"\nConnected Providers: {data['connected_providers_count']}")
        if connected_providers:
            for p in sorted(connected_providers, key=lambda x: x["name"]):
                suffix = "connection" if p["count"] == 1 else "connections"
                ctx_obj.echo(f"  {p['name']} ({p['count']} {suffix})")


@cli.command()
@common_options
@pass_ctx
@handle_errors
def doctor(ctx_obj: ContextObj) -> None:
    """Run health checks on directory layout and encryption."""
    actx = ctx_obj.initialize()
    results = actx.doctor()

    if ctx_obj.json_output:
        ctx_obj.print_json(results)
    else:
        all_ok = results.get("status") == "ready"
        for key, val in results.get("checks", {}).items():
            ok = val == "ok"
            ctx_obj.echo(f"{key}: ", nl=False)
            ctx_obj.echo("OK" if ok else "FAIL", color="green" if ok else "red")
        issues = results.get("issues", [])
        if issues:
            ctx_obj.echo("\nIssues found:", color="red")
            for issue in issues:
                ctx_obj.echo(f" - {issue}", color="red")

        if not all_ok:
            sys.exit(1)


@cli.group()
def daemon() -> None:
    """Manage the local Authsome daemon."""


@daemon.command(name="serve")
def daemon_serve() -> None:
    """Run the daemon in the foreground."""
    from authsome.server.daemon import serve

    serve()


@daemon.command(name="start")
@common_options
@pass_ctx
@handle_errors
def daemon_start(ctx_obj: ContextObj) -> None:
    """Start the local daemon in the background."""
    start_daemon()
    ctx_obj.echo("Daemon start requested.", color="green")


@daemon.command(name="stop")
@common_options
@pass_ctx
@handle_errors
def daemon_stop(ctx_obj: ContextObj) -> None:
    """Stop the local daemon."""
    stop_daemon()
    ctx_obj.echo("Daemon stopped.", color="green")


@daemon.command(name="restart")
@common_options
@pass_ctx
@handle_errors
def daemon_restart(ctx_obj: ContextObj) -> None:
    """Restart the local daemon."""
    stop_daemon()
    start_daemon()
    ctx_obj.echo("Daemon restart requested.", color="green")


@daemon.command(name="status")
@common_options
@pass_ctx
@handle_errors
def daemon_status_cmd(ctx_obj: ContextObj) -> None:
    """Show daemon status."""
    status = daemon_status()
    if ctx_obj.json_output:
        ctx_obj.print_json(status)
    else:
        ctx_obj.echo(json_lib.dumps(status, indent=2))


@daemon.command(name="logs")
@click.option("-n", "--lines", default=80, help="Number of lines to show.")
@common_options
@pass_ctx
@handle_errors
def daemon_logs(ctx_obj: ContextObj, lines: int) -> None:
    """Show daemon log output."""
    from authsome.cli.daemon_control import LOG_FILE

    if not LOG_FILE.exists():
        ctx_obj.echo(f"No daemon log found at {LOG_FILE}", err=True, color="yellow")
        return
    for line in LOG_FILE.read_text(encoding="utf-8", errors="replace").splitlines()[-lines:]:
        ctx_obj.echo(line)


if __name__ == "__main__":
    cli()
