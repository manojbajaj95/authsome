"""Command-line interface for authsome.

Implements all commands defined in spec §18 using Click.
"""

import functools
import json as json_lib
import logging
import sys
from typing import Any

import click

from authsome import __version__
from authsome.client import AuthClient
from authsome.errors import AuthsomeError
from authsome.models.enums import ExportFormat, FlowType


class ContextObj:
    """Context object passed to all commands."""

    def __init__(self, json_output: bool, quiet: bool, no_color: bool):
        self.json_output = json_output
        self.quiet = quiet
        self.no_color = no_color
        self.client: AuthClient | None = None

    def initialize_client(self) -> AuthClient:
        if self.client is None:
            self.client = AuthClient()
        return self.client

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
    """Decorator to add common global options to both group and subcommands."""

    @click.option(
        "--json",
        "json_output",
        is_flag=True,
        help="Output in machine-readable JSON format.",
    )
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
    """Map exceptions to standard exit codes per spec §18.3."""
    if not isinstance(exc, AuthsomeError):
        return 1

    exc_name = exc.__class__.__name__
    if exc_name == "ProviderNotFoundError":
        return 3
    if exc_name == "AuthenticationFailedError":
        return 4
    if exc_name == "CredentialMissingError":
        return 5
    if exc_name == "RefreshFailedError":
        return 6
    if exc_name == "StoreUnavailableError":
        return 7
    return 1


def handle_errors(func):
    """Decorator to catch exceptions and exit with proper codes."""

    @functools.wraps(func)
    def wrapper(ctx_obj: ContextObj, *args, **kwargs):
        try:
            return func(ctx_obj, *args, **kwargs)
        except Exception as exc:
            if ctx_obj.json_output:
                ctx_obj.print_json(
                    {
                        "error": exc.__class__.__name__,
                        "message": str(exc),
                    }
                )
            else:
                ctx_obj.echo(f"Error: {exc}", err=True, color="red")
            sys.exit(format_error_code(exc))

    return wrapper


@click.group()
@click.version_option(__version__, "-v", "--version")
@common_options
@click.pass_context
def cli(ctx: click.Context) -> None:
    """Authsome: Portable local authentication library for AI agents and tools."""
    logging.getLogger("authsome").setLevel(logging.WARNING if ctx.obj.quiet else logging.INFO)


@cli.command()
@common_options
@pass_ctx
@handle_errors
def init(ctx_obj: ContextObj) -> None:
    """Initialize the authsome root directory and default profile."""
    client = ctx_obj.initialize_client()
    client.init()

    if ctx_obj.json_output:
        ctx_obj.print_json({"status": "initialized", "home": str(client.home)})
    else:
        ctx_obj.echo(f"Initialized authsome at {client.home}", color="green")


@cli.command(name="list")
@common_options
@pass_ctx
@handle_errors
def list_cmd(ctx_obj: ContextObj) -> None:
    """List providers and connection states."""
    client = ctx_obj.initialize_client()
    raw_list = client.list_connections()
    by_source = client.list_providers_by_source()

    # Index connections by provider name
    connected: dict[str, list[dict]] = {}
    for provider_group in raw_list:
        connected[provider_group["name"]] = provider_group["connections"]

    def build_provider_entry(provider, source: str) -> dict:
        conns = connected.get(provider.name, [])
        connections_out = []
        if conns:
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

    bundled_out = [build_provider_entry(p, "bundled") for p in by_source["bundled"]]
    custom_out = [build_provider_entry(p, "custom") for p in by_source["custom"]]

    if ctx_obj.json_output:
        ctx_obj.print_json(
            {
                "bundled": bundled_out,
                "custom": custom_out,
            }
        )
        return

    def print_provider_section(label: str, providers: list[dict]) -> None:
        ctx_obj.echo(f"\n{label}:")
        if not providers:
            ctx_obj.echo("  (none)")
            return
        for p in providers:
            ctx_obj.echo(f"  {p['display_name']}  [{p['name']}]")
            conns = p["connections"]
            if conns:
                for c in conns:
                    status = c["status"]
                    color = "green" if status == "connected" else "yellow"
                    ctx_obj.echo(f"    {c['connection_name']}  ", nl=False)
                    ctx_obj.echo(status, color=color)
            else:
                ctx_obj.echo("    (no connections)", color="yellow")

    print_provider_section("Bundled Providers", bundled_out)
    print_provider_section("Custom Providers", custom_out)


@cli.command()
@click.argument("provider")
@click.option("--connection", default="default", help="Connection name.")
@click.option("--flow", help="Authentication flow override.")
@click.option("--scopes", help="Comma-separated scopes to request.")
@click.option(
    "--force",
    is_flag=True,
    help="Overwrite an existing connection if it already exists.",
)
@common_options
@pass_ctx
@handle_errors
def login(
    ctx_obj: ContextObj,
    provider: str,
    connection: str,
    flow: str | None,
    scopes: str | None,
    force: bool,
) -> None:
    """Authenticate with a provider using its configured flow."""
    client = ctx_obj.initialize_client()
    flow_enum = FlowType(flow) if flow else None
    scope_list = [s.strip() for s in scopes.split(",")] if scopes else None

    if force and not ctx_obj.quiet:
        ctx_obj.echo(
            "Warning: Forcing login will overwrite any existing connection.",
            color="yellow",
        )

    if not ctx_obj.json_output:
        ctx_obj.echo(f"Starting login for {provider}...", color="cyan")

    record = client.login(
        provider=provider,
        connection_name=connection,
        scopes=scope_list,
        flow_override=flow_enum,
        force=force,
    )

    if ctx_obj.json_output:
        ctx_obj.print_json(
            {
                "status": "success",
                "provider": provider,
                "connection": connection,
                "record_status": record.status.value,
            }
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
    client = ctx_obj.initialize_client()
    client.logout(provider, connection)

    if ctx_obj.json_output:
        ctx_obj.print_json({"status": "logged_out", "provider": provider, "connection": connection})
    else:
        ctx_obj.echo(f"Logged out of {provider} ({connection}).", color="green")


@cli.command()
@click.argument("provider")
@common_options
@pass_ctx
@handle_errors
def revoke(ctx_obj: ContextObj, provider: str) -> None:
    """Complete reset of the provider, removing all connections and client secrets."""
    client = ctx_obj.initialize_client()
    client.revoke(provider)

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
    """Uninstall a local provider or reset a bundled one."""
    client = ctx_obj.initialize_client()
    client.remove(provider)

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
def get(
    ctx_obj: ContextObj,
    provider: str,
    connection: str,
    field: str | None,
    show_secret: bool,
) -> None:
    """Return provider connection metadata by default."""
    client = ctx_obj.initialize_client()
    record = client.get_connection(provider, connection)

    data = record.model_dump(mode="json")

    # Redact secrets unless requested
    if not show_secret:
        for secret_field in [
            "access_token",
            "refresh_token",
            "api_key",
            "client_secret",
        ]:
            if data.get(secret_field):
                data[secret_field] = "***REDACTED***"
    else:
        for secret_field in [
            "access_token",
            "refresh_token",
            "api_key",
            "client_secret",
        ]:
            val = getattr(record, secret_field, None)
            if val:
                data[secret_field] = client.crypto.decrypt(val)

    if field:
        if field in data:
            if ctx_obj.json_output:
                ctx_obj.print_json({field: data[field]})
            else:
                ctx_obj.echo(str(data[field]))
        else:
            ctx_obj.echo(f"Field '{field}' not found.", err=True, color="red")
            sys.exit(1)
        return

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
    client = ctx_obj.initialize_client()
    definition = client.get_provider(provider)

    data = definition.model_dump(mode="json")
    if ctx_obj.json_output:
        ctx_obj.print_json(data)
    else:
        ctx_obj.echo(json_lib.dumps(data, indent=2))


@cli.command()
@click.argument("provider")
@click.option("--connection", default="default", help="Connection name.")
@click.option(
    "--format",
    "export_format",
    type=click.Choice(["env", "shell", "json"]),
    default="env",
)
@common_options
@pass_ctx
@handle_errors
def export(ctx_obj: ContextObj, provider: str, connection: str, export_format: str) -> None:
    """Export credential material in selected format."""
    client = ctx_obj.initialize_client()
    fmt = ExportFormat(export_format)
    output = client.export(provider, connection, format=fmt)

    # Do not apply color or structured wrapping here, just output exactly what is requested
    if output:
        click.echo(output)


@cli.command(context_settings=dict(ignore_unknown_options=True))
@click.argument("command", nargs=-1, required=True)
@common_options
@pass_ctx
@handle_errors
def run(ctx_obj: ContextObj, command: tuple[str]) -> None:
    """Run a subprocess behind the local auth proxy.

    The proxy injects provider auth headers into matched HTTP(S)
    requests without exporting secrets into the child environment.
    """
    from authsome.proxy.runner import ProxyRunner

    client = ctx_obj.initialize_client()
    runner = ProxyRunner(client)
    result = runner.run(list(command))
    sys.exit(result.returncode)


@cli.command()
@click.argument("path")
@click.option("--force", is_flag=True, help="Force overwrite if provider exists.")
@common_options
@pass_ctx
@handle_errors
def register(ctx_obj: ContextObj, path: str, force: bool) -> None:
    """Register a provider definition from a local JSON file path."""
    import pathlib

    client = ctx_obj.initialize_client()

    filepath = pathlib.Path(path)
    if not filepath.exists():
        ctx_obj.echo(f"File not found: {path}", err=True, color="red")
        sys.exit(1)

    try:
        data = json_lib.loads(filepath.read_text(encoding="utf-8"))
        from authsome.models.provider import ProviderDefinition

        definition = ProviderDefinition.model_validate(data)
        client.register_provider(definition, force=force)

        if ctx_obj.json_output:
            ctx_obj.print_json({"status": "registered", "provider": definition.name})
        else:
            ctx_obj.echo(f"Provider {definition.name} registered.", color="green")
    except Exception as exc:
        ctx_obj.echo(f"Failed to register provider: {exc}", err=True, color="red")
        sys.exit(1)


@cli.command()
@common_options
@pass_ctx
@handle_errors
def whoami(ctx_obj: ContextObj) -> None:
    """Show basic local context."""
    client = ctx_obj.initialize_client()
    data = {
        "home_directory": str(client.home),
        "encryption_mode": (client.config.encryption.mode if client.config.encryption else "local_key"),
    }

    if ctx_obj.json_output:
        ctx_obj.print_json(data)
    else:
        ctx_obj.echo(f"Home Directory: {data['home_directory']}")
        ctx_obj.echo(f"Encryption Mode: {data['encryption_mode']}")


@cli.command()
@common_options
@pass_ctx
@handle_errors
def doctor(ctx_obj: ContextObj) -> None:
    """Run health checks on directory layout and encryption."""
    client = ctx_obj.initialize_client()
    results = client.doctor()

    if ctx_obj.json_output:
        ctx_obj.print_json(results)
    else:
        all_ok = True
        for key, val in results.items():
            if key in ["issues", "providers_count"]:
                continue
            status = "OK" if val else "FAIL"
            color = "green" if val else "red"
            if not val:
                all_ok = False
            ctx_obj.echo(f"{key}: ", nl=False)
            ctx_obj.echo(status, color=color)

        ctx_obj.echo(f"Providers Configured: {results.get('providers_count', 0)}")

        issues = results.get("issues", [])
        if issues:
            ctx_obj.echo("\nIssues found:", color="red")
            for issue in issues:
                ctx_obj.echo(f" - {issue}", color="red")

        if not all_ok:
            sys.exit(1)


if __name__ == "__main__":
    cli()
