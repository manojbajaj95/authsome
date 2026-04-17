"""Command-line interface for authsome.

Implements all commands defined in spec §18 using Click.
"""

import functools
import json as json_lib
import logging
import sys
from typing import Any

import click

from authsome.client import AuthClient
from authsome.errors import AuthsomeError
from authsome.models.enums import ExportFormat, FlowType


class ContextObj:
    """Context object passed to all commands."""

    def __init__(self, profile: str | None, json_output: bool, quiet: bool, no_color: bool):
        self.profile = profile
        self.json_output = json_output
        self.quiet = quiet
        self.no_color = no_color
        self.client: AuthClient | None = None

    def initialize_client(self) -> AuthClient:
        if self.client is None:
            self.client = AuthClient(profile=self.profile)
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
@click.option("--profile", help="Override the active profile.")
@click.option("--json", "json_output", is_flag=True, help="Output in machine-readable JSON format.")
@click.option("--quiet", is_flag=True, help="Suppress non-essential output.")
@click.option("--no-color", is_flag=True, help="Disable ANSI colors.")
@click.pass_context
def cli(ctx: click.Context, profile: str | None, json_output: bool, quiet: bool, no_color: bool) -> None:
    """Authsome: Portable local authentication library for AI agents and tools."""
    logging.getLogger("authsome").setLevel(logging.WARNING if quiet else logging.INFO)
    ctx.obj = ContextObj(profile, json_output, quiet, no_color)


@cli.command()
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
                "profile": client.active_profile,
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

    ctx_obj.echo(f"Profile: {client.active_profile}")
    print_provider_section("Bundled Providers", bundled_out)
    print_provider_section("Custom Providers", custom_out)


@cli.command()
@click.argument("provider")
@click.option("--connection", default="default", help="Connection name.")
@click.option("--flow", help="Authentication flow override.")
@click.option("--scopes", help="Comma-separated scopes to request.")
@pass_ctx
@handle_errors
def login(ctx_obj: ContextObj, provider: str, connection: str, flow: str | None, scopes: str | None) -> None:
    """Authenticate with a provider using its configured flow."""
    client = ctx_obj.initialize_client()
    flow_enum = FlowType(flow) if flow else None
    scope_list = [s.strip() for s in scopes.split(",")] if scopes else None

    if not ctx_obj.json_output:
        ctx_obj.echo(f"Starting login for {provider}...", color="cyan")

    record = client.login(
        provider=provider,
        connection_name=connection,
        scopes=scope_list,
        flow_override=flow_enum,
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
@pass_ctx
@handle_errors
def revoke(ctx_obj: ContextObj, provider: str, connection: str) -> None:
    """Revoke credentials remotely (if supported) and remove locally."""
    client = ctx_obj.initialize_client()
    client.revoke(provider, connection)

    if ctx_obj.json_output:
        ctx_obj.print_json({"status": "revoked", "provider": provider, "connection": connection})
    else:
        ctx_obj.echo(f"Revoked credentials for {provider} ({connection}).", color="green")


@cli.command()
@click.argument("provider")
@click.option("--connection", default="default", help="Connection name.")
@pass_ctx
@handle_errors
def remove(ctx_obj: ContextObj, provider: str, connection: str) -> None:
    """Remove local credential state without remote revocation."""
    client = ctx_obj.initialize_client()
    client.remove(provider, connection)

    if ctx_obj.json_output:
        ctx_obj.print_json({"status": "removed", "provider": provider, "connection": connection})
    else:
        ctx_obj.echo(f"Removed local credentials for {provider} ({connection}).", color="green")


@cli.command()
@click.argument("provider")
@click.option("--connection", default="default", help="Connection name.")
@click.option("--field", help="Return only a specific field.")
@click.option("--show-secret", is_flag=True, help="Reveal encrypted secrets.")
@pass_ctx
@handle_errors
def get(ctx_obj: ContextObj, provider: str, connection: str, field: str | None, show_secret: bool) -> None:
    """Return provider connection metadata by default."""
    client = ctx_obj.initialize_client()
    record = client.get_connection(provider, connection)

    data = record.model_dump()

    # Redact secrets unless requested
    if not show_secret:
        for secret_field in ["access_token", "refresh_token", "api_key", "client_secret"]:
            if data.get(secret_field):
                data[secret_field] = "***REDACTED***"
    else:
        for secret_field in ["access_token", "refresh_token", "api_key", "client_secret"]:
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
@pass_ctx
@handle_errors
def inspect(ctx_obj: ContextObj, provider: str) -> None:
    """Return provider definition and local connection summary."""
    client = ctx_obj.initialize_client()
    definition = client.get_provider(provider)

    data = definition.model_dump()
    if ctx_obj.json_output:
        ctx_obj.print_json(data)
    else:
        ctx_obj.echo(json_lib.dumps(data, indent=2))


@cli.command()
@click.argument("provider")
@click.option("--connection", default="default", help="Connection name.")
@click.option("--format", "export_format", type=click.Choice(["env", "shell", "json"]), default="env")
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
@click.option("--provider", "-p", multiple=True, help="Provider(s) to inject credentials for.")
@click.argument("command", nargs=-1, required=True)
@pass_ctx
@handle_errors
def run(ctx_obj: ContextObj, provider: list[str], command: tuple[str]) -> None:
    """Run a subprocess with injected exported credentials."""
    client = ctx_obj.initialize_client()
    # spec states "Repeated flags for provider", so `provider` is a tuple of strings due to multiple=True
    result = client.run(list(command), providers=list(provider))
    sys.exit(result.returncode)


@cli.command()
@click.argument("path")
@click.option("--force", is_flag=True, help="Force overwrite if provider exists.")
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
@pass_ctx
@handle_errors
def whoami(ctx_obj: ContextObj) -> None:
    """Show the active profile and basic local context."""
    client = ctx_obj.initialize_client()
    data = {
        "active_profile": client.active_profile,
        "home_directory": str(client.home),
        "encryption_mode": client.config.encryption.mode if client.config.encryption else "local_key",
    }

    if ctx_obj.json_output:
        ctx_obj.print_json(data)
    else:
        ctx_obj.echo(f"Active Profile: {data['active_profile']}")
        ctx_obj.echo(f"Home Directory: {data['home_directory']}")
        ctx_obj.echo(f"Encryption Mode: {data['encryption_mode']}")


@cli.command()
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
            if key in ["issues", "providers_count", "profiles_count"]:
                continue
            status = "OK" if val else "FAIL"
            color = "green" if val else "red"
            if not val:
                all_ok = False
            ctx_obj.echo(f"{key}: ", nl=False)
            ctx_obj.echo(status, color=color)

        ctx_obj.echo(f"Providers Configured: {results.get('providers_count', 0)}")
        ctx_obj.echo(f"Profiles: {results.get('profiles_count', 0)}")

        issues = results.get("issues", [])
        if issues:
            ctx_obj.echo("\nIssues found:", color="red")
            for issue in issues:
                ctx_obj.echo(f" - {issue}", color="red")

        if not all_ok:
            sys.exit(1)


@cli.group(name="profile")
def profile_group() -> None:
    """Manage local profiles."""
    pass


@profile_group.command(name="list")
@pass_ctx
@handle_errors
def profile_list(ctx_obj: ContextObj) -> None:
    """List local profiles."""
    client = ctx_obj.initialize_client()
    profiles = client.list_profiles()
    active = client.active_profile

    if ctx_obj.json_output:
        ctx_obj.print_json({"active": active, "profiles": [p.model_dump(mode="json") for p in profiles]})
    else:
        ctx_obj.echo("Profiles:")
        for p in profiles:
            mark = "*" if p.name == active else " "
            ctx_obj.echo(f" {mark} {p.name} ({p.description or 'No description'})")


@profile_group.command(name="create")
@click.argument("name")
@pass_ctx
@handle_errors
def profile_create(ctx_obj: ContextObj, name: str) -> None:
    """Create a profile."""
    client = ctx_obj.initialize_client()
    metadata = client.create_profile(name)

    if ctx_obj.json_output:
        ctx_obj.print_json({"status": "created", "profile": metadata.model_dump(mode="json")})
    else:
        ctx_obj.echo(f"Profile '{name}' created.", color="green")


@profile_group.command(name="use")
@click.argument("name")
@pass_ctx
@handle_errors
def profile_use(ctx_obj: ContextObj, name: str) -> None:
    """Set the global default profile."""
    client = ctx_obj.initialize_client()
    client.set_default_profile(name)

    if ctx_obj.json_output:
        ctx_obj.print_json({"status": "default_changed", "profile": name})
    else:
        ctx_obj.echo(f"Default profile set to '{name}'.", color="green")


if __name__ == "__main__":
    cli()
