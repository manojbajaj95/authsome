"""Command-line interface for authsome."""

import functools
import json as json_lib
import sys
from pathlib import Path
from typing import Any

import click
from loguru import logger

from authsome import __version__, audit
from authsome.auth.models.enums import ExportFormat, FlowType
from authsome.context import AuthsomeContext
from authsome.errors import AuthsomeError
from authsome.utils import redact


class ContextObj:
    """Context object passed to all commands."""

    def __init__(self, json_output: bool, quiet: bool, no_color: bool):
        self.json_output = json_output
        self.quiet = quiet
        self.no_color = no_color
        self._ctx: AuthsomeContext | None = None

    def initialize(self) -> AuthsomeContext:
        if self._ctx is None:
            self._ctx = AuthsomeContext.create()
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
    raw_list = actx.auth.list_connections()
    by_source = actx.auth.list_providers_by_source()

    connected: dict[str, list[dict]] = {}
    for provider_group in raw_list:
        connected[provider_group["name"]] = provider_group["connections"]

    def build_provider_entry(provider, source: str) -> dict:
        conns = connected.get(provider.name, [])
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

    bundled_out = [build_provider_entry(p, "bundled") for p in by_source["bundled"]]
    custom_out = [build_provider_entry(p, "custom") for p in by_source["custom"]]

    if ctx_obj.json_output:
        ctx_obj.print_json({"bundled": bundled_out, "custom": custom_out})
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
    flow_enum = FlowType(flow) if flow else None
    scope_list = [s.strip() for s in scopes.split(",")] if scopes else None

    if force and not ctx_obj.quiet:
        ctx_obj.echo("Warning: Forcing login will overwrite any existing connection.", color="yellow")
    if not ctx_obj.json_output:
        ctx_obj.echo(f"Starting login for {provider}...", color="cyan")

    try:
        record = actx.auth.login(
            provider=provider,
            connection_name=connection,
            scopes=scope_list,
            flow_override=flow_enum,
            force=force,
            base_url=base_url,
        )
        audit.log("login", provider=provider, connection=connection, flow=record.auth_type.value, status="success")
    except Exception:
        audit.log("login", provider=provider, connection=connection, status="failure")
        raise

    if ctx_obj.json_output:
        ctx_obj.print_json(
            {"status": "success", "provider": provider, "connection": connection, "record_status": record.status.value}
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
    actx.auth.logout(provider, connection)
    audit.log("logout", provider=provider, connection=connection)

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
    actx = ctx_obj.initialize()
    actx.auth.revoke(provider)
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
    """Uninstall a local provider or reset a bundled one."""
    actx = ctx_obj.initialize()
    actx.auth.remove(provider)
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
    record = actx.auth.get_connection(provider, connection)

    if show_secret:
        audit.log("get", provider=provider, connection=connection, field=field or "all")

    data = redact(record) if not show_secret else record.model_dump(mode="json")

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
    actx = ctx_obj.initialize()
    definition = actx.auth.get_provider(provider)
    data = definition.model_dump(mode="json")
    if ctx_obj.json_output:
        ctx_obj.print_json(data)
    else:
        ctx_obj.echo(json_lib.dumps(data, indent=2))


@cli.command()
@click.argument("provider", required=False)
@click.option("--connection", default="default", help="Connection name.")
@click.option("--format", "export_format", type=click.Choice(["env", "json"]), default="env")
@common_options
@pass_ctx
@handle_errors
def export(ctx_obj: ContextObj, provider: str | None, connection: str, export_format: str) -> None:
    """Export credential material in selected format."""
    actx = ctx_obj.initialize()
    fmt = ExportFormat(export_format)
    output = actx.auth.export(provider, connection, format=fmt)
    audit.log("export", provider=provider, connection=connection, format=export_format)
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
    result = actx.proxy.run(list(command))
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

    actx = ctx_obj.initialize()
    filepath = pathlib.Path(path)
    if not filepath.exists():
        ctx_obj.echo(f"File not found: {path}", err=True, color="red")
        sys.exit(1)

    try:
        data = json_lib.loads(filepath.read_text(encoding="utf-8"))
        from authsome.auth.models.provider import ProviderDefinition

        definition = ProviderDefinition.model_validate(data)
        actx.auth.register_provider(definition, force=force)

        endpoints = [
            ep
            for ep in [
                definition.oauth.authorization_url if definition.oauth else None,
                definition.oauth.token_url if definition.oauth else None,
                definition.oauth.revocation_url if definition.oauth else None,
                definition.host_url,
            ]
            if ep
        ]
        audit.log("register", provider=definition.name, endpoints=endpoints)

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
    actx = ctx_obj.initialize()
    from authsome.auth.models.config import GlobalConfig

    home = actx.home
    config_path = home / "config.json"
    config = GlobalConfig()
    if config_path.exists():
        try:
            config = GlobalConfig.model_validate_json(config_path.read_text(encoding="utf-8"))
        except Exception:
            pass

    data = {
        "home_directory": str(home),
        "encryption_mode": config.encryption.mode if config.encryption else "local_key",
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
    actx = ctx_obj.initialize()
    results = actx.doctor()

    if ctx_obj.json_output:
        ctx_obj.print_json(results)
    else:
        all_ok = True
        for key, val in results.items():
            if key in ["issues", "providers_count", "profiles_count"]:
                continue
            status = "OK" if val else "FAIL"
            color = "green" if val else "red"
            if isinstance(val, bool) and not val:
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
