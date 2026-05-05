"""HTML rendering helpers for the operator console and session pages.

Milestone 1 ships a practical local operator console — not a full admin
product, but enough to provide useful diagnostics, flow progress, and
connection views.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from authsome.runtime.models import RuntimeSession
    from authsome.runtime.service import AuthRuntimeService


_CSS = """
<style>
    * { margin: 0; padding: 0; box-sizing: border-box; }
    body {
        font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
        background: #0d1117; color: #c9d1d9; line-height: 1.6; padding: 2rem;
    }
    h1 { color: #58a6ff; margin-bottom: 1rem; }
    h2 { color: #8b949e; margin-bottom: 0.5rem; font-size: 1.1rem; }
    .card {
        background: #161b22; border: 1px solid #30363d; border-radius: 8px;
        padding: 1.25rem; margin-bottom: 1rem;
    }
    .badge {
        display: inline-block; padding: 2px 8px; border-radius: 12px;
        font-size: 0.8rem; font-weight: 600;
    }
    .badge-pending { background: #1f2937; color: #9ca3af; }
    .badge-waiting { background: #854d0e; color: #fbbf24; }
    .badge-processing { background: #1e3a5f; color: #60a5fa; }
    .badge-completed { background: #14532d; color: #4ade80; }
    .badge-failed { background: #7f1d1d; color: #f87171; }
    .badge-expired { background: #78350f; color: #fb923c; }
    .badge-cancelled { background: #374151; color: #9ca3af; }
    .badge-connected { background: #14532d; color: #4ade80; }
    .badge-not_connected { background: #1f2937; color: #9ca3af; }
    table { width: 100%; border-collapse: collapse; margin-top: 0.5rem; }
    th, td { text-align: left; padding: 0.5rem 0.75rem; border-bottom: 1px solid #21262d; }
    th { color: #8b949e; font-weight: 600; font-size: 0.85rem; }
    a { color: #58a6ff; text-decoration: none; }
    a:hover { text-decoration: underline; }
    .mono { font-family: 'SFMono-Regular', Consolas, monospace; font-size: 0.9rem; }
    .nav { margin-bottom: 1.5rem; }
    .nav a { margin-right: 1rem; }
    .kv { display: grid; grid-template-columns: 160px 1fr; gap: 0.25rem; }
    .kv dt { color: #8b949e; }
    .kv dd { color: #c9d1d9; }
</style>
"""

_NAV = """
<nav class="nav">
    <a href="/ui/">Dashboard</a>
    <a href="/ui/connections">Connections</a>
</nav>
"""


def _state_badge(state: str) -> str:
    badge_map = {
        "pending": "badge-pending",
        "waiting_for_user": "badge-waiting",
        "processing": "badge-processing",
        "completed": "badge-completed",
        "failed": "badge-failed",
        "expired": "badge-expired",
        "cancelled": "badge-cancelled",
        "connected": "badge-connected",
        "not_connected": "badge-not_connected",
    }
    css_class = badge_map.get(state, "badge-pending")
    return f'<span class="badge {css_class}">{state}</span>'


def render_dashboard_page(service: AuthRuntimeService) -> str:
    """Render the main operator console dashboard."""
    sessions = service.list_sessions()
    connections_data = service.list_connections()
    connections = connections_data.get("connections", [])

    session_rows = ""
    for s in sessions:
        session_rows += f"""
        <tr>
            <td class="mono"><a href="/ui/sessions/{s.session_id}">{s.session_id}</a></td>
            <td>{s.provider}</td>
            <td>{s.flow_type}</td>
            <td>{_state_badge(s.state)}</td>
            <td class="mono">{s.created_at.isoformat()[:19] if s.created_at else "-"}</td>
        </tr>"""

    connected_count = sum(1 for pg in connections for c in pg.get("connections", []) if c.get("status") == "connected")

    return f"""<!DOCTYPE html>
<html lang="en">
<head><meta charset="utf-8"><title>Authsome — Operator Console</title>{_CSS}</head>
<body>
{_NAV}
<h1>Authsome — Operator Console</h1>

<div class="card">
    <h2>Overview</h2>
    <dl class="kv">
        <dt>Profile</dt><dd>{service.auth.identity}</dd>
        <dt>Active Sessions</dt><dd>{len(sessions)}</dd>
        <dt>Connected Providers</dt><dd>{connected_count}</dd>
    </dl>
</div>

<div class="card">
    <h2>Active Sessions</h2>
    {
        f'''<table>
        <thead><tr><th>Session ID</th><th>Provider</th><th>Flow</th><th>State</th><th>Created</th></tr></thead>
        <tbody>{session_rows}</tbody>
    </table>'''
        if sessions
        else '<p style="color:#8b949e; margin-top:0.5rem;">No active sessions.</p>'
    }
</div>
</body></html>"""


def render_session_page(session: RuntimeSession) -> str:
    """Render a session detail page."""
    payload_rows = ""
    for k, v in session.payload.items():
        payload_rows += f"<tr><td class='mono'>{k}</td><td class='mono'>{v}</td></tr>"

    return f"""<!DOCTYPE html>
<html lang="en">
<head><meta charset="utf-8"><title>Session {session.session_id}</title>{_CSS}</head>
<body>
{_NAV}
<h1>Session Detail</h1>

<div class="card">
    <dl class="kv">
        <dt>Session ID</dt><dd class="mono">{session.session_id}</dd>
        <dt>Provider</dt><dd>{session.provider}</dd>
        <dt>Profile</dt><dd>{session.profile}</dd>
        <dt>Connection</dt><dd>{session.connection_name}</dd>
        <dt>Flow Type</dt><dd>{session.flow_type}</dd>
        <dt>State</dt><dd>{_state_badge(session.state)}</dd>
        <dt>Created</dt><dd class="mono">{session.created_at.isoformat()[:19] if session.created_at else "-"}</dd>
        <dt>Updated</dt><dd class="mono">{session.updated_at.isoformat()[:19] if session.updated_at else "-"}</dd>
    </dl>
</div>

{
        f'''<div class="card">
    <h2>Status</h2>
    <p>{session.status_message}</p>
</div>'''
        if session.status_message
        else ""
    }

{
        f'''<div class="card">
    <h2>Error</h2>
    <p style="color:#f87171;">{session.error_message}</p>
</div>'''
        if session.error_message
        else ""
    }

{
        f'''<div class="card">
    <h2>Flow Payload</h2>
    <table>
        <thead><tr><th>Key</th><th>Value</th></tr></thead>
        <tbody>{payload_rows}</tbody>
    </table>
</div>'''
        if session.payload
        else ""
    }

</body></html>"""


def render_connections_page(service: AuthRuntimeService) -> str:
    """Render the connections view page."""
    connections_data = service.list_connections()
    connections = connections_data.get("connections", [])

    rows = ""
    for pg in connections:
        provider_name = pg["name"]
        for conn in pg.get("connections", []):
            rows += f"""
            <tr>
                <td>{provider_name}</td>
                <td>{conn.get("connection_name", "default")}</td>
                <td>{conn.get("auth_type", "-")}</td>
                <td>{_state_badge(conn.get("status", "not_connected"))}</td>
                <td class="mono">{conn.get("expires_at", "-") or "-"}</td>
            </tr>"""

    return f"""<!DOCTYPE html>
<html lang="en">
<head><meta charset="utf-8"><title>Authsome — Connections</title>{_CSS}</head>
<body>
{_NAV}
<h1>Connections</h1>

<div class="card">
    <table>
        <thead><tr><th>Provider</th><th>Connection</th><th>Auth Type</th><th>Status</th><th>Expires</th></tr></thead>
        <tbody>{rows if rows else '<tr><td colspan="5" style="color:#8b949e;">No connections.</td></tr>'}</tbody>
    </table>
</div>
</body></html>"""
