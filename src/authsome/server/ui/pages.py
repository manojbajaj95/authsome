"""HTML page generators for the Authsome server."""

from __future__ import annotations

import html
from typing import Any

from authsome.server.ui.web_theme import DARK_THEME_CSS, DEVICE_BRIDGE_STYLE


def message_page(title: str, message: str) -> str:
    """Generate a simple message page."""
    return f"""<!doctype html>
<html>
  <head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <title>{html.escape(title)}</title>
    <style>{DARK_THEME_CSS}</style>
  </head>
  <body>
    <main>
      <h1>{html.escape(title)}</h1>
      <p>{html.escape(message)}</p>
    </main>
  </body>
</html>"""


def input_page(session_id: str, display_name: str, docs_url: str | None, fields: list[dict[str, Any]]) -> str:
    """Generate a dynamic input form for provider credentials."""
    required_rows = []
    optional_rows = []
    for field in fields:
        row = _field_row(field)
        if field.get("default") is None:
            required_rows.append(row)
        else:
            optional_rows.append(row)

    docs = (
        f'<p><a href="{html.escape(docs_url)}" target="_blank" rel="noreferrer">Provider documentation</a></p>'
        if docs_url
        else ""
    )

    optional = ""
    if optional_rows:
        optional = f"<details><summary>Advanced options</summary>{''.join(optional_rows)}</details>"

    return f"""<!doctype html>
<html>
  <head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <title>Authsome - {html.escape(display_name)}</title>
    <style>{DARK_THEME_CSS}</style>
  </head>
  <body>
    <main>
      <h1>{html.escape(display_name)}</h1>
      {docs}
      <form method="post" action="/auth/sessions/{html.escape(session_id)}/input">
        {"".join(required_rows)}
        {optional}
        <button type="submit">Continue</button>
      </form>
    </main>
  </body>
</html>"""


def _field_row(field: dict[str, Any]) -> str:
    name = html.escape(str(field["name"]))
    label = html.escape(str(field["label"]))
    input_type = "password" if field.get("secret", True) else "text"
    value = html.escape(str(field.get("default") or ""))
    required = " required" if field.get("default") is None else ""
    pattern = f' pattern="{html.escape(str(field["pattern"]))}"' if field.get("pattern") else ""
    hint = f"<small>{html.escape(str(field['pattern_hint']))}</small>" if field.get("pattern_hint") else ""
    return (
        f'<div class="field-group">'
        f'<label for="{name}">{label}</label>'
        f'<input id="{name}" type="{input_type}" name="{name}" value="{value}"{required}{pattern}>'
        f"{hint}</div>"
    )


def device_code_page(
    display_name: str,
    user_code: str,
    verification_uri: str,
    verification_uri_complete: str | None,
) -> str:
    """Generate a device code verification page with a premium theme."""
    link = verification_uri_complete or verification_uri
    return f"""<!doctype html>
<html>
  <head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <title>Authsome - Device Login</title>
    {DEVICE_BRIDGE_STYLE}
  </head>
  <body>
    <div class="brand">Authsome</div>
    <h2>{html.escape(display_name)}</h2>
    <p class="subtitle">Enter the following code on your device to complete the login.</p>
    
    <div class="code-wrap">
      <input type="text" id="user-code" value="{html.escape(user_code)}" readonly>
      <button class="copybtn" onclick="copyCode()">Copy</button>
    </div>
    
    <a href="{html.escape(link)}" target="_blank" class="verify">Open Login Page</a>
    
    <p class="note">
      After completing the login on your device, return to your terminal.
    </p>

    <script>
      function copyCode() {{
        var copyText = document.getElementById("user-code");
        copyText.select();
        copyText.setSelectionRange(0, 99999);
        navigator.clipboard.writeText(copyText.value);
        
        const btn = document.querySelector('.copybtn');
        const originalText = btn.innerText;
        btn.innerText = 'Copied!';
        setTimeout(() => {{
          btn.innerText = originalText;
        }}, 2000);
      }}
    </script>
  </body>
</html>"""
