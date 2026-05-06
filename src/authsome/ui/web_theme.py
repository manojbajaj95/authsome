"""Web UI themes and styles for Authsome local server."""

from __future__ import annotations

DARK_THEME_CSS = """
:root {
  color-scheme: dark;
  --bg: #000000;
  --panel: #0a0a0a;
  --text: #ededed;
  --muted: #a1a1aa;
  --line: #27272a;
  --focus: #ededed;
  --primary: #ededed;
  --primary-text: #000000;
}
* { box-sizing: border-box; }
body {
  margin: 0;
  min-height: 100vh;
  background: var(--bg);
  color: var(--text);
  font-family: ui-sans-serif, system-ui, -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif;
  -webkit-font-smoothing: antialiased;
  display: flex;
  align-items: center;
  justify-content: center;
  padding: 20px;
}
main {
  width: 100%;
  max-width: 360px;
  background: var(--panel);
  border: 1px solid var(--line);
  border-radius: 8px;
  padding: 32px;
}
h1 {
  margin: 0 0 4px;
  font-size: 20px;
  font-weight: 500;
  letter-spacing: -0.02em;
}
p {
  margin: 0 0 24px;
  color: var(--muted);
  font-size: 14px;
}
a {
  color: var(--text);
  text-decoration: underline;
  text-underline-offset: 4px;
}
a:hover { color: var(--muted); }
.field-group { margin-bottom: 16px; }
label {
  display: block;
  font-size: 13px;
  font-weight: 500;
  margin-bottom: 6px;
  color: var(--text);
}
input {
  width: 100%;
  background: var(--bg);
  border: 1px solid var(--line);
  border-radius: 6px;
  color: var(--text);
  font-family: inherit;
  font-size: 14px;
  padding: 10px 12px;
  transition: border-color 0.15s;
}
input:focus {
  outline: none;
  border-color: var(--focus);
}
small {
  display: block;
  margin-top: 6px;
  color: var(--muted);
  font-size: 12px;
}
button {
  width: 100%;
  background: var(--primary);
  color: var(--primary-text);
  border: none;
  border-radius: 6px;
  padding: 10px 12px;
  font-size: 14px;
  font-weight: 500;
  cursor: pointer;
  margin-top: 12px;
  transition: opacity 0.15s;
}
button:hover { opacity: 0.9; }
details {
  margin: 24px 0;
  padding: 12px;
  background: var(--bg);
  border: 1px solid var(--line);
  border-radius: 6px;
}
summary {
  font-size: 13px;
  font-weight: 500;
  color: var(--text);
  cursor: pointer;
  user-select: none;
}
details[open] summary { margin-bottom: 12px; }
"""

BRIDGE_STYLE = """
<style>
:root {
  color-scheme: dark;
  --bg: #000000;
  --panel: #0a0a0a;
  --text: #ededed;
  --muted: #a1a1aa;
  --line: #27272a;
  --focus: #ededed;
  --danger: #ef4444;
  --danger-bg: #450a0a;
  --success-bg: #064e3b;
  --cancel-bg: #1e293b;
  --primary: #ededed;
  --primary-text: #000000;
}
* { box-sizing: border-box; }
body {
  margin: 0;
  min-height: 100vh;
  background: var(--bg);
  color: var(--text);
  font-family: ui-sans-serif, system-ui, -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif;
  line-height: 1.45;
  -webkit-font-smoothing: antialiased;
}
.page {
  width: min(100% - 32px, 420px);
  margin: 0 auto;
  padding: 48px 0;
}
.brand {
  margin-bottom: 14px;
  color: var(--muted);
  font-size: 13px;
  font-weight: 500;
  letter-spacing: 0.04em;
  text-transform: uppercase;
}
.panel {
  background: var(--panel);
  border: 1px solid var(--line);
  border-radius: 8px;
  padding: 32px;
}
h1 {
  margin: 0 0 4px;
  font-size: 20px;
  font-weight: 500;
  letter-spacing: -0.02em;
}
.subtitle {
  margin: 0 0 24px;
  color: var(--muted);
  font-size: 14px;
}
form { margin: 0; }
.field { margin-bottom: 16px; }
.label-row {
  display: flex;
  align-items: center;
  justify-content: space-between;
  gap: 12px;
  margin-bottom: 6px;
}
label {
  display: block;
  font-size: 13px;
  font-weight: 500;
  color: var(--text);
}
.optional-chip {
  color: var(--muted);
  font-size: 12px;
}
input {
  width: 100%;
  min-height: 38px;
  background: var(--bg);
  border: 1px solid var(--line);
  border-radius: 6px;
  color: var(--text);
  font-family: inherit;
  font-size: 14px;
  padding: 8px 12px;
  transition: border-color 0.15s;
}
input:focus {
  border-color: var(--focus);
  outline: none;
}
input.has-error {
  border-color: var(--danger);
  background: var(--danger-bg);
}
.field-error {
  color: var(--danger);
  font-size: 13px;
  margin-top: 6px;
}
.form-error {
  background: var(--danger-bg);
  border: 1px solid #7f1d1d;
  border-radius: 6px;
  color: #fca5a5;
  font-size: 14px;
  margin-bottom: 16px;
  padding: 10px 12px;
}
.secret-wrap,
.static-wrap {
  display: flex;
  gap: 8px;
  align-items: stretch;
}
.secret-wrap input,
.static-wrap input[readonly] {
  flex: 1;
  min-width: 0;
}
.static-wrap input[readonly] {
  background: #111111;
  color: var(--muted);
  cursor: default;
}
button,
.button {
  min-height: 38px;
  border: none;
  border-radius: 6px;
  cursor: pointer;
  font-family: inherit;
  font-size: 14px;
  font-weight: 500;
  padding: 8px 12px;
  transition: opacity 0.15s;
}
.primary-button {
  width: 100%;
  background: var(--primary);
  color: var(--primary-text);
  margin-top: 12px;
}
.primary-button:hover { opacity: 0.9; }
.secondary-button {
  background: #111111;
  border: 1px solid var(--line);
  color: var(--text);
  flex: none;
}
.secondary-button:hover { background: #222222; }
.actions {
  display: grid;
  gap: 10px;
  margin-top: 24px;
}
.cancel-button {
  width: 100%;
  background: transparent;
  color: var(--muted);
}
.cancel-button:hover {
  color: var(--text);
}
.instructions {
  background: #111111;
  border: 1px solid var(--line);
  border-radius: 6px;
  margin-bottom: 16px;
  padding: 12px;
}
.instructions-title {
  margin: 0 0 8px;
  font-size: 13px;
  font-weight: 500;
  color: var(--text);
}
.instructions-links {
  margin: 0;
  padding-left: 18px;
  color: var(--muted);
  font-size: 13px;
}
.instructions-links li { margin-bottom: 4px; }
a { color: var(--text); text-decoration: underline; text-underline-offset: 4px; }
a:hover { color: var(--muted); }
.status-panel {
  text-align: center;
}
.status-mark {
  display: inline-grid;
  width: 42px;
  height: 42px;
  margin-bottom: 14px;
  place-items: center;
  border-radius: 999px;
  font-weight: 600;
}
.status-mark.success { background: var(--success-bg); color: #34d399; }
.status-mark.cancelled { background: var(--cancel-bg); color: #94a3b8; }
.code-display {
  background: var(--bg);
  border: 1px solid var(--line);
  border-radius: 6px;
  padding: 16px;
  font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace;
  font-size: 24px;
  letter-spacing: 2px;
  text-align: center;
  margin: 24px 0;
  color: var(--text);
}
.warning {
  color: #fbbf24;
  font-size: 13px;
  margin-top: 12px;
  display: flex;
  align-items: center;
  gap: 8px;
}
.warning::before {
  content: "⚠";
}
@media (max-width: 520px) {
  .page {
    width: min(100% - 24px, 520px);
    padding: 24px 0;
  }
  .panel { padding: 22px; }
}
</style>
"""

DEVICE_BRIDGE_STYLE = """
<style>
:root {
  color-scheme: dark;
  --bg: #000000;
  --panel: #0a0a0a;
  --text: #ededed;
  --muted: #a1a1aa;
  --line: #27272a;
  --focus: #ededed;
  --primary: #ededed;
  --primary-text: #000000;
}
body {
  font-family: ui-sans-serif, system-ui, -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif;
  max-width: 480px;
  margin: 40px auto;
  padding: 20px;
  background: var(--bg);
  color: var(--text);
  -webkit-font-smoothing: antialiased;
}
h2 { margin-bottom: 8px; font-weight: 500; letter-spacing: -0.02em; }
.subtitle { color: var(--muted); margin-bottom: 24px; font-size: 14px; }
.code-wrap { display: flex; gap: 8px; align-items: center; margin-bottom: 20px; }
.code-wrap input {
  flex: 1;
  font-size: 24px;
  font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace;
  padding: 12px;
  border: 1px solid var(--line);
  border-radius: 6px;
  background: var(--panel);
  color: var(--text);
  text-align: center;
  letter-spacing: 2px;
  box-sizing: border-box;
}
.code-wrap input:focus { outline: none; border-color: var(--focus); }
.copybtn {
  padding: 12px 16px;
  font-size: 14px;
  border: 1px solid var(--line);
  background: var(--panel);
  color: var(--text);
  border-radius: 6px;
  cursor: pointer;
  transition: background 0.15s;
  font-weight: 500;
}
.copybtn:hover { background: #111111; }
a.verify {
  display: inline-block;
  margin-bottom: 20px;
  padding: 12px 16px;
  background: var(--primary);
  color: var(--primary-text);
  text-decoration: none;
  border-radius: 6px;
  font-weight: 500;
  transition: opacity 0.15s;
  width: 100%;
  text-align: center;
  box-sizing: border-box;
}
a.verify:hover { opacity: 0.9; }
.note { font-size: 13px; color: var(--muted); text-align: center; }
</style>
"""
