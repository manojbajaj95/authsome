"""Local daemon process control for CLI commands."""

from __future__ import annotations

import json
import os
import signal
import subprocess
import sys
import time
from pathlib import Path
from typing import Any

from authsome.cli.client import DEFAULT_DAEMON_URL, AuthsomeApiClient
from authsome.server.daemon import DEFAULT_HOST, DEFAULT_PORT

AUTHSOME_HOME = Path(os.environ.get("AUTHSOME_HOME", str(Path.home() / ".authsome")))
DAEMON_DIR = AUTHSOME_HOME / "daemon"
PID_FILE = DAEMON_DIR / "daemon.pid"
LOG_FILE = DAEMON_DIR / "daemon.log"
STATE_FILE = DAEMON_DIR / "daemon.json"


class DaemonUnavailableError(RuntimeError):
    """Raised when the local daemon cannot be started or reached."""


def ensure_daemon() -> AuthsomeApiClient:
    """Return a ready daemon client, starting/restarting the daemon if needed."""
    client = AuthsomeApiClient(DEFAULT_DAEMON_URL)
    if _is_ready(client):
        return client
    if _pid_file_process_alive():
        stop_daemon()
    start_daemon()
    deadline = time.monotonic() + 10
    while time.monotonic() < deadline:
        if _is_ready(client):
            return client
        time.sleep(0.2)
    raise DaemonUnavailableError(_startup_error())


def start_daemon() -> None:
    DAEMON_DIR.mkdir(parents=True, exist_ok=True)
    log = LOG_FILE.open("ab")
    process = subprocess.Popen(
        [sys.executable, "-m", "authsome.cli.main", "daemon", "serve"],
        stdout=log,
        stderr=log,
        start_new_session=True,
    )
    PID_FILE.write_text(str(process.pid), encoding="utf-8")
    STATE_FILE.write_text(
        json.dumps({"pid": process.pid, "host": DEFAULT_HOST, "port": DEFAULT_PORT}, indent=2),
        encoding="utf-8",
    )


def stop_daemon() -> None:
    pid = _read_pid()
    if pid is None:
        return
    try:
        os.kill(pid, signal.SIGTERM)
    except ProcessLookupError:
        _clear_daemon_files()
        return
    deadline = time.monotonic() + 5
    while time.monotonic() < deadline:
        if not _process_alive(pid):
            _clear_daemon_files()
            return
        time.sleep(0.2)
    try:
        os.kill(pid, signal.SIGKILL)
    except ProcessLookupError:
        pass
    _clear_daemon_files()


def daemon_status() -> dict[str, Any]:
    client = AuthsomeApiClient(DEFAULT_DAEMON_URL)
    try:
        health = client.health()
        ready = client.ready()
        return {"running": True, "health": health, "ready": ready, "pid_file": str(PID_FILE), "log_file": str(LOG_FILE)}
    except Exception as exc:
        return {"running": False, "error": str(exc), "pid_file": str(PID_FILE), "log_file": str(LOG_FILE)}


def _is_ready(client: AuthsomeApiClient) -> bool:
    try:
        return client.health().get("status") == "ok" and client.ready().get("status") == "ready"
    except Exception:
        return False


def _read_pid() -> int | None:
    try:
        return int(PID_FILE.read_text(encoding="utf-8").strip())
    except Exception:
        return None


def _process_alive(pid: int) -> bool:
    try:
        os.kill(pid, 0)
        return True
    except OSError:
        return False


def _pid_file_process_alive() -> bool:
    pid = _read_pid()
    return pid is not None and _process_alive(pid)


def _clear_daemon_files() -> None:
    for path in (PID_FILE, STATE_FILE):
        try:
            path.unlink()
        except FileNotFoundError:
            pass


def _startup_error() -> str:
    lines: list[str] = []
    if LOG_FILE.exists():
        lines = LOG_FILE.read_text(encoding="utf-8", errors="replace").splitlines()[-12:]
    detail = "\n".join(lines) if lines else "No daemon log output was captured."
    return f"Authsome daemon failed to start.\nLog: {LOG_FILE}\n\n{detail}"
