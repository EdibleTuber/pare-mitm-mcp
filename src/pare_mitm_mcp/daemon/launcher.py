from __future__ import annotations

import os
import secrets
import shutil
import subprocess
import sys
import time

from pare_mitm_mcp.config import Config, load_config
from pare_mitm_mcp.client import DaemonClient, DaemonUnreachable

_ACTIONABLE_NOT_FOUND = (
    "mitmweb not found in this environment. Set PARE_MITM_MITMWEB=/path/to/mitmweb "
    "to point at it explicitly (e.g. the pare-mitm-mcp repo's .venv/bin/mitmweb)."
)


def addon_path() -> str:
    return os.path.join(os.path.dirname(__file__), "addon.py")


def _token_path(cfg: Config) -> str:
    return os.path.join(cfg.state_dir, "web_token")


def _log_path(cfg: Config) -> str:
    return os.path.join(cfg.state_dir, "daemon.log")


def resolve_web_token(cfg: Config) -> str:
    """Resolve the mitmweb UI auth token (the `web_password` value).

    Precedence:
      1. cfg.web_password (PARE_MITM_WEB_PASSWORD) — explicit operator override.
      2. a token previously persisted at <state_dir>/web_token, so the UI URL
         stays stable across daemon restarts.
      3. a freshly generated token, persisted to that file for next time.

    Never raises: if state_dir can't be read or written (permissions, missing
    disk, etc.), falls back to an in-memory generated token so `up` still
    works — just without a stable token across restarts.
    """
    if cfg.web_password:
        return cfg.web_password

    token_path = _token_path(cfg)
    try:
        with open(token_path, "r") as f:
            existing = f.read().strip()
        if existing:
            return existing
    except OSError:
        pass

    token = secrets.token_hex(16)
    try:
        os.makedirs(cfg.state_dir, exist_ok=True)
        fd = os.open(token_path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        try:
            os.write(fd, token.encode())
        finally:
            os.close(fd)
        os.chmod(token_path, 0o600)  # belt-and-braces: os.open's mode is umask-subject
    except OSError:
        pass
    return token


def ui_url(cfg: Config, token: str) -> str:
    return f"http://127.0.0.1:{cfg.web_port}/?token={token}"


def is_up(cfg: Config) -> bool:
    try:
        DaemonClient.from_config(cfg, timeout=0.5).health()
        return True
    except DaemonUnreachable:
        return False


def _is_executable_file(path: str) -> bool:
    return bool(path) and os.path.isfile(path) and os.access(path, os.X_OK)


def resolve_mitmweb(cfg: Config) -> str | None:
    """Resolve an absolute path to an executable mitmweb binary.

    Tried in order, first hit wins:
      1. cfg.mitmweb_path (PARE_MITM_MITMWEB) — explicit operator override.
         If set but not usable, this is a hard error (raises), not a
         silent fall-through.
      2. alongside the running interpreter (same env as the launcher).
      3. shutil.which("mitmweb") — normal PATH case.
      4. the worker package's own sibling venv: <repo>/.venv/bin/mitmweb,
         derived from pare_mitm_mcp.__file__. Makes PARE's `/mitm up` work
         out of the box against ~/Projects/pare-mitm-mcp's own venv even
         though pare-mitm-mcp is installed --no-deps in PARE's venv.
    """
    if cfg.mitmweb_path:
        if _is_executable_file(cfg.mitmweb_path):
            return os.path.abspath(cfg.mitmweb_path)
        raise FileNotFoundError(
            f"PARE_MITM_MITMWEB={cfg.mitmweb_path!r} is not an executable file"
        )

    interpreter_adjacent = os.path.join(os.path.dirname(sys.executable), "mitmweb")
    if _is_executable_file(interpreter_adjacent):
        return interpreter_adjacent

    on_path = shutil.which("mitmweb")
    if on_path:
        return on_path

    try:
        import pare_mitm_mcp

        pkg_file = os.path.abspath(pare_mitm_mcp.__file__)
        # editable install layout: <repo>/src/pare_mitm_mcp/__init__.py
        repo_root = os.path.dirname(os.path.dirname(os.path.dirname(pkg_file)))
        sibling_venv = os.path.join(repo_root, ".venv", "bin", "mitmweb")
        if _is_executable_file(sibling_venv):
            return sibling_venv
    except Exception:
        pass

    return None


def build_mitmweb_cmd(cfg: Config) -> list[str]:
    binary = resolve_mitmweb(cfg)
    if binary is None:
        raise FileNotFoundError(_ACTIONABLE_NOT_FOUND)
    token = resolve_web_token(cfg)
    return [
        binary,
        "-s", addon_path(),
        "--listen-host", "0.0.0.0",           # device reaches the proxy over LAN
        "--listen-port", str(cfg.proxy_port),
        "--web-host", "127.0.0.1",            # human UI stays local
        "--web-port", str(cfg.web_port),
        "--set", "web_open_browser=false",
        "--set", f"web_password={token}",
    ]


def _open_log_for_append(cfg: Config):
    """Best-effort log file for mitmweb's stdout/stderr.

    Falls back to DEVNULL if state_dir can't be created/opened, so a
    permissions problem there doesn't block `up` — it just means we lose
    diagnostics for this run instead of crashing.
    """
    try:
        os.makedirs(cfg.state_dir, exist_ok=True)
        return open(_log_path(cfg), "ab")
    except OSError:
        return subprocess.DEVNULL


def _up(cfg: Config) -> int:
    if is_up(cfg):
        print("mitm daemon already up")
        print(f"ui: {ui_url(cfg, resolve_web_token(cfg))}")
        return 0
    try:
        cmd = build_mitmweb_cmd(cfg)
        log_f = _open_log_for_append(cfg)
        # PYTHONUNBUFFERED: stdio block-buffers when redirected to a file, so
        # startup/crash lines would sit unflushed in the child's buffer — which
        # defeats the point of capturing the log for diagnosis.
        subprocess.Popen(cmd, stdout=log_f, stderr=log_f, start_new_session=True,
                         env={**os.environ, "PYTHONUNBUFFERED": "1"})
    except FileNotFoundError as e:
        print(str(e) or _ACTIONABLE_NOT_FOUND, file=sys.stderr)
        return 2
    for _ in range(50):  # up to ~5s
        if is_up(cfg):
            print(f"mitm daemon up (proxy :{cfg.proxy_port}, ui :{cfg.web_port}, "
                  f"control :{cfg.control_port}, mitmweb: {cmd[0]})")
            print(f"ui: {ui_url(cfg, resolve_web_token(cfg))}")
            return 0
        time.sleep(0.1)
    print("mitm daemon did not come up within 5s — check the port isn't held "
          f"(:{cfg.proxy_port}/:{cfg.web_port}/:{cfg.control_port}); "
          f"see {_log_path(cfg)} for mitmweb's output", file=sys.stderr)
    return 1


def _status(cfg: Config) -> int:
    if is_up(cfg):
        h = DaemonClient.from_config(cfg).health()
        print(f"up — {h['flows']} flows, {h['tls_errors']} tls-errors")
        print(f"ui: {ui_url(cfg, resolve_web_token(cfg))}")
        return 0
    print("down")
    return 0


def _down(cfg: Config) -> int:
    # v1: mitmweb is operator-launched in its own session; instruct rather than kill.
    print("stop the mitmweb process from its terminal (Ctrl-C) or: pkill -f "
          f"'mitmweb.*{addon_path()}'")
    return 0


def main(argv: list[str] | None = None, cfg: Config | None = None) -> int:
    argv = sys.argv[1:] if argv is None else argv
    cfg = cfg or load_config()
    cmd = argv[0] if argv else "status"
    if cmd == "up":
        return _up(cfg)
    if cmd == "down":
        return _down(cfg)
    if cmd == "status":
        return _status(cfg)
    print(f"usage: pare-mitm-daemon [up|down|status]", file=sys.stderr)
    return 2
