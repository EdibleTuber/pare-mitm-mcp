from __future__ import annotations

import os
import subprocess
import sys
import time

from pare_mitm_mcp.config import Config, load_config
from pare_mitm_mcp.client import DaemonClient, DaemonUnreachable


def addon_path() -> str:
    return os.path.join(os.path.dirname(__file__), "addon.py")


def is_up(cfg: Config) -> bool:
    try:
        DaemonClient.from_config(cfg, timeout=0.5).health()
        return True
    except DaemonUnreachable:
        return False


def build_mitmweb_cmd(cfg: Config) -> list[str]:
    return [
        "mitmweb",
        "-s", addon_path(),
        "--listen-host", "0.0.0.0",           # device reaches the proxy over LAN
        "--listen-port", str(cfg.proxy_port),
        "--web-host", "127.0.0.1",            # human UI stays local
        "--web-port", str(cfg.web_port),
        "--set", "web_open_browser=false",
    ]


def _up(cfg: Config) -> int:
    if is_up(cfg):
        print("mitm daemon already up")
        return 0
    cmd = build_mitmweb_cmd(cfg)
    try:
        subprocess.Popen(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                         start_new_session=True)
    except FileNotFoundError:
        print("mitmweb not found — is mitmproxy installed in this env?", file=sys.stderr)
        return 2
    for _ in range(50):  # up to ~5s
        if is_up(cfg):
            print(f"mitm daemon up (proxy :{cfg.proxy_port}, ui :{cfg.web_port}, "
                  f"control :{cfg.control_port})")
            return 0
        time.sleep(0.1)
    print("mitm daemon did not come up within 5s — check the port isn't held "
          f"(:{cfg.proxy_port}/:{cfg.web_port}/:{cfg.control_port})", file=sys.stderr)
    return 1


def _status(cfg: Config) -> int:
    if is_up(cfg):
        h = DaemonClient.from_config(cfg).health()
        print(f"up — {h['flows']} flows, {h['tls_errors']} tls-errors")
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
