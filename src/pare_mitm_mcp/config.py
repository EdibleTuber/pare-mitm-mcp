from __future__ import annotations

import os
from dataclasses import dataclass


@dataclass(frozen=True)
class Config:
    control_host: str = "127.0.0.1"
    control_port: int = 8788
    proxy_port: int = 8080
    web_port: int = 8081
    max_flows: int = 5000        # ring-buffer retention cap (security cheapie #2)
    mitmweb_path: str = ""       # explicit override for the mitmweb binary (see daemon/launcher.py)


def load_config() -> Config:
    return Config(
        control_host=os.environ.get("PARE_MITM_CONTROL_HOST", "127.0.0.1"),
        control_port=int(os.environ.get("PARE_MITM_CONTROL_PORT", "8788")),
        proxy_port=int(os.environ.get("PARE_MITM_PROXY_PORT", "8080")),
        web_port=int(os.environ.get("PARE_MITM_WEB_PORT", "8081")),
        max_flows=int(os.environ.get("PARE_MITM_MAX_FLOWS", "5000")),
        mitmweb_path=os.environ.get("PARE_MITM_MITMWEB", ""),
    )
