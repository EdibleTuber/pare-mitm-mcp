from __future__ import annotations

import os
from dataclasses import dataclass, field

_DEFAULT_STATE_DIR = "~/.local/state/pare-mitm"


def _default_state_dir() -> str:
    # Expanded at instantiation time (not class-definition time) so that
    # monkeypatching $HOME in tests, or constructing Config() directly,
    # never leaves a literal "~" to be treated as a repo-relative path.
    return os.path.expanduser(_DEFAULT_STATE_DIR)


@dataclass(frozen=True)
class Config:
    control_host: str = "127.0.0.1"
    control_port: int = 8788
    proxy_port: int = 8080
    web_port: int = 8081
    max_flows: int = 5000        # ring-buffer retention cap (security cheapie #2)
    mitmweb_path: str = ""       # explicit override for the mitmweb binary (see daemon/launcher.py)
    web_password: str = ""       # explicit mitmweb UI token override (see daemon/launcher.py)
    state_dir: str = field(default_factory=_default_state_dir)  # small daemon state (persisted web token, daemon.log)


def load_config() -> Config:
    return Config(
        control_host=os.environ.get("PARE_MITM_CONTROL_HOST", "127.0.0.1"),
        control_port=int(os.environ.get("PARE_MITM_CONTROL_PORT", "8788")),
        proxy_port=int(os.environ.get("PARE_MITM_PROXY_PORT", "8080")),
        web_port=int(os.environ.get("PARE_MITM_WEB_PORT", "8081")),
        max_flows=int(os.environ.get("PARE_MITM_MAX_FLOWS", "5000")),
        mitmweb_path=os.environ.get("PARE_MITM_MITMWEB", ""),
        web_password=os.environ.get("PARE_MITM_WEB_PASSWORD", ""),
        state_dir=os.path.expanduser(
            os.environ.get("PARE_MITM_STATE_DIR", _DEFAULT_STATE_DIR)
        ),
    )
