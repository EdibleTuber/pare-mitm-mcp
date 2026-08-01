from __future__ import annotations

import json
import urllib.error
import urllib.parse
import urllib.request


class DaemonUnreachable(Exception):
    pass


class DaemonClient:
    def __init__(self, base_url: str, timeout: float = 2.0) -> None:
        self._base = base_url.rstrip("/")
        self._timeout = timeout

    @classmethod
    def from_config(cls, cfg, timeout: float = 2.0) -> "DaemonClient":
        return cls(f"http://{cfg.control_host}:{cfg.control_port}", timeout)

    def _get(self, path: str, params: dict | None = None):
        url = self._base + path
        if params:
            clean = {k: v for k, v in params.items() if v is not None}
            if clean:
                url += "?" + urllib.parse.urlencode(clean)
        try:
            with urllib.request.urlopen(url, timeout=self._timeout) as r:
                return json.loads(r.read().decode()), 200
        except urllib.error.HTTPError as e:
            return None, e.code
        except (urllib.error.URLError, ConnectionError, OSError) as e:
            raise DaemonUnreachable(str(e))

    def health(self) -> dict:
        data, _ = self._get("/health")
        return data

    def flows(self, **filters) -> list[dict]:
        data, _ = self._get("/flows", filters)
        return data

    def flow(self, flow_id: str) -> dict | None:
        data, code = self._get(f"/flow/{urllib.parse.quote(flow_id)}")
        return None if code == 404 else data

    def search(self, pattern: str, scope: str = "all", limit: int = 50) -> list[dict]:
        data, _ = self._get("/search", {"pattern": pattern, "scope": scope, "limit": limit})
        return data
