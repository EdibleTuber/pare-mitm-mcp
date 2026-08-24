from __future__ import annotations

import json
import urllib.error
import urllib.parse
import urllib.request
from typing import Any, Literal


class DaemonUnreachable(Exception):
    pass


class DaemonError(Exception):
    """Daemon responded but with a non-200 status (e.g. a bad search regex)."""

    def __init__(self, code: int, detail: str) -> None:
        self.code = code
        self.detail = detail
        super().__init__(f"daemon returned {code}: {detail}")


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
                return json.loads(r.read().decode()), r.status
        except urllib.error.HTTPError as e:
            body = e.read()
            try:
                detail = json.loads(body.decode()).get("error", e.reason)
            except (ValueError, AttributeError):
                detail = e.reason
            return detail, e.code
        except (urllib.error.URLError, ConnectionError, OSError) as e:
            raise DaemonUnreachable(str(e))

    def _post(self, path: str, payload: dict) -> tuple[Any, int]:
        url = self._base + path
        data = json.dumps(payload).encode()
        req = urllib.request.Request(url, data=data, headers={"Content-Type": "application/json"})
        try:
            with urllib.request.urlopen(req, timeout=self._timeout) as r:
                return json.loads(r.read().decode()), r.status
        except urllib.error.HTTPError as e:
            body = e.read()
            try:
                detail = json.loads(body.decode()).get("error", e.reason)
            except (ValueError, AttributeError):
                detail = e.reason
            return detail, e.code
        except (urllib.error.URLError, ConnectionError, OSError) as e:
            raise DaemonUnreachable(str(e))

    def _delete(self, path: str) -> tuple[Any, int]:
        url = self._base + path
        req = urllib.request.Request(url, method="DELETE")
        try:
            with urllib.request.urlopen(req, timeout=self._timeout) as r:
                return json.loads(r.read().decode()), r.status
        except urllib.error.HTTPError as e:
            body = e.read()
            try:
                detail = json.loads(body.decode()).get("error", e.reason)
            except (ValueError, AttributeError):
                detail = e.reason
            return detail, e.code
        except (urllib.error.URLError, ConnectionError, OSError) as e:
            raise DaemonUnreachable(str(e))

    def health(self) -> dict:
        data, code = self._get("/health")
        if code != 200:
            raise DaemonError(code, str(data))
        return data

    def flows(self, **filters) -> list[dict]:
        data, code = self._get("/flows", filters)
        if code != 200:
            raise DaemonError(code, str(data))
        return data

    def flow(self, flow_id: str) -> dict | None:
        data, code = self._get(f"/flow/{urllib.parse.quote(flow_id)}")
        return data if code == 200 else None

    def search(self, pattern: str, scope: str = "all", limit: int = 50) -> list[dict]:
        data, code = self._get("/search", {"pattern": pattern, "scope": scope, "limit": limit})
        if code != 200:
            raise DaemonError(code, str(data))
        return data

    def rules(self) -> list[dict]:
        data, code = self._get("/rules")
        if code != 200:
            raise DaemonError(code, str(data))
        return data

    def add_rule(self, action: Literal["block", "modify"], **kwargs) -> str:
        path = f"/rules/{action}"
        data, code = self._post(path, kwargs)
        if code != 201:
            raise DaemonError(code, str(data))
        return data["rule_id"]

    def delete_rule(self, rule_id: str) -> bool:
        data, code = self._delete(f"/rules/{rule_id}")
        if code == 200:
            return True
        return False

    def clear_rules(self) -> bool:
        data, code = self._post("/rules/clear", {})
        return code == 200

    def inject(self, **kwargs) -> dict:
        data, code = self._post("/inject", kwargs)
        if code not in (200, 202):
            raise DaemonError(code, str(data))
        return data

    def replay(self, flow_id: str) -> dict:
        data, code = self._post("/replay", {"id": flow_id})
        if code != 200:
            raise DaemonError(code, str(data))
        return data
