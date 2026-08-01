from __future__ import annotations

import json
from typing import Any

from pare_mitm_mcp.config import load_config
from pare_mitm_mcp.client import DaemonClient, DaemonUnreachable, DaemonError

CFG = load_config()

_DOWN = "daemon not reachable — start it with /mitm up"


def _client() -> DaemonClient:
    return DaemonClient.from_config(CFG)


def _ok(summary: str, **extra: Any) -> str:
    return json.dumps({"summary": summary, **extra})


def _err(summary: str, exc: Exception | None = None) -> str:
    payload = {"summary": summary, "error": True}
    if exc is not None:
        payload["detail"] = str(exc)
    return json.dumps(payload)


async def capture_health() -> str:
    try:
        h = _client().health()
    except DaemonUnreachable:
        return _ok(_DOWN, reachable=False, flows=0, tls_errors=0, last_flow_ts=None)
    return _ok(
        f"proxy reachable — {h['flows']} flows, {h['tls_errors']} tls-errors",
        reachable=True, **h)


async def list_flows(host: str = "", method: str = "", status: int | None = None,
                     since: float | None = None, limit: int = 200) -> str:
    try:
        rows = _client().flows(
            host=host or None, method=method or None, status=status,
            since=since, limit=limit)
    except DaemonUnreachable:
        return _err(_DOWN)
    except DaemonError as e:
        return _err(f"list failed: {e.detail}", e)
    n_err = sum(1 for r in rows if r["kind"] == "error")
    hint = f" ({n_err} tls-error rows — pinning?)" if n_err else ""
    return _ok(f"{len(rows)} flows{hint}", rows=rows)


async def get_flow(id: str) -> str:
    try:
        rec = _client().flow(id)
    except DaemonUnreachable:
        return _err(_DOWN)
    if rec is None:
        return _err(f"no flow with id {id!r}")
    return _ok(f"{rec.get('method') or rec['kind']} {rec['host']}{rec['path']}", flow=rec)


async def search_flows(pattern: str, scope: str = "all", limit: int = 50) -> str:
    try:
        hits = _client().search(pattern, scope, limit)
    except DaemonUnreachable:
        return _err(_DOWN)
    except DaemonError as e:
        return _err(f"search failed: {e.detail}", e)
    return _ok(f"{len(hits)} matches for {pattern!r} in {scope}", hits=hits)
