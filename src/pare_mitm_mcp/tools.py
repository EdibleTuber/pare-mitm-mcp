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

async def list_rules() -> str:
    try:
        rules = _client().rules()
    except DaemonUnreachable:
        return _err(_DOWN)
    except DaemonError as e:
        return _err(f"list rules failed: {e.detail}", e)
    return _ok(f"{len(rules)} rules configured", rules=rules)

async def add_blocking_rule(scope: str, pattern: str) -> str:
    try:
        rid = _client().add_rule("block", scope=scope, pattern=pattern)
        return _ok(f"blocking rule added: {rid}", rule_id=rid)
    except DaemonUnreachable:
        return _err(_DOWN)
    except DaemonError as e:
        return _err(f"add rule failed: {e.detail}", e)

async def add_modification_rule(scope: str, pattern: str, target: str, replacement: str, header_name: str | None = None) -> str:
    try:
        rid = _client().add_rule("modify", scope=scope, pattern=pattern, target=target, replacement=replacement, header_name=header_name)
        return _ok(f"modification rule added: {rid}", rule_id=rid)
    except DaemonUnreachable:
        return _err(_DOWN)
    except DaemonError as e:
        return _err(f"add rule failed: {e.detail}", e)

async def delete_rule(rule_id: str) -> str:
    try:
        if _client().delete_rule(rule_id):
            return _ok(f"rule {rule_id!r} deleted")
        return _err(f"no such rule {rule_id!r}")
    except DaemonUnreachable:
        return _err(_DOWN)
    except DaemonError as e:
        return _err(f"delete failed: {e.detail}", e)

async def clear_rules() -> str:
    try:
        if _client().clear_rules():
            return _ok("all rules cleared")
        return _err("failed to clear rules")
    except DaemonUnreachable:
        return _err(_DOWN)
    except DaemonError as e:
        return _err(f"clear failed: {e.detail}", e)

async def inject_request(method: str, url: str, headers: dict | None = None, body: str | None = None) -> str:
    try:
        res = _client().inject(method=method, url=url, headers=headers or {}, body=body or "")
        return _ok("request injected", **res)
    except DaemonUnreachable:
        return _err(_DOWN)
    except DaemonError as e:
        return _err(f"injection failed: {e.detail}", e)

async def replay_flow(id: str) -> str:
    try:
        res = _client().replay(id)
        return _ok("flow replayed", **res)
    except DaemonUnreachable:
        return _err(_DOWN)
    except DaemonError as e:
        return _err(f"replay failed: {e.detail}", e)
