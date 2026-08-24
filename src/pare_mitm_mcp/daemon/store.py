from __future__ import annotations

import copy
import re
import threading
from collections import deque
from dataclasses import dataclass
from typing import Any, Literal, Optional

SUMMARY_KEYS = ("id", "ts", "kind", "method", "host", "path",
                "scheme", "status", "content_type", "resp_size", "error")


@dataclass
class InterceptionRule:
    rule_id: str
    action: Literal["BLOCK", "MODIFY"]
    scope: Literal["host", "path", "url", "headers", "req_body", "resp_body"]
    pattern: str  # regex
    target: Optional[Literal["req_headers", "req_body", "resp_headers", "resp_body", "status"]] = None
    replacement: Optional[str] = None
    header_name: Optional[str] = None  # For header modifications



class FlowStore:
    """Thread-safe ring buffer of flow records. The ring cap is the retention
    policy — old flows (which may hold live tokens) roll off automatically."""

    def __init__(self, max_flows: int = 5000) -> None:
        self._flows: deque[dict] = deque(maxlen=max_flows)
        self._by_id: dict[str, dict] = {}
        self._seq = 0
        self._lock = threading.Lock()

    def add(self, record: dict) -> str:
        with self._lock:
            self._seq += 1
            fid = f"{self._seq:04x}"
            rec = {"id": fid, **record}
            if self._flows.maxlen and len(self._flows) == self._flows.maxlen:
                evicted = self._flows[0]
                self._by_id.pop(evicted["id"], None)
            self._flows.append(rec)
            self._by_id[fid] = rec
            return fid

    def summaries(self, *, host: str | None = None, method: str | None = None,
                  status: int | None = None, since: float | None = None,
                  limit: int = 200) -> list[dict]:
        with self._lock:
            rows = list(self._flows)
        out = []
        for r in reversed(rows):  # newest first
            if host is not None and r["host"] != host:
                continue
            if method is not None and r["method"] != method:
                continue
            if status is not None and r["status"] != status:
                continue
            if since is not None and r["ts"] < since:
                continue
            out.append({k: r[k] for k in SUMMARY_KEYS})
            if len(out) >= limit:
                break
        return out

    def get(self, flow_id: str) -> dict | None:
        with self._lock:
            r = self._by_id.get(flow_id)
            return copy.deepcopy(r) if r else None

    def search(self, pattern: str, scope: str = "all", limit: int = 50) -> list[dict]:
        rx = re.compile(pattern)
        with self._lock:
            rows = list(self._flows)
        hits = []
        for r in reversed(rows):
            hay = _scope_text(r, scope)
            m = rx.search(hay)
            if m:
                start = max(0, m.start() - 40)
                end = min(len(hay), m.end() + 40)
                hits.append({"id": r["id"], "snippet": hay[start:end]})
                if len(hits) >= limit:
                    break
        return hits

    def health(self) -> dict:
        with self._lock:
            rows = list(self._flows)
        tls_errors = sum(1 for r in rows if r["kind"] == "error")
        last_ts = rows[-1]["ts"] if rows else None
        return {"flows": len(rows), "tls_errors": tls_errors, "last_flow_ts": last_ts}


class RuleStore:
    """Thread-safe storage for interception rules."""

    def __init__(self) -> None:
        self._rules: dict[str, InterceptionRule] = {}
        self._lock = threading.Lock()
        self._seq = 0

    def add(self, rule: InterceptionRule) -> str:
        with self._lock:
            self._seq += 1
            rid = f"rule_{self._seq:04x}"
            # If the user provided a rule_id, we'll overwrite it with our own
            # to ensure uniqueness and control.
            rule.rule_id = rid
            self._rules[rid] = rule
            return rid

    def remove(self, rule_id: str) -> bool:
        with self._lock:
            if rule_id in self._rules:
                del self._rules[rule_id]
                return True
            return False

    def clear(self) -> None:
        with self._lock:
            self._rules.clear()

    def get_all(self) -> list[InterceptionRule]:
        with self._lock:
            return list(self._rules.values())

    def get(self, rule_id: str) -> InterceptionRule | None:
        with self._lock:
            return self._rules.get(rule_id)


def _scope_text(r: dict, scope: str) -> str:
    if scope == "url":
        return f"{r['scheme']}://{r['host']}{r['path']}"
    if scope == "headers":
        return _hdrs(r["req_headers"]) + "\n" + _hdrs(r["resp_headers"])
    if scope == "req-body":
        return r["req_body"]
    if scope == "resp-body":
        return r["resp_body"]
    # all
    return "\n".join([f"{r['scheme']}://{r['host']}{r['path']}",
                      _hdrs(r["req_headers"]), _hdrs(r["resp_headers"]),
                      r["req_body"], r["resp_body"]])


def _hdrs(h: dict[str, str]) -> str:
    return "\n".join(f"{k}: {v}" for k, v in h.items())
