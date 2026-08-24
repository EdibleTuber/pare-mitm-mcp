from __future__ import annotations

import re
import sys
import time
from typing import Any, Literal, Optional

from pare_mitm_mcp.config import load_config
from pare_mitm_mcp.daemon.store import FlowStore, RuleStore, InterceptionRule
from pare_mitm_mcp.daemon.control import ControlServer

_TEXT_CT = ("json", "text", "xml", "x-www-form-urlencoded", "javascript")


class InterceptionManager:
    """Handles rule matching and application for mitmproxy flows."""

    def __init__(self, rule_store: RuleStore) -> None:
        self.rule_store = rule_store

    def get_blocking_rule(self, flow) -> Optional[InterceptionRule]:
        for rule in self.rule_store.get_all():
            if rule.action == "BLOCK" and self._matches(rule, flow):
                return rule
        return None

    def get_modification_rules(self, flow) -> list[InterceptionRule]:
        return [
            rule for rule in self.rule_store.get_all()
            if rule.action == "MODIFY" and self._matches(rule, flow)
        ]

    def _matches(self, rule: InterceptionRule, flow) -> bool:
        # Determine what to check based on scope
        if rule.scope == "host":
            val = flow.request.host
        elif rule.scope == "path":
            val = flow.request.path
        elif rule.scope == "url":
            val = f"{flow.request.scheme}://{flow.request.host}{flow.request.path}"
        elif rule.scope == "headers":
            val = str(flow.request.headers) + str(flow.response.headers if flow.response else "")
        elif rule.scope == "req_body":
            val = flow.request.get_text(strict=False) or ""
        elif rule.scope == "resp_body":
            val = flow.response.get_text(strict=False) if flow.response else ""
        else:
            return False

        return bool(re.search(rule.pattern, val))


def _decode_body(message) -> str:
    """Return decoded text for a textual body, or a '<binary N bytes>' marker."""
    if message is None:
        return ""
    ct = message.headers.get("Content-Type", "") if hasattr(message, "headers") else ""
    raw = getattr(message, "raw_content", None) or b""
    if any(t in ct.lower() for t in _TEXT_CT):
        try:
            return message.get_text(strict=False) or ""
        except Exception:
            return f"<binary {len(raw)} bytes>"
    if not raw:
        return ""
    return f"<binary {len(raw)} bytes>"


def record_from_flow(flow) -> dict[str, Any]:
    req = flow.request
    resp = flow.response
    resp_ct = resp.headers.get("Content-Type") if resp is not None else None
    resp_raw = getattr(resp, "raw_content", None) or b"" if resp is not None else b""
    return {
        "ts": time.time(),
        "kind": "flow",
        "method": req.method,
        "host": req.host,
        "path": req.path,
        "scheme": req.scheme,
        "status": resp.status_code if resp is not None else None,
        "content_type": resp_ct,
        "resp_size": len(resp_raw),
        "error": None,
        "req_headers": dict(req.headers),
        "req_body": _decode_body(req),
        "resp_headers": dict(resp.headers) if resp is not None else {},
        "resp_body": _decode_body(resp),
    }


def record_from_error(flow) -> dict[str, Any]:
    req = getattr(flow, "request", None)
    msg = getattr(getattr(flow, "error", None), "msg", None) or "connection error"
    return {
        "ts": time.time(),
        "kind": "error",
        "method": getattr(req, "method", None) if req else None,
        "host": getattr(req, "host", "") if req else "",
        "path": getattr(req, "path", "") if req else "",
        "scheme": getattr(req, "scheme", "https") if req else "https",
        "status": None,
        "content_type": None,
        "resp_size": 0,
        "error": str(msg),
        "req_headers": dict(getattr(req, "headers", {})) if req else {},
        "req_body": "",
        "resp_headers": {},
        "resp_body": "",
    }


def record_from_tls_failure(data, side: str) -> dict[str, Any]:
    conn = getattr(data, "conn", None)
    context = getattr(data, "context", None)

    sni = getattr(conn, "sni", None)
    host = sni
    if not host:
        server = getattr(context, "server", None)
        address = getattr(server, "address", None)
        try:
            host = address[0] if address else ""
        except (TypeError, IndexError):
            host = ""
    host = host or ""

    conn_error = getattr(conn, "error", None)
    reason = str(conn_error) if conn_error else "unknown TLS handshake failure"
    error = f"TLS handshake failed ({side}): {reason}"

    return {
        "ts": time.time(),
        "kind": "error",
        "method": None,
        "host": host,
        "path": "",
        "scheme": "https",
        "status": None,
        "content_type": None,
        "resp_size": 0,
        "error": error,
        "req_headers": {},
        "req_body": "",
        "resp_headers": {},
        "resp_body": "",
    }


class PareAddon:
    def __init__(self) -> None:
        self.cfg = load_config()
        self.store = FlowStore(max_flows=self.cfg.max_flows)
        self.rule_store = RuleStore()
        self.interceptor = InterceptionManager(self.rule_store)
        self.control = ControlServer(self.store, self.rule_store, self.cfg.control_host, self.cfg.control_port)
        self._started = False

    def load(self, loader) -> None:
        if not self._started:
            self.control.start()
            self._started = True

    def request(self, flow) -> None:
        try:
            blocking_rule = self.interceptor.get_blocking_rule(flow)
        except re.error as e:
            print(f"pare-mitm: skipping blocking rule (bad regex): {e}", file=sys.stderr)
            blocking_rule = None
        if blocking_rule:
            flow.kill()
            return

        try:
            mod_rules = self.interceptor.get_modification_rules(flow)
        except re.error as e:
            print(f"pare-mitm: skipping modification rules (bad regex): {e}", file=sys.stderr)
            mod_rules = []

        for rule in mod_rules:
            try:
                if rule.target == "req_headers":
                    if rule.header_name:
                        if rule.replacement:
                            flow.request.headers[rule.header_name] = rule.replacement
                        else:
                            flow.request.headers.pop(rule.header_name, None)
                elif rule.target == "req_body":
                    if rule.replacement is not None:
                        current = flow.request.get_text(strict=False) or ""
                        flow.request.set_text(re.sub(rule.pattern, rule.replacement, current))
                # ... other targets
            except Exception as e:
                print(f"pare-mitm: rule {rule.rule_id!r} failed to apply: {e}", file=sys.stderr)

    def response(self, flow) -> None:
        try:
            mod_rules = self.interceptor.get_modification_rules(flow)
        except re.error as e:
            print(f"pare-mitm: skipping modification rules (bad regex): {e}", file=sys.stderr)
            mod_rules = []

        for rule in mod_rules:
            try:
                if rule.target == "resp_headers":
                    if rule.header_name:
                        if rule.replacement:
                            flow.response.headers[rule.header_name] = rule.replacement
                        else:
                            flow.response.headers.pop(rule.header_name, None)
                elif rule.target == "resp_body":
                    if rule.replacement is not None:
                        current = flow.response.get_text(strict=False) or ""
                        flow.response.set_text(re.sub(rule.pattern, rule.replacement, current))
                elif rule.target == "status":
                    if rule.replacement:
                        flow.response.status_code = int(rule.replacement)
            except Exception as e:
                print(f"pare-mitm: rule {rule.rule_id!r} failed to apply: {e}", file=sys.stderr)

        self.store.add(record_from_flow(flow))

    def error(self, flow) -> None:
        self.store.add(record_from_error(flow))

    def tls_failed_client(self, data) -> None:
        self.store.add(record_from_tls_failure(data, "client"))

    def tls_failed_server(self, data) -> None:
        self.store.add(record_from_tls_failure(data, "server"))


addons = [PareAddon()]
