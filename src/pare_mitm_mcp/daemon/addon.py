from __future__ import annotations

import time
from typing import Any

from pare_mitm_mcp.config import load_config
from pare_mitm_mcp.daemon.store import FlowStore
from pare_mitm_mcp.daemon.control import ControlServer

_TEXT_CT = ("json", "text", "xml", "x-www-form-urlencoded", "javascript")


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
        self.control = ControlServer(self.store, self.cfg.control_host, self.cfg.control_port)
        self._started = False

    def load(self, loader) -> None:
        if not self._started:
            self.control.start()
            self._started = True

    def response(self, flow) -> None:
        self.store.add(record_from_flow(flow))

    def error(self, flow) -> None:
        self.store.add(record_from_error(flow))

    def tls_failed_client(self, data) -> None:
        self.store.add(record_from_tls_failure(data, "client"))

    def tls_failed_server(self, data) -> None:
        self.store.add(record_from_tls_failure(data, "server"))


addons = [PareAddon()]
