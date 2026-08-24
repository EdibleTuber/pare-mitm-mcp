from __future__ import annotations

import ipaddress
import json
import re
import sys
import threading
import urllib.request
import urllib.parse
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlparse, parse_qs

from pare_mitm_mcp.daemon.store import FlowStore, RuleStore, InterceptionRule

_LOOPBACK_HOSTS = {"localhost"}


def _is_loopback(host: str) -> bool:
    if host in _LOOPBACK_HOSTS:
        return True
    try:
        return ipaddress.ip_address(host).is_loopback
    except ValueError:
        return False


class ControlServer:
    def __init__(self, store: FlowStore, rule_store: RuleStore, host: str = "127.0.0.1", port: int = 8788, proxy_port: int = 8080) -> None:
        self._store = store
        self._rule_store = rule_store
        self._host = host
        self._port = port
        self._proxy_port = proxy_port
        self._httpd: ThreadingHTTPServer | None = None
        self._thread: threading.Thread | None = None

    def start(self) -> int:
        if not _is_loopback(self._host):
            print(
                f"warning: control API bound to non-loopback {self._host}; "
                "it is unauthenticated and exposes captured traffic",
                file=sys.stderr,
            )

        store = self._store
        rule_store = self._rule_store

        class Handler(BaseHTTPRequestHandler):
            def log_message(self, *a):  # silence
                pass

            def _send(self, code, payload):
                body = json.dumps(payload).encode()
                self.send_response(code)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            def do_GET(self):
                u = urlparse(self.path)
                q = {k: v[0] for k, v in parse_qs(u.query).items()}
                try:
                    if u.path == "/health":
                        return self._send(200, store.health())
                    if u.path == "/flows":
                        return self._send(200, store.summaries(
                            host=q.get("host"), method=q.get("method"),
                            status=int(q["status"]) if "status" in q else None,
                            since=float(q["since"]) if "since" in q else None,
                            limit=int(q.get("limit", "200"))))
                    if u.path.startswith("/flow/"):
                        rec = store.get(u.path[len("/flow/"):])
                        if rec is None:
                            return self._send(404, {"error": "no such flow"})
                        return self._send(200, rec)
                    if u.path == "/search":
                        return self._send(200, store.search(
                            q.get("pattern", ""), q.get("scope", "all"),
                            int(q.get("limit", "50"))))
                    if u.path == "/rules":
                        return self._send(200, [{"rule_id": r.rule_id, **r.__dict__} for r in rule_store.get_all()])
                    return self._send(404, {"error": "no such route"})
                except Exception as e:
                    return self._send(400, {"error": str(e)})

            def do_POST(self):
                u = urlparse(self.path)
                content_length = int(self.headers.get("Content-Length", 0))
                body_bytes = self.rfile.read(content_length)
                try:
                    payload = json.loads(body_bytes) if body_bytes else {}
                except json.JSONDecodeError:
                    return self._send(400, {"error": "invalid JSON"})

                try:
                    if u.path == "/rules/block":
                        pattern = payload.get("pattern", "")
                        try:
                            re.compile(pattern)
                        except re.error as e:
                            return self._send(400, {"error": f"bad pattern: {e}"})
                        rule = InterceptionRule(
                            rule_id="",
                            action="BLOCK",
                            scope=payload.get("scope", "host"),
                            pattern=pattern,
                            target=None,
                            replacement=None,
                            header_name=None
                        )
                        rid = rule_store.add(rule)
                        return self._send(201, {"rule_id": rid})

                    if u.path == "/rules/modify":
                        pattern = payload.get("pattern", "")
                        try:
                            re.compile(pattern)
                        except re.error as e:
                            return self._send(400, {"error": f"bad pattern: {e}"})
                        rule = InterceptionRule(
                            rule_id="",
                            action="MODIFY",
                            scope=payload.get("scope", "host"),
                            pattern=pattern,
                            target=payload.get("target"),
                            replacement=payload.get("replacement"),
                            header_name=payload.get("header_name")
                        )
                        rid = rule_store.add(rule)
                        return self._send(201, {"rule_id": rid})

                    if u.path == "/rules/clear":
                        rule_store.clear()
                        return self._send(200, {"status": "cleared"})

                    if u.path == "/inject":
                        # Reconstruct request from payload
                        method = payload.get("method", "GET")
                        url = payload.get("url")
                        if not url:
                            return self._send(400, {"error": "url is required"})
                        
                        headers = payload.get("headers", {})
                        body = payload.get("body", "")
                        
                        proxy_handler = urllib.request.ProxyHandler({
                            'http': f'http://127.0.0.1:{proxy_port}',
                            'https': f'http://127.0.0.1:{proxy_port}'
                        })
                        opener = urllib.request.build_opener(proxy_handler)
                        
                        req = urllib.request.Request(url, data=body.encode() if body else None, headers=headers, method=method)
                        try:
                            with opener.open(req, timeout=10) as response:
                                return self._send(200, {"status": "injected", "status_code": response.status})
                        except Exception as e:
                            return self._send(500, {"error": str(e)})

                    if u.path == "/replay":
                        flow_id = payload.get("id")
                        if not flow_id:
                            return self._send(400, {"error": "id is required"})
                        
                        rec = store.get(flow_id)
                        if not rec or rec.get("kind") != "flow":
                            return self._send(404, {"error": "no such flow"})
                        
                        method = rec["method"]
                        url = f"{rec['scheme']}://{rec['host']}{rec['path']}"
                        headers = rec["req_headers"]
                        body = rec["req_body"]
                        
                        proxy_handler = urllib.request.ProxyHandler({
                            'http': f'http://127.0.0.1:{proxy_port}',
                            'https': f'http://127.0.0.1:{proxy_port}'
                        })
                        opener = urllib.request.build_opener(proxy_handler)
                        
                        # Note: body might be '<binary N bytes>' if it was binary. 
                        # This is a limitation of the current storage.
                        req_data = None
                        if body and not body.startswith("<binary"):
                            req_data = body.encode()
                        
                        req = urllib.request.Request(url, data=req_data, headers=headers, method=method)
                        try:
                            with opener.open(req, timeout=10) as response:
                                return self._send(200, {"status": "replayed", "status_code": response.status})
                        except Exception as e:
                            return self._send(500, {"error": str(e)})

                    return self._send(404, {"error": "no such route"})
                except Exception as e:
                    return self._send(400, {"error": str(e)})

            def do_DELETE(self):
                u = urlparse(self.path)
                try:
                    if u.path.startswith("/rules/"):
                        rule_id = u.path[len("/rules/"):]
                        if rule_store.remove(rule_id):
                            return self._send(200, {"status": "deleted"})
                        else:
                            return self._send(404, {"error": "no such rule"})
                    return self._send(404, {"error": "no such route"})
                except Exception as e:
                    return self._send(400, {"error": str(e)})

        self._httpd = ThreadingHTTPServer((self._host, self._port), Handler)
        self._port = self._httpd.server_address[1]
        self._thread = threading.Thread(target=self._httpd.serve_forever, daemon=True)
        self._thread.start()
        return self._port

    def stop(self) -> None:
        if self._httpd is not None:
            self._httpd.shutdown()
            self._httpd.server_close()
        if self._thread is not None:
            self._thread.join(timeout=2)

    @property
    def url(self) -> str:
        return f"http://{self._host}:{self._port}"
