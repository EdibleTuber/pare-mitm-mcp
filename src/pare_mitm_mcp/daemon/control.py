from __future__ import annotations

import json
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlparse, parse_qs

from pare_mitm_mcp.daemon.store import FlowStore


class ControlServer:
    def __init__(self, store: FlowStore, host: str = "127.0.0.1", port: int = 8788) -> None:
        self._store = store
        self._host = host
        self._port = port
        self._httpd: ThreadingHTTPServer | None = None
        self._thread: threading.Thread | None = None

    def start(self) -> int:
        store = self._store

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
                    return self._send(404, {"error": "no such route"})
                except Exception as e:  # never crash the daemon on a bad query
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

    @property
    def url(self) -> str:
        return f"http://{self._host}:{self._port}"
