"""
Local web dashboard — a read-only, stdlib-only server over a runs directory.

Routes:
  GET /                       index of runs (newest first)
  GET /run/<id>              the dark KASABONKA dashboard for one run
  GET /evidence/<id>/<eid>   the raw captured response body for a finding

It is a local tool: it binds to 127.0.0.1 by default, serves read-only, re-renders
each run from its run.json on request, and adds no dependency (http.server). Run
and evidence ids are strictly validated, so a request can't path-traverse out of
the runs root. Evidence bodies are raw target responses, so they are served as
text/plain with nosniff and as a download, never as HTML the browser would run.
"""

from __future__ import annotations

import os
import re
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import unquote

from .evidence import EvidenceStore
from .persistence import list_runs, load_run, render_run_html, build_index_html

_SAFE = re.compile(r"^[A-Za-z0-9._-]+$")


def _safe(part: str) -> bool:
    return bool(part) and part not in (".", "..") and bool(_SAFE.match(part))


class _Handler(BaseHTTPRequestHandler):
    server_version = "horkos-oss"

    def log_message(self, *a):
        pass

    def _send(self, code: int, body: bytes, ctype: str = "text/html; charset=utf-8",
              extra=None):
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Content-Security-Policy", "default-src 'none'; style-src 'unsafe-inline'; script-src 'unsafe-inline'")
        for k, v in (extra or {}).items():
            self.send_header(k, v)
        self.end_headers()
        self.wfile.write(body)

    def _nf(self):
        self._send(404, b"<h1>404</h1>", "text/html; charset=utf-8")

    def do_GET(self):
        root = self.server.runs_root
        path = unquote(self.path.split("?", 1)[0])
        parts = [p for p in path.split("/") if p]

        if not parts:
            self._send(200, build_index_html(list_runs(root)).encode("utf-8"))
            return

        if parts[0] == "run" and len(parts) == 2 and _safe(parts[1]):
            rdir = os.path.join(root, parts[1])
            if not os.path.isfile(os.path.join(rdir, "run.json")):
                return self._nf()
            store = EvidenceStore(rdir) if os.path.isdir(os.path.join(rdir, "evidence")) else None
            html = render_run_html(load_run(rdir), store=store)
            self._send(200, html.encode("utf-8"))
            return

        if parts[0] == "evidence" and len(parts) == 3 and _safe(parts[1]) and _safe(parts[2]):
            body_path = os.path.join(root, parts[1], "evidence", parts[2] + ".body")
            # keep the resolved path inside the runs root
            if not os.path.realpath(body_path).startswith(os.path.realpath(root) + os.sep):
                return self._nf()
            if not os.path.isfile(body_path):
                return self._nf()
            with open(body_path, "rb") as fh:
                data = fh.read()
            self._send(200, data, "text/plain; charset=utf-8",
                       extra={"Content-Disposition": f'attachment; filename="{parts[2]}.txt"'})
            return

        self._nf()


def make_server(runs_root: str, host: str = "127.0.0.1", port: int = 8787) -> ThreadingHTTPServer:
    srv = ThreadingHTTPServer((host, port), _Handler)
    srv.runs_root = os.path.abspath(runs_root)
    return srv


def serve(runs_root: str, host: str = "127.0.0.1", port: int = 8787) -> None:
    srv = make_server(runs_root, host, port)
    print(f"horkos-oss dashboard on http://{host}:{srv.server_address[1]}  (runs: {srv.runs_root})")
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        srv.shutdown()


if __name__ == "__main__":
    import sys
    serve(sys.argv[1] if len(sys.argv) > 1 else "runs")
