"""
Evidence capture — persist the request/response behind each finding so it is
reproducible and reviewable later.

Each saved response becomes two files under `<output_dir>/evidence/`:
  <id>.json  — metadata: url, final_url, status, ip, the request (method +
               attribution headers sent), response headers, body length, a
               SHA-256 of the body, truncation flag, and a timestamp.
  <id>.body  — the raw response bytes.

`id` is content-addressed (SHA-256 over final_url + body, truncated), so the same
page captured twice is stored once and a finding can cite a stable id. The body
hash in the metadata lets a reviewer confirm the stored body is the one the
finding was drawn from.
"""

from __future__ import annotations

import hashlib
import json
import os
import time
from typing import Dict, Optional


class EvidenceStore:
    def __init__(self, output_dir: str):
        self._dir = os.path.join(output_dir, "evidence")
        os.makedirs(self._dir, exist_ok=True)

    def save_response(self, result, request_headers: Optional[Dict[str, str]] = None,
                      method: str = "GET") -> str:
        """Persist a response (a FetchResult-like). Returns its evidence id."""
        url = getattr(result, "url", "") or ""
        final_url = getattr(result, "final_url", "") or url
        body = getattr(result, "body", b"") or b""
        if isinstance(body, str):
            body = body.encode("utf-8", "replace")

        body_sha = hashlib.sha256(body).hexdigest()
        eid = hashlib.sha256((final_url + "\x00").encode("utf-8") + body).hexdigest()[:16]

        body_path = os.path.join(self._dir, eid + ".body")
        meta_path = os.path.join(self._dir, eid + ".json")
        if os.path.exists(meta_path):
            return eid  # already captured (content-addressed)

        meta = {
            "id": eid,
            "ts": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "url": url,
            "final_url": final_url,
            "status": getattr(result, "status", None),
            "ip": getattr(result, "ip", ""),
            "request": {"method": method, "headers": dict(request_headers or {})},
            "response_headers": dict(getattr(result, "headers", {}) or {}),
            "body_sha256": body_sha,
            "body_len": len(body),
            "truncated": bool(getattr(result, "truncated", False)),
        }
        with open(body_path, "wb") as fh:
            fh.write(body)
        with open(meta_path, "w", encoding="utf-8") as fh:
            json.dump(meta, fh, indent=2, sort_keys=True)
        return eid

    def load(self, eid: str) -> Dict:
        with open(os.path.join(self._dir, eid + ".json"), "r", encoding="utf-8") as fh:
            return json.load(fh)

    def body_path(self, eid: str) -> str:
        return os.path.join(self._dir, eid + ".body")

    def verify(self, eid: str) -> bool:
        """Confirm the stored body still matches the metadata's hash."""
        meta = self.load(eid)
        with open(self.body_path(eid), "rb") as fh:
            return hashlib.sha256(fh.read()).hexdigest() == meta["body_sha256"]
