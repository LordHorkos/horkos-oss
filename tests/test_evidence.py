#!/usr/bin/env python3
"""Standalone tests for evidence.py. Run: python3 test_evidence.py."""
import os
import sys
import tempfile
from dataclasses import dataclass, field
from typing import Dict

from horkos_sec.evidence import EvidenceStore


@dataclass
class R:
    url: str = "https://example.com/a"
    final_url: str = "https://example.com/a"
    status: int = 200
    ip: str = "93.184.216.34"
    headers: Dict[str, str] = field(default_factory=lambda: {"server": "nginx"})
    body: bytes = b"<html>hi</html>"
    truncated: bool = False


def _store():
    return EvidenceStore(tempfile.mkdtemp())


def test_save_writes_meta_and_body():
    s = _store()
    eid = s.save_response(R(), request_headers={"X-Research": "horkos"})
    meta = s.load(eid)
    assert meta["status"] == 200 and meta["final_url"] == "https://example.com/a"
    assert meta["request"]["headers"]["X-Research"] == "horkos"
    assert meta["response_headers"]["server"] == "nginx"
    assert os.path.exists(s.body_path(eid))
    assert open(s.body_path(eid), "rb").read() == b"<html>hi</html>"


def test_content_addressed_dedup():
    s = _store()
    a = s.save_response(R())
    b = s.save_response(R())                 # identical -> same id, stored once
    assert a == b
    files = os.listdir(os.path.join(s._dir))
    assert files.count(a + ".json") == 1


def test_different_body_different_id():
    s = _store()
    a = s.save_response(R(body=b"one"))
    b = s.save_response(R(body=b"two"))
    assert a != b


def test_verify_detects_tamper():
    s = _store()
    eid = s.save_response(R())
    assert s.verify(eid)
    with open(s.body_path(eid), "wb") as fh:
        fh.write(b"tampered")
    assert not s.verify(eid)


def test_body_hash_recorded():
    s = _store()
    import hashlib
    eid = s.save_response(R(body=b"abc"))
    assert s.load(eid)["body_sha256"] == hashlib.sha256(b"abc").hexdigest()


def _main():
    tests = [v for k, v in sorted(globals().items())
             if k.startswith("test_") and callable(v)]
    n = 0
    for t in tests:
        t(); n += 1; print(f"ok {n} {t.__name__}")
    print(f"RESULT: {n}/{len(tests)} passed")
    sys.exit(0 if n == len(tests) else 1)


if __name__ == "__main__":
    _main()
