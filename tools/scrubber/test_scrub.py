#!/usr/bin/env python3
"""Standalone tests for scrub.py. Run: python3 test_scrub.py  (exit 0 = pass)."""
from __future__ import annotations

import json
import sys
import tempfile
from pathlib import Path

import scrub

HERE = Path(__file__).parent
RULES = HERE / "rules.json"


def _tree(root: Path, files: dict[str, str]) -> None:
    for rel, content in files.items():
        p = root / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(content, encoding="utf-8")


def _run(files: dict[str, str], denylist: list[str] | None):
    tmp = Path(tempfile.mkdtemp())
    src, out = tmp / "src", tmp / "out"
    src.mkdir()
    _tree(src, files)
    dl = None
    if denylist is not None:
        dl = tmp / "deny.txt"
        dl.write_text("\n".join(denylist), encoding="utf-8")
    code = scrub.main(["--src", str(src), "--out", str(out),
                       "--rules", str(RULES)] + (["--denylist", str(dl)] if dl else []))
    report = json.loads((out / "scrub-report.json").read_text())
    return code, out, report


def test_rfc1918_and_email_redacted():
    code, out, rep = _run(
        {"app.py": "HOST = '10.0.0.42'\nMAIL = 'dev@example.com'\n"},
        denylist=[])
    body = (out / "app.py").read_text()
    assert "10.0.0.42" not in body, body
    assert "example.com" not in body, body
    assert code == 0, code
    assert rep["summary"]["redactions"] >= 2


def test_literal_denylist_redacts_hostnames():
    code, out, rep = _run(
        {"c.py": "CB = 'cb.internal.example'\nPROG = 'acme-widgets'\n"},
        denylist=["cb.internal.example", "acme-widgets => [PROGRAM]"])
    body = (out / "c.py").read_text()
    assert "internal.example" not in body, body
    assert "acme-widgets" not in body, body
    assert "[PROGRAM]" in body, body
    assert code == 0


def test_block_globs_refuse_not_copied():
    code, out, rep = _run(
        {"engine/keys/signing.key": "secret",
         "engine/ledger/log.jsonl": "{}",
         "scopes/acme.yaml": "allowed: x",
         "src/app.py": "x = 1\n"},
        denylist=[])
    assert code == 1, "refused files must force exit 1"
    assert not (out / "engine/keys/signing.key").exists()
    assert not (out / "scopes/acme.yaml").exists()
    assert (out / "src/app.py").exists()
    refused = set(rep["refused"])
    assert "engine/keys/signing.key" in refused
    assert "scopes/acme.yaml" in refused


def test_private_key_block_redacted():
    code, out, rep = _run(
        {"k.txt": "-----BEGIN OPENSSH PRIVATE KEY-----\nabc\n"},
        denylist=[])
    body = (out / "k.txt").read_text()
    assert "BEGIN OPENSSH PRIVATE KEY" not in body
    assert code == 0


def test_double_check_flags_surviving_pattern():
    # The double-check net: feed it text that still holds a verify pattern and
    # confirm it records a residual hit (this is the fail-closed backstop that
    # forces exit 1 if any scrub rule ever regresses).
    cfg = scrub.load_config(RULES, None)
    verify = [r for r in cfg.rules if r.verify]
    rep = scrub.Report()
    scrub.double_check("host = 10.0.0.42\n", verify, "f.py", rep)
    assert rep.residual, "RFC1918 IP must be flagged as residual"
    assert rep.residual[0].rule == "rfc1918-ipv4"

    clean = scrub.Report()
    scrub.double_check("host = [REDACTED_RFC1918_IP]\n", verify, "f.py", clean)
    assert not clean.residual, "scrubbed text must leave no residual"


def test_missing_denylist_fails_closed():
    tmp = Path(tempfile.mkdtemp())
    src, out = tmp / "src", tmp / "out"
    src.mkdir()
    _tree(src, {"f.py": "x=1\n"})
    try:
        scrub.main(["--src", str(src), "--out", str(out),
                    "--rules", str(RULES), "--denylist", str(tmp / "nope.txt")])
    except SystemExit as e:
        assert e.code == 2, e.code
        return
    raise AssertionError("missing denylist must exit 2 (fail-closed)")


def test_out_inside_src_refused():
    tmp = Path(tempfile.mkdtemp())
    src = tmp / "src"
    src.mkdir()
    _tree(src, {"f.py": "x=1\n"})
    try:
        scrub.main(["--src", str(src), "--out", str(src / "out"),
                    "--rules", str(RULES)])
    except SystemExit as e:
        assert e.code == 2, e.code
        return
    raise AssertionError("--out inside --src must exit 2")


def _main() -> None:
    tests = [v for k, v in sorted(globals().items())
             if k.startswith("test_") and callable(v)]
    passed = 0
    for t in tests:
        t()
        passed += 1
        print(f"ok {passed} {t.__name__}")
    print(f"RESULT: {passed}/{len(tests)} passed")
    if passed != len(tests):
        sys.exit(1)


if __name__ == "__main__":
    _main()
