#!/usr/bin/env python3
"""Standalone tests for severity.py. Run: python3 test_severity.py (exit 0 = pass)."""
import sys

from horkos_sec.severity import cap_severity, with_true_severity


def test_cap_passthrough():
    assert cap_severity("info") == "info"
    assert cap_severity("low") == "low"
    assert cap_severity("medium") == "medium"


def test_cap_folds_high_critical():
    assert cap_severity("high") == "medium"
    assert cap_severity("critical") == "medium"
    assert cap_severity("CRITICAL") == "medium"


def test_cap_unknown_is_medium():
    assert cap_severity("") == "medium"
    assert cap_severity(None) == "medium"
    assert cap_severity("bogus") == "medium"


def test_true_severity_marks_only_above_band():
    assert with_true_severity("high", "x") == "CHAIN_SEVERITY=high; x"
    assert with_true_severity("critical") == "CHAIN_SEVERITY=critical"
    assert with_true_severity("medium", "x") == "x"
    assert with_true_severity("low") == ""


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
