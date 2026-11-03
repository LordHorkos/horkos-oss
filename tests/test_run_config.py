#!/usr/bin/env python3
"""Standalone tests for run_config.py. Run: python3 test_run_config.py."""
import sys

from horkos_sec.run_config import build_run_plan, RunOptions, PROD_RATE_CEILING
from horkos_sec.governance import Engagement
from horkos_sec.scope_guard import ScopeConfig


def _eng(authorized=True, modes=("observe",)):
    return Engagement("acme", ScopeConfig(allowed_domains=["example.com"],
                                          allowed_schemes=["https"]),
                      authorized=authorized, modes=modes)


def test_keeps_authorized_rejects_out_of_scope():
    plan = build_run_plan(_eng(), [
        "https://example.com/a",
        "https://sub.example.com/b",
        "https://evil.test/c",
    ])
    assert plan.seeds == ["https://example.com/a", "https://sub.example.com/b"]
    assert len(plan.rejected) == 1 and "evil.test" in plan.rejected[0][0]


def test_dedupes_seeds():
    plan = build_run_plan(_eng(), ["https://example.com/a", "https://example.com/a"])
    assert plan.seeds == ["https://example.com/a"]


def test_unauthorized_engagement_leaves_nothing():
    try:
        build_run_plan(_eng(authorized=False), ["https://example.com/a"])
    except ValueError as e:
        assert "not confirmed authorized" in str(e)
        return
    raise AssertionError("unauthorized engagement must raise")


def test_all_out_of_scope_raises():
    try:
        build_run_plan(_eng(), ["https://evil.test/a"])
    except ValueError as e:
        assert "No authorized seeds" in str(e)
        return
    raise AssertionError("must raise when nothing authorized")


def test_rate_ceiling_enforced():
    try:
        build_run_plan(_eng(), ["https://example.com/a"],
                       RunOptions(rate=5.0))
    except ValueError as e:
        assert "ceiling" in str(e)
        return
    raise AssertionError("rate above ceiling must raise without opt-out")


def test_rate_ceiling_opt_out():
    plan = build_run_plan(_eng(), ["https://example.com/a"],
                          RunOptions(rate=5.0, allow_fast_rate=True))
    assert plan.options.rate == 5.0


def test_default_rate_is_ceiling():
    plan = build_run_plan(_eng(), ["https://example.com/a"])
    assert plan.options.rate == PROD_RATE_CEILING


def test_mode_must_match_engagement():
    try:
        build_run_plan(_eng(modes=("observe",)), ["https://example.com/a"],
                       RunOptions(mode="validate"))
    except ValueError as e:
        assert "mode" in str(e)
        return
    raise AssertionError("mode not in engagement must raise")


def test_bad_caps_raise():
    for opts in (RunOptions(rate=0), RunOptions(max_requests=0)):
        try:
            build_run_plan(_eng(), ["https://example.com/a"], opts)
        except ValueError:
            continue
        raise AssertionError("non-positive rate/cap must raise")


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
