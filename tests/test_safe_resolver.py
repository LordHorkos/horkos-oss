#!/usr/bin/env python3
"""Standalone tests for safe_resolver.py. Network-free: getaddrinfo is faked.
Run: python3 test_safe_resolver.py."""
import socket
import sys

from horkos_sec import safe_resolver
from horkos_sec.safe_resolver import resolve, validate_ip, _check_ip


# ---- _check_ip / validate_ip: the SSRF core, no DNS ------------------------

def test_public_ips_pass():
    assert _check_ip("8.8.8.8") is None
    assert _check_ip("1.1.1.1") is None
    assert _check_ip("2606:4700:4700::1111") is None   # public IPv6


def test_blocked_ranges_denied():
    for ip in ["10.0.0.5", "172.16.1.1", "192.168.1.1", "127.0.0.1",
               "169.254.1.1", "100.64.0.1", "0.0.0.0", "255.255.255.255",
               "224.0.0.1", "::1", "fe80::1", "fc00::1"]:
        assert _check_ip(ip) is not None, f"{ip} must be blocked"


def test_ipv4_mapped_ipv6_blocked():
    # ::ffff:10.0.0.1 would otherwise smuggle a private v4 through a v6 literal
    assert _check_ip("::ffff:10.0.0.1") is not None


def test_unparseable_denied():
    assert _check_ip("not-an-ip") is not None
    assert _check_ip("999.999.999.999") is not None


def test_allow_private_flag():
    assert _check_ip("127.0.0.1") is not None               # default: blocked
    assert _check_ip("127.0.0.1", allow_private=True) is None
    assert _check_ip("10.0.0.5", allow_private=True) is None
    assert _check_ip("fe80::1", allow_private=True) is None
    # multicast stays blocked even with the hatch
    assert _check_ip("224.0.0.1", allow_private=True) is not None


def test_validate_ip_shapes():
    ok = validate_ip("8.8.8.8")
    assert ok.is_valid and ok.ip == "8.8.8.8" and ok.ips == ["8.8.8.8"]
    bad = validate_ip("10.0.0.1")
    assert not bad.is_valid and bad.denial_reason
    assert not validate_ip("").is_valid


# ---- resolve(): fake getaddrinfo -------------------------------------------

def _fake_gai(mapping):
    def _gai(host, *a, **k):
        if host not in mapping:
            raise socket.gaierror(-2, "Name or service not known")
        return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", (ip, 0)) for ip in mapping[host]]
    return _gai


def _with_gai(mapping, fn):
    orig = socket.getaddrinfo
    safe_resolver.socket.getaddrinfo = _fake_gai(mapping)
    try:
        return fn()
    finally:
        safe_resolver.socket.getaddrinfo = orig


def test_resolve_public_ok():
    r = _with_gai({"ok.test": ["93.184.216.34"]},
                  lambda: resolve("ok.test"))
    assert r.is_valid and r.ip == "93.184.216.34"


def test_resolve_denies_if_any_record_blocked():
    # one public, one private -> whole hostname denied (multi-record SSRF)
    r = _with_gai({"rebind.test": ["93.184.216.34", "10.0.0.5"]},
                  lambda: resolve("rebind.test"))
    assert not r.is_valid and "10.0.0.5" in r.denial_reason
    assert set(r.ips) == {"93.184.216.34", "10.0.0.5"}


def test_resolve_dns_failure_denied():
    r = _with_gai({}, lambda: resolve("nxdomain.test"))
    assert not r.is_valid and "DNS resolution failed" in r.denial_reason


def test_resolve_empty_hostname_denied():
    assert not resolve("").is_valid


def test_resolve_allow_private_opt_in():
    r = _with_gai({"lab.test": ["127.0.0.1"]},
                  lambda: resolve("lab.test", allow_private=True))
    assert r.is_valid and r.ip == "127.0.0.1"


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
