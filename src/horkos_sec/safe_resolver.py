"""
SSRF-safe DNS resolver.

Resolves a hostname to IP addresses and validates them against private,
loopback, link-local, and other non-routable ranges. Fail-closed: any
uncertainty denies.

Hardening over the naive pattern:
  * Resolves ALL addresses (IPv4 and IPv6) via getaddrinfo, not just the first
    IPv4 from gethostbyname. A host with several A records, or any AAAA record,
    cannot slip an unvalidated address through. If ANY resolved address is in a
    blocked range, the whole hostname is denied.
  * The "allow private" escape hatch is an explicit parameter, not an ambient
    environment variable, so a caller must opt in deliberately and locally.

Note: this validates the addresses a hostname resolves to at call time. It does
not by itself defeat DNS rebinding — to be safe against that, resolve once here,
then connect to the validated IP literal (not the hostname) and send the host
header separately, or re-pin via validate_ip at connect time.
"""

import ipaddress
import socket
import threading
import time
from dataclasses import dataclass, field
from typing import List, Optional


# Private / reserved ranges that are never allowed targets.
_BLOCKED_NETWORKS = [
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("127.0.0.0/8"),
    ipaddress.ip_network("::1/128"),
    ipaddress.ip_network("fc00::/7"),
    ipaddress.ip_network("fe80::/10"),
    ipaddress.ip_network("169.254.0.0/16"),   # link-local
    ipaddress.ip_network("100.64.0.0/10"),    # shared address space (CGNAT)
    ipaddress.ip_network("0.0.0.0/8"),
    ipaddress.ip_network("240.0.0.0/4"),      # reserved
    ipaddress.ip_network("224.0.0.0/4"),      # multicast
    ipaddress.ip_network("::ffff:0:0/96"),    # IPv4-mapped IPv6
]


@dataclass
class ResolvedTarget:
    hostname: str
    ip: str                                   # first valid address, "" on denial
    is_valid: bool
    denial_reason: Optional[str] = None
    ips: List[str] = field(default_factory=list)   # every address resolved


class ResolutionCache:
    """Short-TTL cache of hostname -> resolved IP list. It caches only the DNS
    lookup, never the validation verdict: resolve() re-validates every cached
    address on every call, so a cached result can never bypass the SSRF checks."""

    def __init__(self, ttl: float = 60.0):
        self._ttl = ttl
        self._lock = threading.Lock()
        self._data: dict = {}

    def get(self, host: str):
        with self._lock:
            entry = self._data.get(host)
            if entry and entry[0] > time.monotonic():
                return list(entry[1])
            if entry:
                self._data.pop(host, None)
            return None

    def set(self, host: str, ips: List[str]) -> None:
        with self._lock:
            self._data[host] = (time.monotonic() + self._ttl, list(ips))


def resolve(hostname: str, allow_private: bool = False,
            cache: Optional["ResolutionCache"] = None) -> ResolvedTarget:
    """
    Resolve hostname → all IPs and validate every one.
    Returns is_valid=False with a denial_reason on any problem, including a
    single blocked address among several. An optional ResolutionCache skips the
    DNS lookup for a hot host; validation still runs on every call.
    """
    if not hostname or not isinstance(hostname, str):
        return ResolvedTarget(str(hostname), "", False, "Invalid hostname input.")

    ips = cache.get(hostname) if cache is not None else None
    if ips is None:
        try:
            infos = socket.getaddrinfo(hostname, None)
        except socket.gaierror as e:
            return ResolvedTarget(hostname, "", False, f"DNS resolution failed: {e}")
        except Exception as e:
            return ResolvedTarget(hostname, "", False, f"Unexpected resolution error: {e}")
        # De-duplicate while preserving order.
        seen: dict = {}
        for info in infos:
            seen.setdefault(info[4][0], None)
        ips = list(seen)
        if not ips:
            return ResolvedTarget(hostname, "", False, "No addresses resolved.")
        if cache is not None:
            cache.set(hostname, ips)

    # Always validate every address, cached or freshly resolved.
    for ip_str in ips:
        reason = _check_ip(ip_str, allow_private)
        if reason:
            return ResolvedTarget(hostname, ip_str, False, reason, ips)

    return ResolvedTarget(hostname, ips[0], True, None, ips)


def validate_ip(ip_str: str, allow_private: bool = False) -> ResolvedTarget:
    """
    Validate an IP literal directly — no DNS involved.

    Use this when the caller already has a candidate IP (e.g. from a prior
    resolve()) and needs to independently re-validate that exact literal without
    re-resolving. Re-resolving would let DNS hand back a different IP than the
    one already vetted, making the earlier resolve() load-bearing for this
    check's safety — the opposite of the fail-independently design.
    """
    if not ip_str or not isinstance(ip_str, str):
        return ResolvedTarget("", str(ip_str), False, "Invalid IP input.")

    reason = _check_ip(ip_str, allow_private)
    if reason:
        return ResolvedTarget("", ip_str, False, reason)
    return ResolvedTarget("", ip_str, True, None, [ip_str])


def _check_ip(ip_str: str, allow_private: bool = False) -> Optional[str]:
    """Return a denial reason if the IP is blocked, else None."""
    try:
        addr = ipaddress.ip_address(ip_str)
    except ValueError:
        return f"Could not parse resolved IP: {ip_str!r}"

    # Opt-in escape hatch: permit loopback + private + link-local for local
    # testing. Multicast / reserved / unspecified stay blocked even so.
    if allow_private and (addr.is_loopback or addr.is_private or addr.is_link_local):
        return None

    for network in _BLOCKED_NETWORKS:
        if addr in network:
            return f"Resolved IP {ip_str} is in blocked network {network}."

    if addr.is_loopback:
        return f"Resolved IP {ip_str} is loopback."
    if addr.is_private:
        return f"Resolved IP {ip_str} is private."
    if addr.is_link_local:
        return f"Resolved IP {ip_str} is link-local."
    if addr.is_multicast:
        return f"Resolved IP {ip_str} is multicast."
    if addr.is_reserved:
        return f"Resolved IP {ip_str} is reserved."
    if addr.is_unspecified:
        return f"Resolved IP {ip_str} is unspecified."

    return None
