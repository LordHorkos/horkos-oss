# safe-resolver

An SSRF-safe DNS resolver. It resolves a hostname to its IP addresses and
validates every one against private, loopback, link-local, and other
non-routable ranges. Fail-closed: any uncertainty denies.

It also exposes `validate_ip()` for checking an IP literal directly, with no
DNS involved — useful for re-pinning an address you already resolved.

## Why resolve *all* addresses

The naive pattern (`socket.gethostbyname`) returns a single IPv4 address and
ignores IPv6. A host that publishes several A records, or any AAAA record, can
then present one routable address to the check and a private one to the actual
connection. This resolver uses `getaddrinfo`, collects **every** address (v4 and
v6), and denies the whole hostname if **any** of them is blocked.

It also blocks IPv4-mapped IPv6 (`::ffff:10.0.0.1`), which otherwise smuggles a
private v4 address through a v6 literal.

## Usage

```python
from safe_resolver import resolve, validate_ip

r = resolve("example.com")
if r.is_valid:
    connect(r.ip)                 # first validated address; r.ips has them all
else:
    reject(r.denial_reason)       # e.g. "Resolved IP 10.0.0.5 is in blocked network 10.0.0.0/8."

# Local testing: opt in explicitly (multicast/reserved stay blocked even so)
resolve("localhost", allow_private=True)

# Re-validate a literal without touching DNS:
validate_ip("93.184.216.34")
```

## Blocked ranges

RFC1918 (`10/8`, `172.16/12`, `192.168/16`), loopback (`127/8`, `::1`),
link-local (`169.254/16`, `fe80::/10`), unique-local (`fc00::/7`), CGNAT
(`100.64/10`), `0.0.0.0/8`, reserved (`240/4`), multicast (`224/4`), and
IPv4-mapped IPv6 (`::ffff:0:0/96`), plus Python's `is_reserved` /
`is_unspecified` catch-alls.

## Not a DNS-rebinding defense on its own

This validates the addresses a hostname resolves to **at call time**. A rebinding
attacker can return a good address here and a bad one at connect time. To be
safe against that: resolve once, then connect to the validated **IP literal**
(not the hostname) with the host header set separately, or re-pin via
`validate_ip()` at connect time.

## Tests

```bash
python3 test_safe_resolver.py     # exit 0 = pass; network-free (getaddrinfo is faked)
```
