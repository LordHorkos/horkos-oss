# governance

Three primitives that make a live run accountable: an authorization gate, a
tamper-evident audit log, and a kill switch. None of them send or scan anything —
they decide whether an action is permitted, record that it happened, and let a
run be stopped.

## Authorization — `Engagement` + `authorize()`

A platform being "cleared" is not a target being cleared. An engagement must be
marked `authorized=True` deliberately, and every URL is still scope-checked.

```python
from horkos_sec import Engagement, authorize, parse_hackerone_scope

eng = Engagement(
    program="acme",
    scope=parse_hackerone_scope(pasted).config,
    authorized=True,                 # set only after you've confirmed the program
    modes=("observe",),              # active modes must be listed explicitly
)

d = authorize(eng, "https://api.example.com/x", mode="observe")
if not d.allowed:
    skip(d.reason)                   # unauthorized, wrong mode, or out of scope
```

Fail-closed: no program id, `authorized` not set, a mode the engagement doesn't
list, or an out-of-scope URL all deny.

## Audit log — `AuditLog`

Append-only JSONL with a SHA-256 hash chain: each entry commits to the previous
one, so a removed or altered line is detectable.

```python
from horkos_sec import AuditLog

log = AuditLog("runs/acme/audit.jsonl")
log.record("request", url=u, method="GET", status=r.status, ip=r.ip)
log.record("decision", url=u, allowed=False, reason="out of scope")

ok, bad_line = AuditLog.verify("runs/acme/audit.jsonl")   # (True, None) if intact
```

Thread-safe, and the chain resumes correctly across process restarts (a new
`AuditLog` on the same file continues the chain). `verify()` returns the first
bad line number if the chain was broken by editing or deleting an entry.

**Optional keyed (tamper-resistant) mode.** By default the chain is unkeyed
SHA-256 — tamper-*evident* (an edit is detectable, but an attacker with file
access can recompute the whole chain). Pass a `key` for an HMAC-SHA256 chain —
tamper-*resistant*, since re-chaining a forged entry needs the key. `verify()`
must then get the same key; without it, or with the wrong key, verification
fails. Keyed mode is stdlib-only (`hmac`), so it adds no dependency.

```python
log = AuditLog("runs/acme/audit.jsonl", key=secret_key)   # secret_key: bytes
log.record("request", url=u, status=200)
AuditLog.verify("runs/acme/audit.jsonl", key=secret_key)   # (True, None)
```

## Kill switch — `KillSwitch`

A thread-safe abort flag, optionally backed by a sentinel file so a run can be
stopped from outside the process.

```python
from horkos_sec import KillSwitch, Aborted

kill = KillSwitch(path="runs/acme/STOP")   # creating that file also trips it

for url in targets:
    try:
        kill.check()                       # raises Aborted once tripped
    except Aborted:
        break
    ...

# from anywhere: kill.trip("rate complaint from program") — or `touch runs/acme/STOP`
```

## Where these fit

Before a run touches a real target: gate each URL with `authorize()`, record
every request and decision to an `AuditLog`, and have the run loop `check()` a
`KillSwitch` each iteration. The controller (later) wires these around the guarded
HTTP client.

## Tests

```bash
python3 tests/test_governance.py     # or: python -m pytest
```
