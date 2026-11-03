"""
Governance primitives for a live-but-careful scanner: an authorization gate, an
append-only tamper-evident audit log, and a kill switch. None of them send or
scan anything — they decide whether an action is permitted, record that it
happened, and let a run be stopped cleanly.

  * Engagement + authorize() — refuse any target that isn't part of an explicitly
    confirmed, in-scope engagement, in a mode the engagement allows. A platform
    clearance is not a target clearance: `authorized` must be set deliberately
    per engagement, and scope is still enforced per URL.

  * AuditLog — append-only JSONL with a SHA-256 hash chain, so a removed or
    altered line is detectable with verify(). Thread-safe.

  * KillSwitch — a thread-safe, optionally file-backed abort flag. check() raises
    Aborted once tripped, so a long run can be stopped from another thread or by
    creating a sentinel file.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import os
import threading
import time
from dataclasses import dataclass, field
from typing import List, Optional, Tuple

from .scope_guard import ScopeConfig, check_scope


# ---- authorization ---------------------------------------------------------

@dataclass
class Engagement:
    program: str
    scope: ScopeConfig
    authorized: bool = False                       # must be set deliberately
    modes: Tuple[str, ...] = ("observe",)          # e.g. ("observe", "validate")
    note: str = ""


@dataclass
class AuthDecision:
    allowed: bool
    reason: str = "authorized"


def authorize(engagement: Engagement, url: str, mode: str = "observe") -> AuthDecision:
    """Permit `url` under `engagement` only if the engagement is explicitly
    authorized, the mode is allowed, and the URL is in scope. Fail-closed."""
    if not engagement.program:
        return AuthDecision(False, "engagement has no program identifier")
    if not engagement.authorized:
        return AuthDecision(False, f"engagement '{engagement.program}' is not confirmed authorized")
    if mode not in engagement.modes:
        return AuthDecision(False, f"mode '{mode}' not permitted for '{engagement.program}' (allowed: {list(engagement.modes)})")
    scope_result = check_scope(url, engagement.scope)
    if not scope_result.in_scope:
        return AuthDecision(False, f"out of scope: {scope_result.reason}")
    return AuthDecision(True)


# ---- audit log -------------------------------------------------------------

_GENESIS = "0" * 64


def _chain(prev: str, payload: str, key) -> str:
    data = (prev + payload).encode("utf-8")
    if key:
        return hmac.new(key, data, hashlib.sha256).hexdigest()
    return hashlib.sha256(data).hexdigest()


class AuditLog:
    """Append-only JSONL audit log with a SHA-256 hash chain.

    Default: an unkeyed SHA-256 chain — tamper-EVIDENT (an edit/delete is
    detectable). Pass a `key` (bytes) to switch the chain to keyed HMAC-SHA256:
    tamper-RESISTANT, since forging or re-chaining an entry needs the key.
    verify() must then be given the same key. Keyed mode uses only the standard
    library (hmac), so it adds no dependency.
    """

    def __init__(self, path: str, key: Optional[bytes] = None):
        self._path = path
        self._key = key
        self._lock = threading.Lock()
        self._last_hash = self._read_last_hash()

    def _read_last_hash(self) -> str:
        if not os.path.exists(self._path):
            return _GENESIS
        last = _GENESIS
        with open(self._path, "r", encoding="utf-8") as fh:
            for line in fh:
                line = line.strip()
                if line:
                    try:
                        last = json.loads(line)["h"]
                    except (ValueError, KeyError):
                        continue
        return last

    def record(self, action: str, **fields) -> str:
        """Append an entry; returns its chain hash."""
        with self._lock:
            entry = {
                "ts": fields.pop("ts", None) or _now(),
                "action": action,
                **fields,
                "alg": "hmac-sha256" if self._key else "sha256",
                "prev": self._last_hash,
            }
            payload = json.dumps(entry, sort_keys=True, separators=(",", ":"))
            h = _chain(self._last_hash, payload, self._key)
            entry["h"] = h
            line = json.dumps(entry, sort_keys=True, separators=(",", ":"))
            with open(self._path, "a", encoding="utf-8") as fh:
                fh.write(line + "\n")
            self._last_hash = h
            return h

    @staticmethod
    def verify(path: str, key: Optional[bytes] = None) -> Tuple[bool, Optional[int]]:
        """Re-walk the chain. Returns (ok, first_bad_line_number or None). For a
        keyed (HMAC) log, pass the same key; without it a keyed entry can't be
        verified and fails at that line."""
        prev = _GENESIS
        n = 0
        if not os.path.exists(path):
            return True, None
        with open(path, "r", encoding="utf-8") as fh:
            for n, raw in enumerate(fh, 1):
                raw = raw.strip()
                if not raw:
                    continue
                try:
                    entry = json.loads(raw)
                    stored = entry.pop("h")
                except (ValueError, KeyError):
                    return False, n
                if entry.get("prev") != prev:
                    return False, n
                keyed = entry.get("alg") == "hmac-sha256"
                if keyed and not key:
                    return False, n   # can't verify a keyed entry without the key
                payload = json.dumps(entry, sort_keys=True, separators=(",", ":"))
                h = _chain(prev, payload, key if keyed else None)
                if not hmac.compare_digest(h, stored):
                    return False, n
                prev = stored
        return True, None


def _now() -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())


# ---- kill switch -----------------------------------------------------------

class Aborted(Exception):
    """Raised by KillSwitch.check() once the switch is tripped."""


class KillSwitch:
    """Thread-safe abort flag, optionally backed by a sentinel file.

    Tripped if trip() was called OR (when `path` is set) the sentinel file
    exists. check() raises Aborted; tripped is a bool probe.
    """

    def __init__(self, path: Optional[str] = None):
        self._path = path
        self._lock = threading.Lock()
        self._tripped = False
        self._reason = ""

    def trip(self, reason: str = "manually tripped") -> None:
        with self._lock:
            self._tripped = True
            self._reason = reason
        if self._path:
            try:
                with open(self._path, "w", encoding="utf-8") as fh:
                    fh.write(reason)
            except OSError:
                pass

    @property
    def tripped(self) -> bool:
        with self._lock:
            if self._tripped:
                return True
        if self._path and os.path.exists(self._path):
            with self._lock:
                self._tripped = True
                if not self._reason:
                    self._reason = f"sentinel file present: {self._path}"
            return True
        return False

    @property
    def reason(self) -> str:
        return self._reason

    def check(self) -> None:
        if self.tripped:
            raise Aborted(self._reason or "aborted")
