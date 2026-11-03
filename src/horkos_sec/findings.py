"""
Finding — the unit a detector emits.

Construction goes through make_finding(), which routes the raw severity through
the severity module: the stored `severity` is capped into the allowed band and
the true level is preserved in `detail` via a CHAIN_SEVERITY marker when it
exceeds the cap. A detector therefore never has to think about the band — it
states the real severity and the helper keeps the model honest.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Dict

from .severity import cap_severity, with_true_severity


@dataclass
class Finding:
    title: str                       # stable label; used for de-duplication later
    severity: str                    # capped: info / low / medium
    url: str
    category: str = ""               # e.g. "security-headers", "cookie", "info-disclosure"
    detail: str = ""                 # may carry a CHAIN_SEVERITY=<raw> marker
    evidence: Dict[str, str] = field(default_factory=dict)

    def key(self) -> tuple:
        """De-dup key: same finding on the same URL is one finding."""
        return (self.category, self.title, self.url)


def make_finding(title: str, raw_severity: str, url: str,
                 detail: str = "", category: str = "", evidence=None) -> Finding:
    return Finding(
        title=title,
        severity=cap_severity(raw_severity),
        url=url,
        category=category,
        detail=with_true_severity(raw_severity, detail),
        evidence=dict(evidence or {}),
    )
