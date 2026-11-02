#!/usr/bin/env python3
"""
scrub.py — redact sensitive identifiers from a source tree before open-sourcing it.

Reads a source tree, writes a SCRUBBED COPY to an output directory (never edits
in place), and emits a report of every redaction and every refused file.

Two kinds of rule:
  * patterns  — generic regexes (RFC1918 IPs, emails, private keys, ...).
                Safe to publish; live in rules.json.
  * literals  — exact strings (real hostnames, program slugs, operator IDs).
                Secret by nature; loaded from a local denylist file that is
                gitignored and NEVER committed. Pass it with --denylist.

Exit status:
  0  clean: everything requested was scrubbed, no residual high-risk hits
  1  refused files were present (paths that must never be published), or a
     residual high-risk pattern survived the scrub (double-check failed)
  2  usage / config error

The scrubber fails closed: if it cannot read the denylist, or a block rule has
no patterns, it stops rather than emit an under-redacted tree.
"""
from __future__ import annotations

import argparse
import fnmatch
import json
import re
import shutil
import sys
from dataclasses import dataclass, field
from pathlib import Path


# ---- config models ---------------------------------------------------------

@dataclass
class Rule:
    name: str
    regex: re.Pattern
    placeholder: str
    # a "verify" rule is also used in the post-scrub double-check pass
    verify: bool = False


@dataclass
class Config:
    rules: list[Rule]
    block_globs: list[str]          # paths that must never be published
    skip_globs: list[str]           # paths to omit from the copy, silently (vcs, caches)
    binary_suffixes: set[str]


@dataclass
class Hit:
    path: str
    line: int
    rule: str


@dataclass
class Report:
    hits: list[Hit] = field(default_factory=list)
    refused: list[str] = field(default_factory=list)   # block-glob matches found in input
    skipped_binary: list[str] = field(default_factory=list)
    copied: list[str] = field(default_factory=list)
    residual: list[Hit] = field(default_factory=list)   # survived the double-check


# ---- loading ---------------------------------------------------------------

def load_config(rules_path: Path, denylist_path: Path | None) -> Config:
    raw = json.loads(rules_path.read_text(encoding="utf-8"))
    rules: list[Rule] = []

    for r in raw.get("patterns", []):
        try:
            rx = re.compile(r["regex"])
        except re.error as e:
            die(f"bad regex in rule {r.get('name')!r}: {e}")
        rules.append(Rule(r["name"], rx, r.get("placeholder", "[REDACTED]"),
                          verify=bool(r.get("verify", True))))

    # literals: exact strings, longest first so substrings don't win.
    literals: list[tuple[str, str]] = []
    if denylist_path is not None:
        if not denylist_path.exists():
            die(f"denylist not found: {denylist_path} (fail-closed; refusing to scrub without it)")
        for ln in denylist_path.read_text(encoding="utf-8").splitlines():
            ln = ln.strip()
            if not ln or ln.startswith("#"):
                continue
            if "=>" in ln:
                val, _, ph = ln.partition("=>")
                literals.append((val.strip(), ph.strip()))
            else:
                literals.append((ln, "[REDACTED]"))
    # Literals are matched case-insensitively: a hostname or program slug shows
    # up in more than one casing, and a curated denylist should catch all of
    # them rather than require every variant be listed.
    for val, ph in sorted(literals, key=lambda t: len(t[0]), reverse=True):
        rules.insert(0, Rule(f"literal:{_short(val)}",
                             re.compile(re.escape(val), re.IGNORECASE), ph, verify=True))

    block = raw.get("block_globs", [])
    if not block:
        die("rules.json has no block_globs; refusing to run (fail-closed)")
    return Config(
        rules=rules,
        block_globs=block,
        skip_globs=raw.get("skip_globs", []),
        binary_suffixes={s.lower() for s in raw.get("binary_suffixes", [])},
    )


def _short(v: str) -> str:
    return (v[:8] + "...") if len(v) > 11 else v


# ---- core -------------------------------------------------------------------

def matches_any(rel: str, globs: list[str]) -> bool:
    parts = rel.split("/")
    for g in globs:
        if fnmatch.fnmatch(rel, g):
            return True
        # also match a glob against any path segment (so "keys" blocks a/keys/b)
        if "/" not in g and any(fnmatch.fnmatch(p, g) for p in parts):
            return True
    return False


def scrub_text(text: str, rules: list[Rule], path: str, rep: Report) -> str:
    lines = text.split("\n")
    out = []
    for i, line in enumerate(lines, 1):
        for rule in rules:
            if rule.regex.search(line):
                line = rule.regex.sub(rule.placeholder, line)
                rep.hits.append(Hit(path, i, rule.name))
        out.append(line)
    return "\n".join(out)


def double_check(text: str, rules: list[Rule], path: str, rep: Report) -> None:
    for i, line in enumerate(text.split("\n"), 1):
        for rule in rules:
            if rule.verify and rule.regex.search(line):
                rep.residual.append(Hit(path, i, rule.name))


def run(src: Path, dst: Path, cfg: Config) -> Report:
    rep = Report()
    verify_rules = [r for r in cfg.rules if r.verify]

    for f in sorted(src.rglob("*")):
        if not f.is_file():
            continue
        rel = f.relative_to(src).as_posix()

        if matches_any(rel, cfg.skip_globs):
            continue
        if matches_any(rel, cfg.block_globs):
            rep.refused.append(rel)                 # never copied, scrubbed, or read
            continue
        if f.suffix.lower() in cfg.binary_suffixes:
            rep.skipped_binary.append(rel)
            continue

        try:
            text = f.read_text(encoding="utf-8")
        except (UnicodeDecodeError, ValueError):
            rep.skipped_binary.append(rel)
            continue

        scrubbed = scrub_text(text, cfg.rules, rel, rep)
        double_check(scrubbed, verify_rules, rel, rep)

        target = dst / rel
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(scrubbed, encoding="utf-8")
        rep.copied.append(rel)

    return rep


# ---- reporting --------------------------------------------------------------

def write_reports(rep: Report, out_dir: Path) -> None:
    j = {
        "summary": {
            "copied": len(rep.copied),
            "redactions": len(rep.hits),
            "files_with_redactions": len({h.path for h in rep.hits}),
            "refused": len(rep.refused),
            "skipped_binary": len(rep.skipped_binary),
            "residual_highrisk": len(rep.residual),
        },
        "refused": rep.refused,
        "residual": [h.__dict__ for h in rep.residual],
        "redactions": [h.__dict__ for h in rep.hits],
        "skipped_binary": rep.skipped_binary,
    }
    (out_dir / "scrub-report.json").write_text(json.dumps(j, indent=2), encoding="utf-8")

    per_file: dict[str, dict[str, int]] = {}
    for h in rep.hits:
        per_file.setdefault(h.path, {}).setdefault(h.rule, 0)
        per_file[h.path][h.rule] += 1

    md = ["# Scrub report", ""]
    s = j["summary"]
    md += [
        f"- Files copied (scrubbed): **{s['copied']}**",
        f"- Redactions: **{s['redactions']}** across **{s['files_with_redactions']}** files",
        f"- Refused (never published): **{s['refused']}**",
        f"- Skipped binary: **{s['skipped_binary']}**",
        f"- Residual high-risk after scrub: **{s['residual_highrisk']}**",
        "",
    ]
    if rep.refused:
        md += ["## Refused — must NOT be published", ""]
        md += [f"- `{p}`" for p in rep.refused] + [""]
    if rep.residual:
        md += ["## Residual high-risk (double-check FAILED)", ""]
        md += [f"- `{h.path}`:{h.line} — {h.rule}" for h in rep.residual] + [""]
    if per_file:
        md += ["## Redactions by file", ""]
        for p in sorted(per_file):
            rules = ", ".join(f"{k}×{v}" for k, v in sorted(per_file[p].items()))
            md.append(f"- `{p}` — {rules}")
        md += [""]
    (out_dir / "scrub-report.md").write_text("\n".join(md), encoding="utf-8")


def die(msg: str) -> None:
    print(f"scrub: {msg}", file=sys.stderr)
    raise SystemExit(2)


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description="Scrub a source tree for open-sourcing.")
    ap.add_argument("--src", required=True, type=Path, help="source tree (read-only)")
    ap.add_argument("--out", required=True, type=Path, help="output dir for the scrubbed copy")
    ap.add_argument("--rules", type=Path,
                    default=Path(__file__).with_name("rules.json"))
    ap.add_argument("--denylist", type=Path, default=None,
                    help="local file of exact secret strings (gitignored; not committed)")
    ap.add_argument("--force", action="store_true", help="overwrite a non-empty --out")
    args = ap.parse_args(argv)

    if not args.src.is_dir():
        die(f"--src is not a directory: {args.src}")
    if args.out.exists() and any(args.out.iterdir()) and not args.force:
        die(f"--out is not empty: {args.out} (use --force)")
    if args.out.resolve() == args.src.resolve() or args.src.resolve() in args.out.resolve().parents:
        die("--out must not be inside --src")

    cfg = load_config(args.rules, args.denylist)
    if args.denylist is None:
        print("scrub: WARNING — no --denylist; only generic patterns applied. "
              "Project-specific hostnames/slugs will NOT be redacted.", file=sys.stderr)

    if args.out.exists() and args.force:
        shutil.rmtree(args.out)
    args.out.mkdir(parents=True, exist_ok=True)

    rep = run(args.src, args.out, cfg)
    write_reports(rep, args.out)

    s = (f"scrub: {len(rep.copied)} copied, {len(rep.hits)} redactions, "
         f"{len(rep.refused)} refused, {len(rep.residual)} residual")
    print(s)

    if rep.refused:
        print("scrub: refused files were present in --src (see scrub-report.md). "
              "They were NOT copied. Exit 1.", file=sys.stderr)
    if rep.residual:
        print("scrub: residual high-risk strings survived scrubbing. "
              "Extend the denylist/patterns. Exit 1.", file=sys.stderr)
    return 1 if (rep.refused or rep.residual) else 0


if __name__ == "__main__":
    raise SystemExit(main())
