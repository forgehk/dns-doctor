"""SPF record check.

Grades:
  A — present + hard-fail (-all)
  B — present + soft-fail (~all)
  C — present + neutral (?all) or no qualifier
  D — present but ends in +all (open relay)
  F — missing
"""

from __future__ import annotations

import re
from typing import Any

from ..grading import Grade
from ..report import CheckResult

def parse_spf(record: str) -> dict[str, Any]:
    """Return a small structural summary of an SPF record."""
    parts = record.strip().split()
    if not parts or parts[0].lower() != "v=spf1":
        return {"valid": False}
    final = parts[-1].lower()
    info = {
        "valid": True,
        "mechanisms": parts[1:-1],
        "final": final,
        "includes": [p[len("include:"):] for p in parts if p.lower().startswith("include:")],
    }
    return info

def grade_spf(parsed: dict[str, Any]) -> tuple[Grade, str, list[str]]:
    if not parsed.get("valid"):
        return (
            Grade.F,
            "no v=spf1 record",
            ["Publish an SPF TXT record: 'v=spf1 include:_spf.<provider> -all'."],
        )
    final = parsed["final"]
    if final == "-all":
        return Grade.A, f"hard fail (-all), {len(parsed['includes'])} includes", []
    if final == "~all":
        return (
            Grade.B,
            "soft fail (~all)",
            ["Tighten SPF to '-all' once you've confirmed all senders are in the record."],
        )
    if final in {"?all", "all"}:
        return (
            Grade.C,
            f"neutral ({final})",
            ["Change SPF final mechanism to '-all'."],
        )
    if final == "+all":
        return (
            Grade.D,
            "+all (open relay!)",
            ["URGENT: +all means anyone can send as you. Change to '-all' immediately."],
        )
    return Grade.C, f"unusual final mechanism: {final}", ["Review SPF final mechanism."]

def run(domain: str, resolver: Any = None) -> CheckResult:
    """Query SPF TXT and grade it."""
    record = _fetch_spf(domain, resolver)
    if record is None:
        return CheckResult(
            name="SPF",
            grade=Grade.F,
            summary="missing",
            fixes=["Publish SPF: 'v=spf1 -all' as a starting point."],
        )
    parsed = parse_spf(record)
    grade, summary, fixes = grade_spf(parsed)
    return CheckResult(
        name="SPF",
        grade=grade,
        summary=summary,
        details={"record": record, "parsed": parsed},
        fixes=fixes,
    )

def _fetch_spf(domain: str, resolver: Any = None) -> str | None:
    try:
        import dns.resolver
    except ImportError:
        return None
    r = resolver or dns.resolver.Resolver()
    try:
        answers = r.resolve(domain, "TXT")
    except Exception:
        return None
    for rdata in answers:
        # rdata.strings is a list of bytes; join them
        try:
            text = b"".join(rdata.strings).decode("utf-8", errors="ignore")
        except Exception:
            text = str(rdata)
        if re.match(r"v=spf1\b", text, re.IGNORECASE):
            return text
    return None
