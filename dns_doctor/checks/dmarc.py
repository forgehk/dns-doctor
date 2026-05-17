"""DMARC record check.

Grades:
  A — p=reject + rua reporter configured
  B — p=quarantine + rua reporter configured
  C — p=reject or p=quarantine, no rua reporter (no visibility)
  D — p=none (visibility only, not enforced)
  F — missing
"""

from __future__ import annotations

import re
from typing import Any

from ..grading import Grade
from ..report import CheckResult

def parse_dmarc(record: str) -> dict[str, str]:
    """Parse 'v=DMARC1; p=reject; rua=...; ...' into a dict."""
    out: dict[str, str] = {}
    for part in record.split(";"):
        part = part.strip()
        if "=" in part:
            k, v = part.split("=", 1)
            out[k.strip().lower()] = v.strip()
    return out

def grade_dmarc(parsed: dict[str, str]) -> tuple[Grade, str, list[str]]:
    v = parsed.get("v", "").upper()
    if v != "DMARC1":
        return Grade.F, "no v=DMARC1", ["Publish a DMARC record."]
    p = parsed.get("p", "").lower()
    has_rua = "rua" in parsed
    if p == "reject":
        if has_rua:
            return Grade.A, "p=reject with rua reporter", []
        return Grade.C, "p=reject, but no rua reporter", [
            "Add 'rua=mailto:dmarc-reports@yourdomain' to get visibility."
        ]
    if p == "quarantine":
        if has_rua:
            return Grade.B, "p=quarantine with rua reporter", [
                "Once aggregate reports are clean, tighten to p=reject."
            ]
        return Grade.C, "p=quarantine, no rua reporter", [
            "Add 'rua=' tag; review aggregate reports; then move to p=reject."
        ]
    if p == "none":
        return Grade.D, "p=none — visibility only, not enforced", [
            "Once you've reviewed reports, move from p=none to p=quarantine."
        ]
    return Grade.D, f"unknown p value: {p!r}", ["Set DMARC p= to none, quarantine, or reject."]

def run(domain: str, resolver: Any = None) -> CheckResult:
    record = _fetch_dmarc(domain, resolver)
    if record is None:
        return CheckResult(
            name="DMARC",
            grade=Grade.F,
            summary="missing",
            fixes=["Publish '_dmarc.<domain> TXT v=DMARC1; p=none; rua=mailto:...'"],
        )
    parsed = parse_dmarc(record)
    grade, summary, fixes = grade_dmarc(parsed)
    return CheckResult(
        name="DMARC",
        grade=grade,
        summary=summary,
        details={"record": record, "parsed": parsed},
        fixes=fixes,
    )

def _fetch_dmarc(domain: str, resolver: Any = None) -> str | None:
    try:
        import dns.resolver
    except ImportError:
        return None
    r = resolver or dns.resolver.Resolver()
    try:
        answers = r.resolve(f"_dmarc.{domain}", "TXT")
    except Exception:
        return None
    for rdata in answers:
        try:
            text = b"".join(rdata.strings).decode("utf-8", errors="ignore")
        except Exception:
            text = str(rdata)
        if re.match(r"v=DMARC1\b", text, re.IGNORECASE):
            return text
    return None
