"""Basic DNS sanity: A / AAAA / MX / NS."""

from __future__ import annotations

from typing import Any

from ..grading import Grade
from ..report import CheckResult

def run(domain: str, resolver: Any = None) -> CheckResult:
    try:
        import dns.resolver
    except ImportError:
        return CheckResult(name="DNS", grade=Grade.F, summary="dnspython not installed")

    r = resolver or dns.resolver.Resolver()

    def safe(rtype: str) -> list[str]:
        try:
            return [str(x) for x in r.resolve(domain, rtype)]
        except Exception:
            return []

    a = safe("A")
    aaaa = safe("AAAA")
    mx = safe("MX")
    ns = safe("NS")

    fixes: list[str] = []
    if not a and not aaaa:
        return CheckResult(
            name="DNS",
            grade=Grade.F,
            summary="domain does not resolve to any IP",
            fixes=["Add an A or AAAA record for the apex."],
        )

    grade = Grade.A
    summary_parts: list[str] = [f"{len(a)} A", f"{len(aaaa)} AAAA"]
    if mx:
        summary_parts.append(f"{len(mx)} MX")
    else:
        # MX absence isn't a fail — many static sites don't accept mail.
        summary_parts.append("0 MX")
    summary_parts.append(f"{len(ns)} NS")

    if not aaaa:
        grade = Grade.B
        fixes.append("Add IPv6 (AAAA) records.")
    if not ns:
        grade = Grade.D
        fixes.append("NS records not resolving — check delegation.")

    return CheckResult(
        name="DNS",
        grade=grade,
        summary=" · ".join(summary_parts),
        details={"a": a, "aaaa": aaaa, "mx": mx, "ns": ns},
        fixes=fixes,
    )
