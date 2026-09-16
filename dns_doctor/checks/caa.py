"""CAA record check (RFC 8659).

CAA records say which Certificate Authorities are allowed to issue for a
domain. The failure modes we care about are the ones that either leave
issuance wide open or quietly break renewals:

  A — at least one CA authorised, plus an `iodef` contact for violation reports
  B — at least one CA authorised, no `iodef` contact
  C — no CAA records at all: any public CA may issue for this domain
  D — CAA present but every `issue` property is ';' — no CA may issue, which
      breaks certificate renewal
  F — an unrecognised property carries the critical flag, so a conforming CA
      must refuse to issue
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any

from ..grading import Grade
from ..report import CheckResult

# Property tags defined by RFC 8659 / RFC 9495.
KNOWN_TAGS = {"issue", "issuewild", "issuemail", "iodef", "contactemail", "contactphone"}

CRITICAL_BIT = 0b1000_0000

_RECORD_RE = re.compile(
    r"""^\s*(?P<flags>\d+)\s+(?P<tag>[A-Za-z0-9]+)\s+(?P<value>.*?)\s*$"""
)


@dataclass(frozen=True)
class CaaRecord:
    flags: int
    tag: str
    value: str

    @property
    def critical(self) -> bool:
        """True when the issuer-critical flag is set."""
        return bool(self.flags & CRITICAL_BIT)

    @property
    def forbids_issuance(self) -> bool:
        """True for `issue ";"`, the RFC 8659 way of saying 'no CA may issue'."""
        return self.tag in {"issue", "issuewild"} and self.value.strip(" ;") == ""


def parse_caa(records: list[str]) -> list[CaaRecord]:
    """Parse CAA records in presentation format, e.g. `0 issue "letsencrypt.org"`.

    Unparseable lines are skipped rather than raising: a single malformed
    record should not take the whole check down.
    """
    out: list[CaaRecord] = []
    for raw in records:
        m = _RECORD_RE.match(raw)
        if not m:
            continue
        value = m.group("value").strip()
        if len(value) >= 2 and value[0] == value[-1] and value[0] in "\"'":
            value = value[1:-1]
        try:
            flags = int(m.group("flags"))
        except ValueError:
            continue
        out.append(CaaRecord(flags=flags, tag=m.group("tag").lower(), value=value))
    return out


def issuers(records: list[CaaRecord]) -> list[str]:
    """CA domains authorised to issue, ignoring `;` (deny-all) entries."""
    return [
        r.value.split(";", 1)[0].strip()
        for r in records
        if r.tag in {"issue", "issuewild"} and not r.forbids_issuance and r.value.strip()
    ]


def grade_caa(records: list[CaaRecord]) -> tuple[Grade, str, list[str]]:
    if not records:
        return Grade.C, "no CAA records — any CA may issue", [
            'Publish CAA, e.g. \'example.com. CAA 0 issue "letsencrypt.org"\'.'
        ]

    critical_unknown = [r for r in records if r.critical and r.tag not in KNOWN_TAGS]
    if critical_unknown:
        tags = ", ".join(sorted({r.tag for r in critical_unknown}))
        return Grade.F, f"critical flag on unrecognised tag: {tags}", [
            f"Drop the critical flag from CAA tag(s) {tags} — a conforming CA "
            "must refuse issuance it cannot understand."
        ]

    allowed = issuers(records)
    if not allowed:
        return Grade.D, "CAA forbids all issuance (issue \";\")", [
            "CAA denies every CA — certificate renewal will fail. Authorise "
            "your CA, or remove the records if the block is unintentional."
        ]

    fixes: list[str] = []
    unknown = sorted({r.tag for r in records if r.tag not in KNOWN_TAGS})
    if unknown:
        fixes.append(f"Unrecognised CAA tag(s): {', '.join(unknown)} — check for typos.")

    shown = ", ".join(sorted(set(allowed))[:3])
    if not any(r.tag == "iodef" for r in records):
        fixes.append(
            "Add 'iodef' (e.g. 0 iodef \"mailto:security@example.com\") to be "
            "told about unauthorised issuance attempts."
        )
        return Grade.B, f"authorises {shown}, no iodef contact", fixes

    return Grade.A, f"authorises {shown}, iodef contact set", fixes


def run(domain: str, resolver: Any = None) -> CheckResult:
    raw = _fetch_caa(domain, resolver)
    records = parse_caa(raw)
    grade, summary, fixes = grade_caa(records)
    return CheckResult(
        name="CAA",
        grade=grade,
        summary=summary,
        details={
            "records": raw,
            "issuers": issuers(records),
        },
        fixes=fixes,
    )


def _fetch_caa(domain: str, resolver: Any = None) -> list[str]:
    try:
        import dns.resolver
    except ImportError:
        return []
    r = resolver or dns.resolver.Resolver()
    try:
        answers = r.resolve(domain, "CAA")
    except Exception:
        return []
    return [str(rdata) for rdata in answers]
