"""Result types and human-readable + JSON renderers."""

from __future__ import annotations

import json
from dataclasses import asdict, dataclass, field
from typing import Any

from .grading import Grade

@dataclass
class CheckResult:
    name: str           # 'DNS', 'TLS', 'SPF', ...
    grade: Grade
    summary: str        # short one-liner shown in the table
    details: dict[str, Any] = field(default_factory=dict)
    fixes: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        d = asdict(self)
        d["grade"] = self.grade.label
        return d

@dataclass
class Report:
    domain: str
    checks: list[CheckResult] = field(default_factory=list)

    @property
    def composite(self) -> str:
        base, mod = Grade.composite([c.grade for c in self.checks])
        return f"{base.label}{mod}"

    def render_text(self) -> str:
        if not self.checks:
            return f"dns-doctor: no checks ran for {self.domain}"
        lines: list[str] = [f"dns-doctor audit {self.domain}", ""]
        name_w = max(len(c.name) for c in self.checks)
        for c in self.checks:
            lines.append(f"  {c.name:<{name_w}}  {c.grade.label}   {c.summary}")
        lines.append("")
        lines.append(f"  Overall: {self.composite}")
        top_fixes = [f for c in self.checks for f in c.fixes][:3]
        if top_fixes:
            lines.append("  Top fixes: " + "; ".join(top_fixes))
        return "\n".join(lines)

    def render_json(self) -> str:
        return json.dumps(
            {
                "domain": self.domain,
                "composite": self.composite,
                "checks": [c.to_dict() for c in self.checks],
            },
            indent=2,
        )
