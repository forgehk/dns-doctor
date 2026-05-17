"""Letter-grade conversion + composite scoring."""

from __future__ import annotations

from enum import IntEnum

class Grade(IntEnum):
    F = 0
    D = 1
    C = 2
    B = 3
    A = 4

    @classmethod
    def from_score(cls, score: float) -> "Grade":
        """Map a 0–100 score to a letter grade."""
        if score >= 90:
            return cls.A
        if score >= 80:
            return cls.B
        if score >= 70:
            return cls.C
        if score >= 60:
            return cls.D
        return cls.F

    @property
    def label(self) -> str:
        return self.name

    @classmethod
    def composite(cls, grades: list["Grade"]) -> tuple["Grade", str]:
        """Average grades, then express with a +/-/'' modifier."""
        if not grades:
            return cls.F, ""
        avg = sum(g.value for g in grades) / len(grades)
        whole = round(avg)
        whole = max(0, min(4, whole))
        base = cls(whole)
        frac = avg - whole
        if frac >= 0.33:
            modifier = "+"
        elif frac <= -0.33:
            modifier = "-"
        else:
            modifier = ""
        # 'A+' is valid; 'F+' is silly — clamp at extremes
        if base == cls.A and modifier == "+":
            modifier = ""
        if base == cls.F and modifier == "-":
            modifier = ""
        return base, modifier
