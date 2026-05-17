"""Tests for SPF parsing and grading."""

from dns_doctor.checks.spf import parse_spf, grade_spf
from dns_doctor.grading import Grade

def test_parse_basic():
    p = parse_spf("v=spf1 include:_spf.google.com -all")
    assert p["valid"] is True
    assert p["final"] == "-all"
    assert "_spf.google.com" in p["includes"]

def test_parse_invalid():
    p = parse_spf("not an spf record")
    assert p["valid"] is False

def test_grade_hard_fail_is_A():
    p = parse_spf("v=spf1 include:_spf.google.com -all")
    grade, summary, fixes = grade_spf(p)
    assert grade == Grade.A
    assert fixes == []

def test_grade_soft_fail_is_B():
    p = parse_spf("v=spf1 include:_spf.example.com ~all")
    grade, summary, fixes = grade_spf(p)
    assert grade == Grade.B
    assert len(fixes) == 1

def test_grade_plus_all_is_D():
    p = parse_spf("v=spf1 +all")
    grade, summary, fixes = grade_spf(p)
    assert grade == Grade.D
    assert "URGENT" in fixes[0]

def test_missing_is_F():
    p = parse_spf("")
    grade, summary, fixes = grade_spf(p)
    assert grade == Grade.F
