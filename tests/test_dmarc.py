"""Tests for DMARC parsing and grading."""

from dns_doctor.checks.dmarc import parse_dmarc, grade_dmarc
from dns_doctor.grading import Grade

def test_parse_basic():
    p = parse_dmarc("v=DMARC1; p=reject; rua=mailto:r@example.com; pct=100;")
    assert p["v"] == "DMARC1"
    assert p["p"] == "reject"
    assert p["rua"] == "mailto:r@example.com"
    assert p["pct"] == "100"

def test_reject_with_rua_is_A():
    p = parse_dmarc("v=DMARC1; p=reject; rua=mailto:r@e.com")
    grade, summary, fixes = grade_dmarc(p)
    assert grade == Grade.A
    assert fixes == []

def test_quarantine_with_rua_is_B():
    p = parse_dmarc("v=DMARC1; p=quarantine; rua=mailto:r@e.com")
    grade, summary, fixes = grade_dmarc(p)
    assert grade == Grade.B

def test_p_none_is_D():
    p = parse_dmarc("v=DMARC1; p=none")
    grade, summary, fixes = grade_dmarc(p)
    assert grade == Grade.D

def test_missing_is_F():
    p = parse_dmarc("not a dmarc record")
    grade, summary, fixes = grade_dmarc(p)
    assert grade == Grade.F

def test_reject_without_rua_is_C():
    p = parse_dmarc("v=DMARC1; p=reject")
    grade, summary, fixes = grade_dmarc(p)
    assert grade == Grade.C
