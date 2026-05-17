"""Tests for the grading module."""

from dns_doctor.grading import Grade

def test_grade_from_score():
    assert Grade.from_score(95) == Grade.A
    assert Grade.from_score(85) == Grade.B
    assert Grade.from_score(75) == Grade.C
    assert Grade.from_score(65) == Grade.D
    assert Grade.from_score(40) == Grade.F

def test_composite_averages():
    base, mod = Grade.composite([Grade.A, Grade.A, Grade.A])
    assert base == Grade.A
    assert mod == ""

def test_composite_mixed():
    base, mod = Grade.composite([Grade.A, Grade.B])
    assert base in {Grade.A, Grade.B}

def test_composite_empty():
    base, mod = Grade.composite([])
    assert base == Grade.F

def test_no_f_minus():
    base, mod = Grade.composite([Grade.F, Grade.F])
    assert base == Grade.F
    assert mod != "-"

def test_no_a_plus_above_average():
    base, mod = Grade.composite([Grade.A, Grade.A, Grade.A, Grade.A])
    assert base == Grade.A
    assert mod != "+"
