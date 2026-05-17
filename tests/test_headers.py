"""Tests for HTTP security header grading."""

from dns_doctor.checks.headers import grade_headers
from dns_doctor.grading import Grade

def test_all_headers_is_A():
    h = {
        "Strict-Transport-Security": "max-age=63072000; includeSubDomains; preload",
        "Content-Security-Policy": "default-src 'self'",
        "X-Content-Type-Options": "nosniff",
        "X-Frame-Options": "DENY",
        "Referrer-Policy": "strict-origin-when-cross-origin",
        "Permissions-Policy": "geolocation=()",
    }
    grade, summary, fixes = grade_headers(h)
    assert grade == Grade.A
    assert fixes == []

def test_no_headers_is_F():
    grade, summary, fixes = grade_headers({})
    assert grade == Grade.F
    assert len(fixes) >= 5

def test_unsafe_inline_dings_csp():
    h = {
        "Strict-Transport-Security": "max-age=31536000",
        "Content-Security-Policy": "default-src 'self' 'unsafe-inline'",
        "X-Content-Type-Options": "nosniff",
        "X-Frame-Options": "DENY",
        "Referrer-Policy": "no-referrer",
        "Permissions-Policy": "geolocation=()",
    }
    grade, summary, fixes = grade_headers(h)
    # Still passing but not A; should have a fix about unsafe-inline
    assert any("unsafe-inline" in f for f in fixes)

def test_hsts_max_age_zero_treated_as_missing():
    h = {"Strict-Transport-Security": "max-age=0"}
    grade, summary, fixes = grade_headers(h)
    assert any("HSTS" in f or "max-age=0" in f for f in fixes)
