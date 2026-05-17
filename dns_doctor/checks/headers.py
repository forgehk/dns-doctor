"""HTTP security-header check.

We grade based on presence + sanity of:
  - Strict-Transport-Security (HSTS)
  - Content-Security-Policy (CSP)
  - X-Content-Type-Options
  - X-Frame-Options / frame-ancestors
  - Referrer-Policy
  - Permissions-Policy
"""

from __future__ import annotations

from typing import Any

from ..grading import Grade
from ..report import CheckResult

def grade_headers(headers: dict[str, str]) -> tuple[Grade, str, list[str]]:
    h = {k.lower(): v for k, v in headers.items()}
    score = 100
    fixes: list[str] = []

    hsts = h.get("strict-transport-security", "")
    if not hsts:
        score -= 25
        fixes.append("Add 'Strict-Transport-Security: max-age=31536000; includeSubDomains'.")
    elif "max-age=0" in hsts:
        score -= 25
        fixes.append("HSTS max-age=0 disables HSTS — set a real value.")

    csp = h.get("content-security-policy", "")
    if not csp:
        score -= 20
        fixes.append("Add a Content-Security-Policy header.")
    elif "unsafe-inline" in csp or "unsafe-eval" in csp:
        score -= 8
        fixes.append("CSP uses unsafe-inline / unsafe-eval — refactor to use nonces or hashes.")

    if "x-content-type-options" not in h:
        score -= 10
        fixes.append("Add 'X-Content-Type-Options: nosniff'.")

    if "x-frame-options" not in h and "frame-ancestors" not in csp:
        score -= 10
        fixes.append("Add 'X-Frame-Options: DENY' (or CSP frame-ancestors).")

    if "referrer-policy" not in h:
        score -= 5
        fixes.append("Add 'Referrer-Policy: strict-origin-when-cross-origin'.")

    if "permissions-policy" not in h:
        score -= 5
        fixes.append("Add a 'Permissions-Policy' header (lock down camera/microphone/geolocation).")

    score = max(0, score)
    grade = Grade.from_score(score)
    have = sum(1 for k in [
        "strict-transport-security", "content-security-policy",
        "x-content-type-options", "x-frame-options",
        "referrer-policy", "permissions-policy"] if k in h)
    return grade, f"{have}/6 headers set, score {score}", fixes

def run(domain: str, fetcher: Any = None) -> CheckResult:
    headers = _fetch_headers(domain, fetcher)
    if headers is None:
        return CheckResult(
            name="Headers",
            grade=Grade.F,
            summary="could not fetch over HTTPS",
            fixes=["Make the site reachable via HTTPS."],
        )
    grade, summary, fixes = grade_headers(headers)
    return CheckResult(
        name="Headers",
        grade=grade,
        summary=summary,
        details={"headers": dict(headers)},
        fixes=fixes,
    )

def _fetch_headers(domain: str, fetcher: Any = None) -> dict[str, str] | None:
    if fetcher is not None:
        return fetcher(domain)
    try:
        import httpx
    except ImportError:
        return None
    try:
        r = httpx.get(f"https://{domain}", timeout=10.0, follow_redirects=True)
        return dict(r.headers)
    except Exception:
        return None
