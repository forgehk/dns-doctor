"""Orchestrator: run all checks against a domain and assemble the report."""

from __future__ import annotations

from .checks import run_dns, run_spf, run_dmarc, run_headers
from .report import Report

def audit(domain: str) -> Report:
    """Run all default checks against `domain` and return a Report."""
    domain = domain.strip().lower().rstrip(".")
    report = Report(domain=domain)
    report.checks.append(run_dns(domain))
    report.checks.append(run_spf(domain))
    report.checks.append(run_dmarc(domain))
    report.checks.append(run_headers(domain))
    return report
