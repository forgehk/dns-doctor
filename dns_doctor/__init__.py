"""dns-doctor: audit DNS, TLS, email-auth, and HTTP-security posture."""

from .grading import Grade
from .report import CheckResult, Report

__version__ = "0.1.0"
__all__ = ["Grade", "CheckResult", "Report"]
