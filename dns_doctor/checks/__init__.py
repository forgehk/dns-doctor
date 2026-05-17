"""Per-domain checks. Each module exports `run(domain) -> CheckResult`."""

from . import dns_records, headers, spf, dmarc
from .dns_records import run as run_dns
from .spf import run as run_spf
from .dmarc import run as run_dmarc
from .headers import run as run_headers

__all__ = ["dns_records", "headers", "spf", "dmarc",
           "run_dns", "run_spf", "run_dmarc", "run_headers"]
