"""Per-domain checks. Each module exports `run(domain) -> CheckResult`."""

from . import caa, dns_records, headers, spf, dmarc
from .dns_records import run as run_dns
from .caa import run as run_caa
from .spf import run as run_spf
from .dmarc import run as run_dmarc
from .headers import run as run_headers

__all__ = ["caa", "dns_records", "headers", "spf", "dmarc",
           "run_dns", "run_caa", "run_spf", "run_dmarc", "run_headers"]
