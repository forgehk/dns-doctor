"""dns-doctor CLI."""

from __future__ import annotations

import argparse
import sys

from .audit import audit

def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="dns-doctor",
        description="Audit DNS, TLS, email-auth, and HTTP-security posture for a domain.",
    )
    sub = parser.add_subparsers(dest="command", required=True)

    a = sub.add_parser("audit", help="Audit a single domain.")
    a.add_argument("domain", help="Domain name to audit (e.g. example.com).")
    a.add_argument("--json", action="store_true", help="Emit JSON instead of a text report.")

    args = parser.parse_args(argv)

    if args.command == "audit":
        report = audit(args.domain)
        if args.json:
            print(report.render_json())
        else:
            print(report.render_text())
        return 0

    return 1

if __name__ == "__main__":
    sys.exit(main())
