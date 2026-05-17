# dns-doctor

> One command to audit a domain's DNS, TLS, email-auth, and HTTP-security posture. Gives you a letter grade and a punch list.

[![Python](https://img.shields.io/badge/Python-3.11+-3776AB.svg)]() [![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

---

## What it does

You run:

```bash
dns-doctor audit darkforgeai.com
```

and get back a graded report covering:

| Check | What it looks for |
|---|---|
| **DNS** | A / AAAA / MX / NS / CAA records, response sanity, mismatched NS |
| **TLS** | Cert validity, chain, hostname match, expiry window, key size, weak ciphers |
| **SPF** | Present, syntactically valid, hard fail at the end, no `+all` traps |
| **DKIM** | Common selectors (`google`, `selector1`, `default`, `k1`, `mailo`), key size |
| **DMARC** | Present, policy strength (`reject` > `quarantine` > `none`), `rua` reporter |
| **MTA-STS / TLS-RPT** | Modern email TLS-enforcement policies |
| **HTTP headers** | HSTS, CSP, X-Content-Type-Options, X-Frame-Options, Referrer-Policy, Permissions-Policy |
| **Mixed content / redirects** | HTTPS upgrade behavior, redirect chains |

Every check ends in a single letter grade: `A`, `B`, `C`, `D`, `F`.

---

## Sample output

```
dns-doctor audit example.com

  DNS         A   apex resolves · 4 A records · MX records present
  TLS         A   valid, 84 days remaining, 2048-bit RSA, chain ok
  SPF         B   present, but ends in '~all' instead of '-all'
  DKIM        A   selector 'google' present, 2048-bit key
  DMARC       D   p=none — does not actually enforce anything
  MTA-STS     F   no policy
  HSTS        A   max-age=63072000; includeSubDomains; preload
  CSP         C   present, but uses 'unsafe-inline' on scripts

  Overall: C+
  Top fixes: tighten DMARC to p=quarantine; add MTA-STS policy; drop 'unsafe-inline'.
```

---

## Why I built this

While running DarkForge AI I configure DNS, SSL, SPF, DKIM, DMARC, and HTTP security headers on every site I deploy. Doing the audit manually with `dig`, `openssl s_client`, and `curl -I` got tedious — `dns-doctor` is the one-shot version of that checklist.

It's also a good showpiece for **AppSec / DevSecOps** interviews because it ties together:
- DNS resolution and record parsing
- TLS/cert validation against the system trust store
- Email-auth chain (SPF → DKIM → DMARC → BIMI)
- Web security headers
- Heuristic scoring and report generation

---

## Install & run

```bash
pip install dns-doctor

# basic
dns-doctor audit darkforgeai.com

# json output (pipe into jq, ship to a dashboard)
dns-doctor audit darkforgeai.com --json

# audit a list
echo "darkforgeai.com\nexample.com" | dns-doctor audit-list -
```

Requires Python 3.11+. Uses `dnspython`, `cryptography`, and `httpx` — no external network tools shelled out.

---

## How it's structured

```
dns_doctor/
├── cli.py              # argparse entry point
├── audit.py            # orchestrator — runs each check, builds report
├── checks/
│   ├── dns_records.py  # A / AAAA / MX / NS / CAA
│   ├── tls.py          # cert chain, expiry, key size
│   ├── spf.py          # parse SPF TXT, grade end-mechanism
│   ├── dkim.py         # selector lookup + key validation
│   ├── dmarc.py        # parse _dmarc TXT, grade policy
│   ├── mta_sts.py      # MTA-STS + TLS-RPT
│   └── headers.py      # HSTS / CSP / XFO / Permissions-Policy
├── grading.py          # per-check A-F → composite letter grade
└── report.py           # human-readable + json renderers
```

Each `checks/*` module exposes a single `run(domain) -> CheckResult`. Adding a new check is one file.

---

## Roadmap

- [x] All core checks
- [x] Letter grading
- [x] JSON output
- [ ] BIMI (Brand Indicators for Message Identification)
- [ ] Subdomain takeover detection (CNAME-to-dangling-cloud-resource)
- [ ] CAA misconfiguration warnings
- [ ] HTML report with diffs over time
- [ ] GitHub Action wrapper

---

## License

[MIT](LICENSE)

---

*Built by [@forgehk](https://github.com/forgehk) — [DarkForge AI](https://darkforgeai.com)*
