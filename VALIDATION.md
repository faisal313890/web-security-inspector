# Verification — Web Security Inspector 0.2.0

Validated on 2026-10-25 in Linux with Python 3.12.14.

## Passed

- 40 tests: `python -m unittest discover -s tests -v`.
- JavaScript syntax: `node --check static/app.js`.
- HTML/JavaScript element-reference consistency, including status count elements.
- Real local HTTP integration: the included demo site and browser-service endpoint completed an inspection and returned findings. The weak route produced more review findings than the hardened route. The hardened HTTP route correctly retained a transport review finding.
- Query-string and cookie-value redaction; report-only versus enforced CSP; HTML applicability; positive/zero/invalid HSTS; frame-ancestors precedence; cookie flags/prefixes; referrer-policy fallback interpretation.
- Redirect scope, downgrade prevention, loops, request limits, and invalid/credential-bearing Location handling.
- DNS address restrictions, mixed public/private answers, public-port restrictions, explicit loopback mode, and the checked-IP/original-host TLS connection design.
- Incomplete network failures did not produce passed checks for unobserved configurations.
- Local GUI endpoint rejects cross-origin requests and serves restrictive response headers.

- Eight additional reporting tests cover context-only cookie omissions, incompatible cookie settings, missing versus zero HSTS, HSTS on IP addresses, report-only CSP evidence, and exported scope limitations.

## User verification of the previous version

The user verified v0.1 on Windows: weak and hardened local routes, JSON/PDF downloads, and a public HTTPS inspection. These observations establish prior-version behavior; v0.2 browser rendering and exports need a local recheck after updating.

## Not verified

- Live public HTTPS inspection: a smoke check against https://example.com stopped at DNS lookup in this execution environment. No public-site findings were fabricated or included in this package.
- Actual browser layout, print dialog, downloads, responsive behavior, and accessibility were not visually tested. JavaScript syntax and UI element references were checked.
- Execution on Windows remains to be verified on the user's machine.
- Live public TLS handshakes were not available; TLS SNI/pinning and failure behavior have automated checks, not a full TLS audit.

## First acceptance check

Start `start_windows.cmd`, then `start_demo.cmd`. Open http://127.0.0.1:8787, inspect both local practice routes, compare findings, export JSON, and print/save a PDF. Then inspect a site you own or are authorized to assess, with public DNS/network access available.
