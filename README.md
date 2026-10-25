# Web Security Inspector

A Python cybersecurity portfolio project that turns HTTP response observations into evidence, explanations, and suggested fixes. Includes a local browser interface, command-line interface, JSON export, printable reports, and a practice website. **No API key, external scanning service, or pip dependency is required.** Python 3.12+ is recommended.

## What version 0.2 checks

| Check | Evidence and interpretation |
|---|---|
| HTTPS transport | Whether the observed response used verified TLS |
| TLS observations | Negotiated protocol and certificate expiry field; not a full TLS configuration audit |
| Redirect chain | Up to six responses; loops, external-scope redirects, and HTTPS downgrades are recorded |
| HTTP root redirect | Optional single request to HTTP `/` to check for an immediate in-scope HTTPS redirect |
| HSTS | A single header with a positive max-age on HTTPS; zero, missing, duplicate, or invalid values need review |
| Enforced CSP | Header presence on HTML responses; report-only is distinguished; policy effectiveness requires review |
| Frame embedding | Recognized restrictive frame-ancestors or X-Frame-Options; custom parent allowlists require review |
| MIME sniffing | X-Content-Type-Options: nosniff |
| Referrer policy | Explicit restrictive response policy; missing does not mean browser defaults are unsafe |
| Cookie attributes | Secure, HttpOnly, SameSite, and __Host-/__Secure- prefix requirements on every observed hop |
| Informational items | Permissions-Policy and selected technology banners |

Findings have **pass**, **review**, **info**, or **skipped** status. A pass means only the specific stated criterion was observed. Missing headers are hardening observations, not proof of an exploitable vulnerability. No overall security score is assigned.

## Changes in v0.2

- Each finding now labels an observed criterion, a hardening observation, a setting requiring application context, or a check not assessed.
- Missing HttpOnly or omitted SameSite alone is informational; incompatible settings and missing Secure still need review. Actual cookie purpose and exploitability remain unknown.
- HSTS wording distinguishes an absent header from a zero/invalid lifetime. Browser preload lists, inherited policies, and stored browser state are explicitly unassessed. HSTS checks are skipped for IP-address targets.
- CSP evidence explicitly shows report-only versus enforced headers. Meta policies and effective policy strength are listed as unassessed.
- The HTTP probe distinguishes server redirect behavior from browser HSTS/preload upgrades.
- Browser and JSON reports list coverage gaps. The completion badge describes the request chain, not a full security assessment.

### Updating from v0.1

Stop the old Inspector CMD process with Ctrl+C. Extract the new ZIP into a separate folder, run its `start_windows.cmd`, and refresh the browser (Ctrl+F5 if needed). The existing demo process may remain running because the lab routes are unchanged. The footer should show v0.2. Existing exported reports are not changed.

## Windows — first run

1. Install Python 3.12 if it is not already available.
2. Extract the ZIP and open the `WebSecurityInspector` folder.
3. Double-click **start_windows.cmd**. Keep its CMD window open.
4. Open **http://127.0.0.1:8787** in your browser.

No virtual environment or package installation is necessary because this version uses the Python standard library only.

Equivalent CMD commands, if the project folder is directly on your Desktop:

```bat
cd /d "%USERPROFILE%\Desktop\WebSecurityInspector"
py -3.12 server.py
```

Press Ctrl+C in CMD to stop. If port 8787 is occupied:

```bat
set "INSPECTOR_PORT=8788"
py -3.12 server.py
```

Then open http://127.0.0.1:8788. On Linux/macOS, run `python3 server.py` with Python 3.12+.

## First practical exercise — included local website

1. Run **start_demo.cmd** in a second window. It serves http://127.0.0.1:8011.
2. Return to the Inspector browser tab and click **Weak headers**.
3. Click **Inspect website**. Review missing CSP, framing, nosniff, referrer-policy, and cookie-attribute observations.
4. Click **Hardened headers**, then inspect again. Compare the evidence and reduced review count.
5. Use **Export JSON** and **Print / Save PDF** to produce report evidence.

Both lab routes use unencrypted local HTTP. The hardened route deliberately still receives an HTTPS-transport review finding and an HSTS skip. It is not presented as a fully secure website.

`/redirect` redirects to `/weak`; `/loop` demonstrates loop detection. The lab has no real credentials, database, uploads, or external dependencies.

## Inspect your own or an authorized website

Enter an HTTP(S) URL. Bare hostnames default to HTTPS. Click **Inspect website**. The tool performs ordinary GET requests and reads response headers; it does not crawl links, submit forms, send attack payloads, or download/analyze response bodies. GET requests can still have application side effects if a target is designed that way, so choose appropriate routes.

Public targets support ports 80/443. The optional localhost checkbox permits loopback lab targets; it does not enable private-LAN or metadata-service addresses. Redirect scope is the entered hostname and its bare-domain/www counterpart only. Other subdomains, external hosts, and HTTPS-to-HTTP downgrades are recorded and not followed. DNS is checked on every requested hop and the connection is pinned to the checked IP while keeping the original HTTP Host and TLS SNI/certificate identity.

The scanner does not bypass TLS certificate failures, rate limits, authentication, or bot challenges. A 403/429 response can be reported as an error-page observation; results may then reflect the block page rather than the intended application. Failed requests and incomplete chains are clearly marked.

## Command-line usage

Replace the example hostname below with your authorized target:

```bat
py -3.12 inspector.py https://your-domain.example --out reports\inspection.json
```

Local lab:

```bat
py -3.12 inspector.py http://127.0.0.1:8011/weak --allow-local --no-http-probe --out reports\lab-weak.json
```

An inspection with a completed chain exits 0; an incomplete chain exits 1; invalid CLI input exits 2. Exit 0 does not mean there are no findings. Console output includes review items. The separate HTTP-root probe is not run for an HTTP starting URL or a nonstandard HTTPS port; the supplied request chain is still inspected.

## Reporting and data handling

Each finding includes its criterion, evidence, meaning, suggested action where relevant, and a reference link. Reports include a unique report ID, UTC observation time, status counts, redacted response-chain details, and limitations.

Cookie values and URL query strings are omitted from reports. Only selected configuration/technology headers are exported; raw Set-Cookie, Authorization, and Location values are not exported. Cookie names, hostnames, security-policy values, and URL paths can still contain sensitive information. Review reports before sharing.

The browser interface keeps the current report in memory and does not deliberately store it on disk. JSON/PDF exports are saved by your browser; CLI output files are written only when `--out` is used. The server suppresses request logging. Targets will see ordinary incoming requests, including the Inspector User-Agent and your network address. OS/browser behavior is outside the app's memory-only guarantee.

## Project structure

```text
inspector.py                  URL handling, transport, checks, CLI
server.py                     Local browser service
static/index.html             Interface
static/style.css              Responsive and print styles
static/app.js                 Inspection requests, findings, export
start_windows.cmd             Start the Inspector on Windows
start_demo.cmd                Start the practice site on Windows
demo.py                       Weak/hardened loopback practice routes
tests/test_inspector.py        Original checks and local integration
tests/test_reporting.py        Reporting interpretation regressions
examples/                     Reports generated from the real local lab
VALIDATION.md                 Verification results and limits
```

The sample reports under `examples` were generated by running the included lab during development. Their targets use the temporary local port assigned during that run; they are evidence examples, not live public-site assessments.

## Tests

From the project folder:

```bat
py -3.12 -m unittest discover -s tests -v
```

## Practical limits

This is a single-user localhost prototype, not a hosted scanner or a complete penetration-testing tool. It has no login/session handling, browser execution, authenticated checks, SQL injection/XSS testing, access-control testing, CORS validation, body/meta-tag analysis, or certificate revocation/cipher-suite audit. CSP presence is not a policy-quality verdict. JavaScript-created cookies and other routes are outside coverage. The HTTP probe checks only the first redirect at `/`, not all routes or the complete HTTP upgrade chain. HSTS preload membership and inherited policies are not checked.

The application binds to localhost, checks incoming Host/Origin and a required custom request header, limits request size, serializes inspections, filters target addresses, and renders findings as text. It has no authentication or multi-user isolation. Keep it local. Outbound requests use a seven-second socket timeout, not a guaranteed whole-scan deadline; DNS and slow responses can take longer. Environment HTTP proxies are not used because connections are pinned directly to validated target IPs.

## References

- CSP: https://developer.mozilla.org/en-US/docs/Web/HTTP/Reference/Headers/Content-Security-Policy
- HSTS: https://developer.mozilla.org/en-US/docs/Web/HTTP/Reference/Headers/Strict-Transport-Security
- Frame restrictions: https://developer.mozilla.org/en-US/docs/Web/HTTP/Reference/Headers/X-Frame-Options
- Cookie configuration: https://developer.mozilla.org/en-US/docs/Web/Security/Practical_implementation_guides/Cookies
- MIME sniffing: https://developer.mozilla.org/en-US/docs/Web/HTTP/Reference/Headers/X-Content-Type-Options
- Referrer policy: https://developer.mozilla.org/en-US/docs/Web/HTTP/Reference/Headers/Referrer-Policy
