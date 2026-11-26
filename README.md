# cookie-audit

A cookie security analyzer. `cookie-audit` parses `Set-Cookie` headers and
flags the misconfigurations that lead to session theft and CSRF: missing
`Secure`/`HttpOnly`, weak or invalid `SameSite`, `__Host-`/`__Secure-`
prefix-rule violations, over-long lifetimes, and overly broad `Domain`/`Path`
scopes. Every finding carries a severity and a concrete remediation, and each
cookie gets a 0–100 risk score.

Pure Python standard library — no runtime dependencies.

## Install

```bash
pip install -e .
```

## Usage

Audit headers from a file (one `Set-Cookie` header per line):

```bash
cookie-audit --file headers.txt
```

Pipe headers on stdin:

```bash
curl -sI https://example.com/login | grep -i '^set-cookie' | cookie-audit
```

Fetch a URL directly and audit the cookies it sets:

```bash
cookie-audit --url https://example.com/login
```

Choose a report format and the severity that fails the run:

```bash
cookie-audit --file headers.txt --format json --fail-on high
cookie-audit --file headers.txt --format markdown > report.md
```

Options:

| Option | Description |
| --- | --- |
| `--file PATH` | Read headers from `PATH` (`-` reads stdin). Default: stdin when piped. |
| `--url URL` | Fetch `URL` and audit its `Set-Cookie` headers. |
| `--format {text,json,markdown}` | Report format (default: `text`). |
| `--fail-on {info,low,medium,high,critical}` | Exit 1 when a finding is at or above this severity (default: `medium`). |
| `--host HOST` | Host the cookies belong to; sharpens `Domain` scope checks. Defaults to the `--url` host. |

Exit codes: `0` = no findings at or above `--fail-on`, `1` = findings at or
above `--fail-on`, `2` = usage or input error.

## Example

Input (`headers.txt`):

```text
session_token=abc; Path=/
theme=dark; Secure; HttpOnly; SameSite=Lax; Max-Age=86400; Path=/app
```

Output:

```text
cookie-audit report
Cookies audited: 2
Risk score: 68/100

Cookie: session_token (risk 68/100)
  [HIGH] missing-secure: Cookie is sent over plain HTTP (no Secure attribute).
    Fix: Add the Secure attribute so the cookie is only sent over HTTPS.
  [HIGH] missing-httponly: Cookie is readable from JavaScript (no HttpOnly attribute).
    Fix: Add the HttpOnly attribute so scripts cannot read the cookie.
  [MEDIUM] samesite-missing: No SameSite attribute; cross-site sending relies on browser defaults.
    Fix: Set SameSite=Lax or SameSite=Strict unless cross-site use is required.
  [INFO] session-sensitive-cookie: Sensitive cookie has no expiry (browser-session lifetime).
    Fix: Confirm the session lifetime is intentional; consider an explicit, bounded Max-Age for sensitive cookies.
  [LOW] path-root-sensitive: Sensitive cookie uses Path=/ and is sent to every path on the host.
    Fix: Narrow Path to the application path that needs the cookie.

Cookie: theme (risk 0/100)
  No findings.

Findings: 5 (high=2, medium=1, low=1, info=1)
```

## Checks

| Check | Severity | What it catches |
| --- | --- | --- |
| `missing-secure` | medium (high if sensitive) | Cookie sent over plain HTTP |
| `missing-httponly` | medium (high if sensitive) | Cookie readable from JavaScript |
| `samesite-missing` | low (medium if sensitive) | No `SameSite` attribute |
| `samesite-invalid` | medium | `SameSite` value other than Strict/Lax/None |
| `samesite-none-without-secure` | high | `SameSite=None` without `Secure` (browsers reject it) |
| `expiry-too-long` | medium (high if sensitive) | Lifetime over 400 days |
| `session-sensitive-cookie` | info | Sensitive cookie with browser-session lifetime |
| `host-prefix-secure` / `host-prefix-path` / `host-prefix-domain` | high | `__Host-` cookie missing `Secure`, missing `Path=/`, or setting `Domain` |
| `secure-prefix-secure` | high | `__Secure-` cookie missing `Secure` |
| `domain-too-broad` | medium–high | Single-label `Domain`, or a sensitive cookie shared across subdomains |
| `path-root-sensitive` | low | Sensitive cookie scoped to `Path=/` |

A cookie name is treated as **sensitive** when it looks like it carries
credentials (`session`, `auth`, `token`, `password`, `sid`, …). Sensitive
cookies missing `Secure` or `HttpOnly` escalate to high severity.

## Risk score

Each cookie scores 0–100 from its findings (info=1, low=5, medium=12,
high=25, critical=40, capped at 100). The overall risk score is the worst
cookie's score.

## Development

```bash
pip install -e ".[dev]"
pytest
ruff check .
```

## License

MIT — see [LICENSE](LICENSE).
