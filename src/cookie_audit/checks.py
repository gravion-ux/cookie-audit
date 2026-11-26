"""Security checks and risk scoring for parsed cookies."""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from datetime import datetime

from .parser import Cookie

SEVERITY_ORDER: dict[str, int] = {
    "info": 0,
    "low": 1,
    "medium": 2,
    "high": 3,
    "critical": 4,
}

SEVERITY_WEIGHTS: dict[str, int] = {
    "info": 1,
    "low": 5,
    "medium": 12,
    "high": 25,
    "critical": 40,
}

MAX_LIFETIME_DAYS = 400

_SENSITIVE_SUBSTRINGS = (
    "session",
    "sessid",
    "auth",
    "token",
    "jwt",
    "password",
    "passwd",
    "secret",
    "credential",
    "login",
)
_SENSITIVE_TOKENS = {"sid", "sess", "sessid", "pwd", "remember"}
_VALID_SAMESITE = {"strict", "lax", "none"}


@dataclass
class Finding:
    cookie: str
    check_id: str
    severity: str
    message: str
    remediation: str


@dataclass
class AuditResult:
    cookies: list[Cookie]
    findings: list[Finding]
    cookie_scores: dict[str, int] = field(default_factory=dict)

    @property
    def risk_score(self) -> int:
        """Overall 0-100 risk score, driven by the worst cookie."""
        if not self.cookie_scores:
            return 0
        return max(self.cookie_scores.values())


def is_sensitive_name(name: str) -> bool:
    """Heuristic: does this cookie name look like it carries credentials?"""
    lowered = name.lower()
    if any(part in lowered for part in _SENSITIVE_SUBSTRINGS):
        return True
    tokens = set(re.split(r"[^a-z0-9]+", lowered))
    return bool(tokens & _SENSITIVE_TOKENS)


def score_findings(findings: list[Finding]) -> int:
    """Map a cookie's findings to a 0-100 risk score."""
    total = sum(SEVERITY_WEIGHTS[f.severity] for f in findings)
    return min(100, total)


def check_cookie(
    cookie: Cookie,
    *,
    now: datetime | None = None,
    host: str | None = None,
) -> list[Finding]:
    findings: list[Finding] = []
    sensitive = is_sensitive_name(cookie.name)

    def add(check_id: str, severity: str, message: str, remediation: str) -> None:
        findings.append(
            Finding(
                cookie=cookie.name,
                check_id=check_id,
                severity=severity,
                message=message,
                remediation=remediation,
            )
        )

    # Secure / HttpOnly. Sensitive cookies missing either flag are the
    # classic session-theft setup, so they escalate to high severity.
    if not cookie.secure:
        add(
            "missing-secure",
            "high" if sensitive else "medium",
            "Cookie is sent over plain HTTP (no Secure attribute).",
            "Add the Secure attribute so the cookie is only sent over HTTPS.",
        )
    if not cookie.httponly:
        add(
            "missing-httponly",
            "high" if sensitive else "medium",
            "Cookie is readable from JavaScript (no HttpOnly attribute).",
            "Add the HttpOnly attribute so scripts cannot read the cookie.",
        )

    # SameSite
    samesite = cookie.samesite
    if samesite is None:
        add(
            "samesite-missing",
            "medium" if sensitive else "low",
            "No SameSite attribute; cross-site sending relies on browser defaults.",
            "Set SameSite=Lax or SameSite=Strict unless cross-site use is required.",
        )
    elif samesite.strip().lower() not in _VALID_SAMESITE:
        add(
            "samesite-invalid",
            "medium",
            f"SameSite value {samesite!r} is not Strict, Lax, or None.",
            "Use SameSite=Strict, SameSite=Lax, or SameSite=None with Secure.",
        )
    elif samesite.strip().lower() == "none" and not cookie.secure:
        add(
            "samesite-none-without-secure",
            "high",
            "SameSite=None without Secure; browsers reject this combination.",
            "Add Secure, or switch to SameSite=Lax/Strict.",
        )

    # Lifetime
    lifetime = cookie.lifetime_days(now)
    if lifetime is not None and lifetime > MAX_LIFETIME_DAYS:
        add(
            "expiry-too-long",
            "high" if sensitive else "medium",
            f"Cookie lifetime is about {lifetime:.0f} days "
            f"(limit {MAX_LIFETIME_DAYS} days).",
            f"Reduce Max-Age/Expires to at most {MAX_LIFETIME_DAYS} days.",
        )
    if cookie.is_session_cookie and sensitive:
        add(
            "session-sensitive-cookie",
            "info",
            "Sensitive cookie has no expiry (browser-session lifetime).",
            "Confirm the session lifetime is intentional; consider an "
            "explicit, bounded Max-Age for sensitive cookies.",
        )

    # __Host- prefix: Secure, Path=/, and no Domain are all mandatory.
    if cookie.name.startswith("__Host-"):
        if not cookie.secure:
            add(
                "host-prefix-secure",
                "high",
                "__Host- cookie is missing Secure; browsers will reject it.",
                "Add the Secure attribute.",
            )
        if cookie.path != "/":
            add(
                "host-prefix-path",
                "high",
                "__Host- cookie does not set Path=/; browsers will reject it.",
                "Set Path=/ on __Host- cookies.",
            )
        if cookie.domain is not None:
            add(
                "host-prefix-domain",
                "high",
                "__Host- cookie sets a Domain attribute; browsers will reject it.",
                "Remove the Domain attribute from __Host- cookies.",
            )

    # __Secure- prefix: Secure is mandatory.
    if cookie.name.startswith("__Secure-") and not cookie.secure:
        add(
            "secure-prefix-secure",
            "high",
            "__Secure- cookie is missing Secure; browsers will reject it.",
            "Add the Secure attribute.",
        )

    # Overly broad Domain scope.
    if cookie.domain:
        domain = cookie.domain.lstrip(".").lower()
        labels = [part for part in domain.split(".") if part]
        host_lower = host.lower() if host else None
        if len(labels) < 2:
            add(
                "domain-too-broad",
                "high",
                f"Domain={cookie.domain} is a single label and matches "
                "far more hosts than intended.",
                "Scope the cookie to a specific host or registrable domain.",
            )
        elif (
            sensitive
            and host_lower
            and host_lower != domain
            and host_lower.endswith("." + domain)
        ):
            add(
                "domain-too-broad",
                "medium",
                f"Sensitive cookie is shared with every subdomain of {domain}.",
                "Omit Domain (host-only cookie) or narrow it to the exact host.",
            )
        elif sensitive and len(labels) == 2:
            add(
                "domain-too-broad",
                "medium",
                f"Sensitive cookie is scoped to {domain} and all its subdomains.",
                "Omit Domain (host-only cookie) or narrow it to the exact host.",
            )

    # Path=/ exposes a sensitive cookie to every path on the host.
    # __Host- cookies are exempt: Path=/ is mandatory for them.
    if sensitive and cookie.path == "/" and not cookie.name.startswith("__Host-"):
        add(
            "path-root-sensitive",
            "low",
            "Sensitive cookie uses Path=/ and is sent to every path on the host.",
            "Narrow Path to the application path that needs the cookie.",
        )

    return findings


def check_cookies(
    cookies: list[Cookie],
    *,
    now: datetime | None = None,
    host: str | None = None,
) -> AuditResult:
    findings: list[Finding] = []
    cookie_scores: dict[str, int] = {}
    for cookie in cookies:
        cookie_findings = check_cookie(cookie, now=now, host=host)
        findings.extend(cookie_findings)
        score = score_findings(cookie_findings)
        # A response may set the same cookie name more than once. Keep the
        # worst score for that name so a later clean cookie cannot hide an
        # earlier risky one in the overall result.
        cookie_scores[cookie.name] = max(cookie_scores.get(cookie.name, 0), score)
    return AuditResult(cookies=cookies, findings=findings, cookie_scores=cookie_scores)
