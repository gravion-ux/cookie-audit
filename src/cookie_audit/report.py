"""Text, JSON, and Markdown rendering of audit results."""

from __future__ import annotations

import json
from collections import Counter

from .checks import AuditResult


def _severity_counts(result: AuditResult) -> dict[str, int]:
    counts = Counter(f.severity for f in result.findings)
    return {level: counts.get(level, 0) for level in ("critical", "high", "medium", "low", "info")}


def render_text(result: AuditResult) -> str:
    lines = [
        "cookie-audit report",
        f"Cookies audited: {len(result.cookies)}",
        f"Risk score: {result.risk_score}/100",
        "",
    ]
    if not result.findings:
        lines.append("No findings. All cookies passed every check.")
        return "\n".join(lines) + "\n"

    by_cookie: dict[str, list] = {}
    for finding in result.findings:
        by_cookie.setdefault(finding.cookie, []).append(finding)

    for cookie in result.cookies:
        score = result.cookie_scores.get(cookie.name, 0)
        lines.append(f"Cookie: {cookie.name} (risk {score}/100)")
        for finding in by_cookie.get(cookie.name, []):
            lines.append(f"  [{finding.severity.upper()}] {finding.check_id}: {finding.message}")
            lines.append(f"    Fix: {finding.remediation}")
        if cookie.name not in by_cookie:
            lines.append("  No findings.")
        lines.append("")

    counts = _severity_counts(result)
    summary = ", ".join(f"{level}={count}" for level, count in counts.items() if count)
    lines.append(f"Findings: {len(result.findings)} ({summary})")
    return "\n".join(lines) + "\n"


def render_json(result: AuditResult) -> str:
    payload = {
        "risk_score": result.risk_score,
        "cookie_count": len(result.cookies),
        "finding_count": len(result.findings),
        "severity_counts": _severity_counts(result),
        "cookies": [
            {
                "name": cookie.name,
                "risk_score": result.cookie_scores.get(cookie.name, 0),
                "secure": cookie.secure,
                "httponly": cookie.httponly,
                "samesite": cookie.samesite,
                "path": cookie.path,
                "domain": cookie.domain,
            }
            for cookie in result.cookies
        ],
        "findings": [
            {
                "cookie": f.cookie,
                "check_id": f.check_id,
                "severity": f.severity,
                "message": f.message,
                "remediation": f.remediation,
            }
            for f in result.findings
        ],
    }
    return json.dumps(payload, indent=2) + "\n"


def render_markdown(result: AuditResult) -> str:
    lines = [
        "# cookie-audit report",
        "",
        f"- Cookies audited: {len(result.cookies)}",
        f"- Risk score: **{result.risk_score}/100**",
        f"- Findings: {len(result.findings)}",
        "",
    ]
    if not result.findings:
        lines.append("No findings. All cookies passed every check.")
        return "\n".join(lines) + "\n"

    lines += [
        "| Cookie | Severity | Check | Finding | Remediation |",
        "| --- | --- | --- | --- | --- |",
    ]
    for f in result.findings:
        lines.append(
            f"| {f.cookie} | {f.severity} | {f.check_id} | {f.message} | {f.remediation} |"
        )
    lines.append("")
    lines += ["## Per-cookie risk", ""]
    for cookie in result.cookies:
        lines.append(f"- `{cookie.name}`: {result.cookie_scores.get(cookie.name, 0)}/100")
    return "\n".join(lines) + "\n"


RENDERERS = {
    "text": render_text,
    "json": render_json,
    "markdown": render_markdown,
}
