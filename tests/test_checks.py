from datetime import UTC, datetime

from cookie_audit.checks import check_cookie, check_cookies, is_sensitive_name
from cookie_audit.parser import parse_set_cookie

NOW = datetime(2026, 1, 1, tzinfo=UTC)


def ids(header, **kwargs):
    cookie = parse_set_cookie(header)
    assert cookie is not None
    return {f.check_id: f for f in check_cookie(cookie, now=NOW, **kwargs)}


def test_clean_cookie_has_no_findings():
    findings = ids("theme=dark; Secure; HttpOnly; SameSite=Lax; Max-Age=86400; Path=/app")
    assert findings == {}


def test_missing_secure_and_httponly_flagged():
    findings = ids("theme=dark; SameSite=Lax; Max-Age=86400")
    assert findings["missing-secure"].severity == "medium"
    assert findings["missing-httponly"].severity == "medium"


def test_sensitive_name_escalates_missing_flags():
    findings = ids("session_token=abc; SameSite=Lax; Max-Age=86400")
    assert findings["missing-secure"].severity == "high"
    assert findings["missing-httponly"].severity == "high"


def test_sensitive_name_heuristics():
    assert is_sensitive_name("PHPSESSID") is True
    assert is_sensitive_name("auth_token") is True
    assert is_sensitive_name("user_password_hint") is True
    assert is_sensitive_name("sid") is True
    assert is_sensitive_name("theme") is False
    assert is_sensitive_name("consent") is False


def test_samesite_missing_invalid_and_none_without_secure():
    assert "samesite-missing" in ids("a=1; Secure; HttpOnly; Max-Age=60")
    assert "samesite-invalid" in ids("a=1; Secure; HttpOnly; SameSite=Sometimes; Max-Age=60")
    findings = ids("a=1; HttpOnly; SameSite=None; Max-Age=60")
    assert findings["samesite-none-without-secure"].severity == "high"


def test_expiry_too_long_via_max_age_and_expires():
    assert "expiry-too-long" in ids(
        "a=1; Secure; HttpOnly; SameSite=Lax; Max-Age=99999999"
    )
    assert "expiry-too-long" in ids(
        "a=1; Secure; HttpOnly; SameSite=Lax; Expires=Wed, 21 Oct 2099 07:28:00 GMT"
    )
    assert "expiry-too-long" not in ids(
        "a=1; Secure; HttpOnly; SameSite=Lax; Max-Age=86400"
    )


def test_session_sensitive_cookie_is_info():
    findings = ids("session=abc; Secure; HttpOnly; SameSite=Strict; Path=/app")
    assert findings["session-sensitive-cookie"].severity == "info"
    assert "session-sensitive-cookie" not in ids(
        "theme=dark; Secure; HttpOnly; SameSite=Lax; Path=/app"
    )


def test_host_prefix_rules():
    findings = ids("__Host-session=abc; HttpOnly; SameSite=Lax; Domain=example.com; Path=/app")
    assert "host-prefix-secure" in findings
    assert "host-prefix-path" in findings
    assert "host-prefix-domain" in findings
    clean = ids("__Host-session=abc; Secure; HttpOnly; SameSite=Lax; Path=/; Max-Age=3600")
    assert clean == {}


def test_secure_prefix_rule():
    findings = ids("__Secure-id=1; HttpOnly; SameSite=Lax; Max-Age=60")
    assert findings["secure-prefix-secure"].severity == "high"
    assert "secure-prefix-secure" not in ids(
        "__Secure-id=1; Secure; HttpOnly; SameSite=Lax; Max-Age=60"
    )


def test_overly_broad_domain():
    single = ids("a=1; Secure; HttpOnly; SameSite=Lax; Domain=com; Max-Age=60")
    assert single["domain-too-broad"].severity == "high"
    sensitive = ids(
        "session=abc; Secure; HttpOnly; SameSite=Lax; Domain=example.com; Max-Age=60"
    )
    assert sensitive["domain-too-broad"].severity == "medium"
    host_only = ids("session=abc; Secure; HttpOnly; SameSite=Lax; Max-Age=60; Path=/app")
    assert "domain-too-broad" not in host_only


def test_path_root_on_sensitive_cookie():
    findings = ids("auth=abc; Secure; HttpOnly; SameSite=Lax; Path=/; Max-Age=60")
    assert findings["path-root-sensitive"].severity == "low"
    assert "path-root-sensitive" not in ids(
        "auth=abc; Secure; HttpOnly; SameSite=Lax; Path=/account; Max-Age=60"
    )


def test_scoring_clean_zero_and_bad_cookie_high():
    good = parse_set_cookie("theme=dark; Secure; HttpOnly; SameSite=Lax; Max-Age=60")
    bad = parse_set_cookie("session_token=abc")
    result = check_cookies([good, bad], now=NOW)
    assert result.cookie_scores["theme"] == 0
    assert result.cookie_scores["session_token"] >= 50
    assert result.risk_score == result.cookie_scores["session_token"]


def test_scoring_capped_at_100():
    cookie = parse_set_cookie(
        "__Host-session_token=abc; SameSite=None; Domain=com; Path=/app; Max-Age=99999999"
    )
    result = check_cookies([cookie], now=NOW)
    assert result.risk_score == 100


def test_duplicate_cookie_names_keep_the_worst_score():
    risky = parse_set_cookie("session=abc")
    clean = parse_set_cookie(
        "session=def; Secure; HttpOnly; SameSite=Strict; Max-Age=60; Path=/app"
    )
    result = check_cookies([risky, clean], now=NOW)
    assert result.cookie_scores["session"] >= 50
    assert result.risk_score == result.cookie_scores["session"]


def test_every_finding_has_remediation():
    cookie = parse_set_cookie("session_token=abc")
    for finding in check_cookie(cookie, now=NOW):
        assert finding.remediation
        assert finding.message
