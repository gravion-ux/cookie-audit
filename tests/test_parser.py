from cookie_audit.parser import parse_headers_text, parse_set_cookie


def test_parse_basic_cookie_with_flags():
    cookie = parse_set_cookie("session=abc123; Secure; HttpOnly; SameSite=Lax; Path=/app")
    assert cookie is not None
    assert cookie.name == "session"
    assert cookie.value == "abc123"
    assert cookie.secure is True
    assert cookie.httponly is True
    assert cookie.samesite == "Lax"
    assert cookie.path == "/app"


def test_parse_strips_set_cookie_prefix():
    cookie = parse_set_cookie("Set-Cookie: theme=dark; Secure")
    assert cookie is not None
    assert cookie.name == "theme"
    assert cookie.secure is True


def test_parse_value_containing_equals_and_quotes():
    cookie = parse_set_cookie('token="a=b=c"; Secure')
    assert cookie is not None
    assert cookie.value == "a=b=c"


def test_parse_attribute_names_are_case_insensitive():
    cookie = parse_set_cookie("id=1; SECURE; httponly; samesite=strict")
    assert cookie is not None
    assert cookie.secure is True
    assert cookie.httponly is True
    assert cookie.samesite == "strict"


def test_parse_max_age_and_expires():
    cookie = parse_set_cookie(
        "id=1; Max-Age=3600; Expires=Wed, 21 Oct 2099 07:28:00 GMT"
    )
    assert cookie is not None
    assert cookie.max_age == 3600
    assert cookie.expires is not None
    assert cookie.expires.year == 2099
    assert cookie.is_session_cookie is False


def test_parse_invalid_max_age_returns_none():
    cookie = parse_set_cookie("id=1; Max-Age=soon")
    assert cookie is not None
    assert cookie.max_age is None
    assert cookie.is_session_cookie is True


def test_parse_rejects_lines_without_name_value():
    assert parse_set_cookie("not-a-cookie") is None
    assert parse_set_cookie("") is None
    assert parse_set_cookie("=value-only") is None


def test_parse_headers_text_skips_comments_and_other_headers():
    text = (
        "# captured response\n"
        "Content-Type: text/html\n"
        "Set-Cookie: a=1; Secure\n"
        "\n"
        "b=2; HttpOnly\n"
    )
    cookies = parse_headers_text(text)
    assert [c.name for c in cookies] == ["a", "b"]
