"""Parsing of ``Set-Cookie`` header values into structured cookies."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import UTC, datetime
from email.utils import parsedate_to_datetime


@dataclass
class Cookie:
    """A single parsed cookie from a ``Set-Cookie`` header."""

    name: str
    value: str
    # Attribute names are lower-cased; flag attributes (Secure, HttpOnly)
    # map to None, valued attributes map to their string value.
    attributes: dict[str, str | None] = field(default_factory=dict)
    raw: str = ""

    @property
    def secure(self) -> bool:
        return "secure" in self.attributes

    @property
    def httponly(self) -> bool:
        return "httponly" in self.attributes

    @property
    def samesite(self) -> str | None:
        return self.attributes.get("samesite")

    @property
    def path(self) -> str | None:
        return self.attributes.get("path")

    @property
    def domain(self) -> str | None:
        return self.attributes.get("domain")

    @property
    def max_age(self) -> int | None:
        raw = self.attributes.get("max-age")
        if raw is None:
            return None
        try:
            return int(raw)
        except ValueError:
            return None

    @property
    def expires(self) -> datetime | None:
        raw = self.attributes.get("expires")
        if not raw:
            return None
        try:
            parsed = parsedate_to_datetime(raw)
        except (TypeError, ValueError):
            return None
        if parsed is None:
            return None
        if parsed.tzinfo is None:
            parsed = parsed.replace(tzinfo=UTC)
        return parsed

    @property
    def is_session_cookie(self) -> bool:
        """True when neither Max-Age nor Expires is set (browser-session lifetime)."""
        return self.max_age is None and self.expires is None

    def lifetime_days(self, now: datetime | None = None) -> float | None:
        """Cookie lifetime in days, or None for session cookies."""
        if self.max_age is not None:
            return self.max_age / 86400
        expires = self.expires
        if expires is None:
            return None
        reference = now or datetime.now(UTC)
        return (expires - reference).total_seconds() / 86400


def _unquote(value: str) -> str:
    if len(value) >= 2 and value.startswith('"') and value.endswith('"'):
        return value[1:-1]
    return value


def parse_set_cookie(header: str) -> Cookie | None:
    """Parse one ``Set-Cookie`` header value.

    Accepts an optional ``Set-Cookie:`` prefix. Returns None when the
    header has no ``name=value`` pair in its first segment.
    """
    text = header.strip()
    if not text:
        return None
    if text.lower().startswith("set-cookie:"):
        text = text[len("set-cookie:") :].strip()

    segments = text.split(";")
    first = segments[0].strip()
    name, sep, value = first.partition("=")
    name = name.strip()
    if not sep or not name:
        return None

    attributes: dict[str, str | None] = {}
    for segment in segments[1:]:
        segment = segment.strip()
        if not segment:
            continue
        key, attr_sep, attr_value = segment.partition("=")
        key = key.strip().lower()
        if not key:
            continue
        attributes[key] = _unquote(attr_value.strip()) if attr_sep else None

    return Cookie(
        name=name,
        value=_unquote(value.strip()),
        attributes=attributes,
        raw=header.strip(),
    )


def parse_headers_text(text: str) -> list[Cookie]:
    """Parse every ``Set-Cookie`` header found in a block of text.

    One header per line; blank lines and ``#`` comments are skipped.
    Lines that are not cookies (for example other HTTP headers) are
    ignored.
    """
    cookies: list[Cookie] = []
    for line in text.splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        cookie = parse_set_cookie(stripped)
        if cookie is not None:
            cookies.append(cookie)
    return cookies
