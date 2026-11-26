"""cookie-audit: a Set-Cookie security analyzer."""

from .checks import AuditResult, Finding, check_cookie, check_cookies, is_sensitive_name
from .parser import Cookie, parse_headers_text, parse_set_cookie

__version__ = "0.1.0"

__all__ = [
    "AuditResult",
    "Cookie",
    "Finding",
    "__version__",
    "check_cookie",
    "check_cookies",
    "is_sensitive_name",
    "parse_headers_text",
    "parse_set_cookie",
]
