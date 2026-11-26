"""Command-line interface for cookie-audit.

Exit codes: 0 = no findings at or above --fail-on, 1 = findings at or
above --fail-on, 2 = usage or input error.
"""

from __future__ import annotations

import argparse
import sys
import urllib.error
import urllib.request
from urllib.parse import urlparse

from . import __version__
from .checks import SEVERITY_ORDER, check_cookies
from .parser import parse_headers_text
from .report import RENDERERS


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="cookie-audit",
        description="Audit Set-Cookie headers for security misconfigurations.",
    )
    parser.add_argument("--version", action="version", version=f"cookie-audit {__version__}")
    source = parser.add_mutually_exclusive_group()
    source.add_argument(
        "--file",
        metavar="PATH",
        help="Read Set-Cookie headers from PATH ('-' reads stdin). "
        "Default: read stdin when piped.",
    )
    source.add_argument(
        "--url",
        metavar="URL",
        help="Fetch URL and audit the Set-Cookie headers it returns.",
    )
    parser.add_argument(
        "--format",
        choices=sorted(RENDERERS),
        default="text",
        help="Report format (default: text).",
    )
    parser.add_argument(
        "--fail-on",
        choices=sorted(SEVERITY_ORDER, key=SEVERITY_ORDER.get),
        default="medium",
        help="Exit 1 when a finding is at or above this severity (default: medium).",
    )
    parser.add_argument(
        "--host",
        metavar="HOST",
        help="Host the cookies belong to (improves Domain scope checks). "
        "Defaults to the --url host.",
    )
    return parser


def fetch_set_cookie_headers(url: str) -> list[str]:
    """Return the Set-Cookie header values served by *url*."""
    request = urllib.request.Request(url, headers={"User-Agent": f"cookie-audit/{__version__}"})
    with urllib.request.urlopen(request, timeout=10) as response:
        return response.headers.get_all("Set-Cookie") or []


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    host = args.host
    if args.url:
        try:
            headers = fetch_set_cookie_headers(args.url)
        except (urllib.error.URLError, ValueError, OSError) as exc:
            print(f"cookie-audit: failed to fetch {args.url}: {exc}", file=sys.stderr)
            return 2
        text = "\n".join(headers)
        host = host or urlparse(args.url).hostname
    elif args.file and args.file != "-":
        try:
            with open(args.file, encoding="utf-8") as handle:
                text = handle.read()
        except OSError as exc:
            print(f"cookie-audit: cannot read {args.file}: {exc}", file=sys.stderr)
            return 2
    elif args.file == "-" or not sys.stdin.isatty():
        text = sys.stdin.read()
    else:
        parser.error("no input: pass --file, --url, or pipe headers on stdin")

    cookies = parse_headers_text(text)
    if not cookies:
        print("cookie-audit: no Set-Cookie headers found in input", file=sys.stderr)
        return 2

    result = check_cookies(cookies, host=host)
    sys.stdout.write(RENDERERS[args.format](result))

    threshold = SEVERITY_ORDER[args.fail_on]
    if any(SEVERITY_ORDER[f.severity] >= threshold for f in result.findings):
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
