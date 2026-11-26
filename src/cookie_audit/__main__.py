"""Allow ``python -m cookie_audit``."""

from .cli import main

if __name__ == "__main__":
    raise SystemExit(main())
