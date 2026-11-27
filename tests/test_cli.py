import io
import json
import urllib.request
from email.message import Message

import pytest

from cookie_audit.cli import main, validate_http_url

CLEAN = "theme=dark; Secure; HttpOnly; SameSite=Lax; Max-Age=86400; Path=/app\n"
DIRTY = "session_token=abc; Path=/\n"


def write(tmp_path, text):
    path = tmp_path / "headers.txt"
    path.write_text(text, encoding="utf-8")
    return str(path)


def test_cli_clean_file_exits_zero(tmp_path, capsys):
    assert main(["--file", write(tmp_path, CLEAN)]) == 0
    assert "Risk score: 0/100" in capsys.readouterr().out


def test_cli_findings_exit_one(tmp_path, capsys):
    assert main(["--file", write(tmp_path, DIRTY)]) == 1
    out = capsys.readouterr().out
    assert "missing-secure" in out
    assert "missing-httponly" in out


def test_cli_fail_on_threshold(tmp_path):
    # Only an info finding: passes at the default threshold, fails at info.
    text = "session=abc; Secure; HttpOnly; SameSite=Strict; Path=/app\n"
    path = write(tmp_path, text)
    assert main(["--file", path]) == 0
    assert main(["--file", path, "--fail-on", "info"]) == 1
    assert main(["--file", path, "--fail-on", "critical"]) == 0


def test_cli_json_format(tmp_path, capsys):
    assert main(["--file", write(tmp_path, DIRTY), "--format", "json"]) == 1
    payload = json.loads(capsys.readouterr().out)
    assert payload["cookie_count"] == 1
    assert payload["risk_score"] > 0
    check_ids = {f["check_id"] for f in payload["findings"]}
    assert "missing-secure" in check_ids
    assert all(f["remediation"] for f in payload["findings"])


def test_cli_markdown_format(tmp_path, capsys):
    assert main(["--file", write(tmp_path, DIRTY), "--format", "markdown"]) == 1
    out = capsys.readouterr().out
    assert out.startswith("# cookie-audit report")
    assert "| session_token | high | missing-secure |" in out


def test_cli_reads_stdin(monkeypatch, capsys):
    monkeypatch.setattr("sys.stdin", io.StringIO(DIRTY))
    assert main([]) == 1
    assert "session_token" in capsys.readouterr().out


def test_cli_no_cookies_is_usage_error(tmp_path, capsys):
    assert main(["--file", write(tmp_path, "# nothing here\n")]) == 2
    assert "no Set-Cookie" in capsys.readouterr().err


def test_cli_missing_file_is_usage_error(tmp_path, capsys):
    assert main(["--file", str(tmp_path / "nope.txt")]) == 2
    assert "cannot read" in capsys.readouterr().err


def test_cli_no_input_on_tty_is_usage_error(monkeypatch):
    class FakeTty(io.StringIO):
        def isatty(self):
            return True

    monkeypatch.setattr("sys.stdin", FakeTty(""))
    with pytest.raises(SystemExit) as excinfo:
        main([])
    assert excinfo.value.code == 2


class FakeResponse:
    def __init__(self, set_cookie_values):
        self.headers = Message()
        for value in set_cookie_values:
            self.headers.add_header("Set-Cookie", value)

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False


def test_cli_url_fetch_is_mocked(monkeypatch, capsys):
    def fake_urlopen(request, timeout=None):
        assert request.full_url == "https://example.test/login"
        return FakeResponse(["session=abc; Path=/", CLEAN.strip()])

    monkeypatch.setattr(urllib.request, "urlopen", fake_urlopen)
    assert main(["--url", "https://example.test/login", "--format", "json"]) == 1
    payload = json.loads(capsys.readouterr().out)
    assert payload["cookie_count"] == 2


def test_cli_url_fetch_failure_is_usage_error(monkeypatch, capsys):
    def failing_urlopen(request, timeout=None):
        raise urllib.error.URLError("offline")

    monkeypatch.setattr(urllib.request, "urlopen", failing_urlopen)
    assert main(["--url", "https://example.test/"]) == 2
    assert "failed to fetch" in capsys.readouterr().err




@pytest.mark.parametrize("url", ["file:///etc/passwd", "ftp://example.com/x", "example.com", "https://"])
def test_validate_http_url_rejects_non_http(url):
    with pytest.raises(ValueError):
        validate_http_url(url)


def test_validate_http_url_accepts_https():
    assert validate_http_url("https://example.com/login") == "https://example.com/login"
