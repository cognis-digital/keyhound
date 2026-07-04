"""Smoke tests for KEYHOUND. Standard library + pytest only, no network."""
import json
import os
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from keyhound import TOOL_NAME, TOOL_VERSION, scan_bytes, scan_path  # noqa: E402
from keyhound.cli import main  # noqa: E402

DEMO = os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
    "demos",
    "01-basic",
    "firmware_dump.txt",
)


def test_metadata():
    assert TOOL_NAME == "keyhound"
    assert TOOL_VERSION.count(".") == 2


def test_scan_demo_finds_expected_detectors():
    findings = scan_path(DEMO)
    ids = {f.detector for f in findings}
    # The detectors the demo is built to trip.
    assert "private-key" in ids
    assert "aws-access-key" in ids
    assert "hardcoded-password" in ids
    assert "telnet-default-cred" in ids
    assert "connection-uri-password" in ids
    assert "unix-shadow-hash" in ids
    assert len(findings) >= 6


def test_aws_secret_value_extracted():
    findings = scan_path(DEMO)
    aws = [f for f in findings if f.detector == "aws-access-key"]
    assert aws
    assert aws[0].secret == "AKIAIOSFODNN7EXAMPLE"
    # redaction keeps head/tail, masks middle
    red = aws[0].redacted()
    assert red.startswith("AKIA")
    assert "*" in red
    assert aws[0].secret not in red


def test_connection_uri_password_extracted():
    findings = scan_path(DEMO)
    uri = [f for f in findings if f.detector == "connection-uri-password"]
    assert uri
    assert uri[0].secret == "hunter2pass"


def test_placeholder_not_flagged():
    # password=changeme in the demo must be suppressed as a placeholder
    findings = scan_path(DEMO)
    secrets = {f.secret for f in findings}
    assert "changeme" not in secrets


def test_scan_bytes_clean_input_no_findings():
    assert scan_bytes(b"just some harmless text\nlog_level=info\n") == []


def test_line_numbers_are_real():
    findings = scan_path(DEMO)
    for f in findings:
        assert f.line >= 1
        assert f.column >= 1


def test_cli_table_exit_code_one(capsys):
    rc = main(["scan", DEMO])
    out = capsys.readouterr().out
    assert rc == 1  # findings -> non-zero for CI gate
    assert "Found" in out
    assert "critical" in out.lower()


def test_cli_json_output(capsys):
    rc = main(["scan", DEMO, "--format", "json"])
    out = capsys.readouterr().out
    assert rc == 1
    data = json.loads(out)
    assert data["tool"] == "keyhound"
    assert data["count"] >= 6
    assert len(data["findings"]) == data["count"]
    # redacted by default: no raw match field, secret is masked
    f0 = data["findings"][0]
    assert "secret" in f0
    assert "match" not in f0


def test_cli_show_secrets_unredacted(capsys):
    rc = main(["scan", DEMO, "--format", "json", "--show-secrets"])
    out = capsys.readouterr().out
    assert rc == 1
    data = json.loads(out)
    secrets = {f["secret"] for f in data["findings"]}
    assert "AKIAIOSFODNN7EXAMPLE" in secrets


def test_cli_clean_path_exit_zero(tmp_path, capsys):
    clean = tmp_path / "clean.txt"
    clean.write_text("nothing to see here\nlog_level=debug\n")
    rc = main(["scan", str(clean)])
    out = capsys.readouterr().out
    assert rc == 0
    assert "No secrets found" in out


def test_cli_missing_path_exit_two(capsys):
    rc = main(["scan", "/no/such/path/keyhound_xyz"])
    err = capsys.readouterr().err
    assert rc == 2
    assert "not found" in err


def test_severity_filter(capsys):
    rc = main(["scan", DEMO, "--format", "json", "--severity", "critical"])
    out = capsys.readouterr().out
    assert rc == 1
    data = json.loads(out)
    assert all(f["severity"] == "critical" for f in data["findings"])


if __name__ == "__main__":
    sys.exit(pytest.main([__file__, "-v"]))
