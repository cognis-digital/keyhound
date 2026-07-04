"""Per-detector unit tests for keyhound's core scanning engine.

Standard library + pytest only, no network. Each detector is exercised on a
minimal positive case, a redaction check, and (where relevant) a negative case
that must NOT fire. These assertions pin the regex behaviour so a future tweak
to one detector can't silently break another.
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from keyhound.core import (  # noqa: E402
    DETECTORS,
    Finding,
    _shannon_entropy,
    scan,
    scan_bytes,
    to_json,
)


def _ids(text):
    fs = scan_bytes(text.encode("utf-8"), "x")
    return fs, {f.detector for f in fs}


# --- detector inventory ----------------------------------------------------

def test_detector_inventory_count():
    # The README and feature list advertise 12 detectors; keep them honest.
    assert len(DETECTORS) == 12


def test_detector_ids_are_unique():
    ids = [d.id for d in DETECTORS]
    assert len(ids) == len(set(ids))


def test_every_detector_has_valid_severity():
    for d in DETECTORS:
        assert d.severity in {"critical", "high", "medium", "low"}


def test_every_detector_has_description():
    for d in DETECTORS:
        assert d.description and isinstance(d.description, str)


# --- private-key -----------------------------------------------------------

def test_private_key_rsa():
    _, ids = _ids("-----BEGIN RSA PRIVATE KEY-----\nabc\n")
    assert "private-key" in ids


def test_private_key_openssh():
    _, ids = _ids("-----BEGIN OPENSSH PRIVATE KEY-----\nabc\n")
    assert "private-key" in ids


def test_private_key_ec():
    _, ids = _ids("-----BEGIN EC PRIVATE KEY-----\nabc\n")
    assert "private-key" in ids


def test_private_key_plain():
    _, ids = _ids("-----BEGIN PRIVATE KEY-----\nabc\n")
    assert "private-key" in ids


def test_public_key_not_flagged():
    _, ids = _ids("-----BEGIN PUBLIC KEY-----\nabc\n")
    assert "private-key" not in ids


def test_private_key_severity_is_critical():
    fs, _ = _ids("-----BEGIN RSA PRIVATE KEY-----\nabc\n")
    assert fs[0].severity == "critical"


# --- aws-access-key --------------------------------------------------------

def test_aws_akia():
    fs, ids = _ids("AKIAIOSFODNN7EXAMPLE")
    assert "aws-access-key" in ids
    assert any(f.secret == "AKIAIOSFODNN7EXAMPLE" for f in fs)


def test_aws_asia():
    _, ids = _ids("ASIAY34FZKBOKMUTVV7A")
    assert "aws-access-key" in ids


def test_aws_lowercase_not_flagged():
    _, ids = _ids("akiaiosfodnn7example")
    assert "aws-access-key" not in ids


# --- aws-secret-key --------------------------------------------------------

def test_aws_secret_key():
    fs, ids = _ids('aws_secret_access_key = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"')
    assert "aws-secret-key" in ids
    sk = [f for f in fs if f.detector == "aws-secret-key"][0]
    assert len(sk.secret) == 40


# --- gcp-api-key -----------------------------------------------------------

def test_gcp_api_key():
    fs, ids = _ids("key=AIzaSyA1234567890abcdefghijklmnopqrstuv")
    assert "gcp-api-key" in ids
    g = [f for f in fs if f.detector == "gcp-api-key"][0]
    assert g.secret.startswith("AIza")
    assert g.severity == "high"


# --- github-token ----------------------------------------------------------

def test_github_ghp_token():
    _, ids = _ids("GITHUB_TOKEN=ghp_ab12CD34ef56GH78ij90KL12mn34OP56qr78")
    assert "github-token" in ids


def test_github_pat_token():
    _, ids = _ids("token=github_pat_11ABCDEFG0aBcDeFgHiJkLmNoPqRsTuVwXyZ012345")
    assert "github-token" in ids


def test_github_short_not_flagged():
    _, ids = _ids("ghp_short")
    assert "github-token" not in ids


# --- slack-token -----------------------------------------------------------

def test_slack_token():
    _, ids = _ids("SLACK=xoxb-EXAMPLE-NOT-A-REAL-TOKEN-demo0only0value0here")
    assert "slack-token" in ids


# --- jwt -------------------------------------------------------------------

def test_jwt():
    jwt = ("eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9."
           "eyJzdWIiOiIxMjM0NTY3ODkwIn0."
           "dummysignatureForDemoPurposesOnly1234")
    fs, ids = _ids(jwt)
    assert "jwt" in ids
    j = [f for f in fs if f.detector == "jwt"][0]
    assert j.severity == "medium"


# --- connection-uri-password ----------------------------------------------

def test_connection_uri_mysql():
    fs, ids = _ids("DB=mysql://u:hunter2pass@10.0.0.5:3306/db")
    assert "connection-uri-password" in ids
    u = [f for f in fs if f.detector == "connection-uri-password"][0]
    assert u.secret == "hunter2pass"


def test_connection_uri_amqp():
    fs, _ = _ids("AMQP=amqp://rabbit:Rabb1tMQSecret@rabbitmq:5672/vhost")
    u = [f for f in fs if f.detector == "connection-uri-password"]
    assert u and u[0].secret == "Rabb1tMQSecret"


def test_connection_uri_no_password_not_flagged():
    _, ids = _ids("DB=postgres://app_user@db.internal:5432/appdb")
    assert "connection-uri-password" not in ids


# --- unix-shadow-hash ------------------------------------------------------

def test_shadow_sha512():
    fs, ids = _ids("root:$6$abcd1234$Xy9zQwErTyUiOpAsDfGh.:19000:0:99999:7:::")
    assert "unix-shadow-hash" in ids


def test_shadow_locked_account_not_flagged():
    _, ids = _ids("daemon:*:19000:0:99999:7:::\nsshd:!:19000:0:99999:7:::")
    assert "unix-shadow-hash" not in ids


# --- hardcoded-password ----------------------------------------------------

def test_hardcoded_password():
    fs, ids = _ids('admin_password = "Sup3rR0uter!2024"')
    assert "hardcoded-password" in ids
    p = [f for f in fs if f.detector == "hardcoded-password"][0]
    assert p.secret == "Sup3rR0uter!2024"


def test_hardcoded_password_placeholder_suppressed():
    _, ids = _ids('password = "changeme"')
    assert "hardcoded-password" not in ids


# --- api-key-assignment (entropy gated) ------------------------------------

def test_api_key_high_entropy_fires():
    _, ids = _ids('api_key = "aB3xK9mZ2qR7tW1nP5vL8jH4dF6gS0cY"')
    assert "api-key-assignment" in ids


def test_api_key_low_entropy_suppressed():
    _, ids = _ids('api_key = "aaaaaaaaaaaaaaaa"')
    assert "api-key-assignment" not in ids


# --- telnet-default-cred ---------------------------------------------------

def test_telnet_default_cred():
    _, ids = _ids("busybox telnetd -l /bin/sh -p 9527 -b 192.168.1.1")
    assert "telnet-default-cred" in ids


# --- entropy helper --------------------------------------------------------

def test_entropy_empty_is_zero():
    assert _shannon_entropy("") == 0.0


def test_entropy_uniform_is_higher_than_repeated():
    assert _shannon_entropy("abcdefgh") > _shannon_entropy("aaaaaaaa")


def test_entropy_single_char_is_zero():
    assert _shannon_entropy("aaaa") == 0.0


# --- redaction -------------------------------------------------------------

def test_redaction_long_secret():
    f = Finding("d", "desc", "high", "p", 1, 1, "m", "AKIAIOSFODNN7EXAMPLE")
    r = f.redacted()
    assert r.startswith("AKIA")
    assert r.endswith("MPLE")
    assert "*" in r
    assert "OSFODNN7" not in r


def test_redaction_short_secret():
    f = Finding("d", "desc", "high", "p", 1, 1, "m", "abc")
    assert f.redacted() == "a**"


def test_redaction_empty_secret():
    f = Finding("d", "desc", "high", "p", 1, 1, "m", "")
    assert f.redacted() == ""


def test_to_dict_redacts_and_drops_match():
    f = Finding("d", "desc", "high", "p", 1, 1, "MATCHTEXT", "supersecretvalue123")
    d = f.to_dict(redact=True)
    assert "match" not in d
    assert d["secret"] != "supersecretvalue123"


def test_to_dict_unredacted_keeps_match():
    f = Finding("d", "desc", "high", "p", 1, 1, "MATCHTEXT", "supersecretvalue123")
    d = f.to_dict(redact=False)
    assert d["secret"] == "supersecretvalue123"
    assert d["match"] == "MATCHTEXT"


# --- scan()/to_json() convenience API --------------------------------------

DEMOS = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "demos")


def test_scan_api_shape():
    res = scan(os.path.join(DEMOS, "01-basic"))
    assert res["tool"] == "keyhound"
    assert res["count"] >= 6
    assert "severity_counts" in res
    assert isinstance(res["findings"], list)
    assert len(res["findings"]) == res["count"]


def test_scan_api_redacts_by_default():
    res = scan(os.path.join(DEMOS, "01-basic"))
    secrets = {f["secret"] for f in res["findings"]}
    assert "AKIAIOSFODNN7EXAMPLE" not in secrets


def test_scan_api_show_secrets():
    res = scan(os.path.join(DEMOS, "01-basic"), redact=False)
    secrets = {f["secret"] for f in res["findings"]}
    assert "AKIAIOSFODNN7EXAMPLE" in secrets


def test_to_json_roundtrips():
    import json
    res = scan(os.path.join(DEMOS, "02-clean"))
    parsed = json.loads(to_json(res))
    assert parsed["tool"] == "keyhound"


def test_scan_clean_dir_counts_zero():
    res = scan(os.path.join(DEMOS, "10-clean-config"))
    assert res["count"] == 0
    assert res["severity_counts"] == {}


# --- ordering & line/column correctness ------------------------------------

def test_findings_have_line_and_column():
    res = scan(os.path.join(DEMOS, "01-basic"))
    for f in res["findings"]:
        assert f["line"] >= 1
        assert f["column"] >= 1


def test_line_number_points_at_secret():
    text = "line1\nline2\nAKIAIOSFODNN7EXAMPLE\n"
    fs = scan_bytes(text.encode(), "x")
    aws = [f for f in fs if f.detector == "aws-access-key"][0]
    assert aws.line == 3


def test_dedupe_same_secret_same_line():
    # Two identical AWS keys on the same line should dedupe to one finding.
    text = "AKIAIOSFODNN7EXAMPLE AKIAIOSFODNN7EXAMPLE\n"
    fs = scan_bytes(text.encode(), "x")
    aws = [f for f in fs if f.detector == "aws-access-key"]
    assert len(aws) == 1
