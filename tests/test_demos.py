"""Verify every demos/<NN-*> scenario actually fires as its SCENARIO.md claims.

Standard library + pytest only, no network. Each demo is a realistic input in
keyhound's real input format; this test is the contract that they keep working.
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from keyhound import scan_path  # noqa: E402

DEMOS = os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "demos"
)


def _ids(name):
    findings = scan_path(os.path.join(DEMOS, name))
    return findings, {f.detector for f in findings}


def test_demo_04_ci_pipeline():
    findings, ids = _ids("04-ci-pipeline")
    assert {"aws-access-key", "aws-secret-key", "github-token", "gcp-api-key"} <= ids
    assert len(findings) == 4


def test_demo_05_mobile_app():
    findings, ids = _ids("05-mobile-app")
    assert {"gcp-api-key", "jwt", "connection-uri-password"} <= ids
    assert len(findings) == 3


def test_demo_06_iot_router():
    findings, ids = _ids("06-iot-router")
    assert {"private-key", "telnet-default-cred", "slack-token",
            "hardcoded-password"} <= ids
    # placeholder must be suppressed
    assert "changeme" not in {f.secret for f in findings}
    assert len(findings) == 4


def test_demo_07_docker_compose():
    findings, ids = _ids("07-docker-compose")
    assert "connection-uri-password" in ids
    assert "hardcoded-password" in ids
    assert len(findings) == 3


def test_demo_08_k8s_secrets():
    findings, ids = _ids("08-k8s-secrets")
    assert "connection-uri-password" in ids
    assert "api-key-assignment" in ids
    assert len(findings) == 3


def test_demo_09_source_leak():
    findings, ids = _ids("09-source-leak")
    assert "hardcoded-password" in ids
    assert "api-key-assignment" in ids
    assert len(findings) == 3


def test_demo_10_clean_config_is_clean():
    findings, _ = _ids("10-clean-config")
    assert findings == []


def test_demo_11_backup_shadow():
    findings, ids = _ids("11-backup-shadow")
    assert "private-key" in ids
    shadow = [f for f in findings if f.detector == "unix-shadow-hash"]
    assert len(shadow) == 3  # root, admin, backup; daemon/sshd not flagged
    assert len(findings) == 4
