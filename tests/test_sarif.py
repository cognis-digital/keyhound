"""Tests for SARIF output, --out, and --fail-on (the CI-gate surface)."""
import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from keyhound.cli import main  # noqa: E402

DEMO = os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
    "demos",
    "01-basic",
    "firmware_dump.txt",
)


def test_sarif_is_valid_2_1_0(capsys):
    rc = main(["scan", DEMO, "--format", "sarif"])
    out = capsys.readouterr().out
    assert rc == 1
    doc = json.loads(out)
    assert doc["version"] == "2.1.0"
    assert "$schema" in doc
    run = doc["runs"][0]
    driver = run["tool"]["driver"]
    assert driver["name"] == "keyhound"
    assert driver["rules"], "expected at least one rule"
    assert run["results"], "expected at least one result"
    # every result references a declared rule and uses a valid SARIF level
    rule_ids = {r["id"] for r in driver["rules"]}
    for res in run["results"]:
        assert res["ruleId"] in rule_ids
        assert res["level"] in {"error", "warning", "note"}
        loc = res["locations"][0]["physicalLocation"]
        assert loc["region"]["startLine"] >= 1
        # paths are posix-normalized for code-scanning ingestion
        assert "\\" not in loc["artifactLocation"]["uri"]


def test_sarif_redacts_by_default(capsys):
    main(["scan", DEMO, "--format", "sarif"])
    out = capsys.readouterr().out
    assert "AKIAIOSFODNN7EXAMPLE" not in out
    assert "AKIA" in out  # redacted head is kept


def test_out_writes_file(tmp_path, capsys):
    dest = tmp_path / "results.sarif"
    rc = main(["scan", DEMO, "--format", "sarif", "--out", str(dest)])
    assert rc == 1
    assert capsys.readouterr().out.strip() == ""  # nothing on stdout
    doc = json.loads(dest.read_text(encoding="utf-8"))
    assert doc["version"] == "2.1.0"


def test_fail_on_high_gates_on_severity(tmp_path, capsys):
    # A file with only a medium finding (generic api-key-assignment).
    f = tmp_path / "cfg.py"
    f.write_text('api_key = "aB3xK9mZ2qR7tW1nP5vL8jH4dF6gS0cY"\n')
    rc_high = main(["scan", str(f), "--fail-on", "high"])
    capsys.readouterr()
    assert rc_high == 0  # medium finding does not trip a high gate
    rc_med = main(["scan", str(f), "--fail-on", "medium"])
    capsys.readouterr()
    assert rc_med == 1


def test_fail_on_default_any_finding(capsys):
    rc = main(["scan", DEMO])
    capsys.readouterr()
    assert rc == 1  # default: any finding fails
