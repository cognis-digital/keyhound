"""Tests for the bundled VulnDB and the `keyhound vulndb` CLI surface.

Standard library + pytest only, fully offline — the 262k-record OSV corpus is
bundled in the package, so these never touch the network.
"""
import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from keyhound.cli import main  # noqa: E402
from keyhound.vulndb_local import VulnDB, count  # noqa: E402


def test_db_has_many_records():
    assert VulnDB().count() >= 100000


def test_module_count_helper():
    assert count() >= 100000


def test_records_have_core_fields():
    r = next(iter(VulnDB()))
    for field in ("id", "aliases", "ecosystem", "summary", "severity", "packages"):
        assert field in r


def test_by_cve_known_log4shell():
    hits = VulnDB().by_cve("CVE-2021-44228")
    assert isinstance(hits, list)
    assert len(hits) >= 1
    # the alias must be present on the returned record
    assert any("CVE-2021-44228" in (r.get("aliases") or []) for r in hits)


def test_by_cve_is_case_insensitive():
    db = VulnDB()
    assert db.by_cve("cve-2021-44228") == db.by_cve("CVE-2021-44228")


def test_by_cve_unknown_returns_empty():
    assert VulnDB().by_cve("CVE-0000-00000") == []


def test_search_returns_summaries():
    hits = VulnDB().search("overflow", limit=5)
    assert len(hits) <= 5
    assert all("overflow" in (r.get("summary", "") or "").lower() for r in hits)


def test_search_limit_respected():
    assert len(VulnDB().search("the", limit=3)) <= 3


def test_index_is_lazy_and_reusable():
    db = VulnDB()
    a = db.by_cve("CVE-2021-44228")
    b = db.by_cve("CVE-2021-44228")
    assert a == b  # second call uses the cached index


# --- CLI surface -----------------------------------------------------------

def test_cli_vulndb_count(capsys):
    rc = main(["vulndb", "--count"])
    out = capsys.readouterr().out.strip()
    assert rc == 0
    assert int(out) >= 100000


def test_cli_vulndb_cve_lookup(capsys):
    rc = main(["vulndb", "CVE-2021-44228"])
    out = capsys.readouterr().out
    assert rc == 0
    data = json.loads(out)
    assert data["count"] >= 1
    assert data["query"] == "CVE-2021-44228"


def test_cli_vulndb_search(capsys):
    rc = main(["vulndb", "--search", "deserialization", "--limit", "3"])
    out = capsys.readouterr().out
    data = json.loads(out)
    assert len(data["records"]) <= 3


def test_cli_vulndb_unknown_cve_exit_one(capsys):
    rc = main(["vulndb", "CVE-0000-00000"])
    capsys.readouterr()
    assert rc == 1  # no hits -> exit 1


def test_cli_vulndb_no_query_is_usage_error(capsys):
    rc = main(["vulndb"])
    err = capsys.readouterr().err
    assert rc == 2
    assert "query" in err.lower() or "count" in err.lower()
