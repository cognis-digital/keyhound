"""Tests for the edge/air-gap data-feed catalog + ingester.

These tests are strictly OFFLINE: they exercise catalog parsing, cache freshness
math, offline serving, and snapshot export/import using a temp cache directory.
They never call datafeeds.fetch / .update, so no network access ever happens.
"""
import importlib
import json
import os
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from keyhound import datafeeds  # noqa: E402
from keyhound.cli import main  # noqa: E402


@pytest.fixture()
def cache(tmp_path, monkeypatch):
    d = tmp_path / "feeds-cache"
    monkeypatch.setenv("COGNIS_FEEDS_CACHE", str(d))
    # cache_dir() reads the env var each call, so this redirects all I/O.
    return d


# --- catalog ---------------------------------------------------------------

def test_catalog_loads():
    cat = datafeeds.load_catalog()
    assert isinstance(cat, dict)
    assert cat.get("feeds")


def test_catalog_has_known_vuln_feeds():
    ids = {f["id"] for f in datafeeds.list_feeds()}
    for want in ("cisa-kev", "epss", "osv", "nvd-cve"):
        assert want in ids


def test_list_feeds_domain_filter():
    vuln = datafeeds.list_feeds(domain="vuln")
    assert vuln
    assert all(f["domain"] == "vuln" for f in vuln)


def test_every_feed_has_url_and_domain():
    for f in datafeeds.list_feeds():
        assert f.get("url")
        assert f.get("domain")
        assert f.get("id")


def test_feeds_are_marked_keyless_or_documented():
    # keyless feeds are the air-gap-friendly default; field must exist.
    for f in datafeeds.list_feeds():
        assert "keyless" in f


# --- cache freshness math --------------------------------------------------

def test_cached_age_none_when_absent(cache):
    assert datafeeds.cached_age_hours("cisa-kev") is None


def test_offline_get_without_cache_raises(cache):
    with pytest.raises(FileNotFoundError):
        datafeeds.get("cisa-kev", offline=True)


def test_offline_get_serves_cached_json(cache):
    # Seed the cache by hand (simulating a prior fetch / sneakernet import),
    # then prove offline=True serves it without touching the network.
    data_path, meta_path = datafeeds._paths("osv")
    data_path.parent.mkdir(parents=True, exist_ok=True)
    payload = {"vulns": [{"id": "OSV-TEST-1"}]}
    data_path.write_bytes(json.dumps(payload).encode())
    meta_path.write_text(json.dumps({"feed": "osv", "fetched_at": 9e9, "format": "json"}))
    got = datafeeds.get("osv", offline=True)
    assert got == payload


def test_cached_age_after_seeding(cache):
    import time
    data_path, meta_path = datafeeds._paths("epss")
    data_path.parent.mkdir(parents=True, exist_ok=True)
    data_path.write_bytes(b"x")
    meta_path.write_text(json.dumps({"feed": "epss", "fetched_at": time.time()}))
    age = datafeeds.cached_age_hours("epss")
    assert age is not None
    assert age < 1.0


# --- snapshot export / import (sneakernet to air-gap) ----------------------

def test_snapshot_export_import_roundtrip(cache, tmp_path):
    # populate cache
    data_path, meta_path = datafeeds._paths("feodo-c2")
    data_path.parent.mkdir(parents=True, exist_ok=True)
    data_path.write_bytes(b"1.2.3.4\n")
    meta_path.write_text(json.dumps({"feed": "feodo-c2", "fetched_at": 1.0}))

    snap = tmp_path / "feeds.tar.gz"
    n = datafeeds.snapshot_export(str(snap))
    assert snap.exists()
    assert n >= 1

    # wipe and re-import
    data_path.unlink()
    meta_path.unlink()
    assert datafeeds.cached_age_hours("feodo-c2") is None
    datafeeds.snapshot_import(str(snap))
    assert data_path.exists()


# --- CLI surface (offline only) --------------------------------------------

def test_cli_feeds_list(capsys):
    rc = main(["feeds", "list"])
    out = capsys.readouterr().out
    assert rc == 0
    assert "cisa-kev" in out
    assert "feed(s)" in out


def test_cli_feeds_list_domain(capsys):
    rc = main(["feeds", "list", "--domain", "vuln"])
    out = capsys.readouterr().out
    assert rc == 0
    assert "osv" in out


def test_cli_feeds_get_offline_missing(cache, capsys):
    # offline get with empty cache surfaces an error, never a network call.
    with pytest.raises(FileNotFoundError):
        main(["feeds", "get", "cisa-kev", "--offline"])


def test_cli_feeds_update_requires_id(capsys):
    rc = main(["feeds", "update"])
    err = capsys.readouterr().err
    assert rc == 2
    assert "feed id" in err.lower()
