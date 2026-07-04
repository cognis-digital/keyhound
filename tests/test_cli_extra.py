"""Tests for CLI wiring of the mcp subcommand and the scan()/to_json() bridge
the MCP server uses. The live MCP stdio loop is not started here (it would
block on stdin); we assert the command is wired and the tool function works.
"""
import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import keyhound.cli as cli  # noqa: E402
from keyhound.core import scan, to_json  # noqa: E402

DEMOS = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "demos")


def test_mcp_subcommand_invokes_serve(monkeypatch):
    called = {}

    def fake_serve():
        called["yes"] = True
        return 0

    # mcp_server.serve is imported lazily inside main(); patch it there.
    import keyhound.mcp_server as ms
    monkeypatch.setattr(ms, "serve", fake_serve)
    rc = cli.main(["mcp"])
    assert rc == 0
    assert called.get("yes") is True


def test_mcp_server_module_imports():
    # The module must import cleanly now that core exposes scan()/to_json().
    import keyhound.mcp_server as ms
    assert hasattr(ms, "serve")


def test_scan_bridge_is_json_serializable():
    payload = to_json(scan(os.path.join(DEMOS, "01-basic")))
    data = json.loads(payload)
    assert data["tool"] == "keyhound"
    assert data["count"] >= 1


def test_no_command_prints_help_exit_two(capsys):
    rc = cli.main([])
    out = capsys.readouterr().out
    assert rc == 2
    assert "usage" in out.lower()


def test_global_format_help_lists_subcommands(capsys):
    try:
        cli.main(["--help"])
    except SystemExit:
        pass
    out = capsys.readouterr().out
    assert "scan" in out
    assert "vulndb" in out
    assert "feeds" in out
