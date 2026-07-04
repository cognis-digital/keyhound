"""KEYHOUND MCP server — exposes scan() as an MCP tool for Cognis.Studio."""
from __future__ import annotations
from keyhound.core import scan, to_json

def serve() -> int:
    """Start an MCP stdio server. Requires the optional 'mcp' extra:
        pip install "keyhound[mcp]"
    """
    try:
        from mcp.server.fastmcp import FastMCP
    except Exception:
        print("Install the MCP extra: pip install 'keyhound[mcp]'")
        return 1
    app = FastMCP("keyhound")

    @app.tool()
    def keyhound_scan(target: str) -> str:
        """Scan firmware blobs and filesystem dumps for hardcoded private keys, API tokens, default creds, and weak RSA/ECC material.. Returns JSON findings."""
        return to_json(scan(target))

    app.run()
    return 0
