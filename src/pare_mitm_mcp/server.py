from __future__ import annotations

from mcp.server.fastmcp import FastMCP


def build_server() -> FastMCP:
    return FastMCP("pare-mitm-mcp")


def main() -> None:
    build_server().run(transport="stdio")
