import asyncio

from agent_core.workers.risk import RISK_TIER_META_KEY
from pare_mitm_mcp.contract import TOOL_SPECS
from pare_mitm_mcp.server import build_server


def test_build_server_advertises_risk_tier_over_the_wire():
    server = build_server()
    tools = asyncio.run(server.list_tools())
    by_name = {t.name: t for t in tools}

    assert {s.name for s in TOOL_SPECS} == set(by_name)
    for spec in TOOL_SPECS:
        tool = by_name[spec.name]
        assert tool.meta == {RISK_TIER_META_KEY: "low"}
