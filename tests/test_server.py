import asyncio

from pare_worker_kit import PRODUCES_META_KEY, RISK_TIER_META_KEY

from pare_mitm_mcp.contract import TOOL_SPECS
from pare_mitm_mcp.server import build_server


def _wire_tools():
    """The tool list as the daemon actually sees it, via FastMCP."""
    server = build_server()
    return {t.name: t for t in asyncio.run(server.list_tools())}


def test_build_server_advertises_risk_tier_over_the_wire():
    by_name = _wire_tools()
    assert {s.name for s in TOOL_SPECS} == set(by_name)
    for spec in TOOL_SPECS:
        assert by_name[spec.name].meta[RISK_TIER_META_KEY] == spec.risk_tier


def test_build_server_advertises_produces_over_the_wire():
    by_name = _wire_tools()
    for spec in TOOL_SPECS:
        assert by_name[spec.name].meta[PRODUCES_META_KEY] == spec.produces


def test_wire_meta_carries_the_contract_keys_and_nothing_else():
    """A stray _meta key is an unreviewed addition to the wire contract.

    Deliberately exact, where the two assertions above are per-key. Adding a
    third contract key changes what every worker in the fleet advertises to
    the daemon, so it should fail here and be made on purpose rather than
    inherited from whatever a library decided to attach.
    """
    for tool in _wire_tools().values():
        assert set(tool.meta) == {RISK_TIER_META_KEY, PRODUCES_META_KEY}
