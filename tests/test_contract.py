from pare_worker_kit import VALID_PRODUCES

from pare_mitm_mcp.contract import TOOL_SPECS, WorkerContractAdapter

EXPECTED = {
    "list_flows", "get_flow", "search_flows", "capture_health",
    "list_rules", "add_blocking_rule", "add_modification_rule",
    "delete_rule", "clear_rules", "inject_request", "replay_flow"
}


def test_all_tools_named():
    assert {s.name for s in TOOL_SPECS} == EXPECTED


def test_all_tools_low_tier():
    # Some tools are high or critical
    low_tier_tools = [s for s in TOOL_SPECS if s.risk_tier == "low"]
    assert len(low_tier_tools) > 0
    assert all(s.risk_tier == "low" for s in low_tier_tools)


def test_adapter_lists_all():
    assert len(WorkerContractAdapter().list_tools()) == len(EXPECTED)


def test_every_tool_declares_a_produces_value_the_daemon_understands():
    """A typo here is invisible at runtime, which is why it is caught here.

    Dispatch falls back to the safe reading when `produces` is unrecognised,
    so a tool meaning `artifact` and writing `ARTIFACT` would quietly stream a
    file's contents back as a tool result instead of a descriptor. agent_core
    rejects it at build time too; this catches it one repo earlier, where the
    typo actually gets written.
    """
    for spec in TOOL_SPECS:
        assert spec.produces in VALID_PRODUCES, (
            f"{spec.name} declares produces={spec.produces!r}, "
            f"which is not one of {VALID_PRODUCES}")
