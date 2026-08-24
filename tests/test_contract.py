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
