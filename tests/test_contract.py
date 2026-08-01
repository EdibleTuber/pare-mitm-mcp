from pare_mitm_mcp.contract import TOOL_SPECS, WorkerContractAdapter

EXPECTED = {"list_flows", "get_flow", "search_flows", "capture_health"}


def test_all_tools_named():
    assert {s.name for s in TOOL_SPECS} == EXPECTED


def test_all_tools_low_tier():
    assert all(s.risk_tier == "low" for s in TOOL_SPECS)


def test_adapter_lists_all():
    assert len(WorkerContractAdapter().list_tools()) == len(EXPECTED)
