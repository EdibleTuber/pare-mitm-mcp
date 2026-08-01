from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

CONTRACT_VERSION = 1

_BOUNDED_OUT = {"type": "object", "properties": {"summary": {"type": "string"}}}


@dataclass(frozen=True)
class ToolSpec:
    name: str
    risk_tier: str
    description: str
    input_schema: dict[str, Any]
    output_schema: dict[str, Any] = field(default_factory=lambda: dict(_BOUNDED_OUT))


def _in(**props) -> dict[str, Any]:
    return {"type": "object", "properties": props}


TOOL_SPECS = [
    ToolSpec("list_flows", "low",
             "TRAFFIC. List captured HTTPS flows as summary rows "
             "{id, ts, kind, method, host, path, scheme, status, content_type, resp_size, error}. "
             "kind='error' rows are failed TLS/connection attempts (e.g. cert pinning) — they are "
             "surfaced, not hidden. Filters: host, method, status, since (unix ts; 'flows since I "
             "last triggered'), limit. Requires the daemon (start with /mitm up).",
             _in(host={"type": "string"}, method={"type": "string"},
                 status={"type": "integer"}, since={"type": "number"},
                 limit={"type": "integer"})),
    ToolSpec("get_flow", "low",
             "TRAFFIC. Full detail for one flow id: request line + headers + body, response headers "
             "+ body. JSON bodies are pretty-printed; binary is summarised as '<binary N bytes>'. "
             "Large bodies are auto-persisted by the capture layer (read via read_capture).",
             _in(id={"type": "string"})),
    ToolSpec("search_flows", "low",
             "TRAFFIC. Regex/substring search across a scope (url|headers|req-body|resp-body|all); "
             "returns matching flow ids with a context snippet. Runs daemon-side.",
             _in(pattern={"type": "string"}, scope={"type": "string"},
                 limit={"type": "integer"})),
    ToolSpec("capture_health", "low",
             "TRAFFIC. Is the proxy reachable? Returns {reachable, flows, tls_errors, last_flow_ts}. "
             "Use this to disambiguate an empty capture: daemon down vs nothing-triggered-yet vs "
             "pinning breaking the handshake (tls_errors>0).",
             _in()),
]


class WorkerContractAdapter:
    """Exposes the agent_core WorkerContract shape for assert_conformance."""

    def contract_version(self) -> int:
        return CONTRACT_VERSION

    def list_tools(self) -> list[dict[str, Any]]:
        return [
            {"name": s.name, "risk_tier": s.risk_tier,
             "input_schema": s.input_schema, "output_schema": s.output_schema}
            for s in TOOL_SPECS
        ]
