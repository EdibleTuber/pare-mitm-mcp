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


TOOL_SPECS: list[ToolSpec] = []  # filled in Task 2
