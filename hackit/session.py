"""
In-memory session state for one HACKiT run: the query history and
whatever was last recommended, so follow-ups like 'run it' or 'show
alternatives' have something to refer back to.
"""
from __future__ import annotations

from dataclasses import dataclass, field

from hackit.intent import IntentResult
from hackit.knowledge import ToolInfo


@dataclass
class Session:
    history: list[str] = field(default_factory=list)
    last_result: IntentResult | None = None
    last_tool: ToolInfo | None = None
    last_command: str | None = None

    def record(self, query: str) -> None:
        self.history.append(query)

    def set_recommendation(self, result: IntentResult) -> None:
        self.last_result = result
        self.last_tool = result.candidates[0] if result.candidates else None
        self.last_command = None
