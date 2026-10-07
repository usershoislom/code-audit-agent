"""The single interface both evidence engines (code / http) implement.

The orchestrator only talks to this interface; engines differ in *where
evidence comes from*, not in the pipeline, ladder or report.
"""
from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass, field

from caa.core.citations import ReadLedger
from caa.core.llm.provider import ChatModel
from caa.core.models import Candidate, Finding
from caa.tools.registry import ToolRegistry


@dataclass
class ContextSlice:
    text: str                                   # numbered code / HTTP exchanges shown to the model
    ranges: list[tuple[str, int, int]] = field(default_factory=list)   # data-path ranges (for refutation refs)
    facts: dict = field(default_factory=dict)   # deterministic facts (trace, route map, ...)


class EvidenceEngine(ABC):
    name: str
    ledger: ReadLedger

    @abstractmethod
    def inventory(self) -> dict: ...

    @abstractmethod
    def generate(self, inventory: dict) -> list[Candidate]: ...

    def llm_hypotheses(self, inventory: dict, model: ChatModel) -> list[Candidate]:
        return []

    @abstractmethod
    def to_findings(self, candidates: list[Candidate]) -> list[Finding]: ...

    @abstractmethod
    def context(self, finding: Finding) -> ContextSlice: ...

    def tools(self) -> ToolRegistry | None:
        return None

    @abstractmethod
    def verify(self, finding: Finding, ctx: ContextSlice) -> None:
        """Deterministic ladder steps L1-L3 (+ refutations with verified references)."""

    def dynamic(self, finding: Finding) -> None:
        """L4: harmless dynamic confirmation (property check / two-own-accounts diff)."""

    def fix(self, finding: Finding, model: ChatModel | None) -> None:
        """L5: minimal patch + rescan."""

    def close(self) -> None:
        pass
