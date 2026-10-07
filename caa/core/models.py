"""Shared data model for both engines (code and http).

Everything that crosses a stage boundary is a pydantic model so the run state
can be serialized after every stage (reproducibility, audit).
"""
from __future__ import annotations

import hashlib
from enum import Enum, IntEnum
from typing import Literal

from pydantic import BaseModel, Field


class Level(IntEnum):
    """Evidence ladder. Confidence == highest level actually reached."""

    L0 = 0  # pattern match
    L1 = 1  # independent sources agree
    L2 = 2  # source->sink trace with verified file:line, no sanitizer
    L3 = 3  # defender pass failed to refute
    L4 = 4  # harmless dynamic property check confirms
    L5 = 5  # patch confirmed (rescan clean, property passes after patch)


class Group(str, Enum):
    DATAFLOW = "A"
    ACCESS_CONTROL = "B"
    BUSINESS_LOGIC = "C"
    SECRETS_CONFIG = "D"
    DEPENDENCIES = "E"
    AGENT_SAFETY = "X"  # e.g. prompt-injection text found in analysed material


class Status(str, Enum):
    OPEN = "open"            # still a finding (any level)
    REFUTED = "refuted"      # dismissed WITH a verified protection reference
    NEEDS_HUMAN = "needs_human"


class Location(BaseModel):
    file: str
    start_line: int
    end_line: int | None = None
    function: str | None = None

    def key(self) -> str:
        return f"{self.file}:{self.start_line}"


class Ref(BaseModel):
    """A verifiable reference: file:line (code) or request id (http)."""

    file: str | None = None
    line: int | None = None
    http_exchange: str | None = None
    note: str = ""

    def __str__(self) -> str:  # pragma: no cover - cosmetic
        if self.file:
            return f"{self.file}:{self.line}"
        return f"http#{self.http_exchange}"


class DataflowStep(BaseModel):
    kind: Literal["source", "propagation", "call", "sink", "check"]
    ref: Ref
    code: str = ""


class Evidence(BaseModel):
    level: Level
    by: str                   # analyzer / stage that produced it
    detail: str
    refs: list[Ref] = Field(default_factory=list)


class Candidate(BaseModel):
    """A raw hypothesis from any generator (SAST, LLM, route analysis, http)."""

    rule_id: str
    source: str               # semgrep | bandit | taint | authz | llm-entrypoints | gitleaks | ...
    cwe: str                  # "CWE-89"
    group: Group
    location: Location
    message: str = ""
    snippet: str = ""
    extra: dict = Field(default_factory=dict)

    def dedup_key(self) -> tuple[str, int, str]:
        return (self.location.file, self.location.start_line, self.cwe)


class Patch(BaseModel):
    diff: str
    explanation: str
    by: str                   # "template:<name>" | "llm"
    rescan_clean: bool | None = None
    property_after: bool | None = None


class Finding(BaseModel):
    id: str = ""
    title: str
    cwe: str
    group: Group
    owasp: str = ""
    asvs: str = ""
    location: Location
    sources: list[str] = Field(default_factory=list)   # generators that agreed
    dataflow: list[DataflowStep] = Field(default_factory=list)
    explanation: str = ""
    severity: str = "medium"
    severity_rationale: str = ""
    evidence: list[Evidence] = Field(default_factory=list)
    level: Level = Level.L0
    status: Status = Status.OPEN
    not_verified: list[str] = Field(default_factory=list)
    refutation: Ref | None = None
    fix: Patch | None = None
    llm_verdict: dict | None = None
    extra: dict = Field(default_factory=dict)

    def add_evidence(self, ev: Evidence) -> None:
        self.evidence.append(ev)
        if ev.level > self.level:
            self.level = ev.level

    def make_id(self) -> str:
        h = hashlib.sha1(f"{self.location.file}:{self.location.start_line}:{self.cwe}".encode()).hexdigest()
        self.id = f"CAA-{h[:8]}"
        return self.id

    @property
    def confidence_label(self) -> str:
        return f"L{int(self.level)}"
