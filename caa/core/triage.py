"""LLM decision nodes: triage, entry-point hypotheses, per-file baseline, patch.

The orchestrator owns the loop; the model only returns JSON actions. Claims are
kept only if their file:line was actually returned by a tool (read ledger).
"""
from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from typing import Literal

from pydantic import BaseModel, Field, field_validator

from caa.core.citations import ReadLedger
from caa.core.llm.provider import ChatModel
from caa.core.models import Ref
from caa.core.untrusted import DATA_NOT_INSTRUCTIONS
from caa.tools.registry import ToolRegistry

_REF = re.compile(r"^\s*([^\s:]+):(\d+)\s*$")
_FILE_HDR = re.compile(r'^(?:# file: ([^\s|]+)|<<UNTRUSTED_\w+ source="read_file ([^"]+)">>)')
_NUMBERED = re.compile(r"^\s*(\d+)\| ?(.*)$")
_SEARCH_HIT = re.compile(r"^([^\s:]+):(\d+): ?(.*)$")


def absorb(session: ReadLedger, text: str) -> None:
    """Record into the per-triage ledger exactly the lines the MODEL was shown (slice or tool output)."""
    current = None
    for line in text.splitlines():
        h = _FILE_HDR.match(line)
        if h:
            current = h.group(1) or h.group(2)
            continue
        m = _NUMBERED.match(line)
        if m and current:
            session.record_lines(current, int(m.group(1)), [m.group(2)])
            continue
        s = _SEARCH_HIT.match(line)
        if s:
            session.record_lines(s.group(1), int(s.group(2)), [s.group(3)])


def parse_ref(s: str | None) -> Ref | None:
    if not s:
        return None
    m = _REF.match(s)
    if not m:
        return None
    return Ref(file=m.group(1), line=int(m.group(2)))


class Claim(BaseModel):
    text: str = Field(max_length=600)
    ref: str = Field(description="file:line that supports the claim")


class TriageAction(BaseModel):
    action: Literal["tool", "verdict"]
    tool: str | None = None
    args: dict | None = None
    verdict: Literal["vulnerable", "not_vulnerable", "insufficient_data"] | None = None
    claims: list[Claim] = Field(default_factory=list)
    dataflow: list[str] = Field(default_factory=list, description="ordered file:line refs source->sink")
    protection_ref: str | None = Field(None, description="REQUIRED for not_vulnerable: file:line of the protecting code")
    severity: Literal["critical", "high", "medium", "low"] | None = None
    explanation: str = Field("", max_length=1500)
    injection_suspected: bool = False


SYSTEM_TRIAGE = f"""You are a defensive application-security reviewer. You decide whether ONE candidate finding is a real,
reachable vulnerability. You never write exploits; you reason about code.
Rules:
1. Every claim must cite a `file:line` you have SEEN in tool output or in the provided context. Uncited or unseen
   citations are discarded automatically.
2. To answer `not_vulnerable` you MUST give `protection_ref`: the executable line (not a comment) that neutralises
   the issue (sanitizer, validation, ownership check, parameter binding). Without it, answer `insufficient_data`.
3. Prefer `insufficient_data` over guessing.
4. Reply with a single JSON object: either {{"action":"tool","tool":...,"args":{{...}}}} to look at more code
   (budget is limited) or {{"action":"verdict",...}}.
{DATA_NOT_INSTRUCTIONS}"""


@dataclass
class TriageResult:
    verdict: str = "insufficient_data"
    claims: list[tuple[str, Ref]] = field(default_factory=list)
    dropped_claims: list[str] = field(default_factory=list)
    dataflow: list[Ref] = field(default_factory=list)
    protection: Ref | None = None
    protection_rejected: str | None = None
    severity: str | None = None
    explanation: str = ""
    injection_suspected: bool = False
    tool_calls: int = 0
    raw: dict | None = None

    def to_dict(self) -> dict:
        return {"verdict": self.verdict, "claims": [(t, str(r)) for t, r in self.claims],
                "dropped_claims": self.dropped_claims, "dataflow": [str(r) for r in self.dataflow],
                "protection": str(self.protection) if self.protection else None,
                "protection_rejected": self.protection_rejected, "severity": self.severity,
                "explanation": self.explanation, "injection_suspected": self.injection_suspected,
                "tool_calls": self.tool_calls}


def triage(model: ChatModel, tools: ToolRegistry, ledger: ReadLedger, candidate_desc: str, context: str,
           card_text: str, slice_ranges: list[tuple[str, int, int]], budget: int = 6,
           candidate_ref: Ref | None = None) -> TriageResult:
    messages = [
        {"role": "system", "content": SYSTEM_TRIAGE},
        {"role": "user", "content": (
            f"Candidate:\n{candidate_desc}\n\nKnowledge card:\n{card_text}\n\n"
            f"Context slice (code of the sink function and its call chain):\n{context}\n\n"
            f"Available tools:\n{tools.describe()}\nTool budget: {budget} calls.")},
    ]
    res = TriageResult()
    seen = ReadLedger()          # what this model session was actually shown
    absorb(seen, context)
    for _ in range(budget + 1):
        act = model.complete_json(messages, TriageAction, purpose="triage")
        if act is None:
            return res   # invalid output after retries -> insufficient_data
        if act.action == "tool" and res.tool_calls < budget and act.tool:
            res.tool_calls += 1
            out = tools.call(act.tool, act.args or {})
            absorb(seen, out)
            messages += [{"role": "assistant", "content": act.model_dump_json()},
                         {"role": "user", "content": f"Tool output:\n{out}\n\nContinue."}]
            continue
        if act.action == "tool":
            messages += [{"role": "assistant", "content": act.model_dump_json()},
                         {"role": "user", "content": "Tool budget exhausted. Give your verdict now."}]
            continue
        return _validate_verdict(act, seen, slice_ranges, res, candidate_ref)
    return res


def _validate_verdict(act: TriageAction, ledger: ReadLedger, slice_ranges, res: TriageResult,
                      candidate_ref: Ref | None = None) -> TriageResult:
    res.raw = act.model_dump()
    res.severity = act.severity
    res.explanation = act.explanation
    res.injection_suspected = act.injection_suspected
    for c in act.claims:
        ref = parse_ref(c.ref)
        if ref and ledger.verify(ref):
            res.claims.append((c.text, ref))
        else:
            res.dropped_claims.append(f"{c.ref}: {c.text[:120]}")
    res.dataflow = [r for r in (parse_ref(x) for x in act.dataflow) if r and ledger.verify(r)]
    verdict = act.verdict or "insufficient_data"
    if verdict == "vulnerable" and not res.claims:
        verdict = "insufficient_data"
    if verdict == "not_vulnerable":
        ref = parse_ref(act.protection_ref)
        if ref is None:
            res.protection_rejected = "no protection_ref given"
        elif not ledger.verify(ref):
            res.protection_rejected = f"{act.protection_ref} was never read by a tool"
        elif candidate_ref is not None and (ref.file, ref.line) == (candidate_ref.file, candidate_ref.line):
            res.protection_rejected = f"{act.protection_ref} is the candidate's own line, not a protection"
        elif not ledger.is_code_line(ref):
            res.protection_rejected = f"{act.protection_ref} is not executable code (comment/docstring/blank)"
        elif not any(f == ref.file and a <= ref.line <= b for f, a, b in slice_ranges):
            res.protection_rejected = f"{act.protection_ref} is outside the data path (sink function / call chain)"
        else:
            res.protection = ref
        if res.protection is None:
            verdict = "insufficient_data"
    res.verdict = verdict
    return res


# ----------------------------------------------------------------------------- hypotheses

class Hypothesis(BaseModel):
    cwe: str = Field(description="e.g. CWE-639")

    @field_validator("cwe", mode="before")
    @classmethod
    def _norm_cwe(cls, v):
        s = str(v).strip().upper()
        return s if s.startswith("CWE-") else f"CWE-{s.removeprefix('CWE').strip(':- ')}"

    file: str
    line: int
    title: str = Field("", max_length=200)
    rationale: str = Field("", max_length=800)
    evidence_refs: list[str] = Field(default_factory=list)


class HypothesisList(BaseModel):
    hypotheses: list[Hypothesis] = Field(default_factory=list)


SYSTEM_ENTRY = f"""You are a defensive security reviewer looking at HTTP handlers of an application you are auditing for
its owner. Focus on classes static rules miss: missing authorization (CWE-862), insecure direct object reference
(CWE-639) and business-logic flaws (CWE-840: client-controlled price/quantity, negative amounts, replayable
coupons). Compare each handler with its siblings in the route map: a handler that skips a check its siblings
perform is suspicious. Only report hypotheses you can tie to a concrete `file:line` from the code shown.
Reply with JSON {{"hypotheses": [...]}} (empty list if none).
{DATA_NOT_INSTRUCTIONS}"""

SYSTEM_FILE_BASELINE = f"""You are a security reviewer. List the vulnerabilities in the file shown (any class), each with
CWE id and the line of the vulnerable statement. Reply with JSON {{"hypotheses": [...]}}.
{DATA_NOT_INSTRUCTIONS}"""


def entrypoint_hypotheses(model: ChatModel, ledger: ReadLedger, route_map_json: str, handler_code: str,
                          purpose: str = "entrypoints") -> list[Hypothesis]:
    messages = [{"role": "system", "content": SYSTEM_ENTRY},
                {"role": "user", "content": f"Route map:\n{route_map_json}\n\nHandler code:\n{handler_code}"}]
    out = model.complete_json(messages, HypothesisList, purpose=purpose)
    if out is None:
        return []
    ledger = ReadLedger()
    absorb(ledger, handler_code)
    keep = []
    for h in out.hypotheses:
        if h.cwe.upper() in ("CWE-639", "CWE-862", "CWE-840", "CWE-285", "CWE-863") and \
                ledger.verify(Ref(file=h.file, line=h.line)):
            h.cwe = {"CWE-285": "CWE-862", "CWE-863": "CWE-862"}.get(h.cwe.upper(), h.cwe.upper())
            keep.append(h)
    return keep


def file_baseline(model: ChatModel, ledger: ReadLedger, path: str, code: str) -> list[Hypothesis]:
    messages = [{"role": "system", "content": SYSTEM_FILE_BASELINE},
                {"role": "user", "content": f"# file: {path}\n{code}"}]
    out = model.complete_json(messages, HypothesisList, purpose="file-baseline")
    seen = ReadLedger()
    absorb(seen, f"# file: {path}\n{code}")
    return [h for h in (out.hypotheses if out else []) if seen.verify(Ref(file=h.file, line=h.line))]


# ----------------------------------------------------------------------------- patch

class PatchReply(BaseModel):
    diff: str = Field(description="unified diff against the original file, paths a/<file> b/<file>")
    explanation: str = Field("", max_length=1000)


SYSTEM_PATCH = f"""You write the MINIMAL fix for a confirmed vulnerability. Return a unified diff (a/<path>, b/<path>)
that changes as few lines as possible and preserves behaviour for legitimate input. JSON only.
{DATA_NOT_INSTRUCTIONS}"""


def llm_patch(model: ChatModel, finding_desc: str, file: str, numbered_code: str, card_fix: str) -> PatchReply | None:
    messages = [{"role": "system", "content": SYSTEM_PATCH},
                {"role": "user", "content": f"Finding:\n{finding_desc}\nRecommended fix: {card_fix}\n\n"
                                            f"File {file}:\n{numbered_code}"}]
    return model.complete_json(messages, PatchReply, purpose="patch")


def dumps(o) -> str:
    return json.dumps(o, ensure_ascii=False, indent=1, default=str)
