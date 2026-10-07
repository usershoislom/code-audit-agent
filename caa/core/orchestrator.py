"""Fixed 6-stage pipeline. Order is decided here, never by the model.

  1 inventory  2 candidates  3 context  4 triage (LLM)  5 verification ladder  6 patch + report

State is serialised after every stage (out/state/NN-<stage>.json) so a run is
reproducible and auditable; the audit log holds every tool and model call.
"""
from __future__ import annotations

import json
import time
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field
from pathlib import Path

from caa.core.audit import AuditLog
from caa.core.engine import ContextSlice, EvidenceEngine
from caa.core.kb import KnowledgeBase
from caa.core.llm.router import Confidentiality, ModelRouter
from caa.core.models import Evidence, Finding, Group, Level, Ref, Status
from caa.core.triage import TriageResult, dumps, triage


@dataclass
class PipelineOptions:
    use_verification: bool = True     # deterministic L2/L3 (taint, route policy, defender)
    use_llm_triage: bool = False
    use_llm_entrypoints: bool = False
    use_rag: bool = True              # knowledge card in the triage prompt
    use_dynamic: bool = False         # L4 (sandbox) - trusted code only
    use_patch: bool = True
    triage_budget: int = 6
    llm_concurrency: int = 8
    max_candidates: int = 200
    target_trust: str = "third_party"  # third_party | own_stand
    stages_to_save: bool = True


@dataclass
class RunResult:
    findings: list[Finding]
    inventory: dict
    stats: dict = field(default_factory=dict)


class Orchestrator:
    def __init__(self, engine: EvidenceEngine, kb: KnowledgeBase, opts: PipelineOptions, out_dir: Path | None,
                 router: ModelRouter | None = None, audit: AuditLog | None = None):
        self.engine, self.kb, self.opts, self.out_dir = engine, kb, opts, out_dir
        self.router = router
        self.audit = audit or AuditLog(out_dir / "audit.jsonl" if out_dir else None)
        self.tag = Confidentiality.OWN_STAND if opts.target_trust == "own_stand" else Confidentiality.TARGET_PRIVATE
        self.stats: dict = {"stage_seconds": {}}

    def _model(self, role: str = "analysis"):
        if self.router is None:
            return None
        return self.router.for_task(role, self.tag)

    def _save(self, n: int, stage: str, payload) -> None:
        if not self.out_dir or not self.opts.stages_to_save:
            return
        d = self.out_dir / "state"
        d.mkdir(parents=True, exist_ok=True)
        (d / f"{n:02d}-{stage}.json").write_text(dumps(payload))

    def _timed(self, stage: str, fn):
        t0 = time.time()
        out = fn()
        self.stats["stage_seconds"][stage] = round(time.time() - t0, 2)
        self.audit.write("stage_done", stage=stage, seconds=self.stats["stage_seconds"][stage])
        return out

    def run(self) -> RunResult:
        eng, o = self.engine, self.opts
        self.audit.write("run_start", engine=eng.name, options=o.__dict__, tag=self.tag.value)
        # 1. inventory
        inv = self._timed("inventory", eng.inventory)
        self._save(1, "inventory", inv)
        # 2. candidates
        cands = self._timed("candidates", lambda: eng.generate(inv))
        if o.use_llm_entrypoints and self.router is not None:
            model = self._model()
            cands += self._timed("llm_entrypoints", lambda: eng.llm_hypotheses(inv, model))
        findings = eng.to_findings(cands)[: o.max_candidates]
        self.stats["candidates"] = len(cands)
        self.stats["findings_initial"] = len(findings)
        self._save(2, "candidates", [f.model_dump() for f in findings])
        # 3. context
        contexts: dict[str, ContextSlice] = {}

        def stage_context():
            for f in findings:
                contexts[f.id] = eng.context(f)
        self._timed("context", stage_context)
        self._save(3, "context", {fid: {"ranges": c.ranges, "facts": c.facts} for fid, c in contexts.items()})
        # 4. triage (LLM node)
        triages: dict[str, TriageResult] = {}
        if o.use_llm_triage and self.router is not None:
            model = self._model()
            tools = eng.tools()

            def one(f):
                ctx = contexts[f.id]
                card = self.kb.get(f.cwe) if o.use_rag else None
                return f.id, triage(model, tools, eng.ledger, _describe(f), ctx.text,
                                    self.kb.render(card) if card else "(knowledge base disabled)",
                                    ctx.ranges, budget=o.triage_budget,
                                    candidate_ref=Ref(file=f.location.file, line=f.location.start_line))

            def stage_triage():
                # independent candidates -> concurrent model calls; results are keyed, order-independent
                todo = [f for f in findings if f.group != Group.AGENT_SAFETY]
                with ThreadPoolExecutor(max_workers=o.llm_concurrency) as pool:
                    for fid, t in pool.map(one, todo):
                        triages[fid] = t
            self._timed("triage", stage_triage)
        self._save(4, "triage", {k: v.to_dict() for k, v in triages.items()})
        # 5. verification ladder
        def stage_verify():
            for f in findings:
                _agreement(f)
                if o.use_verification:
                    eng.verify(f, contexts[f.id])
                if f.id in triages:
                    apply_triage(f, triages[f.id], deterministic=o.use_verification)
                if o.use_dynamic and f.status == Status.OPEN and f.level >= Level.L2:
                    eng.dynamic(f)
                _finalise(f, self.kb)
        self._timed("verify", stage_verify)
        self._save(5, "verified", [f.model_dump() for f in findings])
        # 6. patch
        if o.use_patch:
            model = self._model() if (self.router is not None and o.use_llm_triage) else None

            def stage_patch():
                for f in findings:
                    if f.status == Status.OPEN and f.level >= Level.L2:
                        eng.fix(f, model)
            self._timed("patch", stage_patch)
        self._save(6, "final", [f.model_dump() for f in findings])
        eng.close()
        if self.router is not None:
            self.stats["llm_usage"] = {n: getattr(m, "usage", {}) for n, m in self.router.models.items()}
        self.audit.write("run_end", stats=self.stats)
        return RunResult(findings, inv, self.stats)


def _describe(f: Finding) -> str:
    return (f"{f.title} ({f.cwe}) at {f.location.file}:{f.location.start_line}"
            f"{' in ' + f.location.function + '()' if f.location.function else ''}\n"
            f"Reported by: {', '.join(f.sources)}\nMessage: {f.explanation or f.extra.get('message', '')}")


_INDEPENDENT = {"semgrep": "sast-rules", "opengrep": "sast-rules", "bandit": "bandit", "codeql": "codeql",
                "llm-entrypoints": "llm", "llm": "llm", "authz-routes": "route-policy", "secrets": "secrets",
                "gitleaks": "secrets", "deps-snapshot": "deps", "osv-scanner": "deps", "injection-scan": "inj"}


def _agreement(f: Finding) -> None:
    fams = {_INDEPENDENT.get(s, s) for s in f.sources}
    if len(fams) >= 2:
        f.add_evidence(Evidence(level=Level.L1, by="agreement",
                                detail=f"independent sources agree on place and CWE: {', '.join(sorted(f.sources))}"))


def apply_triage(f: Finding, t: TriageResult, deterministic: bool) -> None:
    f.llm_verdict = t.to_dict()
    if t.dropped_claims:
        f.not_verified.append(f"{len(t.dropped_claims)} model claim(s) discarded: cited lines were never read")
    if t.injection_suspected:
        f.extra["llm_injection_suspected"] = True
    if t.verdict == "vulnerable":
        refs = [r for _, r in t.claims]
        f.add_evidence(Evidence(level=Level.L1 if "llm" not in f.sources else Level.L0,
                                by="llm-triage", detail="model agrees, with verified citations", refs=refs))
        if "llm" not in f.sources:
            f.sources.append("llm")
        if not deterministic and len(t.dataflow) >= 2:
            f.add_evidence(Evidence(level=Level.L2, by="llm-trace",
                                    detail="model-provided source->sink path; every step cited and read",
                                    refs=t.dataflow))
        if f.status == Status.REFUTED:
            f.status = Status.NEEDS_HUMAN
            f.not_verified.append("deterministic analysis found a protection but the model disagrees")
        if t.severity:
            f.extra["llm_severity"] = t.severity
    elif t.verdict == "not_vulnerable" and t.protection is not None:
        if f.status != Status.REFUTED:
            f.status = Status.REFUTED
            f.refutation = t.protection
            f.extra["refuted_by"] = "llm-triage"
            f.not_verified.append("refuted by model citing a protecting line; not proven by deterministic analysis")
    else:
        if t.protection_rejected:
            f.not_verified.append(f"model's refutation rejected: {t.protection_rejected}")


def _finalise(f: Finding, kb: KnowledgeBase) -> None:
    card = kb.get(f.cwe) or {}
    f.owasp = f.owasp or card.get("owasp", "")
    f.asvs = f.asvs or card.get("asvs", "")
    if f.group == Group.BUSINESS_LOGIC:
        if f.level > Level.L3:
            f.level = Level.L3
        if f.status == Status.OPEN:
            f.status = Status.NEEDS_HUMAN
            f.not_verified.append("business-logic hypothesis: requires human confirmation")
    if f.level < Level.L4 and f.group in (Group.DATAFLOW, Group.ACCESS_CONTROL) and f.status != Status.REFUTED:
        f.not_verified.append("no dynamic (L4) confirmation was performed")
    if f.status != Status.REFUTED:
        if f.level >= Level.L4:
            f.not_verified.append("dynamic check used one harmless marker on one entry point; "
                                  "other call sites of the same sink were not exercised")
        f.not_verified.append("scope: first-party code only; framework and driver behaviour assumed as documented")
    f.not_verified = list(dict.fromkeys(f.not_verified))


def load_json(p: Path):
    return json.loads(p.read_text())
