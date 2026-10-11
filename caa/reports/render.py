"""One finding structure -> SARIF 2.1.0 (CI/IDE) and Markdown (humans). Secrets are masked."""
from __future__ import annotations

import json

from caa.core.audit import mask_secrets
from caa.core.models import Finding, Level, Status

_SARIF_LEVEL = {"critical": "error", "high": "error", "medium": "warning", "low": "note"}


def to_sarif(findings: list[Finding], tool_version: str = "0.1.0") -> dict:
    rules, results = {}, []
    for f in findings:
        rid = f"caa/{f.cwe}"
        rules.setdefault(rid, {
            "id": rid, "name": f.title.replace(" ", ""), "shortDescription": {"text": f.title},
            "properties": {"tags": [f.cwe, "security", f.owasp], "asvs": f.asvs},
        })
        res = {
            "ruleId": rid,
            "level": _SARIF_LEVEL.get(f.severity, "warning") if f.status != Status.REFUTED else "none",
            "message": {"text": mask_secrets(f"{f.title}: {f.explanation}")[:1000]},
            "locations": [_loc(f.location.file, f.location.start_line, f.location.end_line)],
            "partialFingerprints": {"caaId": f.id},
            "properties": {
                "confidence": f.confidence_label, "status": f.status.value, "severity": f.severity,
                "severityRationale": f.severity_rationale, "group": f.group.value,
                "notVerified": f.not_verified, "sources": f.sources,
                "evidence": [{"level": f"L{int(e.level)}", "by": e.by, "detail": mask_secrets(e.detail)} for e in f.evidence],
            },
        }
        if f.status == Status.REFUTED:
            res["suppressions"] = [{"kind": "external", "justification":
                                    f"refuted by {f.extra.get('refuted_by')} at {f.refutation.file}:{f.refutation.line}"}]
        if f.dataflow:
            res["codeFlows"] = [{"threadFlows": [{"locations": [
                {"location": {**_loc(s.ref.file, s.ref.line, None),
                              "message": {"text": f"{s.kind}: {mask_secrets(s.code)[:200]}"}}} for s in f.dataflow]}]}]
        if f.fix:
            res["fixes"] = [{"description": {"text": f.fix.explanation}, "artifactChanges": [],
                             "properties": {"unifiedDiff": f.fix.diff, "rescanClean": f.fix.rescan_clean,
                                            "propertyAfter": f.fix.property_after, "by": f.fix.by}}]
        results.append(res)
    return {"$schema": "https://json.schemastore.org/sarif-2.1.0.json", "version": "2.1.0",
            "runs": [{"tool": {"driver": {"name": "code-audit-agent", "version": tool_version,
                                          "informationUri": "https://github.com/usershoislom/code-audit-agent",
                                          "rules": list(rules.values())}},
                      "results": results}]}


def _loc(file: str | None, line: int | None, end: int | None) -> dict:
    region = {"startLine": line or 1}
    if end and end >= (line or 1):
        region["endLine"] = end
    return {"physicalLocation": {"artifactLocation": {"uri": file or ""}, "region": region}}


def to_markdown(findings: list[Finding], inventory: dict, stats: dict, title: str = "Security review") -> str:
    open_ = [f for f in findings if f.status != Status.REFUTED]
    refuted = [f for f in findings if f.status == Status.REFUTED]
    open_.sort(key=lambda f: (-int(f.level), ["critical", "high", "medium", "low"].index(f.severity)
                              if f.severity in ("critical", "high", "medium", "low") else 9))
    lines = [f"# {title}", "",
             f"Target: `{inventory.get('root', inventory.get('base_url', '?'))}`  ",
             f"Findings: **{len(open_)} open** ({sum(1 for f in open_ if f.status == Status.NEEDS_HUMAN)} need human review), "
             f"{len(refuted)} candidates refuted with a cited protection.", "",
             "Confidence is the highest evidence level reached: L0 pattern · L1 independent agreement · L2 trace · "
             "L3 refutation failed · L4 harmless dynamic check · L5 patch verified.", "",
             "| ID | Level | Severity | CWE | Location | Title | Status |", "|---|---|---|---|---|---|---|"]
    for f in open_:
        lines.append(f"| {f.id} | {f.confidence_label} | {f.severity} | {f.cwe} | `{f.location.file}:{f.location.start_line}` "
                     f"| {f.title} | {f.status.value} |")
    lines.append("")
    for f in open_:
        lines += _finding_md(f)
    if refuted:
        lines += ["## Refuted candidates", "", "| Candidate | CWE | Protection (verified line) | By |", "|---|---|---|---|"]
        for f in refuted:
            r = f.refutation
            lines.append(f"| `{f.location.file}:{f.location.start_line}` | {f.cwe} | `{r.file}:{r.line}` {r.note} "
                         f"| {f.extra.get('refuted_by')} |")
        lines.append("")
    lines += ["## Run", "", "```json", json.dumps(stats, indent=1, default=str), "```", ""]
    return mask_secrets("\n".join(lines))


def _finding_md(f: Finding) -> list[str]:
    out = [f"## {f.id} — {f.title} ({f.cwe})", "",
           f"- **Location:** `{f.location.file}:{f.location.start_line}`"
           + (f" in `{f.location.function}()`" if f.location.function else ""),
           f"- **Mapping:** {f.owasp or '-'}; ASVS {f.asvs or '-'}",
           f"- **Severity:** {f.severity} — {f.severity_rationale}",
           f"- **Confidence:** {f.confidence_label} ({f.status.value}); reported by {', '.join(f.sources)}", ""]
    if f.explanation:
        out += [f"**Why it is a risk.** {f.explanation}", ""]
    if f.dataflow:
        out += ["**Data flow (verified references):**", ""]
        for i, s in enumerate(f.dataflow, 1):
            out.append(f"{i}. `{s.kind}` `{s.ref.file}:{s.ref.line}` — `{s.code[:120]}`"
                       + (f" ({s.ref.note})" if s.ref.note and not s.ref.note.startswith("param:") else ""))
        out.append("")
    out += ["**Evidence ladder:**", ""]
    for e in sorted(f.evidence, key=lambda e: e.level):
        refs = ", ".join(f"`{r.file}:{r.line}`" for r in e.refs if r.file)
        out.append(f"- L{int(e.level)} [{e.by}] {e.detail}" + (f" — {refs}" if refs else ""))
    out.append("")
    if f.llm_verdict:
        out += [f"**Model triage:** {f.llm_verdict.get('verdict')} — {f.llm_verdict.get('explanation', '')[:400]}", ""]
    out += ["**Not verified:**", ""] + [f"- {n}" for n in (f.not_verified or ["(nothing listed)"])] + [""]
    if f.fix:
        state = (f"rescan clean: {f.fix.rescan_clean}; property after patch: "
                 f"{f.fix.property_after if f.fix.property_after is not None else 'not run'}")
        out += [f"**Fix** ({f.fix.by}; {state}). {f.fix.explanation}", "", "```diff", f.fix.diff.rstrip(), "```", ""]
    return out
