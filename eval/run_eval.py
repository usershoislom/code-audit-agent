"""Ablation table on the seeded stand.

  python -m eval.run_eval                 # deterministic rows (no model needed)
  python -m eval.run_eval --llm           # + rows that need a model (configs/providers.yaml, own stand)

Rows (cumulative where it makes sense):
  sast_only        Semgrep (our offline rules) + Bandit, every candidate reported (L0)
  llm_only_files   the model alone, one prompt per file, no tools (needs --llm)
  sast_llm_triage  SAST candidates + LLM triage, no deterministic verification (needs --llm)
  agent_no_llm     all generators + deterministic ladder L1-L3 (taint, route policy, defender)
  agent_llm_norag  agent_no_llm + LLM triage/entry-point pass without knowledge cards (needs --llm)
  agent_llm_rag    agent_no_llm + LLM triage/entry-point pass with knowledge cards (needs --llm)
  agent_full       agent_no_llm + L4 property checks in the sandbox + patch/rescan (L5)
Every run keeps its state/, audit log and reports under eval/results/<row>/ so the table can be
re-derived from logs (`python -m eval.run_eval --from-logs`).
"""
from __future__ import annotations

import argparse
import json
import shutil
import sys
import time
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from caa.cli import load_dotenv  # noqa: E402
from caa.core.audit import AuditLog  # noqa: E402
from caa.core.citations import ReadLedger  # noqa: E402
from caa.core.kb import KnowledgeBase  # noqa: E402
from caa.core.llm.router import Confidentiality, build_router  # noqa: E402
from caa.core.models import Status  # noqa: E402
from caa.core.orchestrator import Orchestrator, PipelineOptions  # noqa: E402
from caa.core.triage import file_baseline  # noqa: E402
from caa.engine_code.engine import CodeEngine  # noqa: E402
from caa.reports.render import to_markdown, to_sarif  # noqa: E402
from caa.sandbox.runner import Sandbox, SandboxConfig, SandboxUnavailable  # noqa: E402
from caa.tools.fs import RepoFS  # noqa: E402
from eval.metrics import evaluate, load_labels  # noqa: E402

REPO = ROOT / "eval" / "seeded" / "repo"
LABELS = ROOT / "eval" / "seeded" / "labels.yaml"
RESULTS = ROOT / "eval" / "results"

ROWS = {
    "sast_only": dict(generators=set(), verify=False, triage=False, entry=False, rag=False, dynamic=False, reanchor=False),
    "llm_only_files": dict(llm_baseline=True),
    "sast_llm_triage": dict(generators=set(), verify=False, triage=True, entry=False, rag=True, dynamic=False),
    "agent_no_llm": dict(verify=True, triage=False, entry=False, rag=False, dynamic=False),
    "agent_llm_norag": dict(verify=True, triage=True, entry=True, rag=False, dynamic=False),
    "agent_llm_rag": dict(verify=True, triage=True, entry=True, rag=True, dynamic=False),
    "agent_full": dict(verify=True, triage=False, entry=False, rag=False, dynamic=True, patch=True),
}
NEEDS_LLM = {"llm_only_files", "sast_llm_triage", "agent_llm_norag", "agent_llm_rag"}


def rows_from_findings(findings) -> list[dict]:
    return [{"file": f["location"]["file"], "line": f["location"]["start_line"], "cwe": f["cwe"],
             "level": f["level"], "status": f["status"]} for f in findings]


def reported(rows: list[dict], min_level: int = 0) -> list[dict]:
    return [r for r in rows if r["status"] != Status.REFUTED.value and r["level"] >= min_level]


def run_row(name: str, spec: dict, router, sandbox) -> dict:
    out = RESULTS / name
    shutil.rmtree(out, ignore_errors=True)
    out.mkdir(parents=True)
    t0 = time.time()
    if router is not None:      # model calls of this row are logged in this row's audit log
        row_audit = AuditLog(out / "audit.jsonl")
        router.audit = row_audit
        for m in router.models.values():
            m._audit = row_audit
            if getattr(m, "_m", None) is not None:
                m._m.audit = row_audit
                m._m.usage = {"prompt_tokens": 0, "completion_tokens": 0, "calls": 0}
    if spec.get("llm_baseline"):
        return run_llm_baseline(out, router, t0)
    kb = KnowledgeBase()
    audit = AuditLog(out / "audit.jsonl")
    eng = CodeEngine(REPO, kb, sandbox=sandbox if spec.get("dynamic") else None, audit=audit,
                     generators=spec.get("generators"), reanchor=spec.get("reanchor", True))
    opts = PipelineOptions(use_verification=spec["verify"], use_llm_triage=spec["triage"],
                           use_llm_entrypoints=spec["entry"], use_rag=spec["rag"],
                           use_dynamic=spec.get("dynamic", False), use_patch=spec.get("patch", False),
                           target_trust="own_stand")
    res = Orchestrator(eng, kb, opts, out, router=router if spec["triage"] or spec["entry"] else None,
                       audit=audit).run()
    findings = [f.model_dump(mode="json") for f in res.findings]
    (out / "findings.json").write_text(json.dumps(findings, indent=1))
    (out / "report.md").write_text(to_markdown(res.findings, res.inventory, res.stats, f"Seeded stand: {name}"))
    (out / "report.sarif").write_text(json.dumps(to_sarif(res.findings), indent=1))
    return {"seconds": round(time.time() - t0, 1), "stats": res.stats, "loc": res.inventory["python_loc"]}


def run_llm_baseline(out: Path, router, t0) -> dict:
    model = router.for_task("analysis", Confidentiality.OWN_STAND)
    ledger = ReadLedger()
    fs = RepoFS(REPO, ledger)
    findings, loc = [], 0
    audit = AuditLog(out / "audit.jsonl")
    files = fs.iter_files("*.py") + fs.iter_files("*requirements*.txt")
    codes = {rel: fs.read_file(rel, 1, None) for rel in files}
    loc = sum(c.count("\n") + 1 for c in codes.values())
    with ThreadPoolExecutor(max_workers=8) as pool:
        results = list(pool.map(lambda rel: (rel, file_baseline(model, ledger, rel, codes[rel])), files))
    for rel, hyps in results:
        audit.write("file_baseline", file=rel, hypotheses=[h.model_dump() for h in hyps])
        for h in hyps:
            findings.append({"location": {"file": h.file, "start_line": h.line}, "cwe": h.cwe.upper(),
                             "level": 0, "status": "open"})
    (out / "findings.json").write_text(json.dumps(findings, indent=1))
    return {"seconds": round(time.time() - t0, 1), "stats": {"llm_usage": {"analysis": model.usage}}, "loc": loc}


def meta_from_logs(name: str) -> dict:
    """Seconds and token usage of a row recomputed from its audit log alone."""
    p = RESULTS / name / "audit.jsonl"
    if not p.exists():
        return {}
    recs = [json.loads(line) for line in p.read_text().splitlines() if line.strip()]
    calls = [r for r in recs if r["kind"] == "llm_call"]
    usage = {"prompt_tokens": 0, "completion_tokens": sum(r.get("completion_tokens") or 0 for r in calls),
             "calls": len(calls)}
    loc = sum((REPO / f).read_text().count("\n") + 1 for f in RepoFS(REPO).iter_files("*.py"))
    return {"seconds": round(recs[-1]["ts"] - recs[0]["ts"], 1) if recs else 0,
            "stats": {"llm_usage": {"analysis": usage}}, "loc": loc, "derived_from_logs": True}


def table(results: dict, labels, all_files) -> tuple[str, dict]:
    metrics = {}
    for d in sorted(RESULTS.iterdir()) if RESULTS.exists() else []:
        if d.is_dir() and d.name in ROWS and d.name not in results and (d / "findings.json").exists():
            results[d.name] = meta_from_logs(d.name)
    for name, meta in results.items():
        p = RESULTS / name / "findings.json"
        if not p.exists():
            continue
        rows = rows_from_findings(json.loads(p.read_text()))
        m_all = evaluate(reported(rows), labels, all_files)
        m_l2 = evaluate(reported(rows, 2), labels, all_files)
        usage = (meta.get("stats") or {}).get("llm_usage") or {}
        tokens = sum(u.get("prompt_tokens", 0) + u.get("completion_tokens", 0) for u in usage.values() if u)
        loc = meta.get("loc") or 1
        metrics[name] = {"all_open": m_all, "level_ge_2": m_l2, "seconds": meta.get("seconds"),
                         "sec_per_kloc": round(meta.get("seconds", 0) / loc * 1000, 1),
                         "tokens_per_kloc": round(tokens / loc * 1000) if tokens else 0}
    base_fp = metrics.get("sast_only", {}).get("all_open", {}).get("overall", {}).get("fp")
    base_tp = metrics.get("sast_only", {}).get("all_open", {}).get("overall", {}).get("tp")
    lines = ["| row | reported | TP | FP | FN | precision | recall | F1 | FP vs SAST | TP lost vs SAST | "
             "FPR clean files | pair acc. | P (≥L2) | R (≥L2) | s/kLOC | tok/kLOC |",
             "|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|"]
    for name in ROWS:
        if name not in metrics:
            lines.append(f"| {name} | not run | | | | | | | | | | | | | | |")
            continue
        m = metrics[name]
        o = m["all_open"]["overall"]
        o2 = m["level_ge_2"]["overall"]
        fpd = "—"
        if base_fp and name != "sast_only":
            fpd = f"-{(1 - o['fp'] / base_fp) * 100:.0f}%" if o["fp"] <= base_fp else f"+{(o['fp'] / base_fp - 1) * 100:.0f}%"
        lost = "-"
        if base_tp is not None and name != "sast_only":
            sast_hits = set(_hits("sast_only", labels))
            lost = str(len(sast_hits - set(_hits(name, labels))))
        lines.append(f"| {name} | {o['tp'] + o['fp']} | {o['tp']} | {o['fp']} | {o['fn']} | {o['precision']} | "
                     f"{o['recall']} | {o['f1']} | {fpd} | {lost} | {m['all_open']['fpr_clean_files']} | "
                     f"{m['all_open']['pair_accuracy']} | {o2['precision']} | {o2['recall']} | "
                     f"{m['sec_per_kloc']} | {m['tokens_per_kloc']} |")
    return "\n".join(lines), metrics


def _hits(name: str, labels) -> list[int]:
    from eval.metrics import match
    rows = rows_from_findings(json.loads((RESULTS / name / "findings.json").read_text()))
    hit, _, _ = match(reported(rows), labels)
    return sorted(hit)


def llm_reachable(router) -> str | None:
    try:
        m = router.for_task("analysis", Confidentiality.OWN_STAND)
        m._get().client.models.list()
        return None
    except Exception as exc:  # noqa: BLE001
        return f"{type(exc).__name__}: {str(exc)[:200]}"


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--llm", action="store_true")
    ap.add_argument("--rows", nargs="*")
    ap.add_argument("--from-logs", action="store_true", help="recompute the table from eval/results/* only")
    args = ap.parse_args()
    load_dotenv()
    labels = load_labels(LABELS, REPO)
    all_files = RepoFS(REPO).iter_files("*.py") + ["requirements.txt"]
    meta_path = RESULTS / "runs.json"
    results = json.loads(meta_path.read_text()) if meta_path.exists() else {}
    if not args.from_logs:
        router = build_router(yaml.safe_load((ROOT / "configs" / "providers.yaml").read_text())) if args.llm else None
        if router is not None:
            err = llm_reachable(router)
            if err:
                print(f"[eval] model not reachable, LLM rows skipped: {err}", file=sys.stderr)
                router = None
        try:
            sandbox = Sandbox(SandboxConfig())
        except SandboxUnavailable as exc:
            print(f"[eval] {exc}", file=sys.stderr)
            sandbox = None
        for name in args.rows or ROWS:
            if name in NEEDS_LLM and router is None:
                continue
            if name == "agent_full" and sandbox is None:
                continue
            print(f"[eval] {name} ...", file=sys.stderr)
            results[name] = run_row(name, ROWS[name], router, sandbox)
            results[name]["sandbox"] = sandbox.backend if (sandbox and ROWS[name].get("dynamic")) else None
        RESULTS.mkdir(parents=True, exist_ok=True)
        meta_path.write_text(json.dumps(results, indent=1, default=str))
    md, metrics = table(results, labels, all_files)
    (RESULTS / "metrics.json").write_text(json.dumps(metrics, indent=1))
    (RESULTS / "table.md").write_text(md + "\n")
    print(md)
    return 0


if __name__ == "__main__":
    sys.exit(main())
