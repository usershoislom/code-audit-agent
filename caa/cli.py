"""Command line: `caa scan <repo>` (engine CODE) and `caa live --roe <file>` (engine HTTP)."""
from __future__ import annotations

import argparse
import json
import sys
import time
from pathlib import Path

import yaml

from caa.core.audit import AuditLog
from caa.core.kb import KnowledgeBase
from caa.core.models import Status
from caa.core.orchestrator import Orchestrator, PipelineOptions
from caa.reports.render import to_markdown, to_sarif

ROOT = Path(__file__).resolve().parents[1]


def load_dotenv(path: Path = ROOT / ".env") -> None:
    """Minimal .env reader (KEY=VALUE); never overrides variables already set."""
    import os
    if not path.exists():
        return
    for line in path.read_text().splitlines():
        if "=" in line and not line.lstrip().startswith("#"):
            k, v = line.split("=", 1)
            os.environ.setdefault(k.strip(), v.strip().strip('"').strip("'"))


def _load_yaml(p: Path) -> dict:
    return yaml.safe_load(p.read_text()) if p.exists() else {}


def _router(args, audit):
    if not args.llm:
        return None
    from caa.core.llm.router import build_router
    return build_router(_load_yaml(Path(args.providers)), audit)


def _write(out: Path, findings, inventory, stats, title):
    out.mkdir(parents=True, exist_ok=True)
    (out / "report.sarif").write_text(json.dumps(to_sarif(findings), indent=1))
    (out / "report.md").write_text(to_markdown(findings, inventory, stats, title))
    (out / "findings.json").write_text(json.dumps([f.model_dump(mode="json") for f in findings], indent=1))


def cmd_scan(args) -> int:
    from caa.engine_code.engine import CodeEngine
    from caa.sandbox.runner import Sandbox, SandboxConfig, SandboxUnavailable

    cfg = _load_yaml(Path(args.config))
    out = Path(args.out or f"caa-out/{time.strftime('%Y%m%d-%H%M%S')}")
    audit = AuditLog(out / "audit.jsonl")
    sandbox = None
    if args.trust_target:
        sc = cfg.get("sandbox", {})
        try:
            sandbox = Sandbox(SandboxConfig(backend=args.sandbox or sc.get("backend", "auto"),
                                            image=sc.get("image", "caa-sandbox:latest"),
                                            timeout_s=sc.get("timeout_s", 20), memory_mb=sc.get("memory_mb", 512)))
        except SandboxUnavailable as exc:
            print(f"[caa] L4 disabled: {exc}", file=sys.stderr)
    kb = KnowledgeBase()
    engine = CodeEngine(Path(args.repo), kb, sandbox=sandbox, audit=audit,
                        codeql_sarif=Path(args.codeql_sarif) if args.codeql_sarif else None)
    llm_cfg = cfg.get("llm", {})
    opts = PipelineOptions(use_llm_triage=args.llm, use_llm_entrypoints=args.llm and llm_cfg.get("entrypoint_pass", True),
                           use_dynamic=sandbox is not None, triage_budget=llm_cfg.get("triage_tool_budget", 6),
                           target_trust="own_stand" if args.own_stand else cfg.get("target_trust", "third_party"),
                           use_patch=not args.no_patch)
    res = Orchestrator(engine, kb, opts, out, router=_router(args, audit), audit=audit).run()
    _write(out, res.findings, res.inventory, res.stats, f"Security review: {Path(args.repo).name}")
    n_open = sum(1 for f in res.findings if f.status != Status.REFUTED)
    print(f"[caa] {n_open} open finding(s), {len(res.findings) - n_open} refuted -> {out}/report.md, {out}/report.sarif")
    return 0


def cmd_live(args) -> int:
    print("[caa] engine HTTP is not implemented in this build", file=sys.stderr)
    return 2


def main(argv=None) -> int:
    p = argparse.ArgumentParser(prog="caa", description="Local AI agent for defensive security code review")
    sub = p.add_subparsers(dest="cmd", required=True)
    s = sub.add_parser("scan", help="white-box review of a source tree (engine CODE)")
    s.add_argument("repo")
    s.add_argument("--out")
    s.add_argument("--config", default=str(ROOT / "configs" / "default.yaml"))
    s.add_argument("--providers", default=str(ROOT / "configs" / "providers.yaml"))
    s.add_argument("--llm", action="store_true", help="enable LLM triage / entry-point pass (local model by default)")
    s.add_argument("--own-stand", action="store_true",
                   help="target is our own stand: hosted providers allowed (default: third-party, local model only)")
    s.add_argument("--trust-target", action="store_true",
                   help="code is trusted (own stand): allow L4 property checks in the sandbox")
    s.add_argument("--sandbox", choices=["auto", "docker", "local-unshare"])
    s.add_argument("--codeql-sarif")
    s.add_argument("--no-patch", action="store_true")
    s.set_defaults(fn=cmd_scan)
    lv = sub.add_parser("live", help="read-only assessment of a live app within an ROE (engine HTTP)")
    lv.add_argument("--roe", required=True)
    lv.add_argument("--out")
    lv.add_argument("--llm", action="store_true")
    lv.add_argument("--providers", default=str(ROOT / "configs" / "providers.yaml"))
    lv.set_defaults(fn=cmd_live)
    args = p.parse_args(argv)
    load_dotenv()
    return args.fn(args)


if __name__ == "__main__":
    sys.exit(main())
