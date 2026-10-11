"""Command line: `caa scan <repo>` (engine CODE) and `caa live --roe <file>` (engine HTTP)."""
from __future__ import annotations

import argparse
import json
import os
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


def _write(out: Path, findings, inventory, stats, title, run: dict | None = None, lang: str = "ru"):
    from caa.reports.full import Report, dump_run, to_html
    from caa.reports.full import to_markdown as full_markdown

    out.mkdir(parents=True, exist_ok=True)
    rep = Report(findings, inventory, stats, run or {}, lang)
    (out / "report.sarif").write_text(json.dumps(to_sarif(findings), indent=1))
    (out / "report.md").write_text(full_markdown(rep), encoding="utf-8")
    (out / "report.html").write_text(to_html(rep), encoding="utf-8")
    (out / "run.json").write_text(dump_run(rep), encoding="utf-8")
    (out / "findings.json").write_text(json.dumps([f.model_dump(mode="json") for f in findings], indent=1))
    return rep


def cmd_scan(args) -> int:
    from caa.engine_code.engine import CodeEngine
    from caa.reports.full import console_summary
    from caa.sandbox.runner import Sandbox, SandboxConfig, SandboxUnavailable
    from caa.sources import SourceError, resolve

    cfg = _load_yaml(Path(args.config))
    if (args.run_app or args.sandbox_network == "egress" or args.install_deps) and not args.trust_target:
        print("[caa] --run-app / --sandbox-network egress / --install-deps execute the target's code: "
              "add --trust-target (own or trusted code only)", file=sys.stderr)
        return 2
    t_start = time.time()
    try:
        source = resolve(args.target, ref=args.ref)
    except SourceError as exc:
        print(f"[caa] {exc}", file=sys.stderr)
        return 2
    name = Path(source.url).stem if source.url else source.path.name
    default_root = "/out" if os.environ.get("CAA_IN_DOCKER") else "caa-out"   # /out is the mounted volume
    out = Path(args.out or f"{default_root}/{name}-{time.strftime('%Y%m%d-%H%M%S')}")
    audit = AuditLog(out / "audit.jsonl")
    audit.write("source", source=source.meta())
    if source.kind == "git":
        print(f"[caa] cloned {source.url} @ {source.ref} ({(source.commit or '')[:12]})", file=sys.stderr)
    sandbox = None
    if args.trust_target:
        sc = cfg.get("sandbox", {})
        try:
            sandbox = Sandbox(SandboxConfig(backend=args.sandbox or sc.get("backend", "auto"),
                                            image=sc.get("image", "caa-sandbox:latest"),
                                            timeout_s=sc.get("timeout_s", 20), memory_mb=sc.get("memory_mb", 512),
                                            network=args.sandbox_network))
        except SandboxUnavailable as exc:
            print(f"[caa] L4 disabled: {exc}", file=sys.stderr)
    kb = KnowledgeBase()
    try:
        engine = CodeEngine(source.path, kb, sandbox=sandbox, audit=audit,
                            codeql_sarif=Path(args.codeql_sarif) if args.codeql_sarif else None,
                            install_deps=args.install_deps)
        llm_cfg = cfg.get("llm", {})
        trust = "own_stand" if (args.own_stand or args.trust_target) else cfg.get("target_trust", "third_party")
        opts = PipelineOptions(use_llm_triage=args.llm,
                               use_llm_entrypoints=args.llm and llm_cfg.get("entrypoint_pass", True),
                               use_dynamic=sandbox is not None, use_runtime=sandbox is not None and args.run_app,
                               triage_budget=llm_cfg.get("triage_tool_budget", 6), target_trust=trust,
                               use_patch=not args.no_patch)
        router = _router(args, audit)
        res = Orchestrator(engine, kb, opts, out, router=router, audit=audit).run()
    finally:
        if not args.keep_clone:
            source.cleanup()
    llm_name = None
    if router is not None:
        role = (router.roles or {}).get("analysis")
        llm_name = f"{role}: {router.models[role].config.model}" if role in router.models else role
    run = {"source": source.meta(), "started": time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(t_start)),
           "seconds": round(time.time() - t_start, 1),
           "options": {"trust": "own" if trust == "own_stand" else "third_party", "llm": llm_name,
                       "sandbox": sandbox.backend if sandbox else None, "network": args.sandbox_network,
                       "run_app": args.run_app}}
    rep = _write(out, res.findings, res.inventory, res.stats, name, run, args.report_lang)
    print(console_summary(rep))
    print(f"[caa] full report: {out / 'report.html'}  |  {out / 'report.md'}  |  SARIF: {out / 'report.sarif'}")
    return 0


def cmd_live(args) -> int:
    print("[caa] engine HTTP is not implemented in this build", file=sys.stderr)
    return 2


def main(argv=None) -> int:
    p = argparse.ArgumentParser(prog="caa", description="Local AI agent for defensive security code review")
    sub = p.add_subparsers(dest="cmd", required=True)
    s = sub.add_parser("scan", help="white-box review of a source tree (engine CODE)")
    s.add_argument("target", help="local folder OR https git URL (github.com/owner/repo or owner/repo)")
    s.add_argument("--ref", help="branch or tag to clone (remote targets)")
    s.add_argument("--keep-clone", action="store_true", help="keep the cloned repository after the scan")
    s.add_argument("--report-lang", choices=["ru", "en"], default="ru", help="language of report headings")
    s.add_argument("--out")
    s.add_argument("--config", default=str(ROOT / "configs" / "default.yaml"))
    s.add_argument("--providers", default=str(ROOT / "configs" / "providers.yaml"))
    s.add_argument("--llm", action="store_true", help="enable LLM triage / entry-point pass (local model by default)")
    s.add_argument("--own-stand", action="store_true",
                   help="target is our own stand: hosted providers allowed (default: third-party, local model only)")
    s.add_argument("--trust-target", action="store_true",
                   help="code is trusted (own stand): allow L4 property checks in the sandbox")
    s.add_argument("--sandbox", choices=["auto", "docker", "local-unshare"])
    s.add_argument("--run-app", action="store_true",
                   help="start the application(s) in the sandbox and run localhost-only runtime checks")
    s.add_argument("--sandbox-network", choices=["none", "egress"], default="none",
                   help="egress lets the sandboxed app reach the internet (its APIs, package registries)")
    s.add_argument("--install-deps", action="store_true",
                   help="install the app's dependencies inside the sandbox before starting it (needs egress)")
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
