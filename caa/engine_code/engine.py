"""Engine A - CODE (white box). Evidence = trace in code (+ optional property check)."""
from __future__ import annotations

import ast
import json
import re
from collections import Counter
from pathlib import Path

from caa.core.audit import NULL_AUDIT, AuditLog, mask_secrets
from caa.core.citations import ReadLedger
from caa.core.engine import ContextSlice, EvidenceEngine
from caa.core.kb import KnowledgeBase
from caa.core.models import (Candidate, DataflowStep, Evidence, Finding, Group, Level, Location, Patch, Ref,
                             Status)
from caa.core.triage import entrypoint_hypotheses, llm_patch
from caa.core.untrusted import find_injection_attempts, wrap
from caa.engine_code.authz import build_route_map, authz_candidates
from caa.engine_code.patcher import WorkingCopy, template_patch, unified_diff
from caa.engine_code.taint import TaintEngine, is_route
from caa.sandbox.runner import Sandbox
from caa.tools import deps as deps_tool
from caa.tools import sast
from caa.tools.fs import RepoFS
from caa.tools.registry import ToolRegistry
from caa.tools.secrets_scan import scan_secrets
from caa.tools.symbols import SymbolIndex

FRAMEWORK_HINTS = {"flask": r"^\s*(?:from flask|import flask)", "django": r"^\s*(?:from django|import django)",
                   "fastapi": r"^\s*(?:from fastapi|import fastapi)"}
PLACEHOLDER = re.compile(r"(?i)(example|changeme|change_me|dummy|placeholder|your[_-]|xxx+|<[^>]+>|test|sample|fake)")
TITLES = {"CWE-89": "SQL injection", "CWE-78": "OS command injection", "CWE-22": "Path traversal",
          "CWE-79": "Cross-site scripting", "CWE-918": "Server-side request forgery",
          "CWE-639": "Insecure direct object reference", "CWE-862": "Missing authorization",
          "CWE-840": "Business logic flaw", "CWE-798": "Hard-coded credential", "CWE-327": "Weak cryptographic hash",
          "CWE-489": "Debug mode enabled", "CWE-942": "Permissive CORS", "CWE-1395": "Vulnerable dependency",
          "CWE-1427": "Prompt-injection text aimed at AI reviewers"}
DYNAMIC_CWES = {"CWE-89", "CWE-78", "CWE-22", "CWE-79", "CWE-918"}
_SRC_PARAM = re.compile(r"request\.(args|form|values|json|get_json\(\))\s*(?:\.get\(\s*|\[\s*)['\"]([^'\"]+)['\"]")


class CodeEngine(EvidenceEngine):
    name = "code"

    def __init__(self, root: Path, kb: KnowledgeBase, sandbox: Sandbox | None = None, audit: AuditLog = NULL_AUDIT,
                 use_semgrep: bool = True, use_bandit: bool = True, codeql_sarif: Path | None = None,
                 generators: set[str] | None = None, reanchor: bool = True):
        self.root = root.resolve()
        self.ledger = ReadLedger()
        self.fs = RepoFS(self.root, self.ledger)
        self.kb = kb
        self.audit = audit
        self.symbols = SymbolIndex(self.fs)
        self.taint = TaintEngine(self.fs, self.symbols)
        self.routes = build_route_map(self.fs)
        self.sandbox = sandbox
        self.use_semgrep, self.use_bandit, self.codeql_sarif = use_semgrep, use_bandit, codeql_sarif
        self._registry = ToolRegistry(self.fs, self.symbols, kb, audit)
        self._wc: WorkingCopy | None = None
        self.sarif_runs: list[dict] = []
        self.generators = generators if generators is not None else {"secrets", "deps", "authz", "injection"}
        self.reanchor = reanchor

    # ------------------------------------------------------------- stage 1
    def inventory(self) -> dict:
        files = self.fs.iter_files("*")
        langs = Counter(Path(f).suffix or "<none>" for f in files)
        py = [f for f in files if f.endswith(".py")]
        frameworks = set()
        loc = 0
        for f in py:
            text = self.fs.resolve(f).read_text(encoding="utf-8", errors="replace")
            loc += text.count("\n") + 1
            for fw, rx in FRAMEWORK_HINTS.items():
                if re.search(rx, text, re.M):
                    frameworks.add(fw)
        cli = [s.qualname + "@" + s.file for s in self.symbols.symbols if s.name == "main"]
        return {
            "root": str(self.root), "files": len(files), "python_files": len(py), "python_loc": loc,
            "languages": dict(langs.most_common(10)), "frameworks": sorted(frameworks),
            "entrypoints": {"routes": [r.to_dict() for r in self.routes.routes],
                            "global_auth_hooks": [str(r.file) + ":" + str(r.line) for r in self.routes.global_auth],
                            "cli": cli},
            "manifests": [f for f in files if re.search(r"(requirements.*\.txt|pyproject\.toml|setup\.py|Pipfile)$", f)],
            "configs": [f for f in files if re.search(r"(settings|config)[^/]*\.(py|ya?ml|ini|toml|env)$", f)],
            "symbol_index": self.symbols.backend,
            "analyzers": sast.available_analyzers(),
        }

    # ------------------------------------------------------------- stage 2
    def generate(self, inventory: dict) -> list[Candidate]:
        runs = []
        if self.use_semgrep:
            runs.append(sast.run_semgrep(self.root))
        if self.use_bandit:
            runs.append(sast.run_bandit(self.root))
        if self.codeql_sarif:
            runs.append(sast.load_codeql_sarif(self.codeql_sarif))
        self.sarif_runs = runs
        cands = sast.sarif_runs_to_candidates(runs)
        cands = [c for c in cands if self.kb.get(c.cwe)]          # only classes we have knowledge for
        g = self.generators
        if "secrets" in g:
            cands += scan_secrets(self.fs)
        if "deps" in g:
            cands += deps_tool.scan_dependencies(self.fs)
        if "authz" in g:
            cands += authz_candidates(self.routes)
        if "injection" in g:
            cands += self._injection_candidates()
        for c in cands:
            if self.reanchor and c.group == Group.DATAFLOW:
                self._reanchor(c)
        self.audit.write("candidates", count=len(cands), by_source=dict(Counter(c.source for c in cands)))
        return cands

    def _injection_candidates(self) -> list[Candidate]:
        out = []
        for rel in self.fs.iter_files("*.py"):
            for line, txt in find_injection_attempts(self.fs.resolve(rel).read_text(errors="replace")):
                out.append(Candidate(rule_id="caa.agent.prompt-injection-text", source="injection-scan",
                                     cwe="CWE-1427", group=Group.AGENT_SAFETY,
                                     location=Location(file=rel, start_line=line), message=f"steering text: {txt!r}"))
        return out

    def _reanchor(self, c: Candidate) -> None:
        """Analyzers report different lines for one flaw (query string vs execute call). Move to the sink."""
        func = self.taint.func_at(c.location.file, c.location.start_line)
        if func is None:
            return
        res = self.taint._trace_in(c.location.file, func, c.location.start_line, c.cwe)
        if res.sink_found:
            return
        for ln in range(c.location.start_line + 1, min(func.end_lineno, c.location.start_line + 8) + 1):
            r = self.taint._trace_in(c.location.file, func, ln, c.cwe)
            if r.sink_found:
                c.extra["reported_line"] = c.location.start_line
                c.location.start_line = ln
                c.location.end_line = ln
                return

    def llm_hypotheses(self, inventory: dict, model) -> list[Candidate]:
        out = []
        rm_json = json.dumps([r.to_dict() for r in self.routes.routes], indent=0)
        by_file: dict[str, list] = {}
        for r in self.routes.routes:
            by_file.setdefault(r.file, []).append(r)
        for rel, routes in by_file.items():
            start = min(r.deco_line for r in routes)
            end = max(r.end_line for r in routes)
            code = wrap(f"# file: {rel}\n" + self.fs.read_file(rel, max(1, start - 30), end), rel)
            app = [r for r in self.routes.routes if r.file == rel]
            has_policy = any(r.auth or r.ownership for r in app) or bool(self.routes.hooks_for(app[0]))
            for h in entrypoint_hypotheses(model, self.ledger, rm_json, code):
                grp = Group.BUSINESS_LOGIC if h.cwe == "CWE-840" else Group.ACCESS_CONTROL
                if grp == Group.ACCESS_CONTROL and not has_policy:
                    # ABSENTIA: access-control flaws are deviations from the app's own policy; none exists here
                    self.audit.write("hypothesis_dropped", file=h.file, line=h.line, cwe=h.cwe,
                                     reason="no access-control policy in this app to deviate from")
                    continue
                out.append(Candidate(rule_id="caa.llm.entrypoint", source="llm-entrypoints", cwe=h.cwe, group=grp,
                                     location=Location(file=h.file, start_line=h.line), message=h.title,
                                     extra={"rationale": h.rationale}))
        return out

    # ------------------------------------------------------------- findings
    def to_findings(self, candidates: list[Candidate]) -> list[Finding]:
        merged = sast.dedup(candidates)
        # access-control / logic hypotheses on the same handler collapse into one finding
        findings: dict[tuple, Finding] = {}
        for c in merged:
            sym = self.symbols.enclosing(c.location.file, c.location.start_line)
            fn = sym.qualname if sym else None
            key = (c.location.file, fn, c.cwe) if c.group in (Group.ACCESS_CONTROL, Group.BUSINESS_LOGIC) and fn \
                else c.dedup_key()
            if key in findings:
                f = findings[key]
                for s in c.extra.get("sources", [c.source]):
                    if s not in f.sources:
                        f.sources.append(s)
                f.extra.setdefault("candidates", []).append(c.model_dump())
                continue
            loc = c.location.model_copy()
            loc.function = loc.function or fn
            f = Finding(title=TITLES.get(c.cwe, c.message[:60]), cwe=c.cwe, group=c.group, location=loc,
                        sources=list(c.extra.get("sources", [c.source])), explanation=c.message,
                        extra={"rules": c.extra.get("rules", [c.rule_id]), "candidates": [c.model_dump()],
                               "message": c.message})
            f.add_evidence(Evidence(level=Level.L0, by=",".join(f.sources), detail=f"pattern match: {c.rule_id}",
                                    refs=[Ref(file=loc.file, line=loc.start_line)]))
            f.make_id()
            findings[key] = f
        return list(findings.values())

    # ------------------------------------------------------------- stage 3
    def context(self, f: Finding) -> ContextSlice:
        file, line = f.location.file, f.location.start_line
        ranges, parts, facts = [], [], {}
        if f.group == Group.DATAFLOW:
            tr = self.taint.trace(file, line, f.cwe)
            facts["trace"] = {"reached": tr.reached, "steps": [s.model_dump() for s in tr.steps],
                              "sanitizer": tr.sanitizer.model_dump() if tr.sanitizer else None,
                              "constant": tr.constant_ref.model_dump() if tr.constant_ref else None,
                              "partial_checks": [p.model_dump() for p in tr.partial_checks],
                              "sink_found": tr.sink_found, "entry": tr.entry, "notes": tr.notes}
            funcs = {(file, line)}
            for s in tr.steps:
                funcs.add((s.ref.file, s.ref.line))
            seen = set()
            for fl, ln in sorted(funcs):
                fn = self.taint.func_at(fl, ln)
                if fn is None:
                    a, b = max(1, ln - 5), ln + 5
                else:
                    a, b = fn.lineno - len(fn.decorator_list), fn.end_lineno
                if (fl, a) in seen:
                    continue
                seen.add((fl, a))
                ranges.append((fl, a, b))
                parts.append(f"# file: {fl}\n" + self.fs.read_file(fl, a, b))
            for sym, ln in self.symbols.get_callers(f.location.function or ""):
                if len(ranges) > 5:
                    break
                ranges.append((sym.file, sym.start, sym.end))
                parts.append(f"# file: {sym.file} | caller {sym.qualname}\n" + self.fs.read_file(sym.file, sym.start, sym.end))
        elif f.group in (Group.ACCESS_CONTROL, Group.BUSINESS_LOGIC):
            fn = self.taint.func_at(file, line)
            a, b = ((fn.lineno - len(fn.decorator_list), fn.end_lineno) if fn else (max(1, line - 10), line + 10))
            ranges.append((file, a, b))
            parts.append(f"# file: {file}\n" + self.fs.read_file(file, a, b))
            sibs = [r.to_dict() for r in self.routes.routes if r.file == file]
            facts["routes_in_file"] = sibs
            parts.append("# route map (same file)\n" + json.dumps(sibs, indent=0))
            for r in self.routes.routes:
                if r.file == file and r.func != (fn.name if fn else None):
                    ranges.append((r.file, r.deco_line, r.end_line))
                    parts.append(f"# file: {r.file} | sibling {r.func}\n" + self.fs.read_file(r.file, r.deco_line, r.end_line))
            for h in [h for h in self.routes.global_auth if h.file == file]:
                ranges.append((h.file, h.line, h.line + 6))
                parts.append(f"# file: {h.file} | global hook\n" + self.fs.read_file(h.file, h.line, h.line + 6))
        else:
            a, b = max(1, line - 5), line + 5
            ranges.append((file, a, b))
            try:
                parts.append(f"# file: {file}\n" + mask_secrets(self.fs.read_file(file, a, b)))
            except OSError:
                pass
        # module-level statements (constants, imports, config) of the files on the path also define values
        for fl in {r[0] for r in ranges if r[0].endswith(".py")}:
            tree = self.taint.tree(fl)
            for st in (tree.body if tree else []):
                if not isinstance(st, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
                    ranges.append((fl, st.lineno, st.end_lineno or st.lineno))
        return ContextSlice(text=wrap("\n\n".join(parts), f"code slice {file}"), ranges=ranges, facts=facts)

    def tools(self) -> ToolRegistry:
        return self._registry

    # ------------------------------------------------------------- stage 5
    def verify(self, f: Finding, ctx: ContextSlice) -> None:
        {Group.DATAFLOW: self._verify_dataflow, Group.ACCESS_CONTROL: self._verify_access,
         Group.SECRETS_CONFIG: self._verify_config, Group.DEPENDENCIES: self._verify_deps,
         Group.AGENT_SAFETY: self._verify_injection, Group.BUSINESS_LOGIC: lambda f, c: None}[f.group](f, ctx)
        self._severity(f)

    def _refute(self, f: Finding, ref: Ref, by: str) -> bool:
        if not self.ledger.verify(ref):
            self.fs.read_file(ref.file, ref.line, ref.line)
        if self.ledger.verify(ref) and self.ledger.is_code_line(ref):
            f.status = Status.REFUTED
            f.refutation = ref
            f.extra["refuted_by"] = by
            return True
        f.not_verified.append(f"refutation reference {ref} is not executable code; finding kept")
        return False

    def _verify_dataflow(self, f: Finding, ctx: ContextSlice) -> None:
        t = ctx.facts.get("trace", {})
        file, line = f.location.file, f.location.start_line
        if t.get("reached"):
            steps = [DataflowStep(**s) for s in t["steps"]]
            if all(self.ledger.verify(s.ref) for s in steps):
                f.dataflow = steps
                src = steps[0]
                f.add_evidence(Evidence(level=Level.L2, by="taint",
                                        detail=f"source {src.ref.note or src.code} reaches sink with no sanitizer",
                                        refs=[s.ref for s in steps]))
            for p in t.get("partial_checks", []):
                f.not_verified.append(f"a check exists at {p['file']}:{p['line']} ({p['note']}) "
                                      "but does not neutralise the input")
            self._defend_dataflow(f, t)
            return
        if t.get("sanitizer"):
            self._refute(f, Ref(**t["sanitizer"]), "taint-sanitizer")
            return
        if t.get("constant"):
            self._refute(f, Ref(**t["constant"]), "taint-no-source")
            return
        text = (self.ledger.line_text(file, line) or self.fs.read_lines(file)[line - 1]).strip()
        if not t.get("sink_found") and re.match(r"(import |from \S+ import |def |class |@)", text):
            self.fs.read_file(file, line, line)
            self._refute(f, Ref(file=file, line=line, note="no data-flow sink on this line (declaration/import)"),
                         "no-sink")
            return
        f.not_verified += [f"trace not established: {n}" for n in t.get("notes", [])] or ["trace not established"]

    def _defend_dataflow(self, f: Finding, t: dict) -> None:
        """L3: try to refute what L2 claims - reachability, global filters, test-only code."""
        objections = []
        entry = t.get("entry")
        entry_fn = None
        if entry and f.dataflow:
            entry_fn = self.taint.func_at(f.dataflow[0].ref.file, f.dataflow[0].ref.line)
        if entry_fn is None or not is_route(entry_fn):
            if not (entry_fn and entry_fn.name == "main"):
                objections.append("no HTTP route or CLI entry point found at the start of the trace")
        if re.search(r"(^|/)(tests?|fixtures)/", f.location.file):
            objections.append("code lives in a test directory")
        entry_file = f.dataflow[0].ref.file if f.dataflow else f.location.file
        src = self.fs.resolve(entry_file).read_text(errors="replace")
        m = re.search(r"before_request\s*\n\s*def \w+\([^)]*\):(?:\n[ \t]+.*)*", src)
        if m and re.search(r"request\.(args|form|values|json)", m.group(0)):
            ln = src[:m.start()].count("\n") + 1
            objections.append(f"a before_request hook inspects request input ({entry_file}:{ln}); not proven irrelevant")
        if objections:
            f.not_verified += [f"defender: {o}" for o in objections]
            return
        f.add_evidence(Evidence(level=Level.L3, by="defender",
                                detail=f"refutation failed: entry {entry}() is a route, no sanitizer on the path, "
                                       "no global input filter, not test code",
                                refs=[f.dataflow[0].ref, f.dataflow[-1].ref]))

    def _verify_access(self, f: Finding, ctx: ContextSlice) -> None:
        r = next((x for x in self.routes.routes if x.file == f.location.file and x.func == f.location.function), None)
        if r is None:
            f.not_verified.append("handler not found in route map")
            return
        self.fs.read_file(r.file, r.deco_line, r.end_line)
        cand = (f.extra.get("candidates") or [{}])[0].get("extra", {})
        if f.cwe == "CWE-862" and self.routes.hooks_for(r):
            self._refute(f, self.routes.hooks_for(r)[0], "global-auth-hook")
            return
        if f.cwe == "CWE-639" and r.ownership:
            self._refute(f, r.ownership[0], "ownership-check")
            return
        if f.cwe == "CWE-862" and r.auth:
            self._refute(f, r.auth, "auth-present")
            return
        cands = [c.get("extra", {}) for c in f.extra.get("candidates") or []]
        policy = next((c.get("sibling_check") or c.get("policy_ref") for c in cands
                       if c.get("sibling_check") or c.get("policy_ref")), None)
        if "authz-routes" not in f.sources:
            # model-only hypothesis: the route map shows no deviation from a sibling policy -> no trace level
            f.not_verified.append("route-map analysis did not confirm a deviation from the app's access policy; "
                                  "hypothesis rests on the model only")
            return
        refs = [Ref(file=r.file, line=r.deco_line, note="route")]
        if r.lookups:
            refs.append(r.lookups[0])
        if policy:
            pref = Ref(**policy)
            self.fs.read_file(pref.file, pref.line, pref.line)
            refs.append(pref)
            f.add_evidence(Evidence(level=Level.L1, by="route-policy",
                                    detail="two hints: handler lacks the check AND a sibling of the same resource has it",
                                    refs=refs))
        f.add_evidence(Evidence(level=Level.L2, by="route-map",
                                detail=("object loaded by client id without owner filter or ownership comparison"
                                        if f.cwe == "CWE-639" else "no authentication decorator or inline check"),
                                refs=refs))
        f.dataflow = [DataflowStep(kind="source", ref=refs[0], code=self.ledger.line_text(r.file, r.deco_line) or "")]
        if r.lookups:
            f.dataflow.append(DataflowStep(kind="sink", ref=r.lookups[0],
                                           code=self.ledger.line_text(r.file, r.lookups[0].line) or ""))
        # defender: helper callees doing the check, custom decorators
        fn = self.taint.func_at(r.file, r.line)
        for callee, ln in self.symbols.get_callees(r.func):
            for s in self.symbols.find_symbol(callee):
                body = "\n".join(self.fs.read_lines(s.file)[s.start - 1:s.end])
                if re.search(r"(owner|user_id|current_user|session\[)", body) and re.search(r"abort|raise|403|404", body):
                    f.not_verified.append(f"defender: callee {callee}() may perform an ownership check ({s.file}:{s.start})")
                    return
        decos = [ast.unparse(d) for d in (fn.decorator_list if fn else [])]
        if any(re.search(r"(owner|permission|policy|authorize)", d) for d in decos):
            f.not_verified.append("defender: a custom decorator may enforce the policy")
            return
        f.add_evidence(Evidence(level=Level.L3, by="defender",
                                detail="no global hook, no ownership check in handler, callees or decorators",
                                refs=refs[:1]))

    def _verify_config(self, f: Finding, ctx: ContextSlice) -> None:
        file, line = f.location.file, f.location.start_line
        self.fs.read_file(file, line, line)
        text = self.ledger.line_text(file, line) or ""
        ref = Ref(file=file, line=line)
        if f.cwe == "CWE-798":
            m = re.search(r"['\"]([^'\"]{6,})['\"]\s*$", text.split("#")[0].strip()) or \
                re.search(r"=\s*['\"]([^'\"]{6,})['\"]", text)
            if not m or "environ" in text or "getenv" in text:
                self._refute(f, Ref(file=file, line=line, note="value read from environment"), "env-value")
                return
            val = m.group(1)
            if PLACEHOLDER.search(val) or re.search(r"(^|/)(tests?|fixtures)/", file):
                self._refute(f, Ref(file=file, line=line, note="placeholder / test fixture value"), "placeholder")
                return
            f.add_evidence(Evidence(level=Level.L2, by="line-check",
                                    detail=f"literal credential at the cited line ({mask_secrets(val)[:12]}...)",
                                    refs=[ref]))
            f.add_evidence(Evidence(level=Level.L3, by="defender",
                                    detail="not a placeholder, not test code, not read from the environment", refs=[ref]))
            f.not_verified.append("whether the credential is live/rotated was not checked")
        elif f.cwe == "CWE-327":
            if "usedforsecurity=False" in text:
                self._refute(f, Ref(file=file, line=line, note="usedforsecurity=False: non-security use"), "non-security-hash")
                return
            fn = self.taint.func_at(file, line)
            name = fn.name if fn else ""
            if re.search(r"(pass|pw|token|secret|sign|auth|key)", name + text, re.I):
                f.add_evidence(Evidence(level=Level.L2, by="line-check",
                                        detail=f"weak hash used in security context ({name}())", refs=[ref]))
            else:
                f.not_verified.append("purpose of the hash could not be determined")
        elif f.cwe == "CWE-489":
            if re.search(r"debug\s*=\s*True", text):
                f.add_evidence(Evidence(level=Level.L2, by="line-check", detail="debug=True literal", refs=[ref]))
                f.not_verified.append("whether this entry point is used in production was not checked")
            else:
                self._refute(f, ref, "debug-not-literal")
        else:
            f.add_evidence(Evidence(level=Level.L2, by="line-check", detail="configuration value read", refs=[ref]))

    def _verify_deps(self, f: Finding, ctx: ContextSlice) -> None:
        cand = (f.extra.get("candidates") or [{}])[0].get("extra", {})
        imp = cand.get("import_name")
        f.extra["dependency"] = {k: cand.get(k) for k in ("package", "version", "vuln_id", "fixed", "db")}
        hits = [h for h in self.fs.search(rf"^\s*(import|from)\s+{re.escape(imp)}\b", "*.py")] if imp else []
        if hits:
            f.add_evidence(Evidence(level=Level.L2, by="import-fact",
                                    detail=f"vulnerable version pinned and package imported ({len(hits)} import(s))",
                                    refs=[Ref(file=hits[0][0], line=hits[0][1])]))
            f.not_verified.append("whether the affected API is actually called was not analysed; no exploit is run")
        else:
            f.status = Status.NEEDS_HUMAN
            f.not_verified.append("package is pinned but never imported by first-party code (unused or transitive)")

    def _verify_injection(self, f: Finding, ctx: ContextSlice) -> None:
        self.fs.read_file(f.location.file, f.location.start_line, f.location.start_line)
        f.add_evidence(Evidence(level=Level.L2, by="injection-scan", detail="steering text read at cited line",
                                refs=[Ref(file=f.location.file, line=f.location.start_line)]))
        f.severity = "low"

    def _severity(self, f: Finding) -> None:
        card = self.kb.get(f.cwe) or {}
        base = card.get("severity", "medium")
        order = ["low", "medium", "high", "critical"]
        reach = "reachable from an HTTP route" if f.level >= Level.L3 else "reachability not proven"
        sev = base
        if f.level < Level.L2 and base in order[1:]:
            sev = order[order.index(base) - 1]
        f.severity = sev
        f.severity_rationale = f"impact: {card.get('impact', 'n/a')} | {reach} (evidence {f.confidence_label})"

    # ------------------------------------------------------------- L4
    def _spec(self, f: Finding) -> dict | None:
        if f.cwe not in DYNAMIC_CWES or not f.dataflow:
            return None
        src = f.dataflow[0]
        fn = self.taint.func_at(src.ref.file, src.ref.line)
        route = next((r for r in self.routes.routes if fn and r.file == src.ref.file and r.func == fn.name), None)
        if route is None:
            return None
        m = _SRC_PARAM.search(src.code + " " + src.ref.note)
        if "route parameter" in src.ref.note:
            inj = {"where": "path", "name": src.ref.note.split("<")[1].rstrip(">")}
        elif m:
            where = {"get_json()": "json"}.get(m.group(1), m.group(1))
            inj = {"where": "args" if where == "values" else where, "name": m.group(2)}
        else:
            return None
        path = re.sub(r"<(?:[^:<>]+:)?([^<>]+)>", "caa1", route.path)
        extra = {}
        return {"module": route.file, "cwe": f.cwe, "method": route.methods[0], "path": path, "rule": route.path,
                "inject": inj, "extra_args": extra}

    def dynamic(self, f: Finding) -> None:
        if self.sandbox is None:
            f.not_verified.append("L4 skipped: sandbox disabled (enable only for trusted code)")
            return
        spec = self._spec(f)
        if spec is None:
            f.not_verified.append("L4 skipped: no property check for this class / entry point")
            return
        res = self.sandbox.run_check(self.root, spec)
        self.audit.write("sandbox_check", finding=f.id, spec=spec, result=res)
        f.extra["l4"] = {"spec": spec, "result": res}
        if res.get("status") == "violated":
            f.add_evidence(Evidence(level=Level.L4, by=f"property-check[{res.get('backend')}]",
                                    detail=f"harmless marker broke the {f.cwe} safety property",
                                    refs=[f.dataflow[-1].ref]))
        elif res.get("status") == "holds":
            f.not_verified.append("L4: property held at runtime - static trace not confirmed dynamically")
        else:
            f.not_verified.append(f"L4 inconclusive: {res.get('reason', '')[:160]}")

    # ------------------------------------------------------------- L5
    def fix(self, f: Finding, model) -> None:
        if f.group != Group.DATAFLOW or not f.dataflow:
            return
        sink = f.dataflow[-1].ref
        rel = sink.file
        original = self.fs.resolve(rel).read_text()
        made = template_patch(original, f.cwe, sink.line)
        by = f"template:{f.cwe}"
        diff = None
        if made is not None:
            new, why = made
            diff = unified_diff(rel, original, new)
        elif model is not None:
            card = self.kb.get(f.cwe) or {}
            rep = llm_patch(model, f"{f.title} {f.cwe} sink at {rel}:{sink.line}", rel,
                            wrap(self.fs.read_file(rel, 1, None), rel), card.get("fix", ""))
            if rep is not None:
                diff, why, by = rep.diff, rep.explanation, "llm"
        if not diff:
            f.not_verified.append("no automatic fix: template does not cover this shape")
            return
        if self._wc is None:
            self._wc = WorkingCopy(self.root)
        ok, err = self._wc.apply_patch(diff)
        patch = Patch(diff=diff, explanation=why, by=by)
        if not ok:
            f.not_verified.append(f"patch did not apply to working copy: {err[:150]}")
            f.fix = patch
            return
        patch.rescan_clean, note = self._rescan(rel, f)
        f.extra["rescan"] = note
        if self.sandbox is not None and f.level >= Level.L4 and "l4" in f.extra:
            res = self.sandbox.run_check(self._wc.root, f.extra["l4"]["spec"])
            patch.property_after = res.get("status") == "holds"
            f.extra["l5_property"] = res
        f.fix = patch
        if patch.rescan_clean and patch.property_after:
            f.add_evidence(Evidence(level=Level.L5, by="patch-verify",
                                    detail="after the patch: no reachable unsanitised flow on rescan, property check passes",
                                    refs=[sink]))
        elif patch.rescan_clean:
            f.not_verified.append("patch verified by rescan only (no dynamic re-check)")
        self._wc.revert(rel, original)

    def _rescan(self, rel: str, f: Finding) -> tuple[bool, str]:
        wc_fs = RepoFS(self._wc.root)
        te = TaintEngine(wc_fs, SymbolIndex(wc_fs))
        run = sast.run_semgrep(self._wc.root / rel)
        for res in run.get("results", []):
            res["locations"][0]["physicalLocation"]["artifactLocation"]["uri"] = rel
        hits = [c for c in sast.sarif_runs_to_candidates([run]) if c.cwe == f.cwe]
        fname = f.location.function
        tree = ast.parse((self._wc.root / rel).read_text())
        fn = next((n for n in ast.walk(tree) if isinstance(n, ast.FunctionDef) and n.name == (fname or "").split(".")[-1]), None)
        if fn is not None:
            hits = [h for h in hits if fn.lineno <= h.location.start_line <= fn.end_lineno]
        rule_fires = bool(hits)
        reachable = [h for h in hits if te.trace(rel, h.location.start_line, f.cwe).reached]
        if not rule_fires:
            return True, "rule no longer fires in the patched function"
        if not reachable:
            return True, "rule still matches the shape, but taint shows the value is neutralised"
        return False, f"still reachable at line(s) {[h.location.start_line for h in reachable]}"

    def close(self) -> None:
        if self._wc is not None:
            self._wc.cleanup()
