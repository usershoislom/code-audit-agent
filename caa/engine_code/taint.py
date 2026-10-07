"""Lightweight source->sink taint tracing for Python (ladder level L2).

Scope (deliberately small and explainable):
* intra-procedural, statement-ordered propagation through assignments,
  f-strings, concatenation, %, .format(), method calls, containers;
* sanitizers per CWE (casts, escape, shlex.quote, secure_filename, ...);
* guards: `if <validation of v>: <exit>` (allow-list membership, regex
  fullmatch, isdigit, normalised-path prefix check) sanitize v afterwards;
* inter-procedural: parameters are symbolic sources; call sites are resolved
  through the symbol index up to MAX_DEPTH callers; helper functions in the
  repo get return summaries (sanitizer / source / propagate).

Every step carries file:line; the lines are read through RepoFS, so they are
recorded in the read ledger and can be verified like LLM citations.
"""
from __future__ import annotations

import ast
import re
from pathlib import Path
from dataclasses import dataclass, field

from caa.core.models import DataflowStep, Ref
from caa.tools.fs import RepoFS
from caa.tools.symbols import SymbolIndex

MAX_DEPTH = 3
REQUEST_ATTRS = {"args", "form", "values", "json", "cookies", "headers", "data", "files", "get_json",
                 "get_data", "view_args", "query_string", "GET", "POST", "body", "query_params", "path_params"}
EXIT_CALLS = {"abort", "exit", "_exit", "redirect"}
CASTS = {"int", "float", "bool", "UUID", "uuid4", "len", "hash", "ord"}
SANITIZERS = {
    "CWE-89": CASTS,
    "CWE-78": CASTS | {"quote"},                                    # shlex.quote
    "CWE-22": CASTS | {"secure_filename", "basename", "_caa_contained"},
    "CWE-79": CASTS | {"escape", "clean", "quote_plus", "urlencode", "dumps"},
    "CWE-918": CASTS,
}
NORMALISERS = {"realpath", "abspath", "normpath", "resolve"}
PATH_SAFE_JOIN = {"safe_join"}          # werkzeug.utils.safe_join returns None on escape
ROUTE_DECOS = re.compile(r"\.(?:route|get|post|put|patch|delete)\(")
ROUTE_PARAM = re.compile(r"<(?:[^:<>]+:)?([^<>]+)>")


@dataclass
class Taint:
    steps: list[DataflowStep]
    param: str | None = None          # symbolic: comes from this function parameter
    normalized: bool = False          # path passed through realpath/abspath/normpath

    def extend(self, step: DataflowStep, normalized: bool | None = None) -> "Taint":
        last = self.steps[-1] if self.steps else None
        same_line = last is not None and last.ref.file == step.ref.file and last.ref.line == step.ref.line
        steps = self.steps if same_line else self.steps + [step]
        return Taint(steps, self.param, self.normalized if normalized is None else normalized)


@dataclass
class TraceResult:
    reached: bool = False
    steps: list[DataflowStep] = field(default_factory=list)
    sanitizer: Ref | None = None          # where taint was neutralised (refutation reference)
    constant_ref: Ref | None = None       # sink argument is constant/derived from constants
    partial_checks: list[Ref] = field(default_factory=list)  # checks that exist but don't neutralise
    sink_found: bool = False
    entry: str | None = None              # route/entry function the trace starts from
    notes: list[str] = field(default_factory=list)


class _Stop(Exception):
    def __init__(self, result: TraceResult):
        self.result = result


def _call_name(node: ast.AST) -> str | None:
    if isinstance(node, ast.Call):
        node = node.func
    if isinstance(node, ast.Attribute):
        return node.attr
    if isinstance(node, ast.Name):
        return node.id
    return None


def _dotted(node: ast.AST) -> str:
    try:
        return ast.unparse(node)
    except Exception:  # pragma: no cover
        return ""


def _root_name(node: ast.AST) -> str | None:
    while isinstance(node, (ast.Attribute, ast.Subscript, ast.Call)):
        node = node.func if isinstance(node, ast.Call) else node.value
    return node.id if isinstance(node, ast.Name) else None


def _exits(body: list[ast.stmt]) -> bool:
    if not body:
        return False
    last = body[-1]
    if isinstance(last, (ast.Return, ast.Raise, ast.Continue, ast.Break)):
        return True
    if isinstance(last, ast.Expr) and isinstance(last.value, ast.Call) and _call_name(last.value) in EXIT_CALLS:
        return True
    return False


def route_params(func: ast.FunctionDef) -> set[str]:
    out = set()
    for d in func.decorator_list:
        src = _dotted(d)
        if ROUTE_DECOS.search(src):
            out.update(ROUTE_PARAM.findall(src))
    return out


def is_route(func: ast.FunctionDef) -> bool:
    return any(ROUTE_DECOS.search(_dotted(d)) for d in func.decorator_list)


class TaintEngine:
    def __init__(self, fs: RepoFS, symbols: SymbolIndex):
        self.fs = fs
        self.symbols = symbols
        self._trees: dict[str, ast.Module] = {}
        self._summaries: dict[tuple[str, str], tuple[str, Taint | None]] = {}

    # ------------------------------------------------------------------ utils
    def tree(self, file: str) -> ast.Module | None:
        if file not in self._trees:
            try:
                self._trees[file] = ast.parse(self.fs.resolve(file).read_text(encoding="utf-8"))
            except (SyntaxError, OSError, UnicodeDecodeError):
                self._trees[file] = None
        return self._trees[file]

    def func_at(self, file: str, line: int) -> ast.FunctionDef | None:
        tree = self.tree(file)
        best = None
        if tree is None:
            return None
        for n in ast.walk(tree):
            if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef)) and n.lineno <= line <= (n.end_lineno or n.lineno):
                if best is None or n.lineno > best.lineno:
                    best = n
        return best

    def _line(self, file: str, line: int) -> str:
        text = self.fs.ledger.line_text(file, line)
        if text is None:
            self.fs.read_file(file, line, line)
            text = self.fs.ledger.line_text(file, line) or ""
        return text.strip()

    def step(self, kind: str, file: str, line: int, note: str = "") -> DataflowStep:
        return DataflowStep(kind=kind, ref=Ref(file=file, line=line, note=note), code=self._line(file, line))

    # ------------------------------------------------------------ public API
    def trace(self, file: str, line: int, cwe: str) -> TraceResult:
        func = self.func_at(file, line)
        tree = self.tree(file)
        if tree is None:
            return TraceResult(notes=["file could not be parsed"])
        if func is not None:
            self.fs.read_file(file, func.lineno, func.end_lineno)   # recorded in ledger
        res = self._trace_in(file, func, line, cwe)
        if res.reached and res.steps and res.steps[0].kind == "source" and res.steps[0].ref.note.startswith("param:"):
            # symbolic parameter: resolve through callers
            return self._resolve_param(file, func, res, cwe, depth=1)
        if res.reached and func is not None:
            res.entry = func.name
        return res

    # -------------------------------------------------------- interprocedural
    def _resolve_param(self, file: str, func: ast.FunctionDef, res: TraceResult, cwe: str, depth: int) -> TraceResult:
        pname = res.steps[0].ref.note.split(":", 1)[1]
        params = [a.arg for a in func.args.args]
        idx = params.index(pname) if pname in params else -1
        callers = self.symbols.get_callers(func.name)
        best = TraceResult(notes=[f"parameter '{pname}' of {func.name}() has no tainted caller"])
        if not [c for c in callers if self.resolves(c[0].file, func.name, file)]:
            best.notes = [f"{func.name}() has no callers in the repository (not reachable from an entry point)"]
        callers = [(c, ln) for c, ln in callers if self.resolves(c.file, func.name, file)]
        for caller_sym, call_line in callers:
            cfunc = self.func_at(caller_sym.file, call_line)
            if cfunc is None or cfunc is func:
                continue
            self.fs.read_file(caller_sym.file, cfunc.lineno, cfunc.end_lineno)
            arg_res = self._trace_in(caller_sym.file, cfunc, call_line, cwe,
                                     call_target=(func.name, idx, pname))
            if arg_res.sanitizer and not best.sanitizer:
                best.sanitizer = arg_res.sanitizer
            if not arg_res.reached:
                continue
            call_step = self.step("call", caller_sym.file, call_line, note=f"{func.name}({pname}=...)")
            merged = TraceResult(reached=True, sink_found=True,
                                 steps=arg_res.steps + [call_step] + res.steps[1:],
                                 partial_checks=arg_res.partial_checks + res.partial_checks)
            if arg_res.steps and arg_res.steps[0].ref.note.startswith("param:") and depth < MAX_DEPTH:
                merged = self._resolve_param(caller_sym.file, cfunc, merged, cwe, depth + 1)
                if not merged.reached:
                    continue
            elif arg_res.steps and arg_res.steps[0].ref.note.startswith("param:"):
                continue
            merged.entry = merged.entry or cfunc.name
            return merged
        return best

    # ------------------------------------------------------------ intra-proc
    def _trace_in(self, file: str, func, line: int, cwe: str, call_target=None) -> TraceResult:
        env: dict[str, Taint] = {}
        rparams = set()
        result_holder = TraceResult()
        if func is not None:
            rparams = route_params(func)
            for a in func.args.args + func.args.kwonlyargs:
                if a.arg in ("self", "cls"):
                    continue
                if a.arg in rparams:
                    env[a.arg] = Taint([self.step("source", file, func.lineno, note=f"route parameter <{a.arg}>")])
                elif a.arg == "request":
                    continue
                else:
                    env[a.arg] = Taint([self.step("source", file, func.lineno, note=f"param:{a.arg}")], param=a.arg)
        ctx = _Ctx(self, file, cwe, line, call_target, result_holder)
        body = func.body if func is not None else self.tree(file).body
        try:
            ctx.walk(body, env, in_branch=False)
        except _Stop as s:
            return s.result
        result_holder.notes.append("sink statement not reached by the walker")
        return result_holder

    def resolves(self, caller_file: str, name: str, callee_file: str) -> bool:
        """Does `name` called in caller_file refer to the definition in callee_file? (import-aware)"""
        if caller_file == callee_file:
            return True
        tree = self.tree(caller_file)
        if tree is None:
            return False
        stem = Path(callee_file).stem
        for n in ast.walk(tree):
            if isinstance(n, ast.ImportFrom) and n.module and n.module.split(".")[-1] == stem \
                    and any(a.name in (name, "*") for a in n.names):
                return True
            if isinstance(n, ast.Import) and any(a.name.split(".")[-1] == stem for a in n.names):
                return True
        return False

    # --------------------------------------------------------- summaries
    def summary(self, name: str, from_file: str | None = None) -> tuple[str, Taint | None]:
        """Classify a repo function by what its return statements produce."""
        syms = [s for s in self.symbols.find_symbol(name)
                if from_file is None or self.resolves(from_file, name, s.file)]
        if len(syms) != 1:
            return ("unknown", None)
        s = syms[0]
        key = (s.file, s.qualname)
        if key in self._summaries:
            return self._summaries[key]
        self._summaries[key] = ("unknown", None)   # recursion guard
        func = self.func_at(s.file, s.start)
        if func is None:
            return ("unknown", None)
        returns = [n for n in ast.walk(func) if isinstance(n, ast.Return) and n.value is not None]
        if not returns:
            out = ("none", None)
        else:
            kinds = set()
            src_taint = None
            for r in returns:
                v = r.value
                if isinstance(v, ast.Constant):
                    kinds.add("const")
                elif isinstance(v, ast.Call) and _call_name(v) in CASTS | {"escape", "quote", "secure_filename"}:
                    kinds.add("sanitizer")
                else:
                    ctx = _Ctx(self, s.file, "CWE-89", -1, None, TraceResult())
                    t = ctx.expr({}, v)
                    if t is not None and t.param is None:
                        kinds.add("source")
                        src_taint = t
                    else:
                        kinds.add("propagate")
            if kinds <= {"const", "sanitizer"}:
                out = ("sanitizer", None)
            elif "source" in kinds:
                out = ("source", src_taint)
            else:
                out = ("propagate", None)
        self._summaries[key] = out
        return out


class _Ctx:
    def __init__(self, eng: TaintEngine, file: str, cwe: str, line: int, call_target, holder: TraceResult):
        self.eng, self.file, self.cwe, self.line = eng, file, cwe, line
        self.call_target = call_target
        self.holder = holder
        self.sanitizers = SANITIZERS.get(cwe, CASTS)

    # ---------------------------------------------------------- expressions
    def expr(self, env: dict[str, Taint], node: ast.AST | None) -> Taint | None:
        if node is None or isinstance(node, ast.Constant):
            return None
        if isinstance(node, ast.Name):
            return env.get(node.id)
        if self._is_request_source(node):
            ln = getattr(node, "lineno", self.line)
            return Taint([self.eng.step("source", self.file, ln, note=_dotted(node)[:80])])
        if isinstance(node, ast.Call):
            return self._call(env, node)
        if isinstance(node, ast.JoinedStr):
            return self._first(env, [v.value for v in node.values if isinstance(v, ast.FormattedValue)])
        if isinstance(node, ast.FormattedValue):
            return self.expr(env, node.value)
        if isinstance(node, ast.BinOp):
            return self._first(env, [node.left, node.right])
        if isinstance(node, ast.BoolOp):
            return self._first(env, node.values)
        if isinstance(node, ast.IfExp):
            return self._first(env, [node.body, node.orelse])
        if isinstance(node, (ast.Subscript, ast.Attribute, ast.Starred)):
            return self.expr(env, node.value)
        if isinstance(node, (ast.Tuple, ast.List, ast.Set)):
            return self._first(env, node.elts)
        if isinstance(node, ast.Dict):
            return self._first(env, [v for v in node.values if v is not None])
        if isinstance(node, (ast.ListComp, ast.GeneratorExp, ast.SetComp)):
            return self._first(env, [node.elt] + [g.iter for g in node.generators])
        return None

    def _first(self, env, nodes) -> Taint | None:
        for n in nodes:
            t = self.expr(env, n)
            if t is not None:
                return t
        return None

    def _is_request_source(self, node: ast.AST) -> bool:
        cur = node
        while isinstance(cur, (ast.Attribute, ast.Subscript, ast.Call)):
            if isinstance(cur, ast.Attribute) and cur.attr in REQUEST_ATTRS and isinstance(cur.value, ast.Name) \
                    and cur.value.id in ("request", "req"):
                return True
            cur = cur.func if isinstance(cur, ast.Call) else cur.value
        if isinstance(node, ast.Call) and _call_name(node) == "input" and isinstance(node.func, ast.Name):
            return True
        if isinstance(node, ast.Subscript) and _dotted(node.value) == "sys.argv":
            return True
        return False

    def _call(self, env, node: ast.Call) -> Taint | None:
        name = _call_name(node)
        args = list(node.args) + [k.value for k in node.keywords]
        recv = node.func.value if isinstance(node.func, ast.Attribute) else None
        if name in self.sanitizers:
            t = self._first(env, args + ([recv] if recv is not None else []))
            if t is not None:
                self.holder.sanitizer = self.holder.sanitizer or Ref(file=self.file, line=node.lineno,
                                                                      note=f"{name}() neutralises the value")
            return None
        if self.cwe == "CWE-22" and name in PATH_SAFE_JOIN:
            t = self._first(env, args)
            if t is not None:
                self.holder.sanitizer = self.holder.sanitizer or Ref(file=self.file, line=node.lineno,
                                                                      note="safe_join() refuses paths outside base")
            return None
        # repo helper summaries
        if isinstance(node.func, ast.Name) and name:
            kind, src = self.eng.summary(name, self.file)
            if kind == "sanitizer":
                if self._first(env, args) is not None:
                    self.holder.sanitizer = self.holder.sanitizer or Ref(
                        file=self.file, line=node.lineno, note=f"{name}() returns a cast/escaped/constant value")
                return None
            if kind == "source" and src is not None:
                return src.extend(self.eng.step("call", self.file, node.lineno, note=f"{name}() returns request data"))
        t = self._first(env, args + ([recv] if recv is not None else []))
        if t is None:
            return None
        if name in NORMALISERS:
            return t.extend(self.eng.step("propagation", self.file, node.lineno, note=f"{name}()"), normalized=True)
        return t

    # ---------------------------------------------------------- statements
    def walk(self, stmts: list[ast.stmt], env: dict[str, Taint], in_branch: bool) -> None:
        for st in stmts:
            start, end = st.lineno, getattr(st, "end_lineno", st.lineno) or st.lineno
            contains = start <= self.line <= end
            if contains and not self._is_compound(st):
                raise _Stop(self.at_sink(st, env))
            if isinstance(st, ast.If):
                self.walk(st.body, env, True)
                self.walk(st.orelse, env, True)
                self._guard(st, env)
            elif isinstance(st, (ast.For, ast.AsyncFor)):
                t = self.expr(env, st.iter)
                if t:
                    for n in ast.walk(st.target):
                        if isinstance(n, ast.Name):
                            env[n.id] = t.extend(self.eng.step("propagation", self.file, st.lineno))
                self.walk(st.body, env, True)
                self.walk(st.orelse, env, True)
            elif isinstance(st, ast.While):
                self.walk(st.body, env, True)
            elif isinstance(st, (ast.With, ast.AsyncWith)):
                for it in st.items:
                    t = self.expr(env, it.context_expr)
                    if t and isinstance(it.optional_vars, ast.Name):
                        env[it.optional_vars.id] = t
                self.walk(st.body, env, in_branch)
            elif isinstance(st, ast.Try):
                self.walk(st.body, env, in_branch)
                for h in st.handlers:
                    self.walk(h.body, env, True)
                self.walk(st.orelse, env, True)
                self.walk(st.finalbody, env, in_branch)
            elif isinstance(st, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
                if contains:
                    self.walk(st.body, dict(env), in_branch)
            else:
                self._simple(st, env, in_branch)
            if contains:
                # compound statement containing the line but sink not found inside
                raise _Stop(self.at_sink(st, env))

    @staticmethod
    def _is_compound(st: ast.stmt) -> bool:
        return isinstance(st, (ast.If, ast.For, ast.AsyncFor, ast.While, ast.With, ast.AsyncWith, ast.Try,
                               ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef))

    def _simple(self, st: ast.stmt, env: dict[str, Taint], in_branch: bool) -> None:
        if isinstance(st, (ast.Assign, ast.AnnAssign, ast.AugAssign)):
            value = st.value
            targets = st.targets if isinstance(st, ast.Assign) else [st.target]
            t = self.expr(env, value)
            for tgt in targets:
                for n in ast.walk(tgt):
                    if isinstance(n, ast.Name) and isinstance(n.ctx, ast.Store):
                        if t is not None:
                            norm = t.normalized and not isinstance(st, ast.AugAssign)
                            env[n.id] = t.extend(self.eng.step("propagation", self.file, st.lineno), normalized=norm)
                        elif not in_branch and not isinstance(st, ast.AugAssign):
                            env.pop(n.id, None)
                if isinstance(tgt, (ast.Subscript, ast.Attribute)) and t is not None:
                    root = _root_name(tgt)
                    if root:
                        env[root] = t.extend(self.eng.step("propagation", self.file, st.lineno))
        elif isinstance(st, ast.Expr) and isinstance(st.value, ast.Call):
            call = st.value
            if isinstance(call.func, ast.Attribute) and call.func.attr in ("append", "extend", "update", "add", "insert"):
                t = self._first(env, list(call.args))
                root = _root_name(call.func.value)
                if t is not None and root:
                    env[root] = t.extend(self.eng.step("propagation", self.file, st.lineno))

    def _guard(self, st: ast.If, env: dict[str, Taint]) -> None:
        """`if <validation failed>: exit` sanitizes the validated variable afterwards."""
        if not _exits(st.body):
            return
        test = st.test
        neg = isinstance(test, ast.UnaryOp) and isinstance(test.op, ast.Not)
        inner = test.operand if neg else test
        names: list[str] = []
        strong = False
        why = ""
        if isinstance(inner, ast.Compare) and len(inner.ops) == 1 and isinstance(inner.left, ast.Name):
            op = inner.ops[0]
            if isinstance(op, ast.NotIn) and not neg:
                names, strong, why = [inner.left.id], True, "allow-list membership check"
            elif isinstance(op, ast.In) and not neg:
                # blacklist: `if ".." in x` style
                names, why = [inner.left.id], "deny-list check"
        if isinstance(inner, ast.Compare) and len(inner.ops) == 1 and isinstance(inner.ops[0], ast.In) \
                and isinstance(inner.comparators[0], ast.Name) and not neg:
            names, why = [inner.comparators[0].id], "deny-list substring check"
        if neg and isinstance(inner, ast.Call):
            cname = _call_name(inner)
            vars_ = [n.id for a in inner.args for n in ast.walk(a) if isinstance(n, ast.Name)]
            if cname in ("fullmatch", "match") and inner.args:
                pat = inner.args[0]
                anchored = cname == "fullmatch" or (isinstance(pat, ast.Constant) and str(pat.value).endswith(("$", r"\Z")))
                if anchored:
                    names, strong, why = vars_[1:] if len(vars_) > 1 else vars_, True, f"regex {cname} validation"
            elif cname in ("isdigit", "isalnum", "isdecimal", "isnumeric", "isidentifier", "isalpha"):
                recv = _root_name(inner.func)
                names, strong, why = ([recv] if recv else []), True, f"{cname}() validation"
            elif cname == "startswith" and isinstance(inner.func, ast.Attribute):
                recv = _root_name(inner.func.value)
                if recv and recv in env:
                    if env[recv].normalized:
                        names, strong, why = [recv], True, "normalised path prefix check"
                    else:
                        names, why = [recv], "prefix check on a non-normalised path"
            elif cname == "is_relative_to" and isinstance(inner.func, ast.Attribute):
                recv = _root_name(inner.func.value)
                if recv and recv in env:
                    names, strong, why = [recv], env[recv].normalized, "Path.is_relative_to check"
        if isinstance(inner, ast.Compare) and isinstance(inner.left, ast.Call) and _call_name(inner.left) == "commonpath":
            vars_ = [n.id for n in ast.walk(inner.left) if isinstance(n, ast.Name) and n.id in env]
            if vars_ and all(env[v].normalized for v in vars_):
                names, strong, why = vars_, True, "commonpath containment check"
        ref = Ref(file=self.file, line=st.lineno, note=why)
        for n in names:
            if n not in env:
                continue
            if strong:
                env.pop(n)
                # all variables derived from n before the guard are also covered when they alias it
                self.holder.sanitizer = self.holder.sanitizer or ref
            else:
                self.holder.partial_checks.append(ref)

    # ----------------------------------------------------------------- sinks
    def at_sink(self, st: ast.stmt, env: dict[str, Taint]) -> TraceResult:
        res = self.holder
        if self.call_target is not None:
            return self._at_call_site(st, env)
        sink_expr, sink_line = self._find_sink(st)
        if sink_expr is None:
            res.notes.append("no recognised sink at this line")
            return res
        res.sink_found = True
        if sink_expr == "SAFE":
            res.constant_ref = Ref(file=self.file, line=sink_line, note="sink uses bound parameters / argument list")
            return res
        t = self.expr(env, sink_expr)
        if t is None:
            if not any(isinstance(n, ast.Name) and n.id in env for n in ast.walk(sink_expr)) and res.sanitizer is None:
                res.constant_ref = Ref(file=self.file, line=sink_line,
                                       note="no request-controlled value reaches the sink argument")
            return res
        res.reached = True
        res.steps = t.steps + [self.eng.step("sink", self.file, sink_line)]
        return res

    def _at_call_site(self, st: ast.stmt, env: dict[str, Taint]) -> TraceResult:
        fname, idx, pname = self.call_target
        for n in ast.walk(st):
            if isinstance(n, ast.Call) and _call_name(n) == fname:
                arg = None
                if 0 <= idx < len(n.args):
                    arg = n.args[idx]
                for k in n.keywords:
                    if k.arg == pname:
                        arg = k.value
                t = self.expr(env, arg)
                if t is not None:
                    self.holder.reached = True
                    self.holder.steps = t.steps
                return self.holder
        return self.holder

    def _find_sink(self, st: ast.stmt):
        cwe = self.cwe
        candidates = []
        for n in ast.walk(st):
            if not isinstance(n, ast.Call):
                continue
            name = _call_name(n)
            dotted = _dotted(n.func)
            if cwe == "CWE-89" and name in ("execute", "executemany", "executescript", "text", "raw"):
                if not n.args:
                    continue
                candidates.append((n.args[0], n.lineno))
            elif cwe == "CWE-78":
                if dotted in ("os.system", "os.popen", "system", "popen") and n.args:
                    candidates.append((n.args[0], n.lineno))
                elif name in ("run", "call", "Popen", "check_output", "check_call", "getoutput", "getstatusoutput") \
                        and ("subprocess" in dotted or isinstance(n.func, ast.Name)):
                    shell = any(k.arg == "shell" and isinstance(k.value, ast.Constant) and k.value.value for k in n.keywords)
                    if name in ("getoutput", "getstatusoutput"):
                        shell = True
                    if not n.args:
                        continue
                    if not shell:
                        candidates.append(("SAFE", n.lineno))
                    else:
                        candidates.append((n.args[0], n.lineno))
            elif cwe == "CWE-22" and name in ("open", "send_file", "remove", "unlink", "rmtree", "read_text",
                                               "write_text", "read_bytes", "FileResponse"):
                if name in ("read_text", "read_bytes", "write_text", "unlink") and isinstance(n.func, ast.Attribute):
                    candidates.append((n.func.value, n.lineno))
                elif n.args:
                    candidates.append((n.args[0], n.lineno))
            elif cwe == "CWE-79" and name in ("make_response", "render_template_string", "Markup", "Response", "HTMLResponse"):
                if n.args:
                    candidates.append((n.args[0], n.lineno))
            elif cwe == "CWE-918" and (dotted.startswith("requests.") or name in ("urlopen", "get", "post")) and \
                    (n.args or any(k.arg == "url" for k in n.keywords)):
                arg = n.args[0] if n.args else next(k.value for k in n.keywords if k.arg == "url")
                candidates.append((arg, n.lineno))
        if cwe == "CWE-79" and isinstance(st, ast.Return) and st.value is not None and not candidates:
            v = st.value
            if isinstance(v, ast.Call) and _call_name(v) in ("render_template", "jsonify", "redirect", "url_for"):
                return "SAFE", st.lineno
            candidates.append((v, st.lineno))
        if not candidates:
            return None, None
        # prefer a candidate whose argument is non-constant
        for expr, ln in candidates:
            if expr != "SAFE" and not isinstance(expr, ast.Constant):
                return expr, ln
        return candidates[0]
