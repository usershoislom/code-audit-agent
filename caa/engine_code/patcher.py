"""Minimal fixes for confirmed data-flow findings + apply_patch on a working COPY.

Deterministic templates (AST rewrite of the sink statement only):
  CWE-89  string-built SQL         -> constant SQL text + bound parameters
  CWE-78  subprocess(shell=True)   -> argument list without shell
          os.system(str)           -> shlex.quote() around non-constant parts
  CWE-22  join/concat with input   -> _caa_contained(base, part) (realpath + commonpath)
  CWE-79  HTML built from input    -> markupsafe.escape(); render_template_string -> template variables
Anything else goes to the LLM patch node (if enabled) or is reported without a fix.
"""
from __future__ import annotations

import ast
import difflib
import re
import shlex
import shutil
import subprocess
import tempfile
from pathlib import Path

CONTAINED_HELPER = '''

def _caa_contained(base, *parts):
    """Join under base and refuse any result outside it (path traversal guard)."""
    root = os.path.realpath(base)
    full = os.path.realpath(os.path.join(root, *parts))
    if os.path.commonpath([root, full]) != root:
        raise PermissionError("path escapes base directory")
    return full
'''


class PatchError(Exception):
    pass


# ----------------------------------------------------------------------------- helpers

def _replace(text: str, edits: list[tuple[ast.AST, str]]) -> str:
    lines = text.splitlines(keepends=True)
    spans = []
    for node, new in edits:
        a = _offset(lines, node.lineno, node.col_offset)
        b = _offset(lines, node.end_lineno, node.end_col_offset)
        spans.append((a, b, new))
    for a, b, new in sorted(spans, reverse=True):
        text = text[:a] + new + text[b:]
    return text


def _offset(lines: list[str], lineno: int, col_bytes: int) -> int:
    before = sum(len(x) for x in lines[:lineno - 1])
    line_bytes = lines[lineno - 1].encode()
    return before + len(line_bytes[:col_bytes].decode(errors="ignore"))


def _ensure_import(text: str, line: str, probe: str) -> str:
    if re.search(probe, text, re.M):
        return text
    tree = ast.parse(text)
    last = 0
    for n in tree.body:
        if isinstance(n, (ast.Import, ast.ImportFrom)):
            last = n.end_lineno
        elif not (isinstance(n, ast.Expr) and isinstance(getattr(n, "value", None), ast.Constant)):
            break
    lines = text.splitlines(keepends=True)
    lines.insert(last, line + "\n")
    return "".join(lines)


def _stmt_at(tree: ast.AST, line: int) -> ast.stmt | None:
    """Innermost simple statement on `line`, or the compound statement whose header holds it."""
    best = None
    for n in ast.walk(tree):
        if not isinstance(n, ast.stmt) or not (n.lineno <= line <= (n.end_lineno or n.lineno)):
            continue
        body = getattr(n, "body", None)
        if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            continue
        if isinstance(body, list) and body and line >= body[0].lineno:
            continue           # line is inside the body, a deeper statement will match
        if best is None or n.lineno >= best.lineno:
            best = n
    if best is not None and isinstance(getattr(best, "body", None), list):
        items = getattr(best, "items", None) or ([best.test] if hasattr(best, "test") else []) + \
            ([best.iter] if hasattr(best, "iter") else [])
        holder = ast.Expr(value=ast.Tuple(elts=[getattr(i, "context_expr", i) for i in items], ctx=ast.Load()))
        ast.copy_location(holder, best)
        holder.end_lineno, holder.end_col_offset = best.end_lineno, best.end_col_offset
        return holder
    return best


def _func_at(tree: ast.AST, line: int):
    best = None
    for n in ast.walk(tree):
        if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef)) and n.lineno <= line <= n.end_lineno:
            if best is None or n.lineno > best.lineno:
                best = n
    return best


def _last_assign(func, name: str, before: int) -> ast.Assign | None:
    found = None
    for n in ast.walk(func) if func is not None else []:
        if isinstance(n, ast.Assign) and n.lineno < before and any(
                isinstance(t, ast.Name) and t.id == name for t in n.targets):
            if found is None or n.lineno > found.lineno:
                found = n
    return found


def _parts(expr: ast.AST) -> list:
    """Flatten a string-building expression into [str | ast.expr]."""
    if isinstance(expr, ast.Constant) and isinstance(expr.value, str):
        return [expr.value]
    if isinstance(expr, ast.JoinedStr):
        out = []
        for v in expr.values:
            if isinstance(v, ast.Constant):
                out.append(v.value)
            elif isinstance(v, ast.FormattedValue):
                if v.format_spec is not None or v.conversion not in (-1, None):
                    raise PatchError("formatted value with spec/conversion")
                out.append(v.value)
        return out
    if isinstance(expr, ast.BinOp) and isinstance(expr.op, ast.Add):
        return _parts(expr.left) + _parts(expr.right)
    if isinstance(expr, ast.BinOp) and isinstance(expr.op, ast.Mod) and isinstance(expr.left, ast.Constant):
        vals = expr.right.elts if isinstance(expr.right, ast.Tuple) else [expr.right]
        chunks = re.split(r"%[sd]", expr.left.value)
        if len(chunks) != len(vals) + 1 or "%(" in expr.left.value:
            raise PatchError("unsupported % format")
        return _interleave(chunks, vals)
    if isinstance(expr, ast.Call) and isinstance(expr.func, ast.Attribute) and expr.func.attr == "format" \
            and isinstance(expr.func.value, ast.Constant) and not expr.keywords:
        chunks = re.split(r"\{\d*\}", expr.func.value.value)
        if len(chunks) != len(expr.args) + 1:
            raise PatchError("unsupported str.format")
        return _interleave(chunks, list(expr.args))
    return [expr]


def _interleave(chunks: list[str], vals: list) -> list:
    out: list = []
    for i, c in enumerate(chunks):
        if c:
            out.append(c)
        if i < len(vals):
            out.append(vals[i])
    return out


def _merge_literals(parts: list) -> list:
    out: list = []
    for p in parts:
        if isinstance(p, str) and out and isinstance(out[-1], str):
            out[-1] += p
        else:
            out.append(p)
    return out


def _is_constant_name(e: ast.AST) -> bool:
    return isinstance(e, ast.Name) and e.id.isupper()


def _py_str(s: str) -> str:
    return '"' + s.replace("\\", "\\\\").replace('"', '\\"').replace("\n", "\\n") + '"'


def _call_name(n: ast.Call) -> str:
    f = n.func
    return f.attr if isinstance(f, ast.Attribute) else getattr(f, "id", "")


# ----------------------------------------------------------------------------- templates

def patch_sql(text: str, sink_line: int) -> tuple[str, str]:
    tree = ast.parse(text)
    st = _stmt_at(tree, sink_line)
    call = next((n for n in ast.walk(st) if isinstance(n, ast.Call)
                 and _call_name(n) in ("execute", "executemany") and n.args), None) if st else None
    if call is None or len(call.args) > 1:
        raise PatchError("no single-argument execute() at sink")
    func = _func_at(tree, sink_line)
    q = call.args[0]
    assign = None
    if isinstance(q, ast.Name):
        assign = _last_assign(func, q.id, call.lineno)
        if assign is None:
            raise PatchError("query variable definition not found")
        expr = assign.value
    else:
        expr = q
    parts = _merge_literals(_parts(expr))
    placeholder = "?" if re.search(r"^\s*import sqlite3|^\s*from sqlite3", text, re.M) else "%s"
    sql, params = "", []
    i = 0
    while i < len(parts):
        p = parts[i]
        if isinstance(p, str):
            sql += p
        elif _is_constant_name(p):
            raise PatchError("identifier interpolation (needs allow-list, not a parameter)")
        else:
            nxt = parts[i + 1] if i + 1 < len(parts) and isinstance(parts[i + 1], str) else ""
            pre, post_prefix = "", ""
            m_pre = re.search(r"(['\"])(%?)$", sql)
            m_post = re.match(r"(%?)(['\"])", nxt)
            if m_pre and m_post and m_pre.group(1) == m_post.group(2):
                sql = sql[:m_pre.start()]
                pre, post_prefix = m_pre.group(2), m_post.group(1)
                parts[i + 1] = nxt[m_post.end():]
            src = ast.unparse(p)
            if pre or post_prefix:
                src = f'"{pre}" + str({src}) + "{post_prefix}"'.replace('"" + ', "").replace(' + ""', "")
            params.append(src)
            sql += placeholder
        i += 1
    if not params:
        raise PatchError("nothing to parametrise")
    ptuple = "(" + ", ".join(params) + ("," if len(params) == 1 else "") + ")"
    edits = []
    if assign is not None:
        edits.append((assign.value, _py_str(sql)))
        edits.append((q, f"{q.id}, {ptuple}"))
    else:
        edits.append((q, f"{_py_str(sql)}, {ptuple}"))
    return _replace(text, edits), "SQL text is now constant; user values are passed as bound parameters."


_SHELL_META = re.compile(r"[|&;<>`$()]")


def patch_cmd(text: str, sink_line: int) -> tuple[str, str]:
    tree = ast.parse(text)
    st = _stmt_at(tree, sink_line)
    calls = [n for n in ast.walk(st) if isinstance(n, ast.Call)] if st else []
    func = _func_at(tree, sink_line)
    for call in calls:
        dotted = ast.unparse(call.func)
        if dotted in ("os.system",) and call.args:
            parts = _merge_literals(_parts(call.args[0]))
            if not any(not isinstance(p, str) for p in parts):
                raise PatchError("constant command")
            new = " + ".join(_py_str(p) if isinstance(p, str) else
                             (ast.unparse(p) if _is_constant_name(p) else f"shlex.quote(str({ast.unparse(p)}))")
                             for p in parts)
            out = _replace(text, [(call.args[0], new)])
            out = _ensure_import(out, "import shlex", r"^\s*import shlex")
            return out, "Every non-constant part of the shell command is quoted with shlex.quote()."
        shell_kw = next((k for k in call.keywords if k.arg == "shell"), None)
        if shell_kw is not None and call.args:
            cmd = call.args[0]
            assign = _last_assign(func, cmd.id, call.lineno) if isinstance(cmd, ast.Name) else None
            expr = assign.value if assign is not None else cmd
            parts = _merge_literals(_parts(expr))
            lit = "".join(p if isinstance(p, str) else f"\x00{i}\x00" for i, p in enumerate(parts))
            if _SHELL_META.search("".join(p for p in parts if isinstance(p, str))):
                raise PatchError("command uses shell features; needs manual rewrite")
            exprs = {str(i): p for i, p in enumerate(parts) if not isinstance(p, str)}
            tokens = []
            for tok in shlex.split(lit):
                pieces = re.split(r"\x00(\d+)\x00", tok)
                elems = []
                for j, piece in enumerate(pieces):
                    if j % 2 == 0:
                        if piece:
                            elems.append(("s", piece))
                    else:
                        elems.append(("e", exprs[piece]))
                if len(elems) == 1 and elems[0][0] == "s":
                    tokens.append(_py_str(elems[0][1]))
                elif len(elems) == 1:
                    tokens.append(f"str({ast.unparse(elems[0][1])})")
                else:
                    tokens.append("f" + _py_str("".join(v.replace("{", "{{").replace("}", "}}") if k == "s"
                                                        else "{" + ast.unparse(v) + "}" for k, v in elems)))
            argv = "[" + ", ".join(tokens) + "]"
            new_call = ast.parse(ast.unparse(call), mode="eval").body
            new_call.keywords = [k for k in new_call.keywords if k.arg != "shell"]
            edits = []
            if assign is not None:
                edits.append((assign.value, argv))
                edits.append((call, ast.unparse(new_call)))
            else:
                new_call.args[0] = ast.parse(argv, mode="eval").body
                edits.append((call, ast.unparse(new_call)))
            return _replace(text, edits), "The command is passed as an argument list without a shell."
    raise PatchError("no shell sink at line")


def patch_path(text: str, sink_line: int) -> tuple[str, str]:
    tree = ast.parse(text)
    st = _stmt_at(tree, sink_line)
    func = _func_at(tree, sink_line)
    sink = next((n for n in ast.walk(st) if isinstance(n, ast.Call)
                 and _call_name(n) in ("open", "send_file") and n.args), None) if st else None
    if sink is None:
        raise PatchError("no file sink at line")
    arg = sink.args[0]
    target = arg
    if isinstance(arg, ast.Name):
        a = _last_assign(func, arg.id, sink.lineno)
        if a is None:
            raise PatchError("path variable definition not found")
        target = a.value
        # unwrap normalisers: realpath(join(...))
    while isinstance(target, ast.Call) and _call_name(target) in ("realpath", "abspath", "normpath") and target.args:
        target = target.args[0]
    if isinstance(target, ast.Call) and ast.unparse(target.func) in ("os.path.join", "path.join", "join"):
        new = f"_caa_contained({', '.join(ast.unparse(x) for x in target.args)})"
    elif isinstance(target, ast.BinOp) and isinstance(target.op, ast.Add):
        flat = []

        def flatten(e):
            if isinstance(e, ast.BinOp) and isinstance(e.op, ast.Add):
                flatten(e.left)
                flatten(e.right)
            else:
                flat.append(e)
        flatten(target)
        idx = next((i for i, e in enumerate(flat) if not (isinstance(e, ast.Constant) or _is_constant_name(e))), None)
        if idx is None or idx == 0:
            raise PatchError("no constant base prefix")
        base = " + ".join(ast.unparse(e) for e in flat[:idx])
        rest = " + ".join(ast.unparse(e) for e in flat[idx:])
        new = f"_caa_contained({base}, {rest})"
    else:
        raise PatchError("unsupported path expression")
    out = _replace(text, [(target, new)])
    out = _ensure_import(out, "import os", r"^\s*import os\b")
    if "def _caa_contained" not in out:
        out = out.rstrip("\n") + "\n" + CONTAINED_HELPER
    return out, "The final path is resolved and refused unless it stays inside the base directory."


def patch_xss(text: str, sink_line: int) -> tuple[str, str]:
    tree = ast.parse(text)
    st = _stmt_at(tree, sink_line)
    if st is None:
        raise PatchError("no statement")
    rts = next((n for n in ast.walk(st) if isinstance(n, ast.Call) and _call_name(n) == "render_template_string"
                and n.args), None)
    if rts is not None:
        parts = _merge_literals(_parts(rts.args[0]))
        tpl, kwargs = "", []
        for p in parts:
            if isinstance(p, str):
                tpl += p
            else:
                name = p.id if isinstance(p, ast.Name) else f"caa_v{len(kwargs)}"
                kwargs.append(f"{name}={ast.unparse(p)}")
                tpl += "{{ " + name + " }}"
        if not kwargs:
            raise PatchError("constant template")
        return (_replace(text, [(rts, f"render_template_string({_py_str(tpl)}, {', '.join(kwargs)})")]),
                "User values are passed as template variables (autoescaped by Jinja) instead of template text.")
    target = None
    for n in ast.walk(st):
        if isinstance(n, ast.Call) and _call_name(n) in ("make_response", "Response", "Markup") and n.args:
            target = n.args[0]
            break
    if target is None and isinstance(st, ast.Return):
        target = st.value
    if target is None:
        raise PatchError("no HTML sink")
    edits = []
    for node in ast.walk(target):
        if isinstance(node, ast.FormattedValue) and not _is_escaped(node.value) and not isinstance(node.value, ast.Constant):
            edits.append((node.value, f"escape({ast.unparse(node.value)})"))
    if isinstance(target, ast.BinOp):
        flat = []

        def flatten(e):
            if isinstance(e, ast.BinOp) and isinstance(e.op, (ast.Add, ast.Mod)):
                flatten(e.left)
                flatten(e.right)
            else:
                flat.append(e)
        flatten(target)
        for e in flat:
            if not isinstance(e, (ast.Constant, ast.JoinedStr)) and not _is_escaped(e):
                edits.append((e, f"str(escape({ast.unparse(e)}))"))
    if not edits:
        raise PatchError("nothing to escape")
    out = _replace(text, edits)
    out = _ensure_import(out, "from markupsafe import escape", r"^\s*from markupsafe import .*\bescape\b")
    return out, "User-controlled values are HTML-escaped with markupsafe.escape() before being placed in markup."


def _is_escaped(e: ast.AST) -> bool:
    return isinstance(e, ast.Call) and _call_name(e) in ("escape", "int", "float", "len")


TEMPLATES = {"CWE-89": patch_sql, "CWE-78": patch_cmd, "CWE-22": patch_path, "CWE-79": patch_xss}


def template_patch(text: str, cwe: str, sink_line: int) -> tuple[str, str] | None:
    fn = TEMPLATES.get(cwe)
    if fn is None:
        return None
    try:
        new, why = fn(text, sink_line)
        ast.parse(new)
        return new, why
    except (PatchError, SyntaxError, IndexError, KeyError, ValueError):
        return None


def unified_diff(rel: str, old: str, new: str) -> str:
    return "".join(difflib.unified_diff(old.splitlines(keepends=True), new.splitlines(keepends=True),
                                        fromfile=f"a/{rel}", tofile=f"b/{rel}"))


class WorkingCopy:
    """apply_patch target: a throw-away copy of the repository; the original is never modified."""

    def __init__(self, root: Path):
        self.dir = Path(tempfile.mkdtemp(prefix="caa-wc-"))
        self.root = self.dir / "repo"
        shutil.copytree(root, self.root, ignore=shutil.ignore_patterns(".git", "__pycache__", ".caa"))

    def apply_patch(self, diff: str) -> tuple[bool, str]:
        proc = subprocess.run(["git", "apply", "--recount", "--whitespace=nowarn", "-"], input=diff, text=True,
                              cwd=self.root, capture_output=True)
        return proc.returncode == 0, proc.stderr.strip()

    def revert(self, rel: str, original: str) -> None:
        (self.root / rel).write_text(original)

    def cleanup(self) -> None:
        shutil.rmtree(self.dir, ignore_errors=True)
