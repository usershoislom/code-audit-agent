"""Symbol index (functions, calls) for find_symbol / get_callers / get_callees.

tree-sitter is used when installed (language-agnostic path for future
languages); a stdlib `ast` backend keeps the tool working on a bare machine.
"""
from __future__ import annotations

import ast
from dataclasses import dataclass, field

from caa.tools.fs import RepoFS

try:  # optional dependency
    import tree_sitter
    import tree_sitter_python

    _TS_LANG = tree_sitter.Language(tree_sitter_python.language())
except Exception:  # pragma: no cover - depends on environment
    _TS_LANG = None


@dataclass
class Symbol:
    name: str             # short name
    qualname: str         # Class.method or func
    file: str
    start: int
    end: int
    decorators: list[str] = field(default_factory=list)
    calls: list[tuple[str, int]] = field(default_factory=list)  # (callee short name, line)


class SymbolIndex:
    def __init__(self, fs: RepoFS, backend: str | None = None):
        self.fs = fs
        self.backend = backend or ("tree-sitter" if _TS_LANG else "ast")
        self.symbols: list[Symbol] = []
        for rel in fs.iter_files("*.py"):
            try:
                src = fs.resolve(rel).read_bytes()
            except OSError:
                continue
            if self.backend == "tree-sitter":
                self.symbols.extend(_ts_symbols(rel, src))
            else:
                self.symbols.extend(_ast_symbols(rel, src))

    def find_symbol(self, name: str) -> list[Symbol]:
        return [s for s in self.symbols if s.name == name or s.qualname == name]

    def get_callees(self, name: str) -> list[tuple[str, int]]:
        out = []
        for s in self.find_symbol(name):
            out.extend(s.calls)
        return out

    def get_callers(self, name: str) -> list[tuple[Symbol, int]]:
        short = name.split(".")[-1]
        out = []
        for s in self.symbols:
            for callee, line in s.calls:
                if callee == short:
                    out.append((s, line))
        return out

    def enclosing(self, file: str, line: int) -> Symbol | None:
        best = None
        for s in self.symbols:
            if s.file == file and s.start <= line <= s.end:
                if best is None or s.start >= best.start:
                    best = s
        return best


# --- tree-sitter backend -----------------------------------------------------

def _ts_symbols(rel: str, src: bytes) -> list[Symbol]:
    parser = tree_sitter.Parser(_TS_LANG)
    tree = parser.parse(src)
    out: list[Symbol] = []

    def text(n) -> str:
        return src[n.start_byte:n.end_byte].decode("utf-8", "replace")

    def visit(node, prefix: str, decorators: list[str]):
        for child in node.children:
            if child.type == "decorated_definition":
                decs = [text(d).lstrip("@").strip() for d in child.children if d.type == "decorator"]
                inner = child.child_by_field_name("definition")
                if inner is not None:
                    handle(inner, prefix, decs)
            elif child.type in ("function_definition", "class_definition"):
                handle(child, prefix, [])
            elif child.type in ("block", "module"):
                visit(child, prefix, [])

    def handle(n, prefix: str, decs: list[str]):
        name = text(n.child_by_field_name("name"))
        qual = f"{prefix}.{name}" if prefix else name
        if n.type == "class_definition":
            visit(n.child_by_field_name("body"), qual, [])
            return
        sym = Symbol(name, qual, rel, n.start_point[0] + 1, n.end_point[0] + 1, decs)
        collect_calls(n.child_by_field_name("body"), sym)
        out.append(sym)
        visit(n.child_by_field_name("body"), qual, [])

    def collect_calls(n, sym: Symbol):
        if n is None:
            return
        stack = [n]
        while stack:
            cur = stack.pop()
            if cur.type == "call":
                fn = cur.child_by_field_name("function")
                if fn is not None:
                    sym.calls.append((text(fn).split(".")[-1], cur.start_point[0] + 1))
            if cur.type in ("function_definition",) and cur is not n:
                continue
            stack.extend(cur.children)

    visit(tree.root_node, "", [])
    return out


# --- ast backend ---------------------------------------------------------------

def _ast_symbols(rel: str, src: bytes) -> list[Symbol]:
    try:
        tree = ast.parse(src)
    except SyntaxError:
        return []
    out: list[Symbol] = []

    def visit(body, prefix):
        for node in body:
            if isinstance(node, ast.ClassDef):
                visit(node.body, f"{prefix}.{node.name}" if prefix else node.name)
            elif isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                qual = f"{prefix}.{node.name}" if prefix else node.name
                sym = Symbol(node.name, qual, rel, node.lineno, node.end_lineno or node.lineno,
                             [ast.unparse(d) for d in node.decorator_list])
                for sub in ast.walk(node):
                    if isinstance(sub, ast.Call):
                        f = sub.func
                        nm = f.attr if isinstance(f, ast.Attribute) else getattr(f, "id", None)
                        if nm:
                            sym.calls.append((nm, sub.lineno))
                out.append(sym)
                visit(node.body, qual)

    visit(tree.body, "")
    return out
