"""Whitelisted tool surface for the model. No shell, fixed argument schemas.

The model can only name tools in ToolRegistry.exposed; arguments are validated
by pydantic; every call is written to the audit log; output that comes from
the analysed system is wrapped as untrusted material.
"""
from __future__ import annotations

from typing import Callable

from pydantic import BaseModel, Field, ValidationError

from caa.core.audit import NULL_AUDIT, AuditLog, mask_secrets
from caa.core.kb import KnowledgeBase
from caa.core.untrusted import wrap
from caa.tools.fs import PathOutsideRepo, RepoFS
from caa.tools.symbols import SymbolIndex


class ReadFileArgs(BaseModel):
    path: str
    start: int = Field(1, ge=1)
    end: int | None = None


class SearchArgs(BaseModel):
    pattern: str = Field(max_length=200)
    glob: str = "*.py"


class SymbolArgs(BaseModel):
    name: str = Field(max_length=200)


class KbArgs(BaseModel):
    query: str = Field(max_length=300)


class ToolError(Exception):
    pass


class ToolRegistry:
    def __init__(self, fs: RepoFS, symbols: SymbolIndex, kb: KnowledgeBase, audit: AuditLog = NULL_AUDIT):
        self.fs, self.symbols, self.kb, self.audit = fs, symbols, kb, audit
        self._tools: dict[str, tuple[type[BaseModel], Callable[[BaseModel], str]]] = {
            "read_file": (ReadFileArgs, self._read_file),
            "search": (SearchArgs, self._search),
            "find_symbol": (SymbolArgs, self._find_symbol),
            "get_callers": (SymbolArgs, self._get_callers),
            "get_callees": (SymbolArgs, self._get_callees),
            "kb_lookup": (KbArgs, self._kb),
        }
        self.calls = 0

    @property
    def exposed(self) -> list[str]:
        return sorted(self._tools)

    def describe(self) -> str:
        return "\n".join(f"- {n}({', '.join(m.model_fields)})" for n, (m, _) in sorted(self._tools.items()))

    def call(self, name: str, args: dict) -> str:
        self.calls += 1
        if name not in self._tools:
            self.audit.write("tool_refused", tool=name, args=args)
            return f"ERROR: tool {name!r} is not available. Allowed: {', '.join(self.exposed)}"
        model, fn = self._tools[name]
        try:
            parsed = model.model_validate(args)
            out = fn(parsed)
        except (ValidationError, PathOutsideRepo, FileNotFoundError, IsADirectoryError, ToolError) as exc:
            self.audit.write("tool_error", tool=name, args=args, error=str(exc)[:300])
            return f"ERROR: {type(exc).__name__}: {str(exc)[:300]}"
        self.audit.write("tool_call", tool=name, args=args, output_chars=len(out))
        return out

    # -- implementations (all outputs from the target are wrapped as untrusted)
    def _read_file(self, a: ReadFileArgs) -> str:
        return wrap(mask_secrets(self.fs.read_file(a.path, a.start, a.end)), f"read_file {a.path}")

    def _search(self, a: SearchArgs) -> str:
        hits = self.fs.search(a.pattern, a.glob)
        return wrap(mask_secrets("\n".join(f"{f}:{ln}: {t}" for f, ln, t in hits[:50]) or "(no matches)"),
                    f"search {a.pattern}")

    def _find_symbol(self, a: SymbolArgs) -> str:
        syms = self.symbols.find_symbol(a.name)
        return "\n".join(f"{s.qualname} {s.file}:{s.start}-{s.end} decorators={s.decorators}" for s in syms) or "(none)"

    def _get_callers(self, a: SymbolArgs) -> str:
        return "\n".join(f"{s.qualname} at {s.file}:{ln}" for s, ln in self.symbols.get_callers(a.name)) or "(none)"

    def _get_callees(self, a: SymbolArgs) -> str:
        return "\n".join(f"{n} at line {ln}" for n, ln in self.symbols.get_callees(a.name)) or "(none)"

    def _kb(self, a: KbArgs) -> str:
        cards = self.kb.lookup(a.query)
        return "\n\n".join(self.kb.render(c) for c in cards) or "(no card)"
