"""read_file / search, jailed to the repository root."""
from __future__ import annotations

import fnmatch
import os
import re
import shutil
import subprocess
from pathlib import Path

from caa.core.citations import ReadLedger

MAX_READ_LINES = 400
MAX_SEARCH_HITS = 200
SKIP_DIRS = {".git", "node_modules", ".venv", "venv", "__pycache__", ".mypy_cache", ".pytest_cache", ".caa"}


class PathOutsideRepo(PermissionError):
    pass


class RepoFS:
    def __init__(self, root: Path, ledger: ReadLedger | None = None):
        self.root = root.resolve()
        self.ledger = ledger or ReadLedger()

    # -- jail ---------------------------------------------------------------
    def resolve(self, rel: str) -> Path:
        p = (self.root / rel).resolve()
        if p != self.root and self.root not in p.parents:
            raise PathOutsideRepo(f"path escapes repository root: {rel!r}")
        return p

    def rel(self, p: Path) -> str:
        return p.resolve().relative_to(self.root).as_posix()

    # -- tools --------------------------------------------------------------
    def read_lines(self, rel: str) -> list[str]:
        return self.resolve(rel).read_text(encoding="utf-8", errors="replace").splitlines()

    def read_file(self, path: str, start: int = 1, end: int | None = None, record: bool = True) -> str:
        lines = self.read_lines(path)
        start = max(1, start)
        end = min(len(lines), end or start + MAX_READ_LINES - 1, start + MAX_READ_LINES - 1)
        chunk = lines[start - 1:end]
        if record:
            self.ledger.record_lines(path, start, chunk)
        return "\n".join(f"{start + i:>5}| {t}" for i, t in enumerate(chunk))

    def iter_files(self, glob: str = "*") -> list[str]:
        out = []
        for dirpath, dirnames, filenames in os.walk(self.root):
            dirnames[:] = sorted(d for d in dirnames if d not in SKIP_DIRS)
            for fn in sorted(filenames):
                rel = Path(dirpath, fn).relative_to(self.root).as_posix()
                if fnmatch.fnmatch(rel, glob) or fnmatch.fnmatch(fn, glob):
                    out.append(rel)
        return out

    def search(self, pattern: str, glob: str = "*") -> list[tuple[str, int, str]]:
        """Regex search. Uses ripgrep when available, pure-python otherwise."""
        hits: list[tuple[str, int, str]] = []
        if shutil.which("rg"):
            cmd = ["rg", "--no-heading", "--line-number", "--color=never", "-e", pattern, "--glob", glob, "."]
            proc = subprocess.run(cmd, cwd=self.root, capture_output=True, text=True, timeout=60)
            for line in proc.stdout.splitlines():
                parts = line.split(":", 2)
                if len(parts) == 3 and parts[1].isdigit():
                    hits.append((parts[0].removeprefix("./"), int(parts[1]), parts[2]))
        else:
            rx = re.compile(pattern)
            for rel in self.iter_files(glob):
                for i, t in enumerate(self.read_lines(rel), 1):
                    if rx.search(t):
                        hits.append((rel, i, t))
        hits.sort()
        hits = hits[:MAX_SEARCH_HITS]
        for f, ln, t in hits:
            self.ledger.record_lines(f, ln, [t])
        return hits
