"""Read ledger: every claim the model makes must cite a line that a tool actually read.

The orchestrator owns the ledger; tools record what they returned; verdict
validation rejects citations outside the recorded ranges.
"""
from __future__ import annotations

import threading
from collections import defaultdict

from caa.core.models import Ref


class ReadLedger:
    def __init__(self) -> None:
        self._ranges: dict[str, list[tuple[int, int]]] = defaultdict(list)
        self._lines: dict[tuple[str, int], str] = {}
        self._http: dict[str, str] = {}
        self._lock = threading.Lock()

    # --- recording -------------------------------------------------------
    def record_lines(self, file: str, start: int, lines: list[str]) -> None:
        if not lines:
            return
        with self._lock:
            self._ranges[file].append((start, start + len(lines) - 1))
            for i, text in enumerate(lines):
                self._lines[(file, start + i)] = text

    def record_http(self, exchange_id: str, summary: str) -> None:
        self._http[exchange_id] = summary

    # --- checking --------------------------------------------------------
    def was_read(self, file: str, line: int) -> bool:
        with self._lock:
            return any(a <= line <= b for a, b in self._ranges.get(file, []))

    def line_text(self, file: str, line: int) -> str | None:
        return self._lines.get((file, line))

    def verify(self, ref: Ref) -> bool:
        if ref.http_exchange:
            return ref.http_exchange in self._http
        if ref.file is None or ref.line is None:
            return False
        return self.was_read(ref.file, ref.line)

    def is_code_line(self, ref: Ref) -> bool:
        """A protection reference must point at executable code, not a comment or docstring."""
        text = self.line_text(ref.file or "", ref.line or -1)
        if text is None:
            return False
        s = text.strip()
        if not s or s.startswith("#"):
            return False
        if s.startswith(('"""', "'''")) or (s[:1] in "\"'" and s[-1:] in "\"'"):
            return False
        return True
