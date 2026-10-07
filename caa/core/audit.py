"""Append-only audit log of every tool call / model call, with secret masking."""
from __future__ import annotations

import json
import re
import threading
import time
from pathlib import Path

# Patterns for values that must never reach logs or reports in clear text.
_SECRET_PATTERNS = [
    re.compile(r"AKIA[0-9A-Z]{16}"),                                   # AWS access key id
    re.compile(r"(?i)(?:aws_secret_access_key|secret_key)\s*[=:]\s*['\"]?([A-Za-z0-9/+=]{30,})"),
    re.compile(r"gh[pousr]_[A-Za-z0-9]{30,}"),                         # GitHub tokens
    re.compile(r"xox[baprs]-[A-Za-z0-9-]{10,}"),                       # Slack
    re.compile(r"sk-[A-Za-z0-9_-]{20,}"),                              # OpenAI-style
    re.compile(r"gsk_[A-Za-z0-9]{20,}"),                               # Groq
    re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----[\s\S]*?-----END [A-Z ]*PRIVATE KEY-----"),
    re.compile(r"(?i)(?:password|passwd|pwd|token|api_key|apikey|secret)\s*[=:]\s*['\"]([^'\"\s]{6,})['\"]"),
    re.compile(r"(?i)authorization:\s*(?:bearer|basic)\s+[A-Za-z0-9._~+/=-]+"),
    re.compile(r"(?i)(?:session|sessionid|csrftoken)=[A-Za-z0-9._%-]{8,}"),
]


def mask_secrets(text: str) -> str:
    if not text:
        return text

    def _mask(m: re.Match) -> str:
        whole = m.group(0)
        if m.groups() and m.group(1):
            val = m.group(1)
            return whole.replace(val, _redact(val))
        return _redact(whole)

    for pat in _SECRET_PATTERNS:
        text = pat.sub(_mask, text)
    return text


def _redact(val: str) -> str:
    if len(val) <= 8:
        return "****"
    return f"{val[:4]}****[{len(val)}]"


class AuditLog:
    def __init__(self, path: Path | None):
        self.path = path
        self._lock = threading.Lock()
        if path:
            path.parent.mkdir(parents=True, exist_ok=True)

    def write(self, kind: str, **payload) -> None:
        rec = {"ts": round(time.time(), 3), "kind": kind, **payload}
        line = mask_secrets(json.dumps(rec, ensure_ascii=False, default=str))
        if self.path is None:
            return
        with self._lock, self.path.open("a", encoding="utf-8") as fh:
            fh.write(line + "\n")


NULL_AUDIT = AuditLog(None)
