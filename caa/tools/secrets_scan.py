"""scan_secrets: gitleaks when installed, built-in high-signal regexes otherwise.

Values are masked before they leave this module.
"""
from __future__ import annotations

import json
import math
import re
import shutil
import subprocess
import tempfile
from pathlib import Path

from caa.core.audit import mask_secrets
from caa.core.models import Candidate, Group, Location
from caa.tools.fs import RepoFS

BUILTIN_RULES = [
    ("aws-access-key-id", re.compile(r"\b(AKIA[0-9A-Z]{16})\b")),
    ("github-token", re.compile(r"\b(gh[pousr]_[A-Za-z0-9]{36,})\b")),
    ("slack-token", re.compile(r"\b(xox[baprs]-[A-Za-z0-9-]{10,})\b")),
    ("private-key", re.compile(r"(-----BEGIN (?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----)")),
    ("generic-secret-assignment",
     re.compile(r"(?i)\b(?:secret|token|api[_-]?key|password|passwd)\w*\s*[=:]\s*['\"]([A-Za-z0-9_\-+/=!@#$%^&*]{12,})['\"]")),
]
TEXT_SUFFIXES = {".py", ".js", ".ts", ".env", ".cfg", ".ini", ".toml", ".yaml", ".yml", ".json", ".txt", ".conf", ""}


def shannon_entropy(s: str) -> float:
    if not s:
        return 0.0
    freq = {c: s.count(c) / len(s) for c in set(s)}
    return -sum(p * math.log2(p) for p in freq.values())


def scan_secrets(fs: RepoFS) -> list[Candidate]:
    if shutil.which("gitleaks"):
        return _gitleaks(fs)
    return _builtin(fs)


def _builtin(fs: RepoFS) -> list[Candidate]:
    out = []
    for rel in fs.iter_files("*"):
        if Path(rel).suffix not in TEXT_SUFFIXES:
            continue
        try:
            lines = fs.read_lines(rel)
        except (OSError, UnicodeDecodeError):
            continue
        for i, line in enumerate(lines, 1):
            for name, rx in BUILTIN_RULES:
                m = rx.search(line)
                if not m:
                    continue
                val = m.group(1)
                if name == "generic-secret-assignment" and shannon_entropy(val) < 3.0:
                    continue
                out.append(Candidate(rule_id=f"secrets.{name}", source="secrets", cwe="CWE-798",
                                     group=Group.SECRETS_CONFIG,
                                     location=Location(file=rel, start_line=i, end_line=i),
                                     message=f"Possible hard-coded secret ({name})",
                                     snippet=mask_secrets(line.strip()),
                                     extra={"entropy": round(shannon_entropy(val), 2)}))
                break
    return out


def _gitleaks(fs: RepoFS) -> list[Candidate]:
    with tempfile.TemporaryDirectory() as td:
        report = Path(td) / "gl.json"
        subprocess.run(["gitleaks", "detect", "--no-git", "--redact", "-s", str(fs.root), "-r", str(report),
                        "-f", "json"], capture_output=True, text=True, timeout=300)
        try:
            data = json.loads(report.read_text())
        except (OSError, json.JSONDecodeError):
            return _builtin(fs)
    out = []
    for r in data:
        rel = Path(r["File"]).resolve().relative_to(fs.root).as_posix() if Path(r["File"]).is_absolute() else r["File"]
        out.append(Candidate(rule_id=f"gitleaks.{r['RuleID']}", source="gitleaks", cwe="CWE-798",
                             group=Group.SECRETS_CONFIG,
                             location=Location(file=rel, start_line=r["StartLine"], end_line=r["EndLine"]),
                             message=r.get("Description", "secret"), snippet=mask_secrets(r.get("Match", ""))))
    return out
