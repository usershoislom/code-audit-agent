"""Project profile: which languages, frameworks and kinds of program are in the repository.

The profile decides which analyzers run (caa/tools/analyzers.py) and which
entry points the verification stage looks for. Detection is by file
extension, manifests and import/annotation patterns - no code is executed.
"""
from __future__ import annotations

import json
import re
from collections import Counter
from dataclasses import asdict, dataclass, field
from pathlib import Path

from caa.tools.fs import RepoFS

EXTENSIONS = {
    ".py": "python",
    ".js": "javascript", ".mjs": "javascript", ".cjs": "javascript", ".jsx": "javascript",
    ".ts": "typescript", ".tsx": "typescript",
    ".java": "java",
    ".go": "go",
    ".html": "html", ".htm": "html", ".jinja": "html", ".jinja2": "html", ".j2": "html", ".ejs": "html",
}
MANIFESTS = {
    "requirements.txt": "python", "pyproject.toml": "python", "setup.py": "python", "Pipfile": "python",
    "package.json": "javascript", "package-lock.json": "javascript", "yarn.lock": "javascript",
    "pnpm-lock.yaml": "javascript", "pom.xml": "java", "build.gradle": "java", "build.gradle.kts": "java",
    "go.mod": "go",
}
# (language, framework, regex over source text)
FRAMEWORKS = [
    ("python", "flask", r"^\s*(?:from flask\b|import flask\b)"),
    ("python", "django", r"^\s*(?:from django\b|import django\b)"),
    ("python", "fastapi", r"^\s*(?:from fastapi\b|import fastapi\b)"),
    ("python", "click", r"^\s*(?:import click\b|from click\b)"),
    ("python", "typer", r"^\s*(?:import typer\b|from typer\b)"),
    ("python", "argparse", r"^\s*import argparse\b|ArgumentParser\("),
    ("javascript", "express", r"require\(['\"]express['\"]\)|from ['\"]express['\"]"),
    ("javascript", "koa", r"require\(['\"]koa['\"]\)|from ['\"]koa['\"]"),
    ("javascript", "nextjs", r"from ['\"]next(?:/[^'\"]*)?['\"]"),
    ("javascript", "react", r"from ['\"]react['\"]"),
    ("java", "spring", r"import org\.springframework\."),
    ("java", "servlet", r"import (?:javax|jakarta)\.servlet\."),
    ("go", "net/http", r"\"net/http\""),
    ("go", "gin", r"\"github\.com/gin-gonic/gin\""),
    ("go", "echo", r"\"github\.com/labstack/echo"),
]
WEB = {"flask", "django", "fastapi", "express", "koa", "nextjs", "spring", "servlet", "net/http", "gin", "echo"}
CLI = {"click", "typer", "argparse"}
SKIP_PARTS = {"node_modules", "vendor", "dist", "build", "target", ".venv", "venv", "site-packages"}


@dataclass
class LanguageInfo:
    files: int = 0
    loc: int = 0
    frameworks: list[str] = field(default_factory=list)
    manifests: list[str] = field(default_factory=list)


@dataclass
class Profile:
    languages: dict[str, LanguageInfo] = field(default_factory=dict)
    kinds: list[str] = field(default_factory=list)       # web | cli | library
    manifests: list[str] = field(default_factory=list)
    files_by_language: dict[str, list[str]] = field(default_factory=dict)

    @property
    def frameworks(self) -> set[str]:
        return {f for li in self.languages.values() for f in li.frameworks}

    def has(self, lang: str) -> bool:
        return lang in self.languages

    def to_dict(self) -> dict:
        d = asdict(self)
        d.pop("files_by_language")
        return d


def detect(fs: RepoFS) -> Profile:
    prof = Profile()
    hits: dict[str, Counter] = {}
    for rel in fs.iter_files("*"):
        parts = set(Path(rel).parts)
        if parts & SKIP_PARTS:
            continue
        name = Path(rel).name
        if name in MANIFESTS:
            lang = MANIFESTS[name]
            prof.manifests.append(rel)
            prof.languages.setdefault(lang, LanguageInfo()).manifests.append(rel)
        lang = EXTENSIONS.get(Path(rel).suffix.lower())
        if lang is None:
            continue
        try:
            text = fs.resolve(rel).read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        li = prof.languages.setdefault(lang, LanguageInfo())
        li.files += 1
        li.loc += text.count("\n") + 1
        prof.files_by_language.setdefault(lang, []).append(rel)
        for flang, fw, rx in FRAMEWORKS:
            # TypeScript shares the JavaScript framework patterns
            if flang == lang or (flang == "javascript" and lang == "typescript"):
                if re.search(rx, text, re.M):
                    hits.setdefault(lang, Counter())[fw] += 1
    # package.json dependencies are a stronger framework signal than imports
    for rel in prof.manifests:
        if rel.endswith("package.json"):
            try:
                deps = json.loads(fs.resolve(rel).read_text())
            except (OSError, json.JSONDecodeError):
                continue
            names = set((deps.get("dependencies") or {}) | (deps.get("devDependencies") or {}))
            for fw, pkg in (("express", "express"), ("koa", "koa"), ("nextjs", "next"), ("react", "react")):
                if pkg in names:
                    hits.setdefault("javascript", Counter())[fw] += 1
    for lang, c in hits.items():
        if lang in prof.languages:
            prof.languages[lang].frameworks = sorted(c)
    fws = prof.frameworks
    if fws & WEB:
        prof.kinds.append("web")
    if fws & CLI or _has_main(fs, prof):
        prof.kinds.append("cli")
    if not prof.kinds:
        prof.kinds.append("library")
    return prof


def _has_main(fs: RepoFS, prof: Profile) -> bool:
    for rel in prof.files_by_language.get("python", []):
        if re.search(r"^if __name__ == ['\"]__main__['\"]", fs.resolve(rel).read_text(errors="replace"), re.M):
            text = fs.resolve(rel).read_text(errors="replace")
            if "sys.argv" in text or "input(" in text:
                return True
    for rel in prof.files_by_language.get("go", []):
        if re.search(r"^package main\b", fs.resolve(rel).read_text(errors="replace"), re.M) and \
                "os.Args" in fs.resolve(rel).read_text(errors="replace"):
            return True
    return False
