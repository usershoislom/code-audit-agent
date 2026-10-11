"""Analyzer plugins chosen by the project profile (caa/langs.py).

Each plugin declares the languages it serves and whether its tool is
installed; the engine runs every applicable, available plugin and records
the ones it skipped (and why) in the inventory. Tool output is SARIF where the
tool can produce it; everything ends up as `Candidate`s.

  plugin        languages                         tool
  semgrep       python js ts java go html         Semgrep/Opengrep + our rules (configs/rules/<lang>.yaml)
  bandit        python                            Bandit
  gosec         go                                gosec
  govulncheck   go (dependencies, reachability)   govulncheck
  osv           all manifests                     osv-scanner (offline DB) / bundled snapshot
  secrets       all                               gitleaks / built-in regexes
  hygiene       all                               built-in repository checks (caa/tools/hygiene.py)
"""
from __future__ import annotations

import json
import os
import shutil
import subprocess
import tempfile
from dataclasses import dataclass, field
from pathlib import Path

from caa.core.audit import mask_secrets
from caa.core.models import Candidate, Group, Location
from caa.langs import Profile
from caa.tools import deps as deps_tool
from caa.tools import hygiene, sast
from caa.tools.fs import RepoFS
from caa.tools.secrets_scan import scan_secrets

RULES_DIR = sast.RULES_DIR
RULE_FILES = {"python": "python-core.yaml", "javascript": "javascript.yaml", "typescript": "javascript.yaml",
              "java": "java.yaml", "go": "go.yaml", "html": "html.yaml"}


@dataclass
class AnalyzerResult:
    name: str
    candidates: list[Candidate] = field(default_factory=list)
    sarif_runs: list[dict] = field(default_factory=list)
    status: str = "ran"          # ran | skipped | failed
    note: str = ""


class Analyzer:
    name = "base"
    languages: set[str] | None = None        # None = every project
    tool: str | None = None

    def applies(self, prof: Profile) -> bool:
        return self.languages is None or any(prof.has(lang) for lang in self.languages)

    def available(self) -> bool:
        return self.tool is None or shutil.which(self.tool) is not None

    def run(self, fs: RepoFS, prof: Profile) -> AnalyzerResult:  # pragma: no cover - interface
        raise NotImplementedError


class SemgrepAnalyzer(Analyzer):
    name, tool = "semgrep", "semgrep"
    languages = set(RULE_FILES)

    def available(self) -> bool:
        return bool(shutil.which("opengrep") or shutil.which("semgrep"))

    def run(self, fs, prof):
        files = sorted({RULES_DIR / RULE_FILES[lang] for lang in prof.languages if lang in RULE_FILES})
        files = [f for f in files if f.exists()]
        run = sast.run_semgrep(fs.root, files)
        return AnalyzerResult(self.name, sast.sarif_runs_to_candidates([run]), [run],
                              note="rules: " + ", ".join(f.name for f in files))


class BanditAnalyzer(Analyzer):
    name, tool, languages = "bandit", "bandit", {"python"}

    def run(self, fs, prof):
        run = sast.run_bandit(fs.root)
        return AnalyzerResult(self.name, sast.sarif_runs_to_candidates([run]), [run])


def _go_modules(fs: RepoFS) -> list[Path]:
    return sorted({fs.resolve(f).parent for f in fs.iter_files("go.mod")})


class GosecAnalyzer(Analyzer):
    name, tool, languages = "gosec", "gosec", {"go"}

    def run(self, fs, prof):
        cands, runs = [], []
        for mod in _go_modules(fs):
            with tempfile.TemporaryDirectory() as td:
                out = Path(td) / "gosec.sarif"
                subprocess.run(["gosec", "-quiet", "-no-fail", "-fmt", "sarif", "-out", str(out), "./..."],
                               cwd=mod, capture_output=True, text=True, timeout=600)
                if not out.exists():
                    continue
                run = json.loads(out.read_text())["runs"][0]
            sast._relativise(run, fs.root)
            _relativise_from(run, mod, fs.root)
            runs.append(run)
            cands += sast.sarif_runs_to_candidates([run])
        return AnalyzerResult(self.name, cands, runs, note=f"{len(runs)} go module(s)")


class GovulncheckAnalyzer(Analyzer):
    """Go dependencies: reports only vulnerabilities whose affected functions are actually called."""
    name, tool, languages = "govulncheck", "govulncheck", {"go"}

    def run(self, fs, prof):
        if os.environ.get("CAA_DEPS_ONLINE") != "1" and not os.environ.get("CAA_GOVULNDB"):
            return AnalyzerResult(self.name, status="skipped",
                                  note="needs vuln.go.dev (set CAA_DEPS_ONLINE=1) or a local DB (CAA_GOVULNDB=file://...)")
        cands = []
        for mod in _go_modules(fs):
            cmd = ["govulncheck", "-format", "json", "./..."]
            if os.environ.get("CAA_GOVULNDB"):
                cmd[1:1] = ["-db", os.environ["CAA_GOVULNDB"]]
            proc = subprocess.run(cmd, cwd=mod, capture_output=True, text=True, timeout=900)
            cands += _parse_govulncheck(proc.stdout, mod, fs)
        return AnalyzerResult(self.name, cands)


def _parse_govulncheck(stream: str, mod: Path, fs: RepoFS) -> list[Candidate]:
    dec = json.JSONDecoder()
    osvs, out, i = {}, [], 0
    stream = stream.strip()
    while i < len(stream):
        obj, j = dec.raw_decode(stream, i)
        i = j
        while i < len(stream) and stream[i].isspace():
            i += 1
        if "osv" in obj:
            osvs[obj["osv"]["id"]] = obj["osv"]
        f = obj.get("finding")
        if not f or not f.get("trace"):
            continue
        frame = f["trace"][0]
        called = bool(frame.get("function"))
        if not called:
            continue            # package imported but vulnerable symbol not reached: not a candidate
        user_frame = next((t for t in reversed(f["trace"]) if t.get("position")), None)
        if user_frame:
            path = Path(user_frame["position"]["filename"])
            rel = (path if path.is_absolute() else mod / path).resolve().relative_to(fs.root).as_posix()
            line = user_frame["position"].get("line", 1)
        else:
            rel, line = (mod / "go.mod").relative_to(fs.root).as_posix(), 1
        vid = f["osv"]
        out.append(Candidate(rule_id=f"govulncheck.{vid}", source="govulncheck", cwe="CWE-1395",
                             group=Group.DEPENDENCIES, location=Location(file=rel, start_line=line),
                             message=f"{frame.get('module')} {f.get('found_version', '')}: "
                                     f"{osvs.get(vid, {}).get('summary', vid)} (vulnerable function is called)",
                             extra={"package": frame.get("module"), "version": f.get("found_version"),
                                    "vuln_id": vid, "fixed": [f.get("fixed_version")], "reachable": True,
                                    "db": "vuln.go.dev"}))
    return _dedup_by_vuln(out)


def _dedup_by_vuln(cands: list[Candidate]) -> list[Candidate]:
    seen, out = set(), []
    for c in cands:
        k = (c.extra.get("vuln_id"), c.location.file, c.location.start_line)
        if k not in seen:
            seen.add(k)
            out.append(c)
    return out


def _relativise_from(run: dict, base: Path, root: Path) -> None:
    for res in run.get("results", []):
        for loc in res.get("locations", []):
            art = loc["physicalLocation"]["artifactLocation"]
            p = Path(art.get("uri", "").removeprefix("file://"))
            if not p.is_absolute():
                p = base / p
            try:
                art["uri"] = p.resolve().relative_to(root.resolve()).as_posix()
            except ValueError:
                pass


class OsvAnalyzer(Analyzer):
    name = "osv"
    languages = None

    def applies(self, prof):
        return bool(prof.manifests)

    def available(self):
        return True     # falls back to the bundled snapshot

    def run(self, fs, prof):
        cands = deps_tool.scan_dependencies(fs)
        how = "osv-scanner (offline DB)" if shutil.which("osv-scanner") and any(
            c.source == "osv-scanner" for c in cands) else "bundled snapshot"
        return AnalyzerResult(self.name, cands, note=how)


class SecretsAnalyzer(Analyzer):
    name, languages = "secrets", None

    def available(self):
        return True

    def run(self, fs, prof):
        cands = scan_secrets(fs)
        for c in cands:
            c.snippet = mask_secrets(c.snippet)
        return AnalyzerResult(self.name, cands, note="gitleaks" if shutil.which("gitleaks") else "built-in rules")


class HygieneAnalyzer(Analyzer):
    name, languages = "hygiene", None

    def available(self):
        return True

    def run(self, fs, prof):
        return AnalyzerResult(self.name, hygiene.check(fs, prof))


ALL = [SemgrepAnalyzer(), BanditAnalyzer(), GosecAnalyzer(), GovulncheckAnalyzer(), OsvAnalyzer(),
       SecretsAnalyzer(), HygieneAnalyzer()]


GO_ONLY = {"gosec", "govulncheck"}


def run_all(fs: RepoFS, prof: Profile, only: set[str] | None = None) -> list[AnalyzerResult]:
    results = []
    for a in ALL:
        if only is not None and a.name not in only:
            continue
        if not a.applies(prof):
            results.append(AnalyzerResult(a.name, status="skipped", note="no matching language in project"))
            continue
        if not a.available():
            hint = " (Docker: uncomment WITH_GO=1 in build.conf)" if a.name in GO_ONLY else ""
            results.append(AnalyzerResult(a.name, status="skipped", note=f"{a.tool} not installed{hint}"))
            continue
        try:
            results.append(a.run(fs, prof))
        except (subprocess.SubprocessError, OSError, json.JSONDecodeError, ValueError) as exc:
            results.append(AnalyzerResult(a.name, status="failed", note=f"{type(exc).__name__}: {exc}"[:300]))
    return results
