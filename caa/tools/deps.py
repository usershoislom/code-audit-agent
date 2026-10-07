"""scan_dependencies: pinned manifests vs an OFFLINE vulnerability snapshot.

Order of preference: osv-scanner in offline mode (if installed and its local
DB exists) -> bundled JSON snapshot. Nothing here touches the network.
"""
from __future__ import annotations

import json
import re
import shutil
import subprocess
from pathlib import Path

from caa.core.models import Candidate, Group, Location
from caa.tools.fs import RepoFS

SNAPSHOT = Path(__file__).resolve().parents[2] / "configs" / "offline_db" / "osv_snapshot.json"
IMPORT_NAMES = {"pyyaml": "yaml", "pillow": "PIL", "beautifulsoup4": "bs4", "scikit-learn": "sklearn"}
_REQ_RE = re.compile(r"^\s*([A-Za-z0-9_.\-]+)\s*==\s*([0-9][0-9A-Za-z.\-]*)")


def parse_version(v: str) -> tuple:
    parts = []
    for p in re.split(r"[.\-]", v):
        parts.append(int(p) if p.isdigit() else 0)
    return tuple(parts + [0] * (4 - len(parts)))


def is_vulnerable(version: str, fixed: list[str]) -> bool:
    v = parse_version(version)
    fx = sorted(parse_version(f) for f in fixed)
    if v < fx[0]:
        return True
    return any(v[:2] == f[:2] and v < f for f in fx[1:])


def parse_requirements(fs: RepoFS) -> list[tuple[str, str, str, int]]:
    out = []
    for rel in fs.iter_files("*requirements*.txt"):
        for i, line in enumerate(fs.read_lines(rel), 1):
            m = _REQ_RE.match(line)
            if m:
                out.append((m.group(1).lower(), m.group(2), rel, i))
    return out


def scan_dependencies(fs: RepoFS, snapshot: Path = SNAPSHOT) -> list[Candidate]:
    if shutil.which("osv-scanner"):
        res = _osv_scanner(fs)
        if res is not None:
            return res
    db = json.loads(snapshot.read_text())
    by_pkg: dict[str, list[dict]] = {}
    for v in db["vulns"]:
        by_pkg.setdefault(v["package"], []).append(v)
    out = []
    for pkg, ver, rel, line in parse_requirements(fs):
        for vuln in by_pkg.get(pkg, []):
            if is_vulnerable(ver, vuln["fixed"]):
                out.append(Candidate(
                    rule_id=f"deps.{vuln['id']}", source="deps-snapshot", cwe="CWE-1395",
                    group=Group.DEPENDENCIES, location=Location(file=rel, start_line=line, end_line=line),
                    message=f"{pkg}=={ver} affected by {vuln['id']}: {vuln['summary']}",
                    snippet=f"{pkg}=={ver}",
                    extra={"package": pkg, "version": ver, "vuln_id": vuln["id"], "fixed": vuln["fixed"],
                           "import_name": IMPORT_NAMES.get(pkg, pkg.replace("-", "_")),
                           "db": f"snapshot {db['snapshot_date']}"}))
    return out


def _osv_scanner(fs: RepoFS) -> list[Candidate] | None:
    proc = subprocess.run(["osv-scanner", "scan", "--offline", "--format", "json", "-r", str(fs.root)],
                          capture_output=True, text=True, timeout=600)
    try:
        data = json.loads(proc.stdout)
    except json.JSONDecodeError:
        return None
    out = []
    for res in data.get("results", []):
        rel = Path(res["source"]["path"]).resolve().relative_to(fs.root).as_posix()
        for pkg in res.get("packages", []):
            name, ver = pkg["package"]["name"].lower(), pkg["package"]["version"]
            line = next((ln for p, v, r, ln in parse_requirements(fs) if p == name and r == rel), 1)
            for vuln in pkg.get("vulnerabilities", []):
                out.append(Candidate(rule_id=f"deps.{vuln['id']}", source="osv-scanner", cwe="CWE-1395",
                                     group=Group.DEPENDENCIES, location=Location(file=rel, start_line=line),
                                     message=f"{name}=={ver}: {vuln.get('summary', vuln['id'])}",
                                     extra={"package": name, "version": ver, "vuln_id": vuln["id"],
                                            "import_name": IMPORT_NAMES.get(name, name.replace("-", "_")),
                                            "db": "osv-scanner offline"}))
    return out
