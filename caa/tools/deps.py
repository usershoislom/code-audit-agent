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
    """osv-scanner v2 against OFFLINE databases: whole-ecosystem DBs are downloaded, the project's
    package list is never sent anywhere. Covers PyPI, npm, Go, Maven, ... manifests and lockfiles."""
    cmd = ["osv-scanner", "scan", "source", "-r", "--format", "json", "--offline-vulnerabilities",
           "--download-offline-databases", "--data-source", "native", str(fs.root)]
    proc = subprocess.run(cmd, capture_output=True, text=True, timeout=1200)
    try:
        data = json.loads(proc.stdout)
    except json.JSONDecodeError:
        return None
    out = []
    for res in data.get("results", []):
        src = Path(res["source"]["path"])
        try:
            rel = src.resolve().relative_to(fs.root).as_posix()
        except ValueError:
            continue
        for pkg in res.get("packages", []):
            name, ver = pkg["package"]["name"], pkg["package"].get("version", "")
            vulns = pkg.get("vulnerabilities", [])
            if not vulns:
                continue
            # one finding per vulnerable package; PYSEC/GHSA/CVE ids of the same flaw are grouped
            groups = pkg.get("groups") or [{"ids": [v["id"]]} for v in vulns]
            by_id = {v["id"]: v for v in vulns}
            fixed = sorted({ev["fixed"] for v in vulns for a in v.get("affected", []) for r in a.get("ranges", [])
                            for ev in r.get("events", []) if "fixed" in ev}, key=parse_version)
            advisories = []
            for g in groups:
                ids = g.get("ids", [])
                summary = next((by_id[i].get("summary") for i in ids if by_id.get(i, {}).get("summary")), "")
                cves = sorted({a for i in ids for a in by_id.get(i, {}).get("aliases", []) if a.startswith("CVE-")})
                advisories.append({"ids": ids, "cves": cves, "summary": summary})
            line = _manifest_line(fs, rel, name)
            head = advisories[0]
            out.append(Candidate(
                rule_id=f"deps.{name}", source="osv-scanner", cwe="CWE-1395", group=Group.DEPENDENCIES,
                location=Location(file=rel, start_line=line),
                message=f"{name} {ver}: {len(advisories)} known vulnerabilit{'y' if len(advisories) == 1 else 'ies'}"
                        f" (e.g. {(head['cves'] or head['ids'])[0]}: {head['summary']})",
                snippet=f"{name} {ver}",
                extra={"package": name, "version": ver, "vuln_id": (head["cves"] or head["ids"])[0],
                       "advisories": advisories, "fixed": fixed[-3:],
                       "ecosystem": pkg["package"].get("ecosystem"),
                       "import_name": IMPORT_NAMES.get(name.lower(), name), "db": "osv-scanner offline"}))
    return out


def _manifest_line(fs: RepoFS, rel: str, name: str) -> int:
    try:
        lines = fs.read_lines(rel)
    except OSError:
        return 1
    short = name.split("/")[-1].split(":")[-1]
    for i, t in enumerate(lines, 1):
        if name in t or (short and re.search(rf"\b{re.escape(short)}\b", t)):
            return i
    return 1
