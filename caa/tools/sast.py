"""run_sast: Opengrep/Semgrep + Bandit (+ optional CodeQL SARIF), normalised to SARIF.

Every analyzer is turned into a SARIF 2.1.0 `run`; candidates are then read
from SARIF uniformly, so adding an analyzer means adding one converter.
"""
from __future__ import annotations

import json
import shutil
import subprocess
from pathlib import Path

from caa.core.models import Candidate, Group, Location

RULES_DIR = Path(__file__).resolve().parents[2] / "configs" / "rules"

# Bandit test id -> (CWE, group). Bandit's own CWE field is used when present.
_BANDIT_GROUP = {"89": Group.DATAFLOW, "78": Group.DATAFLOW, "22": Group.DATAFLOW, "79": Group.DATAFLOW,
                 "259": Group.SECRETS_CONFIG, "798": Group.SECRETS_CONFIG, "327": Group.SECRETS_CONFIG,
                 "328": Group.SECRETS_CONFIG, "94": Group.DATAFLOW, "502": Group.DATAFLOW,
                 "489": Group.SECRETS_CONFIG, "295": Group.SECRETS_CONFIG}
# Normalise near-duplicate CWEs so (file, line, CWE) dedup merges analyzers.
CWE_ALIASES = {"CWE-259": "CWE-798", "CWE-328": "CWE-327", "CWE-94": "CWE-489"}


def available_analyzers() -> dict[str, str | None]:
    return {
        "opengrep": shutil.which("opengrep"),
        "semgrep": shutil.which("semgrep"),
        "bandit": shutil.which("bandit"),
        "codeql": shutil.which("codeql"),
    }


def run_semgrep(target: Path, ruleset: Path | None = None, timeout: int = 300) -> dict:
    exe = shutil.which("opengrep") or shutil.which("semgrep")
    if not exe:
        return _empty_run("semgrep", note="not installed")
    ruleset = ruleset or RULES_DIR
    cmd = [exe, "scan", "--config", str(ruleset), "--sarif", "--metrics=off", "--quiet",
           "--disable-version-check", "--no-git-ignore", str(target)]
    if Path(exe).name == "opengrep":
        cmd = [c for c in cmd if c not in ("--metrics=off", "--disable-version-check")]
    proc = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
    try:
        sarif = json.loads(proc.stdout)
        run = sarif["runs"][0]
    except (json.JSONDecodeError, KeyError, IndexError):
        return _empty_run("semgrep", note=f"failed: {proc.stderr[-500:]}")
    # Rule ids carry the config path prefix; keep only our stable id.
    for res in run.get("results", []):
        rid = res.get("ruleId", "")
        if "caa." in rid:
            res["ruleId"] = rid[rid.index("caa."):]
    rules = run.get("tool", {}).get("driver", {}).get("rules", [])
    for r in rules:
        rid = r.get("id", "")
        if "caa." in rid:
            r["id"] = rid[rid.index("caa."):]
    _relativise(run, target)
    return run


def run_bandit(target: Path, timeout: int = 300) -> dict:
    exe = shutil.which("bandit")
    if not exe:
        return _empty_run("bandit", note="not installed")
    proc = subprocess.run([exe, "-r", "-f", "json", "-q", str(target)], capture_output=True, text=True, timeout=timeout)
    try:
        data = json.loads(proc.stdout)
    except json.JSONDecodeError:
        return _empty_run("bandit", note=f"failed: {proc.stderr[-500:]}")
    results = []
    for r in data.get("results", []):
        cwe = r.get("issue_cwe", {}).get("id")
        try:
            path = Path(r["filename"]).resolve().relative_to(target.resolve()).as_posix()
        except ValueError:
            path = r["filename"]
        results.append({
            "ruleId": f"bandit.{r['test_id']}.{r['test_name']}",
            "level": {"HIGH": "error", "MEDIUM": "warning"}.get(r["issue_severity"], "note"),
            "message": {"text": r["issue_text"]},
            "locations": [{"physicalLocation": {
                "artifactLocation": {"uri": path},
                "region": {"startLine": r["line_number"], "endLine": r.get("line_range", [r["line_number"]])[-1],
                           "snippet": {"text": r.get("code", "")}}}}],
            "properties": {"cwe": f"CWE-{cwe}" if cwe else None, "confidence": r["issue_confidence"]},
        })
    return {"tool": {"driver": {"name": "bandit", "rules": []}}, "results": results}


def load_codeql_sarif(path: Path) -> dict:
    """CodeQL is optional and heavy; accept a SARIF it produced offline."""
    sarif = json.loads(path.read_text())
    return sarif["runs"][0]


def _empty_run(name: str, note: str) -> dict:
    return {"tool": {"driver": {"name": name, "rules": []}}, "results": [], "properties": {"note": note}}


def _relativise(run: dict, target: Path) -> None:
    root = target.resolve()
    for res in run.get("results", []):
        for loc in res.get("locations", []):
            art = loc["physicalLocation"]["artifactLocation"]
            uri = art.get("uri", "").removeprefix("file://")
            p = Path(uri)
            if p.is_absolute():
                try:
                    art["uri"] = p.resolve().relative_to(root).as_posix()
                except ValueError:
                    pass
            elif uri.startswith(str(target)):
                art["uri"] = Path(uri).relative_to(target).as_posix()


def sarif_runs_to_candidates(runs: list[dict]) -> list[Candidate]:
    out: list[Candidate] = []
    for run in runs:
        tool = run["tool"]["driver"]["name"]
        rule_meta = {r["id"]: r for r in run["tool"]["driver"].get("rules", [])}
        for res in run.get("results", []):
            loc = res["locations"][0]["physicalLocation"]
            rid = res.get("ruleId", "?")
            cwe, group = _classify(rid, res, rule_meta.get(rid, {}))
            if cwe is None:
                continue
            out.append(Candidate(
                rule_id=rid,
                source="semgrep" if tool.lower() in ("semgrep", "opengrep", "semgrep oss") else tool.lower(),
                cwe=cwe, group=group,
                location=Location(file=loc["artifactLocation"]["uri"],
                                  start_line=loc["region"]["startLine"],
                                  end_line=loc["region"].get("endLine")),
                message=res.get("message", {}).get("text", ""),
                snippet=loc["region"].get("snippet", {}).get("text", ""),
            ))
    return out


def _classify(rid: str, res: dict, rule: dict) -> tuple[str | None, Group]:
    props = res.get("properties", {}) or {}
    cwe = props.get("cwe")
    meta = (rule.get("properties") or {})
    if not cwe:
        tags = meta.get("tags", [])
        for t in tags:
            if t.upper().startswith("CWE-"):
                cwe = t.split(":")[0].upper()
                break
    if not cwe and rid.startswith("caa."):
        cwe = _CAA_RULE_CWE.get(rid)
    if not cwe:
        return None, Group.DATAFLOW
    cwe = CWE_ALIASES.get(cwe, cwe)
    num = cwe.split("-")[1]
    group = _BANDIT_GROUP.get(num, Group.DATAFLOW)
    if rid.startswith("caa."):
        group = _CAA_RULE_GROUP.get(rid, group)
    return cwe, group


def _load_caa_rule_meta() -> tuple[dict, dict]:
    cwe, grp = {}, {}
    try:
        import yaml  # optional, only to read our own rule metadata
    except ImportError:  # pragma: no cover
        return cwe, grp
    for f in RULES_DIR.glob("*.yaml"):
        for r in yaml.safe_load(f.read_text()).get("rules", []):
            md = r.get("metadata", {})
            cwe[r["id"]] = md.get("cwe")
            grp[r["id"]] = Group(md.get("group", "A"))
    return cwe, grp


_CAA_RULE_CWE, _CAA_RULE_GROUP = _load_caa_rule_meta()


def dedup(cands: list[Candidate]) -> list[Candidate]:
    """Merge candidates on (file, line, CWE); keep list of agreeing sources."""
    merged: dict[tuple, Candidate] = {}
    for c in cands:
        k = c.dedup_key()
        if k in merged:
            m = merged[k]
            srcs = m.extra.setdefault("sources", [m.source])
            if c.source not in srcs:
                srcs.append(c.source)
            m.extra.setdefault("rules", [m.rule_id]).append(c.rule_id)
        else:
            c.extra.setdefault("sources", [c.source])
            c.extra.setdefault("rules", [c.rule_id])
            merged[k] = c
    return sorted(merged.values(), key=lambda c: c.dedup_key())
