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

# CWE -> evidence group (how the finding is searched for and confirmed).
CWE_GROUP = {
    **{c: Group.DATAFLOW for c in ("89", "78", "77", "22", "23", "79", "918", "94", "95", "502", "601", "611",
                                   "1336", "643", "90", "113", "117", "400")},
    **{c: Group.ACCESS_CONTROL for c in ("639", "862", "863", "285", "306")},
    **{c: Group.SECRETS_CONFIG for c in ("259", "798", "321", "327", "328", "326", "338", "295", "489", "942",
                                         "693", "540", "538", "250", "1188", "614", "1004", "352", "829",
                                         "1357", "209", "215")},
    **{c: Group.DEPENDENCIES for c in ("1395", "1104", "937", "1035")},
}
# Normalise near-duplicate CWEs so (file, line, CWE) dedup merges analyzers.
CWE_ALIASES = {"CWE-259": "CWE-798", "CWE-321": "CWE-798", "CWE-328": "CWE-327", "CWE-77": "CWE-78",
               "CWE-23": "CWE-22", "CWE-95": "CWE-94", "CWE-1104": "CWE-1395", "CWE-937": "CWE-1395"}
# Rule-specific overrides (tool rule id prefix -> CWE)
RULE_CWE = {
    "bandit.B201": "CWE-489",                       # flask debug=True (bandit tags it CWE-94)
    # gosec: https://github.com/securego/gosec#available-rules
    "G101": "CWE-798", "G102": "CWE-1188", "G104": None, "G106": "CWE-322", "G107": "CWE-918",
    "G108": "CWE-200", "G109": "CWE-190", "G110": "CWE-400", "G111": "CWE-22", "G112": "CWE-400",
    "G114": "CWE-400", "G115": None, "G201": "CWE-89", "G202": "CWE-89", "G203": "CWE-79", "G204": "CWE-78",
    "G301": None, "G302": None, "G303": "CWE-377", "G304": "CWE-22", "G305": "CWE-22", "G306": None,
    "G307": None, "G401": "CWE-327", "G402": "CWE-295", "G403": "CWE-326", "G404": "CWE-338",
    "G405": "CWE-327", "G406": "CWE-327", "G501": "CWE-327", "G502": "CWE-327", "G503": "CWE-327",
    "G504": "CWE-327", "G505": "CWE-327", "G506": "CWE-327", "G507": "CWE-327", "G601": None, "G602": None,
}


def available_analyzers() -> dict[str, str | None]:
    return {
        "opengrep": shutil.which("opengrep"),
        "semgrep": shutil.which("semgrep"),
        "bandit": shutil.which("bandit"),
        "codeql": shutil.which("codeql"),
    }


def run_semgrep(target: Path, ruleset: Path | list[Path] | None = None, timeout: int = 600) -> dict:
    exe = shutil.which("opengrep") or shutil.which("semgrep")
    if not exe:
        return _empty_run("semgrep", note="not installed")
    configs = ruleset if isinstance(ruleset, list) else [ruleset or RULES_DIR]
    cmd = [exe, "scan"]
    for c in configs:
        cmd += ["--config", str(c)]
    cmd += ["--sarif", "--dataflow-traces", "--metrics=off", "--quiet", "--disable-version-check",
            "--no-git-ignore", str(target)]
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
    root = target.resolve() if target.is_dir() else target.resolve().parent
    for res in run.get("results", []):
        locs = list(res.get("locations", []))
        for cf in res.get("codeFlows", []):
            for tf in cf.get("threadFlows", []):
                locs += [x["location"] for x in tf.get("locations", []) if "location" in x]
        for loc in locs:
            if "physicalLocation" not in loc:
                continue
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
            cwe, group = _classify(rid, res, rule_meta.get(rid, {}), tool)
            if cwe is None:
                continue
            flow = []
            for cf in res.get("codeFlows", [])[:1]:
                for tf in cf.get("threadFlows", [])[:1]:
                    for x in tf.get("locations", []):
                        pl = x.get("location", {}).get("physicalLocation")
                        if pl:
                            flow.append([pl["artifactLocation"]["uri"], pl["region"]["startLine"]])
            out.append(Candidate(
                rule_id=rid,
                source=_source_name(tool),
                cwe=cwe, group=group,
                location=Location(file=loc["artifactLocation"]["uri"],
                                  start_line=loc["region"]["startLine"],
                                  end_line=loc["region"].get("endLine")),
                message=res.get("message", {}).get("text", ""),
                snippet=loc["region"].get("snippet", {}).get("text", ""),
                extra={"codeflow": flow} if flow else {},
            ))
    return out


def _source_name(tool: str) -> str:
    t = tool.lower()
    if "semgrep" in t or "opengrep" in t:
        return "semgrep"
    return t.split()[0]


def _classify(rid: str, res: dict, rule: dict, tool: str = "") -> tuple[str | None, Group]:
    props = res.get("properties", {}) or {}
    cwe = props.get("cwe")
    meta = (rule.get("properties") or {})
    for prefix, forced in RULE_CWE.items():
        if rid == prefix or rid.startswith(prefix + "."):
            if forced is None:
                return None, Group.DATAFLOW      # not a security finding for our purposes
            cwe = forced
    if "gitleaks" in tool.lower():
        cwe = "CWE-798"
    if not cwe:
        tags = meta.get("tags", [])
        for t in tags:
            if t.upper().startswith("CWE-"):
                cwe = t.split(":")[0].split()[0].upper()
                break
    if not cwe and rid.startswith("caa."):
        cwe = _CAA_RULE_CWE.get(rid)
    if not cwe:
        return None, Group.DATAFLOW
    cwe = CWE_ALIASES.get(cwe, cwe)
    num = cwe.split("-")[1]
    group = CWE_GROUP.get(num, Group.DATAFLOW)
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
