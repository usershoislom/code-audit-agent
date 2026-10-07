"""Matching findings to ground truth and computing the evaluation table."""
from __future__ import annotations

import ast
from collections import defaultdict
from pathlib import Path

import yaml

# CWEs that describe the same flaw for matching purposes.
EQUIV = [{"CWE-639", "CWE-862", "CWE-285", "CWE-863", "CWE-306"}, {"CWE-798", "CWE-259", "CWE-321"},
         {"CWE-327", "CWE-328", "CWE-916"}, {"CWE-1395", "CWE-1104", "CWE-937"}]
EXCLUDED = {"CWE-1427"}   # agent-safety items are reported separately


def same_class(a: str, b: str) -> bool:
    return a == b or any(a in s and b in s for s in EQUIV)


def load_labels(path: Path, repo: Path) -> list[dict]:
    data = yaml.safe_load(path.read_text())
    labels = []
    for lab in data["vulnerable"]:
        src = (repo / lab["file"]).read_text()
        if "function" in lab:
            tree = ast.parse(src)
            fn = next(n for n in ast.walk(tree) if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef))
                      and n.name == lab["function"])
            lo, hi = fn.lineno - len(fn.decorator_list), fn.end_lineno
        else:
            ln = next(i for i, t in enumerate(src.splitlines(), 1) if lab["anchor"] in t)
            lo = hi = ln
        labels.append({**lab, "lo": lo, "hi": hi})
    return labels


def match(findings: list[dict], labels: list[dict]):
    """findings: dicts with file, line, cwe, level, status. Returns (tp_labels, fp_findings, matched pairs)."""
    hit = set()
    fps = []
    tps = []
    for f in findings:
        if f["cwe"] in EXCLUDED:
            continue
        m = next((i for i, lab in enumerate(labels) if lab["file"] == f["file"]
                  and any(same_class(c, f["cwe"]) for c in [lab["cwe"], *lab.get("cwe_alt", [])])
                  and lab["lo"] <= f["line"] <= lab["hi"]), None)
        if m is None:
            fps.append(f)
        else:
            tps.append((f, labels[m]))
            hit.add(m)
    return hit, fps, tps


def prf(tp: int, fp: int, fn: int) -> dict:
    p = tp / (tp + fp) if tp + fp else 0.0
    r = tp / (tp + fn) if tp + fn else 0.0
    f1 = 2 * p * r / (p + r) if p + r else 0.0
    return {"tp": tp, "fp": fp, "fn": fn, "precision": round(p, 3), "recall": round(r, 3), "f1": round(f1, 3)}


def evaluate(findings: list[dict], labels: list[dict], all_files: list[str]) -> dict:
    hit, fps, tps = match(findings, labels)
    # duplicates on the same label count once as TP and are not FPs
    out = {"overall": prf(len(hit), len(fps), len(labels) - len(hit))}
    per = defaultdict(lambda: [set(), 0, 0])
    for i, lab in enumerate(labels):
        per[lab["cwe"]][2] += 1
        if i in hit:
            per[lab["cwe"]][0].add(i)
    for f in fps:
        key = next((lab["cwe"] for lab in labels if same_class(lab["cwe"], f["cwe"])), f["cwe"])
        per[key][1] += 1
    out["per_cwe"] = {k: prf(len(v[0]), v[1], v[2] - len(v[0])) for k, v in sorted(per.items())}
    per_group = defaultdict(lambda: [0, 0])
    for i, lab in enumerate(labels):
        per_group[lab["group"]][1] += 1
        per_group[lab["group"]][0] += i in hit
    out["recall_per_group"] = {g: f"{a}/{b}" for g, (a, b) in sorted(per_group.items())}
    # FPR on clean files: files with no label at all
    labelled = {lab["file"] for lab in labels}
    clean = [f for f in all_files if f not in labelled]
    flagged = {f["file"] for f in fps if f["file"] in clean}
    out["clean_files"] = len(clean)
    out["clean_files_flagged"] = len(flagged)
    out["fpr_clean_files"] = round(len(flagged) / len(clean), 3) if clean else 0.0
    # pairwise: vulnerable file found AND its *_fixed twin silent
    pairs = []
    for lab_file in sorted(labelled):
        twin = lab_file.replace(".py", "_fixed.py")
        if twin in all_files:
            found = any(labels[i]["file"] == lab_file for i in hit)
            twin_clean = twin not in {f["file"] for f in fps}
            pairs.append(found and twin_clean)
    out["pairs"] = len(pairs)
    out["pair_accuracy"] = round(sum(pairs) / len(pairs), 3) if pairs else 0.0
    # calibration: precision by evidence level
    by_level = defaultdict(lambda: [0, 0])
    tp_ids = {id(f) for f, _ in tps}
    for f in findings:
        if f["cwe"] in EXCLUDED:
            continue
        by_level[f["level"]][0 if id(f) in tp_ids else 1] += 1
    out["calibration"] = {f"L{lv}": {"tp": a, "fp": b, "precision": round(a / (a + b), 3) if a + b else None}
                          for lv, (a, b) in sorted(by_level.items())}
    out["false_positives"] = [f"{f['file']}:{f['line']} {f['cwe']} L{f['level']}" for f in fps]
    out["missed"] = [f"{labels[i]['file']} {labels[i]['cwe']} ({labels[i].get('function') or labels[i].get('anchor')})"
                     for i in range(len(labels)) if i not in hit]
    return out
