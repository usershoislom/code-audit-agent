"""Find out how to start the application(s) in a repository and which runtime probes to send.

Launch plans, in order of preference:
  1. `.caa.yaml` in the target root:  run: {cmd: [...], cwd: ".", port: 8000, health: "/", install: true}
  2. auto-detected per framework:
       Flask    python -m flask --app <module> run      (module that creates Flask(...))
       FastAPI  python -m uvicorn <module>:app          (module that creates FastAPI(...))
       Django   python manage.py runserver --noreload   (directory with manage.py)
       Node     npm start                               (package.json with a start script)
       Go       go run .                                (module whose main calls ListenAndServe)
Probes come from the route map and from data-flow findings: a reflect probe for XSS candidates,
an error probe for injection candidates. Everything is sent to 127.0.0.1 inside the sandbox.
"""
from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from pathlib import Path

import yaml

from caa.tools.fs import RepoFS

ROUTE_PARAM = re.compile(r"<(?:[^:<>]+:)?([^<>]+)>|\{([A-Za-z_]\w*)(?::[^}]*)?\}")


@dataclass
class LaunchPlan:
    name: str
    cmd: list[str]
    cwd: str
    port: int
    framework: str
    health: str = "/"
    install: bool = False
    env: dict = field(default_factory=dict)
    file: str | None = None            # module the plan starts (to attach probes to its routes)
    probes: list[dict] = field(default_factory=list)

    def spec(self) -> dict:
        return {"cmd": self.cmd, "cwd": self.cwd, "port": self.port, "health": self.health,
                "install": self.install, "env": self.env, "probes": self.probes, "boot_timeout": 40}


def detect_plans(fs: RepoFS, install: bool = False, limit: int = 12) -> list[LaunchPlan]:
    cfg = fs.root / ".caa.yaml"
    if cfg.exists():
        run = (yaml.safe_load(cfg.read_text()) or {}).get("run")
        if run:
            return [LaunchPlan("configured", list(run["cmd"]), run.get("cwd", "."), int(run.get("port", 8000)),
                               "custom", run.get("health", "/"), bool(run.get("install", install)),
                               run.get("env") or {})]
    plans: list[LaunchPlan] = []
    port = 18080
    for rel in fs.iter_files("*.py"):
        text = fs.resolve(rel).read_text(errors="replace")
        d, stem = Path(rel).parent.as_posix() or ".", Path(rel).stem
        if re.search(r"^\s*app\s*=\s*Flask\(", text, re.M):
            plans.append(LaunchPlan(f"flask:{rel}", ["python", "-m", "flask", "--app", stem, "run", "--host",
                                                     "127.0.0.1", "--port", str(port)], d, port, "flask",
                                    install=install, file=rel))
        elif re.search(r"^\s*app\s*=\s*FastAPI\(", text, re.M):
            plans.append(LaunchPlan(f"fastapi:{rel}", ["python", "-m", "uvicorn", f"{stem}:app", "--host",
                                                       "127.0.0.1", "--port", str(port)], d, port, "fastapi",
                                    install=install, file=rel))
        elif Path(rel).name == "manage.py":
            plans.append(LaunchPlan(f"django:{rel}", ["python", "manage.py", "runserver", f"127.0.0.1:{port}",
                                                      "--noreload"], d, port, "django", install=install, file=rel))
        else:
            continue
        port += 1
    for rel in fs.iter_files("package.json"):
        if "node_modules" in rel:
            continue
        try:
            pkg = json.loads(fs.resolve(rel).read_text())
        except json.JSONDecodeError:
            continue
        if (pkg.get("scripts") or {}).get("start"):
            plans.append(LaunchPlan(f"node:{rel}", ["npm", "start"], Path(rel).parent.as_posix() or ".", port,
                                    "node", install=True, file=rel))
            port += 1
    for rel in fs.iter_files("go.mod"):
        d = Path(rel).parent
        main_src = "\n".join(fs.resolve(f).read_text(errors="replace") for f in fs.iter_files("*.go")
                             if Path(f).parent == d)
        m = re.search(r"ListenAndServe\(\s*\"[^\"]*:(\d+)\"", main_src)
        if "package main" in main_src and m:
            plans.append(LaunchPlan(f"go:{rel}", ["go", "run", "."], d.as_posix() or ".", int(m.group(1)), "go",
                                    file=rel))
    return plans[:limit]


def attach_probes(plan: LaunchPlan, routes, findings) -> None:
    """GET probes for this app's routes that have XSS / injection candidates."""
    if plan.file is None:
        return
    app_dir = Path(plan.file).parent.as_posix()
    for r in routes:
        if r.file != plan.file and not (plan.framework in ("node", "go") and r.file.startswith(app_dir)):
            continue
        if "GET" not in r.methods:
            continue
        for f in findings:
            if f.location.file != r.file or not (r.line <= f.location.start_line <= r.end_line) or not f.dataflow:
                continue
            param = _query_param(f.dataflow[0].code + " " + (f.dataflow[0].ref.note or ""))
            if param is None:
                continue
            kind = "reflect" if f.cwe == "CWE-79" else ("errors" if f.cwe in ("CWE-89", "CWE-78", "CWE-22") else None)
            if kind:
                # path parameters carry the marker in the URL path, others in the query string
                path = ROUTE_PARAM.sub(lambda m: "{CAA}" if (m.group(1) or m.group(2)) == param else "caa1",
                                       r.path or "/")
                plan.probes.append({"kind": kind, "path": path, "param": param, "finding": f.id})


_PARAM_RX = [re.compile(r"(?:args|GET|query_params|values)\.get\(\s*['\"]([^'\"]+)['\"]"),
             re.compile(r"(?:args|GET|query_params|values)\[\s*['\"]([^'\"]+)['\"]"),
             re.compile(r"route parameter <(\w+)>")]


def _query_param(text: str) -> str | None:
    for rx in _PARAM_RX:
        m = rx.search(text)
        if m:
            return m.group(1)
    return None
