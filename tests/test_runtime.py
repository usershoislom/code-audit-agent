"""App runner: start the application in the sandbox, probe it on loopback only."""
import importlib.util

import pytest

from caa.sandbox.app_runner import detect_plans
from caa.sandbox.runner import RUNTIME_HARNESS, Sandbox, SandboxConfig, SandboxUnavailable
from caa.tools.fs import RepoFS

APP = '''from flask import Flask, request
app = Flask(__name__)

@app.route("/hello")
def hello():
    return f"<h1>{request.args.get('name', '')}</h1>"
'''


def test_probes_are_loopback_only():
    spec = importlib.util.spec_from_file_location("rh", RUNTIME_HARNESS)
    rh = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(rh)
    assert rh.LOOPBACK == "127.0.0.1"
    import inspect
    assert "assert urllib.parse.urlparse(url).hostname == LOOPBACK" in inspect.getsource(rh._http)


def test_plan_detection(tmp_path):
    (tmp_path / "web.py").write_text(APP)
    (tmp_path / "api.py").write_text("from fastapi import FastAPI\napp = FastAPI()\n")
    plans = {p.framework: p for p in detect_plans(RepoFS(tmp_path))}
    assert plans["flask"].cmd[:4] == ["python", "-m", "flask", "--app"]
    assert plans["fastapi"].cmd[2] == "uvicorn"


def test_configured_plan_wins(tmp_path):
    (tmp_path / ".caa.yaml").write_text("run: {cmd: [node, server.js], port: 3000, health: /health}\n")
    (tmp_path / "web.py").write_text(APP)
    plans = detect_plans(RepoFS(tmp_path))
    assert len(plans) == 1 and plans[0].cmd == ["node", "server.js"] and plans[0].port == 3000


def test_running_app_reflection_without_network(tmp_path):
    try:
        sb = Sandbox(SandboxConfig(network="none"))
    except SandboxUnavailable as exc:
        pytest.skip(str(exc))
    (tmp_path / "web.py").write_text(APP)
    plan = detect_plans(RepoFS(tmp_path))[0]
    plan.probes = [{"kind": "reflect", "path": "/hello", "param": "name"}]
    res = sb.run_app(tmp_path, plan.spec(), timeout=60)
    assert res["started"] and res["loopback_up"]
    reflect = next(p for p in res["probes"] if p["kind"] == "reflect")
    assert reflect["raw_reflected"] is True
