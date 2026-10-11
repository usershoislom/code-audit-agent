"""Property-check harness. Runs INSIDE the sandbox (no network, temp copy of the code).

Standalone on purpose (stdlib + the app's own deps): it must not import the
agent. It never attacks anything: every dangerous sink (DB driver, process
spawning, file open, outbound HTTP) is replaced by a recorder that stores the
call and stops the request. A harmless marker value is sent through the
handler and the recorded call is checked for a safety PROPERTY:

  CWE-89  marker must reach the driver as a bound parameter, not inside SQL text
  CWE-78  no shell command string may contain the marker
  CWE-22  resolved path for the marker must stay in the directory used for a benign name
  CWE-79  marker HTML must come back entity-encoded
  CWE-918 the server must not contact the client-chosen host

Output: one JSON object on stdout: {"status": "violated|holds|inconclusive", ...}
"""
import builtins
import importlib.util
import json
import os
import socket
import sys
from urllib.parse import urlparse

MARKERS = {
    "CWE-89": "caa'mk\"89",
    "CWE-78": "caa;mk78",
    "CWE-22": "../../caa_mk22",
    "CWE-79": "<caa-mk79>",
    "CWE-918": "http://caa-mk918.invalid/x",
}
BENIGN = {"CWE-22": "caa_benign22.txt", "CWE-918": "https://benign.invalid/x"}


class Halt(BaseException):
    """Raised by recorders; BaseException so app-level `except Exception` cannot swallow it."""


def _no_network(*a, **k):
    raise OSError("network disabled in sandbox")


socket.socket.connect = _no_network          # defence in depth on top of the namespace / --network none
socket.create_connection = _no_network


class Recorder:
    def __init__(self):
        self.calls = []

    def hit(self, kind, **data):
        self.calls.append({"kind": kind, **{k: _s(v) for k, v in data.items()}})
        raise Halt()


def _s(v):
    if isinstance(v, (list, tuple)):
        return [_s(x) for x in v]
    if isinstance(v, (str, int, float, bool)) or v is None:
        return v
    return repr(v)


def install(mod, rec, cwe):
    import subprocess
    import sqlite3

    class FakeConn:
        def execute(self, sql, params=()):
            rec.hit("sql", sql=sql, params=list(params) if params else [])

        def cursor(self):
            return self

        def executescript(self, sql):
            rec.hit("sql", sql=sql, params=[])

        def __getattr__(self, name):
            return lambda *a, **k: None

    sqlite3.connect = lambda *a, **k: FakeConn()
    for name in ("run", "call", "Popen", "check_output", "check_call"):
        setattr(subprocess, name, lambda cmd, *a, _n=name, **k: rec.hit("proc", fn=_n, cmd=cmd, shell=bool(k.get("shell"))))
    subprocess.getoutput = lambda cmd: rec.hit("proc", fn="getoutput", cmd=cmd, shell=True)
    os.system = lambda cmd: rec.hit("proc", fn="os.system", cmd=cmd, shell=True)
    os.popen = lambda cmd, *a, **k: rec.hit("proc", fn="os.popen", cmd=cmd, shell=True)

    def fake_open(path, *a, **k):
        rec.hit("open", path=os.path.normpath(os.path.join(os.getcwd(), str(path))))

    def fake_send_file(path, *a, **k):
        rec.hit("open", path=os.path.normpath(os.path.join(os.getcwd(), str(path))))

    def fake_send_from_directory(directory, path, *a, **k):
        from werkzeug.utils import safe_join
        joined = safe_join(str(directory), str(path))
        rec.hit("open", path=os.path.normpath(joined) if joined else None, contained=joined is not None,
                base=os.path.normpath(str(directory)))

    if cwe == "CWE-22":
        mod.open = fake_open
        builtins_open = builtins.open  # noqa: F841  (builtins untouched: flask itself may need it)
    for name, fn in (("send_file", fake_send_file), ("send_from_directory", fake_send_from_directory)):
        if hasattr(mod, name):
            setattr(mod, name, fn)
    try:
        import requests
        for m in ("get", "post", "put", "head", "request"):
            setattr(requests, m, lambda url=None, *a, _m=m, **k: rec.hit("http", url=url if _m != "request" else a[0] if a else k.get("url")))
        if hasattr(mod, "requests"):
            mod.requests = requests
    except ImportError:
        pass
    import urllib.request
    urllib.request.urlopen = lambda url, *a, **k: rec.hit("http", url=getattr(url, "full_url", url))


def load_module(path):
    d = os.path.dirname(os.path.abspath(path))
    sys.path.insert(0, d)
    sys.path.insert(1, os.getcwd())
    name = os.path.splitext(os.path.basename(path))[0]
    spec = importlib.util.spec_from_file_location(name, path)
    mod = importlib.util.module_from_spec(spec)
    sys.modules[name] = mod
    spec.loader.exec_module(mod)
    return mod


def find_app(mod):
    from flask import Flask
    for v in vars(mod).values():
        if isinstance(v, Flask):
            return v
    raise RuntimeError("no Flask app object in module")


def fire(app, spec, value):
    client = app.test_client()
    inj = spec["inject"]
    path = spec["path"]
    kwargs = {}
    if inj["where"] == "path":
        import re
        path = re.sub(r"<(?:[^:<>]+:)?" + re.escape(inj["name"]) + r">", value.replace("/", "%2F"), spec["rule"])
    elif inj["where"] == "args":
        kwargs["query_string"] = {inj["name"]: value}
    elif inj["where"] == "form":
        kwargs["data"] = {inj["name"]: value}
    elif inj["where"] == "json":
        kwargs["json"] = {inj["name"]: value}
    for k, v in (spec.get("extra_args") or {}).items():
        kwargs.setdefault("query_string", {})[k] = v
    try:
        resp = client.open(path, method=spec.get("method", "GET"), **kwargs)
        return {"status_code": resp.status_code, "body": resp.get_data(as_text=True)[:2000]}
    except Halt:
        return {"halted": True}
    except Exception as exc:  # the handler refused the value (e.g. PermissionError from a guard)
        return {"exception": type(exc).__name__}


def _shell_splits_marker(cmd, marker):
    """True when a POSIX shell would NOT see the marker as one literal word (metacharacters active)."""
    import shlex
    if marker not in cmd:
        return False
    try:
        lex = shlex.shlex(cmd, posix=True, punctuation_chars=True)
        lex.whitespace_split = True
        return not any(marker in tok for tok in lex)
    except ValueError:
        return True


def check(spec):
    cwe = spec["cwe"]
    marker = MARKERS[cwe]
    mod = load_module(spec["module"])
    app = find_app(mod)
    app.testing = True
    rec = Recorder()
    install(mod, rec, cwe)

    def run(value):
        rec.calls.clear()
        resp = fire(app, spec, value)
        return resp, list(rec.calls)

    if cwe == "CWE-89":
        resp, calls = run(marker)
        sql = [c for c in calls if c["kind"] == "sql"]
        if not sql:
            return {"status": "inconclusive", "reason": "no SQL reached the driver", "response": resp}
        bad = [c for c in sql if marker in (c["sql"] or "")]
        return {"status": "violated" if bad else "holds", "observations": sql}
    if cwe == "CWE-78":
        resp, calls = run(marker)
        procs = [c for c in calls if c["kind"] == "proc"]
        if not procs:
            return {"status": "inconclusive", "reason": "no process call reached", "response": resp}
        bad = [c for c in procs if isinstance(c["cmd"], str) and _shell_splits_marker(c["cmd"], marker)]
        return {"status": "violated" if bad else "holds", "observations": procs}
    if cwe == "CWE-22":
        resp0, calls0 = run(BENIGN[cwe])
        opened0 = [c for c in calls0 if c["kind"] == "open" and c.get("path")]
        if not opened0:
            return {"status": "inconclusive", "reason": "benign value did not reach a file sink", "response": resp0}
        base = os.path.dirname(opened0[0]["path"])
        observations = []
        for m in (marker, "/caa_mk22_abs"):          # relative climb and absolute-path variants
            resp1, calls1 = run(m)
            opened1 = [c for c in calls1 if c["kind"] == "open"]
            observations.append({"marker": m, "opened": opened1, "response": resp1})
            bad = [c for c in opened1 if c.get("path") and not (c["path"] + os.sep).startswith(base + os.sep)]
            bad = [c for c in bad if c.get("contained", False) is False]
            if bad:
                return {"status": "violated", "base": base, "observations": observations}
        return {"status": "holds", "base": base, "observations": observations}
    if cwe == "CWE-79":
        resp, _ = run(marker)
        body = resp.get("body", "")
        if marker in body:
            return {"status": "violated", "observations": [body[:300]]}
        if "&lt;caa-mk79&gt;" in body or "&lt;caa-mk79>" in body:
            return {"status": "holds", "observations": [body[:300]]}
        return {"status": "inconclusive", "reason": "marker not reflected", "response": resp}
    if cwe == "CWE-918":
        resp, calls = run(marker)
        http = [c for c in calls if c["kind"] == "http"]
        if not http:
            return {"status": "holds", "reason": "no outbound request for client-chosen host", "response": resp}
        bad = [c for c in http if urlparse(str(c["url"])).hostname == urlparse(marker).hostname]
        return {"status": "violated" if bad else "holds", "observations": http}
    return {"status": "inconclusive", "reason": f"no property for {cwe}"}


def main():
    spec = json.load(open(sys.argv[1]))
    try:
        out = check(spec)
    except Exception as exc:  # report, never crash silently
        out = {"status": "inconclusive", "reason": f"harness error: {type(exc).__name__}: {exc}"}
    sys.stdout.write("CAA_RESULT " + json.dumps(out, default=str) + "\n")


if __name__ == "__main__":
    main()
