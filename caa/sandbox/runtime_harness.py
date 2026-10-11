"""Runtime harness: runs INSIDE the sandbox. Starts the application under review, waits until it
answers, runs harmless localhost-only probes, stops it and prints one JSON result line.

Standalone on purpose (stdlib only). Probes never leave 127.0.0.1: the target URL is built here
from a fixed loopback host and the port of the process we started ourselves.

Probes (all GET, no state change):
  boot       did the app start and answer on its port (and how long it took)
  headers    security headers on the root page (CSP, X-Content-Type-Options, X-Frame-Options)
  reflect    an HTML marker sent in a parameter comes back unescaped (confirms CWE-79 at runtime)
  errors     a quote-heavy marker triggers a stack trace / debug page / SQL error in the response (CWE-209),
             or a 5xx while a benign value of the same parameter is answered normally (differential)

Optional install step (egress mode): pip install -r requirements.txt into a venv inside the temp
copy, or npm ci / npm install, so the app runs with its real dependencies.
"""
import json
import os
import re
import subprocess
import sys
import time
import urllib.error
import urllib.parse
import urllib.request

LOOPBACK = "127.0.0.1"
XSS_MARK = "<caa-rt79>"
ERR_MARK = "caa'\"`)(;--"
ERROR_SIGNATURES = [
    ("python-traceback", r"Traceback \(most recent call last\)"),
    ("werkzeug-debugger", r"Werkzeug Debugger|The debugger caught an exception"),
    ("django-debug", r"You're seeing this error because you have <code>DEBUG = True</code>"),
    ("java-stacktrace", r"\bat [a-z]+(\.[A-Za-z0-9_$]+)+\([A-Za-z0-9_]+\.java:\d+\)"),
    ("go-panic", r"goroutine \d+ \[running\]|panic: "),
    ("node-stack", r"at [A-Za-z0-9_.<>]+ \(/[^)]+\.js:\d+:\d+\)"),
    ("sql-error", r"(sqlite3\.OperationalError|SQLSTATE\[|syntax error at or near|You have an error in your SQL "
                  r"syntax|unrecognized token|ORA-\d{5})"),
]
SEC_HEADERS = ["content-security-policy", "x-content-type-options", "x-frame-options"]


def _http(port, path, params=None, timeout=5):
    if "{CAA}" in path:                      # marker goes into a path parameter
        value = next(iter(params.values())) if params else "caa1"
        path, params = path.replace("{CAA}", urllib.parse.quote(value, safe="")), None
    url = f"http://{LOOPBACK}:{int(port)}{path}"
    if params:
        url += ("&" if "?" in url else "?") + urllib.parse.urlencode(params)
    assert urllib.parse.urlparse(url).hostname == LOOPBACK, "runtime probes are loopback-only"
    req = urllib.request.Request(url, method="GET", headers={"User-Agent": "caa-runtime-check"})
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))      # never via a proxy
    try:
        with opener.open(req, timeout=timeout) as r:
            return r.status, dict(r.headers), r.read(200_000).decode("utf-8", "replace")
    except urllib.error.HTTPError as e:
        return e.code, dict(e.headers), e.read(200_000).decode("utf-8", "replace")


def loopback_up():
    """In a fresh network namespace even `lo` is down. Bring it up (loopback only - nothing external)."""
    import fcntl
    import socket
    import struct
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        ifr = struct.pack("16sh", b"lo", 0)
        flags = struct.unpack("16sh", fcntl.ioctl(s, 0x8913, ifr))[1]          # SIOCGIFFLAGS
        if not flags & 0x1:
            fcntl.ioctl(s, 0x8914, struct.pack("16sh", b"lo", flags | 0x1))   # SIOCSIFFLAGS |= IFF_UP
        s.close()
        return True
    except OSError:
        return False


def install(spec, log):
    if not spec.get("install"):
        return
    cwd = spec.get("cwd") or "."
    if os.path.exists(os.path.join(cwd, "requirements.txt")):
        subprocess.run([sys.executable, "-m", "venv", ".caa-venv"], cwd=cwd, capture_output=True, timeout=120)
        r = subprocess.run([".caa-venv/bin/pip", "install", "-q", "-r", "requirements.txt"], cwd=cwd,
                           capture_output=True, text=True, timeout=600)
        log.append({"install": "pip", "rc": r.returncode, "tail": r.stderr[-300:]})
        spec["cmd"] = [os.path.abspath(os.path.join(cwd, ".caa-venv/bin/python")) if c in ("python", "python3")
                       else c for c in spec["cmd"]]
    elif os.path.exists(os.path.join(cwd, "package.json")):
        lock = os.path.exists(os.path.join(cwd, "package-lock.json"))
        r = subprocess.run(["npm", "ci" if lock else "install", "--no-audit", "--no-fund", "--ignore-scripts"],
                           cwd=cwd, capture_output=True, text=True, timeout=600)
        log.append({"install": "npm", "rc": r.returncode, "tail": r.stderr[-300:]})


def main():
    spec = json.load(open(sys.argv[1]))
    port = int(spec["port"])
    out = {"started": False, "probes": [], "log": [], "loopback_up": loopback_up()}
    install(spec, out["log"])
    # "python" in a launch plan means the interpreter this harness runs on (the one with the
    # agent's dependencies); the sandbox PATH is scrubbed and may hold another python or none at all
    spec["cmd"] = [sys.executable if c in ("python", "python3") else c for c in spec["cmd"]]
    env = dict(os.environ, PORT=str(port), HOST=LOOPBACK, **(spec.get("env") or {}))
    try:
        proc = subprocess.Popen(spec["cmd"], cwd=spec.get("cwd") or ".", env=env, stdout=subprocess.PIPE,
                                stderr=subprocess.STDOUT, text=True)
    except OSError as exc:                     # e.g. the runtime (node, go) is not installed in the sandbox
        out["reason"] = f"cannot start {spec['cmd'][0]!r}: {exc}"
        sys.stdout.write("CAA_RESULT " + json.dumps(out) + "\n")
        return
    t0 = time.time()
    try:
        while time.time() - t0 < spec.get("boot_timeout", 40):
            if proc.poll() is not None:
                break
            try:
                status, headers, body = _http(port, spec.get("health", "/"), timeout=2)
                out.update(started=True, boot_seconds=round(time.time() - t0, 1), health_status=status,
                           health_body=body[:300])
                break
            except (urllib.error.URLError, ConnectionError, OSError):
                time.sleep(0.5)
        if out["started"]:
            low = {k.lower(): v for k, v in headers.items()}
            missing = [h for h in SEC_HEADERS if h not in low]
            out["probes"].append({"kind": "headers", "path": spec.get("health", "/"), "missing": missing})
            for p in spec.get("probes", []):
                res = {"kind": p["kind"], "path": p["path"], "param": p.get("param")}
                try:
                    if p["kind"] == "reflect":
                        st, _, body = _http(port, p["path"], {p["param"]: XSS_MARK})
                        res.update(status=st, raw_reflected=XSS_MARK in body,
                                   escaped="&lt;caa-rt79&gt;" in body)
                    elif p["kind"] == "errors":
                        base_st, _, _ = _http(port, p["path"], {p["param"]: "caa1"})
                        st, _, body = _http(port, p["path"], {p["param"]: ERR_MARK})
                        hits = [n for n, rx in ERROR_SIGNATURES if re.search(rx, body)]
                        # differential: a benign value works, only the quote-heavy one breaks the server
                        res.update(status=st, baseline_status=base_st, signatures=hits,
                                   quote_breaks_server=base_st < 500 <= st)
                except (urllib.error.URLError, OSError) as exc:
                    res["error"] = f"{type(exc).__name__}: {exc}"[:200]
                out["probes"].append(res)
    finally:
        proc.terminate()
        try:
            tail = proc.communicate(timeout=5)[0] or ""
        except subprocess.TimeoutExpired:
            proc.kill()
            tail = ""
        out["exit_code"] = proc.returncode
        out["output_tail"] = tail[-1500:]
    sys.stdout.write("CAA_RESULT " + json.dumps(out) + "\n")


if __name__ == "__main__":
    main()
