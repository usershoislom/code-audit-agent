"""Engine HTTP (black box): the passive web check finds common misconfigurations and stays read-only."""
import http.server
import socketserver
import threading

import pytest

from caa.engine_http.scanner import WebScan


class _Vuln(http.server.BaseHTTPRequestHandler):
    hits: list = []

    def log_message(self, *a):
        pass

    def do_GET(self):
        type(self).hits.append(("GET", self.path))
        origin = self.headers.get("Origin")
        if self.path == "/.env":
            self.send_response(200); self.send_header("Content-Type", "text/plain"); self.end_headers()
            self.wfile.write(b"SECRET_KEY=topsecret\nDB_PASSWORD=hunter2\n"); return
        if self.path.startswith("/caa-not-here"):
            self.send_response(500); self.end_headers()
            self.wfile.write(b"<pre>Traceback (most recent call last):\n  File \"app.py\", line 10</pre>"); return
        self.send_response(200)
        self.send_header("Server", "Apache/2.4.49")
        self.send_header("Set-Cookie", "session=abc; Path=/")
        if origin:
            self.send_header("Access-Control-Allow-Origin", origin)
            self.send_header("Access-Control-Allow-Credentials", "true")
        self.end_headers(); self.wfile.write(b"<html>ok</html>")

    def do_POST(self):          # must never be called by the passive scan
        type(self).hits.append(("POST", self.path))
        self.send_response(200); self.end_headers()


@pytest.fixture()
def server():
    _Vuln.hits = []
    socketserver.TCPServer.allow_reuse_address = True
    httpd = socketserver.TCPServer(("127.0.0.1", 0), _Vuln)
    threading.Thread(target=httpd.serve_forever, daemon=True).start()
    yield httpd.server_address
    httpd.shutdown()


def test_passive_scan_finds_misconfigurations(server):
    host, port = server
    findings, inv = WebScan(f"http://{host}:{port}").run()
    cwes = {f.cwe for f in findings}
    assert {"CWE-319", "CWE-1021", "CWE-614", "CWE-942", "CWE-209", "CWE-538"} <= cwes
    assert inv["target"]["reachable"] is True
    # every check observed the live app => evidence is L4 (or L1 for the banner), never a code level
    assert all(f.level in (1, 4) for f in findings)


def test_scan_uses_no_destructive_methods(server):
    host, port = server
    WebScan(f"http://{host}:{port}").run()
    methods = {m for m, _ in _Vuln.hits}
    assert methods <= {"GET", "HEAD", "OPTIONS", "POST"}       # standard, non-destructive verbs
    assert not methods & {"PUT", "PATCH", "DELETE"}            # never PUT / PATCH / DELETE


def test_destructive_methods_are_refused_in_code(server):
    host, port = server
    scan = WebScan(f"http://{host}:{port}")
    for verb in ("DELETE", "PUT", "PATCH"):
        with pytest.raises(ValueError):
            scan._fetch("/", method=verb)


def test_scan_never_leaves_the_target_origin(server):
    host, port = server
    scan = WebScan(f"http://{host}:{port}")
    with pytest.raises(ValueError):
        scan._fetch("http://example.org/evil")       # off-origin request refused by code


def test_unreachable_target_reports_cleanly():
    findings, inv = WebScan("http://127.0.0.1:1").run()   # nothing listening
    assert inv["target"]["reachable"] is False
    assert "not reachable" in inv["analyzers"][0]["note"]


def test_rejects_non_http_url():
    with pytest.raises(ValueError):
        WebScan("ftp://example.com")


# --- browser-driven crawl (Playwright) -----------------------------------------------------
import caa.engine_http.browser as browser_mod


class _App(http.server.BaseHTTPRequestHandler):
    def log_message(self, *a):
        pass

    def do_GET(self):
        import urllib.parse as up
        p = up.urlparse(self.path)
        q = up.parse_qs(p.query)
        if p.path == "/search":
            body = f"<html><body>Results for {q.get('q', [''])[0]}<a href='/login'>login</a></body></html>"
        elif p.path == "/login":
            body = ("<html><body><form method='post' action='/login'>"
                    "<input name='user'><button>go</button></form></body></html>")
        else:
            body = "<html><body><a href='/search?q=hi'>s</a> <a href='/login'>l</a></body></html>"
        self.send_response(200); self.send_header("Content-Type", "text/html"); self.end_headers()
        self.wfile.write(body.encode())


@pytest.fixture()
def app_server():
    socketserver.TCPServer.allow_reuse_address = True
    httpd = socketserver.TCPServer(("127.0.0.1", 0), _App)
    threading.Thread(target=httpd.serve_forever, daemon=True).start()
    yield httpd.server_address
    httpd.shutdown()


@pytest.mark.skipif(not browser_mod.available(), reason="Playwright not installed")
def test_browser_crawl_finds_reflected_xss_and_csrf_form(app_server):
    host, port = app_server
    origin = f"http://{host}:{port}"
    findings, inv = browser_mod.BrowserCrawl(origin, host, origin + "/", max_pages=6).run()
    cwes = {f.cwe for f in findings}
    assert "CWE-79" in cwes        # reflected marker rendered as a real DOM element
    assert "CWE-352" in cwes       # POST /login form has no token field
    assert inv["pages_crawled"] >= 2
    assert all(f.level == 4 for f in findings)   # observed live in the browser


def test_browser_available_is_boolean():
    assert isinstance(browser_mod.available(), bool)
