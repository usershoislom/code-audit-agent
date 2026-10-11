"""Engine HTTP (black box): a passive, read-only security check of a live website.

Given only a URL, it reports configuration and hygiene mistakes an owner commonly leaves behind.
It NEVER attacks the site: every request is a plain GET/HEAD, same-origin, no payloads, no fuzzing,
no authentication bypass, no state change. The checks only observe what the server already reveals:

  transport     HTTPS reachable, HTTP->HTTPS redirect, HSTS
  headers       CSP, X-Content-Type-Options, X-Frame-Options / frame-ancestors, Referrer-Policy
  cookies       Secure / HttpOnly / SameSite flags on Set-Cookie
  cors          Access-Control-Allow-Origin reflects an arbitrary Origin together with credentials
  banner        Server / X-Powered-By version disclosure
  errors        a request for a random missing path returns a stack trace / debug page (not an attack)
  listing       directory listing (autoindex) left on
  exposed       well-known sensitive files served publicly (confirmed by content, e.g. /.git/HEAD)

Boundaries are in the code, not in a prompt:
  * only the scheme+host the operator passed; links are never followed off-origin;
  * only GET and HEAD; a small, fixed request budget; a short delay between requests;
  * the operator must confirm they own / are authorised to test the target (see cli: --authorized).
"""
from __future__ import annotations

import http.cookies
import re
import socket
import ssl
import time
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass, field

from caa.core.audit import NULL_AUDIT, AuditLog
from caa.core.models import Evidence, Finding, Group, Level, Location, Ref

UA = "caa-web-check/1.0 (+passive; owner-authorised)"
REQUEST_BUDGET = 25
DELAY_S = 0.3
TIMEOUT_S = 12

# reused idea from the sandbox runtime harness: signatures of a leaked stack trace / debug page
ERROR_SIGNATURES = [
    ("python-traceback", r"Traceback \(most recent call last\)"),
    ("werkzeug-debugger", r"Werkzeug Debugger|The debugger caught an exception|__traceback_hide__"),
    ("django-debug", r"You're seeing this error because you have <code>DEBUG = True</code>|django\.core\.handlers"),
    ("flask-debug", r"werkzeug\.exceptions|\bapp\.run\(.*debug=True"),
    ("java-stacktrace", r"\bat [a-z]+(\.[A-Za-z0-9_$]+)+\([A-Za-z0-9_]+\.java:\d+\)|javax\.servlet"),
    ("aspnet-stacktrace", r"\[[A-Za-z]+Exception:|Microsoft\.AspNetCore|System\.Web\."),
    ("php-error", r"<b>(Warning|Fatal error|Notice)</b>:|on line <b>\d+</b>|Stack trace:"),
    ("go-panic", r"goroutine \d+ \[running\]|panic: "),
    ("node-stack", r"at [A-Za-z0-9_.<>]+ \(/[^)]+\.js:\d+:\d+\)|ReferenceError:"),
    ("rails-error", r"ActionController|ActiveRecord::"),
]
AUTOINDEX = [r"<title>Index of /", r"Directory listing for /", r">\s*Parent Directory\s*<"]
# well-known files that must never be world-readable; confirmed by a content signature, not just 200
EXPOSED = [
    ("/.git/HEAD", re.compile(r"^ref:\s+refs/|^[0-9a-f]{40}"), "CWE-527", "Public .git directory"),
    ("/.env", re.compile(r"(?m)^[A-Z][A-Z0-9_]*\s*="), "CWE-538", "Public .env file"),
    ("/.svn/entries", re.compile(r"^\d+\s|svn://|dir\n"), "CWE-527", "Public .svn metadata"),
    ("/server-status", re.compile(r"Apache Server Status|<h1>Server Status"), "CWE-200", "Apache mod_status exposed"),
    ("/.DS_Store", re.compile(r"\x00\x00\x00\x01Bud1"), "CWE-200", "Public .DS_Store"),
    ("/phpinfo.php", re.compile(r"<title>phpinfo\(\)|PHP Version"), "CWE-200", "phpinfo() exposed"),
]
SEC_HEADERS = {
    "content-security-policy": ("CWE-1021", "No Content-Security-Policy (clickjacking / content injection defence)",
                                "medium"),
    "x-content-type-options": ("CWE-693", "No X-Content-Type-Options: nosniff (MIME sniffing)", "low"),
    "x-frame-options": ("CWE-1021", "No X-Frame-Options and no CSP frame-ancestors (clickjacking)", "medium"),
    "referrer-policy": ("CWE-200", "No Referrer-Policy (referrer leakage)", "low"),
}
BANNER_HEADERS = ("server", "x-powered-by", "x-aspnet-version", "x-aspnetmvc-version")
VERSION_RE = re.compile(r"\d+\.\d+")


@dataclass
class Exchange:
    idx: int
    method: str
    url: str
    status: int | None
    headers: dict
    body: str
    error: str = ""

    @property
    def label(self) -> str:
        return f"{self.method} {urllib.parse.urlparse(self.url).path or '/'} -> {self.status or self.error}"


@dataclass
class WebScan:
    base: str
    audit: AuditLog = NULL_AUDIT
    follow_links: bool = True
    _count: int = 0
    exchanges: list[Exchange] = field(default_factory=list)

    def __post_init__(self):
        u = urllib.parse.urlparse(self.base if "://" in self.base else "https://" + self.base)
        if u.scheme not in ("http", "https") or not u.hostname:
            raise ValueError(f"not a http(s) URL: {self.base!r}")
        self.scheme, self.host, self.port = u.scheme, u.hostname, u.port
        self.origin = f"{u.scheme}://{u.netloc}"
        self.start_path = u.path or "/"

    # -- transport: only GET/HEAD, only the operator's origin, budget-limited, no redirects followed blindly
    def _fetch(self, path_or_url: str, method: str = "GET", extra_headers: dict | None = None,
               scheme: str | None = None) -> Exchange:
        if self._count >= REQUEST_BUDGET:
            raise RuntimeError("request budget exhausted")
        if "://" in path_or_url:
            url = path_or_url
        else:
            netloc = self.host if self.port is None else f"{self.host}:{self.port}"
            url = f"{scheme or self.scheme}://{netloc}{path_or_url}"
        p = urllib.parse.urlparse(url)
        if p.hostname != self.host:                       # never leave the operator's host
            raise ValueError(f"refusing off-origin request to {p.hostname!r}")
        self._count += 1
        time.sleep(DELAY_S)
        headers = {"User-Agent": UA, "Accept": "*/*"}
        headers.update(extra_headers or {})
        req = urllib.request.Request(url, method=method, headers=headers)
        # do not auto-follow redirects: we want to see the 301/302 itself (HTTP->HTTPS check)
        opener = urllib.request.build_opener(_NoRedirect, urllib.request.ProxyHandler({}),
                                             urllib.request.HTTPSHandler(context=ssl.create_default_context()))
        ex = Exchange(self._count, method, url, None, {}, "")
        try:
            with opener.open(req, timeout=TIMEOUT_S) as r:
                ex.status, ex.headers = r.status, {k.lower(): v for k, v in r.headers.items()}
                ex.body = r.read(300_000).decode("utf-8", "replace")
        except urllib.error.HTTPError as e:
            ex.status = e.code
            ex.headers = {k.lower(): v for k, v in e.headers.items()}
            ex.body = e.read(300_000).decode("utf-8", "replace")
        except (urllib.error.URLError, ssl.SSLError, socket.error, OSError) as e:
            ex.error = f"{type(e).__name__}: {e}"[:200]
        self.exchanges.append(ex)
        self.audit.write("http_probe", method=method, url=re.sub(r"//[^/]+", "//<host>", url),
                         status=ex.status, error=ex.error)
        return ex

    def run(self) -> tuple[list[Finding], dict]:
        findings: list[Finding] = []
        add = lambda f: findings.append(f) if f else None

        home = self._fetch(self.start_path)
        add(self._check_transport(home))
        if home.status is None and self.scheme == "https":
            home = self._fetch(self.start_path, scheme="http") or home
        main = home if (home.headers or home.status) else None
        if main and main.status and 200 <= main.status < 400:
            add(self._check_headers(main))
            for f in self._check_cookies(main):
                add(f)
            add(self._check_banner(main))
            add(self._check_listing(main))
        add(self._check_cors())
        add(self._check_errors())
        for f in self._check_exposed():
            add(f)

        for f in findings:
            f.make_id()
        reachable = any(e.status for e in self.exchanges)
        inv = {
            "root": self.origin,
            "engine": "http",
            "target": {"url": self.base, "origin": self.origin, "reachable": reachable,
                       "server": (main.headers.get("server") if main else "") or "",
                       "final_status": main.status if main else None},
            "analyzers": [{"analyzer": "web-passive", "status": "ok" if reachable else "failed",
                           "candidates": len(findings),
                           "note": f"{self._count} requests, read-only (GET/HEAD)"}],
            "exchanges": [{"idx": e.idx, "label": e.label, "status": e.status, "error": e.error}
                          for e in self.exchanges],
        }
        if not reachable:
            inv["analyzers"][0]["note"] = f"target not reachable: {self.exchanges[0].error if self.exchanges else '?'}"
        return findings, inv

    # ------------------------------------------------------------------ checks
    def _f(self, ex: Exchange, cwe: str, title: str, group: Group, sev: str, detail: str, level=Level.L4) -> Finding:
        loc = Location(file=urllib.parse.urlparse(ex.url).path or "/", start_line=ex.idx)
        f = Finding(title=title, cwe=cwe, group=group, location=loc, severity=sev,
                    sources=["web-passive"], explanation=detail)
        f.add_evidence(Evidence(level=level, by="web-passive", detail=detail,
                                refs=[Ref(http_exchange=ex.label, note=detail)]))
        return f

    def _check_transport(self, home: Exchange) -> Finding | None:
        if self.scheme == "http":
            # given an http URL: is there a redirect to https?
            loc = (home.headers.get("location") or "")
            if not (home.status in (301, 302, 307, 308) and loc.startswith("https")):
                return self._f(home, "CWE-319", "Site served over plain HTTP (no HTTPS redirect)",
                               Group.SECRETS_CONFIG, "high",
                               "The site answers over http:// and does not redirect to https://; traffic and any "
                               "credentials or cookies travel in cleartext.")
            return None
        # https: check HSTS
        if home.status and "strict-transport-security" not in home.headers:
            return self._f(home, "CWE-319", "No HTTP Strict-Transport-Security (HSTS) header",
                           Group.SECRETS_CONFIG, "low",
                           "Without HSTS a browser can be downgraded to http:// on the first visit or via SSL "
                           "stripping.", level=Level.L4)
        return None

    def _check_headers(self, ex: Exchange) -> Finding | None:
        missing = []
        for h, (cwe, msg, sev) in SEC_HEADERS.items():
            if h == "x-frame-options" and "frame-ancestors" in (ex.headers.get("content-security-policy") or ""):
                continue
            if h not in ex.headers:
                missing.append((h, cwe, msg, sev))
        if not missing:
            return None
        worst = max(missing, key=lambda m: {"low": 0, "medium": 1, "high": 2}[m[3]])
        detail = "Response is missing: " + ", ".join(m[0] for m in missing) + "."
        return self._f(ex, worst[1], "Missing HTTP security headers", Group.SECRETS_CONFIG, worst[3], detail)

    def _check_cookies(self, ex: Exchange) -> list[Finding]:
        out = []
        raw = ex.headers.get("set-cookie")
        if not raw:
            return out
        for piece in re.split(r",(?=[^ ;]+=)", raw):
            try:
                c = http.cookies.SimpleCookie(piece)
            except http.cookies.CookieError:
                continue
            for name, morsel in c.items():
                low = piece.lower()
                flags = []
                if "secure" not in low:
                    flags.append(("CWE-614", "Secure"))
                if "httponly" not in low:
                    flags.append(("CWE-1004", "HttpOnly"))
                if "samesite" not in low:
                    flags.append(("CWE-1275", "SameSite"))
                if flags:
                    out.append(self._f(ex, flags[0][0], f"Cookie {name!r} missing flags: "
                                       + ", ".join(fl[1] for fl in flags), Group.SECRETS_CONFIG,
                                       "medium" if any(fl[1] == "HttpOnly" for fl in flags) else "low",
                                       f"Set-Cookie for {name!r} does not set " + "/".join(fl[1] for fl in flags)
                                       + "; session cookies without these are exposed to JS or sent cross-site."))
        return out

    def _check_banner(self, ex: Exchange) -> Finding | None:
        disclosed = [f"{h}: {ex.headers[h]}" for h in BANNER_HEADERS
                     if ex.headers.get(h) and VERSION_RE.search(ex.headers[h])]
        if not disclosed:
            return None
        return self._f(ex, "CWE-200", "Server version disclosed in headers", Group.SECRETS_CONFIG, "low",
                       "Response advertises software versions (" + "; ".join(disclosed)
                       + "), which helps an attacker match known CVEs.", level=Level.L1)

    def _check_listing(self, ex: Exchange) -> Finding | None:
        if any(re.search(rx, ex.body) for rx in AUTOINDEX):
            return self._f(ex, "CWE-548", "Directory listing enabled", Group.SECRETS_CONFIG, "medium",
                           "The server returns an automatic directory index, exposing file names that were not "
                           "meant to be browsable.")
        return None

    def _check_cors(self) -> Finding | None:
        probe = "https://caa-cors-probe.example"
        try:
            ex = self._fetch(self.start_path, extra_headers={"Origin": probe})
        except (ValueError, RuntimeError):
            return None
        acao = ex.headers.get("access-control-allow-origin", "")
        acac = (ex.headers.get("access-control-allow-credentials", "") or "").lower() == "true"
        if acao == probe and acac:
            return self._f(ex, "CWE-942", "CORS reflects any Origin with credentials", Group.ACCESS_CONTROL, "high",
                           "The server echoes an arbitrary Origin in Access-Control-Allow-Origin and also sets "
                           "Access-Control-Allow-Credentials: true, so any website can read authenticated responses.")
        if acao == "*" and acac:
            return self._f(ex, "CWE-942", "CORS allows '*' with credentials", Group.ACCESS_CONTROL, "medium",
                           "Access-Control-Allow-Origin: * together with credentials is a misconfiguration.")
        return None

    def _check_errors(self) -> Finding | None:
        # a request for a path that should not exist; we only READ the error body, no payload is sent
        ex = self._fetch(f"/caa-not-here-{int(time.time())}")
        hits = [n for n, rx in ERROR_SIGNATURES if re.search(rx, ex.body)]
        if hits:
            return self._f(ex, "CWE-209", "Error page leaks a stack trace / debug output", Group.SECRETS_CONFIG,
                           "medium", "A request for a non-existent path returns a detailed error "
                           f"({', '.join(hits)}) instead of a generic page; this leaks framework, path and code "
                           "internals. Debug mode is likely on in production.")
        return None

    def _check_exposed(self) -> list[Finding]:
        out = []
        for path, sig, cwe, title in EXPOSED:
            if self._count >= REQUEST_BUDGET:
                break
            try:
                ex = self._fetch(path)
            except (ValueError, RuntimeError):
                break
            if ex.status == 200 and ex.body and sig.search(ex.body):
                out.append(self._f(ex, cwe, title, Group.SECRETS_CONFIG, "high",
                                   f"{path} is served publicly and its content matches the expected format, so it "
                                   "is really exposed (not a catch-all 200). This can leak source code, secrets or "
                                   "internal configuration."))
        return out


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *a, **k):   # keep the 3xx response instead of following it
        return None
