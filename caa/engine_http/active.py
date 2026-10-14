"""Active probing of the operator's OWN application (opt-in, `caa live --active`).

This is authorised dynamic testing of your own app: the agent actually exercises each input point it
found - query parameters and form fields, including POST forms - to confirm whether a vulnerability
class is really present, the way an attacker's first probe would, but WITHOUT exploiting or damaging
anything. It is the "does my app actually let this through?" step.

Detection is by benign, non-destructive signals, never by exploitation:
  * XSS (CWE-79): a unique harmless custom-element marker; confirmed only if it comes back as raw,
    unescaped HTML. The marker is a made-up tag, never a <script> or event handler.
  * SQL injection (CWE-89): error-based (a single quote raises a DB error that a balanced quote does
    not) and boolean-based (`' OR '1'='1` vs `' OR '1'='2` change the response). No UNION, no stacked
    queries, no data is read or written.
  * OS command injection (CWE-78): time-based only - a `sleep` makes the response measurably slower,
    confirmed on a repeat. Never rm/cat/curl or any command that changes state or exfiltrates.
  * Open redirect (CWE-601): a redirect-looking parameter is set to a marker host; confirmed only if
    the server sends the browser there.
  * Path traversal (CWE-22): a `../` sequence to a world-readable system file; confirmed by a format
    signature (e.g. `root:x:0:0:`). The file content is not copied into the report.

Boundaries, in code (not a prompt):
  * same origin only; GET and POST only (never PUT/PATCH/DELETE);
  * a fixed request budget and a capped number of input points;
  * payloads come from the fixed benign set below - there is no shell-metacharacter fuzzing, no
    destructive SQL, no payload that deletes, overwrites or exfiltrates data.

Active mode submits forms, so it can create or change data in the app under test. Run it against your
own application (ideally a staging copy). caa prints this warning and records every request in the
audit log.
"""
from __future__ import annotations

import re
import ssl
import time
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass, field

from caa.core.audit import NULL_AUDIT, AuditLog
from caa.core.models import Evidence, Finding, Group, Level, Location, Ref

UA = "caa-web-check/1.0 (+active; owner-authorised)"
BUDGET = 400
MAX_POINTS = 25
DELAY_S = 0.2
TIMEOUT_S = 15
SLEEP_S = 5                         # time-based command-injection probe (a delay, nothing else)

XSS_TAG = "caaxss8842"
XSS_MARK = f"<{XSS_TAG}></{XSS_TAG}>"
BASELINE = "caabase1"
SQL_ERROR = re.compile(r"sql syntax|sqlite3\.|psycopg2|OperationalError|SQLSTATE\[|unrecognized token|"
                       r"ORA-\d{5}|You have an error in your SQL|unterminated quoted string|near \"", re.I)
REDIRECT_MARK_HOST = "caa-redirect.example"
REDIRECT_NAMES = re.compile(r"(redirect|return|next|url|dest|continue|target|goto|to)$", re.I)
PASSWD = re.compile(r"root:.*?:0:0:")
CMDI_PAYLOADS = [";sleep {n}", "|sleep {n}", "`sleep {n}`", "$(sleep {n})", "& sleep {n}"]
TRAVERSAL = ["../../../../../../../../etc/passwd", "....//....//....//....//etc/passwd",
             "..%2f..%2f..%2f..%2f..%2f..%2fetc%2fpasswd"]


@dataclass
class Resp:
    status: int | None
    headers: dict
    body: str
    seconds: float
    error: str = ""


@dataclass
class ActiveProber:
    origin: str
    host: str
    points: list[dict]
    audit: AuditLog = NULL_AUDIT
    _count: int = 0
    findings: list[Finding] = field(default_factory=list)

    def _request(self, method: str, url: str, fields: dict) -> Resp | None:
        if method.upper() not in ("GET", "POST"):          # active mode is read-and-submit, never destructive verbs
            raise ValueError(f"method {method!r} not allowed")
        if self._count >= BUDGET:
            raise RuntimeError("request budget exhausted")
        if urllib.parse.urlparse(url).hostname != self.host:
            raise ValueError("off-origin request refused")
        self._count += 1
        time.sleep(DELAY_S)
        data = None
        if method.upper() == "GET":
            sep = "&" if urllib.parse.urlparse(url).query else "?"
            full = url + (sep + urllib.parse.urlencode(fields) if fields else "")
        else:
            full, data = url, urllib.parse.urlencode(fields).encode()
        req = urllib.request.Request(full, data=data, method=method.upper(),
                                     headers={"User-Agent": UA, "Accept": "*/*",
                                              "Content-Type": "application/x-www-form-urlencoded"})
        opener = urllib.request.build_opener(_NoRedirect, urllib.request.ProxyHandler({}),
                                             urllib.request.HTTPSHandler(context=ssl.create_default_context()))
        t0 = time.time()
        try:
            with opener.open(req, timeout=TIMEOUT_S) as r:
                return Resp(r.status, {k.lower(): v for k, v in r.headers.items()},
                            r.read(300_000).decode("utf-8", "replace"), time.time() - t0)
        except urllib.error.HTTPError as e:
            return Resp(e.code, {k.lower(): v for k, v in e.headers.items()},
                        e.read(300_000).decode("utf-8", "replace"), time.time() - t0)
        except (urllib.error.URLError, ssl.SSLError, OSError) as e:
            return Resp(None, {}, "", time.time() - t0, f"{type(e).__name__}: {e}"[:160])

    def _vary(self, point: dict, target: str, value: str) -> dict:
        f = dict(point["fields"])
        f[target] = value
        return f

    def run(self) -> tuple[list[Finding], dict]:
        tested = 0
        for point in self.points[:MAX_POINTS]:
            for target in point.get("submit", []):
                if self._count >= BUDGET:
                    break
                try:
                    self._probe_field(point, target)
                except RuntimeError:
                    break
                except (ValueError, urllib.error.URLError):
                    continue
                tested += 1
        for f in self.findings:
            f.make_id()
        # de-duplicate identical (file, line, cwe)
        uniq, keys = [], set()
        for f in self.findings:
            k = (f.location.file, f.location.start_line, f.cwe)
            if k not in keys:
                keys.add(k)
                uniq.append(f)
        self.findings = uniq
        return self.findings, {"points_tested": tested, "requests": self._count}

    def _probe_field(self, point: dict, target: str) -> None:
        method, url = point["method"], point["url"]
        path = urllib.parse.urlparse(url).path or "/"
        base = self._request(method, url, self._vary(point, target, BASELINE))
        if base is None or base.error:
            return
        label = f"{method.upper()} {path} [{target}]"

        # --- XSS: marker must come back as raw, unescaped HTML
        r = self._request(method, url, self._vary(point, target, XSS_MARK))
        if r and XSS_MARK in r.body and f"&lt;{XSS_TAG}" not in r.body:
            self._add("CWE-79", "Reflected XSS: input returned as unescaped HTML", Group.DATAFLOW, "high", path,
                      label, "The marker placed in this field came back in the response as raw HTML (not escaped), "
                      "so an attacker could inject a working <script> here.")
            return

        # --- SQL injection: error-based, then boolean-based
        rq = self._request(method, url, self._vary(point, target, BASELINE + "'"))
        rqq = self._request(method, url, self._vary(point, target, BASELINE + "''"))
        if rq and SQL_ERROR.search(rq.body) and not (rqq and SQL_ERROR.search(rqq.body)) \
                and not SQL_ERROR.search(base.body):
            self._add("CWE-89", "SQL injection (error-based)", Group.DATAFLOW, "high", path, label,
                      "A single quote in this field triggers a database error while a balanced pair of quotes does "
                      "not - the value reaches the SQL query unescaped.")
            return
        rt = self._request(method, url, self._vary(point, target, BASELINE + "' OR '1'='1"))
        rf = self._request(method, url, self._vary(point, target, BASELINE + "' OR '1'='2"))
        # classic blind SQLi: the always-true variant looks like the normal response, the always-false
        # one differs from it. Both error out identically -> not injectable, so require the split.
        if rt and rf and not rt.error and not rf.error and _differs(rt.body, rf.body) \
                and not _differs(base.body, rt.body):
            self._add("CWE-89", "SQL injection (boolean-based)", Group.DATAFLOW, "high", path, label,
                      "A true condition (`' OR '1'='1`) gives the normal response while a false one "
                      "(`' OR '1'='2`) changes it, so the field is concatenated into a SQL query.")
            return

        # --- open redirect: only for redirect-looking parameter names
        if REDIRECT_NAMES.search(target):
            r = self._request(method, url, self._vary(point, target, f"https://{REDIRECT_MARK_HOST}/caa"))
            loc = (r.headers.get("location") if r else "") or ""
            if r and urllib.parse.urlparse(loc).hostname == REDIRECT_MARK_HOST:
                self._add("CWE-601", "Open redirect", Group.DATAFLOW, "medium", path, label,
                          f"Setting this parameter sends the browser to an external host ({loc}); an attacker can "
                          "use the trusted domain to redirect victims to a phishing page.")
                return

        # --- path traversal: confirmed by a format signature, content not copied out
        for payload in TRAVERSAL:
            r = self._request(method, url, self._vary(point, target, payload))
            if r and PASSWD.search(r.body) and not PASSWD.search(base.body):
                self._add("CWE-22", "Path traversal: reads files outside the intended directory", Group.DATAFLOW,
                          "high", path, label, "A `../` sequence in this field returns the format of a system file "
                          "(the response matched a world-readable file's signature). The app serves files by a "
                          "path it does not confine.")
                return

        # --- OS command injection: time-based only, confirmed on a repeat (a delay, nothing destructive)
        if base.seconds < SLEEP_S - 2:
            for payload in CMDI_PAYLOADS[:3]:
                r = self._request(method, url, self._vary(point, target, BASELINE + payload.format(n=SLEEP_S)))
                if r and not r.error and r.seconds >= SLEEP_S - 1:
                    r2 = self._request(method, url, self._vary(point, target, BASELINE + payload.format(n=SLEEP_S)))
                    if r2 and not r2.error and r2.seconds >= SLEEP_S - 1:
                        self._add("CWE-78", "OS command injection (time-based)", Group.DATAFLOW, "critical", path,
                                  label, f"Injecting a `sleep {SLEEP_S}` through this field delays the response by "
                                  "~5s, on two separate tries - the field reaches a shell command.")
                    break

    def _add(self, cwe, title, group, sev, path, label, detail) -> None:
        loc = Location(file=path, start_line=0)
        f = Finding(title=title, cwe=cwe, group=group, location=loc, severity=sev, sources=["web-active"],
                    explanation=detail)
        f.add_evidence(Evidence(level=Level.L4, by="web-active", detail=f"{label}: {detail}",
                                refs=[Ref(http_exchange=label)]))
        self.audit.write("active_finding", cwe=cwe, point=label)
        self.findings.append(f)


def _differs(a: str, b: str) -> bool:
    """A meaningful difference between two response bodies (length-based, tolerant of small noise)."""
    la, lb = len(a), len(b)
    return abs(la - lb) > max(40, 0.05 * max(la, lb, 1))


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *a, **k):
        return None
