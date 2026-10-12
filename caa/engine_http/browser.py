"""Browser-driven part of engine HTTP: the agent drives a real headless browser (Playwright/Chromium)
over a live site, same-origin and read-only.

A plain HTTP client sees only the first HTML response. A browser runs the page's JavaScript, so it
sees what a user actually gets: single-page apps, client-side rendered content and links, cookies
set from JS, subresources the page pulls in, and reflection that only happens in the DOM. This finds
issues the passive HTTP checks cannot:

  mixed-content   an https page loads http:// scripts/styles/images (CWE-319)
  dom-reflection  a benign marker in a query parameter ends up unescaped in the rendered DOM (CWE-79)
  csrf-form       a state-changing POST form has no anti-CSRF token field (CWE-352)

Boundaries, in code:
  * only the operator's origin; off-origin navigations are blocked and external requests are logged
    but not followed by the crawler;
  * navigation only (GET) plus reading the rendered page; no form is ever submitted, no button
    clicked, no destructive action; a benign marker is only ever placed in a URL query value;
  * a fixed page budget and per-navigation timeout.

If Playwright (or its Chromium) is not installed, available() returns False and caa live simply runs
the passive HTTP checks only.
"""
from __future__ import annotations

import re
import urllib.parse
from dataclasses import dataclass, field

from caa.core.audit import NULL_AUDIT, AuditLog
from caa.core.models import Evidence, Finding, Group, Level, Location, Ref

# a harmless, unique custom element - NOT a script. If it appears as a real DOM element after the
# page renders, the parameter was injected as unescaped HTML (XSS-capable). If it is escaped, it is
# only text and no element exists. This mirrors the sandbox runtime harness's XSS marker.
DOM_TAG = "caa-dom7919"
DOM_MARK = f"<{DOM_TAG}></{DOM_TAG}>"
NAV_TIMEOUT_MS = 15000


def _benign_for(field: dict) -> str:
    """A harmless default value to fill non-targeted fields so a form submits (owner's own app)."""
    t = field.get("type", "text")
    return {"email": "caa@example.com", "number": "1", "tel": "1000000", "url": "https://example.com",
            "password": "Caa-Test-123", "checkbox": "on", "date": "2020-01-01"}.get(t, "caa")


def available() -> bool:
    try:
        import playwright.sync_api  # noqa: F401
    except Exception:
        return False
    return True


@dataclass
class BrowserCrawl:
    origin: str
    host: str
    start_url: str
    max_pages: int = 8
    audit: AuditLog = NULL_AUDIT
    pages: list[dict] = field(default_factory=list)
    points: list[dict] = field(default_factory=list)   # enumerated injection points (for the active prober)
    _mixed: dict = field(default_factory=dict)      # page url -> list of http subresource urls
    _idx: int = 0

    def _same_origin(self, url: str) -> bool:
        try:
            return urllib.parse.urlparse(url).hostname == self.host
        except ValueError:
            return False

    def run(self) -> tuple[list[Finding], dict]:
        from playwright.sync_api import sync_playwright

        findings: list[Finding] = []
        seen: set[str] = set()
        queue = [self.start_url]
        forms_seen: list[dict] = []
        cookies_final: list[dict] = []
        with sync_playwright() as p:
            browser = p.chromium.launch(args=["--no-sandbox", "--disable-dev-shm-usage"])
            context = browser.new_context(ignore_https_errors=True)
            page = context.new_page()
            page.set_default_navigation_timeout(NAV_TIMEOUT_MS)

            def on_request(req):
                # record (but never block) subresources; flag http:// pulled into an https page
                try:
                    if req.url.startswith("http://") and self.origin.startswith("https://") \
                            and req.resource_type in ("script", "stylesheet", "image", "font", "xhr", "fetch"):
                        self._mixed.setdefault(page.url, []).append(f"{req.resource_type}: {req.url}")
                except Exception:
                    pass

            page.on("request", on_request)

            while queue and len(seen) < self.max_pages:
                url = queue.pop(0)
                if url in seen or not self._same_origin(url):
                    continue
                seen.add(url)
                self._idx += 1
                try:
                    resp = page.goto(url, wait_until="domcontentloaded")
                except Exception as exc:
                    self.audit.write("browser_nav_error", url=self._redact(url), error=str(exc)[:160])
                    continue
                status = resp.status if resp else None
                self.pages.append({"idx": self._idx, "url": url, "status": status})
                self.audit.write("browser_nav", url=self._redact(url), status=status)
                # collect same-origin links to keep crawling
                for href in self._links(page):
                    absu = urllib.parse.urljoin(url, href)
                    if self._same_origin(absu) and absu.split("#")[0] not in seen:
                        queue.append(absu.split("#")[0])
                forms_seen += self._forms(page, url)

            # DOM reflection: re-navigate same-origin links that carry a query param, with a marker
            findings += self._check_dom_reflection(page, sorted(seen))
            try:
                cookies_final = context.cookies()
            except Exception:
                cookies_final = []
            browser.close()

        findings += self._mixed_findings()
        findings += self._csrf_findings(forms_seen)
        for f in findings:
            f.make_id()
        self.points = self.injection_points(forms_seen, sorted(seen))
        inv = {
            "pages_crawled": len(seen),
            "forms": len(forms_seen),
            "injection_points": len(self.points),
            "cookies": [{"name": c.get("name"), "secure": c.get("secure"), "httpOnly": c.get("httpOnly"),
                         "sameSite": c.get("sameSite")} for c in cookies_final],
            "page_list": self.pages,
        }
        return findings, inv

    # ------------------------------------------------------------------ helpers
    def _redact(self, url: str) -> str:
        return re.sub(r"//[^/]+", "//<host>", url)

    def _links(self, page) -> list[str]:
        try:
            return page.eval_on_selector_all("a[href]", "els => els.map(e => e.getAttribute('href'))") or []
        except Exception:
            return []

    def _forms(self, page, url) -> list[dict]:
        try:
            raw = page.eval_on_selector_all("form", """els => els.map(f => ({
                method: (f.getAttribute('method')||'get').toLowerCase(),
                action: f.getAttribute('action')||'',
                hasToken: !!f.querySelector("input[type=hidden][name*=csrf i],input[type=hidden][name*=token i],"
                    + "input[name=_token],input[name=authenticity_token],input[name=csrfmiddlewaretoken]"),
                fields: Array.from(f.querySelectorAll('input[name],textarea[name],select[name]'))
                    .map(e => ({name: e.getAttribute('name'),
                                type: (e.getAttribute('type')||'text').toLowerCase(),
                                value: e.getAttribute('value')||''})),
            }))""") or []
        except Exception:
            return []
        for r in raw:
            r["page"] = url
        return raw

    def injection_points(self, forms: list[dict], urls: list[str]) -> list[dict]:
        """Enumerate places user input enters the app: form fields and query parameters. Used by the
        optional active prober. Each point: {method, url, fields:{name:value}, submit:[names], page}."""
        import urllib.parse as up
        points, seen = [], set()
        for form in forms:
            fields = {f["name"]: (f.get("value") or _benign_for(f)) for f in form.get("fields", []) if f.get("name")}
            if not fields:
                continue
            action = up.urljoin(form["page"], form.get("action") or "")
            if not self._same_origin(action):
                continue
            key = (form.get("method", "get"), action, tuple(sorted(fields)))
            if key in seen:
                continue
            seen.add(key)
            points.append({"method": form.get("method", "get"), "url": action, "fields": dict(fields),
                           "submit": list(fields), "page": form["page"]})
        for u in urls:
            parts = up.urlparse(u)
            qs = dict(up.parse_qsl(parts.query))
            if not qs:
                continue
            base = parts._replace(query="").geturl()
            key = ("get", base, tuple(sorted(qs)))
            if key in seen:
                continue
            seen.add(key)
            points.append({"method": "get", "url": base, "fields": qs, "submit": list(qs), "page": u})
        return points

    def _check_dom_reflection(self, page, urls: list[str]) -> list[Finding]:
        out = []
        for url in urls:
            parts = urllib.parse.urlparse(url)
            qs = urllib.parse.parse_qsl(parts.query)
            if not qs:
                continue
            probe = urllib.parse.urlencode([(k, DOM_MARK) for k, _ in qs])
            test = parts._replace(query=probe).geturl()
            self._idx += 1
            try:
                page.goto(test, wait_until="domcontentloaded")
                injected = page.query_selector(DOM_TAG) is not None   # the marker became a real element
            except Exception:
                continue
            if injected:
                loc = Location(file=parts.path or "/", start_line=self._idx)
                f = Finding(title="Reflected / DOM-based XSS: query parameter rendered as HTML",
                            cwe="CWE-79", group=Group.DATAFLOW, location=loc, severity="high",
                            sources=["web-browser"],
                            explanation="A harmless marker placed in a URL query parameter was rendered by the "
                            "browser as a real HTML element, so the value is inserted into the page without "
                            "escaping. A real attacker could inject a <script> the same way (reflected or "
                            "DOM-based XSS).")
                f.add_evidence(Evidence(level=Level.L4, by="web-browser",
                                        detail=f"marker rendered as a DOM element on {parts.path}?{parts.query}",
                                        refs=[Ref(http_exchange=f"GET {parts.path} (rendered)")]))
                out.append(f)
        return out

    def _mixed_findings(self) -> list[Finding]:
        out = []
        for url, subs in self._mixed.items():
            loc = Location(file=urllib.parse.urlparse(url).path or "/", start_line=0)
            f = Finding(title="Mixed content: https page loads http resources", cwe="CWE-319",
                        group=Group.SECRETS_CONFIG, location=loc, severity="medium", sources=["web-browser"],
                        explanation="A page served over https pulls in sub-resources over plain http: "
                        + "; ".join(sorted(set(subs))[:5]) + ". These can be read or tampered with in transit.")
            f.add_evidence(Evidence(level=Level.L4, by="web-browser", detail=f"{len(set(subs))} http sub-resource(s)",
                                    refs=[Ref(http_exchange=f"page {urllib.parse.urlparse(url).path}")]))
            out.append(f)
        return out

    def _csrf_findings(self, forms: list[dict]) -> list[Finding]:
        out = []
        for form in forms:
            if form.get("method") != "post" or form.get("hasToken"):
                continue
            loc = Location(file=urllib.parse.urlparse(form["page"]).path or "/", start_line=0)
            f = Finding(title="POST form without an anti-CSRF token field", cwe="CWE-352",
                        group=Group.ACCESS_CONTROL, location=loc, severity="medium", sources=["web-browser"],
                        explanation=f"A POST form (action {form.get('action') or '(self)'!r}) has no hidden CSRF "
                        "token field. Unless it is protected another way (e.g. a SameSite session cookie or a "
                        "custom header checked server-side), it may be submittable cross-site.")
            f.add_evidence(Evidence(level=Level.L4, by="web-browser", detail="no hidden csrf/token input in the form",
                                    refs=[Ref(http_exchange=f"form on {urllib.parse.urlparse(form['page']).path}")]))
            out.append(f)
        return out
