"""Route map + ABSENTIA-style access-control hypotheses (group B).

Idea: instead of asking "is this handler vulnerable?", learn the policy that
sibling handlers of the same resource follow (auth decorator, ownership
check) and flag handlers that deviate from it. The route map with per-route
facts is also the context given to the LLM entry-point pass.
"""
from __future__ import annotations

import ast
import re
from dataclasses import dataclass, field

from caa.core.models import Candidate, Group, Location, Ref
from caa.engine_code.taint import ROUTE_DECOS, _call_name, _dotted, route_params
from caa.tools.fs import RepoFS

AUTH_DECORATOR = re.compile(r"(login_required|auth_required|jwt_required|requires_auth|admin_required|"
                            r"roles?_required|permission_required|role_required|authenticated|staff_member_required)")
OWNER_WORDS = re.compile(r"\b(owner|owner_id|user_id|author|author_id|created_by|account_id|tenant_id)\b")
CURRENT_USER = re.compile(r"(current_user|g\.user|session\[['\"]user(?:_id)?['\"]\]|session\.get\(['\"]user(?:_id)?['\"]\)|"
                          r"request\.user|get_current_user\(\)|uid\b|me\.id)")
PUBLIC_NAMES = re.compile(r"(login|logout|register|signup|index|home|health|status|static|public|about|ping|docs)", re.I)
LOOKUP_CALLS = {"get", "get_or_404", "first_or_404", "filter_by", "filter", "execute", "find", "find_one", "load", "fetch"}
INLINE_AUTH = re.compile(r"(current_user\.is_authenticated|['\"]user(?:_id)?['\"]\s+not\s+in\s+session|"
                         r"session\.get\(['\"]user(?:_id)?['\"]\)\s+is\s+None|not\s+g\.user|abort\(401\))")


@dataclass
class Route:
    file: str
    func: str
    line: int                 # def line
    deco_line: int
    path: str
    methods: list[str]
    params: list[str]
    auth: Ref | None = None               # decorator or inline auth check
    lookups: list[Ref] = field(default_factory=list)          # object lookup using a path/query id
    ownership: list[Ref] = field(default_factory=list)        # ownership check / owner-scoped query
    forbidden_exit: list[Ref] = field(default_factory=list)   # abort(403/404) after a comparison
    end_line: int = 0

    @property
    def resource(self) -> str:
        parts = [p for p in self.path.strip("/").split("/") if p and not p.startswith("<")]
        if not parts:
            return "/"
        n = 2 if parts[0] in ("api", "v1", "v2", "v3") else 1
        return "/".join(parts[:n])

    def to_dict(self) -> dict:
        return {"file": self.file, "func": self.func, "line": self.line, "path": self.path,
                "methods": self.methods, "params": self.params, "auth": bool(self.auth),
                "lookup_by_id": bool(self.lookups), "ownership_check": bool(self.ownership)}


@dataclass
class RouteMap:
    routes: list[Route]
    global_auth: list[Ref]          # before_request hooks enforcing auth

    def siblings(self, r: Route) -> list[Route]:
        """Routes of the same resource in the same application module."""
        return [o for o in self.routes if o is not r and o.resource == r.resource and o.file == r.file]

    def hooks_for(self, r: Route) -> list[Ref]:
        return [h for h in self.global_auth if h.file == r.file]

    def app_routes(self, r: Route) -> list[Route]:
        return [o for o in self.routes if o.file == r.file]


def build_route_map(fs: RepoFS) -> RouteMap:
    routes, global_auth = [], []
    for rel in fs.iter_files("*.py"):
        try:
            src = fs.resolve(rel).read_text(encoding="utf-8")
            tree = ast.parse(src)
        except (SyntaxError, OSError, UnicodeDecodeError):
            continue
        lines = src.splitlines()
        for node in ast.walk(tree):
            if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                continue
            decos = [_dotted(d) for d in node.decorator_list]
            if any(d.endswith("before_request") or d.endswith("before_app_request") for d in decos):
                body_src = "\n".join(lines[node.lineno - 1:node.end_lineno])
                if INLINE_AUTH.search(body_src) or "abort(401" in body_src or "redirect" in body_src:
                    global_auth.append(Ref(file=rel, line=node.lineno, note=f"before_request hook {node.name}()"))
                continue
            route_decos = [(d, n) for d, n in zip(decos, node.decorator_list) if ROUTE_DECOS.search(d)]
            if not route_decos:
                continue
            d0, dnode = route_decos[0]
            path = ""
            if isinstance(dnode, ast.Call) and dnode.args and isinstance(dnode.args[0], ast.Constant):
                path = str(dnode.args[0].value)
            methods = ["GET"]
            m = re.search(r"\.(get|post|put|patch|delete)\(", d0)
            if m:
                methods = [m.group(1).upper()]
            if isinstance(dnode, ast.Call):
                for k in dnode.keywords:
                    if k.arg == "methods" and isinstance(k.value, (ast.List, ast.Tuple)):
                        methods = [str(e.value).upper() for e in k.value.elts if isinstance(e, ast.Constant)]
            r = Route(file=rel, func=node.name, line=node.lineno, deco_line=dnode.lineno, path=path,
                      methods=methods, params=sorted(route_params(node)), end_line=node.end_lineno or node.lineno)
            for d, dn in zip(decos, node.decorator_list):
                if AUTH_DECORATOR.search(d):
                    r.auth = Ref(file=rel, line=dn.lineno, note=f"@{d}")
            _analyse_body(rel, node, lines, r)
            routes.append(r)
    return RouteMap(routes, global_auth)


def _analyse_body(rel: str, func: ast.FunctionDef, lines: list[str], r: Route) -> None:
    id_names = set(r.params)
    for n in ast.walk(func):
        # ids from query/body: x = request.args.get("id") / request.json["note_id"]
        if isinstance(n, ast.Assign) and isinstance(n.targets[0], ast.Name):
            src = _dotted(n.value)
            if "request." in src and re.search(r"id['\"]", src):
                id_names.add(n.targets[0].id)
    for n in ast.walk(func):
        line_src = lines[n.lineno - 1] if hasattr(n, "lineno") and n.lineno <= len(lines) else ""
        if r.auth is None and hasattr(n, "lineno") and INLINE_AUTH.search(line_src):
            r.auth = Ref(file=rel, line=n.lineno, note="inline authentication check")
        if isinstance(n, ast.Call) and _call_name(n) in LOOKUP_CALLS:
            used = {x.id for a in list(n.args) + [k.value for k in n.keywords] for x in ast.walk(a)
                    if isinstance(x, ast.Name)}
            call_src = _dotted(n)
            if used & id_names:
                r.lookups.append(Ref(file=rel, line=n.lineno, note=call_src[:100]))
                if OWNER_WORDS.search(call_src) and (CURRENT_USER.search(call_src) or "uid" in used or "user" in " ".join(used)):
                    r.ownership.append(Ref(file=rel, line=n.lineno, note="owner-scoped query"))
        if isinstance(n, ast.If):
            test_src = _dotted(n.test)
            if (OWNER_WORDS.search(test_src) or ".id" in test_src) and CURRENT_USER.search(test_src):
                body_src = " ".join(_dotted(b) for b in n.body)
                if re.search(r"abort\((?:403|404|401)\)|return .*(?:403|404)|raise", body_src):
                    r.ownership.append(Ref(file=rel, line=n.lineno, note="ownership comparison followed by deny"))
            if CURRENT_USER.search(test_src) and re.search(r"(is_admin|role|admin)", test_src):
                r.ownership.append(Ref(file=rel, line=n.lineno, note="role check"))


def authz_candidates(rm: RouteMap) -> list[Candidate]:
    out: list[Candidate] = []
    for r in rm.routes:
        sibs = rm.siblings(r)
        app = rm.app_routes(r)
        any_auth = [o for o in app if o.auth]
        hooks = rm.hooks_for(r)
        protected_sibs = [s for s in sibs if s.auth]
        # --- CWE-862: deviates from the authentication policy of its resource
        if r.auth is None and not hooks and not PUBLIC_NAMES.search(r.func + " " + r.path):
            if protected_sibs or (any_auth and len(any_auth) >= len(app) / 2):
                evidence = protected_sibs[0].auth if protected_sibs else any_auth[0].auth
                out.append(Candidate(
                    rule_id="caa.authz.missing-auth-vs-siblings", source="authz-routes", cwe="CWE-862",
                    group=Group.ACCESS_CONTROL,
                    location=Location(file=r.file, start_line=r.line, end_line=r.end_line, function=r.func),
                    message=(f"{','.join(r.methods)} {r.path} has no authentication while "
                             f"{len(protected_sibs) or len(any_auth)} comparable route(s) require it"),
                    extra={"route": r.to_dict(), "policy_ref": evidence.model_dump() if evidence else None,
                           "siblings": [s.to_dict() for s in sibs]}))
        # --- CWE-639: object fetched by client id without ownership check
        is_admin = bool(r.auth and re.search(r"(admin|staff|role|permission)", r.auth.note))
        user_scoped = bool(r.auth or protected_sibs or hooks or any(s.ownership for s in sibs))
        if r.lookups and not r.ownership and not is_admin and user_scoped:
            owner_sibs = [s for s in sibs if s.ownership]
            out.append(Candidate(
                rule_id="caa.authz.idor-no-ownership", source="authz-routes", cwe="CWE-639",
                group=Group.ACCESS_CONTROL,
                location=Location(file=r.file, start_line=r.lookups[0].line, function=r.func),
                message=(f"{','.join(r.methods)} {r.path} loads an object by a client-supplied id without an "
                         f"ownership check" + (f"; sibling {owner_sibs[0].func}() does check ownership"
                                               if owner_sibs else "")),
                extra={"route": r.to_dict(), "lookup_ref": r.lookups[0].model_dump(),
                       "sibling_check": owner_sibs[0].ownership[0].model_dump() if owner_sibs else None,
                       "siblings": [s.to_dict() for s in sibs]}))
    return out
