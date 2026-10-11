"""Repository hygiene: basic mistakes that are not "code bugs" but leak secrets or weaken deployments.

Every check returns a Candidate pointing at a concrete file:line (the evidence is
the line itself). Checks:

  env-not-ignored        .env / key / credential files present and NOT ignored by git      CWE-540
  env-tracked            such a file is tracked by git (already committed)                   CWE-540
  gitignore-missing-env  project loads .env but .gitignore would not ignore a .env file      CWE-540
  no-gitignore           repository has no .gitignore at all                                  CWE-540
  docker-root            Dockerfile never switches to a non-root USER                         CWE-250
  docker-unpinned        FROM image without tag or with :latest                               CWE-1357
  docker-remote-add      ADD <url> (unverified remote content in the image)                   CWE-829
  docker-secret-env      ENV/ARG with a credential-looking literal                            CWE-798
  dockerignore-env       COPY of the whole context while .env exists and no .dockerignore     CWE-540
  django-debug           DEBUG = True in Django settings                                      CWE-489
  django-hosts           ALLOWED_HOSTS = ['*']                                                CWE-1188
  cookie-insecure        SESSION/CSRF_COOKIE_SECURE = False                                   CWE-614
  cors-credentials       any-origin CORS together with credentials (FastAPI/Starlette/Express) CWE-942
  unpinned-python        requirements line without an exact version                           CWE-1357
  no-lockfile            package.json without package-lock / yarn.lock / pnpm-lock            CWE-1357
  gha-prt-checkout       pull_request_target workflow that checks out the PR head            CWE-829
  gha-unpinned-action    third-party action referenced by branch (@main/@master)              CWE-829
  gha-script-injection   untrusted event text interpolated into a run: script                CWE-78
"""
from __future__ import annotations

import fnmatch
import re
import subprocess
from pathlib import Path

from caa.core.models import Candidate, Group, Location
from caa.tools.fs import RepoFS

SENSITIVE = [".env", ".env.*", "*.pem", "*.key", "id_rsa", "id_rsa*", "id_ed25519*", "*.p12", "*.pfx",
             "*.keystore", "*.jks", "credentials.json", "service-account*.json", "*.tfstate", ".npmrc", ".pypirc"]
NOT_SENSITIVE = {".env.example", ".env.sample", ".env.template", ".env.dist", ".env.defaults"}
DOTENV_USE = re.compile(r"(load_dotenv|dotenv|python-decouple|godotenv|Dotenv::|env_file)")


def _cand(rule: str, cwe: str, file: str, line: int, msg: str, sev: str = "medium", **extra) -> Candidate:
    return Candidate(rule_id=f"caa.hygiene.{rule}", source="hygiene", cwe=cwe, group=Group.SECRETS_CONFIG,
                     location=Location(file=file, start_line=line), message=msg,
                     extra={"severity_hint": sev, **extra})


def _is_git(fs: RepoFS) -> bool:
    """Inside a git work tree (the scanned folder may be a sub-directory of one)."""
    try:
        return _git(fs, "rev-parse", "--is-inside-work-tree").stdout.strip() == "true"
    except (OSError, subprocess.SubprocessError):
        return False


def _git(fs: RepoFS, *args: str) -> subprocess.CompletedProcess:
    return subprocess.run(["git", *args], cwd=fs.root, capture_output=True, text=True, timeout=60)


def _gitignore_patterns(fs: RepoFS) -> list[str]:
    p = fs.root / ".gitignore"
    if not p.exists():
        return []
    return [ln.strip() for ln in p.read_text(errors="replace").splitlines() if ln.strip() and not ln.startswith("#")]


def is_ignored(fs: RepoFS, rel: str) -> bool:
    """Would git ignore `rel`? Uses git itself when available (works for non-existent paths)."""
    if _is_git(fs):
        proc = _git(fs, "check-ignore", "--no-index", "-q", rel)
        return proc.returncode == 0
    ignored = False
    name = Path(rel).name
    for pat in _gitignore_patterns(fs):          # minimal .gitignore semantics, last match wins
        neg = pat.startswith("!")
        pat = pat.lstrip("!").rstrip("/")
        if fnmatch.fnmatch(name, pat.lstrip("/")) or fnmatch.fnmatch(rel, pat.lstrip("/")):
            ignored = not neg
    return ignored


def _tracked(fs: RepoFS) -> set[str]:
    if not _is_git(fs):
        return set()
    proc = _git(fs, "ls-files", "--full-name", ".")
    if proc.returncode != 0:
        return set()
    prefix = _git(fs, "rev-parse", "--show-prefix").stdout.strip()
    return {p[len(prefix):] for p in proc.stdout.splitlines() if p.startswith(prefix)}


def check(fs: RepoFS, prof=None) -> list[Candidate]:
    out: list[Candidate] = []
    files = fs.iter_files("*")
    tracked = _tracked(fs)
    out += _sensitive_files(fs, files, tracked)
    out += _gitignore(fs, files)
    for rel in files:
        name = Path(rel).name
        if name == "Dockerfile" or name.endswith(".Dockerfile") or name.startswith("Dockerfile."):
            out += _dockerfile(fs, rel, files)
        elif rel.endswith(".py"):
            out += _python_settings(fs, rel)
        if re.search(r"\.(py|js|ts|mjs|cjs)$", rel):
            out += _cors(fs, rel)
        if re.search(r"(^|/)requirements[^/]*\.txt$", rel):
            out += _requirements(fs, rel)
        if name == "package.json" and "node_modules" not in rel:
            d = Path(rel).parent
            if not any((fs.root / d / lock).exists() for lock in ("package-lock.json", "yarn.lock", "pnpm-lock.yaml",
                                                                  "npm-shrinkwrap.json", "bun.lockb")):
                out.append(_cand("no-lockfile", "CWE-1357", rel, 1,
                                 "package.json without a lockfile: every install may pull different dependency versions",
                                 "low"))
        if re.search(r"(^|/)\.github/workflows/[^/]+\.ya?ml$", rel):
            out += _workflow(fs, rel)
    return out


def _sensitive_files(fs: RepoFS, files: list[str], tracked: set[str]) -> list[Candidate]:
    out = []
    for rel in files:
        name = Path(rel).name
        if name in NOT_SENSITIVE or not any(fnmatch.fnmatch(name, p) for p in SENSITIVE):
            continue
        if re.search(r"(^|/)(tests?|fixtures|examples?|samples?)/", rel):
            continue
        if rel in tracked:
            out.append(_cand("env-tracked", "CWE-540", rel, 1,
                             f"{rel} is committed to git: its secrets are in the history even if deleted now; "
                             "rotate them and remove the file from history", "high"))
        elif not is_ignored(fs, rel):
            out.append(_cand("env-not-ignored", "CWE-540", rel, 1,
                             f"{rel} is not ignored by .gitignore and will be committed by the next `git add .`",
                             "high"))
    return out


def _gitignore(fs: RepoFS, files: list[str]) -> list[Candidate]:
    out = []
    has_code = any(re.search(r"\.(py|js|ts|go|java)$", f) for f in files)
    uses_dotenv = any(DOTENV_USE.search(fs.resolve(f).read_text(errors="replace"))
                      for f in files if re.search(r"\.(py|js|ts|go|ya?ml|toml|cfg)$|(^|/)requirements[^/]*\.txt$|package\.json$", f))
    if not (fs.root / ".gitignore").exists() and not _is_git(fs):
        if has_code:
            anchor = next((f for f in files if re.search(r"\.(py|js|ts|go|java)$", f)), files[0])
            out.append(_cand("no-gitignore", "CWE-540", anchor, 1,
                             "repository has no .gitignore: .env files, keys and build artefacts get committed",
                             "medium" if uses_dotenv else "low"))
        return out
    if not is_ignored(fs, ".env"):
        anchor = ".gitignore" if (fs.root / ".gitignore").exists() else \
            next((f for f in files if re.search(r"\.(py|js|ts|go|java)$", f)), files[0])
        out.append(_cand("gitignore-missing-env", "CWE-540", anchor, 1,
                         ".gitignore does not ignore `.env`" + (" although the project loads one" if uses_dotenv else ""),
                         "medium" if uses_dotenv else "low"))
    return out


def _dockerfile(fs: RepoFS, rel: str, files: list[str]) -> list[Candidate]:
    out = []
    lines = fs.read_lines(rel)
    user_set = False
    copy_all = None
    stages: set[str] = set()
    for i, raw in enumerate(lines, 1):
        ln = raw.strip()
        up = ln.upper()
        if up.startswith("FROM "):
            toks = [t for t in ln.split()[1:] if not t.startswith("--")]
            image = toks[0] if toks else ""
            if len(toks) >= 3 and toks[1].upper() == "AS":
                stages.add(toks[2].lower())
            last = image.split("/")[-1]
            pinned = "@sha256:" in image or (":" in last and not last.endswith(":latest"))
            if image and image.lower() not in stages | {"scratch"} and "$" not in image and not pinned:
                out.append(_cand("docker-unpinned", "CWE-1357", rel, i,
                                 f"base image `{image}` is not pinned to a version (or is :latest)", "low"))
            user_set = False          # each stage starts as root
        elif up.startswith("USER "):
            user_set = ln.split()[1] not in ("root", "0", "0:0")
        elif up.startswith("ADD ") and re.search(r"https?://", ln):
            out.append(_cand("docker-remote-add", "CWE-829", rel, i,
                             "ADD downloads remote content into the image without integrity check", "medium"))
        elif re.match(r"(ENV|ARG)\s+\w*(PASSWORD|SECRET|TOKEN|API_KEY|APIKEY)\w*[= ]\s*\S{6,}", up) and "$" not in ln:
            out.append(_cand("docker-secret-env", "CWE-798", rel, i,
                             "credential baked into the image via ENV/ARG (visible in image history)", "high"))
        elif re.match(r"COPY\s+\.\s+", up) or re.match(r"ADD\s+\.\s+", up):
            copy_all = i
    if not user_set and lines:
        last_from = max((i for i, t in enumerate(lines, 1) if t.strip().upper().startswith("FROM ")), default=1)
        out.append(_cand("docker-root", "CWE-250", rel, last_from,
                         "container runs as root: no non-root USER in the final stage", "medium"))
    ctx = Path(rel).parent
    if copy_all and not (fs.root / ctx / ".dockerignore").exists() and \
            any(Path(f).name == ".env" and Path(f).parent == ctx for f in files):
        out.append(_cand("dockerignore-env", "CWE-540", rel, copy_all,
                         "COPY . copies the .env file into the image (no .dockerignore)", "high"))
    return out


_PY_SETTINGS = [
    ("django-debug", "CWE-489", re.compile(r"^DEBUG\s*=\s*True\b"), "Django DEBUG = True: detailed error pages leak code and settings", "medium"),
    ("django-hosts", "CWE-1188", re.compile(r"^ALLOWED_HOSTS\s*=\s*\[\s*['\"]\*['\"]\s*\]"), "ALLOWED_HOSTS accepts any host header", "low"),
    ("cookie-insecure", "CWE-614", re.compile(r"^(SESSION|CSRF)_COOKIE_SECURE\s*=\s*False\b"), "cookie may be sent over plain HTTP", "low"),
]


def _python_settings(fs: RepoFS, rel: str) -> list[Candidate]:
    text = fs.resolve(rel).read_text(errors="replace")
    if "settings" not in Path(rel).name and "INSTALLED_APPS" not in text:
        return []
    out = []
    for i, ln in enumerate(text.splitlines(), 1):
        for rule, cwe, rx, msg, sev in _PY_SETTINGS:
            if rx.search(ln.strip()):
                out.append(_cand(rule, cwe, rel, i, msg, sev))
    return out


_CORS_ANY = re.compile(r"allow_origins\s*=\s*\[\s*['\"]\*['\"]\s*\]|origin\s*:\s*(?:true|['\"]\*['\"])")
_CORS_CRED = re.compile(r"allow_credentials\s*=\s*True|credentials\s*:\s*true")


def _cors(fs: RepoFS, rel: str) -> list[Candidate]:
    lines = fs.read_lines(rel)
    out = []
    for i, ln in enumerate(lines, 1):
        if _CORS_ANY.search(ln):
            window = "\n".join(lines[max(0, i - 4):i + 4])
            if _CORS_CRED.search(window):
                out.append(_cand("cors-credentials", "CWE-942", rel, i,
                                 "CORS allows any origin together with credentials: any site can read "
                                 "authenticated responses", "high"))
    return out


def _requirements(fs: RepoFS, rel: str) -> list[Candidate]:
    out = []
    for i, ln in enumerate(fs.read_lines(rel), 1):
        s = ln.split("#")[0].strip()
        if not s or s.startswith(("-", "git+", "http")):
            continue
        if "==" not in s and "@" not in s:
            out.append(_cand("unpinned-python", "CWE-1357", rel, i,
                             f"`{s}` has no exact version: builds are not reproducible and may pick up a "
                             "compromised or vulnerable release", "low"))
    return out


def _workflow(fs: RepoFS, rel: str) -> list[Candidate]:
    lines = fs.read_lines(rel)
    text = "\n".join(lines)
    out = []
    prt = re.search(r"^\s*pull_request_target\s*:|on:\s*\[?[^\n]*pull_request_target", text, re.M)
    for i, ln in enumerate(lines, 1):
        if prt and re.search(r"ref:\s*\$\{\{\s*github\.event\.pull_request\.head\.(sha|ref)", ln):
            out.append(_cand("gha-prt-checkout", "CWE-829", rel, i,
                             "pull_request_target runs with repository secrets but checks out untrusted PR code",
                             "high"))
        m = re.search(r"uses:\s*([\w.-]+/[\w./-]+)@(main|master|HEAD|latest)\b", ln)
        if m and not m.group(1).startswith("actions/"):
            out.append(_cand("gha-unpinned-action", "CWE-829", rel, i,
                             f"third-party action `{m.group(1)}` follows a moving branch; pin it to a commit SHA",
                             "low"))
        if re.search(r"\$\{\{\s*github\.(event\.(issue|pull_request|comment|review|head_commit)\.(title|body)|head_ref)",
                     ln) and _in_run_block(lines, i):
            out.append(_cand("gha-script-injection", "CWE-78", rel, i,
                             "untrusted event text is interpolated into a shell script; pass it via env: instead",
                             "high"))
    return out


def _in_run_block(lines: list[str], i: int) -> bool:
    for j in range(i - 1, max(-1, i - 15), -1):
        s = lines[j].strip()
        if s.startswith("run:") or s.startswith("- run:"):
            return True
        if re.match(r"-?\s*(uses|with|env|name|if):", s) and j != i - 1:
            return False
    return False
