"""Where the code comes from: a local folder or a git repository URL.

Cloning untrusted repositories is itself an attack surface, so the clone is locked down:
* only https:// URLs (plus `owner/repo` shorthand for GitHub); file://, ssh://, ext:: and other
  transports are refused, and git itself is told to allow only https (protocol.allow);
* shallow clone of one ref, no submodules, no LFS smudge, no terminal prompts, hooks never run
  on clone;
* a private-repo token (CAA_GIT_TOKEN, explicit opt-in) is passed as an HTTP header via environment-scoped git config, never in
  the URL, so it does not end up in logs, reports or the clone's .git/config.
The resulting folder is treated as THIRD-PARTY code (default trust mode) unless the user says otherwise.
"""
from __future__ import annotations

import base64
import os
import re
import shutil
import subprocess
import tempfile
from dataclasses import dataclass
from pathlib import Path
from urllib.parse import urlparse

_SHORTHAND = re.compile(r"^(?:github:)?([A-Za-z0-9_.-]+)/([A-Za-z0-9_.-]+?)(?:\.git)?$")
_REF = re.compile(r"^[A-Za-z0-9._/-]{1,200}$")


class SourceError(ValueError):
    pass


@dataclass
class Source:
    path: Path
    kind: str                       # local | git
    url: str | None = None          # without credentials
    ref: str | None = None
    commit: str | None = None
    _tmp: str | None = None

    def meta(self) -> dict:
        return {"kind": self.kind, "path": str(self.path), "url": self.url, "ref": self.ref, "commit": self.commit}

    def cleanup(self) -> None:
        if self._tmp:
            shutil.rmtree(self._tmp, ignore_errors=True)


def is_remote(target: str) -> bool:
    return target.startswith(("https://", "http://", "git@", "ssh://", "file://", "git://", "ext::")) or \
        (bool(_SHORTHAND.match(target)) and not Path(target).exists())


def normalise_url(target: str) -> str:
    m = _SHORTHAND.match(target)
    if m and not target.startswith(("https://", "http://")):
        return f"https://github.com/{m.group(1)}/{m.group(2)}.git"
    u = urlparse(target)
    if u.scheme != "https":
        raise SourceError(f"only https:// repository URLs are accepted (got {u.scheme or target.split(':')[0]}://)")
    if u.username or u.password:
        raise SourceError("do not put credentials in the URL; set CAA_GIT_TOKEN instead")
    if not u.hostname or u.hostname.startswith("-"):
        raise SourceError("invalid repository host")
    return target


def resolve(target: str, ref: str | None = None, workdir: str | None = None) -> Source:
    if not is_remote(target):
        p = Path(target).resolve()
        if not p.is_dir():
            raise SourceError(f"{target} is not a folder")
        commit = _git_out(p, "rev-parse", "HEAD")
        return Source(path=p, kind="local", commit=commit)
    url = normalise_url(target)
    if ref is not None and (not _REF.match(ref) or ref.startswith("-") or ".." in ref):
        raise SourceError("invalid --ref")
    tmp = tempfile.mkdtemp(prefix="caa-clone-", dir=workdir)
    dest = Path(tmp) / _repo_name(url)
    env = _git_env(url)
    cmd = ["git", "-c", "protocol.allow=never", "-c", "protocol.https.allow=always",
           "-c", "core.hooksPath=/dev/null", "-c", "core.symlinks=false",
           "clone", "--depth", "1", "--no-tags", "--single-branch", "--no-recurse-submodules"]
    if ref:
        cmd += ["--branch", ref]
    cmd += ["--", url, str(dest)]
    proc = subprocess.run(cmd, env=env, capture_output=True, text=True, timeout=900)
    if proc.returncode != 0:
        shutil.rmtree(tmp, ignore_errors=True)
        raise SourceError(f"git clone failed: {_redact(proc.stderr.strip())[-400:]}")
    return Source(path=dest, kind="git", url=url, ref=ref or _git_out(dest, "rev-parse", "--abbrev-ref", "HEAD"),
                  commit=_git_out(dest, "rev-parse", "HEAD"), _tmp=tmp)


def _repo_name(url: str) -> str:
    name = urlparse(url).path.rstrip("/").split("/")[-1].removesuffix(".git")
    return re.sub(r"[^A-Za-z0-9._-]", "_", name) or "repo"


def _git_env(url: str) -> dict:
    env = dict(os.environ)
    env.update({"GIT_TERMINAL_PROMPT": "0", "GIT_LFS_SKIP_SMUDGE": "1", "GIT_CONFIG_NOSYSTEM": "1"})
    # the operator's own askpass helper / env-scoped git config (e.g. a corporate proxy) are kept;
    # only when there is none do we make sure git can never prompt
    env.setdefault("GIT_ASKPASS", "/bin/false")
    token = os.environ.get("CAA_GIT_TOKEN")      # explicit opt-in: never pick up unrelated tokens implicitly
    if token:
        host = urlparse(url).hostname
        basic = base64.b64encode(f"x-access-token:{token}".encode()).decode()
        # environment-scoped config: not written to any file, not visible in the URL
        n = int(env.get("GIT_CONFIG_COUNT", "0") or 0)
        env.update({"GIT_CONFIG_COUNT": str(n + 1),
                    f"GIT_CONFIG_KEY_{n}": f"http.https://{host}/.extraheader",
                    f"GIT_CONFIG_VALUE_{n}": f"AUTHORIZATION: basic {basic}"})
    return env


def _git_out(path: Path, *args: str) -> str | None:
    try:
        proc = subprocess.run(["git", "-c", f"safe.directory={path}", *args], cwd=path, capture_output=True,
                              text=True, timeout=30)
    except (OSError, subprocess.SubprocessError):
        return None
    return proc.stdout.strip() if proc.returncode == 0 else None


def _redact(text: str) -> str:
    return re.sub(r"(?i)(authorization:\s*\S+\s+)\S+", r"\1****", re.sub(r"https://[^@\s]+@", "https://****@", text))
