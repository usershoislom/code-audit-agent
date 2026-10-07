"""Ephemeral sandbox for property checks (ladder L4/L5).

Backends:
* docker        - default for real use: --network none, read-only source mount,
                  read-only rootfs, tmpfs /tmp, non-root uid, cap-drop ALL,
                  no-new-privileges, cpu/mem/pids limits, --rm (destroyed after one check).
* local-unshare - fallback when no Docker daemon: new user+network namespace
                  (no interfaces => no network), rlimits (CPU, address space,
                  file size, processes), scrubbed env, temp copy of the code,
                  wall-clock timeout. Weaker filesystem isolation than docker:
                  documented as a development fallback.
If neither is available, L4 is reported as "not verified" - the agent never
runs target code without network isolation.
"""
from __future__ import annotations

import json
import os
import resource
import shutil
import subprocess
import sys
import tempfile
from dataclasses import dataclass
from pathlib import Path

HARNESS = Path(__file__).with_name("harness.py")


@dataclass
class SandboxConfig:
    backend: str = "auto"
    image: str = "caa-sandbox:latest"
    timeout_s: int = 20
    memory_mb: int = 512
    cpus: float = 1.0


class SandboxUnavailable(RuntimeError):
    pass


def docker_available() -> bool:
    if not shutil.which("docker"):
        return False
    try:
        return subprocess.run(["docker", "info"], capture_output=True, timeout=10).returncode == 0
    except (OSError, subprocess.TimeoutExpired):
        return False


def unshare_available() -> bool:
    if not shutil.which("unshare"):
        return False
    try:
        return subprocess.run(["unshare", "-rn", "true"], capture_output=True, timeout=10).returncode == 0
    except (OSError, subprocess.TimeoutExpired):
        return False


class Sandbox:
    def __init__(self, cfg: SandboxConfig):
        self.cfg = cfg
        backend = cfg.backend
        if backend == "auto":
            backend = "docker" if docker_available() else ("local-unshare" if unshare_available() else "none")
        if backend == "docker" and not docker_available():
            raise SandboxUnavailable("docker backend requested but no docker daemon")
        if backend == "local-unshare" and not unshare_available():
            raise SandboxUnavailable("unshare backend requested but user/network namespaces are unavailable")
        if backend == "none":
            raise SandboxUnavailable("no isolating backend (docker or unshare) available; L4 disabled")
        self.backend = backend

    def run_check(self, source_root: Path, spec: dict) -> dict:
        """Copy the code into a fresh temp dir, run one property check, destroy everything."""
        with tempfile.TemporaryDirectory(prefix="caa-sbx-") as td:
            work = Path(td) / "src"
            shutil.copytree(source_root, work, ignore=shutil.ignore_patterns(".git", "__pycache__", ".caa"))
            hdir = Path(td) / "harness"
            hdir.mkdir()
            shutil.copy(HARNESS, hdir / "harness.py")
            (hdir / "spec.json").write_text(json.dumps(spec))
            if self.backend == "docker":
                return self._docker(work, hdir)
            return self._unshare(work, hdir)

    # -------------------------------------------------------------- backends
    def command_docker(self, work: Path, hdir: Path) -> list[str]:
        c = self.cfg
        return ["docker", "run", "--rm", "--network", "none", "--read-only",
                "--cap-drop", "ALL", "--security-opt", "no-new-privileges",
                "--pids-limit", "64", "--memory", f"{c.memory_mb}m", "--cpus", str(c.cpus),
                "--user", "65534:65534", "--tmpfs", "/tmp:rw,size=16m",
                "-v", f"{work}:/src:ro", "-v", f"{hdir}:/harness:ro", "-w", "/src",
                c.image, "python", "-I", "/harness/harness.py", "/harness/spec.json"]

    def _docker(self, work: Path, hdir: Path) -> dict:
        return self._exec(self.command_docker(work, hdir), cwd=None, preexec=None, env=None)

    def command_unshare(self, hdir: Path) -> list[str]:
        return ["unshare", "-rn", sys.executable, "-I", str(hdir / "harness.py"), str(hdir / "spec.json")]

    def _unshare(self, work: Path, hdir: Path) -> dict:
        mem = self.cfg.memory_mb * 1024 * 1024
        cpu = self.cfg.timeout_s

        def limits():
            resource.setrlimit(resource.RLIMIT_CPU, (cpu, cpu))
            resource.setrlimit(resource.RLIMIT_AS, (mem * 4, mem * 4))   # python + flask need address space
            resource.setrlimit(resource.RLIMIT_FSIZE, (16 * 1024 * 1024, 16 * 1024 * 1024))
            resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
            os.setsid()

        env = {"PATH": "/usr/bin:/bin", "HOME": str(work), "LANG": "C.UTF-8", "PYTHONDONTWRITEBYTECODE": "1"}
        for p in work.rglob("*"):          # source is read-only for the check
            if p.is_file():
                p.chmod(0o444)
        return self._exec(self.command_unshare(hdir), cwd=work, preexec=limits, env=env)

    def _exec(self, cmd, cwd, preexec, env) -> dict:
        try:
            proc = subprocess.run(cmd, cwd=cwd, preexec_fn=preexec, env=env, capture_output=True, text=True,
                                  timeout=self.cfg.timeout_s + 10)
        except subprocess.TimeoutExpired:
            return {"status": "inconclusive", "reason": "timeout"}
        for line in proc.stdout.splitlines():
            if line.startswith("CAA_RESULT "):
                out = json.loads(line[len("CAA_RESULT "):])
                out["backend"] = self.backend
                return out
        return {"status": "inconclusive", "reason": f"no result (rc={proc.returncode}): {proc.stderr[-400:]}",
                "backend": self.backend}
