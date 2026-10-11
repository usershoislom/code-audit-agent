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

Network modes (SandboxConfig.network):
* none   (default) - no network at all; used for property checks.
* egress (explicit opt-in, trusted code only) - the app may reach the internet
                  (its own APIs, package registries) to behave like in production.
                  docker: bridge network; local-unshare: user namespace only, the
                  process shares the host network (weaker: documented). Every
                  egress run is written to the audit log.
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
RUNTIME_HARNESS = Path(__file__).with_name("runtime_harness.py")
PROXY_VARS = ("HTTPS_PROXY", "HTTP_PROXY", "NO_PROXY", "https_proxy", "http_proxy", "no_proxy",
              "SSL_CERT_FILE", "REQUESTS_CA_BUNDLE", "NODE_EXTRA_CA_CERTS", "PIP_INDEX_URL", "GOPROXY")


@dataclass
class SandboxConfig:
    backend: str = "auto"
    image: str = "caa-sandbox:latest"
    timeout_s: int = 20
    memory_mb: int = 512
    cpus: float = 1.0
    network: str = "none"            # none | egress


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


def docker_image_present(image: str) -> bool:
    try:
        return subprocess.run(["docker", "image", "inspect", image], capture_output=True, timeout=20).returncode == 0
    except (OSError, subprocess.TimeoutExpired):
        return False


class Sandbox:
    def __init__(self, cfg: SandboxConfig):
        self.cfg = cfg
        backend = cfg.backend
        if backend == "auto":
            # docker only when its sandbox image is already built; a daemon without the image would
            # make every check "inconclusive"
            if docker_available() and docker_image_present(cfg.image):
                backend = "docker"
            else:
                backend = "local-unshare" if unshare_available() else "none"
        if backend == "docker" and not docker_available():
            raise SandboxUnavailable("docker backend requested but no docker daemon")
        if backend == "docker" and not docker_image_present(cfg.image):
            raise SandboxUnavailable(f"sandbox image {cfg.image} is not built (make sandbox-image)")
        if backend == "local-unshare" and not unshare_available():
            raise SandboxUnavailable("unshare backend requested but user/network namespaces are unavailable")
        if backend == "none":
            raise SandboxUnavailable("no isolating backend (docker or unshare) available; L4 disabled")
        self.backend = backend

    def run_check(self, source_root: Path, spec: dict) -> dict:
        """Copy the code into a fresh temp dir, run one property check, destroy everything."""
        return self._run(source_root, HARNESS, spec, timeout=self.cfg.timeout_s, network="none")

    def run_app(self, source_root: Path, spec: dict, timeout: int = 120) -> dict:
        """Start the application inside the sandbox and run localhost-only runtime checks against it."""
        return self._run(source_root, RUNTIME_HARNESS, spec, timeout=timeout, network=self.cfg.network)

    def _run(self, source_root: Path, script: Path, spec: dict, timeout: int, network: str) -> dict:
        with tempfile.TemporaryDirectory(prefix="caa-sbx-") as td:
            work = Path(td) / "src"
            shutil.copytree(source_root, work, ignore=shutil.ignore_patterns(".git", "__pycache__", ".caa",
                                                                             "node_modules", ".venv", "venv"))
            hdir = Path(td) / "harness"
            hdir.mkdir()
            shutil.copy(script, hdir / script.name)
            (hdir / "spec.json").write_text(json.dumps(spec))
            if self.backend == "docker":
                return self._exec(self.command_docker(work, hdir, script.name, network), None, None, None, timeout)
            return self._unshare(work, hdir, script.name, network, timeout)

    # -------------------------------------------------------------- backends
    def command_docker(self, work: Path, hdir: Path, script: str = "harness.py", network: str = "none") -> list[str]:
        c = self.cfg
        writable = ["-v", f"{work}:/src:rw"] if network == "egress" else ["-v", f"{work}:/src:ro"]
        return ["docker", "run", "--rm", "--network", "bridge" if network == "egress" else "none", "--read-only",
                "--cap-drop", "ALL", "--security-opt", "no-new-privileges",
                "--pids-limit", "128", "--memory", f"{c.memory_mb}m", "--cpus", str(c.cpus),
                "--user", "65534:65534", "--tmpfs", "/tmp:rw,size=64m",
                *writable, "-v", f"{hdir}:/harness:ro", "-w", "/src",
                c.image, "python", "-I", f"/harness/{script}", "/harness/spec.json"]

    def command_unshare(self, hdir: Path, script: str = "harness.py", network: str = "none") -> list[str]:
        ns = "-rn" if network == "none" else "-r"
        return ["unshare", ns, sys.executable, "-I", str(hdir / script), str(hdir / "spec.json")]

    def _unshare(self, work: Path, hdir: Path, script: str, network: str, timeout: int) -> dict:
        mem = self.cfg.memory_mb * 1024 * 1024
        cpu = timeout

        def limits():
            resource.setrlimit(resource.RLIMIT_CPU, (cpu, cpu))
            resource.setrlimit(resource.RLIMIT_AS, (mem * 8, mem * 8))   # interpreters/runtimes need address space
            resource.setrlimit(resource.RLIMIT_FSIZE, (256 * 1024 * 1024, 256 * 1024 * 1024))
            resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
            os.setsid()

        tool_dirs = {str(Path(t).resolve().parent) for t in (shutil.which("node"), shutil.which("go"),
                                                               shutil.which("npm")) if t}
        env = {"PATH": ":".join([*sorted(tool_dirs), "/usr/local/bin", "/usr/bin", "/bin"]), "HOME": str(work),
               "LANG": "C.UTF-8", "PYTHONDONTWRITEBYTECODE": "1", "GOCACHE": str(work / ".gocache"),
               "GOPATH": str(work / ".gopath")}
        if network == "egress":
            env.update({k: os.environ[k] for k in PROXY_VARS if k in os.environ})
        else:
            for p in work.rglob("*"):          # source is read-only for the check
                if p.is_file():
                    p.chmod(0o444)
        return self._exec(self.command_unshare(hdir, script, network), work, limits, env, timeout)

    def _exec(self, cmd, cwd, preexec, env, timeout: int | None = None) -> dict:
        try:
            proc = subprocess.run(cmd, cwd=cwd, preexec_fn=preexec, env=env, capture_output=True, text=True,
                                  timeout=(timeout or self.cfg.timeout_s) + 10)
        except subprocess.TimeoutExpired:
            return {"status": "inconclusive", "reason": "timeout"}
        for line in proc.stdout.splitlines():
            if line.startswith("CAA_RESULT "):
                out = json.loads(line[len("CAA_RESULT "):])
                out["backend"] = self.backend
                return out
        return {"status": "inconclusive", "reason": f"no result (rc={proc.returncode}): {proc.stderr[-400:]}",
                "backend": self.backend}
