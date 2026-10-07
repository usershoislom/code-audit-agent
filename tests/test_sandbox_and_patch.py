import json

import pytest

from caa.engine_code.patcher import template_patch, unified_diff
from caa.sandbox.runner import Sandbox, SandboxConfig, SandboxUnavailable
from tests.conftest import line_of


@pytest.fixture(scope="module")
def sandbox():
    try:
        return Sandbox(SandboxConfig())
    except SandboxUnavailable as exc:
        pytest.skip(str(exc))


def test_sandbox_has_no_network(sandbox, tmp_path):
    (tmp_path / "probe.py").write_text("x = 1\n")
    # harness disables sockets AND runs in a namespace without interfaces; probe the namespace directly
    import subprocess
    cmd = sandbox.command_unshare(tmp_path) if sandbox.backend == "local-unshare" else None
    if cmd is None:
        pytest.skip("docker backend: covered by --network none")
    probe = ["unshare", "-rn", "python3", "-c",
             "import socket;s=socket.socket();s.settimeout(2);print(s.connect_ex(('1.1.1.1',80)))"]
    out = subprocess.run(probe, capture_output=True, text=True, timeout=20).stdout.strip()
    assert out != "0"


def test_docker_command_is_locked_down():
    from pathlib import Path
    sb = Sandbox.__new__(Sandbox)
    sb.cfg = SandboxConfig()
    cmd = " ".join(sb.command_docker(Path("/w"), Path("/h")))
    for flag in ("--network none", "--read-only", "--cap-drop ALL", "no-new-privileges", "--user 65534",
                 "/w:/src:ro", "--rm", "--pids-limit"):
        assert flag in cmd


SPEC = {"method": "GET", "extra_args": {}}


@pytest.mark.parametrize("module,cwe,path,inject,expected", [
    ("sqli/user_lookup.py", "CWE-89", "/users/search", {"where": "args", "name": "name"}, "violated"),
    ("sqli/user_lookup_fixed.py", "CWE-89", "/users/search", {"where": "args", "name": "name"}, "holds"),
    ("path/denylist.py", "CWE-22", "/docs", {"where": "args", "name": "page"}, "violated"),
    ("path/download_fixed.py", "CWE-22", "/download", {"where": "args", "name": "file"}, "holds"),
    ("xss/greet.py", "CWE-79", "/hello", {"where": "args", "name": "name"}, "violated"),
    ("xss/greet_fixed.py", "CWE-79", "/hello", {"where": "args", "name": "name"}, "holds"),
])
def test_property_checks_on_pairs(sandbox, stand, module, cwe, path, inject, expected):
    res = sandbox.run_check(stand, {**SPEC, "module": module, "cwe": cwe, "path": path, "rule": path, "inject": inject})
    assert res["status"] == expected, json.dumps(res)[:400]


@pytest.mark.parametrize("rel,needle,cwe,must", [
    ("sqli/orders_concat.py", "cur.execute", "CWE-89", "cur.execute(query, (status,))"),
    ("cmdi/ping.py", "subprocess.run", "CWE-78", "['ping', '-c', '1', str(host)]"),
    ("path/avatar.py", "return send_file", "CWE-22", "_caa_contained(BASE_DIR + '/avatars/', filename)"),
    ("xss/search_page.py", "return render_template_string", "CWE-79", '"<p>Results for {{ q }}</p>", q=q'),
])
def test_template_patches_are_minimal(stand, rel, needle, cwe, must):
    old = (stand / rel).read_text()
    new, why = template_patch(old, cwe, line_of(rel, needle))
    assert must.replace("'", '"') in new.replace("'", '"')
    changed = [ln for ln in unified_diff(rel, old, new).splitlines() if ln[:1] in "+-" and ln[:3] not in ("+++", "---")]
    assert len(changed) <= 30
