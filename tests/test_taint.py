import pytest

from tests.conftest import line_of

VULN = [
    ("sqli/user_lookup.py", "cur.execute", "CWE-89"),
    ("sqli/repo_layer.py", "conn.execute", "CWE-89"),          # inter-procedural via product_routes.py
    ("cmdi/convert.py", "check_output", "CWE-78"),
    ("path/denylist.py", "with open", "CWE-22"),               # deny-list does not neutralise
    ("path/prefix_unnormalised.py", "with open", "CWE-22"),    # prefix check on non-normalised path
    ("xss/greet.py", "return f", "CWE-79"),
]
SAFE = [
    ("sqli/trap_int_cast.py", "cur.execute", "CWE-89", "int()"),
    ("sqli/trap_sort_allowlist.py", "cur.execute", "CWE-89", "allow-list"),
    ("cmdi/convert_fixed.py", "check_output", "CWE-78", "regex"),     # guard lives in the caller
    ("cmdi/trap_digit_guard.py", "os.system", "CWE-78", "isdigit"),
    ("path/download_fixed.py", "with open", "CWE-22", "normalised path"),
    ("path/trap_secure_filename.py", "with open", "CWE-22", "secure_filename"),
    ("xss/greet_fixed.py", "return f", "CWE-79", "escape"),
]


@pytest.mark.parametrize("rel,needle,cwe", VULN)
def test_vulnerable_flows_are_traced(taint_engine, rel, needle, cwe):
    res = taint_engine.trace(rel, line_of(rel, needle), cwe)
    assert res.reached, res.notes
    assert res.steps[0].kind == "source" and res.steps[-1].kind == "sink"
    assert all(taint_engine.fs.ledger.verify(s.ref) for s in res.steps)


@pytest.mark.parametrize("rel,needle,cwe,why", SAFE)
def test_traps_are_refuted_with_a_code_line(taint_engine, rel, needle, cwe, why):
    res = taint_engine.trace(rel, line_of(rel, needle), cwe)
    assert not res.reached
    assert res.sanitizer is not None and why in res.sanitizer.note
    assert taint_engine.fs.ledger.is_code_line(res.sanitizer)


def test_constant_command_is_not_a_flow(taint_engine):
    rel = "cmdi/trap_constant_shell.py"
    res = taint_engine.trace(rel, line_of(rel, "subprocess.run"), "CWE-78")
    assert not res.reached and res.constant_ref is not None
