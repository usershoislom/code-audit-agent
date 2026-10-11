"""Language detection, per-language analyzers, Python framework entry points."""
import shutil

import pytest

from caa.core.kb import KnowledgeBase
from caa.engine_code.engine import CodeEngine
from caa.langs import detect
from caa.tools.fs import RepoFS
from tests.conftest import line_of


def test_profile_detects_languages_frameworks_and_kinds(stand):
    prof = detect(RepoFS(stand))
    assert {"python", "javascript", "typescript", "java", "go", "html"} <= set(prof.languages)
    assert {"flask", "django", "fastapi", "argparse"} <= set(prof.languages["python"].frameworks)
    assert "express" in prof.languages["javascript"].frameworks
    assert {"spring", "servlet"} <= set(prof.languages["java"].frameworks)
    assert "net/http" in prof.languages["go"].frameworks
    assert {"web", "cli"} <= set(prof.kinds)


@pytest.mark.parametrize("rel,needle,cwe", [
    ("django_app/notes/views.py", "return HttpResponse", "CWE-79"),      # Django view registered in urls.py
    ("fastapi_app/main.py", "row = get_db().execute(f", "CWE-89"),       # FastAPI path parameter
    ("cli_tool/grep_logs.py", "subprocess.run(", "CWE-78"),             # argparse namespace
    ("cli_tool/report.py", "conn.execute(", "CWE-89"),                  # sys.argv
])
def test_python_framework_and_cli_sources(stand, rel, needle, cwe):
    eng = CodeEngine(stand, KnowledgeBase())
    res = eng.taint.trace(rel, line_of(rel, needle), cwe)
    assert res.reached, res.notes


def test_fastapi_and_django_access_policy(stand):
    eng = CodeEngine(stand, KnowledgeBase())
    by = {(r.file, r.func): r for r in eng.routes.routes}
    assert by[("fastapi_app/main.py", "read_order")].auth is not None            # Depends(get_current_user)
    assert by[("fastapi_app/main.py", "order_invoice")].ownership                # owner comparison + raise
    assert by[("fastapi_app/main_fixed.py", "read_order")].ownership             # owner-scoped query
    assert by[("django_app/notes/views.py", "note_edit")].ownership              # get_object_or_404(owner=...)
    assert not by[("django_app/notes/views.py", "note_detail")].ownership


@pytest.mark.skipif(not shutil.which("opengrep"), reason="opengrep provides data-flow traces")
def test_non_python_findings_get_traces(stand, tmp_path):
    # small copy: only the JS/Java/Go cases
    for d in ("js", "java", "gosvc"):
        shutil.copytree(stand / d, tmp_path / d)
    from caa.core.orchestrator import Orchestrator, PipelineOptions
    kb = KnowledgeBase()
    eng = CodeEngine(tmp_path, kb, generators={"semgrep"})
    res = Orchestrator(eng, kb, PipelineOptions(use_patch=False), None).run()
    traced = {(f.location.file, f.cwe): f for f in res.findings if f.dataflow}
    assert ("js/users.js", "CWE-89") in traced
    assert ("java/src/UserServlet.java", "CWE-89") in traced
    assert ("gosvc/handlers.go", "CWE-78") in traced
    f = traced[("gosvc/handlers.go", "CWE-78")]
    assert f.level >= 3 and f.dataflow[0].kind == "source"
    assert not any(f.location.file.endswith(("_fixed.js", "Fixed.java", "_fixed.go")) and f.dataflow
                   for f in res.findings)
