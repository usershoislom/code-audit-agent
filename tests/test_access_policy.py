import json

from caa.core.kb import KnowledgeBase
from caa.core.llm.provider import ScriptedModel
from caa.engine_code.engine import CodeEngine
from tests.conftest import line_of


def test_llm_access_hypotheses_need_an_app_policy(stand):
    eng = CodeEngine(stand, KnowledgeBase())
    ping = line_of("cmdi/ping.py", "def ping")
    export = line_of("authz/admin.py", "def admin_export")

    def responder(purpose, messages):
        user = messages[-1]["content"]
        hyps = []
        if "# file: cmdi/ping.py" in user:
            hyps.append({"cwe": "CWE-862", "file": "cmdi/ping.py", "line": ping})
        if "# file: authz/admin.py" in user:
            hyps.append({"cwe": "CWE-862", "file": "authz/admin.py", "line": export})
        return json.dumps({"hypotheses": hyps})

    cands = eng.llm_hypotheses({}, ScriptedModel(responder=responder))
    files = {c.location.file for c in cands}
    assert "authz/admin.py" in files          # app has @admin_required siblings -> policy exists
    assert "cmdi/ping.py" not in files        # app has no access policy at all -> dropped
