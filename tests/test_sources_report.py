"""Repository URLs are cloned safely; the full report renders every section and masks secrets."""
import subprocess

import pytest

from caa.core.models import Evidence, Finding, Group, Level, Location, Ref, Status
from caa.reports.full import Report, to_html, to_markdown
from caa.sources import SourceError, _git_env, normalise_url, resolve


@pytest.mark.parametrize("bad", ["file:///etc", "ext::sh -c id", "git@github.com:a/b.git", "http://github.com/a/b",
                                 "ssh://git@github.com/a/b", "https://user:pw@github.com/a/b.git"])
def test_dangerous_or_credentialed_urls_are_refused(bad):
    with pytest.raises(SourceError):
        resolve(bad)


def test_shorthand_and_ref_validation():
    assert normalise_url("owner/repo") == "https://github.com/owner/repo.git"
    with pytest.raises(SourceError):
        resolve("https://github.com/owner/repo", ref="--upload-pack=evil")


def test_token_goes_to_env_scoped_header_not_url(monkeypatch):
    import os
    for k in [k for k in os.environ if k.startswith("GIT_CONFIG_")]:
        monkeypatch.delenv(k)
    monkeypatch.setenv("CAA_GIT_TOKEN", "tok_secret_value")
    env = _git_env("https://github.com/owner/repo.git")
    assert env["GIT_CONFIG_KEY_0"] == "http.https://github.com/.extraheader"
    assert "tok_secret_value" not in env["GIT_CONFIG_VALUE_0"]          # base64 inside the header only
    monkeypatch.delenv("CAA_GIT_TOKEN")
    monkeypatch.setenv("GITHUB_TOKEN", "unrelated")
    assert "GIT_CONFIG_KEY_0" not in _git_env("https://github.com/owner/repo.git")   # never implicit


def test_local_folder_records_commit(tmp_path):
    subprocess.run(["git", "init", "-q"], cwd=tmp_path, check=True)
    (tmp_path / "a.py").write_text("x = 1\n")
    subprocess.run(["git", "add", "."], cwd=tmp_path, check=True)
    subprocess.run(["git", "-c", "user.email=a@b", "-c", "user.name=a", "commit", "-qm", "i"], cwd=tmp_path, check=True)
    src = resolve(str(tmp_path))
    assert src.kind == "local" and len(src.commit) == 40


def _finding(fid, sev, status=Status.OPEN, level=Level.L3):
    f = Finding(title="SQL injection", cwe="CWE-89", group=Group.DATAFLOW, severity=sev, status=status,
                location=Location(file="app.py", start_line=7, function="search"),
                explanation='password = "hunter2hunter2" <script>x</script>')
    f.add_evidence(Evidence(level=level, by="taint", detail="source reaches sink", refs=[Ref(file="app.py", line=7)]))
    f.not_verified = ["no dynamic check"]
    if status == Status.REFUTED:
        f.refutation = Ref(file="app.py", line=5, note="int() neutralises the value")
    f.id = fid
    return f


@pytest.mark.parametrize("lang,heading", [("ru", "Сводка"), ("en", "Summary")])
def test_full_report_sections_and_masking(lang, heading):
    inv = {"root": "/x", "profile": {"languages": {"python": {"files": 1, "loc": 9, "frameworks": ["flask"]}},
                                      "kinds": ["web"], "manifests": []},
           "analyzers": [{"analyzer": "bandit", "status": "ran", "candidates": 2, "note": ""},
                         {"analyzer": "gosec", "status": "skipped", "candidates": 0, "note": "no matching language"}],
           "runtime": [{"app": "flask:app.py", "started": True, "boot_seconds": 0.5, "probes": 1, "network": "none"}]}
    run = {"source": {"kind": "git", "url": "https://github.com/o/r.git", "ref": "main", "commit": "a" * 40},
           "seconds": 3.2, "options": {"trust": "third_party", "llm": None, "sandbox": None}}
    rep = Report([_finding("CAA-1", "high"), _finding("CAA-2", "low", Status.REFUTED)], inv, {}, run, lang)
    md, page = to_markdown(rep), to_html(rep)
    for text in (md, page):
        assert heading in text and "CAA-1" in text and "https://github.com/o/r.git" in text
        assert "hunter2hunter2" not in text                      # secrets masked
    assert "<script>x</script>" not in page and "&lt;script&gt;" in page   # HTML escaped
    assert "gosec" in md and "flask:app.py" in md and "app.py:5" in md      # analyzers, runtime, refuted
