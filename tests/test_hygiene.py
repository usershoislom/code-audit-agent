import subprocess

from caa.tools.fs import RepoFS
from caa.tools.hygiene import check


def _repo(tmp_path, files: dict, tracked=()):
    subprocess.run(["git", "init", "-q"], cwd=tmp_path, check=True)
    for rel, text in files.items():
        p = tmp_path / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(text)
    if tracked:
        subprocess.run(["git", "add", "-f", *tracked], cwd=tmp_path, check=True)
    return {c.rule_id.split(".")[-1]: c for c in check(RepoFS(tmp_path))}


def test_env_not_ignored_and_gitignore_gap(tmp_path):
    got = _repo(tmp_path, {"app.py": "from dotenv import load_dotenv\n", ".env": "K=v\n", ".gitignore": "dist/\n"})
    assert "env-not-ignored" in got and "gitignore-missing-env" in got


def test_env_ignored_is_fine(tmp_path):
    got = _repo(tmp_path, {"app.py": "x = 1\n", ".env": "K=v\n", ".gitignore": ".env\n", ".env.example": "K=\n"})
    assert not got


def test_committed_env_is_reported_even_if_ignored_later(tmp_path):
    got = _repo(tmp_path, {"app.py": "x = 1\n", ".env": "K=v\n", ".gitignore": ".env\n"}, tracked=[".env"])
    assert "env-tracked" in got and got["env-tracked"].extra["severity_hint"] == "high"


def test_dockerfile_checks(tmp_path):
    got = _repo(tmp_path, {".gitignore": ".env\n", ".env": "K=v\n", "app.py": "x=1\n",
                           "Dockerfile": "FROM python:latest\nENV API_TOKEN=abcdef123456\nCOPY . .\nCMD python app.py\n"})
    assert {"docker-unpinned", "docker-root", "docker-secret-env", "dockerignore-env"} <= set(got)


def test_dockerfile_good(tmp_path):
    got = _repo(tmp_path, {".gitignore": ".env\n", "app.py": "x=1\n", ".dockerignore": ".env\n",
                           "Dockerfile": "FROM python:3.12-slim AS build\nFROM build\nCOPY . .\nUSER 10001\n"})
    assert not got


def test_github_actions_risks(tmp_path):
    wf = ("on: pull_request_target\njobs:\n  t:\n    runs-on: ubuntu-latest\n    steps:\n"
          "      - uses: actions/checkout@v4\n        with:\n          ref: ${{ github.event.pull_request.head.sha }}\n"
          "      - uses: someone/tool@main\n      - run: echo \"${{ github.event.issue.title }}\"\n")
    got = _repo(tmp_path, {".gitignore": ".env\n", ".github/workflows/ci.yml": wf})
    assert {"gha-prt-checkout", "gha-unpinned-action", "gha-script-injection"} <= set(got)


def test_settings_and_cors(tmp_path):
    got = _repo(tmp_path, {".gitignore": ".env\n",
                           "settings.py": "INSTALLED_APPS = []\nDEBUG = True\nALLOWED_HOSTS = ['*']\n",
                           "main.py": "app.add_middleware(CORSMiddleware, allow_origins=['*'], allow_credentials=True)\n",
                           "requirements.txt": "flask\nrequests==2.32.4\n"})
    assert {"django-debug", "django-hosts", "cors-credentials", "unpinned-python"} <= set(got)
