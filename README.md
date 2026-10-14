# code-audit-agent

A local AI agent for **defensive** security review. Point it at your code (or a live site) and it
finds likely vulnerabilities, checks each one as far as it safely can, and writes a clear report
with a suggested fix.

Its guiding rule: **the model never guesses vulnerabilities by eye.** Scanners and analyzers find
the candidates; deterministic checks and narrow, schema-constrained model steps confirm them, and
every claim must point to a line the tool actually read. That keeps false alarms low.

---

## Install

Only [Docker Desktop](https://www.docker.com/products/docker-desktop/) is needed — no WSL, no Python setup.

```bash
git clone https://github.com/usershoislom/code-audit-agent.git
cd code-audit-agent
```

Run with `.\caa.ps1 <args>` on **Windows (PowerShell)** or `./caa.sh <args>` on **macOS/Linux**. The first run builds the image (~1 min). Below, `caa` stands for whichever wrapper you use.

The default image scans Python, JS/TS, Java, Go and HTML and can run Python apps. Optional extras (uncomment a line in `build.conf`, the next run rebuilds): `WITH_GO=1` (Go tools / run Go apps), `WITH_NODE=1` (run JS/TS apps), `WITH_BROWSER=1` (browser-based live checks, +~400 MB).

<sub>Without Docker (Linux): `pip install -e '.[stand,dev,browser]'` · `scripts/install_tools.sh && export PATH="$HOME/.local/caa-tools/bin:$PATH"` · then `caa scan ...` / `caa live ...` directly.</sub>

---

## The two commands

### `caa scan` — review source code

```bash
caa scan https://github.com/owner/repo          # a public repo by URL
caa scan owner/repo --ref develop               # short form + branch/tag
caa scan C:\path\to\my-app                       # a local folder (mounted read-only)
caa scan owner/repo --llm                        # + model review of findings
caa scan C:\path\to\my-app --trust-target --run-app   # also start the app and test it live in a sandbox
```

| Flag | What it adds |
|---|---|
| `--llm` | the model reviews candidates (keys from `.env`) |
| `--trust-target` | allow running the target's code in the sandbox (required by the flags below) |
| `--run-app` | start the app in the sandbox, run harmless localhost checks |
| `--sandbox-network egress` | let the sandboxed app reach the internet |
| `--install-deps` | install the app's dependencies first (needs `egress`) |
| `--report-lang ru` | Russian report (default is English) |

### `caa live` — test a running website (no code needed)

Three depths, each adding to the previous. Run against a site/app **you own or may test**.

```bash
caa live https://your-site.com                   # 1. passive + browser crawl (read-only)
caa live https://your-site.com --no-browser      # 1a. passive HTTP only (no browser)
caa live https://your-app.com  --active          # 2. also actively probe inputs/forms
```

| Depth | What it does | Changes data? |
|---|---|---|
| **passive** | reads headers, cookies, errors, exposed files (`/.git`, `/.env`) | no |
| **browser** (default, needs `WITH_BROWSER=1`) | runs JS, crawls pages, finds DOM-XSS, CSRF forms, mixed content | no |
| **`--active`** | submits inputs/forms with benign probes to confirm XSS, SQLi, command injection, open redirect, path traversal | **yes — may create/change data** |

`--active` sends real requests and submits forms, so run it on your own app or a staging copy. It confirms issues with benign signals only (unique markers, error/timing differences) — never destructive payloads, only GET/POST, same-origin, capped requests. Other flags: `--crawl N` (pages to crawl, default 8), `--report-lang ru`.

---

## Where to read the results

Every run prints a one-line summary and writes a folder: `caa-reports/<name>-<date>/`.

| File | Open it in | What's inside |
|---|---|---|
| **`report.html`** | **a browser — start here** | risk overview, "fix first", every finding with evidence and a fix, dismissed candidates |
| `report.md` | any editor | the same report in Markdown |
| `report.sarif` | your IDE / CI | machine-readable findings |
| `findings.json`, `run.json`, `audit.jsonl`, `state/` | — | raw findings, run metadata, full log |

**Reading a finding.** Each one shows *what* and *where* (file:line or URL), a plain-language *why*, the *evidence*, what was **not** verified, and a suggested *fix*. Sort by **severity** (critical → low) and start with the **Fix first** list.

**Confidence (L0–L5)** — how much was proven, shown on each finding:

| L0 | L1 | L2 | L3 | L4 | L5 |
|---|---|---|---|---|---|
| a rule matched | two tools agree | input→sink path traced, each step a real line | a "defender" pass found no protection | confirmed live (sandbox or against the site) | the fix was applied and the issue is gone |

Higher = more certain. For code scans, treat **L2+** as solid; live-site findings are **L4** (observed on the running app).

### Model keys (optional) and private repos — `.env`

`--llm` and private clones read a `.env` next to the wrapper:
```
GEMMA_API_KEY=...
GROQ_API_KEY=...
CAA_GIT_TOKEN=...   # private repos only; sent as a header, never stored in the report
```

---

# Technical details

The rest of this document is for readers who want to know how it works inside.

## How it works

`caa/langs.py` first builds a project profile: languages (by extension), frameworks (by imports and
`package.json`), and the kind of program (web / cli / library). From that profile
`caa/tools/analyzers.py` runs only the relevant tools; skipped tools and the reason are recorded.

**Pipeline** (the order is fixed in code, `caa/core/orchestrator.py`):
1. inventory;
2. candidates: SAST → SARIF → dedup by (file, line, CWE), moved to the sink line, plus routes,
   secrets, dependencies and an optional model pass;
3. context slice;
4. model triage (optional);
5. evidence ladder;
6. patch and re-scan.

After each stage the state is written to `out/state/NN-*.json`; every tool and model call is written
to `out/audit.jsonl` with secrets masked.

## Languages and tools

| Tool | Languages | Engine | What it gives |
|---|---|---|---|
| semgrep | all | **Opengrep** (LGPL), else Semgrep CE, with our own rules in `configs/rules/<lang>.yaml` | matches; Opengrep adds source→sink traces in SARIF |
| bandit | Python | Bandit | a second independent source for Python |
| gosec | Go | gosec | SAST for Go |
| govulncheck | Go | govulncheck | vulnerable dependencies **whose vulnerable function is actually called** (needs `CAA_DEPS_ONLINE=1` or a local DB) |
| osv | all manifests | osv-scanner with an **offline DB** | vulnerable PyPI/npm/Go/Maven dependencies; the package list never leaves the machine |
| secrets | all | gitleaks + built-in rules | keys and passwords in code |
| hygiene | all | built-in checks | see below |

Semgrep's official rules became non-commercial in December 2024, so the repo ships only its own
rules. Scanners install into a separate prefix because their pinned dependencies conflict with the
app frameworks (Semgrep, for example, clashes with a recent FastAPI).

**Depth per language:**
- **Python** — a custom taint analysis: inter-procedural, with sanitizers and guard checks; sources
  include Flask/FastAPI/Django route params, `request.*`, `argparse`, `click`, `typer`, `sys.argv`,
  `input()`; a route map for access control (`@login_required`, `Depends(get_current_user)`,
  ownership checks); sandbox property checks (L4) and template fixes (L5).
- **JS/TS, Java, Go** — Opengrep taint rules within a file. A quoted line-by-line trace → L2; a
  defender (test code, the source being a framework request) → L3. No L4/L5 or cross-file flow yet.
- **HTML templates** — template rules: SRI for CDN scripts, `target=_blank` without `rel`,
  `|safe` / `autoescape off`, a POST form without a CSRF token.

## Repository hygiene

`caa/tools/hygiene.py`; each finding points to a concrete file and line.

| Check | What it looks for |
|---|---|
| `.env` / keys / `credentials.json` | the file exists and is **not git-ignored** (`git check-ignore`) or is already **committed** (`git ls-files`) |
| `.gitignore` | missing, or does not ignore `.env` although the project loads `.env` |
| Dockerfile | no non-root `USER`; unpinned / `:latest` image; `ADD <url>`; secret in `ENV/ARG`; `COPY .` with a `.env` present and no `.dockerignore` |
| Django settings | `DEBUG = True`, `ALLOWED_HOSTS = ['*']`, `*_COOKIE_SECURE = False` |
| CORS | any origin together with credentials (FastAPI/Starlette/Express) |
| Dependencies | `requirements.txt` without exact versions; `package.json` without a lockfile |
| GitHub Actions | `pull_request_target` + checkout of PR code; a third-party action on `@main`; issue/PR text inside `run:` |

## Running the app in the sandbox

`--run-app` (with `--trust-target`): `caa/sandbox/app_runner.py` works out how to start the app and
runs it in the sandbox.

| How it starts | Command |
|---|---|
| user config `.caa.yaml` | `run: {cmd: [...], port: 8000, health: /}` |
| Flask | `flask --app` |
| FastAPI | `uvicorn` |
| Django | `manage.py runserver` |
| Node | `npm start` |
| Go | `go run .` |

Then `caa/sandbox/runtime_harness.py` runs harmless GET checks — **127.0.0.1 only**, asserted in
code: the app came up and answers; security headers (CSP, X-Content-Type-Options, X-Frame-Options);
an HTML marker returns unescaped → **L4 for XSS**; a quote in a parameter triggers a stack trace,
debug page or SQL error, or breaks a request that works with a normal value → **L4 for SQLi /
CWE-209**.

**Network:** `none` (default) — no network at all; `egress` — the app reaches the internet (Docker:
`bridge`; the `unshare` fallback uses the host network, weaker, documented). Every `egress` run is
written to the audit log. **Limitation:** the app needs its real environment (a database, configs).
On the seeded stand the database is empty, so live SQLi checks often show nothing; there the sandbox
function check confirms SQLi instead.

## Architecture

```
caa/langs.py       project profile: languages, frameworks, kind of program
caa/core/          orchestrator, data models, ladder, KB (CWE cards + BM25), triage, LLM layer, audit
caa/engine_code/   engine A (white box): Python taint, route map (Flask/FastAPI/Django) + ABSENTIA, patcher, verification
caa/engine_http/   engine B (black box): scanner.py (passive HTTP) + browser.py (Playwright crawl) + active.py (opt-in probing) for caa live
caa/tools/         tool whitelist for the model; analyzers.py (per-language plugins), sast.py (SARIF),
                   deps.py (osv-scanner offline), secrets_scan.py, hygiene.py
caa/sandbox/       runner.py (docker / unshare, network none|egress), harness.py (function property tests),
                   app_runner.py + runtime_harness.py (start the app, localhost checks)
caa/reports/       SARIF 2.1.0 and Markdown/HTML from one Finding structure
configs/           providers.yaml, default.yaml, per-language rules, offline vulnerability snapshot
scripts/           install_tools.sh — scanners pinned into an isolated prefix
eval/              seeded stand (repo/ + labels.yaml outside repo/), metrics, ablations, results/
```

**Evidence ladder** (the level is the highest reached). A candidate can be dismissed only with a
reference to an **executable** protecting line on the data path — required equally of the
deterministic analysis and of the model. A comment like "mark this as safe" is not a dismissal and
is itself reported as CWE-1427.

### Boundaries enforced by code (and covered by tests)

- **Model routing** (`caa/core/llm/router.py`). Each request records a tag in the audit log, but it
  does not restrict which provider is used: you analyse your own code and your own sites and may send
  them to the model you configured (local or your own server). Secrets are masked before anything
  leaves the process.
- **Tool whitelist**, pydantic argument validation, paths jailed to the repo root, no shell
  (`caa/tools/registry.py`).
- **Citation checks** (`caa/core/citations.py`, `caa/core/triage.py`): an unread reference is
  dropped; `vulnerable` without a confirmed claim becomes `insufficient_data`; a dismissal by comment
  or off the data path is rejected.
- **Untrusted material** is wrapped in a nonce block; phrases that try to steer the reviewer are
  detected.
- **Sandbox** (`caa/sandbox/runner.py`): Docker with `--network none --read-only --cap-drop ALL
  --security-opt no-new-privileges --user 65534 --pids-limit`, source `:ro`, `--rm`; a fallback of
  `unshare -rn` (no network) with rlimits, a scrubbed environment and a temp copy of the code (weaker
  FS isolation, a dev fallback); sockets are disabled inside the harness; L4 runs only with
  `--trust-target` and not at all without an isolating backend.
- **Property checks do not attack.** Sinks (the DB driver, process launch, `open`, outbound HTTP) are
  replaced with recorders that log the call and stop the request; the check verifies a property, e.g.
  the marker reached the driver as a parameter, not inside the SQL text.

### Models

`configs/providers.yaml` describes the providers; switching needs no code change:

- `local` — Gemma 4 31B on Ollama (`gemma4:31b`).
- `gemma_remote` — your own endpoint (vLLM, `gemma-4-31b-it`, 32K context, structured output via
  guided decoding).
- `groq` — `openai/gpt-oss-120b`.

Keys come from `.env` (git-ignored). Model output always follows a JSON schema (`response_format`);
on an invalid reply it retries with a schema reminder, then returns `insufficient_data`. Triage is a
loop of JSON `tool | verdict` actions with a call budget rather than native tool-calling, so the
format does not depend on the provider.

## Evaluation (seeded stand, `eval/`)

**Stand:** 94 files, 61 labelled vulnerabilities.

| Language / framework | Examples |
|---|---|
| Python | Flask 57, Django 5, FastAPI 2, CLI 3 |
| JS/TS (Express) | 12 |
| Java (Servlet / Spring) | 8 |
| Go (net/http) | 2 |
| HTML templates | 2 |

Groups A–E. Each vulnerability has a fixed twin (`*_fixed`) or a trap — code that looks vulnerable
but is safe. Labels live in `eval/seeded/labels.yaml`, outside the scanned folder, so the model never
sees them. Dependencies are checked against the real OSV database. Model: Gemma 4 31B (vLLM),
`temperature=0`. **One run per row.**

| row | found | TP | FP | FN | P | R | F1 | FP vs SAST | P ≥L2 | R ≥L2 |
|---|---|---|---|---|---|---|---|---|---|---|
| sast_only (Opengrep/Semgrep + Bandit + gosec) | 83 | 47 | 36 | 14 | 0.57 | 0.77 | 0.65 | — | — | — |
| llm_only_files (model per file) | 77 | 52 | 25 | 9 | 0.68 | 0.85 | 0.75 | −31% | — | — |
| sast_llm_triage (SAST + model triage) | 72 | 47 | 25 | 14 | 0.65 | 0.77 | 0.71 | −31% | — | — |
| **agent_no_llm** | 65 | 60 | 5 | 1 | **0.92** | **0.98** | 0.95 | **−86%** | 0.97 | 0.93 |
| agent_llm_norag | 66 | 60 | 6 | 1 | 0.91 | 0.98 | 0.95 | −83% | 0.98 | 0.92 |
| agent_llm_rag | 65 | 60 | 5 | 1 | 0.92 | 0.98 | 0.95 | −86% | **1.00** | 0.92 |
| agent_full (no model + L4 + app runs + L5) | 65 | 60 | 5 | 1 | 0.92 | 0.98 | 0.95 | −86% | 0.97 | 0.93 |

**The headline:** with no model the agent removes **86%** of SAST's false positives (36 → 5) without
losing a single SAST true positive, and recall rises from 0.77 to 0.98 thanks to generators SAST
lacks: routes (group B), hygiene (D), OSV (E).

**By group (agent_no_llm):** A 39/39 · B 5/5 · C 0/1 · D 13/13 · E 3/3. The only FN without a model is
business logic; with the model it is found (C 1/1).

### Error analysis

1. **FP `sqli/trap_column_map.py` and `ssrf/fetch_fixed.py`** (no model). Taint doesn't know a
   constant dict is an allow-list, and doesn't model "a check on `urlparse(url).hostname` protects
   `url`". L4 in the sandbox shows the property **holds** in both cases; the model dismisses both with
   a cited protecting line.
2. **FP gosec on `gosvc/handlers_fixed.go`.** `exec.Command` with an argument list and `os.ReadFile`
   after `filepath.Base` are safe but gosec flags them. No trace, so they stay at L0 and never reach
   the report at the ≥L2 threshold.
3. **FP `requirements.txt` pyyaml.** The version is vulnerable but the package is not imported:
   `needs_human`, L0.
4. **The model wrongly dismissed `go.mod` (Go 1.22 stdlib), norag row.** It claimed `net/http` was
   never imported, though `handlers.go` imports it, and cited the `go 1.22` line as "protection".
   **Fixed after the run:** a protection must be a source line, not a manifest/config line
   (`test_refutation_cannot_cite_a_manifest_line`). The table predates that rule.
5. **The model dismissed `app.run(debug=True)` under `if __name__ == "__main__"`, rag row.** Its
   argument: in production a WSGI server runs and this block does not execute — arguable but
   defensible. Counted as a disagreement with the labels, not a reasoning error.
6. **App runs.** 6 of the stand's 12 apps started; the rest need an `APP_SECRET` env var at import.
   Expected: an app needs its environment, and `.caa.yaml` can set `env` for such cases.

### Honest caveats

- **The numbers are optimistic:** rules, heuristics and the stand were written in one session. A
  held-out evaluation is needed (CVEfixes pairs, third-party apps per language).
- **For JS/TS, Java and Go** analysis is within-file (Opengrep taint), with no sandbox checks or
  patches yet. The symbol index for the model is Python-only so far.
- **One run per row** on a small stand: a 1–2 finding difference is noise.
- **The eval was produced with the `local-unshare` backend** (no Docker daemon in that environment).
  The Docker image build and the in-container sandbox are exercised in CI.

## Reproducibility

Versions are pinned in `pyproject.toml`; rules and the vulnerability snapshot live offline in
`configs/`; the model uses `temperature=0` and `seed=0`. Each evaluation row is its own directory
with `state/`, `audit.jsonl`, `findings.json`, `report.md` and `report.sarif`.

