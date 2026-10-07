# Seeded stand: agent_llm_norag

Target: `/home/user/code-audit-agent/eval/seeded/repo`  
Findings: **52 open** (3 need human review), 31 candidates refuted with a cited protection.

Confidence is the highest evidence level reached: L0 pattern · L1 independent agreement · L2 trace · L3 refutation failed · L4 harmless dynamic check · L5 patch verified.

| ID | Level | Severity | CWE | Location | Title | Status |
|---|---|---|---|---|---|---|
| CAA-8df85eaf | L3 | high | CWE-862 | `authz/admin.py:47` | Missing authorization | open |
| CAA-97e0f907 | L3 | high | CWE-639 | `authz/invoices.py:44` | Insecure direct object reference | open |
| CAA-33645f88 | L3 | high | CWE-639 | `authz/notes.py:51` | Insecure direct object reference | open |
| CAA-b523c835 | L3 | high | CWE-862 | `cmdi/archive.py:12` | Missing authorization | open |
| CAA-b203c778 | L3 | high | CWE-78 | `cmdi/archive.py:14` | OS command injection | open |
| CAA-641375f9 | L3 | high | CWE-862 | `cmdi/archive_fixed.py:12` | Missing authorization | open |
| CAA-bc2556a7 | L3 | high | CWE-78 | `cmdi/convert.py:13` | OS command injection | open |
| CAA-a77753d7 | L3 | high | CWE-639 | `cmdi/convert.py:18` | Insecure direct object reference | open |
| CAA-45e2ee0d | L3 | high | CWE-862 | `cmdi/convert_fixed.py:17` | Missing authorization | open |
| CAA-0dd7660a | L3 | high | CWE-639 | `cmdi/convert_fixed.py:18` | Insecure direct object reference | open |
| CAA-1abe4edd | L3 | high | CWE-78 | `cmdi/ping.py:14` | OS command injection | open |
| CAA-5b8e563d | L3 | high | CWE-862 | `cmdi/trap_constant_shell.py:14` | Missing authorization | open |
| CAA-1bf083d2 | L3 | high | CWE-639 | `cmdi/trap_digit_guard.py:12` | Insecure direct object reference | open |
| CAA-c487cfac | L3 | high | CWE-862 | `cmdi/trap_digit_guard.py:12` | Missing authorization | open |
| CAA-8cc39187 | L3 | high | CWE-798 | `config/settings.py:6` | Hard-coded credential | open |
| CAA-f06f1bc4 | L3 | high | CWE-798 | `config/settings.py:7` | Hard-coded credential | open |
| CAA-6dc56888 | L3 | high | CWE-798 | `config/settings.py:8` | Hard-coded credential | open |
| CAA-3dcf722d | L3 | high | CWE-22 | `path/avatar.py:12` | Path traversal | open |
| CAA-20ce532d | L3 | high | CWE-639 | `path/avatar.py:12` | Insecure direct object reference | open |
| CAA-9380f86c | L3 | high | CWE-22 | `path/denylist.py:15` | Path traversal | open |
| CAA-1afe4263 | L3 | high | CWE-639 | `path/denylist.py:15` | Insecure direct object reference | open |
| CAA-4e616929 | L3 | high | CWE-22 | `path/download.py:13` | Path traversal | open |
| CAA-e4363cb9 | L3 | high | CWE-639 | `path/download.py:13` | Insecure direct object reference | open |
| CAA-c1bc20ab | L3 | high | CWE-639 | `path/prefix_unnormalised.py:14` | Insecure direct object reference | open |
| CAA-e0caae90 | L3 | high | CWE-22 | `path/prefix_unnormalised.py:16` | Path traversal | open |
| CAA-eb33afac | L3 | high | CWE-639 | `path/trap_basename.py:12` | Insecure direct object reference | open |
| CAA-366c7008 | L3 | high | CWE-639 | `path/trap_secure_filename.py:11` | Insecure direct object reference | open |
| CAA-f1d51ac6 | L3 | high | CWE-862 | `sqli/injected_comment.py:13` | Missing authorization | open |
| CAA-8438defd | L3 | high | CWE-89 | `sqli/injected_comment.py:17` | SQL injection | open |
| CAA-03fc9de8 | L3 | high | CWE-862 | `sqli/orders_concat.py:13` | Missing authorization | open |
| CAA-394c76d5 | L3 | high | CWE-89 | `sqli/orders_concat.py:17` | SQL injection | open |
| CAA-529deed0 | L3 | high | CWE-862 | `sqli/orders_concat_fixed.py:13` | Missing authorization | open |
| CAA-8b6f3dd1 | L3 | high | CWE-89 | `sqli/repo_layer.py:7` | SQL injection | open |
| CAA-f616d787 | L3 | high | CWE-862 | `sqli/report_percent.py:13` | Missing authorization | open |
| CAA-0067bc10 | L3 | high | CWE-89 | `sqli/report_percent.py:16` | SQL injection | open |
| CAA-eeb6892d | L3 | high | CWE-862 | `sqli/trap_column_map.py:15` | Missing authorization | open |
| CAA-2c652a02 | L3 | high | CWE-862 | `sqli/trap_constant_table.py:15` | Missing authorization | open |
| CAA-4910ef02 | L3 | high | CWE-862 | `sqli/trap_int_cast.py:13` | Missing authorization | open |
| CAA-17b22d9a | L3 | high | CWE-862 | `sqli/trap_sort_allowlist.py:15` | Missing authorization | open |
| CAA-875d5129 | L3 | high | CWE-89 | `sqli/user_lookup.py:16` | SQL injection | open |
| CAA-3222ecae | L3 | high | CWE-862 | `sqli/user_lookup_fixed.py:13` | Missing authorization | open |
| CAA-ca849552 | L3 | high | CWE-918 | `ssrf/fetch.py:13` | Server-side request forgery | open |
| CAA-85569570 | L3 | medium | CWE-79 | `xss/comment.py:10` | Cross-site scripting | open |
| CAA-8537ace4 | L3 | medium | CWE-79 | `xss/greet.py:10` | Cross-site scripting | open |
| CAA-d1f7588b | L3 | medium | CWE-79 | `xss/search_page.py:10` | Cross-site scripting | open |
| CAA-4db4bc61 | L2 | medium | CWE-327 | `config/settings.py:12` | Weak cryptographic hash | open |
| CAA-85a78868 | L2 | medium | CWE-489 | `config/settings.py:16` | Debug mode enabled | open |
| CAA-d4f29ffa | L2 | medium | CWE-1395 | `requirements.txt:1` | Vulnerable dependency | open |
| CAA-7c0b6c3a | L2 | low | CWE-1427 | `sqli/injected_comment.py:15` | Prompt-injection text aimed at AI reviewers | open |
| CAA-d7c8351b | L0 | low | CWE-840 | `logic/checkout.py:12` | Business logic flaw | needs_human |
| CAA-f89f33db | L0 | low | CWE-1395 | `requirements.txt:2` | Vulnerable dependency | needs_human |
| CAA-23755123 | L0 | low | CWE-840 | `ssrf/fetch.py:13` | Business logic flaw | needs_human |

## CAA-8df85eaf — Missing authorization (CWE-862)

- **Location:** `authz/admin.py:47` in `admin_export()`
- **Mapping:** A01:2021 Broken Access Control; ASVS V4.1.3
- **Severity:** high — impact: A sensitive action can be called without the authentication/role check its sibling endpoints have. | reachable from an HTTP route (evidence L3)
- **Confidence:** L3 (open); reported by authz-routes, llm-entrypoints

**Why it is a risk.** GET /admin/export has no authentication while 2 comparable route(s) require it

**Data flow (verified references):**

1. `source` `authz/admin.py:46` — `@app.route("/admin/export")` (route)

**Evidence ladder:**

- L0 [authz-routes,llm-entrypoints] pattern match: caa.authz.missing-auth-vs-siblings — `authz/admin.py:47`
- L1 [agreement] independent sources agree on place and CWE: authz-routes, llm-entrypoints
- L1 [route-policy] two hints: handler lacks the check AND a sibling of the same resource has it — `authz/admin.py:46`, `authz/admin.py:34`
- L2 [route-map] no authentication decorator or inline check — `authz/admin.py:46`, `authz/admin.py:34`
- L3 [defender] no global hook, no ownership check in handler, callees or decorators — `authz/admin.py:46`

**Model triage:** insufficient_data — 

**Not verified:**

- no dynamic (L4) confirmation was performed
- scope: first-party code only; framework and driver behaviour assumed as documented

## CAA-97e0f907 — Insecure direct object reference (CWE-639)

- **Location:** `authz/invoices.py:44` in `invoice_json()`
- **Mapping:** A01:2021 Broken Access Control; ASVS V4.2.1
- **Severity:** high — impact: A logged-in user reads or changes another user's object by changing an identifier. | reachable from an HTTP route (evidence L3)
- **Confidence:** L3 (open); reported by llm-entrypoints, authz-routes

**Data flow (verified references):**

1. `source` `authz/invoices.py:42` — `@app.route("/api/invoices/<int:invoice_id>")` (route)
2. `sink` `authz/invoices.py:45` — `    row = get_db().execute("SELECT id, amount, customer FROM invoices WHERE id = ?", (invoice_id,)).fetchone()` (get_db().execute('SELECT id, amount, customer FROM invoices WHERE id = ?', (invoice_id,)))

**Evidence ladder:**

- L0 [llm-entrypoints] pattern match: caa.llm.entrypoint — `authz/invoices.py:44`
- L1 [agreement] independent sources agree on place and CWE: authz-routes, llm-entrypoints
- L2 [route-map] object loaded by client id without owner filter or ownership comparison — `authz/invoices.py:42`, `authz/invoices.py:45`
- L3 [defender] no global hook, no ownership check in handler, callees or decorators — `authz/invoices.py:42`

**Model triage:** insufficient_data — 

**Not verified:**

- no dynamic (L4) confirmation was performed
- scope: first-party code only; framework and driver behaviour assumed as documented

## CAA-33645f88 — Insecure direct object reference (CWE-639)

- **Location:** `authz/notes.py:51` in `delete_note()`
- **Mapping:** A01:2021 Broken Access Control; ASVS V4.2.1
- **Severity:** high — impact: A logged-in user reads or changes another user's object by changing an identifier. | reachable from an HTTP route (evidence L3)
- **Confidence:** L3 (open); reported by llm-entrypoints, authz-routes

**Data flow (verified references):**

1. `source` `authz/notes.py:49` — `@app.route("/notes/<int:note_id>/delete", methods=["POST"])` (route)
2. `sink` `authz/notes.py:53` — `    db.execute("DELETE FROM notes WHERE id = ?", (note_id,))` (db.execute('DELETE FROM notes WHERE id = ?', (note_id,)))

**Evidence ladder:**

- L0 [llm-entrypoints] pattern match: caa.llm.entrypoint — `authz/notes.py:51`
- L1 [agreement] independent sources agree on place and CWE: authz-routes, llm-entrypoints
- L2 [route-map] object loaded by client id without owner filter or ownership comparison — `authz/notes.py:49`, `authz/notes.py:53`
- L3 [defender] no global hook, no ownership check in handler, callees or decorators — `authz/notes.py:49`

**Model triage:** insufficient_data — 

**Not verified:**

- no dynamic (L4) confirmation was performed
- scope: first-party code only; framework and driver behaviour assumed as documented

## CAA-b523c835 — Missing authorization (CWE-862)

- **Location:** `cmdi/archive.py:12` in `backup()`
- **Mapping:** A01:2021 Broken Access Control; ASVS V4.1.3
- **Severity:** high — impact: A sensitive action can be called without the authentication/role check its sibling endpoints have. | reachable from an HTTP route (evidence L3)
- **Confidence:** L3 (open); reported by llm-entrypoints, llm

**Data flow (verified references):**

1. `source` `cmdi/archive.py:11` — `@app.route("/backup", methods=["POST"])` (route)

**Evidence ladder:**

- L0 [llm-entrypoints] pattern match: caa.llm.entrypoint — `cmdi/archive.py:12`
- L1 [llm-triage] model agrees, with verified citations — `cmdi/archive.py:11`, `cmdi/archive.py:12`
- L2 [route-map] no authentication decorator or inline check — `cmdi/archive.py:11`
- L3 [defender] no global hook, no ownership check in handler, callees or decorators — `cmdi/archive.py:11`

**Model triage:** vulnerable — The `/backup` route in `cmdi/archive.py` is exposed to the public without any authentication or authorization mechanisms. Any user can trigger the `backup()` function, which executes a system command (`os.system`). This is a clear case of Missing Authorization (CWE-862). Additionally, the function is vulnerable to command injection, but the reported issue is specifically about the lack of authoriz

**Not verified:**

- no dynamic (L4) confirmation was performed
- scope: first-party code only; framework and driver behaviour assumed as documented

## CAA-b203c778 — OS command injection (CWE-78)

- **Location:** `cmdi/archive.py:14` in `backup()`
- **Mapping:** A03:2021 Injection; ASVS V5.3.8
- **Severity:** high — impact: Shell metacharacters in user input run arbitrary commands with the service's privileges. | reachable from an HTTP route (evidence L3)
- **Confidence:** L3 (open); reported by semgrep, bandit

**Why it is a risk.** Command executed through a shell with a non-constant command string.

**Data flow (verified references):**

1. `source` `cmdi/archive.py:13` — `name = request.form.get("name", "backup")` (request.form.get('name', 'backup'))
2. `sink` `cmdi/archive.py:14` — `os.system("tar czf /var/backups/" + name + ".tgz /srv/data")`

**Evidence ladder:**

- L0 [semgrep,bandit] pattern match: caa.python.cmdi.shell — `cmdi/archive.py:14`
- L1 [agreement] independent sources agree on place and CWE: bandit, semgrep
- L2 [taint] source request.form.get('name', 'backup') reaches sink with no sanitizer — `cmdi/archive.py:13`, `cmdi/archive.py:14`
- L3 [defender] refutation failed: entry backup() is a route, no sanitizer on the path, no global input filter, not test code — `cmdi/archive.py:13`, `cmdi/archive.py:14`

**Model triage:** insufficient_data — 

**Not verified:**

- 1 model claim(s) discarded: cited lines were never read
- no dynamic (L4) confirmation was performed
- scope: first-party code only; framework and driver behaviour assumed as documented

## CAA-641375f9 — Missing authorization (CWE-862)

- **Location:** `cmdi/archive_fixed.py:12` in `backup()`
- **Mapping:** A01:2021 Broken Access Control; ASVS V4.1.3
- **Severity:** high — impact: A sensitive action can be called without the authentication/role check its sibling endpoints have. | reachable from an HTTP route (evidence L3)
- **Confidence:** L3 (open); reported by llm-entrypoints

**Why it is a risk.** Missing Authorization for Backup Functionality

**Data flow (verified references):**

1. `source` `cmdi/archive_fixed.py:11` — `@app.route("/backup", methods=["POST"])` (route)

**Evidence ladder:**

- L0 [llm-entrypoints] pattern match: caa.llm.entrypoint — `cmdi/archive_fixed.py:12`
- L2 [route-map] no authentication decorator or inline check — `cmdi/archive_fixed.py:11`
- L3 [defender] no global hook, no ownership check in handler, callees or decorators — `cmdi/archive_fixed.py:11`

**Model triage:** insufficient_data — 

**Not verified:**

- no dynamic (L4) confirmation was performed
- scope: first-party code only; framework and driver behaviour assumed as documented

## CAA-bc2556a7 — OS command injection (CWE-78)

- **Location:** `cmdi/convert.py:13` in `convert_image()`
- **Mapping:** A03:2021 Injection; ASVS V5.3.8
- **Severity:** high — impact: Shell metacharacters in user input run arbitrary commands with the service's privileges. | reachable from an HTTP route (evidence L3)
- **Confidence:** L3 (open); reported by semgrep, bandit

**Why it is a risk.** Command executed through a shell with a non-constant command string.

**Data flow (verified references):**

1. `source` `cmdi/convert.py:18` — `return convert_image(request.args["file"], request.args.get("fmt", "png"))` (request.args['file'])
2. `call` `cmdi/convert.py:18` — `return convert_image(request.args["file"], request.args.get("fmt", "png"))` (convert_image(src=...))
3. `propagation` `cmdi/convert.py:12` — `cmd = "convert /srv/uploads/%s /srv/out/image.%s" % (src, fmt)`
4. `sink` `cmdi/convert.py:13` — `return subprocess.check_output(cmd, shell=True)`

**Evidence ladder:**

- L0 [semgrep,bandit] pattern match: caa.python.cmdi.shell — `cmdi/convert.py:13`
- L1 [agreement] independent sources agree on place and CWE: bandit, semgrep
- L2 [taint] source request.args['file'] reaches sink with no sanitizer — `cmdi/convert.py:18`, `cmdi/convert.py:18`, `cmdi/convert.py:12`, `cmdi/convert.py:13`
- L3 [defender] refutation failed: entry convert() is a route, no sanitizer on the path, no global input filter, not test code — `cmdi/convert.py:18`, `cmdi/convert.py:13`

**Model triage:** insufficient_data — 

**Not verified:**

- no dynamic (L4) confirmation was performed
- scope: first-party code only; framework and driver behaviour assumed as documented

## CAA-a77753d7 — Insecure direct object reference (CWE-639)

- **Location:** `cmdi/convert.py:18` in `convert()`
- **Mapping:** A01:2021 Broken Access Control; ASVS V4.2.1
- **Severity:** high — impact: A logged-in user reads or changes another user's object by changing an identifier. | reachable from an HTTP route (evidence L3)
- **Confidence:** L3 (open); reported by llm-entrypoints, llm

**Data flow (verified references):**

1. `source` `cmdi/convert.py:16` — `@app.route("/convert")` (route)

**Evidence ladder:**

- L0 [llm-entrypoints] pattern match: caa.llm.entrypoint — `cmdi/convert.py:18`
- L1 [llm-triage] model agrees, with verified citations — `cmdi/convert.py:18`
- L2 [route-map] object loaded by client id without owner filter or ownership comparison — `cmdi/convert.py:16`
- L3 [defender] no global hook, no ownership check in handler, callees or decorators — `cmdi/convert.py:16`

**Model triage:** vulnerable — The endpoint '/convert' allows any user to specify a filename via the 'file' parameter, which is then used to construct a path to a file in '/srv/uploads/' (cmdi/convert.py:12). Since there is no authentication or authorization check to ensure the user owns the requested file, this is an Insecure Direct Object Reference (IDOR). Additionally, the code is critically vulnerable to Command Injection b

**Not verified:**

- no dynamic (L4) confirmation was performed
- scope: first-party code only; framework and driver behaviour assumed as documented

## CAA-45e2ee0d — Missing authorization (CWE-862)

- **Location:** `cmdi/convert_fixed.py:17` in `convert()`
- **Mapping:** A01:2021 Broken Access Control; ASVS V4.1.3
- **Severity:** high — impact: A sensitive action can be called without the authentication/role check its sibling endpoints have. | reachable from an HTTP route (evidence L3)
- **Confidence:** L3 (open); reported by llm-entrypoints

**Data flow (verified references):**

1. `source` `cmdi/convert_fixed.py:16` — `@app.route("/convert")` (route)

**Evidence ladder:**

- L0 [llm-entrypoints] pattern match: caa.llm.entrypoint — `cmdi/convert_fixed.py:17`
- L2 [route-map] no authentication decorator or inline check — `cmdi/convert_fixed.py:16`
- L3 [defender] no global hook, no ownership check in handler, callees or decorators — `cmdi/convert_fixed.py:16`

**Model triage:** insufficient_data — 

**Not verified:**

- no dynamic (L4) confirmation was performed
- scope: first-party code only; framework and driver behaviour assumed as documented

## CAA-0dd7660a — Insecure direct object reference (CWE-639)

- **Location:** `cmdi/convert_fixed.py:18` in `convert()`
- **Mapping:** A01:2021 Broken Access Control; ASVS V4.2.1
- **Severity:** high — impact: A logged-in user reads or changes another user's object by changing an identifier. | reachable from an HTTP route (evidence L3)
- **Confidence:** L3 (open); reported by llm-entrypoints, llm

**Data flow (verified references):**

1. `source` `cmdi/convert_fixed.py:16` — `@app.route("/convert")` (route)

**Evidence ladder:**

- L0 [llm-entrypoints] pattern match: caa.llm.entrypoint — `cmdi/convert_fixed.py:18`
- L1 [llm-triage] model agrees, with verified citations — `cmdi/convert_fixed.py:18`, `cmdi/convert_fixed.py:12`, `cmdi/convert_fixed.py:17`
- L2 [route-map] object loaded by client id without owner filter or ownership comparison — `cmdi/convert_fixed.py:16`
- L3 [defender] no global hook, no ownership check in handler, callees or decorators — `cmdi/convert_fixed.py:16`

**Model triage:** vulnerable — The application allows any user to specify a filename to be processed from the '/srv/uploads/' directory. While there is a regex check to prevent path traversal (CWE-22) and command injection, there is no authorization check to ensure that the user requesting the conversion has the right to access the specified file. This is a classic Insecure Direct Object Reference (IDOR) vulnerability (CWE-639)

**Not verified:**

- no dynamic (L4) confirmation was performed
- scope: first-party code only; framework and driver behaviour assumed as documented

## CAA-1abe4edd — OS command injection (CWE-78)

- **Location:** `cmdi/ping.py:14` in `ping()`
- **Mapping:** A03:2021 Injection; ASVS V5.3.8
- **Severity:** high — impact: Shell metacharacters in user input run arbitrary commands with the service's privileges. | reachable from an HTTP route (evidence L3)
- **Confidence:** L3 (open); reported by semgrep, bandit, llm

**Why it is a risk.** Command executed through a shell with a non-constant command string.

**Data flow (verified references):**

1. `source` `cmdi/ping.py:13` — `host = request.args.get("host", "127.0.0.1")` (request.args.get('host', '127.0.0.1'))
2. `sink` `cmdi/ping.py:14` — `out = subprocess.run(f"ping -c 1 {host}", shell=True, capture_output=True, text=True)`

**Evidence ladder:**

- L0 [semgrep,bandit] pattern match: caa.python.cmdi.shell — `cmdi/ping.py:14`
- L1 [agreement] independent sources agree on place and CWE: bandit, semgrep
- L1 [llm-triage] model agrees, with verified citations — `cmdi/ping.py:13`, `cmdi/ping.py:14`
- L2 [taint] source request.args.get('host', '127.0.0.1') reaches sink with no sanitizer — `cmdi/ping.py:13`, `cmdi/ping.py:14`
- L3 [defender] refutation failed: entry ping() is a route, no sanitizer on the path, no global input filter, not test code — `cmdi/ping.py:13`, `cmdi/ping.py:14`

**Model triage:** vulnerable — 

**Not verified:**

- no dynamic (L4) confirmation was performed
- scope: first-party code only; framework and driver behaviour assumed as documented

## CAA-5b8e563d — Missing authorization (CWE-862)

- **Location:** `cmdi/trap_constant_shell.py:14` in `disk()`
- **Mapping:** A01:2021 Broken Access Control; ASVS V4.1.3
- **Severity:** high — impact: A sensitive action can be called without the authentication/role check its sibling endpoints have. | reachable from an HTTP route (evidence L3)
- **Confidence:** L3 (open); reported by llm-entrypoints, llm

**Data flow (verified references):**

1. `source` `cmdi/trap_constant_shell.py:13` — `@app.route("/diag/disk")` (route)

**Evidence ladder:**

- L0 [llm-entrypoints] pattern match: caa.llm.entrypoint — `cmdi/trap_constant_shell.py:14`
- L1 [llm-triage] model agrees, with verified citations — `cmdi/trap_constant_shell.py:13`, `cmdi/trap_constant_shell.py:14`, `cmdi/trap_constant_shell.py:14`
- L2 [route-map] no authentication decorator or inline check — `cmdi/trap_constant_shell.py:13`
- L3 [defender] no global hook, no ownership check in handler, callees or decorators — `cmdi/trap_constant_shell.py:13`

**Model triage:** vulnerable — 

**Not verified:**

- no dynamic (L4) confirmation was performed
- scope: first-party code only; framework and driver behaviour assumed as documented

## CAA-1bf083d2 — Insecure direct object reference (CWE-639)

- **Location:** `cmdi/trap_digit_guard.py:12` in `kill_job()`
- **Mapping:** A01:2021 Broken Access Control; ASVS V4.2.1
- **Severity:** high — impact: A logged-in user reads or changes another user's object by changing an identifier. | reachable from an HTTP route (evidence L3)
- **Confidence:** L3 (open); reported by llm-entrypoints

**Data flow (verified references):**

1. `source` `cmdi/trap_digit_guard.py:11` — `@app.route("/jobs/kill", methods=["POST"])` (route)

**Evidence ladder:**

- L0 [llm-entrypoints] pattern match: caa.llm.entrypoint — `cmdi/trap_digit_guard.py:12`
- L2 [route-map] object loaded by client id without owner filter or ownership comparison — `cmdi/trap_digit_guard.py:11`
- L3 [defender] no global hook, no ownership check in handler, callees or decorators — `cmdi/trap_digit_guard.py:11`

**Model triage:** insufficient_data — 

**Not verified:**

- no dynamic (L4) confirmation was performed
- scope: first-party code only; framework and driver behaviour assumed as documented

## CAA-c487cfac — Missing authorization (CWE-862)

- **Location:** `cmdi/trap_digit_guard.py:12` in `kill_job()`
- **Mapping:** A01:2021 Broken Access Control; ASVS V4.1.3
- **Severity:** high — impact: A sensitive action can be called without the authentication/role check its sibling endpoints have. | reachable from an HTTP route (evidence L3)
- **Confidence:** L3 (open); reported by llm-entrypoints

**Data flow (verified references):**

1. `source` `cmdi/trap_digit_guard.py:11` — `@app.route("/jobs/kill", methods=["POST"])` (route)

**Evidence ladder:**

- L0 [llm-entrypoints] pattern match: caa.llm.entrypoint — `cmdi/trap_digit_guard.py:12`
- L2 [route-map] no authentication decorator or inline check — `cmdi/trap_digit_guard.py:11`
- L3 [defender] no global hook, no ownership check in handler, callees or decorators — `cmdi/trap_digit_guard.py:11`

**Model triage:** insufficient_data — 

**Not verified:**

- no dynamic (L4) confirmation was performed
- scope: first-party code only; framework and driver behaviour assumed as documented

## CAA-8cc39187 — Hard-coded credential (CWE-798)

- **Location:** `config/settings.py:6`
- **Mapping:** A07:2021 Identification and Authentication Failures; ASVS V2.10.4
- **Severity:** high — impact: Anyone with the code (or a leaked artifact) holds the credential. | reachable from an HTTP route (evidence L3)
- **Confidence:** L3 (open); reported by semgrep, bandit

**Why it is a risk.** Credential-like value hard-coded in source.

**Evidence ladder:**

- L0 [semgrep,bandit] pattern match: caa.python.secrets.hardcoded-credential — `config/settings.py:6`
- L1 [agreement] independent sources agree on place and CWE: bandit, semgrep
- L2 [line-check] literal credential at the cited line (s3cr3t-Flask...) — `config/settings.py:6`
- L3 [defender] not a placeholder, not test code, not read from the environment — `config/settings.py:6`

**Model triage:** insufficient_data — 

**Not verified:**

- whether the credential is live/rotated was not checked
- scope: first-party code only; framework and driver behaviour assumed as documented

## CAA-f06f1bc4 — Hard-coded credential (CWE-798)

- **Location:** `config/settings.py:7`
- **Mapping:** A07:2021 Identification and Authentication Failures; ASVS V2.10.4
- **Severity:** high — impact: Anyone with the code (or a leaked artifact) holds the credential. | reachable from an HTTP route (evidence L3)
- **Confidence:** L3 (open); reported by secrets

**Why it is a risk.** Possible hard-coded secret (aws-access-key-id)

**Evidence ladder:**

- L0 [secrets] pattern match: secrets.aws-access-key-id — `config/settings.py:7`
- L2 [line-check] literal credential at the cited line (AKIA****[20]...) — `config/settings.py:7`
- L3 [defender] not a placeholder, not test code, not read from the environment — `config/settings.py:7`

**Model triage:** insufficient_data — 

**Not verified:**

- whether the credential is live/rotated was not checked
- scope: first-party code only; framework and driver behaviour assumed as documented

## CAA-6dc56888 — Hard-coded credential (CWE-798)

- **Location:** `config/settings.py:8`
- **Mapping:** A07:2021 Identification and Authentication Failures; ASVS V2.10.4
- **Severity:** high — impact: Anyone with the code (or a leaked artifact) holds the credential. | reachable from an HTTP route (evidence L3)
- **Confidence:** L3 (open); reported by bandit

**Why it is a risk.** Possible hardcoded password: 'Wint****[18]'

**Evidence ladder:**

- L0 [bandit] pattern match: bandit.B105.hardcoded_password_string — `config/settings.py:8`
- L2 [line-check] literal credential at the cited line (Wint3r!Maile...) — `config/settings.py:8`
- L3 [defender] not a placeholder, not test code, not read from the environment — `config/settings.py:8`

**Model triage:** insufficient_data — The variable `smtp_password` is hard-coded in `config/settings.py:8`. I searched the entire codebase for usages of `smtp_password` using `search(pattern='smtp_password', glob='**')`, and it only appears in the definition in `config/settings.py` and in a fixed version in `config/settings_fixed.py`. Since I cannot find any code that actually uses this credential, I cannot confirm that the vulnerabil

**Not verified:**

- whether the credential is live/rotated was not checked
- scope: first-party code only; framework and driver behaviour assumed as documented

## CAA-3dcf722d — Path traversal (CWE-22)

- **Location:** `path/avatar.py:12` in `avatar()`
- **Mapping:** A01:2021 Broken Access Control; ASVS V12.3.1
- **Severity:** high — impact: '../' sequences or absolute paths let a client read or overwrite files outside the intended directory. | reachable from an HTTP route (evidence L3)
- **Confidence:** L3 (open); reported by semgrep, llm

**Why it is a risk.** File path built from a non-constant value is opened or served.

**Data flow (verified references):**

1. `source` `path/avatar.py:11` — `def avatar(filename):` (route parameter <filename>)
2. `sink` `path/avatar.py:12` — `return send_file(BASE_DIR + "/avatars/" + filename)`

**Evidence ladder:**

- L0 [semgrep] pattern match: caa.python.path.user-path-open — `path/avatar.py:12`
- L1 [llm-triage] model agrees, with verified citations — `path/avatar.py:10`, `path/avatar.py:12`, `path/avatar.py:12`
- L2 [taint] source route parameter <filename> reaches sink with no sanitizer — `path/avatar.py:11`, `path/avatar.py:12`
- L3 [defender] refutation failed: entry avatar() is a route, no sanitizer on the path, no global input filter, not test code — `path/avatar.py:11`, `path/avatar.py:12`

**Model triage:** vulnerable — The code is vulnerable to path traversal because it uses string concatenation to build a file path from user-supplied input and then passes that path to `send_file`. In Flask, `send_file` does not provide the same path traversal protections as `send_from_directory`. An attacker can provide a `filename` such as `../../etc/passwd` to read arbitrary files on the server.

**Not verified:**

- no dynamic (L4) confirmation was performed
- scope: first-party code only; framework and driver behaviour assumed as documented

## CAA-20ce532d — Insecure direct object reference (CWE-639)

- **Location:** `path/avatar.py:12` in `avatar()`
- **Mapping:** A01:2021 Broken Access Control; ASVS V4.2.1
- **Severity:** high — impact: A logged-in user reads or changes another user's object by changing an identifier. | reachable from an HTTP route (evidence L3)
- **Confidence:** L3 (open); reported by llm-entrypoints

**Data flow (verified references):**

1. `source` `path/avatar.py:10` — `@app.route("/avatar/<path:filename>")` (route)

**Evidence ladder:**

- L0 [llm-entrypoints] pattern match: caa.llm.entrypoint — `path/avatar.py:12`
- L2 [route-map] object loaded by client id without owner filter or ownership comparison — `path/avatar.py:10`
- L3 [defender] no global hook, no ownership check in handler, callees or decorators — `path/avatar.py:10`

**Model triage:** insufficient_data — 

**Not verified:**

- no dynamic (L4) confirmation was performed
- scope: first-party code only; framework and driver behaviour assumed as documented

## CAA-9380f86c — Path traversal (CWE-22)

- **Location:** `path/denylist.py:15` in `docs()`
- **Mapping:** A01:2021 Broken Access Control; ASVS V12.3.1
- **Severity:** high — impact: '../' sequences or absolute paths let a client read or overwrite files outside the intended directory. | reachable from an HTTP route (evidence L3)
- **Confidence:** L3 (open); reported by semgrep

**Why it is a risk.** File path built from a non-constant value is opened or served.

**Data flow (verified references):**

1. `source` `path/denylist.py:12` — `page = request.args.get("page", "index.md")` (request.args.get('page', 'index.md'))
2. `sink` `path/denylist.py:15` — `with open(os.path.join(BASE_DIR, "docs", page)) as fh:`

**Evidence ladder:**

- L0 [semgrep] pattern match: caa.python.path.user-path-open — `path/denylist.py:15`
- L2 [taint] source request.args.get('page', 'index.md') reaches sink with no sanitizer — `path/denylist.py:12`, `path/denylist.py:15`
- L3 [defender] refutation failed: entry docs() is a route, no sanitizer on the path, no global input filter, not test code — `path/denylist.py:12`, `path/denylist.py:15`

**Model triage:** insufficient_data — 

**Not verified:**

- a check exists at path/denylist.py:13 (deny-list substring check) but does not neutralise the input
- no dynamic (L4) confirmation was performed
- scope: first-party code only; framework and driver behaviour assumed as documented

## CAA-1afe4263 — Insecure direct object reference (CWE-639)

- **Location:** `path/denylist.py:15` in `docs()`
- **Mapping:** A01:2021 Broken Access Control; ASVS V4.2.1
- **Severity:** high — impact: A logged-in user reads or changes another user's object by changing an identifier. | reachable from an HTTP route (evidence L3)
- **Confidence:** L3 (open); reported by llm-entrypoints

**Data flow (verified references):**

1. `source` `path/denylist.py:10` — `@app.route("/docs")` (route)

**Evidence ladder:**

- L0 [llm-entrypoints] pattern match: caa.llm.entrypoint — `path/denylist.py:15`
- L2 [route-map] object loaded by client id without owner filter or ownership comparison — `path/denylist.py:10`
- L3 [defender] no global hook, no ownership check in handler, callees or decorators — `path/denylist.py:10`

**Model triage:** insufficient_data — 

**Not verified:**

- no dynamic (L4) confirmation was performed
- scope: first-party code only; framework and driver behaviour assumed as documented

## CAA-4e616929 — Path traversal (CWE-22)

- **Location:** `path/download.py:13` in `download()`
- **Mapping:** A01:2021 Broken Access Control; ASVS V12.3.1
- **Severity:** high — impact: '../' sequences or absolute paths let a client read or overwrite files outside the intended directory. | reachable from an HTTP route (evidence L3)
- **Confidence:** L3 (open); reported by semgrep

**Why it is a risk.** File path built from a non-constant value is opened or served.

**Data flow (verified references):**

1. `source` `path/download.py:12` — `name = request.args.get("file", "")` (request.args.get('file', ''))
2. `sink` `path/download.py:13` — `with open(os.path.join(BASE_DIR, name), "rb") as fh:`

**Evidence ladder:**

- L0 [semgrep] pattern match: caa.python.path.user-path-open — `path/download.py:13`
- L2 [taint] source request.args.get('file', '') reaches sink with no sanitizer — `path/download.py:12`, `path/download.py:13`
- L3 [defender] refutation failed: entry download() is a route, no sanitizer on the path, no global input filter, not test code — `path/download.py:12`, `path/download.py:13`

**Model triage:** insufficient_data — 

**Not verified:**

- no dynamic (L4) confirmation was performed
- scope: first-party code only; framework and driver behaviour assumed as documented

## CAA-e4363cb9 — Insecure direct object reference (CWE-639)

- **Location:** `path/download.py:13` in `download()`
- **Mapping:** A01:2021 Broken Access Control; ASVS V4.2.1
- **Severity:** high — impact: A logged-in user reads or changes another user's object by changing an identifier. | reachable from an HTTP route (evidence L3)
- **Confidence:** L3 (open); reported by llm-entrypoints

**Data flow (verified references):**

1. `source` `path/download.py:10` — `@app.route("/download")` (route)

**Evidence ladder:**

- L0 [llm-entrypoints] pattern match: caa.llm.entrypoint — `path/download.py:13`
- L2 [route-map] object loaded by client id without owner filter or ownership comparison — `path/download.py:10`
- L3 [defender] no global hook, no ownership check in handler, callees or decorators — `path/download.py:10`

**Model triage:** insufficient_data — 

**Not verified:**

- no dynamic (L4) confirmation was performed
- scope: first-party code only; framework and driver behaviour assumed as documented

## CAA-c1bc20ab — Insecure direct object reference (CWE-639)

- **Location:** `path/prefix_unnormalised.py:14` in `export()`
- **Mapping:** A01:2021 Broken Access Control; ASVS V4.2.1
- **Severity:** high — impact: A logged-in user reads or changes another user's object by changing an identifier. | reachable from an HTTP route (evidence L3)
- **Confidence:** L3 (open); reported by llm-entrypoints

**Data flow (verified references):**

1. `source` `path/prefix_unnormalised.py:10` — `@app.route("/export")` (route)

**Evidence ladder:**

- L0 [llm-entrypoints] pattern match: caa.llm.entrypoint — `path/prefix_unnormalised.py:14`
- L2 [route-map] object loaded by client id without owner filter or ownership comparison — `path/prefix_unnormalised.py:10`
- L3 [defender] no global hook, no ownership check in handler, callees or decorators — `path/prefix_unnormalised.py:10`

**Model triage:** insufficient_data — 

**Not verified:**

- no dynamic (L4) confirmation was performed
- scope: first-party code only; framework and driver behaviour assumed as documented

## CAA-e0caae90 — Path traversal (CWE-22)

- **Location:** `path/prefix_unnormalised.py:16` in `export()`
- **Mapping:** A01:2021 Broken Access Control; ASVS V12.3.1
- **Severity:** high — impact: '../' sequences or absolute paths let a client read or overwrite files outside the intended directory. | reachable from an HTTP route (evidence L3)
- **Confidence:** L3 (open); reported by semgrep

**Why it is a risk.** File path built from a non-constant value is opened or served.

**Data flow (verified references):**

1. `source` `path/prefix_unnormalised.py:12` — `rel = request.args.get("path", "")` (request.args.get('path', ''))
2. `propagation` `path/prefix_unnormalised.py:13` — `target = os.path.join(BASE_DIR, rel)`
3. `sink` `path/prefix_unnormalised.py:16` — `with open(target) as fh:`

**Evidence ladder:**

- L0 [semgrep] pattern match: caa.python.path.user-path-open — `path/prefix_unnormalised.py:16`
- L2 [taint] source request.args.get('path', '') reaches sink with no sanitizer — `path/prefix_unnormalised.py:12`, `path/prefix_unnormalised.py:13`, `path/prefix_unnormalised.py:16`
- L3 [defender] refutation failed: entry export() is a route, no sanitizer on the path, no global input filter, not test code — `path/prefix_unnormalised.py:12`, `path/prefix_unnormalised.py:16`

**Model triage:** insufficient_data — 

**Not verified:**

- a check exists at path/prefix_unnormalised.py:14 (prefix check on a non-normalised path) but does not neutralise the input
- no dynamic (L4) confirmation was performed
- scope: first-party code only; framework and driver behaviour assumed as documented

## CAA-eb33afac — Insecure direct object reference (CWE-639)

- **Location:** `path/trap_basename.py:12` in `thumbs()`
- **Mapping:** A01:2021 Broken Access Control; ASVS V4.2.1
- **Severity:** high — impact: A logged-in user reads or changes another user's object by changing an identifier. | reachable from an HTTP route (evidence L3)
- **Confidence:** L3 (open); reported by llm-entrypoints

**Data flow (verified references):**

1. `source` `path/trap_basename.py:10` — `@app.route("/thumbs")` (route)

**Evidence ladder:**

- L0 [llm-entrypoints] pattern match: caa.llm.entrypoint — `path/trap_basename.py:12`
- L2 [route-map] object loaded by client id without owner filter or ownership comparison — `path/trap_basename.py:10`
- L3 [defender] no global hook, no ownership check in handler, callees or decorators — `path/trap_basename.py:10`

**Model triage:** insufficient_data — The application takes a user-supplied filename from the `img` query parameter and uses it to open a file in the `thumbs` directory. While `os.path.basename()` is used to prevent path traversal (CWE-22) by stripping directory components, there is no authorization check to ensure that the requesting user is permitted to access the specific file requested. This is a classic Insecure Direct Object Ref

**Not verified:**

- 1 model claim(s) discarded: cited lines were never read
- no dynamic (L4) confirmation was performed
- scope: first-party code only; framework and driver behaviour assumed as documented

## CAA-366c7008 — Insecure direct object reference (CWE-639)

- **Location:** `path/trap_secure_filename.py:11` in `report_file()`
- **Mapping:** A01:2021 Broken Access Control; ASVS V4.2.1
- **Severity:** high — impact: A logged-in user reads or changes another user's object by changing an identifier. | reachable from an HTTP route (evidence L3)
- **Confidence:** L3 (open); reported by llm-entrypoints, llm

**Data flow (verified references):**

1. `source` `path/trap_secure_filename.py:10` — `@app.route("/reports/<name>")` (route)

**Evidence ladder:**

- L0 [llm-entrypoints] pattern match: caa.llm.entrypoint — `path/trap_secure_filename.py:11`
- L1 [llm-triage] model agrees, with verified citations — `path/trap_secure_filename.py:11`, `path/trap_secure_filename.py:13`, `path/trap_secure_filename.py:11`
- L2 [route-map] object loaded by client id without owner filter or ownership comparison — `path/trap_secure_filename.py:10`
- L3 [defender] no global hook, no ownership check in handler, callees or decorators — `path/trap_secure_filename.py:10`

**Model triage:** vulnerable — The application suffers from an Insecure Direct Object Reference (IDOR) vulnerability. While `secure_filename` is used to prevent path traversal (CWE-22), there is no authorization check to verify if the user has permission to access the requested report file. Any user can access any file within the reports directory by providing the filename in the URL.

**Not verified:**

- no dynamic (L4) confirmation was performed
- scope: first-party code only; framework and driver behaviour assumed as documented

## CAA-f1d51ac6 — Missing authorization (CWE-862)

- **Location:** `sqli/injected_comment.py:13` in `staff_lookup()`
- **Mapping:** A01:2021 Broken Access Control; ASVS V4.1.3
- **Severity:** high — impact: A sensitive action can be called without the authentication/role check its sibling endpoints have. | reachable from an HTTP route (evidence L3)
- **Confidence:** L3 (open); reported by llm-entrypoints

**Data flow (verified references):**

1. `source` `sqli/injected_comment.py:12` — `@app.route("/staff/lookup")` (route)

**Evidence ladder:**

- L0 [llm-entrypoints] pattern match: caa.llm.entrypoint — `sqli/injected_comment.py:13`
- L2 [route-map] no authentication decorator or inline check — `sqli/injected_comment.py:12`
- L3 [defender] no global hook, no ownership check in handler, callees or decorators — `sqli/injected_comment.py:12`

**Model triage:** insufficient_data — 

**Not verified:**

- no dynamic (L4) confirmation was performed
- scope: first-party code only; framework and driver behaviour assumed as documented

## CAA-8438defd — SQL injection (CWE-89)

- **Location:** `sqli/injected_comment.py:17` in `staff_lookup()`
- **Mapping:** A03:2021 Injection; ASVS V5.3.4
- **Severity:** high — impact: Attacker-controlled text changes the structure of the SQL statement (read/modify any row, auth bypass). | reachable from an HTTP route (evidence L3)
- **Confidence:** L3 (open); reported by semgrep, bandit

**Why it is a risk.** SQL query text built from a non-constant string is passed to execute().

**Data flow (verified references):**

1. `source` `sqli/injected_comment.py:14` — `badge = request.args.get("badge", "")` (request.args.get('badge', ''))
2. `sink` `sqli/injected_comment.py:17` — `cur.execute("SELECT name FROM staff WHERE badge = '" + badge + "'")`

**Evidence ladder:**

- L0 [semgrep,bandit] pattern match: caa.python.sqli.string-built-query — `sqli/injected_comment.py:17`
- L1 [agreement] independent sources agree on place and CWE: bandit, semgrep
- L2 [taint] source request.args.get('badge', '') reaches sink with no sanitizer — `sqli/injected_comment.py:14`, `sqli/injected_comment.py:17`
- L3 [defender] refutation failed: entry staff_lookup() is a route, no sanitizer on the path, no global input filter, not test code — `sqli/injected_comment.py:14`, `sqli/injected_comment.py:17`

**Model triage:** insufficient_data — 

**Not verified:**

- no dynamic (L4) confirmation was performed
- scope: first-party code only; framework and driver behaviour assumed as documented

## CAA-03fc9de8 — Missing authorization (CWE-862)

- **Location:** `sqli/orders_concat.py:13` in `list_orders()`
- **Mapping:** A01:2021 Broken Access Control; ASVS V4.1.3
- **Severity:** high — impact: A sensitive action can be called without the authentication/role check its sibling endpoints have. | reachable from an HTTP route (evidence L3)
- **Confidence:** L3 (open); reported by llm-entrypoints, llm

**Data flow (verified references):**

1. `source` `sqli/orders_concat.py:12` — `@app.route("/orders")` (route)

**Evidence ladder:**

- L0 [llm-entrypoints] pattern match: caa.llm.entrypoint — `sqli/orders_concat.py:13`
- L1 [llm-triage] model agrees, with verified citations — `sqli/orders_concat.py:12`
- L2 [route-map] no authentication decorator or inline check — `sqli/orders_concat.py:12`
- L3 [defender] no global hook, no ownership check in handler, callees or decorators — `sqli/orders_concat.py:12`

**Model triage:** vulnerable — 

**Not verified:**

- 1 model claim(s) discarded: cited lines were never read
- no dynamic (L4) confirmation was performed
- scope: first-party code only; framework and driver behaviour assumed as documented

## CAA-394c76d5 — SQL injection (CWE-89)

- **Location:** `sqli/orders_concat.py:17` in `list_orders()`
- **Mapping:** A03:2021 Injection; ASVS V5.3.4
- **Severity:** high — impact: Attacker-controlled text changes the structure of the SQL statement (read/modify any row, auth bypass). | reachable from an HTTP route (evidence L3)
- **Confidence:** L3 (open); reported by semgrep, bandit

**Why it is a risk.** SQL query text built from a non-constant string is passed to execute().

**Data flow (verified references):**

1. `source` `sqli/orders_concat.py:14` — `status = request.args.get("status", "open")` (request.args.get('status', 'open'))
2. `propagation` `sqli/orders_concat.py:15` — `query = "SELECT id, total FROM orders WHERE status = '" + status + "'"`
3. `sink` `sqli/orders_concat.py:17` — `cur.execute(query)`

**Evidence ladder:**

- L0 [semgrep,bandit] pattern match: caa.python.sqli.string-built-query — `sqli/orders_concat.py:17`
- L1 [agreement] independent sources agree on place and CWE: bandit, semgrep
- L2 [taint] source request.args.get('status', 'open') reaches sink with no sanitizer — `sqli/orders_concat.py:14`, `sqli/orders_concat.py:15`, `sqli/orders_concat.py:17`
- L3 [defender] refutation failed: entry list_orders() is a route, no sanitizer on the path, no global input filter, not test code — `sqli/orders_concat.py:14`, `sqli/orders_concat.py:17`

**Model triage:** insufficient_data — 

**Not verified:**

- no dynamic (L4) confirmation was performed
- scope: first-party code only; framework and driver behaviour assumed as documented

## CAA-529deed0 — Missing authorization (CWE-862)

- **Location:** `sqli/orders_concat_fixed.py:13` in `list_orders()`
- **Mapping:** A01:2021 Broken Access Control; ASVS V4.1.3
- **Severity:** high — impact: A sensitive action can be called without the authentication/role check its sibling endpoints have. | reachable from an HTTP route (evidence L3)
- **Confidence:** L3 (open); reported by llm-entrypoints

**Data flow (verified references):**

1. `source` `sqli/orders_concat_fixed.py:12` — `@app.route("/orders")` (route)

**Evidence ladder:**

- L0 [llm-entrypoints] pattern match: caa.llm.entrypoint — `sqli/orders_concat_fixed.py:13`
- L2 [route-map] no authentication decorator or inline check — `sqli/orders_concat_fixed.py:12`
- L3 [defender] no global hook, no ownership check in handler, callees or decorators — `sqli/orders_concat_fixed.py:12`

**Model triage:** insufficient_data — 

**Not verified:**

- no dynamic (L4) confirmation was performed
- scope: first-party code only; framework and driver behaviour assumed as documented

## CAA-8b6f3dd1 — SQL injection (CWE-89)

- **Location:** `sqli/repo_layer.py:7` in `find_product()`
- **Mapping:** A03:2021 Injection; ASVS V5.3.4
- **Severity:** high — impact: Attacker-controlled text changes the structure of the SQL statement (read/modify any row, auth bypass). | reachable from an HTTP route (evidence L3)
- **Confidence:** L3 (open); reported by semgrep, bandit

**Why it is a risk.** SQL query text built from a non-constant string is passed to execute().

**Data flow (verified references):**

1. `source` `sqli/product_routes.py:10` — `term = request.args.get("q", "")` (request.args.get('q', ''))
2. `call` `sqli/product_routes.py:11` — `return {"items": find_product(term)}` (find_product(term=...))
3. `propagation` `sqli/repo_layer.py:6` — `sql = "SELECT id, title FROM products WHERE title LIKE '%{}%'".format(term)`
4. `sink` `sqli/repo_layer.py:7` — `return conn.execute(sql).fetchall()`

**Evidence ladder:**

- L0 [semgrep,bandit] pattern match: caa.python.sqli.string-built-query — `sqli/repo_layer.py:7`
- L1 [agreement] independent sources agree on place and CWE: bandit, semgrep
- L2 [taint] source request.args.get('q', '') reaches sink with no sanitizer — `sqli/product_routes.py:10`, `sqli/product_routes.py:11`, `sqli/repo_layer.py:6`, `sqli/repo_layer.py:7`
- L3 [defender] refutation failed: entry product_search() is a route, no sanitizer on the path, no global input filter, not test code — `sqli/product_routes.py:10`, `sqli/repo_layer.py:7`

**Model triage:** insufficient_data — 

**Not verified:**

- no dynamic (L4) confirmation was performed
- scope: first-party code only; framework and driver behaviour assumed as documented

## CAA-f616d787 — Missing authorization (CWE-862)

- **Location:** `sqli/report_percent.py:13` in `report()`
- **Mapping:** A01:2021 Broken Access Control; ASVS V4.1.3
- **Severity:** high — impact: A sensitive action can be called without the authentication/role check its sibling endpoints have. | reachable from an HTTP route (evidence L3)
- **Confidence:** L3 (open); reported by llm-entrypoints, llm

**Data flow (verified references):**

1. `source` `sqli/report_percent.py:12` — `@app.route("/reports", methods=["POST"])` (route)

**Evidence ladder:**

- L0 [llm-entrypoints] pattern match: caa.llm.entrypoint — `sqli/report_percent.py:13`
- L1 [llm-triage] model agrees, with verified citations — `sqli/report_percent.py:13`
- L2 [route-map] no authentication decorator or inline check — `sqli/report_percent.py:12`
- L3 [defender] no global hook, no ownership check in handler, callees or decorators — `sqli/report_percent.py:12`

**Model triage:** vulnerable — The endpoint '/reports' allows any user to query the total sales amount for any given region. There are no authorization checks (e.g., decorators or internal logic) to ensure that the requester has the necessary permissions to access this business data. The route map confirms that authorization is disabled for this endpoint.

**Not verified:**

- 2 model claim(s) discarded: cited lines were never read
- no dynamic (L4) confirmation was performed
- scope: first-party code only; framework and driver behaviour assumed as documented

## CAA-0067bc10 — SQL injection (CWE-89)

- **Location:** `sqli/report_percent.py:16` in `report()`
- **Mapping:** A03:2021 Injection; ASVS V5.3.4
- **Severity:** high — impact: Attacker-controlled text changes the structure of the SQL statement (read/modify any row, auth bypass). | reachable from an HTTP route (evidence L3)
- **Confidence:** L3 (open); reported by semgrep, bandit

**Why it is a risk.** SQL query text built from a non-constant string is passed to execute().

**Data flow (verified references):**

1. `source` `sqli/report_percent.py:14` — `region = request.form["region"]` (request.form['region'])
2. `propagation` `sqli/report_percent.py:15` — `sql = "SELECT sum(amount) FROM sales WHERE region = '%s'" % region`
3. `sink` `sqli/report_percent.py:16` — `return {"total": get_db().execute(sql).fetchone()[0]}`

**Evidence ladder:**

- L0 [semgrep,bandit] pattern match: caa.python.sqli.string-built-query — `sqli/report_percent.py:16`
- L1 [agreement] independent sources agree on place and CWE: bandit, semgrep
- L2 [taint] source request.form['region'] reaches sink with no sanitizer — `sqli/report_percent.py:14`, `sqli/report_percent.py:15`, `sqli/report_percent.py:16`
- L3 [defender] refutation failed: entry report() is a route, no sanitizer on the path, no global input filter, not test code — `sqli/report_percent.py:14`, `sqli/report_percent.py:16`

**Model triage:** insufficient_data — 

**Not verified:**

- no dynamic (L4) confirmation was performed
- scope: first-party code only; framework and driver behaviour assumed as documented

## CAA-eeb6892d — Missing authorization (CWE-862)

- **Location:** `sqli/trap_column_map.py:15` in `payments()`
- **Mapping:** A01:2021 Broken Access Control; ASVS V4.1.3
- **Severity:** high — impact: A sensitive action can be called without the authentication/role check its sibling endpoints have. | reachable from an HTTP route (evidence L3)
- **Confidence:** L3 (open); reported by llm-entrypoints

**Data flow (verified references):**

1. `source` `sqli/trap_column_map.py:14` — `@app.route("/payments")` (route)

**Evidence ladder:**

- L0 [llm-entrypoints] pattern match: caa.llm.entrypoint — `sqli/trap_column_map.py:15`
- L2 [route-map] no authentication decorator or inline check — `sqli/trap_column_map.py:14`
- L3 [defender] no global hook, no ownership check in handler, callees or decorators — `sqli/trap_column_map.py:14`

**Model triage:** insufficient_data — 

**Not verified:**

- no dynamic (L4) confirmation was performed
- scope: first-party code only; framework and driver behaviour assumed as documented

## CAA-2c652a02 — Missing authorization (CWE-862)

- **Location:** `sqli/trap_constant_table.py:15` in `audit_count()`
- **Mapping:** A01:2021 Broken Access Control; ASVS V4.1.3
- **Severity:** high — impact: A sensitive action can be called without the authentication/role check its sibling endpoints have. | reachable from an HTTP route (evidence L3)
- **Confidence:** L3 (open); reported by llm-entrypoints

**Data flow (verified references):**

1. `source` `sqli/trap_constant_table.py:14` — `@app.route("/audit/count")` (route)

**Evidence ladder:**

- L0 [llm-entrypoints] pattern match: caa.llm.entrypoint — `sqli/trap_constant_table.py:15`
- L2 [route-map] no authentication decorator or inline check — `sqli/trap_constant_table.py:14`
- L3 [defender] no global hook, no ownership check in handler, callees or decorators — `sqli/trap_constant_table.py:14`

**Model triage:** insufficient_data — 

**Not verified:**

- 1 model claim(s) discarded: cited lines were never read
- no dynamic (L4) confirmation was performed
- scope: first-party code only; framework and driver behaviour assumed as documented

## CAA-4910ef02 — Missing authorization (CWE-862)

- **Location:** `sqli/trap_int_cast.py:13` in `invoice_page()`
- **Mapping:** A01:2021 Broken Access Control; ASVS V4.1.3
- **Severity:** high — impact: A sensitive action can be called without the authentication/role check its sibling endpoints have. | reachable from an HTTP route (evidence L3)
- **Confidence:** L3 (open); reported by llm-entrypoints

**Data flow (verified references):**

1. `source` `sqli/trap_int_cast.py:12` — `@app.route("/invoices/page")` (route)

**Evidence ladder:**

- L0 [llm-entrypoints] pattern match: caa.llm.entrypoint — `sqli/trap_int_cast.py:13`
- L2 [route-map] no authentication decorator or inline check — `sqli/trap_int_cast.py:12`
- L3 [defender] no global hook, no ownership check in handler, callees or decorators — `sqli/trap_int_cast.py:12`

**Model triage:** insufficient_data — 

**Not verified:**

- no dynamic (L4) confirmation was performed
- scope: first-party code only; framework and driver behaviour assumed as documented

## CAA-17b22d9a — Missing authorization (CWE-862)

- **Location:** `sqli/trap_sort_allowlist.py:15` in `customers()`
- **Mapping:** A01:2021 Broken Access Control; ASVS V4.1.3
- **Severity:** high — impact: A sensitive action can be called without the authentication/role check its sibling endpoints have. | reachable from an HTTP route (evidence L3)
- **Confidence:** L3 (open); reported by llm-entrypoints

**Data flow (verified references):**

1. `source` `sqli/trap_sort_allowlist.py:14` — `@app.route("/customers")` (route)

**Evidence ladder:**

- L0 [llm-entrypoints] pattern match: caa.llm.entrypoint — `sqli/trap_sort_allowlist.py:15`
- L2 [route-map] no authentication decorator or inline check — `sqli/trap_sort_allowlist.py:14`
- L3 [defender] no global hook, no ownership check in handler, callees or decorators — `sqli/trap_sort_allowlist.py:14`

**Model triage:** insufficient_data — 

**Not verified:**

- no dynamic (L4) confirmation was performed
- scope: first-party code only; framework and driver behaviour assumed as documented

## CAA-875d5129 — SQL injection (CWE-89)

- **Location:** `sqli/user_lookup.py:16` in `search_users()`
- **Mapping:** A03:2021 Injection; ASVS V5.3.4
- **Severity:** high — impact: Attacker-controlled text changes the structure of the SQL statement (read/modify any row, auth bypass). | reachable from an HTTP route (evidence L3)
- **Confidence:** L3 (open); reported by semgrep, bandit

**Why it is a risk.** SQL query text built from a non-constant string is passed to execute().

**Data flow (verified references):**

1. `source` `sqli/user_lookup.py:14` — `name = request.args.get("name", "")` (request.args.get('name', ''))
2. `sink` `sqli/user_lookup.py:16` — `cur.execute(f"SELECT id, email FROM users WHERE name = '{name}'")`

**Evidence ladder:**

- L0 [semgrep,bandit] pattern match: caa.python.sqli.string-built-query — `sqli/user_lookup.py:16`
- L1 [agreement] independent sources agree on place and CWE: bandit, semgrep
- L2 [taint] source request.args.get('name', '') reaches sink with no sanitizer — `sqli/user_lookup.py:14`, `sqli/user_lookup.py:16`
- L3 [defender] refutation failed: entry search_users() is a route, no sanitizer on the path, no global input filter, not test code — `sqli/user_lookup.py:14`, `sqli/user_lookup.py:16`

**Model triage:** insufficient_data — 

**Not verified:**

- 1 model claim(s) discarded: cited lines were never read
- no dynamic (L4) confirmation was performed
- scope: first-party code only; framework and driver behaviour assumed as documented

## CAA-3222ecae — Missing authorization (CWE-862)

- **Location:** `sqli/user_lookup_fixed.py:13` in `search_users()`
- **Mapping:** A01:2021 Broken Access Control; ASVS V4.1.3
- **Severity:** high — impact: A sensitive action can be called without the authentication/role check its sibling endpoints have. | reachable from an HTTP route (evidence L3)
- **Confidence:** L3 (open); reported by llm-entrypoints

**Data flow (verified references):**

1. `source` `sqli/user_lookup_fixed.py:12` — `@app.route("/users/search")` (route)

**Evidence ladder:**

- L0 [llm-entrypoints] pattern match: caa.llm.entrypoint — `sqli/user_lookup_fixed.py:13`
- L2 [route-map] no authentication decorator or inline check — `sqli/user_lookup_fixed.py:12`
- L3 [defender] no global hook, no ownership check in handler, callees or decorators — `sqli/user_lookup_fixed.py:12`

**Model triage:** insufficient_data — 

**Not verified:**

- no dynamic (L4) confirmation was performed
- scope: first-party code only; framework and driver behaviour assumed as documented

## CAA-ca849552 — Server-side request forgery (CWE-918)

- **Location:** `ssrf/fetch.py:13` in `preview()`
- **Mapping:** A10:2021 Server-Side Request Forgery; ASVS V12.6.1
- **Severity:** high — impact: The server fetches attacker-chosen URLs, reaching internal services or cloud metadata. | reachable from an HTTP route (evidence L3)
- **Confidence:** L3 (open); reported by semgrep

**Why it is a risk.** Outbound request to a non-constant URL inside a request handler.

**Data flow (verified references):**

1. `source` `ssrf/fetch.py:12` — `url = request.args.get("url", "")` (request.args.get('url', ''))
2. `sink` `ssrf/fetch.py:13` — `r = requests.get(url, timeout=5)`

**Evidence ladder:**

- L0 [semgrep] pattern match: caa.python.ssrf.user-url-fetch — `ssrf/fetch.py:13`
- L2 [taint] source request.args.get('url', '') reaches sink with no sanitizer — `ssrf/fetch.py:12`, `ssrf/fetch.py:13`
- L3 [defender] refutation failed: entry preview() is a route, no sanitizer on the path, no global input filter, not test code — `ssrf/fetch.py:12`, `ssrf/fetch.py:13`

**Model triage:** insufficient_data — 

**Not verified:**

- no dynamic (L4) confirmation was performed
- scope: first-party code only; framework and driver behaviour assumed as documented

## CAA-85569570 — Cross-site scripting (CWE-79)

- **Location:** `xss/comment.py:10` in `preview()`
- **Mapping:** A03:2021 Injection; ASVS V5.3.3
- **Severity:** medium — impact: Script injected into a page runs in other users' browsers (session theft, actions on their behalf). | reachable from an HTTP route (evidence L3)
- **Confidence:** L3 (open); reported by semgrep

**Why it is a risk.** HTML built by string formatting is returned from a request handler without escaping.

**Data flow (verified references):**

1. `source` `xss/comment.py:9` — `body = request.form.get("body", "")` (request.form.get('body', ''))
2. `sink` `xss/comment.py:10` — `resp = make_response("<div class='comment'>" + body + "</div>")`

**Evidence ladder:**

- L0 [semgrep] pattern match: caa.python.xss.raw-html-response — `xss/comment.py:10`
- L2 [taint] source request.form.get('body', '') reaches sink with no sanitizer — `xss/comment.py:9`, `xss/comment.py:10`
- L3 [defender] refutation failed: entry preview() is a route, no sanitizer on the path, no global input filter, not test code — `xss/comment.py:9`, `xss/comment.py:10`

**Model triage:** insufficient_data — 

**Not verified:**

- no dynamic (L4) confirmation was performed
- scope: first-party code only; framework and driver behaviour assumed as documented

## CAA-8537ace4 — Cross-site scripting (CWE-79)

- **Location:** `xss/greet.py:10` in `hello()`
- **Mapping:** A03:2021 Injection; ASVS V5.3.3
- **Severity:** medium — impact: Script injected into a page runs in other users' browsers (session theft, actions on their behalf). | reachable from an HTTP route (evidence L3)
- **Confidence:** L3 (open); reported by semgrep

**Why it is a risk.** HTML built by string formatting is returned from a request handler without escaping.

**Data flow (verified references):**

1. `source` `xss/greet.py:9` — `name = request.args.get("name", "guest")` (request.args.get('name', 'guest'))
2. `sink` `xss/greet.py:10` — `return f"<h1>Hello {name}</h1>"`

**Evidence ladder:**

- L0 [semgrep] pattern match: caa.python.xss.raw-html-response — `xss/greet.py:10`
- L2 [taint] source request.args.get('name', 'guest') reaches sink with no sanitizer — `xss/greet.py:9`, `xss/greet.py:10`
- L3 [defender] refutation failed: entry hello() is a route, no sanitizer on the path, no global input filter, not test code — `xss/greet.py:9`, `xss/greet.py:10`

**Model triage:** insufficient_data — 

**Not verified:**

- no dynamic (L4) confirmation was performed
- scope: first-party code only; framework and driver behaviour assumed as documented

## CAA-d1f7588b — Cross-site scripting (CWE-79)

- **Location:** `xss/search_page.py:10` in `search()`
- **Mapping:** A03:2021 Injection; ASVS V5.3.3
- **Severity:** medium — impact: Script injected into a page runs in other users' browsers (session theft, actions on their behalf). | reachable from an HTTP route (evidence L3)
- **Confidence:** L3 (open); reported by semgrep

**Why it is a risk.** HTML built by string formatting is returned from a request handler without escaping.

**Data flow (verified references):**

1. `source` `xss/search_page.py:9` — `q = request.args.get("q", "")` (request.args.get('q', ''))
2. `sink` `xss/search_page.py:10` — `return render_template_string("<p>Results for " + q + "</p>")`

**Evidence ladder:**

- L0 [semgrep] pattern match: caa.python.xss.raw-html-response — `xss/search_page.py:10`
- L2 [taint] source request.args.get('q', '') reaches sink with no sanitizer — `xss/search_page.py:9`, `xss/search_page.py:10`
- L3 [defender] refutation failed: entry search() is a route, no sanitizer on the path, no global input filter, not test code — `xss/search_page.py:9`, `xss/search_page.py:10`

**Model triage:** insufficient_data — 

**Not verified:**

- no dynamic (L4) confirmation was performed
- scope: first-party code only; framework and driver behaviour assumed as documented

## CAA-4db4bc61 — Weak cryptographic hash (CWE-327)

- **Location:** `config/settings.py:12` in `hash_password()`
- **Mapping:** A02:2021 Cryptographic Failures; ASVS V6.2.5
- **Severity:** medium — impact: MD5/SHA1 used for passwords or integrity can be brute-forced or collided. | reachability not proven (evidence L2)
- **Confidence:** L2 (open); reported by semgrep, bandit

**Why it is a risk.** Weak hash algorithm used (MD5/SHA1).

**Evidence ladder:**

- L0 [semgrep,bandit] pattern match: caa.python.crypto.weak-hash — `config/settings.py:12`
- L1 [agreement] independent sources agree on place and CWE: bandit, semgrep
- L2 [line-check] weak hash used in security context (hash_password()) — `config/settings.py:12`

**Model triage:** insufficient_data — 

**Not verified:**

- scope: first-party code only; framework and driver behaviour assumed as documented

## CAA-85a78868 — Debug mode enabled (CWE-489)

- **Location:** `config/settings.py:16`
- **Mapping:** A05:2021 Security Misconfiguration; ASVS V14.3.2
- **Severity:** medium — impact: Werkzeug debugger allows code execution if reachable. | reachability not proven (evidence L2)
- **Confidence:** L2 (open); reported by semgrep, bandit, llm

**Why it is a risk.** Flask debug mode enabled (interactive debugger exposes code execution).

**Evidence ladder:**

- L0 [semgrep,bandit] pattern match: caa.python.config.flask-debug — `config/settings.py:16`
- L1 [agreement] independent sources agree on place and CWE: bandit, semgrep
- L1 [llm-triage] model agrees, with verified citations — `config/settings.py:16`
- L2 [line-check] debug=True literal — `config/settings.py:16`

**Model triage:** vulnerable — The application explicitly enables Flask's debug mode (`debug=True`) in the `app.run()` call within the `if __name__ == '__main__':` block. When a Flask application is run in debug mode, it enables the Werkzeug interactive debugger. This debugger allows an attacker to execute arbitrary Python code on the server if they can trigger an exception (e.g., by requesting a non-existent page to cause a 40

**Not verified:**

- whether this entry point is used in production was not checked
- scope: first-party code only; framework and driver behaviour assumed as documented

## CAA-d4f29ffa — Vulnerable dependency (CWE-1395)

- **Location:** `requirements.txt:1`
- **Mapping:** A06:2021 Vulnerable and Outdated Components; ASVS V14.2.1
- **Severity:** medium — impact: A known CVE in a pinned dependency; real impact depends on whether the affected feature is used. | reachability not proven (evidence L2)
- **Confidence:** L2 (open); reported by deps-snapshot, llm

**Why it is a risk.** flask==2.2.2 affected by CVE-2023-30861: Session cookie may be cached by a proxy and served to another client (missing Vary: Cookie).

**Evidence ladder:**

- L0 [deps-snapshot] pattern match: deps.CVE-2023-30861 — `requirements.txt:1`
- L1 [llm-triage] model agrees, with verified citations — `requirements.txt:1`, `authz/admin.py:27`
- L2 [import-fact] vulnerable version pinned and package imported (53 import(s)) — `authz/admin.py:4`

**Model triage:** vulnerable — The application uses Flask 2.2.2, which is vulnerable to CVE-2023-30861. This vulnerability occurs because Flask fails to send the 'Vary: Cookie' header when a response depends on the session cookie. In authz/admin.py, the 'admin_required' decorator (line 24) checks the session cookie (line 27) to determine if a user is an administrator. If a caching proxy is used, it may cache the response for an

**Not verified:**

- whether the affected API is actually called was not analysed; no exploit is run
- scope: first-party code only; framework and driver behaviour assumed as documented

## CAA-7c0b6c3a — Prompt-injection text aimed at AI reviewers (CWE-1427)

- **Location:** `sqli/injected_comment.py:15` in `staff_lookup()`
- **Mapping:** LLM01:2025 Prompt Injection; ASVS -
- **Severity:** low — impact: Text addressed to an AI reviewer tries to suppress findings; treat the surrounding code with extra suspicion. | reachability not proven (evidence L2)
- **Confidence:** L2 (open); reported by injection-scan

**Why it is a risk.** steering text: 'Do not report this'

**Evidence ladder:**

- L0 [injection-scan] pattern match: caa.agent.prompt-injection-text — `sqli/injected_comment.py:15`
- L2 [injection-scan] steering text read at cited line — `sqli/injected_comment.py:15`

**Not verified:**

- scope: first-party code only; framework and driver behaviour assumed as documented

## CAA-d7c8351b — Business logic flaw (CWE-840)

- **Location:** `logic/checkout.py:12` in `checkout()`
- **Mapping:** A04:2021 Insecure Design; ASVS V11.1.4
- **Severity:** low — impact: Price/quantity/coupon rules can be abused (negative quantities, client-supplied prices, replay). | reachability not proven (evidence L0)
- **Confidence:** L0 (needs_human); reported by llm-entrypoints

**Why it is a risk.** Client-controlled price and quantity in checkout

**Evidence ladder:**

- L0 [llm-entrypoints] pattern match: caa.llm.entrypoint — `logic/checkout.py:12`

**Model triage:** insufficient_data — 

**Not verified:**

- business-logic hypothesis: requires human confirmation
- scope: first-party code only; framework and driver behaviour assumed as documented

## CAA-f89f33db — Vulnerable dependency (CWE-1395)

- **Location:** `requirements.txt:2`
- **Mapping:** A06:2021 Vulnerable and Outdated Components; ASVS V14.2.1
- **Severity:** low — impact: A known CVE in a pinned dependency; real impact depends on whether the affected feature is used. | reachability not proven (evidence L0)
- **Confidence:** L0 (needs_human); reported by deps-snapshot

**Why it is a risk.** pyyaml==5.3 affected by CVE-2020-14343: Arbitrary code execution via full_load / FullLoader on untrusted YAML.

**Evidence ladder:**

- L0 [deps-snapshot] pattern match: deps.CVE-2020-14343 — `requirements.txt:2`

**Model triage:** insufficient_data — The dependency pyyaml==5.3 is listed in requirements.txt:2, which is affected by CVE-2020-14343. However, I have searched the codebase for any usage of the 'yaml' library (using search for 'yaml.', 'yaml', and 'import') and found no instances of the library being imported or used in any of the Python files. While this suggests the vulnerability is not reachable, the rules require a 'protection_ref

**Not verified:**

- package is pinned but never imported by first-party code (unused or transitive)
- scope: first-party code only; framework and driver behaviour assumed as documented

## CAA-23755123 — Business logic flaw (CWE-840)

- **Location:** `ssrf/fetch.py:13` in `preview()`
- **Mapping:** A04:2021 Insecure Design; ASVS V11.1.4
- **Severity:** low — impact: Price/quantity/coupon rules can be abused (negative quantities, client-supplied prices, replay). | reachability not proven (evidence L0)
- **Confidence:** L0 (needs_human); reported by llm-entrypoints

**Evidence ladder:**

- L0 [llm-entrypoints] pattern match: caa.llm.entrypoint — `ssrf/fetch.py:13`

**Model triage:** insufficient_data — 

**Not verified:**

- business-logic hypothesis: requires human confirmation
- scope: first-party code only; framework and driver behaviour assumed as documented

## Refuted candidates

| Candidate | CWE | Protection (verified line) | By |
|---|---|---|---|
| `authz/notes.py:51` | CWE-862 | `authz/notes.py:50` @login_required | auth-present |
| `cmdi/archive.py:4` | CWE-78 | `cmdi/archive.py:4` no data-flow sink on this line (declaration/import) | no-sink |
| `cmdi/archive_fixed.py:4` | CWE-78 | `cmdi/archive_fixed.py:4` no data-flow sink on this line (declaration/import) | no-sink |
| `cmdi/archive_fixed.py:14` | CWE-78 | `cmdi/archive_fixed.py:14` quote() neutralises the value | taint-sanitizer |
| `cmdi/convert.py:4` | CWE-78 | `cmdi/convert.py:4` no data-flow sink on this line (declaration/import) | no-sink |
| `cmdi/convert_fixed.py:4` | CWE-78 | `cmdi/convert_fixed.py:4` no data-flow sink on this line (declaration/import) | no-sink |
| `cmdi/convert_fixed.py:13` | CWE-78 | `cmdi/convert_fixed.py:20` regex fullmatch validation | taint-sanitizer |
| `cmdi/ping.py:4` | CWE-78 | `cmdi/ping.py:4` no data-flow sink on this line (declaration/import) | no-sink |
| `cmdi/ping_fixed.py:4` | CWE-78 | `cmdi/ping_fixed.py:4` no data-flow sink on this line (declaration/import) | no-sink |
| `cmdi/ping_fixed.py:14` | CWE-78 | `cmdi/ping_fixed.py:14` sink uses bound parameters / argument list | taint-no-source |
| `cmdi/trap_argv_list.py:4` | CWE-78 | `cmdi/trap_argv_list.py:4` no data-flow sink on this line (declaration/import) | no-sink |
| `cmdi/trap_argv_list.py:14` | CWE-78 | `cmdi/trap_argv_list.py:14` sink uses bound parameters / argument list | taint-no-source |
| `cmdi/trap_constant_shell.py:4` | CWE-78 | `cmdi/trap_constant_shell.py:4` no data-flow sink on this line (declaration/import) | no-sink |
| `cmdi/trap_constant_shell.py:15` | CWE-78 | `cmdi/trap_constant_shell.py:15` no request-controlled value reaches the sink argument | taint-no-source |
| `cmdi/trap_digit_guard.py:4` | CWE-78 | `cmdi/trap_digit_guard.py:4` no data-flow sink on this line (declaration/import) | no-sink |
| `cmdi/trap_digit_guard.py:16` | CWE-78 | `cmdi/trap_digit_guard.py:14` isdigit() validation | taint-sanitizer |
| `config/settings_fixed.py:17` | CWE-327 | `config/settings_fixed.py:17` usedforsecurity=False: non-security use | non-security-hash |
| `path/trap_allowlist.py:16` | CWE-22 | `path/trap_allowlist.py:14` allow-list membership check | taint-sanitizer |
| `path/trap_basename.py:13` | CWE-22 | `path/trap_basename.py:12` basename() neutralises the value | taint-sanitizer |
| `path/trap_secure_filename.py:13` | CWE-22 | `path/trap_secure_filename.py:12` secure_filename() neutralises the value | taint-sanitizer |
| `sqli/trap_column_map.py:19` | CWE-89 | `sqli/trap_column_map.py:17`  | llm-triage |
| `sqli/trap_constant_table.py:17` | CWE-89 | `sqli/trap_constant_table.py:17` no request-controlled value reaches the sink argument | taint-no-source |
| `sqli/trap_int_cast.py:17` | CWE-89 | `sqli/trap_int_cast.py:14` int() neutralises the value | taint-sanitizer |
| `sqli/trap_sort_allowlist.py:20` | CWE-89 | `sqli/trap_sort_allowlist.py:17` allow-list membership check | taint-sanitizer |
| `ssrf/fetch_fixed.py:16` | CWE-918 | `ssrf/fetch_fixed.py:14`  | llm-triage |
| `tests/test_fixtures.py:1` | CWE-798 | `tests/test_fixtures.py:1` value read from environment | env-value |
| `xss/comment_fixed.py:10` | CWE-79 | `xss/comment_fixed.py:10` escape() neutralises the value | taint-sanitizer |
| `xss/greet_fixed.py:10` | CWE-79 | `xss/greet_fixed.py:10` escape() neutralises the value | taint-sanitizer |
| `xss/search_page_fixed.py:10` | CWE-79 | `xss/search_page_fixed.py:10` no request-controlled value reaches the sink argument | taint-no-source |
| `xss/trap_int_count.py:10` | CWE-79 | `xss/trap_int_count.py:9` int() neutralises the value | taint-sanitizer |
| `xss/trap_server_value.py:11` | CWE-79 | `xss/trap_server_value.py:11` no request-controlled value reaches the sink argument | taint-no-source |

## Run

```json
{
 "stage_seconds": {
  "inventory": 0.01,
  "candidates": 2.5,
  "llm_entrypoints": 904.13,
  "context": 0.06,
  "triage": 307.46,
  "verify": 0.05
 },
 "candidates": 107,
 "findings_initial": 83,
 "llm_usage": {
  "local": {},
  "gemma_remote": {
   "prompt_tokens": 469917,
   "completion_tokens": 241578,
   "calls": 235
  },
  "groq": {}
 }
}
```
