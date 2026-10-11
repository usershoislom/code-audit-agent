# Seeded stand: sast_llm_triage

Target: `/home/user/code-audit-agent/eval/seeded/repo`  
Findings: **72 open** (0 need human review), 11 candidates refuted with a cited protection.

Confidence is the highest evidence level reached: L0 pattern · L1 independent agreement · L2 trace · L3 refutation failed · L4 harmless dynamic check · L5 patch verified.

| ID | Level | Severity | CWE | Location | Title | Status |
|---|---|---|---|---|---|---|
| CAA-b0df4337 | L1 | medium | CWE-78 | `cli_tool/grep_logs.py:10` | OS command injection | open |
| CAA-31d6d1a4 | L1 | medium | CWE-89 | `cli_tool/report.py:8` | SQL injection | open |
| CAA-b203c778 | L1 | medium | CWE-78 | `cmdi/archive.py:14` | OS command injection | open |
| CAA-33c18287 | L1 | medium | CWE-78 | `cmdi/archive_fixed.py:14` | OS command injection | open |
| CAA-bc2556a7 | L1 | medium | CWE-78 | `cmdi/convert.py:13` | OS command injection | open |
| CAA-9a968212 | L1 | medium | CWE-78 | `cmdi/convert_fixed.py:13` | OS command injection | open |
| CAA-1abe4edd | L1 | medium | CWE-78 | `cmdi/ping.py:14` | OS command injection | open |
| CAA-aaf0c737 | L1 | medium | CWE-78 | `cmdi/trap_digit_guard.py:16` | OS command injection | open |
| CAA-8cc39187 | L1 | medium | CWE-798 | `config/settings.py:6` | Hard-coded credential | open |
| CAA-4db4bc61 | L1 | medium | CWE-327 | `config/settings.py:12` | Weak cryptographic hash | open |
| CAA-85a78868 | L1 | medium | CWE-489 | `config/settings.py:16` | Debug mode enabled | open |
| CAA-6c90af1b | L1 | medium | CWE-89 | `django_app/notes/views.py:32` | SQL injection | open |
| CAA-63e88b21 | L1 | medium | CWE-798 | `django_app/settings.py:2` | Hard-coded credential | open |
| CAA-3f0420fa | L1 | medium | CWE-89 | `fastapi_app/main.py:21` | SQL injection | open |
| CAA-8dfb2540 | L1 | medium | CWE-78 | `gosvc/handlers.go:24` | OS command injection | open |
| CAA-6daca4e3 | L1 | medium | CWE-22 | `gosvc/handlers.go:30` | Path traversal | open |
| CAA-1e0cb09f | L1 | medium | CWE-94 | `js/calc.js:6` | Request data is evaluated as code. | open |
| CAA-d101b85a | L1 | medium | CWE-89 | `js/users.js:7` | SQL injection | open |
| CAA-8438defd | L1 | medium | CWE-89 | `sqli/injected_comment.py:17` | SQL injection | open |
| CAA-394c76d5 | L1 | medium | CWE-89 | `sqli/orders_concat.py:17` | SQL injection | open |
| CAA-8b6f3dd1 | L1 | medium | CWE-89 | `sqli/repo_layer.py:7` | SQL injection | open |
| CAA-0067bc10 | L1 | medium | CWE-89 | `sqli/report_percent.py:16` | SQL injection | open |
| CAA-875d5129 | L1 | medium | CWE-89 | `sqli/user_lookup.py:16` | SQL injection | open |
| CAA-016e3741 | L1 | medium | CWE-79 | `xss/search_page_fixed.py:10` | Cross-site scripting | open |
| CAA-bbb7d647 | L0 | medium | CWE-78 | `cli_tool/grep_logs.py:2` | OS command injection | open |
| CAA-dc0c73b2 | L0 | medium | CWE-78 | `cli_tool/grep_logs_fixed.py:2` | OS command injection | open |
| CAA-05bfc924 | L0 | medium | CWE-78 | `cli_tool/grep_logs_fixed.py:10` | OS command injection | open |
| CAA-d8fa872f | L0 | medium | CWE-78 | `cmdi/archive.py:4` | OS command injection | open |
| CAA-433bad03 | L0 | medium | CWE-78 | `cmdi/archive_fixed.py:4` | OS command injection | open |
| CAA-68fcdaa6 | L0 | medium | CWE-78 | `cmdi/convert.py:4` | OS command injection | open |
| CAA-50a74a04 | L0 | medium | CWE-78 | `cmdi/convert_fixed.py:4` | OS command injection | open |
| CAA-33eb8487 | L0 | medium | CWE-78 | `cmdi/ping.py:4` | OS command injection | open |
| CAA-dafb7904 | L0 | medium | CWE-78 | `cmdi/ping_fixed.py:4` | OS command injection | open |
| CAA-a1e66f44 | L0 | medium | CWE-78 | `cmdi/ping_fixed.py:14` | OS command injection | open |
| CAA-762151de | L0 | medium | CWE-78 | `cmdi/trap_argv_list.py:4` | OS command injection | open |
| CAA-78baf4e9 | L0 | medium | CWE-78 | `cmdi/trap_argv_list.py:14` | OS command injection | open |
| CAA-ebef619f | L0 | medium | CWE-78 | `cmdi/trap_constant_shell.py:4` | OS command injection | open |
| CAA-c30ec4be | L0 | medium | CWE-78 | `cmdi/trap_digit_guard.py:4` | OS command injection | open |
| CAA-6dc56888 | L0 | medium | CWE-798 | `config/settings.py:8` | Hard-coded credential | open |
| CAA-f67a114b | L0 | medium | CWE-327 | `config/settings_fixed.py:17` | Weak cryptographic hash | open |
| CAA-5cbd1e42 | L0 | medium | CWE-79 | `django_app/notes/views.py:47` | Cross-site scripting | open |
| CAA-71731d51 | L0 | medium | CWE-79 | `fastapi_app/main.py:27` | Cross-site scripting | open |
| CAA-174d715f | L0 | medium | CWE-79 | `fastapi_app/main_fixed.py:28` | Cross-site scripting | open |
| CAA-2ab6d323 | L0 | medium | CWE-89 | `gosvc/handlers.go:16` | SQL injection | open |
| CAA-66a95c6c | L0 | medium | CWE-79 | `gosvc/handlers.go:36` | Cross-site scripting | open |
| CAA-9bd0d292 | L0 | medium | CWE-400 | `gosvc/handlers.go:44` | Use of net/http serve function that has no support for setti | open |
| CAA-b90c5897 | L0 | medium | CWE-78 | `gosvc/handlers_fixed.go:22` | OS command injection | open |
| CAA-999aed93 | L0 | medium | CWE-22 | `java/src/FileController.java:11` | Path traversal | open |
| CAA-16d66813 | L0 | medium | CWE-78 | `java/src/FileController.java:16` | OS command injection | open |
| CAA-2d11d26c | L0 | medium | CWE-79 | `java/src/SearchServlet.java:9` | Cross-site scripting | open |
| CAA-40848555 | L0 | medium | CWE-89 | `java/src/UserServlet.java:16` | SQL injection | open |
| CAA-69db5bb2 | L0 | medium | CWE-611 | `java/src/XmlImport.java:8` | XML parser created without disabling DOCTYPE / external enti | open |
| CAA-40a6ab67 | L0 | medium | CWE-22 | `js/files.ts:8` | Path traversal | open |
| CAA-260accae | L0 | medium | CWE-79 | `js/greet.js:6` | Cross-site scripting | open |
| CAA-96ed0a1d | L0 | medium | CWE-78 | `js/ping.js:7` | OS command injection | open |
| CAA-c5e9afc1 | L0 | medium | CWE-601 | `js/redirect.ts:6` | Request data decides the redirect target. | open |
| CAA-3dcf722d | L0 | medium | CWE-22 | `path/avatar.py:12` | Path traversal | open |
| CAA-9380f86c | L0 | medium | CWE-22 | `path/denylist.py:15` | Path traversal | open |
| CAA-4e616929 | L0 | medium | CWE-22 | `path/download.py:13` | Path traversal | open |
| CAA-e0caae90 | L0 | medium | CWE-22 | `path/prefix_unnormalised.py:16` | Path traversal | open |
| CAA-ca849552 | L0 | medium | CWE-918 | `ssrf/fetch.py:13` | Server-side request forgery | open |
| CAA-82d32880 | L0 | medium | CWE-353 | `templates/page.html:4` | Script/stylesheet from another origin loaded without Subreso | open |
| CAA-25f0b6f7 | L0 | medium | CWE-1022 | `templates/page.html:7` | Link opens a new tab without rel="noopener" (reverse tabnabb | open |
| CAA-96c1fe60 | L0 | medium | CWE-79 | `templates/page.html:8` | Cross-site scripting | open |
| CAA-b325b146 | L0 | medium | CWE-352 | `templates/page.html:9` | POST form in a Django/Jinja template without a CSRF token. | open |
| CAA-8f85ee5e | L0 | medium | CWE-798 | `tests/test_fixtures.py:1` | Hard-coded credential | open |
| CAA-85569570 | L0 | medium | CWE-79 | `xss/comment.py:10` | Cross-site scripting | open |
| CAA-328f3ef0 | L0 | medium | CWE-79 | `xss/comment_fixed.py:10` | Cross-site scripting | open |
| CAA-8537ace4 | L0 | medium | CWE-79 | `xss/greet.py:10` | Cross-site scripting | open |
| CAA-323ae7ca | L0 | medium | CWE-79 | `xss/greet_fixed.py:10` | Cross-site scripting | open |
| CAA-d1f7588b | L0 | medium | CWE-79 | `xss/search_page.py:10` | Cross-site scripting | open |
| CAA-603ab841 | L0 | medium | CWE-79 | `xss/trap_server_value.py:11` | Cross-site scripting | open |

## CAA-b0df4337 — OS command injection (CWE-78)

- **Location:** `cli_tool/grep_logs.py:10` in `main()`
- **Mapping:** A03:2021 Injection; ASVS V5.3.8
- **Severity:** medium — 
- **Confidence:** L1 (open); reported by semgrep, bandit

**Why it is a risk.** Command executed through a shell with a non-constant command string.

**Evidence ladder:**

- L0 [semgrep,bandit] pattern match: caa.python.cmdi.shell — `cli_tool/grep_logs.py:10`
- L1 [agreement] independent sources agree on place and CWE: bandit, semgrep

**Model triage:** insufficient_data — 

**Not verified:**

- no dynamic (L4) confirmation was performed
- scope: first-party code only; framework and driver behaviour assumed as documented

## CAA-31d6d1a4 — SQL injection (CWE-89)

- **Location:** `cli_tool/report.py:8` in `main()`
- **Mapping:** A03:2021 Injection; ASVS V5.3.4
- **Severity:** medium — 
- **Confidence:** L1 (open); reported by semgrep, bandit

**Why it is a risk.** SQL query text built from a non-constant string is passed to execute().

**Evidence ladder:**

- L0 [semgrep,bandit] pattern match: caa.python.sqli.string-built-query — `cli_tool/report.py:8`
- L1 [agreement] independent sources agree on place and CWE: bandit, semgrep

**Model triage:** insufficient_data — 

**Not verified:**

- no dynamic (L4) confirmation was performed
- scope: first-party code only; framework and driver behaviour assumed as documented

## CAA-b203c778 — OS command injection (CWE-78)

- **Location:** `cmdi/archive.py:14` in `backup()`
- **Mapping:** A03:2021 Injection; ASVS V5.3.8
- **Severity:** medium — 
- **Confidence:** L1 (open); reported by semgrep, bandit

**Why it is a risk.** Command executed through a shell with a non-constant command string.

**Evidence ladder:**

- L0 [semgrep,bandit] pattern match: caa.python.cmdi.shell — `cmdi/archive.py:14`
- L1 [agreement] independent sources agree on place and CWE: bandit, semgrep

**Model triage:** insufficient_data — 

**Not verified:**

- no dynamic (L4) confirmation was performed
- scope: first-party code only; framework and driver behaviour assumed as documented

## CAA-33c18287 — OS command injection (CWE-78)

- **Location:** `cmdi/archive_fixed.py:14` in `backup()`
- **Mapping:** A03:2021 Injection; ASVS V5.3.8
- **Severity:** medium — 
- **Confidence:** L1 (open); reported by semgrep, bandit

**Why it is a risk.** Command executed through a shell with a non-constant command string.

**Evidence ladder:**

- L0 [semgrep,bandit] pattern match: caa.python.cmdi.shell — `cmdi/archive_fixed.py:14`
- L1 [agreement] independent sources agree on place and CWE: bandit, semgrep

**Model triage:** insufficient_data — 

**Not verified:**

- no dynamic (L4) confirmation was performed
- scope: first-party code only; framework and driver behaviour assumed as documented

## CAA-bc2556a7 — OS command injection (CWE-78)

- **Location:** `cmdi/convert.py:13` in `convert_image()`
- **Mapping:** A03:2021 Injection; ASVS V5.3.8
- **Severity:** medium — 
- **Confidence:** L1 (open); reported by semgrep, bandit

**Why it is a risk.** Command executed through a shell with a non-constant command string.

**Evidence ladder:**

- L0 [semgrep,bandit] pattern match: caa.python.cmdi.shell — `cmdi/convert.py:13`
- L1 [agreement] independent sources agree on place and CWE: bandit, semgrep

**Model triage:** insufficient_data — 

**Not verified:**

- no dynamic (L4) confirmation was performed
- scope: first-party code only; framework and driver behaviour assumed as documented

## CAA-9a968212 — OS command injection (CWE-78)

- **Location:** `cmdi/convert_fixed.py:13` in `convert_image()`
- **Mapping:** A03:2021 Injection; ASVS V5.3.8
- **Severity:** medium — 
- **Confidence:** L1 (open); reported by semgrep, bandit

**Why it is a risk.** Command executed through a shell with a non-constant command string.

**Evidence ladder:**

- L0 [semgrep,bandit] pattern match: caa.python.cmdi.shell — `cmdi/convert_fixed.py:13`
- L1 [agreement] independent sources agree on place and CWE: bandit, semgrep

**Model triage:** insufficient_data — The inputs 'src' and 'fmt' used to construct the command in convert_image() are strictly validated in the caller function convert(). 'src' is validated against a strict alphanumeric regex using re.fullmatch (cmdi/convert_fixed.py:20), and 'fmt' is checked against a small allow-list of extensions (cmdi/convert_fixed.py:22). This prevents any shell metacharacters from reaching the subprocess.check_o

**Not verified:**

- model's refutation rejected: no protection_ref given
- no dynamic (L4) confirmation was performed
- scope: first-party code only; framework and driver behaviour assumed as documented

## CAA-1abe4edd — OS command injection (CWE-78)

- **Location:** `cmdi/ping.py:14` in `ping()`
- **Mapping:** A03:2021 Injection; ASVS V5.3.8
- **Severity:** medium — 
- **Confidence:** L1 (open); reported by semgrep, bandit

**Why it is a risk.** Command executed through a shell with a non-constant command string.

**Evidence ladder:**

- L0 [semgrep,bandit] pattern match: caa.python.cmdi.shell — `cmdi/ping.py:14`
- L1 [agreement] independent sources agree on place and CWE: bandit, semgrep

**Model triage:** insufficient_data — 

**Not verified:**

- no dynamic (L4) confirmation was performed
- scope: first-party code only; framework and driver behaviour assumed as documented

## CAA-aaf0c737 — OS command injection (CWE-78)

- **Location:** `cmdi/trap_digit_guard.py:16` in `kill_job()`
- **Mapping:** A03:2021 Injection; ASVS V5.3.8
- **Severity:** medium — 
- **Confidence:** L1 (open); reported by semgrep, bandit

**Why it is a risk.** Command executed through a shell with a non-constant command string.

**Evidence ladder:**

- L0 [semgrep,bandit] pattern match: caa.python.cmdi.shell — `cmdi/trap_digit_guard.py:16`
- L1 [agreement] independent sources agree on place and CWE: bandit, semgrep

**Model triage:** insufficient_data — 

**Not verified:**

- no dynamic (L4) confirmation was performed
- scope: first-party code only; framework and driver behaviour assumed as documented

## CAA-8cc39187 — Hard-coded credential (CWE-798)

- **Location:** `config/settings.py:6`
- **Mapping:** A07:2021 Identification and Authentication Failures; ASVS V2.10.4
- **Severity:** medium — 
- **Confidence:** L1 (open); reported by semgrep, bandit

**Why it is a risk.** Credential-like value hard-coded in source.

**Evidence ladder:**

- L0 [semgrep,bandit] pattern match: caa.python.secrets.hardcoded-credential — `config/settings.py:6`
- L1 [agreement] independent sources agree on place and CWE: bandit, semgrep

**Model triage:** insufficient_data — 

**Not verified:**

- scope: first-party code only; framework and driver behaviour assumed as documented

## CAA-4db4bc61 — Weak cryptographic hash (CWE-327)

- **Location:** `config/settings.py:12` in `hash_password()`
- **Mapping:** A02:2021 Cryptographic Failures; ASVS V6.2.5
- **Severity:** medium — 
- **Confidence:** L1 (open); reported by semgrep, bandit

**Why it is a risk.** Weak hash algorithm used (MD5/SHA1).

**Evidence ladder:**

- L0 [semgrep,bandit] pattern match: caa.python.crypto.weak-hash — `config/settings.py:12`
- L1 [agreement] independent sources agree on place and CWE: bandit, semgrep

**Model triage:** insufficient_data — 

**Not verified:**

- scope: first-party code only; framework and driver behaviour assumed as documented

## CAA-85a78868 — Debug mode enabled (CWE-489)

- **Location:** `config/settings.py:16`
- **Mapping:** A05:2021 Security Misconfiguration; ASVS V14.3.2
- **Severity:** medium — 
- **Confidence:** L1 (open); reported by semgrep, bandit, llm

**Why it is a risk.** Flask debug mode enabled (interactive debugger exposes code execution).

**Evidence ladder:**

- L0 [semgrep,bandit] pattern match: caa.python.config.flask-debug — `config/settings.py:16`
- L1 [agreement] independent sources agree on place and CWE: bandit, semgrep
- L1 [llm-triage] model agrees, with verified citations — `config/settings.py:16`

**Model triage:** vulnerable — The application explicitly enables Flask's debug mode using `app.run(debug=True)` at config/settings.py:16. While this is wrapped in an `if __name__ == '__main__':` block, this is not a sufficient protection against the debugger being enabled if the application is started by running the script directly in a production environment. The knowledge card specifies that a real sanitizer would be an envi

**Not verified:**

- scope: first-party code only; framework and driver behaviour assumed as documented

## CAA-6c90af1b — SQL injection (CWE-89)

- **Location:** `django_app/notes/views.py:32` in `note_search()`
- **Mapping:** A03:2021 Injection; ASVS V5.3.4
- **Severity:** medium — 
- **Confidence:** L1 (open); reported by semgrep, bandit

**Why it is a risk.** SQL query text built from a non-constant string is passed to execute().

**Evidence ladder:**

- L0 [semgrep,bandit] pattern match: caa.python.sqli.string-built-query — `django_app/notes/views.py:32`
- L1 [agreement] independent sources agree on place and CWE: bandit, semgrep

**Model triage:** insufficient_data — 

**Not verified:**

- no dynamic (L4) confirmation was performed
- scope: first-party code only; framework and driver behaviour assumed as documented

## CAA-63e88b21 — Hard-coded credential (CWE-798)

- **Location:** `django_app/settings.py:2`
- **Mapping:** A07:2021 Identification and Authentication Failures; ASVS V2.10.4
- **Severity:** medium — 
- **Confidence:** L1 (open); reported by semgrep, bandit

**Why it is a risk.** Credential-like value hard-coded in source.

**Evidence ladder:**

- L0 [semgrep,bandit] pattern match: caa.python.secrets.hardcoded-credential — `django_app/settings.py:2`
- L1 [agreement] independent sources agree on place and CWE: bandit, semgrep

**Model triage:** insufficient_data — 

**Not verified:**

- scope: first-party code only; framework and driver behaviour assumed as documented

## CAA-3f0420fa — SQL injection (CWE-89)

- **Location:** `fastapi_app/main.py:21` in `read_item()`
- **Mapping:** A03:2021 Injection; ASVS V5.3.4
- **Severity:** medium — 
- **Confidence:** L1 (open); reported by semgrep, bandit

**Why it is a risk.** SQL query text built from a non-constant string is passed to execute().

**Evidence ladder:**

- L0 [semgrep,bandit] pattern match: caa.python.sqli.string-built-query — `fastapi_app/main.py:21`
- L1 [agreement] independent sources agree on place and CWE: bandit, semgrep

**Model triage:** insufficient_data — 

**Not verified:**

- no dynamic (L4) confirmation was performed
- scope: first-party code only; framework and driver behaviour assumed as documented

## CAA-8dfb2540 — OS command injection (CWE-78)

- **Location:** `gosvc/handlers.go:24`
- **Mapping:** A03:2021 Injection; ASVS V5.3.8
- **Severity:** medium — 
- **Confidence:** L1 (open); reported by semgrep, gosec

**Why it is a risk.** Request data reaches a shell command.

**Evidence ladder:**

- L0 [semgrep,gosec] pattern match: caa.go.cmdi.taint — `gosvc/handlers.go:24`
- L1 [agreement] independent sources agree on place and CWE: gosec, semgrep

**Model triage:** insufficient_data — 

**Not verified:**

- no dynamic (L4) confirmation was performed
- scope: first-party code only; framework and driver behaviour assumed as documented

## CAA-6daca4e3 — Path traversal (CWE-22)

- **Location:** `gosvc/handlers.go:30`
- **Mapping:** A01:2021 Broken Access Control; ASVS V12.3.1
- **Severity:** medium — 
- **Confidence:** L1 (open); reported by semgrep, gosec

**Why it is a risk.** Request data is used as a file path.

**Evidence ladder:**

- L0 [semgrep,gosec] pattern match: caa.go.path.taint — `gosvc/handlers.go:30`
- L1 [agreement] independent sources agree on place and CWE: gosec, semgrep

**Model triage:** insufficient_data — 

**Not verified:**

- no dynamic (L4) confirmation was performed
- scope: first-party code only; framework and driver behaviour assumed as documented

## CAA-1e0cb09f — Request data is evaluated as code. (CWE-94)

- **Location:** `js/calc.js:6`
- **Mapping:** A03:2021 Injection; ASVS V5.2.4
- **Severity:** medium — 
- **Confidence:** L1 (open); reported by semgrep, llm

**Why it is a risk.** Request data is evaluated as code.

**Evidence ladder:**

- L0 [semgrep] pattern match: caa.js.code-injection.taint — `js/calc.js:6`
- L1 [llm-triage] model agrees, with verified citations — `js/calc.js:6`, `js/calc.js:6`

**Model triage:** vulnerable — The endpoint /calc accepts a POST request and passes the 'expr' field from the request body directly into the JavaScript eval() function. This allows an attacker to execute arbitrary JavaScript code on the server, leading to full remote code execution (RCE).

**Not verified:**

- no dynamic (L4) confirmation was performed
- scope: first-party code only; framework and driver behaviour assumed as documented

## CAA-d101b85a — SQL injection (CWE-89)

- **Location:** `js/users.js:7`
- **Mapping:** A03:2021 Injection; ASVS V5.3.4
- **Severity:** medium — 
- **Confidence:** L1 (open); reported by semgrep, llm

**Why it is a risk.** Request data reaches a SQL query string.

**Evidence ladder:**

- L0 [semgrep] pattern match: caa.js.sqli.taint — `js/users.js:7`
- L1 [llm-triage] model agrees, with verified citations — `js/users.js:6`, `js/users.js:7`

**Model triage:** vulnerable — The code directly concatenates user-supplied input from the query string into a SQL query. This allows an attacker to manipulate the SQL statement by providing a specially crafted 'name' parameter, leading to a classic SQL injection vulnerability. Although the current implementation of db.query in js/db.js is a stub, the logic in js/users.js is fundamentally vulnerable.

**Not verified:**

- no dynamic (L4) confirmation was performed
- scope: first-party code only; framework and driver behaviour assumed as documented

## CAA-8438defd — SQL injection (CWE-89)

- **Location:** `sqli/injected_comment.py:17` in `staff_lookup()`
- **Mapping:** A03:2021 Injection; ASVS V5.3.4
- **Severity:** medium — 
- **Confidence:** L1 (open); reported by semgrep, bandit

**Why it is a risk.** SQL query text built from a non-constant string is passed to execute().

**Evidence ladder:**

- L0 [semgrep,bandit] pattern match: caa.python.sqli.string-built-query — `sqli/injected_comment.py:17`
- L1 [agreement] independent sources agree on place and CWE: bandit, semgrep

**Model triage:** insufficient_data — 

**Not verified:**

- no dynamic (L4) confirmation was performed
- scope: first-party code only; framework and driver behaviour assumed as documented

## CAA-394c76d5 — SQL injection (CWE-89)

- **Location:** `sqli/orders_concat.py:17` in `list_orders()`
- **Mapping:** A03:2021 Injection; ASVS V5.3.4
- **Severity:** medium — 
- **Confidence:** L1 (open); reported by semgrep, bandit

**Why it is a risk.** SQL query text built from a non-constant string is passed to execute().

**Evidence ladder:**

- L0 [semgrep,bandit] pattern match: caa.python.sqli.string-built-query — `sqli/orders_concat.py:17`
- L1 [agreement] independent sources agree on place and CWE: bandit, semgrep

**Model triage:** insufficient_data — 

**Not verified:**

- no dynamic (L4) confirmation was performed
- scope: first-party code only; framework and driver behaviour assumed as documented

## CAA-8b6f3dd1 — SQL injection (CWE-89)

- **Location:** `sqli/repo_layer.py:7` in `find_product()`
- **Mapping:** A03:2021 Injection; ASVS V5.3.4
- **Severity:** medium — 
- **Confidence:** L1 (open); reported by semgrep, bandit

**Why it is a risk.** SQL query text built from a non-constant string is passed to execute().

**Evidence ladder:**

- L0 [semgrep,bandit] pattern match: caa.python.sqli.string-built-query — `sqli/repo_layer.py:7`
- L1 [agreement] independent sources agree on place and CWE: bandit, semgrep

**Model triage:** insufficient_data — 

**Not verified:**

- no dynamic (L4) confirmation was performed
- scope: first-party code only; framework and driver behaviour assumed as documented

## CAA-0067bc10 — SQL injection (CWE-89)

- **Location:** `sqli/report_percent.py:16` in `report()`
- **Mapping:** A03:2021 Injection; ASVS V5.3.4
- **Severity:** medium — 
- **Confidence:** L1 (open); reported by semgrep, bandit

**Why it is a risk.** SQL query text built from a non-constant string is passed to execute().

**Evidence ladder:**

- L0 [semgrep,bandit] pattern match: caa.python.sqli.string-built-query — `sqli/report_percent.py:16`
- L1 [agreement] independent sources agree on place and CWE: bandit, semgrep

**Model triage:** insufficient_data — 

**Not verified:**

- no dynamic (L4) confirmation was performed
- scope: first-party code only; framework and driver behaviour assumed as documented

## CAA-875d5129 — SQL injection (CWE-89)

- **Location:** `sqli/user_lookup.py:16` in `search_users()`
- **Mapping:** A03:2021 Injection; ASVS V5.3.4
- **Severity:** medium — 
- **Confidence:** L1 (open); reported by semgrep, bandit

**Why it is a risk.** SQL query text built from a non-constant string is passed to execute().

**Evidence ladder:**

- L0 [semgrep,bandit] pattern match: caa.python.sqli.string-built-query — `sqli/user_lookup.py:16`
- L1 [agreement] independent sources agree on place and CWE: bandit, semgrep

**Model triage:** insufficient_data — 

**Not verified:**

- no dynamic (L4) confirmation was performed
- scope: first-party code only; framework and driver behaviour assumed as documented

## CAA-016e3741 — Cross-site scripting (CWE-79)

- **Location:** `xss/search_page_fixed.py:10` in `search()`
- **Mapping:** A03:2021 Injection; ASVS V5.3.3
- **Severity:** medium — 
- **Confidence:** L1 (open); reported by semgrep, llm

**Why it is a risk.** HTML built by string formatting is returned from a request handler without escaping.

**Evidence ladder:**

- L0 [semgrep] pattern match: caa.python.xss.raw-html-response — `xss/search_page_fixed.py:10`
- L1 [llm-triage] model agrees, with verified citations — `xss/search_page_fixed.py:9`, `xss/search_page_fixed.py:10`, `xss/search_page_fixed.py:10`

**Model triage:** vulnerable — The application takes user input from the 'q' query parameter and renders it using 'render_template_string'. Unlike 'render_template', 'render_template_string' does not enable autoescaping by default in Flask because it does not have a filename extension (like .html) to determine the output format. Consequently, any HTML or script tags provided in the 'q' parameter will be rendered raw in the brow

**Not verified:**

- no dynamic (L4) confirmation was performed
- scope: first-party code only; framework and driver behaviour assumed as documented

## CAA-bbb7d647 — OS command injection (CWE-78)

- **Location:** `cli_tool/grep_logs.py:2`
- **Mapping:** A03:2021 Injection; ASVS V5.3.8
- **Severity:** medium — 
- **Confidence:** L0 (open); reported by bandit

**Why it is a risk.** Consider possible security implications associated with the subprocess module.

**Evidence ladder:**

- L0 [bandit] pattern match: bandit.B404.blacklist — `cli_tool/grep_logs.py:2`

**Model triage:** insufficient_data — 

**Not verified:**

- no dynamic (L4) confirmation was performed
- scope: first-party code only; framework and driver behaviour assumed as documented

## CAA-dc0c73b2 — OS command injection (CWE-78)

- **Location:** `cli_tool/grep_logs_fixed.py:2`
- **Mapping:** A03:2021 Injection; ASVS V5.3.8
- **Severity:** medium — 
- **Confidence:** L0 (open); reported by bandit

**Why it is a risk.** Consider possible security implications associated with the subprocess module.

**Evidence ladder:**

- L0 [bandit] pattern match: bandit.B404.blacklist — `cli_tool/grep_logs_fixed.py:2`

**Model triage:** insufficient_data — The code uses `subprocess.run` with a list of arguments and the default `shell=False`. In this mode, the arguments are passed directly to the operating system's execution API without being interpreted by a shell, which prevents OS command injection. Additionally, the use of `--` ensures that the user-provided pattern is not interpreted as a command-line option for grep.

**Not verified:**

- model's refutation rejected: cli_tool/grep_logs_fixed.py:10 is outside the data path (sink function / call chain)
- no dynamic (L4) confirmation was performed
- scope: first-party code only; framework and driver behaviour assumed as documented

## CAA-05bfc924 — OS command injection (CWE-78)

- **Location:** `cli_tool/grep_logs_fixed.py:10` in `main()`
- **Mapping:** A03:2021 Injection; ASVS V5.3.8
- **Severity:** medium — 
- **Confidence:** L0 (open); reported by bandit

**Why it is a risk.** Starting a process with a partial executable path

**Evidence ladder:**

- L0 [bandit] pattern match: bandit.B607.start_process_with_partial_path — `cli_tool/grep_logs_fixed.py:10`

**Model triage:** insufficient_data — 

**Not verified:**

- model's refutation rejected: cli_tool/grep_logs_fixed.py:10 is the candidate's own line, not a protection
- no dynamic (L4) confirmation was performed
- scope: first-party code only; framework and driver behaviour assumed as documented

## CAA-d8fa872f — OS command injection (CWE-78)

- **Location:** `cmdi/archive.py:4`
- **Mapping:** A03:2021 Injection; ASVS V5.3.8
- **Severity:** medium — 
- **Confidence:** L0 (open); reported by bandit

**Why it is a risk.** Consider possible security implications associated with the subprocess module.

**Evidence ladder:**

- L0 [bandit] pattern match: bandit.B404.blacklist — `cmdi/archive.py:4`

**Model triage:** insufficient_data — 

**Not verified:**

- no dynamic (L4) confirmation was performed
- scope: first-party code only; framework and driver behaviour assumed as documented

## CAA-433bad03 — OS command injection (CWE-78)

- **Location:** `cmdi/archive_fixed.py:4`
- **Mapping:** A03:2021 Injection; ASVS V5.3.8
- **Severity:** medium — 
- **Confidence:** L0 (open); reported by bandit

**Why it is a risk.** Consider possible security implications associated with the subprocess module.

**Evidence ladder:**

- L0 [bandit] pattern match: bandit.B404.blacklist — `cmdi/archive_fixed.py:4`

**Model triage:** insufficient_data — The user input 'name' from the request form is passed through 'shlex.quote()' before being concatenated into the command string executed by 'os.system()'. 'shlex.quote()' properly escapes the input to ensure it is treated as a single shell argument, preventing OS command injection.

**Not verified:**

- model's refutation rejected: cmdi/archive_fixed.py:14 is outside the data path (sink function / call chain)
- no dynamic (L4) confirmation was performed
- scope: first-party code only; framework and driver behaviour assumed as documented

## CAA-68fcdaa6 — OS command injection (CWE-78)

- **Location:** `cmdi/convert.py:4`
- **Mapping:** A03:2021 Injection; ASVS V5.3.8
- **Severity:** medium — 
- **Confidence:** L0 (open); reported by bandit

**Why it is a risk.** Consider possible security implications associated with the subprocess module.

**Evidence ladder:**

- L0 [bandit] pattern match: bandit.B404.blacklist — `cmdi/convert.py:4`

**Model triage:** insufficient_data — 

**Not verified:**

- no dynamic (L4) confirmation was performed
- scope: first-party code only; framework and driver behaviour assumed as documented

## CAA-50a74a04 — OS command injection (CWE-78)

- **Location:** `cmdi/convert_fixed.py:4`
- **Mapping:** A03:2021 Injection; ASVS V5.3.8
- **Severity:** medium — 
- **Confidence:** L0 (open); reported by bandit

**Why it is a risk.** Consider possible security implications associated with the subprocess module.

**Evidence ladder:**

- L0 [bandit] pattern match: bandit.B404.blacklist — `cmdi/convert_fixed.py:4`

**Model triage:** insufficient_data — The inputs 'src' and 'fmt' are strictly validated against allow-lists before being used in the shell command. 'src' is validated using a regular expression that only allows alphanumeric characters, underscores, hyphens, and specific extensions (cmdi/convert_fixed.py:20). 'fmt' is checked against a fixed set of allowed extensions (cmdi/convert_fixed.py:22). This prevents any shell metacharacters fr

**Not verified:**

- model's refutation rejected: cmdi/convert_fixed.py:20 is outside the data path (sink function / call chain)
- no dynamic (L4) confirmation was performed
- scope: first-party code only; framework and driver behaviour assumed as documented

## CAA-33eb8487 — OS command injection (CWE-78)

- **Location:** `cmdi/ping.py:4`
- **Mapping:** A03:2021 Injection; ASVS V5.3.8
- **Severity:** medium — 
- **Confidence:** L0 (open); reported by bandit

**Why it is a risk.** Consider possible security implications associated with the subprocess module.

**Evidence ladder:**

- L0 [bandit] pattern match: bandit.B404.blacklist — `cmdi/ping.py:4`

**Model triage:** insufficient_data — 

**Not verified:**

- no dynamic (L4) confirmation was performed
- scope: first-party code only; framework and driver behaviour assumed as documented

## CAA-dafb7904 — OS command injection (CWE-78)

- **Location:** `cmdi/ping_fixed.py:4`
- **Mapping:** A03:2021 Injection; ASVS V5.3.8
- **Severity:** medium — 
- **Confidence:** L0 (open); reported by bandit

**Why it is a risk.** Consider possible security implications associated with the subprocess module.

**Evidence ladder:**

- L0 [bandit] pattern match: bandit.B404.blacklist — `cmdi/ping_fixed.py:4`

**Model triage:** insufficient_data — The application uses `subprocess.run` with a list of arguments and the default `shell=False` setting. This ensures that the user-provided `host` input is treated as a single argument to the `ping` command and is not interpreted by a shell, preventing OS command injection.

**Not verified:**

- model's refutation rejected: cmdi/ping_fixed.py:14 is outside the data path (sink function / call chain)
- no dynamic (L4) confirmation was performed
- scope: first-party code only; framework and driver behaviour assumed as documented

## CAA-a1e66f44 — OS command injection (CWE-78)

- **Location:** `cmdi/ping_fixed.py:14` in `ping()`
- **Mapping:** A03:2021 Injection; ASVS V5.3.8
- **Severity:** medium — 
- **Confidence:** L0 (open); reported by bandit

**Why it is a risk.** Starting a process with a partial executable path

**Evidence ladder:**

- L0 [bandit] pattern match: bandit.B607.start_process_with_partial_path — `cmdi/ping_fixed.py:14`

**Model triage:** insufficient_data — The code uses subprocess.run with a list of arguments and the default shell=False. This prevents shell injection because the arguments are passed directly to the operating system's process creation API without being interpreted by a shell. The Bandit warning refers to the use of a relative path for the executable, which is a different issue from command injection.

**Not verified:**

- model's refutation rejected: cmdi/ping_fixed.py:14 is the candidate's own line, not a protection
- no dynamic (L4) confirmation was performed
- scope: first-party code only; framework and driver behaviour assumed as documented

## CAA-762151de — OS command injection (CWE-78)

- **Location:** `cmdi/trap_argv_list.py:4`
- **Mapping:** A03:2021 Injection; ASVS V5.3.8
- **Severity:** medium — 
- **Confidence:** L0 (open); reported by bandit

**Why it is a risk.** Consider possible security implications associated with the subprocess module.

**Evidence ladder:**

- L0 [bandit] pattern match: bandit.B404.blacklist — `cmdi/trap_argv_list.py:4`

**Model triage:** insufficient_data — The application uses `subprocess.run` with a list of arguments and the default `shell=False` setting. This prevents shell metacharacters in the `domain` variable from being interpreted as commands, as the arguments are passed directly to the `nslookup` executable.

**Not verified:**

- model's refutation rejected: cmdi/trap_argv_list.py:14 is outside the data path (sink function / call chain)
- no dynamic (L4) confirmation was performed
- scope: first-party code only; framework and driver behaviour assumed as documented

## CAA-78baf4e9 — OS command injection (CWE-78)

- **Location:** `cmdi/trap_argv_list.py:14` in `lookup()`
- **Mapping:** A03:2021 Injection; ASVS V5.3.8
- **Severity:** medium — 
- **Confidence:** L0 (open); reported by bandit

**Why it is a risk.** Starting a process with a partial executable path

**Evidence ladder:**

- L0 [bandit] pattern match: bandit.B607.start_process_with_partial_path — `cmdi/trap_argv_list.py:14`

**Model triage:** insufficient_data — 

**Not verified:**

- model's refutation rejected: cmdi/trap_argv_list.py:14 is the candidate's own line, not a protection
- no dynamic (L4) confirmation was performed
- scope: first-party code only; framework and driver behaviour assumed as documented

## CAA-ebef619f — OS command injection (CWE-78)

- **Location:** `cmdi/trap_constant_shell.py:4`
- **Mapping:** A03:2021 Injection; ASVS V5.3.8
- **Severity:** medium — 
- **Confidence:** L0 (open); reported by bandit

**Why it is a risk.** Consider possible security implications associated with the subprocess module.

**Evidence ladder:**

- L0 [bandit] pattern match: bandit.B404.blacklist — `cmdi/trap_constant_shell.py:4`

**Model triage:** insufficient_data — 

**Not verified:**

- no dynamic (L4) confirmation was performed
- scope: first-party code only; framework and driver behaviour assumed as documented

## CAA-c30ec4be — OS command injection (CWE-78)

- **Location:** `cmdi/trap_digit_guard.py:4`
- **Mapping:** A03:2021 Injection; ASVS V5.3.8
- **Severity:** medium — 
- **Confidence:** L0 (open); reported by bandit

**Why it is a risk.** Consider possible security implications associated with the subprocess module.

**Evidence ladder:**

- L0 [bandit] pattern match: bandit.B404.blacklist — `cmdi/trap_digit_guard.py:4`

**Model triage:** insufficient_data — The user input 'pid' is retrieved from the request form and immediately validated using the `.isdigit()` method. If the input contains any characters other than digits, the application aborts with a 400 error. Since only digits are allowed, no shell metacharacters can be passed to the `os.system` call at line 16, preventing OS command injection.

**Not verified:**

- model's refutation rejected: cmdi/trap_digit_guard.py:14 is outside the data path (sink function / call chain)
- no dynamic (L4) confirmation was performed
- scope: first-party code only; framework and driver behaviour assumed as documented

## CAA-6dc56888 — Hard-coded credential (CWE-798)

- **Location:** `config/settings.py:8`
- **Mapping:** A07:2021 Identification and Authentication Failures; ASVS V2.10.4
- **Severity:** medium — 
- **Confidence:** L0 (open); reported by bandit

**Why it is a risk.** Possible hardcoded password: 'Wint****[18]'

**Evidence ladder:**

- L0 [bandit] pattern match: bandit.B105.hardcoded_password_string — `config/settings.py:8`

**Model triage:** insufficient_data — 

**Not verified:**

- scope: first-party code only; framework and driver behaviour assumed as documented

## CAA-f67a114b — Weak cryptographic hash (CWE-327)

- **Location:** `config/settings_fixed.py:17` in `cache_key()`
- **Mapping:** A02:2021 Cryptographic Failures; ASVS V6.2.5
- **Severity:** medium — 
- **Confidence:** L0 (open); reported by semgrep

**Why it is a risk.** Weak hash algorithm used (MD5/SHA1).

**Evidence ladder:**

- L0 [semgrep] pattern match: caa.python.crypto.weak-hash — `config/settings_fixed.py:17`

**Model triage:** insufficient_data — 

**Not verified:**

- model's refutation rejected: config/settings_fixed.py:17 is the candidate's own line, not a protection
- scope: first-party code only; framework and driver behaviour assumed as documented

## CAA-5cbd1e42 — Cross-site scripting (CWE-79)

- **Location:** `django_app/notes/views.py:47` in `greet()`
- **Mapping:** A03:2021 Injection; ASVS V5.3.3
- **Severity:** medium — 
- **Confidence:** L0 (open); reported by semgrep

**Why it is a risk.** HTML response (Django/FastAPI/Starlette) built by string formatting, or escaping disabled.

**Evidence ladder:**

- L0 [semgrep] pattern match: caa.python.xss.framework-html-response — `django_app/notes/views.py:47`

**Model triage:** insufficient_data — 

**Not verified:**

- no dynamic (L4) confirmation was performed
- scope: first-party code only; framework and driver behaviour assumed as documented

## CAA-71731d51 — Cross-site scripting (CWE-79)

- **Location:** `fastapi_app/main.py:27` in `greet()`
- **Mapping:** A03:2021 Injection; ASVS V5.3.3
- **Severity:** medium — 
- **Confidence:** L0 (open); reported by semgrep

**Why it is a risk.** HTML response (Django/FastAPI/Starlette) built by string formatting, or escaping disabled.

**Evidence ladder:**

- L0 [semgrep] pattern match: caa.python.xss.framework-html-response — `fastapi_app/main.py:27`

**Model triage:** insufficient_data — The application takes a user-provided string 'name' from the query parameters and embeds it directly into an HTML response using an f-string. Since HTMLResponse does not perform automatic escaping of its content, an attacker can inject arbitrary HTML or JavaScript (e.g., ?name=<script>alert(1)</script>), leading to reflected Cross-Site Scripting (XSS).

**Not verified:**

- 1 model claim(s) discarded: cited lines were never read
- no dynamic (L4) confirmation was performed
- scope: first-party code only; framework and driver behaviour assumed as documented

## CAA-174d715f — Cross-site scripting (CWE-79)

- **Location:** `fastapi_app/main_fixed.py:28` in `greet()`
- **Mapping:** A03:2021 Injection; ASVS V5.3.3
- **Severity:** medium — 
- **Confidence:** L0 (open); reported by semgrep

**Why it is a risk.** HTML response (Django/FastAPI/Starlette) built by string formatting, or escaping disabled.

**Evidence ladder:**

- L0 [semgrep] pattern match: caa.python.xss.framework-html-response — `fastapi_app/main_fixed.py:28`

**Model triage:** insufficient_data — The user input `name` is passed through `markupsafe.escape` (imported on line 6) before being embedded in the HTML response. According to the knowledge card, `markupsafe.escape` is a real sanitizer that prevents XSS by escaping HTML special characters.

**Not verified:**

- model's refutation rejected: fastapi_app/main_fixed.py:28 is the candidate's own line, not a protection
- no dynamic (L4) confirmation was performed
- scope: first-party code only; framework and driver behaviour assumed as documented

## CAA-2ab6d323 — SQL injection (CWE-89)

- **Location:** `gosvc/handlers.go:16`
- **Mapping:** A03:2021 Injection; ASVS V5.3.4
- **Severity:** medium — 
- **Confidence:** L0 (open); reported by semgrep

**Why it is a risk.** Request data reaches a SQL query string.

**Evidence ladder:**

- L0 [semgrep] pattern match: caa.go.sqli.taint — `gosvc/handlers.go:16`

**Model triage:** insufficient_data — 

**Not verified:**

- no dynamic (L4) confirmation was performed
- scope: first-party code only; framework and driver behaviour assumed as documented

## CAA-66a95c6c — Cross-site scripting (CWE-79)

- **Location:** `gosvc/handlers.go:36`
- **Mapping:** A03:2021 Injection; ASVS V5.3.3
- **Severity:** medium — 
- **Confidence:** L0 (open); reported by semgrep

**Why it is a risk.** Request data is written into an HTML response without escaping.

**Evidence ladder:**

- L0 [semgrep] pattern match: caa.go.xss.taint — `gosvc/handlers.go:36`

**Model triage:** insufficient_data — 

**Not verified:**

- no dynamic (L4) confirmation was performed
- scope: first-party code only; framework and driver behaviour assumed as documented

## CAA-9bd0d292 — Use of net/http serve function that has no support for setti (CWE-400)

- **Location:** `gosvc/handlers.go:44`
- **Mapping:** A04:2021 Insecure Design; ASVS V12.1.1
- **Severity:** medium — 
- **Confidence:** L0 (open); reported by gosec

**Why it is a risk.** Use of net/http serve function that has no support for setting timeouts

**Evidence ladder:**

- L0 [gosec] pattern match: G114 — `gosvc/handlers.go:44`

**Model triage:** insufficient_data — 

**Not verified:**

- no dynamic (L4) confirmation was performed
- scope: first-party code only; framework and driver behaviour assumed as documented

## CAA-b90c5897 — OS command injection (CWE-78)

- **Location:** `gosvc/handlers_fixed.go:22`
- **Mapping:** A03:2021 Injection; ASVS V5.3.8
- **Severity:** medium — 
- **Confidence:** L0 (open); reported by gosec

**Why it is a risk.** Subprocess launched with variable

**Evidence ladder:**

- L0 [gosec] pattern match: G204 — `gosvc/handlers_fixed.go:22`

**Model triage:** insufficient_data — 

**Not verified:**

- model's refutation rejected: gosvc/handlers_fixed.go:22 is the candidate's own line, not a protection
- no dynamic (L4) confirmation was performed
- scope: first-party code only; framework and driver behaviour assumed as documented

## CAA-999aed93 — Path traversal (CWE-22)

- **Location:** `java/src/FileController.java:11`
- **Mapping:** A01:2021 Broken Access Control; ASVS V12.3.1
- **Severity:** medium — 
- **Confidence:** L0 (open); reported by semgrep

**Why it is a risk.** Request data is used as a file path.

**Evidence ladder:**

- L0 [semgrep] pattern match: caa.java.path.taint — `java/src/FileController.java:11`

**Model triage:** insufficient_data — 

**Not verified:**

- no dynamic (L4) confirmation was performed
- scope: first-party code only; framework and driver behaviour assumed as documented

## CAA-16d66813 — OS command injection (CWE-78)

- **Location:** `java/src/FileController.java:16`
- **Mapping:** A03:2021 Injection; ASVS V5.3.8
- **Severity:** medium — 
- **Confidence:** L0 (open); reported by semgrep

**Why it is a risk.** Request data reaches a process command.

**Evidence ladder:**

- L0 [semgrep] pattern match: caa.java.cmdi.taint — `java/src/FileController.java:16`

**Model triage:** insufficient_data — 

**Not verified:**

- no dynamic (L4) confirmation was performed
- scope: first-party code only; framework and driver behaviour assumed as documented

## CAA-2d11d26c — Cross-site scripting (CWE-79)

- **Location:** `java/src/SearchServlet.java:9`
- **Mapping:** A03:2021 Injection; ASVS V5.3.3
- **Severity:** medium — 
- **Confidence:** L0 (open); reported by semgrep

**Why it is a risk.** Request data is written to the response without HTML encoding.

**Evidence ladder:**

- L0 [semgrep] pattern match: caa.java.xss.taint — `java/src/SearchServlet.java:9`

**Model triage:** insufficient_data — 

**Not verified:**

- no dynamic (L4) confirmation was performed
- scope: first-party code only; framework and driver behaviour assumed as documented

## CAA-40848555 — SQL injection (CWE-89)

- **Location:** `java/src/UserServlet.java:16`
- **Mapping:** A03:2021 Injection; ASVS V5.3.4
- **Severity:** medium — 
- **Confidence:** L0 (open); reported by semgrep

**Why it is a risk.** Request data reaches a SQL query string.

**Evidence ladder:**

- L0 [semgrep] pattern match: caa.java.sqli.taint — `java/src/UserServlet.java:16`

**Model triage:** insufficient_data — 

**Not verified:**

- no dynamic (L4) confirmation was performed
- scope: first-party code only; framework and driver behaviour assumed as documented

## CAA-69db5bb2 — XML parser created without disabling DOCTYPE / external enti (CWE-611)

- **Location:** `java/src/XmlImport.java:8`
- **Mapping:** A05:2021 Security Misconfiguration; ASVS V5.5.2
- **Severity:** medium — 
- **Confidence:** L0 (open); reported by semgrep

**Why it is a risk.** XML parser created without disabling DOCTYPE / external entities.

**Evidence ladder:**

- L0 [semgrep] pattern match: caa.java.xxe.documentbuilder — `java/src/XmlImport.java:8`

**Model triage:** insufficient_data — The code in `java/src/XmlImport.java` is clearly vulnerable to XXE because it uses `DocumentBuilderFactory` without disabling DTDs or external entities (as evidenced by the existence of `java/src/XmlImportFixed.java` which adds the necessary protection). However, I cannot find any call sites for `XmlImport.parse` or any instantiation of the `XmlImport` class in the provided codebase (searches for 

**Not verified:**

- no dynamic (L4) confirmation was performed
- scope: first-party code only; framework and driver behaviour assumed as documented

## CAA-40a6ab67 — Path traversal (CWE-22)

- **Location:** `js/files.ts:8`
- **Mapping:** A01:2021 Broken Access Control; ASVS V12.3.1
- **Severity:** medium — 
- **Confidence:** L0 (open); reported by semgrep

**Why it is a risk.** Request data is used as a file path.

**Evidence ladder:**

- L0 [semgrep] pattern match: caa.js.path.taint — `js/files.ts:8`

**Model triage:** insufficient_data — 

**Not verified:**

- no dynamic (L4) confirmation was performed
- scope: first-party code only; framework and driver behaviour assumed as documented

## CAA-260accae — Cross-site scripting (CWE-79)

- **Location:** `js/greet.js:6`
- **Mapping:** A03:2021 Injection; ASVS V5.3.3
- **Severity:** medium — 
- **Confidence:** L0 (open); reported by semgrep

**Why it is a risk.** Request data is written into an HTML response without escaping.

**Evidence ladder:**

- L0 [semgrep] pattern match: caa.js.xss.taint — `js/greet.js:6`

**Model triage:** insufficient_data — 

**Not verified:**

- no dynamic (L4) confirmation was performed
- scope: first-party code only; framework and driver behaviour assumed as documented

## CAA-96ed0a1d — OS command injection (CWE-78)

- **Location:** `js/ping.js:7`
- **Mapping:** A03:2021 Injection; ASVS V5.3.8
- **Severity:** medium — 
- **Confidence:** L0 (open); reported by semgrep

**Why it is a risk.** Request data reaches a shell command.

**Evidence ladder:**

- L0 [semgrep] pattern match: caa.js.cmdi.taint — `js/ping.js:7`

**Model triage:** insufficient_data — 

**Not verified:**

- no dynamic (L4) confirmation was performed
- scope: first-party code only; framework and driver behaviour assumed as documented

## CAA-c5e9afc1 — Request data decides the redirect target. (CWE-601)

- **Location:** `js/redirect.ts:6`
- **Mapping:** A01:2021 Broken Access Control; ASVS V5.1.5
- **Severity:** medium — 
- **Confidence:** L0 (open); reported by semgrep

**Why it is a risk.** Request data decides the redirect target.

**Evidence ladder:**

- L0 [semgrep] pattern match: caa.js.open-redirect.taint — `js/redirect.ts:6`

**Model triage:** insufficient_data — 

**Not verified:**

- no dynamic (L4) confirmation was performed
- scope: first-party code only; framework and driver behaviour assumed as documented

## CAA-3dcf722d — Path traversal (CWE-22)

- **Location:** `path/avatar.py:12` in `avatar()`
- **Mapping:** A01:2021 Broken Access Control; ASVS V12.3.1
- **Severity:** medium — 
- **Confidence:** L0 (open); reported by semgrep

**Why it is a risk.** File path built from a non-constant value is opened or served.

**Evidence ladder:**

- L0 [semgrep] pattern match: caa.python.path.user-path-open — `path/avatar.py:12`

**Model triage:** insufficient_data — 

**Not verified:**

- no dynamic (L4) confirmation was performed
- scope: first-party code only; framework and driver behaviour assumed as documented

## CAA-9380f86c — Path traversal (CWE-22)

- **Location:** `path/denylist.py:15` in `docs()`
- **Mapping:** A01:2021 Broken Access Control; ASVS V12.3.1
- **Severity:** medium — 
- **Confidence:** L0 (open); reported by semgrep

**Why it is a risk.** File path built from a non-constant value is opened or served.

**Evidence ladder:**

- L0 [semgrep] pattern match: caa.python.path.user-path-open — `path/denylist.py:15`

**Model triage:** insufficient_data — 

**Not verified:**

- no dynamic (L4) confirmation was performed
- scope: first-party code only; framework and driver behaviour assumed as documented

## CAA-4e616929 — Path traversal (CWE-22)

- **Location:** `path/download.py:13` in `download()`
- **Mapping:** A01:2021 Broken Access Control; ASVS V12.3.1
- **Severity:** medium — 
- **Confidence:** L0 (open); reported by semgrep

**Why it is a risk.** File path built from a non-constant value is opened or served.

**Evidence ladder:**

- L0 [semgrep] pattern match: caa.python.path.user-path-open — `path/download.py:13`

**Model triage:** insufficient_data — 

**Not verified:**

- no dynamic (L4) confirmation was performed
- scope: first-party code only; framework and driver behaviour assumed as documented

## CAA-e0caae90 — Path traversal (CWE-22)

- **Location:** `path/prefix_unnormalised.py:16` in `export()`
- **Mapping:** A01:2021 Broken Access Control; ASVS V12.3.1
- **Severity:** medium — 
- **Confidence:** L0 (open); reported by semgrep

**Why it is a risk.** File path built from a non-constant value is opened or served.

**Evidence ladder:**

- L0 [semgrep] pattern match: caa.python.path.user-path-open — `path/prefix_unnormalised.py:16`

**Model triage:** insufficient_data — 

**Not verified:**

- no dynamic (L4) confirmation was performed
- scope: first-party code only; framework and driver behaviour assumed as documented

## CAA-ca849552 — Server-side request forgery (CWE-918)

- **Location:** `ssrf/fetch.py:13` in `preview()`
- **Mapping:** A10:2021 Server-Side Request Forgery; ASVS V12.6.1
- **Severity:** medium — 
- **Confidence:** L0 (open); reported by semgrep

**Why it is a risk.** Outbound request to a non-constant URL inside a request handler.

**Evidence ladder:**

- L0 [semgrep] pattern match: caa.python.ssrf.user-url-fetch — `ssrf/fetch.py:13`

**Model triage:** insufficient_data — 

**Not verified:**

- no dynamic (L4) confirmation was performed
- scope: first-party code only; framework and driver behaviour assumed as documented

## CAA-82d32880 — Script/stylesheet from another origin loaded without Subreso (CWE-353)

- **Location:** `templates/page.html:4`
- **Mapping:** A08:2021 Software and Data Integrity Failures; ASVS V14.2.3
- **Severity:** medium — 
- **Confidence:** L0 (open); reported by semgrep

**Why it is a risk.** Script/stylesheet from another origin loaded without Subresource Integrity.

**Evidence ladder:**

- L0 [semgrep] pattern match: caa.html.sri-missing — `templates/page.html:4`

**Model triage:** insufficient_data — 

**Not verified:**

- scope: first-party code only; framework and driver behaviour assumed as documented

## CAA-25f0b6f7 — Link opens a new tab without rel="noopener" (reverse tabnabb (CWE-1022)

- **Location:** `templates/page.html:7`
- **Mapping:** A05:2021 Security Misconfiguration; ASVS V14.5.2
- **Severity:** medium — 
- **Confidence:** L0 (open); reported by semgrep

**Why it is a risk.** Link opens a new tab without rel="noopener" (reverse tabnabbing in old browsers).

**Evidence ladder:**

- L0 [semgrep] pattern match: caa.html.target-blank — `templates/page.html:7`

**Model triage:** insufficient_data — The reported issue is a potential reverse tabnabbing (CWE-1022) due to the use of `target='_blank'` without `rel='noopener'`. However, CWE-1022 specifically applies to links to *untrusted* targets. In this case, the `href` attribute is hardcoded to `https://partner.example.org` (templates/page.html:7), meaning the target is developer-controlled and trusted. Since the target is not user-supplied or

**Not verified:**

- model's refutation rejected: templates/page.html:7 is the candidate's own line, not a protection
- scope: first-party code only; framework and driver behaviour assumed as documented

## CAA-96c1fe60 — Cross-site scripting (CWE-79)

- **Location:** `templates/page.html:8`
- **Mapping:** A03:2021 Injection; ASVS V5.3.3
- **Severity:** medium — 
- **Confidence:** L0 (open); reported by semgrep

**Why it is a risk.** Template output with escaping turned off.

**Evidence ladder:**

- L0 [semgrep] pattern match: caa.html.template-unescaped — `templates/page.html:8`

**Model triage:** insufficient_data — I searched for references to 'page.html' and 'render_template' across the entire codebase using `search(pattern='page.html', glob='**/*')` and `search(pattern='render_template', glob='**/*')`, but found no occurrences of 'page.html' being rendered. While the template `templates/page.html` contains a potential XSS sink `{{ comment|safe }}`, I cannot find the corresponding Python code that renders t

**Not verified:**

- no dynamic (L4) confirmation was performed
- scope: first-party code only; framework and driver behaviour assumed as documented

## CAA-b325b146 — POST form in a Django/Jinja template without a CSRF token. (CWE-352)

- **Location:** `templates/page.html:9`
- **Mapping:** A01:2021 Broken Access Control; ASVS V4.2.2
- **Severity:** medium — 
- **Confidence:** L0 (open); reported by semgrep

**Why it is a risk.** POST form in a Django/Jinja template without a CSRF token.

**Evidence ladder:**

- L0 [semgrep] pattern match: caa.html.form-no-csrf — `templates/page.html:9`

**Model triage:** insufficient_data — The template at templates/page.html:9 contains a POST form without a {% csrf_token %}. In Django, this typically results in a 403 Forbidden error if the CsrfViewMiddleware is enabled, making it a functional bug rather than a security vulnerability. However, if the middleware is disabled or the view handling '/profile' is marked as @csrf_exempt, it would be a CSRF vulnerability. I attempted to loca

**Not verified:**

- scope: first-party code only; framework and driver behaviour assumed as documented

## CAA-8f85ee5e — Hard-coded credential (CWE-798)

- **Location:** `tests/test_fixtures.py:1`
- **Mapping:** A07:2021 Identification and Authentication Failures; ASVS V2.10.4
- **Severity:** medium — 
- **Confidence:** L0 (open); reported by bandit

**Why it is a risk.** Possible hardcoded password: 'exam****[20]'

**Evidence ladder:**

- L0 [bandit] pattern match: bandit.B105.hardcoded_password_string — `tests/test_fixtures.py:1`

**Model triage:** insufficient_data — The hard-coded credential is located in a test fixtures file (`tests/test_fixtures.py`) and uses a reserved testing domain (`.test`), identifying it as an obvious placeholder for unit tests rather than a production credential. According to the knowledge card, obvious placeholders in test fixtures are not considered vulnerabilities.

**Not verified:**

- model's refutation rejected: tests/test_fixtures.py:1 is the candidate's own line, not a protection
- scope: first-party code only; framework and driver behaviour assumed as documented

## CAA-85569570 — Cross-site scripting (CWE-79)

- **Location:** `xss/comment.py:10` in `preview()`
- **Mapping:** A03:2021 Injection; ASVS V5.3.3
- **Severity:** medium — 
- **Confidence:** L0 (open); reported by semgrep

**Why it is a risk.** HTML built by string formatting is returned from a request handler without escaping.

**Evidence ladder:**

- L0 [semgrep] pattern match: caa.python.xss.raw-html-response — `xss/comment.py:10`

**Model triage:** insufficient_data — 

**Not verified:**

- no dynamic (L4) confirmation was performed
- scope: first-party code only; framework and driver behaviour assumed as documented

## CAA-328f3ef0 — Cross-site scripting (CWE-79)

- **Location:** `xss/comment_fixed.py:10` in `preview()`
- **Mapping:** A03:2021 Injection; ASVS V5.3.3
- **Severity:** medium — 
- **Confidence:** L0 (open); reported by semgrep

**Why it is a risk.** HTML built by string formatting is returned from a request handler without escaping.

**Evidence ladder:**

- L0 [semgrep] pattern match: caa.python.xss.raw-html-response — `xss/comment_fixed.py:10`

**Model triage:** insufficient_data — The user input 'body' is passed through 'markupsafe.escape' before being concatenated into the HTML response. According to the knowledge card, 'markupsafe.escape' is a real sanitizer for CWE-79.

**Not verified:**

- model's refutation rejected: xss/comment_fixed.py:10 is the candidate's own line, not a protection
- no dynamic (L4) confirmation was performed
- scope: first-party code only; framework and driver behaviour assumed as documented

## CAA-8537ace4 — Cross-site scripting (CWE-79)

- **Location:** `xss/greet.py:10` in `hello()`
- **Mapping:** A03:2021 Injection; ASVS V5.3.3
- **Severity:** medium — 
- **Confidence:** L0 (open); reported by semgrep

**Why it is a risk.** HTML built by string formatting is returned from a request handler without escaping.

**Evidence ladder:**

- L0 [semgrep] pattern match: caa.python.xss.raw-html-response — `xss/greet.py:10`

**Model triage:** insufficient_data — 

**Not verified:**

- no dynamic (L4) confirmation was performed
- scope: first-party code only; framework and driver behaviour assumed as documented

## CAA-323ae7ca — Cross-site scripting (CWE-79)

- **Location:** `xss/greet_fixed.py:10` in `hello()`
- **Mapping:** A03:2021 Injection; ASVS V5.3.3
- **Severity:** medium — 
- **Confidence:** L0 (open); reported by semgrep

**Why it is a risk.** HTML built by string formatting is returned from a request handler without escaping.

**Evidence ladder:**

- L0 [semgrep] pattern match: caa.python.xss.raw-html-response — `xss/greet_fixed.py:10`

**Model triage:** insufficient_data — The user input 'name' is passed through 'markupsafe.escape' before being included in the HTML response, which prevents cross-site scripting by escaping HTML special characters.

**Not verified:**

- model's refutation rejected: xss/greet_fixed.py:10 is the candidate's own line, not a protection
- no dynamic (L4) confirmation was performed
- scope: first-party code only; framework and driver behaviour assumed as documented

## CAA-d1f7588b — Cross-site scripting (CWE-79)

- **Location:** `xss/search_page.py:10` in `search()`
- **Mapping:** A03:2021 Injection; ASVS V5.3.3
- **Severity:** medium — 
- **Confidence:** L0 (open); reported by semgrep

**Why it is a risk.** HTML built by string formatting is returned from a request handler without escaping.

**Evidence ladder:**

- L0 [semgrep] pattern match: caa.python.xss.raw-html-response — `xss/search_page.py:10`

**Model triage:** insufficient_data — 

**Not verified:**

- no dynamic (L4) confirmation was performed
- scope: first-party code only; framework and driver behaviour assumed as documented

## CAA-603ab841 — Cross-site scripting (CWE-79)

- **Location:** `xss/trap_server_value.py:11` in `about()`
- **Mapping:** A03:2021 Injection; ASVS V5.3.3
- **Severity:** medium — 
- **Confidence:** L0 (open); reported by semgrep

**Why it is a risk.** HTML built by string formatting is returned from a request handler without escaping.

**Evidence ladder:**

- L0 [semgrep] pattern match: caa.python.xss.raw-html-response — `xss/trap_server_value.py:11`

**Model triage:** insufficient_data — The reported XSS vulnerability occurs because HTML is built using string formatting. However, the value being inserted into the HTML is `platform.python_version()`, which is a system-provided value from the Python standard library and is not user-controllable. Since there is no user-controlled input reaching the sink, this is not a reachable XSS vulnerability.

**Not verified:**

- model's refutation rejected: xss/trap_server_value.py:11 is the candidate's own line, not a protection
- no dynamic (L4) confirmation was performed
- scope: first-party code only; framework and driver behaviour assumed as documented

## Refuted candidates

| Candidate | CWE | Protection (verified line) | By |
|---|---|---|---|
| `cmdi/trap_constant_shell.py:15` | CWE-78 | `cmdi/trap_constant_shell.py:10`  | llm-triage |
| `gosvc/handlers_fixed.go:28` | CWE-22 | `gosvc/handlers_fixed.go:27`  | llm-triage |
| `path/trap_allowlist.py:16` | CWE-22 | `path/trap_allowlist.py:14`  | llm-triage |
| `path/trap_basename.py:13` | CWE-22 | `path/trap_basename.py:12`  | llm-triage |
| `path/trap_secure_filename.py:13` | CWE-22 | `path/trap_secure_filename.py:12`  | llm-triage |
| `sqli/trap_column_map.py:19` | CWE-89 | `sqli/trap_column_map.py:17`  | llm-triage |
| `sqli/trap_constant_table.py:17` | CWE-89 | `sqli/trap_constant_table.py:11`  | llm-triage |
| `sqli/trap_int_cast.py:17` | CWE-89 | `sqli/trap_int_cast.py:14`  | llm-triage |
| `sqli/trap_sort_allowlist.py:20` | CWE-89 | `sqli/trap_sort_allowlist.py:17`  | llm-triage |
| `ssrf/fetch_fixed.py:16` | CWE-918 | `ssrf/fetch_fixed.py:14`  | llm-triage |
| `xss/trap_int_count.py:10` | CWE-79 | `xss/trap_int_count.py:9`  | llm-triage |

## Run

```json
{
 "stage_seconds": {
  "inventory": 0.0,
  "candidates": 4.37,
  "context": 0.04,
  "triage": 216.02,
  "verify": 0.0
 },
 "candidates": 111,
 "findings_initial": 83,
 "llm_usage": {
  "local": {},
  "gemma_remote": {
   "prompt_tokens": 136044,
   "completion_tokens": 108885,
   "calls": 149
  },
  "groq": {}
 }
}
```
