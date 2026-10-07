# Seeded stand: sast_only

Target: `/home/user/code-audit-agent/eval/seeded/repo`  
Findings: **53 open** (0 need human review), 0 candidates refuted with a cited protection.

Confidence is the highest evidence level reached: L0 pattern · L1 independent agreement · L2 trace · L3 refutation failed · L4 harmless dynamic check · L5 patch verified.

| ID | Level | Severity | CWE | Location | Title | Status |
|---|---|---|---|---|---|---|
| CAA-b203c778 | L1 | medium | CWE-78 | `cmdi/archive.py:14` | OS command injection | open |
| CAA-33c18287 | L1 | medium | CWE-78 | `cmdi/archive_fixed.py:14` | OS command injection | open |
| CAA-bc2556a7 | L1 | medium | CWE-78 | `cmdi/convert.py:13` | OS command injection | open |
| CAA-9a968212 | L1 | medium | CWE-78 | `cmdi/convert_fixed.py:13` | OS command injection | open |
| CAA-1abe4edd | L1 | medium | CWE-78 | `cmdi/ping.py:14` | OS command injection | open |
| CAA-aaf0c737 | L1 | medium | CWE-78 | `cmdi/trap_digit_guard.py:16` | OS command injection | open |
| CAA-8cc39187 | L1 | medium | CWE-798 | `config/settings.py:6` | Hard-coded credential | open |
| CAA-4db4bc61 | L1 | medium | CWE-327 | `config/settings.py:12` | Weak cryptographic hash | open |
| CAA-85a78868 | L1 | medium | CWE-489 | `config/settings.py:16` | Debug mode enabled | open |
| CAA-8438defd | L1 | medium | CWE-89 | `sqli/injected_comment.py:17` | SQL injection | open |
| CAA-eadf9f15 | L1 | medium | CWE-89 | `sqli/trap_column_map.py:19` | SQL injection | open |
| CAA-285152cd | L1 | medium | CWE-89 | `sqli/trap_constant_table.py:17` | SQL injection | open |
| CAA-8cf9acce | L1 | medium | CWE-89 | `sqli/trap_int_cast.py:17` | SQL injection | open |
| CAA-1f877485 | L1 | medium | CWE-89 | `sqli/trap_sort_allowlist.py:20` | SQL injection | open |
| CAA-875d5129 | L1 | medium | CWE-89 | `sqli/user_lookup.py:16` | SQL injection | open |
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
| CAA-b755d6b4 | L0 | medium | CWE-78 | `cmdi/trap_constant_shell.py:15` | OS command injection | open |
| CAA-c30ec4be | L0 | medium | CWE-78 | `cmdi/trap_digit_guard.py:4` | OS command injection | open |
| CAA-6dc56888 | L0 | medium | CWE-798 | `config/settings.py:8` | Hard-coded credential | open |
| CAA-f67a114b | L0 | medium | CWE-327 | `config/settings_fixed.py:17` | Weak cryptographic hash | open |
| CAA-3dcf722d | L0 | medium | CWE-22 | `path/avatar.py:12` | Path traversal | open |
| CAA-9380f86c | L0 | medium | CWE-22 | `path/denylist.py:15` | Path traversal | open |
| CAA-4e616929 | L0 | medium | CWE-22 | `path/download.py:13` | Path traversal | open |
| CAA-e0caae90 | L0 | medium | CWE-22 | `path/prefix_unnormalised.py:16` | Path traversal | open |
| CAA-d3738621 | L0 | medium | CWE-22 | `path/trap_allowlist.py:16` | Path traversal | open |
| CAA-fdd661f4 | L0 | medium | CWE-22 | `path/trap_basename.py:13` | Path traversal | open |
| CAA-7ad21d87 | L0 | medium | CWE-22 | `path/trap_secure_filename.py:13` | Path traversal | open |
| CAA-1c619ee1 | L0 | medium | CWE-89 | `sqli/orders_concat.py:15` | SQL injection | open |
| CAA-394c76d5 | L0 | medium | CWE-89 | `sqli/orders_concat.py:17` | SQL injection | open |
| CAA-820d646a | L0 | medium | CWE-89 | `sqli/repo_layer.py:6` | SQL injection | open |
| CAA-8b6f3dd1 | L0 | medium | CWE-89 | `sqli/repo_layer.py:7` | SQL injection | open |
| CAA-39dc7c93 | L0 | medium | CWE-89 | `sqli/report_percent.py:15` | SQL injection | open |
| CAA-0067bc10 | L0 | medium | CWE-89 | `sqli/report_percent.py:16` | SQL injection | open |
| CAA-ca849552 | L0 | medium | CWE-918 | `ssrf/fetch.py:13` | Server-side request forgery | open |
| CAA-7f1bf1df | L0 | medium | CWE-918 | `ssrf/fetch_fixed.py:16` | Server-side request forgery | open |
| CAA-8f85ee5e | L0 | medium | CWE-798 | `tests/test_fixtures.py:1` | Hard-coded credential | open |
| CAA-85569570 | L0 | medium | CWE-79 | `xss/comment.py:10` | Cross-site scripting | open |
| CAA-328f3ef0 | L0 | medium | CWE-79 | `xss/comment_fixed.py:10` | Cross-site scripting | open |
| CAA-8537ace4 | L0 | medium | CWE-79 | `xss/greet.py:10` | Cross-site scripting | open |
| CAA-323ae7ca | L0 | medium | CWE-79 | `xss/greet_fixed.py:10` | Cross-site scripting | open |
| CAA-d1f7588b | L0 | medium | CWE-79 | `xss/search_page.py:10` | Cross-site scripting | open |
| CAA-016e3741 | L0 | medium | CWE-79 | `xss/search_page_fixed.py:10` | Cross-site scripting | open |
| CAA-06467464 | L0 | medium | CWE-79 | `xss/trap_int_count.py:10` | Cross-site scripting | open |
| CAA-603ab841 | L0 | medium | CWE-79 | `xss/trap_server_value.py:11` | Cross-site scripting | open |

## CAA-b203c778 — OS command injection (CWE-78)

- **Location:** `cmdi/archive.py:14` in `backup()`
- **Mapping:** A03:2021 Injection; ASVS V5.3.8
- **Severity:** medium — 
- **Confidence:** L1 (open); reported by semgrep, bandit

**Why it is a risk.** Command executed through a shell with a non-constant command string.

**Evidence ladder:**

- L0 [semgrep,bandit] pattern match: caa.python.cmdi.shell — `cmdi/archive.py:14`
- L1 [agreement] independent sources agree on place and CWE: bandit, semgrep

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

**Not verified:**

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

**Not verified:**

- scope: first-party code only; framework and driver behaviour assumed as documented

## CAA-85a78868 — Debug mode enabled (CWE-489)

- **Location:** `config/settings.py:16`
- **Mapping:** A05:2021 Security Misconfiguration; ASVS V14.3.2
- **Severity:** medium — 
- **Confidence:** L1 (open); reported by semgrep, bandit

**Why it is a risk.** Flask debug mode enabled (interactive debugger exposes code execution).

**Evidence ladder:**

- L0 [semgrep,bandit] pattern match: caa.python.config.flask-debug — `config/settings.py:16`
- L1 [agreement] independent sources agree on place and CWE: bandit, semgrep

**Not verified:**

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

**Not verified:**

- no dynamic (L4) confirmation was performed
- scope: first-party code only; framework and driver behaviour assumed as documented

## CAA-eadf9f15 — SQL injection (CWE-89)

- **Location:** `sqli/trap_column_map.py:19` in `payments()`
- **Mapping:** A03:2021 Injection; ASVS V5.3.4
- **Severity:** medium — 
- **Confidence:** L1 (open); reported by semgrep, bandit

**Why it is a risk.** SQL query text built from a non-constant string is passed to execute().

**Evidence ladder:**

- L0 [semgrep,bandit] pattern match: caa.python.sqli.string-built-query — `sqli/trap_column_map.py:19`
- L1 [agreement] independent sources agree on place and CWE: bandit, semgrep

**Not verified:**

- no dynamic (L4) confirmation was performed
- scope: first-party code only; framework and driver behaviour assumed as documented

## CAA-285152cd — SQL injection (CWE-89)

- **Location:** `sqli/trap_constant_table.py:17` in `audit_count()`
- **Mapping:** A03:2021 Injection; ASVS V5.3.4
- **Severity:** medium — 
- **Confidence:** L1 (open); reported by semgrep, bandit

**Why it is a risk.** SQL query text built from a non-constant string is passed to execute().

**Evidence ladder:**

- L0 [semgrep,bandit] pattern match: caa.python.sqli.string-built-query — `sqli/trap_constant_table.py:17`
- L1 [agreement] independent sources agree on place and CWE: bandit, semgrep

**Not verified:**

- no dynamic (L4) confirmation was performed
- scope: first-party code only; framework and driver behaviour assumed as documented

## CAA-8cf9acce — SQL injection (CWE-89)

- **Location:** `sqli/trap_int_cast.py:17` in `invoice_page()`
- **Mapping:** A03:2021 Injection; ASVS V5.3.4
- **Severity:** medium — 
- **Confidence:** L1 (open); reported by semgrep, bandit

**Why it is a risk.** SQL query text built from a non-constant string is passed to execute().

**Evidence ladder:**

- L0 [semgrep,bandit] pattern match: caa.python.sqli.string-built-query — `sqli/trap_int_cast.py:17`
- L1 [agreement] independent sources agree on place and CWE: bandit, semgrep

**Not verified:**

- no dynamic (L4) confirmation was performed
- scope: first-party code only; framework and driver behaviour assumed as documented

## CAA-1f877485 — SQL injection (CWE-89)

- **Location:** `sqli/trap_sort_allowlist.py:20` in `customers()`
- **Mapping:** A03:2021 Injection; ASVS V5.3.4
- **Severity:** medium — 
- **Confidence:** L1 (open); reported by semgrep, bandit

**Why it is a risk.** SQL query text built from a non-constant string is passed to execute().

**Evidence ladder:**

- L0 [semgrep,bandit] pattern match: caa.python.sqli.string-built-query — `sqli/trap_sort_allowlist.py:20`
- L1 [agreement] independent sources agree on place and CWE: bandit, semgrep

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

**Not verified:**

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

**Not verified:**

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

**Not verified:**

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

**Not verified:**

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

**Not verified:**

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

**Not verified:**

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

**Not verified:**

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

**Not verified:**

- no dynamic (L4) confirmation was performed
- scope: first-party code only; framework and driver behaviour assumed as documented

## CAA-b755d6b4 — OS command injection (CWE-78)

- **Location:** `cmdi/trap_constant_shell.py:15` in `disk()`
- **Mapping:** A03:2021 Injection; ASVS V5.3.8
- **Severity:** medium — 
- **Confidence:** L0 (open); reported by bandit

**Why it is a risk.** subprocess call with shell=True identified, security issue.

**Evidence ladder:**

- L0 [bandit] pattern match: bandit.B602.subprocess_popen_with_shell_equals_true — `cmdi/trap_constant_shell.py:15`

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

**Not verified:**

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

**Not verified:**

- scope: first-party code only; framework and driver behaviour assumed as documented

## CAA-3dcf722d — Path traversal (CWE-22)

- **Location:** `path/avatar.py:12` in `avatar()`
- **Mapping:** A01:2021 Broken Access Control; ASVS V12.3.1
- **Severity:** medium — 
- **Confidence:** L0 (open); reported by semgrep

**Why it is a risk.** File path built from a non-constant value is opened or served.

**Evidence ladder:**

- L0 [semgrep] pattern match: caa.python.path.user-path-open — `path/avatar.py:12`

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

**Not verified:**

- no dynamic (L4) confirmation was performed
- scope: first-party code only; framework and driver behaviour assumed as documented

## CAA-d3738621 — Path traversal (CWE-22)

- **Location:** `path/trap_allowlist.py:16` in `template()`
- **Mapping:** A01:2021 Broken Access Control; ASVS V12.3.1
- **Severity:** medium — 
- **Confidence:** L0 (open); reported by semgrep

**Why it is a risk.** File path built from a non-constant value is opened or served.

**Evidence ladder:**

- L0 [semgrep] pattern match: caa.python.path.user-path-open — `path/trap_allowlist.py:16`

**Not verified:**

- no dynamic (L4) confirmation was performed
- scope: first-party code only; framework and driver behaviour assumed as documented

## CAA-fdd661f4 — Path traversal (CWE-22)

- **Location:** `path/trap_basename.py:13` in `thumbs()`
- **Mapping:** A01:2021 Broken Access Control; ASVS V12.3.1
- **Severity:** medium — 
- **Confidence:** L0 (open); reported by semgrep

**Why it is a risk.** File path built from a non-constant value is opened or served.

**Evidence ladder:**

- L0 [semgrep] pattern match: caa.python.path.user-path-open — `path/trap_basename.py:13`

**Not verified:**

- no dynamic (L4) confirmation was performed
- scope: first-party code only; framework and driver behaviour assumed as documented

## CAA-7ad21d87 — Path traversal (CWE-22)

- **Location:** `path/trap_secure_filename.py:13` in `report_file()`
- **Mapping:** A01:2021 Broken Access Control; ASVS V12.3.1
- **Severity:** medium — 
- **Confidence:** L0 (open); reported by semgrep

**Why it is a risk.** File path built from a non-constant value is opened or served.

**Evidence ladder:**

- L0 [semgrep] pattern match: caa.python.path.user-path-open — `path/trap_secure_filename.py:13`

**Not verified:**

- no dynamic (L4) confirmation was performed
- scope: first-party code only; framework and driver behaviour assumed as documented

## CAA-1c619ee1 — SQL injection (CWE-89)

- **Location:** `sqli/orders_concat.py:15` in `list_orders()`
- **Mapping:** A03:2021 Injection; ASVS V5.3.4
- **Severity:** medium — 
- **Confidence:** L0 (open); reported by bandit

**Why it is a risk.** Possible SQL injection vector through string-based query construction.

**Evidence ladder:**

- L0 [bandit] pattern match: bandit.B608.hardcoded_sql_expressions — `sqli/orders_concat.py:15`

**Not verified:**

- no dynamic (L4) confirmation was performed
- scope: first-party code only; framework and driver behaviour assumed as documented

## CAA-394c76d5 — SQL injection (CWE-89)

- **Location:** `sqli/orders_concat.py:17` in `list_orders()`
- **Mapping:** A03:2021 Injection; ASVS V5.3.4
- **Severity:** medium — 
- **Confidence:** L0 (open); reported by semgrep

**Why it is a risk.** SQL query text built from a non-constant string is passed to execute().

**Evidence ladder:**

- L0 [semgrep] pattern match: caa.python.sqli.string-built-query — `sqli/orders_concat.py:17`

**Not verified:**

- no dynamic (L4) confirmation was performed
- scope: first-party code only; framework and driver behaviour assumed as documented

## CAA-820d646a — SQL injection (CWE-89)

- **Location:** `sqli/repo_layer.py:6` in `find_product()`
- **Mapping:** A03:2021 Injection; ASVS V5.3.4
- **Severity:** medium — 
- **Confidence:** L0 (open); reported by bandit

**Why it is a risk.** Possible SQL injection vector through string-based query construction.

**Evidence ladder:**

- L0 [bandit] pattern match: bandit.B608.hardcoded_sql_expressions — `sqli/repo_layer.py:6`

**Not verified:**

- no dynamic (L4) confirmation was performed
- scope: first-party code only; framework and driver behaviour assumed as documented

## CAA-8b6f3dd1 — SQL injection (CWE-89)

- **Location:** `sqli/repo_layer.py:7` in `find_product()`
- **Mapping:** A03:2021 Injection; ASVS V5.3.4
- **Severity:** medium — 
- **Confidence:** L0 (open); reported by semgrep

**Why it is a risk.** SQL query text built from a non-constant string is passed to execute().

**Evidence ladder:**

- L0 [semgrep] pattern match: caa.python.sqli.string-built-query — `sqli/repo_layer.py:7`

**Not verified:**

- no dynamic (L4) confirmation was performed
- scope: first-party code only; framework and driver behaviour assumed as documented

## CAA-39dc7c93 — SQL injection (CWE-89)

- **Location:** `sqli/report_percent.py:15` in `report()`
- **Mapping:** A03:2021 Injection; ASVS V5.3.4
- **Severity:** medium — 
- **Confidence:** L0 (open); reported by bandit

**Why it is a risk.** Possible SQL injection vector through string-based query construction.

**Evidence ladder:**

- L0 [bandit] pattern match: bandit.B608.hardcoded_sql_expressions — `sqli/report_percent.py:15`

**Not verified:**

- no dynamic (L4) confirmation was performed
- scope: first-party code only; framework and driver behaviour assumed as documented

## CAA-0067bc10 — SQL injection (CWE-89)

- **Location:** `sqli/report_percent.py:16` in `report()`
- **Mapping:** A03:2021 Injection; ASVS V5.3.4
- **Severity:** medium — 
- **Confidence:** L0 (open); reported by semgrep

**Why it is a risk.** SQL query text built from a non-constant string is passed to execute().

**Evidence ladder:**

- L0 [semgrep] pattern match: caa.python.sqli.string-built-query — `sqli/report_percent.py:16`

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

**Not verified:**

- no dynamic (L4) confirmation was performed
- scope: first-party code only; framework and driver behaviour assumed as documented

## CAA-7f1bf1df — Server-side request forgery (CWE-918)

- **Location:** `ssrf/fetch_fixed.py:16` in `preview()`
- **Mapping:** A10:2021 Server-Side Request Forgery; ASVS V12.6.1
- **Severity:** medium — 
- **Confidence:** L0 (open); reported by semgrep

**Why it is a risk.** Outbound request to a non-constant URL inside a request handler.

**Evidence ladder:**

- L0 [semgrep] pattern match: caa.python.ssrf.user-url-fetch — `ssrf/fetch_fixed.py:16`

**Not verified:**

- no dynamic (L4) confirmation was performed
- scope: first-party code only; framework and driver behaviour assumed as documented

## CAA-8f85ee5e — Hard-coded credential (CWE-798)

- **Location:** `tests/test_fixtures.py:1`
- **Mapping:** A07:2021 Identification and Authentication Failures; ASVS V2.10.4
- **Severity:** medium — 
- **Confidence:** L0 (open); reported by bandit

**Why it is a risk.** Possible hardcoded password: 'exam****[20]'

**Evidence ladder:**

- L0 [bandit] pattern match: bandit.B105.hardcoded_password_string — `tests/test_fixtures.py:1`

**Not verified:**

- scope: first-party code only; framework and driver behaviour assumed as documented

## CAA-85569570 — Cross-site scripting (CWE-79)

- **Location:** `xss/comment.py:10` in `preview()`
- **Mapping:** A03:2021 Injection; ASVS V5.3.3
- **Severity:** medium — 
- **Confidence:** L0 (open); reported by semgrep

**Why it is a risk.** HTML built by string formatting is returned from a request handler without escaping.

**Evidence ladder:**

- L0 [semgrep] pattern match: caa.python.xss.raw-html-response — `xss/comment.py:10`

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

**Not verified:**

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

**Not verified:**

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

**Not verified:**

- no dynamic (L4) confirmation was performed
- scope: first-party code only; framework and driver behaviour assumed as documented

## CAA-016e3741 — Cross-site scripting (CWE-79)

- **Location:** `xss/search_page_fixed.py:10` in `search()`
- **Mapping:** A03:2021 Injection; ASVS V5.3.3
- **Severity:** medium — 
- **Confidence:** L0 (open); reported by semgrep

**Why it is a risk.** HTML built by string formatting is returned from a request handler without escaping.

**Evidence ladder:**

- L0 [semgrep] pattern match: caa.python.xss.raw-html-response — `xss/search_page_fixed.py:10`

**Not verified:**

- no dynamic (L4) confirmation was performed
- scope: first-party code only; framework and driver behaviour assumed as documented

## CAA-06467464 — Cross-site scripting (CWE-79)

- **Location:** `xss/trap_int_count.py:10` in `badge()`
- **Mapping:** A03:2021 Injection; ASVS V5.3.3
- **Severity:** medium — 
- **Confidence:** L0 (open); reported by semgrep

**Why it is a risk.** HTML built by string formatting is returned from a request handler without escaping.

**Evidence ladder:**

- L0 [semgrep] pattern match: caa.python.xss.raw-html-response — `xss/trap_int_count.py:10`

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

**Not verified:**

- no dynamic (L4) confirmation was performed
- scope: first-party code only; framework and driver behaviour assumed as documented

## Run

```json
{
 "stage_seconds": {
  "inventory": 0.01,
  "candidates": 2.09,
  "context": 0.04,
  "verify": 0.0
 },
 "candidates": 70,
 "findings_initial": 53
}
```
