"""Engine HTTP (black box): passive, read-only security checks of a live website from its URL.

See scanner.WebScan. The `caa live` command drives it. It never attacks the target: GET/HEAD only,
same-origin, a fixed request budget, no payloads. The operator must confirm they are authorised to
test the target.
"""
