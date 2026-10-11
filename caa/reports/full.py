"""Full report after a scan: one data model -> Markdown and a self-contained HTML page.

Sections: run summary (target, commit, mode, duration), risk overview (severity x status,
groups, languages), project profile, analyzers that ran / were skipped, runtime checks,
every open finding in full (location, data flow, evidence ladder, model verdict, what was NOT
verified, fix diff), refuted candidates with their protection line, limitations and method.
Headings are localised (ru/en); evidence texts produced by the analyzers stay as generated.
Secrets are masked in every output.
"""
from __future__ import annotations

import html
import json
from collections import Counter
from dataclasses import dataclass, field

from caa.core.audit import mask_secrets
from caa.core.models import Finding, Group, Level, Status

SEV_ORDER = ["critical", "high", "medium", "low"]

T = {
    "ru": {
        "title": "Отчёт о проверке безопасности",
        "summary": "Сводка", "target": "Цель", "commit": "Коммит", "branch": "Ветка", "started": "Начало",
        "duration": "Длительность", "mode": "Режим", "trust_tp": "чужой код (только статический анализ, модель — локальная)",
        "trust_own": "собственный/доверенный код", "llm": "Модель", "llm_off": "не использовалась",
        "sandbox": "Песочница", "sandbox_off": "выключена", "network": "сеть", "verdict": "Итог",
        "open": "открытых находок", "need_human": "требуют проверки человеком", "refuted": "кандидатов снято со ссылкой на защиту",
        "overview": "Обзор рисков", "by_sev": "По серьёзности", "severity": "Серьёзность", "count": "Кол-во",
        "by_group": "По группам", "group": "Группа", "by_level": "По уровню доказательства", "level": "Уровень",
        "by_lang": "По языкам", "language": "Язык", "top": "Главное — что исправить первым",
        "profile": "Профиль проекта", "languages": "Языки", "frameworks": "Фреймворки", "kinds": "Тип программы",
        "files": "файлов", "loc": "строк", "manifests": "Манифесты зависимостей", "entrypoints": "Точки входа (маршруты)",
        "analyzers": "Какие проверки выполнены", "analyzer": "Проверка", "status": "Статус", "note": "Примечание",
        "candidates": "Кандидатов", "runtime": "Запуск приложения в песочнице", "app": "Приложение", "started_q": "Запустилось",
        "boot": "Старт, с", "probes": "Проверок", "reason": "Причина", "runtime_off": "не выполнялся",
        "findings": "Находки", "location": "Где", "mapping": "Классификация", "confidence": "Уверенность",
        "reported_by": "Нашли", "why": "Почему это риск", "dataflow": "Путь данных (проверенные ссылки)",
        "ladder": "Лестница доказательств", "model": "Вердикт модели", "not_verified": "Что НЕ проверено",
        "fix": "Исправление", "rescan": "повторный скан чистый", "prop_after": "проверка после патча",
        "not_run": "не запускалась", "refuted_h": "Снятые кандидаты", "candidate": "Кандидат", "protection": "Защита (проверенная строка)",
        "by": "Кем", "limits": "Ограничения этого прогона", "method": "Как читать отчёт",
        "method_text": ("Уверенность = высший достигнутый уровень доказательства. L0 — сработал шаблон; L1 — согласны "
                        "независимые источники; L2 — прослежен путь данных «источник → сток» с проверенными ссылками на "
                        "строки; L3 — попытка опровергнуть не удалась; L4 — безвредная динамическая проверка подтвердила; "
                        "L5 — исправление проверено (правило не срабатывает, проверка проходит). Кандидат снимается "
                        "только со ссылкой на исполняемую строку защиты."),
        "none": "нет", "yes": "да", "no": "нет", "groups": {"A": "Поток данных (инъекции)", "B": "Контроль доступа",
                                                            "C": "Бизнес-логика", "D": "Секреты и настройки",
                                                            "E": "Зависимости", "X": "Безопасность агента"},
        "status_names": {"open": "открыта", "needs_human": "нужен человек", "refuted": "снята"},
        "an_status": {"ran": "выполнена", "skipped": "пропущена", "failed": "ошибка"},
        "no_findings": "Открытых находок нет.",
    },
    "en": {
        "title": "Security review report",
        "summary": "Summary", "target": "Target", "commit": "Commit", "branch": "Branch", "started": "Started",
        "duration": "Duration", "mode": "Mode", "trust_tp": "third-party code (static analysis only, local model)",
        "trust_own": "own / trusted code", "llm": "Model", "llm_off": "not used",
        "sandbox": "Sandbox", "sandbox_off": "off", "network": "network", "verdict": "Result",
        "open": "open findings", "need_human": "need human review", "refuted": "candidates refuted with a cited protection",
        "overview": "Risk overview", "by_sev": "By severity", "severity": "Severity", "count": "Count",
        "by_group": "By group", "group": "Group", "by_level": "By evidence level", "level": "Level",
        "by_lang": "By language", "language": "Language", "top": "Fix first",
        "profile": "Project profile", "languages": "Languages", "frameworks": "Frameworks", "kinds": "Kind of program",
        "files": "files", "loc": "lines", "manifests": "Dependency manifests", "entrypoints": "Entry points (routes)",
        "analyzers": "Checks that ran", "analyzer": "Check", "status": "Status", "note": "Note",
        "candidates": "Candidates", "runtime": "Application run in the sandbox", "app": "App", "started_q": "Started",
        "boot": "Boot, s", "probes": "Probes", "reason": "Reason", "runtime_off": "not performed",
        "findings": "Findings", "location": "Location", "mapping": "Mapping", "confidence": "Confidence",
        "reported_by": "Reported by", "why": "Why it is a risk", "dataflow": "Data flow (verified references)",
        "ladder": "Evidence ladder", "model": "Model verdict", "not_verified": "NOT verified",
        "fix": "Fix", "rescan": "rescan clean", "prop_after": "property after patch",
        "not_run": "not run", "refuted_h": "Refuted candidates", "candidate": "Candidate",
        "protection": "Protection (verified line)", "by": "By", "limits": "Limits of this run", "method": "How to read",
        "method_text": ("Confidence = highest evidence level reached. L0 pattern; L1 independent sources agree; L2 "
                        "source-to-sink path with verified line references; L3 refutation attempt failed; L4 harmless "
                        "dynamic check confirmed; L5 fix verified. A candidate is dropped only with a cited executable "
                        "protection line."),
        "none": "none", "yes": "yes", "no": "no", "groups": {"A": "Data flow (injection)", "B": "Access control",
                                                             "C": "Business logic", "D": "Secrets & configuration",
                                                             "E": "Dependencies", "X": "Agent safety"},
        "status_names": {"open": "open", "needs_human": "needs human", "refuted": "refuted"},
        "an_status": {"ran": "ran", "skipped": "skipped", "failed": "failed"},
        "no_findings": "No open findings.",
    },
}
EXT_LANG = {".py": "Python", ".js": "JavaScript", ".mjs": "JavaScript", ".cjs": "JavaScript", ".jsx": "JavaScript",
            ".ts": "TypeScript", ".tsx": "TypeScript", ".java": "Java", ".go": "Go", ".html": "HTML", ".htm": "HTML"}


@dataclass
class Report:
    findings: list[Finding]
    inventory: dict
    stats: dict
    run: dict = field(default_factory=dict)      # source meta, options, timing
    lang: str = "ru"

    @property
    def t(self) -> dict:
        return T.get(self.lang, T["en"])

    @property
    def open(self) -> list[Finding]:
        out = [f for f in self.findings if f.status != Status.REFUTED]
        return sorted(out, key=lambda f: (SEV_ORDER.index(f.severity) if f.severity in SEV_ORDER else 9,
                                          -int(f.level), f.location.file, f.location.start_line))

    @property
    def refuted(self) -> list[Finding]:
        return [f for f in self.findings if f.status == Status.REFUTED]


def _lang_of(path: str) -> str:
    import os
    name = os.path.basename(path)
    if name in ("requirements.txt", "pyproject.toml", "setup.py"):
        return "Python"
    if name in ("package.json", "package-lock.json"):
        return "JavaScript"
    if name in ("go.mod", "go.sum"):
        return "Go"
    if name in ("pom.xml", "build.gradle"):
        return "Java"
    return EXT_LANG.get(os.path.splitext(name)[1], "config / other")


def _summary_rows(r: Report) -> dict:
    o = r.open
    return {
        "sev": Counter(f.severity for f in o),
        "group": Counter(f.group.value for f in o),
        "level": Counter(f"L{int(f.level)}" for f in o),
        "lang": Counter(_lang_of(f.location.file) for f in o),
        "status": Counter(f.status.value for f in o),
    }


# --------------------------------------------------------------------------------------- Markdown

def to_markdown(r: Report) -> str:
    t, run, inv = r.t, r.run, r.inventory
    s = _summary_rows(r)
    lines = [f"# {t['title']}", ""]
    lines += [f"## {t['summary']}", ""]
    lines += [f"| | |", "|---|---|"]
    for k, v in _run_rows(r):
        lines.append(f"| {k} | {v} |")
    lines += ["", f"**{t['verdict']}:** {len(r.open)} {t['open']} "
              f"({s['status'].get('needs_human', 0)} {t['need_human']}), {len(r.refuted)} {t['refuted']}.", ""]
    lines += [f"## {t['overview']}", ""]
    lines += _md_table([t["severity"], t["count"]], [(k, s["sev"].get(k, 0)) for k in SEV_ORDER])
    lines += _md_table([t["group"], t["count"]], [(f"{g} — {t['groups'][g]}", n) for g, n in sorted(s["group"].items())])
    lines += _md_table([t["level"], t["count"]], sorted(s["level"].items(), reverse=True))
    lines += _md_table([t["language"], t["count"]], s["lang"].most_common())
    top = [f for f in r.open if f.severity in ("critical", "high") and f.level >= Level.L2][:10]
    if top:
        lines += [f"### {t['top']}", ""]
        for f in top:
            lines.append(f"- **{f.title}** ({f.cwe}, {f.confidence_label}) — `{f.location.file}:{f.location.start_line}` [{f.id}](#{f.id.lower()})")
        lines.append("")
    lines += _md_profile(r)
    lines += _md_analyzers(r)
    lines += _md_runtime(r)
    lines += [f"## {t['findings']}", ""]
    if not r.open:
        lines += [t["no_findings"], ""]
    lines += _md_table(["ID", t["level"], t["severity"], "CWE", t["location"], t["status"]],
                       [(f"[{f.id}](#{f.id.lower()})", f.confidence_label, f.severity, f.cwe,
                         f"`{f.location.file}:{f.location.start_line}`", t["status_names"][f.status.value])
                        for f in r.open])
    for f in r.open:
        lines += _md_finding(f, t)
    if r.refuted:
        lines += [f"## {t['refuted_h']}", ""]
        lines += _md_table([t["candidate"], "CWE", t["protection"], t["by"]],
                           [(f"`{f.location.file}:{f.location.start_line}`", f.cwe,
                             f"`{f.refutation.file}:{f.refutation.line}` {f.refutation.note}" if f.refutation else "-",
                             f.extra.get("refuted_by", "")) for f in r.refuted])
    lines += [f"## {t['limits']}", ""] + [f"- {x}" for x in _limits(r)] + [""]
    lines += [f"## {t['method']}", "", t["method_text"], ""]
    return mask_secrets("\n".join(lines))


def _md_table(header: list[str], rows) -> list[str]:
    rows = list(rows)
    if not rows:
        return []
    out = ["| " + " | ".join(header) + " |", "|" + "---|" * len(header)]
    out += ["| " + " | ".join(str(c) for c in row) + " |" for row in rows]
    return out + [""]


def _run_rows(r: Report) -> list[tuple[str, str]]:
    t, run = r.t, r.run
    src = run.get("source") or {}
    target = src.get("url") or src.get("path") or r.inventory.get("root", "?")
    rows = [(t["target"], f"`{target}`")]
    if src.get("ref"):
        rows.append((t["branch"], f"`{src['ref']}`"))
    if src.get("commit"):
        rows.append((t["commit"], f"`{src['commit']}`"))
    if run.get("started"):
        rows.append((t["started"], run["started"]))
    if run.get("seconds") is not None:
        rows.append((t["duration"], f"{run['seconds']} s"))
    opts = run.get("options") or {}
    rows.append((t["mode"], t["trust_own"] if opts.get("trust") == "own" else t["trust_tp"]))
    rows.append((t["llm"], opts.get("llm") or t["llm_off"]))
    sb = opts.get("sandbox")
    rows.append((t["sandbox"], f"{sb}, {t['network']}: {opts.get('network', 'none')}" if sb else t["sandbox_off"]))
    return rows


def _md_profile(r: Report) -> list[str]:
    t, prof = r.t, r.inventory.get("profile") or {}
    if not prof:
        return []
    out = [f"## {t['profile']}", ""]
    rows = [(lang, li.get("files", 0), li.get("loc", 0), ", ".join(li.get("frameworks") or []) or "-")
            for lang, li in (prof.get("languages") or {}).items()]
    out += _md_table([t["language"], t["files"], t["loc"], t["frameworks"]], rows)
    out += [f"- {t['kinds']}: {', '.join(prof.get('kinds') or []) or '-'}",
            f"- {t['manifests']}: {', '.join(f'`{m}`' for m in prof.get('manifests') or []) or t['none']}",
            f"- {t['entrypoints']}: {len((r.inventory.get('entrypoints') or {}).get('routes') or [])}", ""]
    return out


def _md_analyzers(r: Report) -> list[str]:
    t, an = r.t, r.inventory.get("analyzers") or []
    if not an:
        return []
    return [f"## {t['analyzers']}", ""] + _md_table(
        [t["analyzer"], t["status"], t["candidates"], t["note"]],
        [(a["analyzer"], t["an_status"].get(a["status"], a["status"]), a.get("candidates", 0), a.get("note") or "")
         for a in an])


def _md_runtime(r: Report) -> list[str]:
    t, rt = r.t, r.inventory.get("runtime")
    if not rt:
        return []
    if isinstance(rt, dict):
        return [f"## {t['runtime']}", "", f"{t['runtime_off']}: {rt.get('reason', '')}", ""]
    return [f"## {t['runtime']}", ""] + _md_table(
        [t["app"], t["started_q"], t["boot"], t["probes"], t["network"], t["reason"]],
        [(f"`{a['app']}`", t["yes"] if a.get("started") else t["no"], a.get("boot_seconds") or "-",
          a.get("probes", 0), a.get("network", "none"),
          (a.get("reason") or "").replace("\n", " ")[-160:] if not a.get("started") else "")
         for a in rt])


def _md_finding(f: Finding, t: dict) -> list[str]:
    out = [f'<a id="{f.id.lower()}"></a>', f"### {f.id} — {f.title} ({f.cwe})", "",
           f"- **{t['location']}:** `{f.location.file}:{f.location.start_line}`"
           + (f" — `{f.location.function}()`" if f.location.function else ""),
           f"- **{t['severity']}:** {f.severity} — {f.severity_rationale}",
           f"- **{t['confidence']}:** {f.confidence_label} ({t['status_names'][f.status.value]})",
           f"- **{t['mapping']}:** {f.owasp or '-'}; ASVS {f.asvs or '-'}; {t['groups'].get(f.group.value, f.group.value)}",
           f"- **{t['reported_by']}:** {', '.join(f.sources)}", ""]
    if f.explanation:
        out += [f"**{t['why']}.** {f.explanation}", ""]
    if f.dataflow:
        out += [f"**{t['dataflow']}:**", ""]
        for i, s in enumerate(f.dataflow, 1):
            out.append(f"{i}. `{s.kind}` `{s.ref.file}:{s.ref.line}` — `{s.code[:140]}`")
        out.append("")
    out += [f"**{t['ladder']}:**", ""]
    for e in sorted(f.evidence, key=lambda e: e.level):
        refs = ", ".join(f"`{x.file}:{x.line}`" for x in e.refs if x.file)
        out.append(f"- L{int(e.level)} [{e.by}] {e.detail}" + (f" — {refs}" if refs else ""))
    out.append("")
    if f.llm_verdict:
        out += [f"**{t['model']}:** {f.llm_verdict.get('verdict')} — {(f.llm_verdict.get('explanation') or '')[:500]}", ""]
    out += [f"**{t['not_verified']}:**", ""] + [f"- {n}" for n in (f.not_verified or ["-"])] + [""]
    if f.fix:
        state = (f"{t['rescan']}: {f.fix.rescan_clean}; {t['prop_after']}: "
                 f"{f.fix.property_after if f.fix.property_after is not None else t['not_run']}")
        out += [f"**{t['fix']}** ({f.fix.by}; {state}). {f.fix.explanation}", "", "```diff", f.fix.diff.rstrip(), "```", ""]
    return out


def _limits(r: Report) -> list[str]:
    out = []
    for a in r.inventory.get("analyzers") or []:
        if a["status"] != "ran":
            out.append(f"{a['analyzer']}: {a['status']} — {a.get('note', '')}")
    opts = r.run.get("options") or {}
    if not opts.get("sandbox"):
        out.append("L4/L5 dynamic checks were not run (sandbox off: enable only for trusted code with --trust-target)")
    if not opts.get("llm"):
        out.append("no model triage: business-logic (group C) hypotheses are not generated")
    dropped = r.inventory.get("dropped_unknown_cwe") or {}
    if dropped:
        out.append(f"analyzer results without a knowledge card were dropped: {dropped}")
    out.append("JS/TS, Java and Go: intra-file taint only, no dynamic checks or automatic fixes")
    return out


# --------------------------------------------------------------------------------------- HTML

CSS = """
:root{--bg:#fff;--fg:#1d2330;--muted:#5b6475;--line:#e3e6ec;--card:#f7f8fa;--crit:#8b1e3f;--high:#c0392b;
--med:#d68910;--low:#2e86c1;--ok:#1e8449;--code:#f2f4f7}
@media (prefers-color-scheme:dark){:root{--bg:#14171c;--fg:#e6e9ef;--muted:#9aa3b2;--line:#2a2f38;--card:#1b1f26;
--code:#20252d}}
*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--fg);font:15px/1.55 system-ui,-apple-system,
"Segoe UI",Roboto,sans-serif}main{max-width:1080px;margin:0 auto;padding:24px 16px 64px}
h1{font-size:26px;margin:0 0 4px}h2{font-size:20px;margin:36px 0 12px;padding-bottom:6px;border-bottom:1px solid var(--line)}
h3{font-size:16px;margin:0}table{border-collapse:collapse;width:100%;margin:8px 0 16px;font-size:14px}
th,td{text-align:left;padding:6px 8px;border-bottom:1px solid var(--line);vertical-align:top}th{color:var(--muted);font-weight:600}
code,pre{font-family:ui-monospace,SFMono-Regular,Consolas,monospace;font-size:13px}code{background:var(--code);padding:1px 4px;border-radius:4px}
pre{background:var(--code);padding:12px;border-radius:8px;overflow-x:auto}.muted{color:var(--muted)}
.tiles{display:grid;grid-template-columns:repeat(auto-fit,minmax(150px,1fr));gap:10px;margin:12px 0}
.tile{background:var(--card);border:1px solid var(--line);border-radius:10px;padding:12px}.tile b{display:block;font-size:24px}
.sev{display:inline-block;padding:1px 8px;border-radius:999px;color:#fff;font-size:12px;font-weight:600}
.critical{background:var(--crit)}.high{background:var(--high)}.medium{background:var(--med)}.low{background:var(--low)}
.lvl{display:inline-block;padding:1px 6px;border:1px solid var(--line);border-radius:6px;font-size:12px}
details{background:var(--card);border:1px solid var(--line);border-radius:10px;margin:10px 0;padding:10px 14px}
summary{cursor:pointer;display:flex;gap:10px;align-items:center;flex-wrap:wrap}details[open] summary{margin-bottom:8px}
.del{color:var(--high)}.add{color:var(--ok)}.wrap{overflow-x:auto}
"""


def _e(x) -> str:
    """Mask secrets FIRST, then HTML-escape (escaping first would hide quotes from the secret patterns)."""
    return html.escape(mask_secrets(str(x)))


def to_html(r: Report) -> str:
    t, s = r.t, _summary_rows(r)
    e = _e
    parts = [f"<!doctype html><html lang='{r.lang}'><head><meta charset='utf-8'>"
             f"<meta name='viewport' content='width=device-width,initial-scale=1'><title>{e(t['title'])}</title>"
             f"<style>{CSS}</style></head><body><main>"]
    parts.append(f"<h1>{e(t['title'])}</h1><h2>{e(t['summary'])}</h2>")
    parts.append("<table>" + "".join(f"<tr><th>{e(k)}</th><td>{_inline(v)}</td></tr>" for k, v in _run_rows(r)) + "</table>")
    tiles = [(len(r.open), t["open"]), (s["status"].get("needs_human", 0), t["need_human"]),
             (len(r.refuted), t["refuted"])] + [(s["sev"].get(k, 0), k) for k in SEV_ORDER]
    parts.append("<div class='tiles'>" + "".join(f"<div class='tile'><b>{n}</b><span class='muted'>{e(str(lbl))}</span></div>"
                                                for n, lbl in tiles) + "</div>")
    parts.append(f"<h2>{e(t['overview'])}</h2><div class='tiles'>")
    for title, counter, names in ((t["by_group"], s["group"], t["groups"]), (t["by_level"], s["level"], None),
                                  (t["by_lang"], s["lang"], None)):
        rows = "".join(f"<tr><td>{e(names.get(k, k) if names else k)}</td><td>{v}</td></tr>"
                       for k, v in sorted(counter.items(), key=lambda kv: -kv[1]))
        parts.append(f"<div class='tile'><span class='muted'>{e(title)}</span><table>{rows}</table></div>")
    parts.append("</div>")
    top = [f for f in r.open if f.severity in ("critical", "high") and f.level >= Level.L2][:10]
    if top:
        parts.append(f"<h3>{e(t['top'])}</h3><ul>" + "".join(
            f"<li><a href='#{f.id.lower()}'>{e(f.title)}</a> <span class='muted'>{f.cwe}, {f.confidence_label} — "
            f"<code>{e(f.location.file)}:{f.location.start_line}</code></span></li>" for f in top) + "</ul>")
    for block in (_md_profile(r), _md_analyzers(r), _md_runtime(r)):
        parts.append(_md_block_to_html(block))
    parts.append(f"<h2>{e(t['findings'])} ({len(r.open)})</h2>")
    if not r.open:
        parts.append(f"<p>{e(t['no_findings'])}</p>")
    for f in r.open:
        parts.append(_html_finding(f, t))
    if r.refuted:
        parts.append(f"<h2>{e(t['refuted_h'])} ({len(r.refuted)})</h2><div class='wrap'><table><tr><th>{e(t['candidate'])}</th>"
                     f"<th>CWE</th><th>{e(t['protection'])}</th><th>{e(t['by'])}</th></tr>" + "".join(
                         f"<tr><td><code>{e(f.location.file)}:{f.location.start_line}</code></td><td>{f.cwe}</td><td>"
                         + (f"<code>{e(f.refutation.file)}:{f.refutation.line}</code> {e(f.refutation.note)}" if f.refutation else "-")
                         + f"</td><td>{e(f.extra.get('refuted_by', ''))}</td></tr>" for f in r.refuted) + "</table></div>")
    parts.append(f"<h2>{e(t['limits'])}</h2><ul>" + "".join(f"<li>{e(x)}</li>" for x in _limits(r)) + "</ul>")
    parts.append(f"<h2>{e(t['method'])}</h2><p>{e(t['method_text'])}</p>")
    parts.append("</main></body></html>")
    return "".join(parts)


def _inline(v: str) -> str:
    """`code` spans -> <code>, everything else escaped."""
    out, chunks = [], str(v).split("`")
    for i, c in enumerate(chunks):
        out.append(f"<code>{_e(c)}</code>" if i % 2 else _e(c))
    return "".join(out)


def _md_block_to_html(lines: list[str]) -> str:
    if not lines:
        return ""
    out, table = [], []

    def flush():
        if table:
            rows = [r for r in table if not set(r.replace("|", "").strip()) <= {"-"}]
            cells = [[c.strip() for c in r.strip("|").split("|")] for r in rows]
            out.append("<div class='wrap'><table>" + "".join(
                "<tr>" + "".join((f"<th>{_inline(c)}</th>" if i == 0 else f"<td>{_inline(c)}</td>") for c in row) + "</tr>"
                for i, row in enumerate(cells)) + "</table></div>")
            table.clear()
    for ln in lines:
        if ln.startswith("|"):
            table.append(ln)
            continue
        flush()
        if ln.startswith("## "):
            out.append(f"<h2>{_e(ln[3:])}</h2>")
        elif ln.startswith("- "):
            out.append(f"<p>{_inline(ln[2:])}</p>")
        elif ln.strip():
            out.append(f"<p>{_inline(ln)}</p>")
    flush()
    return "".join(out)


def _html_finding(f: Finding, t: dict) -> str:
    e = _e
    head = (f"<summary><span class='sev {e(f.severity)}'>{e(f.severity)}</span><span class='lvl'>{f.confidence_label}</span>"
            f"<h3>{e(f.title)} <span class='muted'>({f.cwe})</span></h3>"
            f"<code>{e(f.location.file)}:{f.location.start_line}</code><span class='muted'>{e(f.id)} · "
            f"{e(t['status_names'][f.status.value])}</span></summary>")
    body = [f"<p><b>{e(t['severity'])}:</b> {e(f.severity_rationale)}</p>",
            f"<p><b>{e(t['mapping'])}:</b> {e(f.owasp or '-')}; ASVS {e(f.asvs or '-')}; "
            f"{e(t['groups'].get(f.group.value, f.group.value))}. <b>{e(t['reported_by'])}:</b> {e(', '.join(f.sources))}</p>"]
    if f.explanation:
        body.append(f"<p><b>{e(t['why'])}.</b> {e(f.explanation)}</p>")
    if f.dataflow:
        body.append(f"<p><b>{e(t['dataflow'])}</b></p><ol>" + "".join(
            f"<li><code>{e(s.kind)}</code> <code>{e(s.ref.file or '')}:{s.ref.line}</code> — <code>{e(s.code[:160])}</code></li>"
            for s in f.dataflow) + "</ol>")
    body.append(f"<p><b>{e(t['ladder'])}</b></p><ul>" + "".join(
        f"<li><span class='lvl'>L{int(ev.level)}</span> [{e(ev.by)}] {e(ev.detail)}</li>"
        for ev in sorted(f.evidence, key=lambda ev: ev.level)) + "</ul>")
    if f.llm_verdict:
        body.append(f"<p><b>{e(t['model'])}:</b> {e(str(f.llm_verdict.get('verdict')))} — "
                    f"{e((f.llm_verdict.get('explanation') or '')[:600])}</p>")
    body.append(f"<p><b>{e(t['not_verified'])}</b></p><ul>" + "".join(f"<li>{e(n)}</li>" for n in (f.not_verified or ["-"])) + "</ul>")
    if f.fix:
        diff = "".join(
            f"<span class='{'add' if ln.startswith('+') and not ln.startswith('+++') else 'del' if ln.startswith('-') and not ln.startswith('---') else ''}'>{e(ln)}</span>\n"
            for ln in f.fix.diff.splitlines())
        state = (f"{t['rescan']}: {f.fix.rescan_clean}; {t['prop_after']}: "
                 f"{f.fix.property_after if f.fix.property_after is not None else t['not_run']}")
        body.append(f"<p><b>{e(t['fix'])}</b> <span class='muted'>({e(f.fix.by)}; {e(state)})</span> {e(f.fix.explanation)}</p>"
                    f"<pre>{diff}</pre>")
    return f"<details id='{f.id.lower()}'>{head}{''.join(body)}</details>"


def console_summary(r: Report) -> str:
    t, s = r.t, _summary_rows(r)
    sev = ", ".join(f"{k}: {s['sev'].get(k, 0)}" for k in SEV_ORDER)
    lines = [f"{t['verdict']}: {len(r.open)} {t['open']} ({sev}); {len(r.refuted)} {t['refuted']}"]
    for f in [f for f in r.open if f.severity in ("critical", "high")][:8]:
        lines.append(f"  [{f.severity:<8}] {f.confidence_label} {f.cwe:<9} {f.location.file}:{f.location.start_line}  {f.title}")
    return "\n".join(lines)


def dump_run(r: Report) -> str:
    return json.dumps({"run": r.run, "stats": r.stats, "summary": {k: dict(v) for k, v in _summary_rows(r).items()}},
                      indent=1, default=str, ensure_ascii=False)
