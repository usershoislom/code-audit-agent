"""kb_lookup: exact CWE match first, then hybrid BM25 (+ optional embeddings)."""
from __future__ import annotations

import math
import re
from collections import Counter
from pathlib import Path
from typing import Callable

import yaml

CARDS_DIR = Path(__file__).parent / "cards"
_TOKEN = re.compile(r"[a-z0-9_]+")


def _tok(s: str) -> list[str]:
    return _TOKEN.findall(s.lower())


class BM25:
    def __init__(self, docs: list[list[str]], k1: float = 1.5, b: float = 0.75):
        self.docs, self.k1, self.b = docs, k1, b
        self.avgdl = sum(map(len, docs)) / max(1, len(docs))
        df = Counter(t for d in docs for t in set(d))
        n = len(docs)
        self.idf = {t: math.log(1 + (n - f + 0.5) / (f + 0.5)) for t, f in df.items()}
        self.tf = [Counter(d) for d in docs]

    def scores(self, q: list[str]) -> list[float]:
        out = []
        for d, tf in zip(self.docs, self.tf):
            s = 0.0
            for t in q:
                if t in tf:
                    f = tf[t]
                    s += self.idf[t] * f * (self.k1 + 1) / (f + self.k1 * (1 - self.b + self.b * len(d) / self.avgdl))
            out.append(s)
        return out


class KnowledgeBase:
    def __init__(self, cards_dir: Path = CARDS_DIR, embed: Callable[[list[str]], list[list[float]]] | None = None):
        self.cards: list[dict] = []
        for f in sorted(cards_dir.glob("*.yaml")):
            self.cards.extend(yaml.safe_load(f.read_text()))
        self.by_cwe = {c["cwe"]: c for c in self.cards}
        self._texts = [self._text(c) for c in self.cards]
        self.bm25 = BM25([_tok(t) for t in self._texts])
        self.embed = embed
        self._vecs = embed(self._texts) if embed else None

    @staticmethod
    def _text(c: dict) -> str:
        parts = [c["cwe"], c["title"], c.get("impact", ""), c.get("fix", "")]
        for k in ("sources", "sinks", "sanitizers", "not_sanitizers"):
            parts.extend(c.get(k, []))
        return " ".join(parts)

    def get(self, cwe: str) -> dict | None:
        return self.by_cwe.get(cwe)

    def lookup(self, query: str, k: int = 2) -> list[dict]:
        q = query.strip().upper()
        if q in self.by_cwe:
            return [self.by_cwe[q]]
        bm = self.bm25.scores(_tok(query))
        scores = _norm(bm)
        if self._vecs is not None:
            qv = self.embed([query])[0]
            cos = [_cos(qv, v) for v in self._vecs]
            scores = [0.5 * a + 0.5 * b for a, b in zip(scores, _norm(cos))]
        ranked = sorted(range(len(self.cards)), key=lambda i: -scores[i])
        return [self.cards[i] for i in ranked[:k] if scores[i] > 0]

    def render(self, card: dict) -> str:
        return (f"{card['cwe']} {card['title']}\nImpact: {card['impact']}\n"
                f"Sinks: {', '.join(card.get('sinks', []))}\nReal sanitizers: {', '.join(card.get('sanitizers', []))}\n"
                f"NOT sanitizers: {', '.join(card.get('not_sanitizers', []))}\nFix: {card['fix']}")


def _norm(xs: list[float]) -> list[float]:
    m = max(xs) if xs else 0
    return [x / m if m > 0 else 0.0 for x in xs]


def _cos(a: list[float], b: list[float]) -> float:
    na = math.sqrt(sum(x * x for x in a)) or 1
    nb = math.sqrt(sum(x * x for x in b)) or 1
    return sum(x * y for x, y in zip(a, b)) / (na * nb)
