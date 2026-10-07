import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
STAND = ROOT / "eval" / "seeded" / "repo"


@pytest.fixture(scope="session")
def stand():
    return STAND


@pytest.fixture(scope="session")
def taint_engine():
    from caa.engine_code.taint import TaintEngine
    from caa.tools.fs import RepoFS
    from caa.tools.symbols import SymbolIndex
    fs = RepoFS(STAND)
    return TaintEngine(fs, SymbolIndex(fs))


def line_of(rel: str, needle: str) -> int:
    for i, t in enumerate((STAND / rel).read_text().splitlines(), 1):
        if needle in t:
            return i
    raise AssertionError(needle)
