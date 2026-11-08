"""The live Elasticsearch oracle's query tokenizers (scripts/engine/oracles/elasticsearch/run.py).

The oracle runs in CI only (.github/workflows/oracle.yml), against queries from the
corpus and from elastic/detection-rules; these tests pin its tokenizers here.
"""

from __future__ import annotations

import importlib.util
import subprocess
import sys
from pathlib import Path
from types import ModuleType

import pytest

ROOT = Path(__file__).resolve().parents[2]
RUN = ROOT / "scripts" / "engine" / "oracles" / "elasticsearch" / "run.py"

# A triple-quoted string that never closes, then newlines: `(?:.|\n)*?` under
# re.DOTALL matches each newline two ways, so a pattern that must fail here
# backtracks 2**64 times.
UNTERMINATED = '"""' + "\n" * 64


@pytest.fixture(scope="module")
def oracle() -> ModuleType:
    spec = importlib.util.spec_from_file_location("elasticsearch_oracle_run", RUN)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_eql_references_are_made_optional_outside_strings(oracle: ModuleType) -> None:
    text = 'process where x == "x" and `x` : """x\nx""" and ?x != null and x.y == 1'
    assert oracle.make_optional(text, {"x"}) == (
        'process where ?x == "x" and ?`x` : """x\nx""" and ?x != null and x.y == 1'
    )


def test_esql_triple_quoted_strings_span_lines(oracle: ModuleType) -> None:
    text = 'FROM o | WHERE a == """b\n|c""" | KEEP a // x\n'
    tokens = [(kind, text[start:end]) for kind, start, end in oracle._tokens(text)]
    assert ("string", '"""b\n|c"""') in tokens
    assert [kind for kind, _ in tokens].count("punct") == 2
    assert tokens[-1] == ("comment", "// x")


def test_an_unterminated_esql_triple_quote_runs_to_the_end(oracle: ModuleType) -> None:
    text = 'ROW a = """never closed\n| KEEP a'
    tokens = [(kind, text[start:end]) for kind, start, end in oracle._tokens(text)]
    assert tokens[-1] == ("string", '"""never closed\n| KEEP a')


@pytest.mark.parametrize("call", ["make_optional(TEXT, {'x'})", "_tokens(TEXT)"])
def test_an_unterminated_triple_quote_is_tokenized_in_linear_time(call: str) -> None:
    """In a child process, so a pattern that backtracks exponentially fails the
    test at the timeout instead of hanging the suite."""
    code = (
        "import importlib.util\n"
        f"spec = importlib.util.spec_from_file_location('run', {str(RUN)!r})\n"
        "module = importlib.util.module_from_spec(spec)\n"
        "spec.loader.exec_module(module)\n"
        f"TEXT = {UNTERMINATED!r}\n"
        f"module.{call}\n"
    )
    subprocess.run([sys.executable, "-I", "-c", code], check=True, timeout=30)
