"""``check_docs_mdx.py``: docs/ prose stays parseable as MDX, which opentide.org renders it as."""

from __future__ import annotations

import importlib.util
from pathlib import Path
from types import ModuleType

import pytest

ROOT = Path(__file__).resolve().parents[2]


def _script() -> ModuleType:
    spec = importlib.util.spec_from_file_location(
        "check_docs_mdx", ROOT / "scripts" / "build" / "check_docs_mdx.py"
    )
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


@pytest.mark.parametrize(
    "line",
    [
        "The CQL link operator <=> links fields.",
        "Startup takes < 120 ms.",
        "Set {name} in the config.",
    ],
)
def test_prose_mdx_cannot_parse_is_reported(line: str) -> None:
    assert _script().problems(f"---\ntitle: T\n---\n\n{line}\n")


@pytest.mark.parametrize(
    "text",
    [
        "Use `<=>` and `{name}` in code.",
        "```\nx <= y and {a: 1}\n```",
        "~~~\n<=>\n~~~",
        "<Tabs items={['CLI', 'SDK']}>\n<Tab value=\"CLI\">x</Tab>\n</Tabs>",
        "<!-- a < b {c} -->",
        "<!--\n a < b\n-->",
        "The operator &lt;=> links fields.",
        "---\ntitle: a < b\n---",
    ],
)
def test_code_tags_comments_and_entities_pass(text: str) -> None:
    assert _script().problems(text) == []


def test_the_docs_tree_parses_as_mdx() -> None:
    found = {
        f"{path.relative_to(ROOT)}:{number}: {message}"
        for path in sorted((ROOT / "docs").rglob("*.md"))
        for number, message in _script().problems(path.read_text(encoding="utf-8"))
    }
    assert not found, "MDX cannot parse this prose; use backticks or &lt; / &#123;:\n" + "\n".join(
        sorted(found)
    )
