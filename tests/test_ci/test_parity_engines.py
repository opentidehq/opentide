"""scripts/parity_engines.py: the engine state the parity dashboard reads (UC-X.2, #844)."""

from __future__ import annotations

import importlib.util
import json
import sys
from pathlib import Path
from types import ModuleType

import pytest

ROOT = Path(__file__).resolve().parents[2]
SCRIPT = ROOT / "scripts" / "parity_engines.py"


def _load() -> ModuleType:
    spec = importlib.util.spec_from_file_location("parity_engines", SCRIPT)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


parity_engines = _load()


def test_the_repositorys_table_reads_and_matches_the_import() -> None:
    from opentide.cli.engines import RUST_COMMANDS

    state = parity_engines.engine_state(parity_engines.ENGINES.read_text(encoding="utf-8"))
    assert state == {"rust": sorted(list(path) for path in RUST_COMMANDS), "flipped": []}


def test_reads_every_command_path_of_the_literal() -> None:
    source = (
        "RUST_COMMANDS: dict[tuple[str, ...], RustCommand] = {\n"
        '    ("validate",): RustCommand(launch=("opentide-rs",)),\n'
        '    ("info", "catalog"): RustCommand(launch=("opentide-rs",)),\n'
        "}\n"
    )
    assert parity_engines.rust_commands(source) == [["info", "catalog"], ["validate"]]
    assert parity_engines.rust_commands("RUST_COMMANDS = {}\n") == []
    # The root command (`opentide` itself) is the empty path.
    assert parity_engines.rust_commands("RUST_COMMANDS = {(): None}\n") == [[]]


@pytest.mark.parametrize(
    ("source", "message"),
    [
        ("OTHER = {}\n", "no RUST_COMMANDS"),
        ("RUST_COMMANDS = dict(table)\n", "not a dict literal"),
        ("RUST_COMMANDS = {**base}\n", "not a dict literal"),
        ('RUST_COMMANDS = {"validate": 1}\n', "not a tuple"),
        ("RUST_COMMANDS = {(1,): 1}\n", "non-string"),
    ],
)
def test_a_table_it_cannot_read_is_an_error(source: str, message: str) -> None:
    with pytest.raises(parity_engines.EngineStateError, match=message):
        parity_engines.rust_commands(source)


def test_main_prints_the_document_or_fails_with_2(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    good = tmp_path / "engines.py"
    good.write_text('RUST_COMMANDS = {("explain",): None}\n', encoding="utf-8")
    assert parity_engines.main(["parity_engines.py", str(good)]) == 0
    assert json.loads(capsys.readouterr().out) == {"rust": [["explain"]], "flipped": []}
    bad = tmp_path / "bad.py"
    bad.write_text("RUST_COMMANDS = build()\n", encoding="utf-8")
    assert parity_engines.main(["parity_engines.py", str(bad)]) == 2
    assert "not a dict literal" in capsys.readouterr().err
