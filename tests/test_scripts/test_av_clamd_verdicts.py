"""The ClamAV job's coverage check (scripts/av/clamd_verdicts.py, #1743).

`clamdscan --multiscan` has clamd walk each tree itself; a file it never reached would pass in
silence. The check holds clamd's log (`LogClean`) to a verdict for every regular file of every
tree, so these tests hold the check to that: a file without a line fails and is named, a
detection counts as a verdict, and a path with ": " in it is read whole.
"""

from __future__ import annotations

import importlib.util
import sys
from pathlib import Path

import pytest

_MODULE = Path(__file__).resolve().parents[2] / "scripts" / "av" / "clamd_verdicts.py"
_spec = importlib.util.spec_from_file_location("av_clamd_verdicts", _MODULE)
assert _spec
assert _spec.loader
clamd_verdicts = importlib.util.module_from_spec(_spec)
sys.modules["av_clamd_verdicts"] = clamd_verdicts
_spec.loader.exec_module(clamd_verdicts)


def _tree(root: Path) -> list[Path]:
    """A tree as the gate's extractor leaves one: nested directories, an empty file, a link."""
    files = [
        root / "opentide.whl",
        root / "opentide.whl.d" / "opentide" / "_native.pyd",
        root / "opentide.whl.d" / "opentide" / "py.typed",
        root / "opentide.whl.d" / "a: colon.txt",
    ]
    for file in files:
        file.parent.mkdir(parents=True, exist_ok=True)
        file.write_bytes(b"" if file.name == "py.typed" else b"data")
    (root / "link").symlink_to(files[0])
    return [file.resolve() for file in files]


def _log(path: Path, lines: list[str]) -> Path:
    path.write_text(
        "\n".join(["+++ Started at Mon Nov 23 09:26:17 2026", "Loaded 3628230 signatures.", *lines])
        + "\n",
        encoding="utf-8",
    )
    return path


def test_clean_and_found_lines_are_verdicts_and_nothing_else_is() -> None:
    seen = clamd_verdicts.verdicts(
        "/t/a: OK\n"
        "/t/b.exe: Win.Coinminer.Generic-7150608-0 FOUND\n"
        "/t/c: Heuristics.Limits.Exceeded.MaxScanTime FOUND\n"
        "/t/d: Access denied. ERROR\n"
        "/t/e: lstat() failed: No such file or directory. ERROR\n"
        "Limits: Global time limit set to 120000 milliseconds.\n"
    )
    assert seen == {"/t/a", "/t/b.exe", "/t/c"}


def test_a_path_holding_a_colon_and_space_is_read_whole() -> None:
    seen = clamd_verdicts.verdicts("/t/a: b.txt: OK\n/t/c: d.exe: Eicar-Test-Signature FOUND\n")
    assert seen == {"/t/a: b.txt", "/t/c: d.exe"}


def test_every_file_with_a_verdict_passes(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    files = _tree(tmp_path / "av-extracted")
    log = _log(
        tmp_path / "clamd.log",
        [f"{files[0]}: OK", f"{files[1]}: Eicar-Test-Signature FOUND"]
        + [f"{file}: OK" for file in files[2:]],
    )
    assert clamd_verdicts.main(["--log", str(log), str(tmp_path / "av-extracted")]) == 0
    out = capsys.readouterr().out
    assert f"{tmp_path / 'av-extracted'}: 4 files, 4 with a verdict" in out


def test_a_file_without_a_verdict_fails_and_is_named(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    files = _tree(tmp_path / "av-extracted")
    log = _log(tmp_path / "clamd.log", [f"{file}: OK" for file in files if file.name != "py.typed"])
    assert clamd_verdicts.main(["--log", str(log), str(tmp_path / "av-extracted")]) == 2
    captured = capsys.readouterr()
    assert "4 files, 3 with a verdict" in captured.out
    assert f"no verdict for {files[2]}" in captured.err


def test_an_error_is_not_a_verdict(tmp_path: Path) -> None:
    files = _tree(tmp_path / "t")
    lines = [f"{file}: OK" for file in files[1:]] + [f"{files[0]}: Access denied. ERROR"]
    assert (
        clamd_verdicts.main(
            ["--log", str(_log(tmp_path / "clamd.log", lines)), str(tmp_path / "t")]
        )
        == 2
    )


def test_each_tree_is_held_to_its_own_files(tmp_path: Path) -> None:
    artifacts = _tree(tmp_path / "av-artifacts")
    extracted = _tree(tmp_path / "av-extracted")
    log = _log(tmp_path / "clamd.log", [f"{file}: OK" for file in artifacts])
    argv = ["--log", str(log), str(tmp_path / "av-artifacts"), str(tmp_path / "av-extracted")]
    assert clamd_verdicts.main(argv) == 2
    log = _log(tmp_path / "clamd.log", [f"{file}: OK" for file in artifacts + extracted])
    assert clamd_verdicts.main(argv) == 0


def test_a_log_that_cannot_be_read_or_a_tree_that_is_not_one_fails(tmp_path: Path) -> None:
    (tmp_path / "t").mkdir()
    assert clamd_verdicts.main(["--log", str(tmp_path / "missing.log"), str(tmp_path / "t")]) == 2
    log = _log(tmp_path / "clamd.log", [])
    assert clamd_verdicts.main(["--log", str(log), str(tmp_path / "no-such-tree")]) == 2
