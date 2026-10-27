"""``validate --watch``: the polling loop, driven by a fake clock and file listing."""

from __future__ import annotations

import io
import re
from collections.abc import Iterator, Sequence
from pathlib import Path

import pytest
from rich.console import Console

from opentide.cli.ui.diagnostics import Diagnostic, Fix, TextEdit
from opentide.cli.ui.mode import OutputMode
from opentide.cli.ui.watch import (
    POLL_INTERVAL,
    Changes,
    LiveView,
    PlainView,
    Snapshot,
    Watcher,
    WatchRun,
    object_files,
    references,
    take_snapshot,
)

_RULE = Path("/ws/objects/rules/rule.yaml")
_THREAT = Path("/ws/objects/threats/threat.yaml")
_ANSI = re.compile(r"\x1b\[[0-9;?]*[A-Za-z]|\x1b\]8;[^\x1b]*\x1b\\")


def _finding(path: Path | None, *, severity: str = "error", code: str = "vocab_unknown"):
    return Diagnostic(
        code=code,
        severity=severity,  # type: ignore[arg-type]
        message=f"{code} in {path.name if path else 'workspace'}",
        path=None if path is None else f"objects/{path.parent.name}/{path.name}",
        file_path=path,
    )


class FakeDisk:
    """A file listing that changes when the test says, and the UUIDs in each file."""

    def __init__(self, files: dict[Path, int]) -> None:
        self.files = dict(files)
        self.refs: dict[Path, frozenset[str]] = {path: frozenset({path.stem}) for path in files}

    def snapshot(self, roots: Sequence[Path]) -> Snapshot:
        return {path: (mtime, 1) for path, mtime in self.files.items()}

    def touch(self, path: Path, *, refs: frozenset[str] | None = None) -> None:
        self.files[path] = self.files.get(path, 0) + 1
        self.refs[path] = refs if refs is not None else self.refs.get(path, frozenset())

    def read_references(self, path: Path) -> frozenset[str]:
        return self.refs.get(path, frozenset())


class FakeValidator:
    """Records each call; answers with the findings the test sets per file."""

    def __init__(self, findings: dict[Path | None, list[Diagnostic]], objects: int = 2) -> None:
        self.findings = findings
        self.objects = objects
        self.calls: list[tuple[Path, ...] | None] = []

    def __call__(self, changed: Sequence[Path] | None) -> tuple[list[Diagnostic], int]:
        self.calls.append(None if changed is None else tuple(changed))
        if changed is None:
            found = [item for items in self.findings.values() for item in items]
            return found, self.objects
        found = [item for path in changed for item in self.findings.get(path, [])]
        return found, len(changed)


class FakeClock:
    def __init__(self) -> None:
        self.now = 100.0

    def __call__(self) -> float:
        self.now += 0.25
        return self.now


def _watcher(disk: FakeDisk, validator: FakeValidator, **kwargs) -> Watcher:
    return Watcher(
        roots=[Path("/ws/objects")],
        validate=validator,
        snapshot=disk.snapshot,
        read_references=disk.read_references,
        clock=FakeClock(),
        sleep=lambda _seconds: None,
        **kwargs,
    )


@pytest.fixture
def disk() -> FakeDisk:
    return FakeDisk({_RULE: 1, _THREAT: 1})


def test_the_first_run_validates_everything(disk: FakeDisk) -> None:
    validator = FakeValidator({_RULE: [_finding(_RULE)], _THREAT: []})
    run = _watcher(disk, validator).start()
    assert validator.calls == [None]
    assert run.summary == {"objects": 2, "errors": 1, "warnings": 0, "files": 1, "fixable": 0}
    assert run.failed
    assert not run.scoped
    assert run.seconds == pytest.approx(0.25)


def test_no_change_means_no_run(disk: FakeDisk) -> None:
    validator = FakeValidator({})
    watcher = _watcher(disk, validator)
    watcher.start()
    assert watcher.poll() is None
    assert validator.calls == [None]


def test_an_edit_that_keeps_references_validates_only_that_file(disk: FakeDisk) -> None:
    validator = FakeValidator({_RULE: [_finding(_RULE)], _THREAT: [_finding(_THREAT)]})
    watcher = _watcher(disk, validator)
    assert watcher.start().errors == 2
    validator.findings[_THREAT] = []
    disk.touch(_THREAT)
    run = watcher.poll()
    assert run is not None
    assert validator.calls == [None, (_THREAT,)]
    assert run.scoped
    assert run.changed == (_THREAT,)
    # The rule's finding from the first run is still counted.
    assert run.summary == {"objects": 2, "errors": 1, "warnings": 0, "files": 1, "fixable": 0}
    assert [item.file_path for item in run.diagnostics] == [_RULE]
    assert run.found == ()


def test_a_changed_reference_validates_everything(disk: FakeDisk) -> None:
    validator = FakeValidator({})
    watcher = _watcher(disk, validator)
    watcher.start()
    disk.touch(_RULE, refs=frozenset({"rule", "00000000-0000-4000-8002-deadbeef0000"}))
    run = watcher.poll()
    assert run is not None and not run.scoped
    assert validator.calls == [None, None]


@pytest.mark.parametrize("change", ["added", "removed"])
def test_an_added_or_removed_file_validates_everything(disk: FakeDisk, change: str) -> None:
    validator = FakeValidator({})
    watcher = _watcher(disk, validator)
    watcher.start()
    if change == "added":
        disk.touch(Path("/ws/objects/rules/new.yaml"))
    else:
        del disk.files[_THREAT]
    run = watcher.poll()
    assert run is not None and not run.scoped
    assert validator.calls == [None, None]


def test_a_finding_outside_the_changed_file_falls_back_to_a_full_run(disk: FakeDisk) -> None:
    validator = FakeValidator({})
    watcher = _watcher(disk, validator)
    watcher.start()
    validator.findings[_RULE] = [_finding(None, code="scope_no_match")]
    disk.touch(_RULE)
    run = watcher.poll()
    assert run is not None and not run.scoped
    assert validator.calls == [None, (_RULE,), None]


def test_a_narrowed_command_validates_its_scope_every_time(disk: FakeDisk) -> None:
    validator = FakeValidator({})
    watcher = _watcher(disk, validator, scoped_runs=False)
    watcher.start()
    disk.touch(_RULE)
    assert watcher.poll() is not None
    assert validator.calls == [None, None]


def test_strict_fails_on_warnings_but_not_on_exempt_ones(disk: FakeDisk) -> None:
    warning = _finding(_RULE, severity="warning", code="field_deprecated")
    exempt = _finding(_THREAT, severity="warning", code="platform_not_enabled")
    validator = FakeValidator({_RULE: [warning], _THREAT: [exempt]})
    loose = _watcher(disk, validator, strict=False).start()
    assert not loose.failed and loose.warnings == 2
    strict = _watcher(
        disk, validator, strict=True, strict_exempt=frozenset({"platform_not_enabled"})
    )
    assert strict.start().failed
    validator.findings[_RULE] = []
    assert (
        not _watcher(
            disk, validator, strict=True, strict_exempt=frozenset({"platform_not_enabled"})
        )
        .start()
        .failed
    )


def test_safe_fixes_are_counted(tmp_path: Path, disk: FakeDisk) -> None:
    rule = tmp_path / "rule.yaml"
    rule.write_text("metadata:\n  tlp: Clear\n")
    fixable = Diagnostic(
        code="vocab_unknown",
        severity="error",
        message="m",
        path="rule.yaml",
        file_path=rule,
        line=2,
        column=8,
        end_column=13,
        fix=Fix(True, (TextEdit(2, 8, 13, "clear"),)),
    )
    run = _watcher(disk, FakeValidator({rule: [fixable]})).start()
    assert run.fixable == 1


def test_the_loop_shows_each_run_and_stops_on_ctrl_c(disk: FakeDisk) -> None:
    validator = FakeValidator({_RULE: [_finding(_RULE)]})
    slept: list[float] = []

    def sleep(seconds: float) -> None:
        slept.append(seconds)
        if len(slept) == 2:
            disk.touch(_RULE)
        if len(slept) == 4:
            raise KeyboardInterrupt

    watcher = Watcher(
        roots=[],
        validate=validator,
        snapshot=disk.snapshot,
        read_references=disk.read_references,
        clock=FakeClock(),
        sleep=sleep,
    )
    shown: list[WatchRun] = []
    with pytest.raises(KeyboardInterrupt):
        watcher.run(shown.append)
    assert slept == [POLL_INTERVAL] * 4
    assert [run.number for run in shown] == [1, 2]
    assert shown[1].scoped


def test_changes_between_snapshots() -> None:
    old = {_RULE: (1, 1), _THREAT: (1, 1)}
    assert not Changes.between(old, dict(old))
    new_file = Path("/ws/objects/rules/new.yaml")
    changes = Changes.between(old, {_RULE: (2, 1), new_file: (1, 1)})
    assert changes.added == {new_file}
    assert changes.removed == {_THREAT}
    assert changes.modified == {_RULE}


def test_the_real_file_listing_reads_yaml_but_not_debug_files(tmp_path: Path) -> None:
    rules = tmp_path / "rules"
    (rules / "team").mkdir(parents=True)
    # A file in a subfolder is not an object (#584), so a watch ignores it.
    (rules / "team" / "nested.yaml").write_text("x: 1\n")
    rule = rules / "rule.yaml"
    rule.write_text(
        "metadata:\n  uuid: 00000000-0000-4000-8003-00000000000A\n"
        "detection_model: 00000000-0000-4000-8002-000000000001\n"
    )
    (rules / "rule.debug.yaml").write_text("x: 1\n")
    (rules / "notes.md").write_text("x\n")
    missing = tmp_path / "missing"
    assert object_files([tmp_path / "rules", missing]) == [rule]
    snapshot = take_snapshot([tmp_path / "rules"])
    assert list(snapshot) == [rule]
    assert references(rule) == {
        "00000000-0000-4000-8003-00000000000a",
        "00000000-0000-4000-8002-000000000001",
    }
    assert references(missing) == frozenset()


def _console(height: int = 40) -> tuple[Console, io.StringIO]:
    out = io.StringIO()
    return Console(file=out, width=100, height=height, color_system=None), out


def _describe(run: WatchRun) -> str:
    return f"{run.errors} errors · run {run.number}"


def _run(diagnostics: Sequence[Diagnostic], **kwargs) -> WatchRun:
    errors = sum(1 for item in diagnostics if item.severity == "error")
    defaults = {
        "number": 1,
        "diagnostics": tuple(diagnostics),
        "found": tuple(diagnostics),
        "objects": 3,
        "errors": errors,
        "warnings": 0,
        "files": 1,
        "failed": bool(errors),
        "seconds": 0.4,
    }
    return WatchRun(**(defaults | kwargs))


def test_the_plain_view_prints_frames_then_one_outcome_line() -> None:
    console, out = _console()
    view = PlainView(console, _describe, mode=OutputMode.PLAIN)
    view(_run([_finding(_RULE)]))
    view(_run([], number=2, failed=False))
    text = out.getvalue()
    assert text.count("error[vocab_unknown]: vocab_unknown in rule.yaml") == 1
    assert text.endswith("✗ 1 errors · run 1\n✓ 0 errors · run 2\n")


def test_the_live_view_keeps_the_outcome_line_on_a_short_terminal() -> None:
    console, _out = _console(height=8)
    view = LiveView(console, _describe, footer="watching objects")
    many = [_finding(Path(f"/ws/objects/rules/r{index}.yaml")) for index in range(5)]
    changed = (_RULE, _THREAT)
    group = view.renderable(_run(many, scoped=True, changed=changed))
    lines = [_ANSI.sub("", str(line)) for line in group.renderables]
    assert len(lines) <= 8
    assert re.fullmatch(r"… \d+ more lines", lines[-3])
    assert lines[-2] == "✗ 5 errors · run 1"
    assert re.fullmatch(
        r"watching objects · re-checked rule\.yaml and 1 more · \d\d:\d\d:\d\d · Ctrl-C to stop",
        lines[-1],
    )


def test_the_live_view_wraps_a_long_header_with_its_indent() -> None:
    """The Live view left wrapping to the terminal, which broke a long header with no
    continuation indent, unlike validate's own frames (post-merge end-to-end run)."""
    console, _out = _console()
    view = LiveView(console, _describe)
    long = Diagnostic(
        code="duplicate_id",
        severity="error",
        message="UUID 962056a0-3bf6-433c-89cd-26cbf1497c1a is also used by "
        "'LSASS access on defender_for_endpoint', a rule in another file of this catalogue",
        path="objects/rules/rule.yaml",
        file_path=_RULE,
    )
    group = view.renderable(_run([long]))
    lines = [_ANSI.sub("", str(line)) for line in group.renderables]
    assert len(lines[0]) <= 100
    assert lines[1].startswith("  ") and "another file" in lines[0] + lines[1]


def test_the_live_view_redraws_in_place(capsys: pytest.CaptureFixture[str]) -> None:
    console, out = _console()
    with LiveView(console, _describe, quiet=True) as view:
        view(_run([_finding(_RULE), _finding(_THREAT, severity="warning")]))
        view(_run([], number=2, failed=False, changed=(_RULE,)))
    text = _ANSI.sub("", out.getvalue())
    assert "✓ 0 errors · run 2" in text
    assert "changed rule.yaml" in text
    assert "warning[" not in text, "--quiet keeps errors only"


@pytest.fixture(autouse=True)
def _no_real_sleep(monkeypatch: pytest.MonkeyPatch) -> Iterator[None]:
    """A test that forgot to pass ``sleep`` would hang; fail it instead."""

    def refuse(_seconds: float) -> None:
        raise AssertionError("the watch loop slept for real")

    monkeypatch.setattr("opentide.cli.ui.watch.time.sleep", refuse)
    yield


_OBJECTIVE = Path("/ws/objects/objectives/objective.yaml")


def test_a_file_that_parses_again_validates_everything() -> None:
    """Fixing a broken objective resolves the rule's reference to it: a full pass."""
    disk = FakeDisk({_RULE: 1, _OBJECTIVE: 1})
    validator = FakeValidator(
        {
            _OBJECTIVE: [_finding(_OBJECTIVE, code="yaml_parse")],
            _RULE: [_finding(_RULE, code="invalid_ref")],
        },
        objects=1,
    )
    watcher = _watcher(disk, validator)
    first = watcher.start()
    assert (first.errors, first.objects) == (2, 1)
    validator.findings = {}
    validator.objects = 2
    disk.touch(_OBJECTIVE)
    run = watcher.poll()
    assert run is not None and not run.scoped
    assert validator.calls == [None, None]
    assert (run.errors, run.objects) == (0, 2), "no stale invalid_ref, and the count is current"


def test_a_file_that_stops_parsing_validates_everything() -> None:
    """Breaking the objective leaves the rule's reference dangling: a full pass."""
    disk = FakeDisk({_RULE: 1, _OBJECTIVE: 1})
    validator = FakeValidator({})
    watcher = _watcher(disk, validator)
    watcher.start()
    validator.findings = {
        _OBJECTIVE: [_finding(_OBJECTIVE, code="yaml_parse")],
        _RULE: [_finding(_RULE, code="invalid_ref")],
    }
    validator.objects = 1
    disk.touch(_OBJECTIVE)
    run = watcher.poll()
    assert run is not None and not run.scoped
    assert validator.calls == [None, (_OBJECTIVE,), None]
    assert (run.errors, run.objects) == (2, 1)
    assert {item.code for item in run.diagnostics} == {"yaml_parse", "invalid_ref"}


def test_a_scoped_pass_that_loses_an_object_validates_everything(disk: FakeDisk) -> None:
    """A file that no longer holds an object, with no finding saying why: a full pass."""

    class Losing(FakeValidator):
        def __call__(self, changed: Sequence[Path] | None) -> tuple[list[Diagnostic], int]:
            found, objects = super().__call__(changed)
            return found, objects if changed is None else 0

    validator = Losing({})
    watcher = _watcher(disk, validator)
    watcher.start()
    validator.objects = 1
    disk.touch(_RULE)
    run = watcher.poll()
    assert run is not None and not run.scoped
    assert validator.calls == [None, (_RULE,), None]
    assert run.objects == 1
