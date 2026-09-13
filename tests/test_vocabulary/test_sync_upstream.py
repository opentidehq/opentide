"""Upstream ATT&CK + MISP vocabulary ingest orchestration."""

from __future__ import annotations

from pathlib import Path

import pytest

from opentide.vocabulary.generate_attack import GenerateReport
from opentide.vocabulary.lifecycle import LifecycleResult
from opentide.vocabulary.sync_upstream import (
    SyncReport,
    cli_main,
    pin_directories,
    specifications_root,
    sync_upstream,
)


def _lifecycle(**overrides: object) -> LifecycleResult:
    payload: dict[str, object] = {
        "keys": (),
        "added": (),
        "updated": (),
        "removed": (),
        "backfilled": (),
        "introducing_version": None,
        "removal_version": None,
    }
    payload.update(overrides)
    return LifecycleResult(**payload)  # type: ignore[arg-type]


def test_pin_directories_include_specs_and_bundle(tmp_path: Path) -> None:
    directories = pin_directories(tmp_path)
    assert directories[0] == tmp_path / "schemas" / "pins"
    assert directories[1].name == "pins"


def test_sync_upstream_check_does_not_write(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    vocab_dir = tmp_path / "vocabularies"
    vocab_dir.mkdir()
    empty = GenerateReport(lifecycles={"att&ck": _lifecycle()}, source_changed=False)
    actors = GenerateReport(lifecycles={"actors": _lifecycle()}, source_changed=False)
    monkeypatch.setattr(
        "opentide.vocabulary.sync_upstream.generate_attack_vocabs",
        lambda **_kwargs: empty,
    )
    monkeypatch.setattr(
        "opentide.vocabulary.sync_upstream.generate_actors_vocabs",
        lambda **_kwargs: actors,
    )
    written = {"sync": False}

    def _sync(_root: Path) -> None:
        written["sync"] = True

    monkeypatch.setattr("opentide.vocabulary.sync_upstream._sync_bundled_vocabularies", _sync)

    report = sync_upstream(fetch=False, apply=False, specifications=tmp_path)
    assert report.dirty is False
    assert report.wrote is False
    assert written["sync"] is False


def test_sync_upstream_apply_writes_when_dirty(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    (tmp_path / "vocabularies").mkdir()
    pins = tmp_path / "schemas" / "pins"
    pins.mkdir(parents=True)
    (pins / "threat.toml").write_text('"threat.att&ck" = "att&ck::1.0"\n', encoding="utf-8")
    dirty = GenerateReport(
        lifecycles={
            "att&ck": _lifecycle(
                added=("T1002",),
                introducing_version="1.1",
                keys=({"id": "T1002"},),
            )
        },
        source_changed=False,
    )
    actors = GenerateReport(lifecycles={"actors": _lifecycle()}, source_changed=False)
    calls: list[bool] = []

    def _attack(*, fetch: bool, vocab_dir: Path, write: bool) -> GenerateReport:
        calls.append(write)
        return dirty

    monkeypatch.setattr("opentide.vocabulary.sync_upstream.generate_attack_vocabs", _attack)
    monkeypatch.setattr(
        "opentide.vocabulary.sync_upstream.generate_actors_vocabs",
        lambda **_kwargs: actors,
    )
    monkeypatch.setattr(
        "opentide.vocabulary.sync_upstream._sync_bundled_vocabularies",
        lambda _root: None,
    )
    monkeypatch.setattr(
        "opentide.vocabulary.sync_upstream.pin_data_dir",
        lambda: pins,
    )

    report = sync_upstream(fetch=False, apply=True, specifications=tmp_path)
    assert report.wrote is True
    assert True in calls
    assert "att&ck::1.1" in (pins / "threat.toml").read_text(encoding="utf-8")


def test_cli_main_rejects_check_and_apply_together() -> None:
    assert cli_main(["--check", "--apply"]) == 2


def test_cli_main_check_exits_one_when_dirty(monkeypatch: pytest.MonkeyPatch) -> None:
    dirty = type("R", (), {"dirty": True, "wrote": False, "summary_lines": lambda self: ["x"]})()
    monkeypatch.setattr("opentide.vocabulary.sync_upstream.sync_upstream", lambda **_k: dirty)
    assert cli_main(["--check", "--no-fetch"]) == 1


def test_cli_main_apply_reports_write(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    result = type("R", (), {"dirty": True, "wrote": True, "summary_lines": lambda self: ["ok"]})()
    monkeypatch.setattr("opentide.vocabulary.sync_upstream.sync_upstream", lambda **_k: result)
    assert cli_main(["--apply", "--no-fetch"]) == 0
    assert "wrote" in capsys.readouterr().out


def test_cli_main_clean_exits_zero(monkeypatch: pytest.MonkeyPatch) -> None:
    clean = type("R", (), {"dirty": False, "wrote": False, "summary_lines": lambda self: []})()
    monkeypatch.setattr("opentide.vocabulary.sync_upstream.sync_upstream", lambda **_k: clean)
    assert cli_main(["--no-fetch"]) == 0


def test_cli_help(capsys: pytest.CaptureFixture[str]) -> None:
    with pytest.raises(SystemExit) as exc:
        cli_main(["--help"])
    assert exc.value.code == 0
    assert "--check" in capsys.readouterr().out


def test_specifications_root_from_env(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("OPENTIDE_SPECIFICATIONS_ROOT", str(tmp_path))
    assert specifications_root() == tmp_path.resolve()


def test_sync_upstream_apply_skips_write_when_clean(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    empty = GenerateReport(lifecycles={"att&ck": _lifecycle()}, source_changed=False)
    actors = GenerateReport(lifecycles={"actors": _lifecycle()}, source_changed=False)
    monkeypatch.setattr(
        "opentide.vocabulary.sync_upstream.generate_attack_vocabs",
        lambda **_kwargs: empty,
    )
    monkeypatch.setattr(
        "opentide.vocabulary.sync_upstream.generate_actors_vocabs",
        lambda **_kwargs: actors,
    )
    written = {"sync": False}
    monkeypatch.setattr(
        "opentide.vocabulary.sync_upstream._sync_bundled_vocabularies",
        lambda _root: written.__setitem__("sync", True),
    )
    report = sync_upstream(fetch=False, apply=True, specifications=tmp_path)
    assert report.wrote is False
    assert written["sync"] is False


def test_sync_report_summary_includes_pin_contract() -> None:
    report = SyncReport(
        attack=GenerateReport(
            lifecycles={
                "att&ck": _lifecycle(
                    added=("T1002",),
                    introducing_version="1.1",
                    keys=({"id": "T1002"},),
                )
            }
        ),
        actors=GenerateReport(lifecycles={"actors": _lifecycle()}, source_changed=True),
        pin_versions={"att&ck": "1.1"},
    )
    text = "\n".join(report.summary_lines())
    assert "att&ck:" in text
    assert "pin → att&ck::1.1" in text
    assert "source provenance changed (actors)" in text
    assert "pin bumps: att&ck::1.1" in text
    assert report.dirty is True
