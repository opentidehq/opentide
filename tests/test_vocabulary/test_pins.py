"""Schema pin bumping for vocabulary ingest."""

from __future__ import annotations

from pathlib import Path

from opentide.vocabulary.pins import bump_pin_contents, bump_pin_dir, bump_pin_file, should_bump


def test_should_bump_same_major_higher_minor() -> None:
    assert should_bump("1.0", "1.1")
    assert not should_bump("1.1", "1.1")
    assert not should_bump("1.1", "1.0")
    assert not should_bump("1.1", "2.0")


def test_bump_pin_contents_updates_matching_contracts() -> None:
    text = (
        '["threat::1.0"]\n'
        '"threat.att&ck" = "att&ck::1.0"\n'
        '"threat.actors" = "actors::1.0"\n'
        '"threat.killchain" = "killchain::1.1"\n'
        '"techniques" = "att&ck::1.0"\n'
    )
    rewritten, changes = bump_pin_contents(text, {"att&ck": "1.1", "actors": "1.1"})
    assert '"threat.att&ck" = "att&ck::1.1"' in rewritten
    assert '"threat.actors" = "actors::1.1"' in rewritten
    assert '"threat.killchain" = "killchain::1.1"' in rewritten
    assert '"techniques" = "att&ck::1.1"' in rewritten
    assert ("att&ck", "1.0", "1.1") in changes
    assert ("actors", "1.0", "1.1") in changes


def test_bump_pin_contents_never_advances_major() -> None:
    text = '"techniques" = "att&ck::1.0"\n'
    rewritten, changes = bump_pin_contents(text, {"att&ck": "2.0"})
    assert rewritten == text
    assert changes == []


def test_bump_pin_dir_rewrites_family_files(tmp_path: Path) -> None:
    threat = tmp_path / "threat.toml"
    objective = tmp_path / "objective.toml"
    threat.write_text('"threat.att&ck" = "att&ck::1.0"\n', encoding="utf-8")
    objective.write_text('"objective.attack" = "att&ck::1.0"\n', encoding="utf-8")
    (tmp_path / "rule.toml").write_text('"severity" = "severity::1.0"\n', encoding="utf-8")

    changes = bump_pin_dir(tmp_path, {"att&ck": "1.1"})
    assert len(changes) == 2
    assert "att&ck::1.1" in threat.read_text(encoding="utf-8")
    assert "att&ck::1.1" in objective.read_text(encoding="utf-8")


def test_bump_pin_file_missing_or_empty_versions(tmp_path: Path) -> None:
    missing = tmp_path / "nope.toml"
    assert bump_pin_file(missing, {"att&ck": "1.1"}) == []
    present = tmp_path / "threat.toml"
    present.write_text('"threat.att&ck" = "att&ck::1.0"\n', encoding="utf-8")
    assert bump_pin_file(present, {}) == []
    assert present.read_text(encoding="utf-8") == '"threat.att&ck" = "att&ck::1.0"\n'
