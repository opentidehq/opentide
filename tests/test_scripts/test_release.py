"""``release.py``: the version a release from development publishes, and its notes PR."""

from __future__ import annotations

import importlib.util
from pathlib import Path
from types import ModuleType

import pytest

ROOT = Path(__file__).resolve().parents[2]
REPOSITORY = "https://github.com/opentidehq/opentide"


def _script() -> ModuleType:
    spec = importlib.util.spec_from_file_location(
        "release", ROOT / "scripts" / "build" / "release.py"
    )
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _write(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")


@pytest.fixture
def repo(tmp_path: Path) -> Path:
    """A tree whose notes PR for 1.2.0 has merged."""
    _write(
        tmp_path / "CHANGELOG.md",
        "# Changelog\n\n## [Unreleased]\n\n## [1.2.0] — 2026-11-02\n\nMinor.\n\n"
        "## [1.1.0] — 2026-10-01\n\nOlder.\n\n"
        f"[Unreleased]: {REPOSITORY}/compare/v1.2.0...HEAD\n"
        f"[1.2.0]: {REPOSITORY}/releases/tag/v1.2.0\n"
        f"[1.1.0]: {REPOSITORY}/releases/tag/v1.1.0\n",
    )
    _write(tmp_path / ".github" / "release-notes" / "v1.2.0.md", "# 1.2.0\n")
    _write(
        tmp_path / "docs" / "usage" / "releases.md",
        "# Releases\n\n## 1.2.0 — 2 November 2026\n\n## 1.1.0 — 1 October 2026\n",
    )
    _write(tmp_path / "README.md", "pip install opentide==1.2.0\n")
    return tmp_path


def _edit(path: Path, old: str, new: str) -> None:
    text = path.read_text(encoding="utf-8")
    assert old in text
    path.write_text(text.replace(old, new), encoding="utf-8")


def test_this_repository_can_release_its_newest_version() -> None:
    # Every merged notes PR leaves the tree releasable: the newest dated
    # changelog version always has its links, notes, releases page and pin.
    script = _script()
    assert script.problems(ROOT, f"v{script.version(ROOT)}") == []


def test_version_is_the_newest_dated_heading_not_unreleased(repo: Path) -> None:
    assert _script().version(repo) == "1.2.0"


def test_a_hyphen_dated_heading_counts(repo: Path) -> None:
    _edit(repo / "CHANGELOG.md", "## [1.2.0] — 2026", "## [1.2.0] - 2026")
    assert _script().version(repo) == "1.2.0"


def test_no_dated_heading_is_an_error(repo: Path) -> None:
    script = _script()
    _write(repo / "CHANGELOG.md", "# Changelog\n\n## [Unreleased]\n")
    with pytest.raises(script.ReleaseError, match="no dated version heading"):
        script.version(repo)
    assert script.problems(repo, "v1.2.0") == [
        "CHANGELOG.md has no dated version heading (## [X.Y.Z] — YYYY-MM-DD)"
    ]


def test_a_merged_notes_pr_is_ready(repo: Path) -> None:
    assert _script().problems(repo, "v1.2.0") == []


@pytest.mark.parametrize("tag", ["1.2.0", "v1.2", "v1.2.0-rc1", "development"])
def test_only_a_vxyz_tag_is_released(repo: Path, tag: str) -> None:
    assert _script().problems(repo, tag) == [f"{tag!r} is not a release tag (vX.Y.Z)"]


def test_releasing_a_version_the_changelog_has_not_reached(repo: Path) -> None:
    found = _script().problems(repo, "v1.3.0")
    assert found[0].startswith("CHANGELOG.md's newest version is 1.2.0, not 1.3.0")
    assert any("v1.3.0.md is missing" in problem for problem in found)
    assert "docs/usage/releases.md starts with 1.2.0, not 1.3.0" in found
    assert "README.md pins opentide==1.2.0, not 1.3.0" in found


def test_each_missing_piece_of_the_notes_pr_is_named(repo: Path) -> None:
    _edit(repo / "CHANGELOG.md", "## [Unreleased]\n\n", "")
    _edit(repo / "CHANGELOG.md", "compare/v1.2.0...HEAD", "compare/v1.1.0...HEAD")
    (repo / ".github" / "release-notes" / "v1.2.0.md").write_text("  \n", encoding="utf-8")
    _edit(repo / "README.md", "1.2.0", "1.1.0")
    assert _script().problems(repo, "v1.2.0") == [
        "CHANGELOG.md has no ## [Unreleased] heading above the release",
        f"CHANGELOG.md lacks the link [Unreleased]: {REPOSITORY}/compare/v1.2.0...HEAD",
        ".github/release-notes/v1.2.0.md is missing or empty: the Release body",
        "README.md pins opentide==1.1.0, not 1.2.0",
    ]


def test_a_readme_with_two_pins_is_refused(repo: Path) -> None:
    _write(repo / "README.md", "opentide==1.2.0\nopentide==1.1.0\n")
    assert _script().problems(repo, "v1.2.0") == [
        "README.md pins opentide==1.1.0, 1.2.0, not 1.2.0"
    ]


def test_main_prints_the_version_and_the_verdict(
    repo: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    script = _script()
    monkeypatch.setattr(script, "ROOT", repo)
    assert script.main(["version"]) == 0
    assert capsys.readouterr().out == "1.2.0\n"
    assert script.main(["check", "v1.2.0"]) == 0
    assert capsys.readouterr().out == "v1.2.0 is ready to release\n"
    assert script.main(["check", "v1.3.0"]) == 1
    assert "error: CHANGELOG.md's newest version is 1.2.0" in capsys.readouterr().err


def test_main_reports_a_missing_file(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    script = _script()
    monkeypatch.setattr(script, "ROOT", tmp_path)
    assert script.main(["version"]) == 1
    assert "CHANGELOG.md" in capsys.readouterr().err


def test_the_script_runs_with_the_standard_library_only() -> None:
    # The guard runs it with the runner's Python, before anything is installed.
    source = (ROOT / "scripts" / "build" / "release.py").read_text(encoding="utf-8")
    imports = {
        line.split()[1].split(".")[0]
        for line in source.splitlines()
        if line.startswith(("import ", "from "))
    }
    assert imports <= {"__future__", "argparse", "re", "sys", "pathlib"}


# --- Release candidates and Release bodies (the release train, #840) ----------


def test_a_candidate_is_of_a_version_newer_than_the_last_release(repo: Path) -> None:
    script = _script()
    assert script.candidate_problems(repo, "v1.3.0-rc.1") == []
    assert script.candidate_problems(repo, "v1.2.10-rc.2") == []
    (problem,) = script.candidate_problems(repo, "v1.2.0-rc.1")
    assert "1.2.0 is not newer than 1.2.0" in problem
    assert "release.py bump" in problem
    assert script.candidate_problems(repo, "v1.1.9-rc.1")
    for tag in ("v1.3.0", "v1.3.0-rc.0", "engine-v1.3.0-rc.1"):
        assert script.candidate_problems(repo, tag) == [
            f"{tag!r} is not a release candidate tag (vX.Y.Z-rc.N)"
        ]


def test_a_candidate_needs_the_unreleased_heading(repo: Path) -> None:
    _edit(repo / "CHANGELOG.md", "## [Unreleased]\n", "")
    problems = _script().candidate_problems(repo, "v1.3.0-rc.1")
    assert problems == [
        "CHANGELOG.md has no ## [Unreleased] heading, which a candidate's notes quote"
    ]


def test_a_releases_notes_are_the_notes_prs_file(repo: Path) -> None:
    script = _script()
    assert script.notes(repo, "v1.2.0") == "# 1.2.0\n"
    with pytest.raises(script.ReleaseError, match=r"v1\.3\.0\.md is missing"):
        script.notes(repo, "v1.3.0")
    with pytest.raises(script.ReleaseError, match="not a release tag"):
        script.notes(repo, "engine-v1.2.0")


def test_a_candidates_notes_quote_unreleased(repo: Path) -> None:
    fixed = "## [Unreleased]\n\n### Fixed\n\n- **A fix.**\n"
    _edit(repo / "CHANGELOG.md", "## [Unreleased]\n", fixed)
    notes = _script().notes(repo, "v1.3.0-rc.2")
    assert notes.startswith("Release candidate 2 of 1.3.0, for testing")
    assert "TestPyPI" in notes and "`next`" in notes
    assert "- **A fix.**" in notes
    # Nothing of the released version leaks in.
    assert "Minor." not in notes


def test_the_cli_prints_a_candidates_notes(repo: Path, capsys: pytest.CaptureFixture[str]) -> None:
    script = _script()
    script.ROOT = repo
    assert script.main(["notes", "v1.3.0-rc.1"]) == 0
    assert capsys.readouterr().out.startswith("Release candidate 1 of 1.3.0")
    assert script.main(["check-candidate", "v1.3.0-rc.1"]) == 0
    assert script.main(["check-candidate", "v1.2.0-rc.1"]) == 1
