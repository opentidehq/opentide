"""``CHANGELOG.md``'s released sections are history: they never change.

integration/unified-core merges ``development`` (0.24.0 to 0.28.0 at M0), and
a merge resolution once copied six ``[Unreleased]`` entries of the Rust core
into four released sections (0.21.0, 0.17.0, 0.16.0, 0.15.0), where 0.28.0's
text has none of them. Released sections must read as development released
them; an entry belongs to one version.
"""

from __future__ import annotations

import re
import subprocess
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
CHANGELOG = ROOT / "CHANGELOG.md"

#: The newest release merged from development, and the development commit merged last.
MERGED_RELEASE = "0.28.1"
MERGED_COMMIT = "164450afcc1b81a9c3e39a0bc5f3ee0fb0d3b54b"

_SECTION = re.compile(r"\n(?=## \[)")


def _sections(text: str) -> list[str]:
    """The ``## [...]`` sections of a changelog, without the preamble."""
    return _SECTION.split(text)[1:]


def _released_from(text: str, version: str) -> str:
    """The text from ``## [version]`` to the end: that release and every older one."""
    start = text.find(f"\n## [{version}]")
    assert start >= 0, f"CHANGELOG.md has no [{version}] section"
    return text[start:]


def _repeated_entries(text: str) -> list[str]:
    """Each entry (``- **Lead** …``) of *text* that an earlier section already has."""
    seen: dict[str, str] = {}
    repeated: list[str] = []
    for section in _sections(text):
        heading = section.split("\n", 1)[0]
        for line in section.splitlines():
            if not line.startswith("- **"):
                continue
            if line in seen:
                repeated.append(f"{heading} repeats an entry of {seen[line]}: {line[:80]}")
            else:
                seen[line] = heading
    return repeated


def test_no_entry_appears_in_two_sections() -> None:
    repeated = _repeated_entries(CHANGELOG.read_text(encoding="utf-8"))
    assert not repeated, "\n".join(repeated)


def test_the_duplication_check_catches_a_copied_entry() -> None:
    entry = "- **An entry** ([#1](https://example.invalid))."
    text = f"# Changelog\n\n## [Unreleased]\n\n{entry}\n\n## [0.1.0] — 2026-01-01\n\n{entry}\n"
    assert _repeated_entries(text) == [
        f"## [0.1.0] — 2026-01-01 repeats an entry of ## [Unreleased]: {entry}"
    ]


def _merged_changelog() -> str | None:
    """``CHANGELOG.md`` at the merged release's commit, or None in a checkout without it."""
    result = subprocess.run(
        ["git", "show", f"{MERGED_COMMIT}:CHANGELOG.md"],
        cwd=ROOT,
        capture_output=True,
        text=True,
        encoding="utf-8",
        check=False,
    )
    return result.stdout if result.returncode == 0 else None


def test_released_sections_read_as_development_released_them() -> None:
    merged = _merged_changelog()
    if merged is None:
        pytest.skip(f"{MERGED_COMMIT[:9]} is not in this checkout (a shallow clone)")
    ours = CHANGELOG.read_text(encoding="utf-8")
    assert _released_from(ours, MERGED_RELEASE) == _released_from(merged, MERGED_RELEASE)
