"""README.md is the PyPI project page: it must read correctly away from the repository.

PyPI renders the README of the release, so a relative link (`CHANGELOG.md`, `docs/`) is
a dead link there, and an install line that only knows the last stable pin leaves a
release candidate's page without a way to install the candidate.
"""

from __future__ import annotations

import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
README = ROOT / "README.md"

_LINK = re.compile(r"\]\(([^)\s]+)\)")
_ABSOLUTE = ("https://", "http://", "mailto:")


def _text() -> str:
    return README.read_text(encoding="utf-8")


def test_every_link_is_absolute() -> None:
    relative = [target for target in _LINK.findall(_text()) if not target.startswith(_ABSOLUTE)]
    assert relative == [], f"README.md has links PyPI cannot resolve: {relative}"


def test_repository_links_point_at_trunk() -> None:
    blobs = [
        target
        for target in _LINK.findall(_text())
        if target.startswith("https://github.com/opentidehq/opentide/") and "/blob/" in target
    ]
    assert blobs, "README.md links no repository file"
    for target in blobs:
        assert "/blob/development/" in target, target


def test_install_names_the_candidates_flag_as_well_as_the_stable_pin() -> None:
    text = _text()
    assert "pip install --pre opentide" in text
    assert "uv pip install --prerelease=allow opentide" in text
    # An exact candidate pin would read as 1.0.0 to the release guard's pin check.
    assert not re.search(r"opentide==\d+\.\d+\.\d+rc", text)
