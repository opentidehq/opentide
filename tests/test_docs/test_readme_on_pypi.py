"""README.md is the PyPI project page: it must read correctly away from the repository.

PyPI renders the README of the release, so a relative link (`CHANGELOG.md`, `docs/`) is
a dead link there, a badge that does not resolve is a broken image on the page, and an
install line that only knows the last stable pin leaves a release candidate's page
without a way to install the candidate.
"""

from __future__ import annotations

import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
README = ROOT / "README.md"

_LINK = re.compile(r"\]\(([^)\s]+)\)")
#: ``![alt](url)`` (a badge or a picture) and ``<img src="url">``.
_IMAGE = re.compile(r"!\[[^\]]*\]\(([^)\s]+)\)|<img\b[^>]*?\bsrc=[\"']([^\"']+)[\"']")
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


#: Endpoints that served a badge once and answer 404 now (RC1-1, RC2-1): the
#: `python-coverage-comment-action-data` branch the coverage action wrote
#: `badge.svg` to no longer exists, and nothing writes it again.
_DEAD_IMAGES = ("python-coverage-comment-action-data",)


def _images() -> list[str]:
    return [url for pair in _IMAGE.findall(_text()) for url in pair if url]


def test_every_image_is_an_absolute_https_url() -> None:
    """PyPI cannot resolve a relative image, and a `http://` one is mixed content."""
    images = _images()
    assert images, "README.md has no badge: the check below would measure nothing"
    bad = [url for url in images if not url.startswith("https://")]
    assert bad == [], f"README.md has images PyPI cannot load: {bad}"


def test_no_image_is_a_known_dead_endpoint() -> None:
    dead = [url for url in _images() if any(pattern in url for pattern in _DEAD_IMAGES)]
    assert dead == [], f"README.md embeds an endpoint that answers 404: {dead}"


def test_a_current_candidate_is_installed_first() -> None:
    """RC2-2: the first install command of a candidate's page installs the candidate.

    While `docs/usage/installation.md` documents a candidate (`opentide==1.0.0rcN`),
    the README's first `pip install` is `pip install --pre opentide`, and the stable pin
    follows in the prose, where `scripts/build/release.py`'s `_PIN` still reads it (it
    ignores pre-release pins, so neither a candidate pin nor `--pre` is one). Without a
    candidate, the page installs the release.
    """
    installation = (ROOT / "docs" / "usage" / "installation.md").read_text(encoding="utf-8")
    first = re.search(r"^\s*(?:uv )?pip install .*$", _text(), re.MULTILINE)
    assert first, "README.md has no install command"
    candidate = re.search(r"opentide==1\.0\.0rc\d+", installation) is not None
    assert ("--pre" in first.group(0)) is candidate, first.group(0)
    assert re.search(r"opentide==\d+\.\d+\.\d+(?![0-9A-Za-z]|[.-][0-9A-Za-z])", _text()), (
        "README.md names no stable pin: the release check (scripts/build/release.py) needs one"
    )
