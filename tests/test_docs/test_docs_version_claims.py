"""The docs must name ONE current release, and it must be the newest one.

Issue #406: through 0.7.0 the docs home and the installation page advertised
0.6.1 as the latest release while their own install block pinned 0.7.0 -- a
reader following the prose installed a version the same page told them not to.
It regressed silently through 0.13.0, which shipped with four pages naming
0.12.1 beside ``pip install 'opentide==0.14.0'``, because the release runbook
tests cover the release *commands* and nothing covered the version *claims*.

``CHANGELOG.md`` is the authoritative in-repo source: the package version is
derived from the git tag by hatch-vcs, so at test time the newest released
changelog heading is the only statement of record that exists in the tree.
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
CHANGELOG = ROOT / "CHANGELOG.md"
DOCS = ROOT / "docs"

#: ``## [0.14.0] - 2026-10-14``, skipping the ``[Unreleased]`` heading.
_RELEASE_HEADING = re.compile(r"^##\s+\[(\d+\.\d+\.\d+)\]\s+[-\u2014]\s+(\d{4}-\d{2}-\d{2})\s*$")
#: ``The latest release is **0.14.0**`` and its linked ``**[0.14.0](...)**`` form.
_LATEST_CLAIM = re.compile(r"latest release is \*\*\[?(\d+\.\d+\.\d+)")
#: Any pinned install, in prose or a fenced block: ``pip install 'opentide==0.14.0'``.
_PINNED_INSTALL = re.compile(r"opentide==(\d+\.\d+\.\d+)")
#: ``[0.14.0 on PyPI](https://pypi.org/project/opentide/0.14.0/)``
_PYPI_LINK = re.compile(r"pypi\.org/project/opentide/(\d+\.\d+\.\d+)")


def _current_release() -> tuple[str, str]:
    """The newest released version and its date, from the changelog."""
    for line in CHANGELOG.read_text(encoding="utf-8").splitlines():
        if match := _RELEASE_HEADING.match(line):
            return match.group(1), match.group(2)
    pytest.fail(f"no released version heading in {CHANGELOG}")


def _pages() -> list[Path]:
    """User-facing documentation pages.

    ``docs/internal`` is excluded: those are maintainer runbooks that cite past
    versions deliberately -- a 0.1.0 verification example, a 0.1.8 CDN-delay
    incident -- and rewriting them to the current release would destroy the
    record they exist to keep.
    """
    internal = DOCS / "internal"
    return sorted(page for page in DOCS.rglob("*.md") if internal not in page.parents)


def _claims(pattern: re.Pattern[str]) -> list[tuple[Path, str]]:
    return [
        (page, version)
        for page in _pages()
        for version in pattern.findall(page.read_text(encoding="utf-8"))
    ]


def test_changelog_has_a_released_version() -> None:
    version, date = _current_release()
    assert version
    assert date


def test_no_page_advertises_a_stale_latest_release() -> None:
    """A 'latest release is X' claim must name the newest changelog release."""
    version, _ = _current_release()
    stale = [
        f"{page.relative_to(ROOT)} says {claimed}"
        for page, claimed in _claims(_LATEST_CLAIM)
        if claimed != version
    ]
    assert not stale, f"docs advertise a release other than {version}: {stale}"


def test_the_release_claim_exists_somewhere() -> None:
    """Guard the guard: a renamed sentence must not silently empty this check."""
    assert _claims(_LATEST_CLAIM), (
        "no page states 'latest release is <version>' any more -- if the wording "
        "changed, update _LATEST_CLAIM so the #406 check keeps measuring something"
    )


def test_every_pinned_install_names_the_current_release() -> None:
    """A reader copying any pinned install must get the release being documented.

    The per-version sections of ``docs/usage/releases.md`` are a record of what
    shipped and must keep their own pins, so only its newest entry is checked,
    via the page's first pin. ``.github/release-notes`` is out of scope for the
    same reason, and ``docs/internal`` is excluded by :func:`_pages`.
    """
    version, _ = _current_release()
    releases_page = DOCS / "usage" / "releases.md"
    stale: list[str] = []
    for page in _pages():
        pins = _PINNED_INSTALL.findall(page.read_text(encoding="utf-8"))
        checked = pins[:1] if page == releases_page else pins
        stale += [f"{page.relative_to(ROOT)} pins {pin}" for pin in checked if pin != version]
    assert not stale, f"docs pin a version other than {version}: {stale}"


def test_pypi_links_outside_the_release_log_name_the_current_release() -> None:
    version, _ = _current_release()
    releases_page = DOCS / "usage" / "releases.md"
    stale = [
        f"{page.relative_to(ROOT)} links {linked}"
        for page, linked in _claims(_PYPI_LINK)
        if linked != version and page != releases_page
    ]
    assert not stale, f"docs link a PyPI release other than {version}: {stale}"


def test_the_release_log_leads_with_the_current_release() -> None:
    version, date = _current_release()
    page = DOCS / "usage" / "releases.md"
    headings = re.findall(
        r"^##\s+(\d+\.\d+\.\d+)\s+[-\u2014]\s+(.+)$", page.read_text("utf-8"), re.MULTILINE
    )
    assert headings, f"no version headings in {page}"
    assert headings[0][0] == version, (
        f"{page.relative_to(ROOT)} leads with {headings[0][0]}, changelog says {version}"
    )
    day, month, year = headings[0][1].strip().split()
    assert year == date[:4], f"{page.relative_to(ROOT)} dates {version} to {year}, not {date[:4]}"
    assert day.zfill(2) == date[8:10], (
        f"{page.relative_to(ROOT)} dates {version} to {day} {month}, changelog says {date}"
    )
