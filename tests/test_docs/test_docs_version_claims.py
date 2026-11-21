"""The docs must name ONE current release, and it must be the newest one.

Issue #406: through 0.7.0 the docs home and the installation page advertised
0.6.1 as the latest release while their own install block pinned 0.7.0 -- a
reader following the prose installed a version the same page told them not to.
It regressed silently through 0.13.0, which shipped with four pages naming
0.12.1 beside ``pip install 'opentide==0.14.0'``, because the release runbook
tests cover the release *commands* and nothing covered the version *claims*.

``CHANGELOG.md`` is the authoritative in-repo source for the released
version: the newest released changelog heading is the statement of record
(the Cargo workspace's version, which the package takes, is the next one's
between releases).
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
#: A pre-release pin (``opentide==1.0.0rc1``, ``1.0.0-rc.1``, ``1.0.0.dev3``) names a
#: candidate, which the installation page documents beside the release: it is not one.
_PINNED_INSTALL = re.compile(r"opentide==(\d+\.\d+\.\d+)(?![0-9A-Za-z]|[.-][0-9A-Za-z])")
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


@pytest.mark.parametrize(
    ("text", "pins"),
    [
        ("pip install 'opentide==0.28.1'", ["0.28.1"]),
        ("opentide==0.28.1.", ["0.28.1"]),
        ("pip install opentide==1.0.0rc1", []),
        ("pip install 'opentide==1.0.0-rc.1'", []),
        ("opentide==1.0.0.dev3 and opentide==1.0.0a2", []),
        ("opentide==1.0.0b4", []),
    ],
)
def test_a_pre_release_pin_is_not_a_release_pin(text: str, pins: list[str]) -> None:
    """The installation page documents the candidate's pins beside the release's."""
    assert _PINNED_INSTALL.findall(text) == pins


def test_the_installation_page_documents_the_release_candidate() -> None:
    """RC1-4: PyPI's ``--pre``, the crates, the installer and how to verify it."""
    page = (DOCS / "usage" / "installation.md").read_text(encoding="utf-8")
    for text in (
        "pip install --pre opentide",
        "opentide-installer.sh",
        "SHA256SUMS",
        "gh attestation verify",
    ):
        assert text in page, text
    # The current candidate's pins, whichever candidate that is: each candidate
    # moves them (release-management skill, "Known locations").
    pypi = re.search(r"opentide==1\.0\.0rc(\d+)", page)
    assert pypi, "no opentide==1.0.0rcN pin"
    n = pypi.group(1)
    assert f"cargo install opentide --version 1.0.0-rc.{n} --features cli" in page
    assert f"releases/download/v1.0.0-rc.{n}/opentide-installer.sh" in page


#: Pages that document the 1.0 API and the Rust core's behaviour. 0.28.1, which
#: `pip install opentide` installs, has neither (no `opentide.Workspace`), so while 1.0 is
#: a candidate each one says how to install the candidate (RC2-5).
_PAGES_OF_THE_CANDIDATE = (
    "index.md",
    "cli/index.md",
    "mcp/index.md",
    "mcp/installation.md",
    "sdk/installation.md",
)


def _candidate() -> str | None:
    """The current candidate's number in `docs/usage/installation.md`, if it has one."""
    page = (DOCS / "usage" / "installation.md").read_text(encoding="utf-8")
    pin = re.search(r"opentide==1\.0\.0rc(\d+)", page)
    return pin.group(1) if pin else None


@pytest.mark.parametrize("name", _PAGES_OF_THE_CANDIDATE)
def test_a_page_of_the_1_0_api_installs_the_candidate(name: str) -> None:
    """RC2-5: no page of 1.0 sends a reader to a stable pin that lacks what it documents."""
    candidate = _candidate()
    page = (DOCS / name).read_text(encoding="utf-8")
    if candidate is None:
        # The final release: the page installs the release and names no candidate:
        # no `--pre`, no candidate pin, no link to the Release candidates section,
        # and none of the prose that says `pip install opentide` still gives 0.28.1
        # (it has no pin, so only these words catch it).
        assert "--pre" not in page, f"docs/{name} still installs with --pre"
        assert "rc" not in "".join(re.findall(r"opentide==\S+", page)), f"docs/{name} pins a rc"
        assert "#release-candidates" not in page, f"docs/{name} still links the candidates"
        assert "0.28" not in page, f"docs/{name} still names 0.28"
        return
    assert "pip install --pre opentide" in page, f"docs/{name} does not install the candidate"
    assert "usage/installation.md#release-candidates" in page, f"docs/{name} does not link it"
    pins = re.findall(r"opentide==1\.0\.0rc(\d+)", page)
    assert set(pins) <= {candidate}, f"docs/{name} pins rc{set(pins)}, not rc{candidate}"
    assert "opentide==0.28" not in page


def test_every_candidate_pin_names_the_current_candidate() -> None:
    """Each candidate moves every `opentide==1.0.0rcN` pin together (release-management)."""
    candidate = _candidate()
    stale = [
        f"{page.relative_to(ROOT)} pins rc{n}"
        for page in _pages()
        for n in re.findall(r"opentide==1\.0\.0rc(\d+)", page.read_text(encoding="utf-8"))
        if n != candidate and page != DOCS / "usage" / "releases.md"
    ]
    assert not stale, f"docs pin a candidate other than rc{candidate}: {stale}"
