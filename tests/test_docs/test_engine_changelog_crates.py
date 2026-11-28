"""``crates/CHANGELOG.md`` groups each release's entries by crate, from 1.0.0 on.

opentide.org renders each opentide version's ``crates/CHANGELOG.md`` section under
the release (opentidehq/website#79) and groups it per crate by its ``####``
headings: under each ``### <Category>``, every entry sits under a
``#### `<crate>``` heading naming a crate the workspace publishes, or under
``#### Across crates`` (the engine-release-notes skill, "Groups").
"""

from __future__ import annotations

import re
import sys
from pathlib import Path

if sys.version_info >= (3, 11):
    import tomllib
else:  # pragma: no cover - Python 3.10
    import tomli as tomllib

ROOT = Path(__file__).resolve().parents[2]
CHANGELOG = ROOT / "crates" / "CHANGELOG.md"

#: The first release grouped by crate: older sections are history, left as they shipped.
FIRST_GROUPED = (1, 0, 0)
ACROSS = "Across crates"

_DATED = re.compile(r"^## \[(\d+)\.(\d+)\.(\d+)\] [-—] \d{4}-\d{2}-\d{2}\s*$")
_CRATE = re.compile(r"^#### `([a-z0-9_-]+)`$")


def published_crates(root: Path = ROOT) -> set[str]:
    """The workspace's crates that reach crates.io: every member without ``publish = false``."""
    workspace = tomllib.loads((root / "Cargo.toml").read_text(encoding="utf-8"))
    names: set[str] = set()
    for member in workspace["workspace"]["members"]:
        manifest = tomllib.loads((root / member / "Cargo.toml").read_text(encoding="utf-8"))
        package = manifest["package"]
        if package.get("publish", True) is not False:
            names.add(package["name"])
    return names


def heading_problems(changelog: str, published: set[str]) -> list[str]:
    """What breaks the per-crate grouping in the dated sections from 1.0.0 on."""
    problems: list[str] = []
    section: str | None = None
    category: str | None = None
    grouped = False
    for number, line in enumerate(changelog.splitlines(), start=1):
        if line.startswith("## "):
            match = _DATED.match(line)
            section = line if match and tuple(map(int, match.groups())) >= FIRST_GROUPED else None
            category = None
            continue
        if section is None:
            continue
        if line.startswith("### "):
            category, grouped = line, False
            continue
        if category is None:
            continue
        if line.startswith("#### "):
            grouped = True
            crate = _CRATE.match(line)
            if line != f"#### {ACROSS}" and (crate is None or crate.group(1) not in published):
                problems.append(
                    f"line {number}: {section} {category}: {line!r} names no published crate "
                    f"(#### `<crate>` or #### {ACROSS})"
                )
        elif line.startswith("#"):
            problems.append(f"line {number}: {section} {category}: {line!r} nests deeper than ####")
        elif line.strip() and not grouped:
            problems.append(
                f"line {number}: {section} {category}: text before its first #### crate "
                f"heading: {line[:80]!r}"
            )
    return problems


def test_the_published_crates_are_the_workspace_less_publish_false() -> None:
    published = published_crates()
    assert {"opentide", "opentide-lsp", "opentide-core"} <= published
    assert not {"xtask", "opentide-wasm", "opentide-cassette"} & published


def test_each_category_from_1_0_0_groups_its_entries_under_crate_headings() -> None:
    changelog = CHANGELOG.read_text(encoding="utf-8")
    assert "## [1.0.0] - " in changelog
    problems = heading_problems(changelog, published_crates())
    assert not problems, "\n".join(problems)


_PUBLISHED = {"opentide", "opentide-lsp"}


def _release(body: str, version: str = "1.0.0") -> str:
    return f"# Changelog\n\n## [Unreleased]\n\n## [{version}] - 2026-11-25\n\nSummary.\n\n{body}"


def test_crate_and_across_crates_headings_pass() -> None:
    body = (
        "### Added\n\n#### `opentide-lsp`\n\n- **A.** a.\n  - nested\n\n"
        "#### Across crates\n\n- **B.** b.\n\n### Fixed\n\n#### `opentide`\n\n- **C.** c.\n"
    )
    assert heading_problems(_release(body), _PUBLISHED) == []


def test_an_entry_outside_a_crate_heading_is_refused() -> None:
    body = "### Fixed\n\n- **A.** a.\n\n#### `opentide`\n\n- **B.** b.\n"
    (problem,) = heading_problems(_release(body), _PUBLISHED)
    assert "### Fixed: text before its first #### crate heading" in problem


def test_a_theme_or_unpublished_heading_is_refused() -> None:
    body = (
        "### Added\n\n#### Problems\n\n- **A.** a.\n\n#### `opentide-wasm`\n\n- **B.** b.\n\n"
        "#### opentide-lsp\n\n- **C.** c.\n"
    )
    problems = heading_problems(_release(body), _PUBLISHED)
    assert [p.split(": ")[2] for p in problems] == [
        "'#### Problems' names no published crate (#### `<crate>` or #### Across crates)",
        "'#### `opentide-wasm`' names no published crate (#### `<crate>` or #### Across crates)",
        "'#### opentide-lsp' names no published crate (#### `<crate>` or #### Across crates)",
    ]


def test_unreleased_and_sections_before_1_0_0_are_not_held() -> None:
    old = "## [0.16.1] - 2026-11-13\n\n### Added\n\n- **Old.** o.\n"
    text = "# Changelog\n\n## [Unreleased]\n\n### Added\n\n- **New.** n.\n\n" + old
    assert heading_problems(text, _PUBLISHED) == []
