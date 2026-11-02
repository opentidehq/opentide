"""``release.py``: the version to release, and whether its notes PR has merged.

``publish-pypi.yml`` releases from "Run workflow" on ``development``, as
language-server's Release workflow does from ``main``: the workflow builds the
version the changelog names, creates its tag with the GitHub Release, and
publishes it. opentide's version comes from the git tag (hatch-vcs), so before
the tag exists the newest dated ``CHANGELOG.md`` heading is the only statement
of the version in the tree::

    uv run python scripts/build/release.py version          # 0.20.0
    uv run python scripts/build/release.py check v0.20.0    # the notes PR merged

``check`` refuses a release whose Step 1 (the release-management skill) is
missing: the changelog section and its links, the GitHub Release notes file,
the Usage → Releases section and the README install pin. That every docs page
pins the same version is ``tests/test_docs/test_docs_version_claims.py``'s job.
"""

from __future__ import annotations

import argparse
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
REPOSITORY = "https://github.com/opentidehq/opentide"

#: ``## [0.19.0] — 2026-10-29``; the ``[Unreleased]`` heading does not match.
_RELEASE_HEADING = re.compile(r"^##\s+\[(\d+\.\d+\.\d+)\]\s+[-—]\s+\d{4}-\d{2}-\d{2}\s*$")
_TAG = re.compile(r"v(\d+\.\d+\.\d+)")
_PIN = re.compile(r"opentide==(\d+\.\d+\.\d+)")
#: ``## 0.19.0 — 29 October 2026`` in ``docs/usage/releases.md``.
_RELEASES_HEADING = re.compile(r"^##\s+(\d+\.\d+\.\d+)\b")


class ReleaseError(Exception):
    """The tree does not say which version to release."""


def version(root: Path) -> str:
    """The newest dated version in ``CHANGELOG.md``: the one a release publishes."""
    for line in (root / "CHANGELOG.md").read_text(encoding="utf-8").splitlines():
        if match := _RELEASE_HEADING.match(line):
            return match.group(1)
    raise ReleaseError("CHANGELOG.md has no dated version heading (## [X.Y.Z] — YYYY-MM-DD)")


def problems(root: Path, tag: str) -> list[str]:
    """What keeps ``tag`` from being released from this tree; empty when nothing does."""
    match = _TAG.fullmatch(tag)
    if match is None:
        return [f"{tag!r} is not a release tag (vX.Y.Z)"]
    release = match.group(1)
    found: list[str] = []
    changelog = (root / "CHANGELOG.md").read_text(encoding="utf-8")
    try:
        newest = version(root)
    except ReleaseError as exc:
        return [str(exc)]
    if newest != release:
        found.append(
            f"CHANGELOG.md's newest version is {newest}, not {release}: "
            "merge the notes PR (## [X.Y.Z] — YYYY-MM-DD under ## [Unreleased]) first"
        )
    if not re.search(r"^## \[Unreleased\]\s*$", changelog, re.MULTILINE):
        found.append("CHANGELOG.md has no ## [Unreleased] heading above the release")
    links = {
        f"[Unreleased]: {REPOSITORY}/compare/{tag}...HEAD",
        f"[{release}]: {REPOSITORY}/releases/tag/{tag}",
    }
    for link in sorted(links):
        if not re.search(rf"^{re.escape(link)}\s*$", changelog, re.MULTILINE):
            found.append(f"CHANGELOG.md lacks the link {link}")
    notes = root / ".github" / "release-notes" / f"{tag}.md"
    if not notes.is_file() or not notes.read_text(encoding="utf-8").strip():
        found.append(f"{notes.relative_to(root).as_posix()} is missing or empty: the Release body")
    releases = root / "docs" / "usage" / "releases.md"
    top = next(
        (
            heading.group(1)
            for line in releases.read_text(encoding="utf-8").splitlines()
            if (heading := _RELEASES_HEADING.match(line))
        ),
        None,
    )
    if top != release:
        found.append(f"docs/usage/releases.md starts with {top}, not {release}")
    pins = set(_PIN.findall((root / "README.md").read_text(encoding="utf-8")))
    if pins != {release}:
        found.append(
            f"README.md pins opentide=={', '.join(sorted(pins)) or '(nothing)'}, not {release}"
        )
    return found


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    commands = parser.add_subparsers(dest="command", required=True)
    commands.add_parser("version", help="print the version CHANGELOG.md releases")
    check = commands.add_parser("check", help="the notes PR for TAG has merged")
    check.add_argument("tag", help="vX.Y.Z")
    args = parser.parse_args(argv)
    try:
        if args.command == "version":
            print(version(ROOT))
            return 0
        found = problems(ROOT, args.tag)
    except (OSError, ReleaseError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    for problem in found:
        print(f"error: {problem}", file=sys.stderr)
    if not found:
        print(f"{args.tag} is ready to release")
    return 1 if found else 0


if __name__ == "__main__":
    raise SystemExit(main())
