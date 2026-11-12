"""``release.py``: the version to release, and whether its notes PR has merged.

``publish.yml``, the release train, releases from "Run workflow" on
``development``, as language-server's Release workflow did from ``main``: the
workflow builds the version the changelog names, creates its tag with the
GitHub Release, and publishes it everywhere. opentide's Python version is the
git tag's (hatch-vcs), so before the tag exists the newest dated
``CHANGELOG.md`` heading is the only statement of the version in the tree::

    uv run python scripts/build/release.py version                  # 0.24.0
    uv run python scripts/build/release.py check v0.24.0            # the notes PR merged
    uv run python scripts/build/release.py check-candidate v0.25.0-rc.1
    uv run python scripts/build/release.py notes v0.24.0            # the Release body

``check`` refuses a release whose Step 1 (the release-management skill) is
missing: the changelog section and its links, the GitHub Release notes file,
the Usage → Releases section and the README install pin. That every docs page
pins the same version is ``tests/test_docs/test_docs_version_claims.py``'s job.
The crates and npm packages carry the same version: ``scripts/engine/release.py
lockstep`` checks them, and the workflow runs both.

``check-candidate`` refuses a release candidate (``vX.Y.Z-rc.N``) of a version
that is not newer than the last release. A candidate needs no notes PR: its
GitHub pre-release says what ``## [Unreleased]`` holds (``notes``).
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
_CANDIDATE = re.compile(r"v(\d+\.\d+\.\d+)-rc\.([1-9]\d*)")
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


def _section(changelog: str, heading: str) -> str | None:
    """The body of ``## [heading]`` in ``changelog``, up to the next version or the links."""
    match = re.search(
        rf"^## \[{re.escape(heading)}\][^\n]*\n(.*?)(?=^## |^\[[^\]]+\]: |\Z)",
        changelog,
        re.MULTILINE | re.DOTALL,
    )
    return match.group(1).strip() if match else None


def _key(version: str) -> tuple[int, ...]:
    return tuple(int(part) for part in version.split("."))


def candidate_problems(root: Path, tag: str) -> list[str]:
    """What keeps ``tag`` (``vX.Y.Z-rc.N``) from being a release candidate:
    its version must be newer than the newest one ``CHANGELOG.md`` dates."""
    match = _CANDIDATE.fullmatch(tag)
    if match is None:
        return [f"{tag!r} is not a release candidate tag (vX.Y.Z-rc.N)"]
    candidate = match.group(1)
    changelog = (root / "CHANGELOG.md").read_text(encoding="utf-8")
    found: list[str] = []
    try:
        newest = version(root)
    except ReleaseError as exc:
        return [str(exc)]
    if _key(candidate) <= _key(newest):
        found.append(
            f"{candidate} is not newer than {newest}, the last release: "
            "bump the workspace version first (scripts/engine/release.py bump X.Y.Z)"
        )
    if _section(changelog, "Unreleased") is None:
        found.append("CHANGELOG.md has no ## [Unreleased] heading, which a candidate's notes quote")
    return found


def notes(root: Path, tag: str) -> str:
    """The GitHub Release body of ``tag``: a release's is the file its notes PR
    wrote; a candidate's says what it is, then quotes ``## [Unreleased]``."""
    if match := _CANDIDATE.fullmatch(tag):
        changelog = (root / "CHANGELOG.md").read_text(encoding="utf-8")
        unreleased = _section(changelog, "Unreleased") or "Nothing is listed under [Unreleased]."
        return (
            f"Release candidate {match.group(2)} of {match.group(1)}, for testing: "
            "on TestPyPI, and on npm under the dist-tag `next`. "
            f"What it holds so far, from CHANGELOG.md's [Unreleased]:\n\n{unreleased}\n"
        )
    if _TAG.fullmatch(tag) is None:
        raise ReleaseError(f"{tag!r} is not a release tag (vX.Y.Z or vX.Y.Z-rc.N)")
    path = root / ".github" / "release-notes" / f"{tag}.md"
    if not path.is_file():
        raise ReleaseError(f"{path.relative_to(root).as_posix()} is missing: the Release body")
    return path.read_text(encoding="utf-8")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    commands = parser.add_subparsers(dest="command", required=True)
    commands.add_parser("version", help="print the version CHANGELOG.md releases")
    check = commands.add_parser("check", help="the notes PR for TAG has merged")
    check.add_argument("tag", help="vX.Y.Z")
    candidate = commands.add_parser("check-candidate", help="TAG may be a release candidate")
    candidate.add_argument("tag", help="vX.Y.Z-rc.N")
    body = commands.add_parser("notes", help="print the GitHub Release body of TAG")
    body.add_argument("tag", help="vX.Y.Z or vX.Y.Z-rc.N")
    args = parser.parse_args(argv)
    try:
        if args.command == "version":
            print(version(ROOT))
            return 0
        if args.command == "notes":
            sys.stdout.write(notes(ROOT, args.tag))
            return 0
        if args.command == "check-candidate":
            found = candidate_problems(ROOT, args.tag)
        else:
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
