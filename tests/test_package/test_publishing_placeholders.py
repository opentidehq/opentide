"""The name placeholders in ``publishing/placeholders/`` (UC-0.1, #799).

Each is published once, by hand, and a published version can never be
replaced, so a mistake in one is permanent: the wrong licence, a missing copy
of it (the EUPL asks for one with every copy of the work), a stray file in the
package, or a ``repository.url`` that npm's trusted publishing will not match
with this repository. ``docs/internal/publishing.md`` tells the maintainer what
to publish; these tests keep the manifests, the licence copies and that page in
step.
"""

from __future__ import annotations

import json
import shutil
import subprocess
from pathlib import Path
from typing import Any

import pytest

from opentide.core.files import tomllib

ROOT = Path(__file__).resolve().parents[2]
PLACEHOLDERS = ROOT / "publishing" / "placeholders"
CRATE = PLACEHOLDERS / "crates" / "opentide"
NPM_PACKAGES = {
    "@opentide/opentide": PLACEHOLDERS / "npm" / "opentide-scoped",
    "opentide": PLACEHOLDERS / "npm" / "opentide",
}
PAGE = ROOT / "docs" / "internal" / "publishing.md"
REPOSITORY = "https://github.com/opentidehq/opentide"
LICENCE = "EUPL-1.2"
VERSION = "0.0.0"


def _crate_manifest() -> dict[str, Any]:
    return tomllib.loads((CRATE / "Cargo.toml").read_text(encoding="utf-8"))


def _package_json(directory: Path) -> dict[str, Any]:
    return json.loads((directory / "package.json").read_text(encoding="utf-8"))


def _placeholder_directories() -> list[Path]:
    return [CRATE, *NPM_PACKAGES.values()]


def test_every_placeholder_directory_is_known() -> None:
    # A placeholder added without a test, a dry run and a line in the page.
    found = {path.parent for path in PLACEHOLDERS.glob("*/*/README.md")}
    assert found == set(_placeholder_directories())


@pytest.mark.parametrize("directory", _placeholder_directories(), ids=lambda path: path.name)
def test_each_placeholder_ships_the_repository_licence(directory: Path) -> None:
    # Byte for byte, CRLF included, but for the final newline: the root
    # LICENSE has none, and pre-commit's end-of-file-fixer gives the copies one.
    copy = (directory / "LICENSE").read_bytes()
    assert copy.rstrip(b"\r\n") == (ROOT / "LICENSE").read_bytes().rstrip(b"\r\n")


@pytest.mark.parametrize("directory", _placeholder_directories(), ids=lambda path: path.name)
def test_each_readme_says_the_name_is_reserved_and_points_at_pypi(directory: Path) -> None:
    readme = (directory / "README.md").read_text(encoding="utf-8")
    assert "is reserved" in readme
    assert "https://pypi.org/project/opentide/" in readme
    assert "pip install opentide" in readme


def test_crate_is_the_reserved_opentide_crate() -> None:
    package = _crate_manifest()["package"]
    assert package["name"] == "opentide"
    assert package["version"] == VERSION
    assert package["license"] == LICENCE
    assert package["repository"] == REPOSITORY
    assert package["homepage"] == "https://opentide.org"
    assert "Reserved for the opentide Rust SDK" in package["description"]
    assert package.get("publish", True) is True
    # Shipped files: the licence copy and the README crates.io renders.
    assert package["readme"] == "README.md"
    assert set(package["include"]) == {"/src/**", "/README.md", "/LICENSE"}


def test_crate_is_its_own_workspace() -> None:
    # The repository root gains a Cargo workspace with an explicit member list
    # (UC-0.2); without its own [workspace] table cargo would refuse to build
    # the placeholder as a package outside that list.
    assert _crate_manifest()["workspace"] == {}


def test_crate_forbids_unsafe_code_and_documents_itself() -> None:
    lib = (CRATE / "src" / "lib.rs").read_text(encoding="utf-8")
    assert "#![forbid(unsafe_code)]" in lib
    assert lib.startswith("//! # opentide\n")
    assert _crate_manifest()["lints"]["rust"] == {"unsafe_code": "forbid", "missing_docs": "deny"}


def test_crate_lockfile_is_committed() -> None:
    # `cargo publish --locked` (the dry run, and the maintainer's publish)
    # needs it, and an untracked one makes cargo refuse a dirty tree.
    lock = tomllib.loads((CRATE / "Cargo.lock").read_text(encoding="utf-8"))
    assert lock["package"] == [{"name": "opentide", "version": VERSION}]


def test_crate_build_output_stays_out_of_the_sdist() -> None:
    """hatchling reads the root ``.gitignore`` only. Ignored by a ``.gitignore`` in the
    placeholder, the ``target/`` a local dry run leaves went into the next sdist."""
    if shutil.which("git") is None or not (ROOT / ".git").exists():
        pytest.skip("not a git checkout")
    built = CRATE.relative_to(ROOT) / "target" / "debug" / "libopentide.rlib"
    result = subprocess.run(
        ["git", "check-ignore", "--no-index", "--verbose", built.as_posix()],
        cwd=ROOT,
        capture_output=True,
        text=True,
        check=False,
    )
    assert result.returncode == 0, result.stdout + result.stderr
    assert result.stdout.split(":", 1)[0] == ".gitignore"


@pytest.mark.parametrize(("name", "directory"), sorted(NPM_PACKAGES.items()))
def test_npm_placeholder_manifest(name: str, directory: Path) -> None:
    manifest = _package_json(directory)
    assert manifest["name"] == name
    assert manifest["version"] == VERSION
    assert manifest["license"] == LICENCE
    assert manifest["homepage"] == "https://opentide.org"
    assert manifest["publishConfig"] == {"access": "public", "provenance": True}
    assert manifest["files"] == ["README.md", "LICENSE"]
    # No code, no install-time scripts, nothing to resolve.
    for key in ("main", "bin", "exports", "scripts", "dependencies"):
        assert key not in manifest, key


@pytest.mark.parametrize(("name", "directory"), sorted(NPM_PACKAGES.items()))
def test_npm_repository_matches_this_repository(name: str, directory: Path) -> None:
    # npm's trusted publishing compares repository.url with the repository the
    # workflow runs in; `directory` makes the npm page link to the sources.
    repository = _package_json(directory)["repository"]
    assert repository == {
        "type": "git",
        "url": f"git+{REPOSITORY}.git",
        "directory": directory.relative_to(ROOT).as_posix(),
    }, name


def test_publishing_page_names_every_placeholder() -> None:
    page = PAGE.read_text(encoding="utf-8")
    assert f"`opentide` {VERSION} on crates.io" in page
    for name in NPM_PACKAGES:
        assert f"`{name}@{VERSION}` on npm" in page
    for directory in _placeholder_directories():
        assert f"(../../{directory.relative_to(ROOT).as_posix()}/)" in page


def test_publishing_page_is_in_the_internal_navigation() -> None:
    meta = json.loads((PAGE.parent / "meta.json").read_text(encoding="utf-8"))
    assert "publishing" in meta["pages"]
