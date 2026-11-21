#!/usr/bin/env python3
"""Fail when a built artifact carries a marker string in plain text (#1743).

Antivirus heuristics read the words of the embedded security datasets as the binary's own. The
datasets are compressed at build time (opentide-dataset), so none of these strings may appear in
any artifact: a PE, an ELF, a `.pyd` or `.so`, a `.wasm`, a wheel, an sdist, a `.vsix`. A new
dataset, or a build that stores one loose again, shows here before it is published.

    markers.py PATH...        a file, or a directory searched recursively

Archives (zip, wheel, vsix, tar.gz, crate) are read member by member, nested archives too. A marker
is matched ignoring ASCII case, as the antivirus rules match it, in its single-byte form and as
UTF-16LE (a Windows wide string). Exit status: 0 clean, 1 a marker found, 2 nothing to scan or an
unreadable path.
"""

from __future__ import annotations

import io
import sys
import tarfile
import zipfile
from collections.abc import Iterator
from dataclasses import dataclass
from pathlib import Path

#: One string per class the issue names: a miner pool, a credential-dumping module, a browser
#: credential store, a PowerShell offensive tool, a Log4Shell exploit string.
MARKERS: tuple[str, ...] = (
    "moneropool",
    "sekurlsa",
    "Login Data",
    "Invoke-Mimikatz",
    "jndi:ldap",
)

#: How deep archives nest (a wheel holding a zip holding the artifact).
MAX_DEPTH = 4

ZIP_SUFFIXES = (".zip", ".whl", ".vsix", ".jar", ".nupkg", ".sigzip")
TAR_SUFFIXES = (".tar.gz", ".tgz", ".crate", ".tar")

#: A source distribution (the sdist, a `.crate`) carries the datasets as the TOML and JSON sources
#: the build compresses, and the tests' own sources (a detection test names the techniques it
#: detects): a sdist builds wherever a Rust toolchain is installed, and its build scripts read them.
#: Inside a `.tar.gz` or `.crate`, text source files (`SOURCE_TEXT`) and everything under
#: `SOURCE_DATA` are exempt; every compiled artifact, and every binary member of a source
#: distribution, is held to the markers. (A source tree is not what antivirus engines flagged: the
#: Windows PE and `.pyd` were built from the same files.)
SOURCE_DATA = (
    "/data/catalogs/",
    "/src/opentide/data/",
    "/highlights/",
    "/assets/",
    "/crates/testdata/",
    "/tests/",
)
SOURCE_TEXT = frozenset(
    {".rs", ".toml", ".json", ".md", ".py", ".yml", ".yaml", ".txt", ".lock", ".kql", ".spl",
     ".yar", ".yara", ".yaral", ".yl2", ".exabeam", ".cql", ".eql", ".esql", ".ps1", ".sh", ".snap"}
)  # fmt: skip
SOURCE_SUFFIXES = (".tar.gz", ".crate")


def is_source_member(archive: str, member: str) -> bool:
    """Whether `member` of the archive named `archive` is source text of a source distribution."""
    if not archive.lower().endswith(SOURCE_SUFFIXES):
        return False
    path = f"/{member}"
    return any(part in path for part in SOURCE_DATA) or Path(member).suffix.lower() in SOURCE_TEXT


@dataclass(frozen=True)
class Hit:
    """A marker found in `where` (a path, and `!member` for each archive entered)."""

    where: str
    marker: str
    form: str  # "ascii" or "utf-16le"
    offset: int


def _variants(marker: str) -> list[tuple[str, bytes]]:
    lowered = marker.lower()
    return [("ascii", lowered.encode("ascii")), ("utf-16le", lowered.encode("utf-16-le"))]


_NEEDLES = [(marker, form, needle) for marker in MARKERS for form, needle in _variants(marker)]


def scan_bytes(data: bytes, where: str) -> list[Hit]:
    """The markers in `data`, ignoring ASCII case (one pass over a lowered copy)."""
    lowered = data.lower()  # bytes.lower() folds ASCII letters only, which is what the rules match
    hits = []
    for marker, form, needle in _NEEDLES:
        offset = lowered.find(needle)
        if offset >= 0:
            hits.append(Hit(where, marker, form, offset))
    return hits


def _is_zip(name: str, data: bytes) -> bool:
    return name.lower().endswith(ZIP_SUFFIXES) or data[:4] == b"PK\x03\x04"


def _is_tar(name: str) -> bool:
    return name.lower().endswith(TAR_SUFFIXES)


def scan_blob(name: str, data: bytes, where: str, depth: int = 0) -> Iterator[Hit]:
    """The hits in one file's bytes and, when it is an archive, in each member's."""
    yield from scan_bytes(data, where)
    if depth >= MAX_DEPTH:
        return
    if _is_zip(name, data):
        try:
            with zipfile.ZipFile(io.BytesIO(data)) as archive:
                for member in archive.infolist():
                    if not member.is_dir():
                        yield from scan_blob(
                            member.filename,
                            archive.read(member),
                            f"{where}!{member.filename}",
                            depth + 1,
                        )
        except zipfile.BadZipFile:
            pass  # not an archive after all; its bytes were scanned above
    elif _is_tar(name):
        try:
            with tarfile.open(fileobj=io.BytesIO(data)) as archive:
                for member in archive:
                    if is_source_member(name, member.name):
                        continue
                    extracted = archive.extractfile(member) if member.isfile() else None
                    if extracted is not None:
                        yield from scan_blob(
                            member.name,
                            extracted.read(),
                            f"{where}!{member.name}",
                            depth + 1,
                        )
        except tarfile.TarError:
            pass


def scan_path(path: Path) -> Iterator[Hit]:
    """The hits in a file, or in every file under a directory."""
    if path.is_dir():
        for child in sorted(path.rglob("*")):
            if child.is_file():
                yield from scan_blob(child.name, child.read_bytes(), str(child))
    else:
        yield from scan_blob(path.name, path.read_bytes(), str(path))


def main(argv: list[str]) -> int:
    paths = [Path(a) for a in argv]
    if not paths:
        print(__doc__, file=sys.stderr)
        return 2
    missing = [p for p in paths if not p.exists()]
    if missing:
        print("markers: no such path: " + ", ".join(map(str, missing)), file=sys.stderr)
        return 2
    scanned = 0
    hits: list[Hit] = []
    for path in paths:
        files = [path] if path.is_file() else [c for c in sorted(path.rglob("*")) if c.is_file()]
        for child in files:
            scanned += 1
            hits.extend(scan_blob(child.name, child.read_bytes(), str(child)))
    if scanned == 0:
        print("markers: nothing to scan", file=sys.stderr)
        return 2
    for hit in hits:
        print(f"marker {hit.marker!r} ({hit.form}) at byte {hit.offset} of {hit.where}")
    print(f"markers: {scanned} file(s) scanned, {len(hits)} marker(s) found")
    return 1 if hits else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
