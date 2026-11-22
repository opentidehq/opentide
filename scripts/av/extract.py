#!/usr/bin/env python3
"""Unpack every archive under a directory, recursively, for scanners that do not open archives.

    extract.py SRC DEST

SRC is a file or a directory of release artifacts. DEST receives a copy of every plain file at its
relative path, and each archive (zip, wheel, vsix, tar.gz, crate, npm tarball) as a directory of its
members next to it (`name.whl.d/`), nested archives too. A member whose path leaves its directory is
refused. Nothing is executed or uploaded.
"""

from __future__ import annotations

import shutil
import sys
import tarfile
import zipfile
from pathlib import Path

MAX_DEPTH = 4
ZIP_SUFFIXES = (".zip", ".whl", ".vsix", ".jar", ".nupkg", ".sigzip")
TAR_SUFFIXES = (".tar.gz", ".tgz", ".crate", ".tar")


def _inside(base: Path, name: str) -> Path:
    target = (base / name).resolve()
    if base.resolve() not in target.parents:
        raise ValueError(f"archive member {name!r} leaves {base}")
    return target


def unpack(path: Path, dest: Path, depth: int = 0) -> int:
    """Write `path`'s members under `dest`; return how many files that wrote, archives included."""
    dest.mkdir(parents=True, exist_ok=True)
    written = 0
    name = path.name.lower()
    try:
        if name.endswith(ZIP_SUFFIXES) and zipfile.is_zipfile(path):
            with zipfile.ZipFile(path) as archive:
                for member in archive.infolist():
                    if member.is_dir():
                        continue
                    target = _inside(dest, member.filename)
                    target.parent.mkdir(parents=True, exist_ok=True)
                    with archive.open(member) as source, target.open("wb") as out:
                        shutil.copyfileobj(source, out)
                    written += 1 + _nested(target, depth)
        elif name.endswith(TAR_SUFFIXES):
            with tarfile.open(path) as archive:
                for member in archive:
                    if not member.isfile():
                        continue
                    target = _inside(dest, member.name)
                    target.parent.mkdir(parents=True, exist_ok=True)
                    extracted = archive.extractfile(member)
                    if extracted is None:
                        continue
                    with target.open("wb") as out:
                        shutil.copyfileobj(extracted, out)
                    written += 1 + _nested(target, depth)
    except (zipfile.BadZipFile, tarfile.TarError) as error:
        print(f"extract: {path}: {error}", file=sys.stderr)
    return written


def _nested(file: Path, depth: int) -> int:
    if depth + 1 >= MAX_DEPTH:
        return 0
    if file.name.lower().endswith(ZIP_SUFFIXES + TAR_SUFFIXES):
        return unpack(file, file.parent / f"{file.name}.d", depth + 1)
    return 0


def main(argv: list[str]) -> int:
    if len(argv) != 2:
        print(__doc__, file=sys.stderr)
        return 2
    src, dest = Path(argv[0]), Path(argv[1])
    if not src.exists():
        print(f"extract: no such path: {src}", file=sys.stderr)
        return 2
    files = [src] if src.is_file() else sorted(p for p in src.rglob("*") if p.is_file())
    total = 0
    for file in files:
        relative = Path(file.name) if src.is_file() else file.relative_to(src)
        target = dest / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(file, target)
        total += 1 + _nested(target, 0)
    print(f"extract: {total} file(s) under {dest}")
    return 0 if total else 2


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
