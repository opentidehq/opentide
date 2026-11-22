#!/usr/bin/env python3
"""List the Windows imports of a release's binaries; fail on a keylogger-like set (#1743).

    pe_imports.py [--allow-none] PATH...

PATH is a file or a directory searched recursively (the extracted artifacts: extract.py). Every PE
file (`.exe`, `.dll`, `.pyd`, `.node`) is parsed with pefile and its user32 imports are printed.

The foreground-window, keyboard-layout and `ToUnicodeEx` imports are crossterm's Windows key
translation, which the terminal UI (`opentide tui`, the `setup` wizard's prompts) reads keys with.
Every Rust terminal UI on Windows has them, and they are only listed for the binaries that carry
the terminal UI: the `opentide` command line, the extension module (`_native.pyd`) and the Node.js
addon. Run 44981495486 of the experiment workflow put a module built with them through ClamAV,
YARA and Microsoft Defender (exclusions removed, signatures updated, a canary detected) and found
nothing; its cloud-delivered protection was off, so a cloud verdict is untested (docs/internal/av-
false-positives-2026-11-21.md). The language server never had the terminal UI, and may not import
them. Exit status: 0 policy met, 1 a forbidden import, 2 no PE found (`--allow-none`: 0, for a set
of artifacts that ships no Windows binary, the GitHub Release's since the standalone Windows
executables were dropped).
"""

from __future__ import annotations

import sys
from collections.abc import Iterable
from pathlib import Path

#: crossterm's `event/sys/windows/parse.rs`: the key-translation set.
KEY_TRANSLATION = frozenset(
    {"GetForegroundWindow", "GetKeyboardLayout", "ToUnicodeEx", "GetWindowThreadProcessId"}
)
PE_SUFFIXES = (".exe", ".dll", ".pyd", ".node")


def must_be_free(name: str) -> bool:
    """Whether the binary `name` may not import the key-translation set: the language server's."""
    return "opentide-lsp" in name.lower()


def forbidden(name: str, imports: Iterable[str]) -> set[str]:
    """The key-translation imports `name` has and may not."""
    return set(imports) & KEY_TRANSLATION if must_be_free(name) else set()


def user32_imports(path: Path) -> list[str] | None:
    """The user32 functions the PE `path` imports (`None` when it is not a PE)."""
    import pefile

    try:
        pe = pefile.PE(str(path), fast_load=True)
    except pefile.PEFormatError:
        return None
    pe.parse_data_directories(directories=[pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_IMPORT"]])
    found: list[str] = []
    for entry in getattr(pe, "DIRECTORY_ENTRY_IMPORT", []):
        if entry.dll.decode("ascii", "replace").lower() == "user32.dll":
            found += [i.name.decode("ascii", "replace") for i in entry.imports if i.name]
    pe.close()
    return sorted(found)


def main(argv: list[str]) -> int:
    allow_none = "--allow-none" in argv
    paths = [Path(a) for a in argv if a != "--allow-none"]
    if not paths or any(not p.exists() for p in paths):
        print(__doc__, file=sys.stderr)
        return 2
    files = [
        f
        for p in paths
        for f in ([p] if p.is_file() else sorted(p.rglob("*")))
        if f.is_file() and f.name.lower().endswith(PE_SUFFIXES)
    ]
    bad = 0
    read = 0
    for file in files:
        imports = user32_imports(file)
        if imports is None:
            continue
        read += 1
        hits = forbidden(file.name, imports)
        names = ", ".join(sorted(set(imports) & KEY_TRANSLATION)) or "none"
        verdict = "  <-- FORBIDDEN" if hits else ""
        print(f"{file.name}: {len(imports)} user32 import(s); key translation: {names}{verdict}")
        bad += bool(hits)
    if read == 0:
        print("pe_imports: no PE file found", file=sys.stderr)
        return 0 if allow_none else 2
    return 1 if bad else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
