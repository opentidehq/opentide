#!/usr/bin/env python3
"""List the Windows imports of a release's binaries; fail on a keylogger-like set (#1743).

    pe_imports.py PATH...

PATH is a file or a directory searched recursively (the extracted artifacts: extract.py). Every PE
file (`.exe`, `.dll`, `.pyd`, `.node`) is parsed with pefile and its user32 imports are printed.

The foreground-window, keyboard-layout and `ToUnicodeEx` imports are crossterm's Windows key
translation, which the terminal UI (`opentide tui`, the `setup` wizard's prompts) reads keys with,
and which antivirus heuristics read as a keylogger's. The Python extension module (`_native.pyd`) is
built without the terminal UI (the facade's `cli-core` feature) and the language server never had
it, so neither may import them. The `opentide` command line's binary and the Node.js addon keep the
terminal UI and are only listed. Exit status: 0 policy met, 1 a forbidden import, 2 no PE found.
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
    """Whether the binary `name` may not import the key-translation set."""
    lowered = name.lower()
    return lowered.endswith(".pyd") or "opentide-lsp" in lowered


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
    paths = [Path(a) for a in argv]
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
        return 2
    return 1 if bad else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
