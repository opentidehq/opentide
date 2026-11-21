#!/usr/bin/env python3
"""Report the Shannon entropy of each section of the binaries a release ships (#1743).

    entropy.py [--limit 7.0] PATH...

PATH is a file or a directory searched recursively. For an ELF (the Linux binaries, `.so`), a PE
(`.exe`, `.dll`, `.pyd`; needs pefile) and a WebAssembly module, every section's size and entropy in
bits per byte (0 to 8) is printed, with the whole file's. Antivirus heuristics treat a code section
or a whole file near 8 as packed or encrypted. Code is never compressed here, and the gate fails
when a code section (`.text`, `.code`, `__text`, the wasm `code` section) or the whole file is at or
above the limit.

The datasets are compressed (opentide-dataset), so a read-only data section (`.rodata`, `.rdata`,
the wasm `data` section) now holds blobs at 8 bits per byte beside tables and strings: its entropy
is reported, flagged `data above the limit`, and does not fail the gate. Exit status: 0 no code
section and not the whole file at or above the limit, 1 one is, 2 nothing read.
"""

from __future__ import annotations

import math
import struct
import sys
from collections import Counter
from pathlib import Path

LIMIT = 7.0
CODE_SECTIONS = {".text", "code", ".code", "__text", "CODE"}
#: Sections smaller than this are neither printed nor held to the limit (a wasm `element` table).
MIN_SECTION = 16 * 1024


def entropy(data: bytes) -> float:
    """Shannon entropy of `data` in bits per byte."""
    if not data:
        return 0.0
    counts = Counter(data)
    total = len(data)
    return -sum(n / total * math.log2(n / total) for n in counts.values())


def elf_sections(data: bytes) -> list[tuple[str, bytes]]:
    """The named, file-backed sections of an ELF64 little-endian file."""
    if data[:4] != b"\x7fELF" or data[4] != 2 or data[5] != 1:
        return []
    (shoff,) = struct.unpack_from("<Q", data, 0x28)
    shentsize, shnum, shstrndx = struct.unpack_from("<HHH", data, 0x3A)
    headers = [struct.unpack_from("<IIQQQQIIQQ", data, shoff + i * shentsize) for i in range(shnum)]
    names_header = headers[shstrndx]
    names = data[names_header[4] : names_header[4] + names_header[5]]
    found = []
    for name_offset, kind, _flags, _addr, offset, size, *_ in headers:
        if kind == 8 or size == 0:  # SHT_NOBITS, or empty
            continue
        name = names[name_offset : names.index(b"\0", name_offset)].decode("ascii", "replace")
        found.append((name, data[offset : offset + size]))
    return found


def wasm_sections(data: bytes) -> list[tuple[str, bytes]]:
    """The sections of a WebAssembly module (`code`, `data`, ...)."""
    if data[:4] != b"\0asm":
        return []
    names = {
        1: "type",
        2: "import",
        3: "function",
        5: "memory",
        6: "global",
        7: "export",
        8: "start",
        9: "element",
        10: "code",
        11: "data",
        12: "datacount",
    }
    position = 8
    found = []
    while position < len(data):
        kind = data[position]
        position += 1
        size = shift = 0
        while True:
            byte = data[position]
            position += 1
            size |= (byte & 0x7F) << shift
            shift += 7
            if byte < 0x80:
                break
        found.append((names.get(kind, f"section-{kind}"), data[position : position + size]))
        position += size
    return found


def pe_sections(path: Path) -> list[tuple[str, bytes]]:
    import pefile

    try:
        pe = pefile.PE(str(path), fast_load=True)
    except pefile.PEFormatError:
        return []
    found = [(s.Name.rstrip(b"\0").decode("ascii", "replace"), s.get_data()) for s in pe.sections]
    pe.close()
    return found


def sections_of(path: Path) -> list[tuple[str, bytes]]:
    data = path.read_bytes()
    found = elf_sections(data) or wasm_sections(data)
    if not found and path.name.lower().endswith((".exe", ".dll", ".pyd", ".node")):
        found = pe_sections(path)
    return found


def main(argv: list[str]) -> int:
    limit = LIMIT
    paths = []
    args = iter(argv)
    for arg in args:
        if arg == "--limit":
            limit = float(next(args))
        else:
            paths.append(Path(arg))
    if not paths or any(not p.exists() for p in paths):
        print(__doc__, file=sys.stderr)
        return 2
    files = [
        f for p in paths for f in ([p] if p.is_file() else sorted(p.rglob("*"))) if f.is_file()
    ]
    over = 0
    read = 0
    for file in files:
        sections = sections_of(file)
        if not sections:
            continue
        read += 1
        whole = entropy(file.read_bytes())
        flag = "  <-- AT OR ABOVE THE LIMIT" if whole >= limit else ""
        over += whole >= limit
        print(f"{file.name}: whole file {whole:.2f}{flag}")
        for name, data in sections:
            if len(data) < MIN_SECTION:
                continue
            value = entropy(data)
            flag = ""
            if value >= limit and name in CODE_SECTIONS:
                flag = "  <-- CODE AT OR ABOVE THE LIMIT"
                over += 1
            elif value >= limit:
                flag = "  (data above the limit: compressed datasets)"
            print(f"  {name:<24} {len(data):>12} bytes  {value:.2f}{flag}")
    if read == 0:
        print("entropy: no ELF, PE or WebAssembly file found", file=sys.stderr)
        return 2
    return 1 if over else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
