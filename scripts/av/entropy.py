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
is reported, flagged `data above the limit`, and does not fail the gate.

The whole-file figure the gate holds to the limit leaves out opentide's own dataset blobs, and
only those. Entropy is a proxy for a packer: the real scanners (ClamAV, YARA, Defender) decide, and
a file near 8 bits per byte is what a packer or an encrypted payload looks like. Our blobs are
known, and identified exactly: each starts with the container header of
`crates/opentide-dataset/src/lib.rs` (`OTD`, version 1, a kind of 0 or 1, the raw length as a
little-endian u32) followed at once by a zstd frame. Its extent is not in the header, which holds
the decoded length: it is found by walking the frame's block headers (nothing is decompressed), and
the frame's own content size must equal the header's raw length. A blob is left out only when all of
that holds and it ends inside the file; a bad header, a frame that is not well formed, a content
size that disagrees with the header or a length that runs past the end of the file is not left out,
and its bytes count in full. Every code section is held to the limit as it is, blobs or not. The
output gives, per file, the figure with and without the blobs and how many bytes were left out.

Exit status: 0 no code section and not the whole file (without its blobs) at or above the limit, 1
one is, 2 nothing read.
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

#: opentide-dataset's container: "OTD", version, kind, raw length (u32 little endian), then a zstd
#: frame (crates/opentide-dataset/src/lib.rs: MAGIC, VERSION, Kind, HEADER_LEN).
OTD_PREFIX = b"OTD\x01"
OTD_KINDS = {0, 1}
OTD_HEADER = 9
#: The most a blob may decode to: the crate reserves at most 16 MiB and its largest dataset is
#: 3.4 MB; a header that claims more is not one of ours.
OTD_MAX_RAW = 64 * 1024 * 1024
ZSTD_MAGIC = b"\x28\xb5\x2f\xfd"


def entropy(data: bytes) -> float:
    """Shannon entropy of `data` in bits per byte."""
    if not data:
        return 0.0
    counts = Counter(data)
    total = len(data)
    return -sum(n / total * math.log2(n / total) for n in counts.values())


def zstd_frame(data: bytes, start: int) -> tuple[int, int | None] | None:
    """The zstd frame at `data[start:]`: (its length in bytes, its content size or None when it
    states none), found by walking its block headers; None when it is not a well-formed frame or
    runs past the end of `data`. Nothing is decompressed."""
    if data[start : start + 4] != ZSTD_MAGIC or start + 5 > len(data):
        return None
    descriptor = data[start + 4]
    if descriptor & 0x08:  # reserved bit
        return None
    single = (descriptor >> 5) & 1
    checksum = (descriptor >> 2) & 1
    position = start + 5 + (0 if single else 1)  # the window descriptor
    position += (0, 1, 2, 4)[descriptor & 3]  # the dictionary id
    size_field = (1 if single else 0, 2, 4, 8)[descriptor >> 6]
    if position + size_field > len(data):
        return None
    content = None
    if size_field:
        content = int.from_bytes(data[position : position + size_field], "little")
        if size_field == 2:
            content += 256
    position += size_field
    while True:
        if position + 3 > len(data):
            return None
        header = int.from_bytes(data[position : position + 3], "little")
        kind, size = (header >> 1) & 3, header >> 3
        if kind == 3:  # reserved
            return None
        position += 3 + (1 if kind == 1 else size)
        if position > len(data):
            return None
        if header & 1:
            break
    position += 4 if checksum else 0
    if position > len(data):
        return None
    return position - start, content


def dataset_blobs(data: bytes) -> list[tuple[int, int]]:
    """The (start, end) of each opentide dataset blob in `data`, in order and not overlapping:
    the container header, then a zstd frame whose content size is the header's raw length."""
    found = []
    position = 0
    while (at := data.find(OTD_PREFIX, position)) != -1:
        position = at + 1
        header = data[at : at + OTD_HEADER]
        if len(header) < OTD_HEADER or header[4] not in OTD_KINDS:
            continue
        raw = int.from_bytes(header[5:9], "little")
        frame = zstd_frame(data, at + OTD_HEADER)
        if frame is None or raw > OTD_MAX_RAW:
            continue
        length, content = frame
        if content is not None and content != raw:
            continue
        found.append((at, at + OTD_HEADER + length))
        position = at + OTD_HEADER + length
    return found


def without_blobs(data: bytes, blobs: list[tuple[int, int]]) -> bytes:
    """`data` with each of `blobs` cut out."""
    pieces = []
    position = 0
    for start, end in blobs:
        pieces.append(data[position:start])
        position = end
    pieces.append(data[position:])
    return b"".join(pieces)


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
        data = file.read_bytes()
        whole = entropy(data)
        blobs = dataset_blobs(data)
        left = len(data) - sum(end - start for start, end in blobs)
        rest = entropy(without_blobs(data, blobs)) if blobs else whole
        flag = "  <-- AT OR ABOVE THE LIMIT" if rest >= limit else ""
        over += rest >= limit
        print(
            f"{file.name}: whole file {whole:.2f}, without its {len(blobs)} dataset blobs "
            f"({len(data) - left} bytes) {rest:.2f}{flag}"
        )
        for name, data in sections:
            if len(data) < MIN_SECTION:
                continue
            value = entropy(data)
            flag = ""
            if value >= limit and name in CODE_SECTIONS:
                flag = "  <-- CODE AT OR ABOVE THE LIMIT"
                over += 1
            elif value >= limit:
                flag = "  (data section above the limit: compressed datasets, or unwind tables)"
            print(f"  {name:<24} {len(data):>12} bytes  {value:.2f}{flag}")
    if read == 0:
        print("entropy: no ELF, PE or WebAssembly file found", file=sys.stderr)
        return 2
    return 1 if over else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
