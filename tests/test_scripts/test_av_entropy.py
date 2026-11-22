"""The entropy report of the release gate (scripts/av/entropy.py, #1743).

Entropy is a proxy for a packer. opentide's compressed datasets are known and identified
exactly (the container header of crates/opentide-dataset, then a zstd frame), so the
whole-file figure leaves out those blobs, and only those. These tests hold the scanner to
that: a blob passes, the same bytes without the header fail, random bytes in a code section
fail whatever else the file holds, and a frame that lies about its length is not skipped
past the end of the file.
"""

from __future__ import annotations

import importlib.util
import os
import struct
import sys
from pathlib import Path

import pytest

_MODULE = Path(__file__).resolve().parents[2] / "scripts" / "av" / "entropy.py"
_spec = importlib.util.spec_from_file_location("av_entropy", _MODULE)
assert _spec
assert _spec.loader
entropy = importlib.util.module_from_spec(_spec)
sys.modules["av_entropy"] = entropy
_spec.loader.exec_module(entropy)

#: A zstd frame's magic, and a descriptor of a single-segment frame with a four-byte content size.
ZSTD_MAGIC = b"\x28\xb5\x2f\xfd"
SINGLE_SEGMENT_FCS4 = 0xA0


def random_bytes(count: int, seed: int = 1) -> bytes:
    """Bytes close to 8 bits of entropy each, the same on every run."""
    out = bytearray()
    state = seed
    while len(out) < count:
        state = (state * 6364136223846793005 + 1442695040888963407) % (1 << 64)
        out += struct.pack("<Q", state ^ (state >> 29))
    return bytes(out[:count])


def zstd_frame(content: bytes, *, content_size: int | None = None) -> bytes:
    """A well-formed zstd frame whose blocks store `content` raw (no compressor is needed to
    make a frame the gate must recognise); `content_size` overrides the size it states."""
    frame = bytearray(ZSTD_MAGIC)
    frame.append(SINGLE_SEGMENT_FCS4)
    frame += struct.pack("<I", len(content) if content_size is None else content_size)
    chunks = [content[i : i + 100_000] for i in range(0, len(content), 100_000)] or [b""]
    for index, chunk in enumerate(chunks):
        last = 1 if index == len(chunks) - 1 else 0
        frame += struct.pack("<I", (len(chunk) << 3) | (0 << 1) | last)[:3]  # a raw block
        frame += chunk
    return bytes(frame)


def blob(content: bytes, *, kind: int = 0, raw: int | None = None, **frame) -> bytes:
    """opentide-dataset's container: OTD, version 1, kind, raw length, then the frame."""
    return (
        b"OTD\x01"
        + bytes([kind])
        + struct.pack("<I", len(content) if raw is None else raw)
        + zstd_frame(content, **frame)
    )


def leb(value: int) -> bytes:
    out = bytearray()
    while True:
        byte = value & 0x7F
        value >>= 7
        out.append(byte | (0x80 if value else 0))
        if not value:
            return bytes(out)


def wasm(code: bytes, data: bytes) -> bytes:
    """A WebAssembly module of two sections, `code` and `data`, with the bytes given."""
    return (
        b"\0asm\x01\0\0\0"
        + bytes([10])
        + leb(len(code))
        + code
        + bytes([11])
        + leb(len(data))
        + data
    )


def run(tmp_path: Path, module: bytes, capsys: pytest.CaptureFixture[str]) -> tuple[int, str]:
    path = tmp_path / "artifact.wasm"
    path.write_bytes(module)
    status = entropy.main([str(path)])
    return status, capsys.readouterr().out


LOW = b"\x00\x01\x02\x03" * 8_192  # 32 KiB of code at 2 bits per byte


def test_a_blob_of_random_bytes_in_the_data_section_passes(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    random = random_bytes(300_000)
    status, out = run(tmp_path, wasm(LOW, LOW + blob(random) + LOW), capsys)
    assert status == 0, out
    # Both figures and the bytes left out are in the output.
    assert "whole file 7." in out or "whole file 6." in out
    assert "without its 1 dataset blobs" in out
    assert f"({9 + len(zstd_frame(random))} bytes)" in out


def test_the_same_bytes_without_the_header_fail(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    random = random_bytes(300_000)
    status, out = run(tmp_path, wasm(LOW, LOW + zstd_frame(random) + LOW), capsys)
    assert status == 1, out
    assert "AT OR ABOVE THE LIMIT" in out
    assert "without its 0 dataset blobs (0 bytes)" in out
    # Random bytes with nothing identifying them fail as well.
    status, out = run(tmp_path, wasm(LOW, LOW + random + LOW), capsys)
    assert status == 1, out


def test_random_bytes_in_a_code_section_fail_whatever_else_the_file_holds(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    random = random_bytes(300_000)
    low_data = LOW * 40  # the file as a whole stays low
    status, out = run(tmp_path, wasm(random, low_data), capsys)
    assert status == 1, out
    assert "CODE AT OR ABOVE THE LIMIT" in out
    # A dataset blob does not excuse the code section it sits in: sections are read as they are.
    status, out = run(tmp_path, wasm(blob(random), low_data), capsys)
    assert status == 1, out
    assert "CODE AT OR ABOVE THE LIMIT" in out


def test_a_frame_that_lies_about_its_length_is_not_skipped_past_the_end() -> None:
    random = random_bytes(200_000)
    good = blob(random)
    prefix = LOW
    # A block that claims more bytes than the file has: the frame runs past the end.
    lying = bytearray(good)
    lying[9 + 9 : 9 + 12] = struct.pack("<I", (5_000_000 << 3) | 1)[:3]
    assert entropy.dataset_blobs(prefix + bytes(lying)) == []
    # A frame cut off at the end of the file.
    assert entropy.dataset_blobs(prefix + good[:-1]) == []
    assert entropy.dataset_blobs(prefix + good[:12]) == []
    # The header's raw length disagrees with the frame's own content size.
    assert entropy.dataset_blobs(prefix + blob(random, raw=len(random) + 1)) == []
    assert entropy.dataset_blobs(prefix + blob(random, content_size=len(random) + 1)) == []
    # A header that claims more than the crate decodes, an unknown kind, another version.
    huge = blob(random, raw=entropy.OTD_MAX_RAW + 1, content_size=entropy.OTD_MAX_RAW + 1)
    assert entropy.dataset_blobs(prefix + huge) == []
    assert entropy.dataset_blobs(prefix + blob(random, kind=2)) == []
    assert entropy.dataset_blobs(prefix + b"OTD\x02" + good[4:]) == []
    # Whatever is found ends inside the data.
    for text in (prefix + bytes(lying), prefix + good[:-1], prefix + good):
        for start, end in entropy.dataset_blobs(text):
            assert 0 <= start < end <= len(text)


def test_the_span_is_exactly_the_header_and_the_frame() -> None:
    first, second = random_bytes(150_000, 2), random_bytes(7_000, 3)
    one, two = blob(first), blob(second, kind=1)
    before, between, after = LOW, b"\x00" * 100, LOW
    data = before + one + between + two + after
    spans = entropy.dataset_blobs(data)
    assert spans == [
        (len(before), len(before) + len(one)),
        (len(before) + len(one) + len(between), len(before) + len(one) + len(between) + len(two)),
    ]
    # What is left is every other byte, in order.
    assert entropy.without_blobs(data, spans) == before + between + after
    # No blob: nothing is left out.
    assert entropy.dataset_blobs(LOW) == []
    assert entropy.without_blobs(LOW, []) == LOW


def test_a_header_inside_another_blobs_bytes_is_not_a_second_blob() -> None:
    # Compressed bytes may hold the four bytes of the prefix by chance: the frame is skipped whole.
    inner = b"OTD\x01\x00" + struct.pack("<I", 10) + zstd_frame(b"0123456789")
    outer = blob(random_bytes(1_000) + inner + random_bytes(1_000))
    spans = entropy.dataset_blobs(LOW + outer)
    assert spans == [(len(LOW), len(LOW) + len(outer))]


@pytest.mark.skipif(not os.environ.get("OPENTIDE_ARTIFACTS"), reason="no artifact named")
def test_the_artifacts_of_a_run_pass() -> None:
    """The release assets of a run (OPENTIDE_ARTIFACTS): the gate's own check, as a test."""
    assert entropy.main([os.environ["OPENTIDE_ARTIFACTS"]]) == 0
