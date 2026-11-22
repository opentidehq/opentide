"""The marker-string check of the release gate (scripts/av/markers.py, #1743).

Compressing the embedded datasets (opentide-dataset) keeps the words of the
security vocabularies out of every artifact. These tests hold the scanner to
its job, and hold the built extension of this checkout (and any artifact a
run names in `OPENTIDE_ARTIFACTS`) to it: a dataset stored loose again, or a
new `include_str!` of one, fails here.
"""

from __future__ import annotations

import importlib.util
import io
import os
import shutil
import subprocess
import sys
import tarfile
import zipfile
from pathlib import Path

import pytest

_MODULE = Path(__file__).resolve().parents[2] / "scripts" / "av" / "markers.py"
_spec = importlib.util.spec_from_file_location("av_markers", _MODULE)
assert _spec
assert _spec.loader
markers = importlib.util.module_from_spec(_spec)
sys.modules["av_markers"] = markers  # a dataclass of the module looks itself up here
_spec.loader.exec_module(markers)

ROOT = Path(__file__).resolve().parents[2]


def _found(data: bytes, name: str = "x.bin") -> set[str]:
    return {hit.marker for hit in markers.scan_blob(name, data, name)}


@pytest.mark.parametrize("marker", markers.MARKERS)
def test_each_marker_is_found_in_plain_text_in_any_case_and_wide(marker: str) -> None:
    assert _found(b"\x00" * 64 + marker.encode() + b"\x00" * 64) == {marker}
    assert _found(marker.upper().encode()) == {marker}
    assert _found(marker.encode("utf-16-le")) == {marker}


def test_clean_bytes_and_compressed_data_pass() -> None:
    assert _found(os.urandom(4096)) == set()
    assert _found(b"mine.mone ropool") == set()


def test_markers_are_found_inside_archives_and_nested_archives() -> None:
    inner = io.BytesIO()
    with zipfile.ZipFile(inner, "w", zipfile.ZIP_DEFLATED) as archive:
        archive.writestr("data/falco.toml", "miner_domains = ['mine.moneropool.com']")
    outer = io.BytesIO()
    with zipfile.ZipFile(outer, "w", zipfile.ZIP_DEFLATED) as archive:
        archive.writestr("README", "clean")
        archive.writestr("opentide/inner.whl", inner.getvalue())
    hits = list(markers.scan_blob("opentide-1.0.0-py3-none-any.whl", outer.getvalue(), "w"))
    assert [(hit.marker, hit.where) for hit in hits if hit.where != "w"] == [
        ("moneropool", "w!opentide/inner.whl!data/falco.toml")
    ]

    def tarball(member: str, payload: bytes, name: str) -> set[str]:
        stream = io.BytesIO()
        with tarfile.open(fileobj=stream, mode="w:gz") as archive:
            info = tarfile.TarInfo(member)
            info.size = len(payload)
            archive.addfile(info, io.BytesIO(payload))
        return _found(stream.getvalue(), name)

    # A source distribution keeps the datasets as the sources the build compresses...
    assert (
        tarball(
            "opentide-1.0.0/data/catalogs/falco/defaults.toml", b"mine.moneropool.com", "o.tar.gz"
        )
        == set()
    )
    assert (
        tarball("opentide-falco-1.0.0/assets/data/catalogs/x.toml", b"sekurlsa", "o.crate") == set()
    )
    # ...and so are its text sources (a test names the techniques it detects)...
    assert (
        tarball("opentide-exabeam-1.0.0/src/tests.rs", b"sekurlsa::logonpasswords", "o.crate")
        == set()
    )
    assert tarball("opentide-1.0.0/crates/x/tests/h.rs", b"Login Data", "o.tar.gz") == set()
    # ...and nothing else of it, nor any other archive, is exempt.
    assert tarball("opentide-1.0.0/src/lib.rs", b"sekurlsa", "o.zip.tar") == {"sekurlsa"}
    assert tarball(
        "opentide-1.0.0/src/opentide/loose.bin", b"sekurlsa::logonpasswords", "o.tar.gz"
    ) == {"sekurlsa"}
    assert tarball("opentide/data/catalogs/falco/defaults.toml", b"moneropool", "o.zip.tar") == {
        "moneropool"
    }


def test_a_path_scan_walks_a_directory(tmp_path: Path) -> None:
    (tmp_path / "a").mkdir()
    (tmp_path / "a" / "clean.bin").write_bytes(b"nothing here")
    (tmp_path / "a" / "dirty.bin").write_bytes(b"Invoke-Mimikatz -DumpCreds")
    assert [hit.marker for hit in markers.scan_path(tmp_path)] == ["Invoke-Mimikatz"]
    assert markers.main([str(tmp_path)]) == 1
    assert markers.main([str(tmp_path / "a" / "clean.bin")]) == 0
    assert markers.main([str(tmp_path / "missing")]) == 2


def _built_artifacts() -> list[Path]:
    """The compiled extension of this checkout, and the artifacts the run names."""
    found = sorted((ROOT / "src" / "opentide").glob("_native*.so"))
    found += sorted((ROOT / "src" / "opentide").glob("_native*.pyd"))
    for name in filter(None, os.environ.get("OPENTIDE_ARTIFACTS", "").split(os.pathsep)):
        found.append(Path(name))
    return found


@pytest.mark.skipif(not _built_artifacts(), reason="no built artifact (uv sync builds _native)")
def test_built_artifacts_carry_no_marker_in_plain_text() -> None:
    found = [hit for path in _built_artifacts() for hit in markers.scan_path(path)]
    assert not found, "\n".join(f"{h.marker!r} ({h.form}) in {h.where}" for h in found)


_PE = Path(__file__).resolve().parents[2] / "scripts" / "av" / "pe_imports.py"
_pe_spec = importlib.util.spec_from_file_location("av_pe_imports", _PE)
assert _pe_spec
assert _pe_spec.loader
pe_imports = importlib.util.module_from_spec(_pe_spec)
sys.modules["av_pe_imports"] = pe_imports
_pe_spec.loader.exec_module(pe_imports)


def test_only_the_language_server_may_not_import_key_translation() -> None:
    """The terminal UI's binaries (the command line, the extension module, the Node.js addon) have
    crossterm's key translation and are listed; the language server never had it."""
    keys = ["GetForegroundWindow", "ToUnicodeEx", "MessageBoxW"]
    assert pe_imports.forbidden("opentide-lsp-v1.0.0-x86_64-pc-windows-msvc.exe", keys) == {
        "GetForegroundWindow",
        "ToUnicodeEx",
    }
    for name in ("_native.pyd", "opentide.win32-x64-msvc.node", "opentide-v1.0.0-x.exe"):
        assert pe_imports.forbidden(name, keys) == set(), name
    assert pe_imports.forbidden("opentide-lsp-v1.0.0-x.exe", ["MessageBoxW"]) == set()


def test_the_yara_gate_skips_the_text_sources_of_a_source_distribution(tmp_path: Path) -> None:
    spec = importlib.util.spec_from_file_location("av_yara_gate", _MODULE.with_name("yara_gate.py"))
    assert spec
    assert spec.loader
    sys.path.insert(0, str(_MODULE.parent))
    try:
        gate = importlib.util.module_from_spec(spec)
        sys.modules["av_yara_gate"] = gate
        spec.loader.exec_module(gate)
    finally:
        sys.path.remove(str(_MODULE.parent))
    tree = tmp_path
    source = tree / "o-1.0.tar.gz.d" / "o-1.0" / "src" / "tests.rs"
    binary = tree / "o-1.0.tar.gz.d" / "o-1.0" / "src" / "blob.bin"
    wheel = tree / "o.whl.d" / "o" / "data.toml"
    assert gate.in_source_distribution(source, tree)
    assert not gate.in_source_distribution(binary, tree)
    assert not gate.in_source_distribution(wheel, tree)


def test_a_set_of_artifacts_without_windows_binaries_passes_only_when_allowed(
    tmp_path: Path,
) -> None:
    spec = importlib.util.spec_from_file_location(
        "av_pe_imports", _MODULE.with_name("pe_imports.py")
    )
    assert spec
    assert spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    (tmp_path / "opentide-lsp-wasm32-wasip1.wasm").write_bytes(b"\0asm\1\0\0\0")
    assert module.main([str(tmp_path)]) == 2
    assert module.main(["--allow-none", str(tmp_path)]) == 0


def _yara_gate() -> object:
    spec = importlib.util.spec_from_file_location(
        "av_yara_gate_exit", _MODULE.with_name("yara_gate.py")
    )
    assert spec
    assert spec.loader
    sys.path.insert(0, str(_MODULE.parent))
    try:
        gate = importlib.util.module_from_spec(spec)
        sys.modules["av_yara_gate_exit"] = gate
        spec.loader.exec_module(gate)
    finally:
        sys.path.remove(str(_MODULE.parent))
    return gate


class _Ran:
    def __init__(self, code: int, out: str = "", err: str = "") -> None:
        self.returncode, self.stdout, self.stderr = code, out, err


def test_the_yara_gate_stops_on_every_yara_error_and_a_missing_canary(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    gate = _yara_gate()
    sample = tmp_path / "f.bin"
    sample.write_bytes(b"x")
    # An error exits 1 (a scan timeout, a rules file that does not load): never "clean".
    monkeypatch.setattr(gate.subprocess, "run", lambda *a, **k: _Ran(1, "", "error: timeout"))
    with pytest.raises(SystemExit) as stopped:
        gate.scan_file(tmp_path / "rules.yarc", sample)
    assert stopped.value.code == 2
    # An error on one file with a zero exit is an error too.
    monkeypatch.setattr(
        gate.subprocess, "run", lambda *a, **k: _Ran(0, "", "error scanning f.bin: too many")
    )
    with pytest.raises(SystemExit):
        gate.scan_file(tmp_path / "rules.yarc", sample)
    # A match is a hit, no match is none.
    monkeypatch.setattr(gate.subprocess, "run", lambda *a, **k: _Ran(0, "Rule_A f.bin\n"))
    assert gate.scan_file(tmp_path / "rules.yarc", sample) == ["Rule_A"]
    monkeypatch.setattr(gate.subprocess, "run", lambda *a, **k: _Ran(0, ""))
    assert gate.scan_file(tmp_path / "rules.yarc", sample) == []
    # A bundle that does not find the canary in its own file scans nothing: the gate stops.
    with pytest.raises(SystemExit) as stopped:
        gate.check_canary(tmp_path / "rules.yarc", tmp_path)
    assert stopped.value.code == 2
    monkeypatch.setattr(
        gate.subprocess, "run", lambda *a, **k: _Ran(0, f"{gate.CANARY_RULE} canary.txt\n")
    )
    gate.check_canary(tmp_path / "rules.yarc", tmp_path)
