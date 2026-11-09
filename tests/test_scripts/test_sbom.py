"""``scripts/engine/sbom.py``: the SBOMs opentide's artifacts ship with (#843)."""

from __future__ import annotations

import importlib.util
import json
from pathlib import Path
from types import ModuleType
from typing import Any

import pytest

ROOT = Path(__file__).resolve().parents[2]


def _script() -> ModuleType:
    spec = importlib.util.spec_from_file_location("sbom", ROOT / "scripts" / "engine" / "sbom.py")
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


sbom = _script()


def _bom(root: str, components: list[str], depends: dict[str, list[str]]) -> dict[str, Any]:
    return {
        "bomFormat": "CycloneDX",
        "specVersion": "1.5",
        "metadata": {"component": {"bom-ref": root, "name": root, "type": "application"}},
        "components": [{"bom-ref": ref, "name": ref, "type": "library"} for ref in components],
        "dependencies": [{"ref": ref, "dependsOn": on} for ref, on in depends.items()],
    }


def test_references_name_workspace_crates_relative_to_the_repository(tmp_path: Path) -> None:
    root = tmp_path / "checkout"
    absolute = f"path+file://{root.resolve().as_posix()}/crates/opentide-lsp#0.11.0"
    bom = _bom(absolute, [], {absolute: []})
    relative = sbom.relative_refs(bom, root)
    assert relative["metadata"]["component"]["bom-ref"] == "path+file:crates/opentide-lsp#0.11.0"
    assert relative["dependencies"][0]["ref"] == "path+file:crates/opentide-lsp#0.11.0"
    assert str(root.resolve()) not in str(relative)


def test_the_browser_build_lists_the_wasi_libc_it_links() -> None:
    script = (ROOT / "scripts" / "engine" / "build-wasm.sh").read_text(encoding="utf-8")
    libc = sbom.wasi_libc_component(script)
    assert libc["name"] == "wasi-libc"
    assert libc["version"].startswith("wasi-sdk-")
    bom = sbom.add_component(_bom("wasm", ["dep"], {"wasm": ["dep"], "dep": []}), libc)
    assert sbom.structural_problems(bom) == []
    assert libc["bom-ref"] in bom["dependencies"][0]["dependsOn"]
    with pytest.raises(SystemExit):
        sbom.wasi_libc_component("no version here")


def test_the_wheel_lists_python_dependencies_and_the_compiled_crates() -> None:
    python = _bom("opentide-1", ["pydantic"], {"opentide-1": ["pydantic"], "pydantic": []})
    native = _bom("native", ["serde"], {"native": ["serde"], "serde": []})
    wheel = sbom.merge_wheel(python, native, "1.2.3")
    assert sbom.structural_problems(wheel) == []
    assert sbom.depends_on_something(wheel)
    names = {c["name"] for c in wheel["components"]}
    assert names == {"pydantic", "native", "serde"}
    root = next(d for d in wheel["dependencies"] if d["ref"] == "opentide-1")
    assert root["dependsOn"] == ["pydantic", "native"]
    assert wheel["metadata"]["component"]["version"] == "1.2.3"
    assert wheel["metadata"]["component"]["purl"] == "pkg:pypi/opentide@1.2.3"
    # The inputs are left as they were.
    assert len(python["components"]) == 1


def test_the_wheel_version_comes_from_the_version_file(tmp_path: Path) -> None:
    assert sbom.wheel_version("9.9.9", tmp_path) == "9.9.9"
    assert sbom.wheel_version(None, tmp_path) is None
    version_file = tmp_path / "src" / "opentide" / "_version.py"
    version_file.parent.mkdir(parents=True)
    version_file.write_text("__version__ = version = '0.24.0'\n", encoding="utf-8")
    assert sbom.wheel_version(None, tmp_path) == "0.24.0"


def test_structural_problems_catch_what_the_schema_does_not() -> None:
    assert sbom.structural_problems(_bom("a", ["b"], {"a": ["b"], "b": []})) == []
    duplicate = _bom("a", ["b", "b"], {"a": ["b"]})
    assert any("not unique" in p for p in sbom.structural_problems(duplicate))
    dangling = _bom("a", ["b"], {"a": ["c"]})
    assert any("'c'" in p for p in sbom.structural_problems(dangling))
    assert sbom.structural_problems({"metadata": {}}) != []
    # A package with no runtime dependency is a valid SBOM, but the Rust and
    # wheel SBOMs must not come out empty.
    empty = _bom("pkg", [], {"pkg": []})
    assert sbom.structural_problems(empty) == []
    assert not sbom.depends_on_something(empty)


def test_sboms_carry_the_epoch_and_no_random_serial() -> None:
    bom = _bom("a", [], {"a": []})
    bom["serialNumber"] = "urn:uuid:random"
    bom["metadata"]["timestamp"] = "2026-11-08T05:53:40.297Z"
    fixed = sbom.reproducible(bom, "1700000000")
    assert "serialNumber" not in fixed
    assert fixed["metadata"]["timestamp"] == "2023-11-14T22:13:20Z"
    assert sbom.reproducible(bom, None)["metadata"]["timestamp"] == bom["metadata"]["timestamp"]
    assert "serialNumber" in bom  # the input is left as it was


class _Validator:
    """Stands in for the CycloneDX schema validator `validate()` runs through
    uv: records each call and answers with ``returncode``."""

    def __init__(self, returncode: int) -> None:
        self.returncode = returncode
        self.calls: list[list[str]] = []

    def __call__(self, command: list[str], **_: Any) -> Any:
        self.calls.append(command)
        return type("Completed", (), {"returncode": self.returncode})()


def _write_bom(path: Path, bom: dict[str, Any]) -> Path:
    path.write_text(json.dumps(bom), encoding="utf-8")
    return path


def test_validate_passes_a_valid_sbom(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    validator = _Validator(0)
    monkeypatch.setattr(sbom.subprocess, "run", validator)
    good = _write_bom(tmp_path / "good.cdx.json", _bom("a", ["b"], {"a": ["b"], "b": []}))
    assert sbom.validate([good]) == 0
    # The schema check ran, on that file, with the pinned validator.
    assert validator.calls and str(good) in validator.calls[0]
    assert sbom.VALIDATOR in validator.calls[0]


@pytest.mark.parametrize(
    "change",
    [
        pytest.param(lambda b: b.update(specVersion="1.4"), id="wrong-spec-version"),
        pytest.param(lambda b: b["dependencies"].append({"ref": "zz"}), id="dangling-ref"),
    ],
)
def test_validate_fails_a_structurally_wrong_sbom(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, change: Any
) -> None:
    monkeypatch.setattr(sbom.subprocess, "run", _Validator(0))
    bom = _bom("a", ["b"], {"a": ["b"], "b": []})
    change(bom)
    assert sbom.validate([_write_bom(tmp_path / "bad.cdx.json", bom)]) == 1


def test_validate_fails_when_the_schema_check_fails(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # A schema violation is the validator's to report: its exit status counts.
    monkeypatch.setattr(sbom.subprocess, "run", _Validator(1))
    good = _write_bom(tmp_path / "x.cdx.json", _bom("a", ["b"], {"a": ["b"], "b": []}))
    assert sbom.validate([good]) == 1
