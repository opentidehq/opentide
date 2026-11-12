#!/usr/bin/env python3
"""CycloneDX SBOMs for what opentide distributes (#843).

    sbom.py generate OUT_DIR [--wheel-version V]   write every SBOM into OUT_DIR
    sbom.py validate FILE...        each FILE is a valid CycloneDX 1.5 SBOM

`generate` writes one SBOM per artifact, CycloneDX 1.5 JSON:

- `opentide-wheel.cdx.json`: the PyPI wheel. The Python dependencies
  (`uv export`) and the Rust crates compiled into `opentide._native`
  (`bindings/python/`, every target).
- `opentide-lsp.cdx.json`: the `opentide-lsp` binaries and its WASI build
  (the crate, every target).
- `opentide-wasm.cdx.json`: the browser build (the `opentide-wasm-web` zip):
  the crate for wasm32-unknown-unknown, and the wasi-libc it links.
- `opentide-lsp-client.cdx.json`, `opentide-lsp-worker.cdx.json`: the npm
  packages (`npm sbom`, without dev dependencies).

The Rust SBOMs come from cargo-cyclonedx without build dependencies (`cc`
runs at build time and ships nothing). Its references name each workspace
crate by its path on disk; `generate` writes them relative to the
repository, so an SBOM is the same wherever it is built. With
`SOURCE_DATE_EPOCH` set, every SBOM carries that time, and none a random
serial number, so two runs on one commit write the same files.

`validate` checks each file against the CycloneDX 1.5 JSON schema
(cyclonedx-python-lib, run through `uv`), then what the schema cannot:
every `bom-ref` is unique, and every dependency names a component the SBOM
lists. `generate` also fails when a Rust or wheel SBOM lists no dependency
(the npm packages have none today).
"""

from __future__ import annotations

import argparse
import datetime
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[2]

# The validator, pinned: `validate` runs it with `uv run --with`.
VALIDATOR = "cyclonedx-python-lib[json-validation]==11.12.0"
SPEC_VERSION = "1.5"

# Each workspace crate cargo-cyclonedx is asked for: (crate directory,
# --target, the SBOM's file name).
RUST_SBOMS = (
    ("crates/opentide-lsp", "all", "opentide-lsp.cdx.json"),
    ("crates/opentide-wasm", "wasm32-unknown-unknown", "opentide-wasm.cdx.json"),
)
NATIVE = "bindings__python"
NPM_PACKAGES = ("lsp-client", "lsp-worker")

Bom = dict[str, Any]


def _run(command: list[str], *, cwd: Path = ROOT) -> str:
    """Run ``command``; its standard output. A failure stops the script."""
    result = subprocess.run(command, cwd=cwd, capture_output=True, text=True, check=False)
    if result.returncode != 0:
        sys.stderr.write(result.stderr)
        raise SystemExit(f"sbom.py: {' '.join(command)} exited {result.returncode}")
    return result.stdout


def relative_refs(bom: Bom, root: Path) -> Bom:
    """``bom`` with the absolute repository path in its references (cargo's
    ``path+file:///…/crates/x#0.11.0``) written relative to the repository."""
    text = json.dumps(bom)
    prefix = root.resolve().as_posix().rstrip("/")
    text = text.replace(f"file://{prefix}/", "file:").replace(f"file://{prefix}", "file:.")
    return json.loads(text)


def wasi_libc_component(build_script: str) -> Bom:
    """The wasi-libc that ``build-wasm.sh`` links into the browser build: C,
    so no Cargo dependency names it."""
    match = re.search(r"^version=([0-9.]+)$", build_script, re.MULTILINE)
    if match is None:
        raise SystemExit("sbom.py: no `version=` in scripts/engine/build-wasm.sh")
    version = match.group(1)
    major = version.split(".")[0]
    return {
        "type": "library",
        "bom-ref": f"wasi-libc@wasi-sdk-{version}",
        "name": "wasi-libc",
        "version": f"wasi-sdk-{version}",
        "description": "wasi-sdk's libc.a, linked into the wasm32-unknown-unknown build "
        "(licenses/wasi-libc, shipped as WASI-LIBC-LICENSES.txt)",
        "scope": "required",
        "licenses": [{"expression": "Apache-2.0 WITH LLVM-exception OR Apache-2.0 OR MIT"}],
        "purl": f"pkg:github/WebAssembly/wasi-sdk@wasi-sdk-{major}",
    }


def add_component(bom: Bom, component: Bom) -> Bom:
    """``bom`` with ``component`` listed and depended on by its subject."""
    bom = json.loads(json.dumps(bom))
    bom.setdefault("components", []).append(component)
    root = bom["metadata"]["component"]["bom-ref"]
    dependencies = bom.setdefault("dependencies", [])
    entry = next((d for d in dependencies if d.get("ref") == root), None)
    if entry is None:
        entry = {"ref": root, "dependsOn": []}
        dependencies.append(entry)
    entry.setdefault("dependsOn", []).append(component["bom-ref"])
    dependencies.append({"ref": component["bom-ref"], "dependsOn": []})
    return bom


def wheel_version(explicit: str | None, root: Path) -> str | None:
    """The wheel's version: ``explicit``, else the one hatch-vcs wrote into
    ``src/opentide/_version.py`` when the package was built (``uv sync``),
    else none (``uv export`` names the project without one: it is dynamic)."""
    if explicit:
        return explicit
    path = root / "src" / "opentide" / "_version.py"
    if not path.is_file():
        return None
    text = path.read_text(encoding="utf-8")
    match = re.search(
        r"^__version__\s*=\s*(?:version\s*=\s*)?['\"]([^'\"]+)['\"]", text, re.MULTILINE
    )
    return match.group(1) if match else None


def merge_wheel(python: Bom, native: Bom, version: str | None = None) -> Bom:
    """The wheel's SBOM: the Python package and its dependencies (``python``,
    from ``uv export``), with the Rust crates compiled into
    ``opentide._native`` (``native``, from cargo-cyclonedx) as a dependency of
    the package."""
    merged = json.loads(json.dumps(python))
    if version:
        subject = merged["metadata"]["component"]
        subject["version"] = version
        subject["purl"] = f"pkg:pypi/opentide@{version}"
    native_root = dict(native["metadata"]["component"])
    native_root["type"] = "library"
    merged.setdefault("components", []).append(native_root)
    merged["components"].extend(native.get("components", []))
    root = merged["metadata"]["component"]["bom-ref"]
    dependencies = merged.setdefault("dependencies", [])
    entry = next((d for d in dependencies if d.get("ref") == root), None)
    if entry is None:
        entry = {"ref": root, "dependsOn": []}
        dependencies.append(entry)
    entry.setdefault("dependsOn", []).append(native_root["bom-ref"])
    dependencies.extend(native.get("dependencies", []))
    tools = merged["metadata"].setdefault("tools", [])
    for tool in native["metadata"].get("tools", []):
        if tool not in tools:
            tools.append(tool)
    return merged


def reproducible(bom: Bom, epoch: str | None) -> Bom:
    """``bom`` with no random serial number and, when ``epoch`` (the value of
    ``SOURCE_DATE_EPOCH``) is set, its timestamp at that time: cargo-cyclonedx
    honours the variable, but ``uv export`` and ``npm sbom`` stamp the
    current time and a random serial."""
    bom = json.loads(json.dumps(bom))
    bom.pop("serialNumber", None)
    if epoch:
        moment = datetime.datetime.fromtimestamp(int(epoch), tz=datetime.timezone.utc)
        bom.setdefault("metadata", {})["timestamp"] = moment.strftime("%Y-%m-%dT%H:%M:%SZ")
    return bom


def structural_problems(bom: Bom) -> list[str]:
    """What the JSON schema does not check: unique references, and
    dependencies that name listed components."""
    problems: list[str] = []
    subject = bom.get("metadata", {}).get("component")
    if not subject or "bom-ref" not in subject:
        return ["metadata.component (the artifact the SBOM describes) is missing"]
    refs = [subject["bom-ref"]]
    stack = list(bom.get("components", []))
    while stack:
        component = stack.pop()
        if "bom-ref" in component:
            refs.append(component["bom-ref"])
        stack.extend(component.get("components", []))
    seen: set[str] = set()
    for ref in refs:
        if ref in seen:
            problems.append(f"bom-ref {ref!r} is not unique")
        seen.add(ref)
    for dependency in bom.get("dependencies", []):
        for ref in [dependency.get("ref"), *dependency.get("dependsOn", [])]:
            if ref not in seen:
                problems.append(f"dependency names {ref!r}, which no component has")
    return problems


def depends_on_something(bom: Bom) -> bool:
    """Whether the SBOM's subject depends on a listed component: true of
    every Rust artifact and of the wheel; the npm packages have no runtime
    dependency today."""
    subject = bom["metadata"]["component"]["bom-ref"]
    entry = next((d for d in bom.get("dependencies", []) if d.get("ref") == subject), None)
    return bool(bom.get("components")) and entry is not None and bool(entry.get("dependsOn"))


def _cargo_sboms(target: str, scratch: Path) -> Path:
    """Run cargo-cyclonedx for every workspace crate for ``target``; the
    directory its files were moved into, one per crate (``<dir>.json``)."""
    name = f"opentide-sbom-{target}"
    _run(
        [
            "cargo",
            "cyclonedx",
            "--manifest-path",
            str(ROOT / "Cargo.toml"),
            "--format",
            "json",
            "--spec-version",
            SPEC_VERSION,
            "--target",
            target,
            "--no-build-deps",
            "--override-filename",
            name,
            "-q",
        ]
    )
    out = scratch / target
    out.mkdir(parents=True)
    members = [ROOT / "bindings" / "python", ROOT / "xtask", *sorted(ROOT.glob("crates/*"))]
    for path in (member / f"{name}.json" for member in members):
        if not path.is_file():
            continue
        crate = path.parent.relative_to(ROOT).as_posix().replace("/", "__")
        shutil.move(str(path), out / f"{crate}.json")
    return out


def _check_dependencies(name: str, bom: Bom) -> None:
    if not depends_on_something(bom):
        raise SystemExit(f"sbom.py: {name} lists no dependency: the generator found nothing")


def _read(path: Path) -> Bom:
    return relative_refs(json.loads(path.read_text(encoding="utf-8")), ROOT)


def _write(path: Path, bom: Bom) -> None:
    bom = reproducible(bom, os.environ.get("SOURCE_DATE_EPOCH"))
    path.write_text(json.dumps(bom, indent=2) + "\n", encoding="utf-8")


def generate(out: Path, version: str | None = None) -> list[Path]:
    """Write every SBOM into ``out``; their paths."""
    out.mkdir(parents=True, exist_ok=True)
    written: list[Path] = []
    with tempfile.TemporaryDirectory() as tmp:
        scratch = Path(tmp)
        by_target: dict[str, Path] = {}
        for target in sorted({target for _, target, _ in RUST_SBOMS} | {"all"}):
            by_target[target] = _cargo_sboms(target, scratch)
        build_wasm = (ROOT / "scripts/engine/build-wasm.sh").read_text(encoding="utf-8")
        for crate, target, name in RUST_SBOMS:
            bom = _read(by_target[target] / f"{crate.replace('/', '__')}.json")
            if crate == "crates/opentide-wasm":
                bom = add_component(bom, wasi_libc_component(build_wasm))
            _check_dependencies(name, bom)
            _write(out / name, bom)
            written.append(out / name)
        python = json.loads(
            _run(
                [
                    "uv",
                    "export",
                    "--format",
                    "cyclonedx1.5",
                    "--frozen",
                    "--no-dev",
                    "--no-emit-project",
                    "--quiet",
                ]
            )
        )
        native = _read(by_target["all"] / f"{NATIVE}.json")
        resolved = wheel_version(version, ROOT)
        if resolved is None:
            raise SystemExit(
                "sbom.py: the wheel's version is unknown: pass --wheel-version "
                "(CI: `hatch version`) or build the package first (`uv sync`)"
            )
        wheel = merge_wheel(python, native, resolved)
        _check_dependencies("opentide-wheel.cdx.json", wheel)
        _write(out / "opentide-wheel.cdx.json", wheel)
        written.append(out / "opentide-wheel.cdx.json")
    for package in NPM_PACKAGES:
        text = _run(
            [
                "npm",
                "sbom",
                "--sbom-format",
                "cyclonedx",
                "--omit",
                "dev",
                "--package-lock-only",
            ],
            cwd=ROOT / "packages" / package,
        )
        path = out / f"opentide-{package}.cdx.json"
        _write(path, json.loads(text))
        written.append(path)
    return written


def validate(paths: list[Path]) -> int:
    """Check each SBOM against the CycloneDX schema and the structural rules;
    the exit status."""
    failed = 0
    for path in paths:
        bom = json.loads(path.read_text(encoding="utf-8"))
        problems = structural_problems(bom)
        if bom.get("specVersion") != SPEC_VERSION:
            problems.append(f"specVersion {bom.get('specVersion')!r}, not {SPEC_VERSION}")
        for problem in problems:
            print(f"{path}: {problem}", file=sys.stderr)
        failed += bool(problems)
    checker = (
        "import sys\n"
        "from cyclonedx.schema import SchemaVersion\n"
        "from cyclonedx.validation.json import JsonStrictValidator\n"
        "bad = 0\n"
        "for name in sys.argv[1:]:\n"
        "    with open(name, encoding='utf-8') as f:\n"
        "        error = JsonStrictValidator(SchemaVersion.V1_5).validate_str(f.read())\n"
        "    if error is not None:\n"
        "        print(f'{name}: {error}', file=sys.stderr)\n"
        "        bad += 1\n"
        "sys.exit(1 if bad else 0)\n"
    )
    schema = subprocess.run(
        ["uv", "run", "--no-project", "--quiet", "--with", VALIDATOR, "python", "-I", "-c", checker]
        + [str(path) for path in paths],
        check=False,
        env={**os.environ, "UV_NO_SYNC": "1"},
    )
    if schema.returncode != 0:
        failed += 1
    if failed:
        return 1
    print(f"{len(paths)} SBOMs valid (CycloneDX {SPEC_VERSION})")
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    sub = parser.add_subparsers(dest="command", required=True)
    gen = sub.add_parser("generate", help="write every SBOM into OUT_DIR")
    gen.add_argument("out", type=Path)
    gen.add_argument(
        "--wheel-version", help="the wheel's version (default: src/opentide/_version.py)"
    )
    val = sub.add_parser("validate", help="check SBOMs against CycloneDX 1.5")
    val.add_argument("files", type=Path, nargs="+")
    args = parser.parse_args(argv)
    if args.command == "generate":
        for path in generate(args.out, args.wheel_version):
            print(path)
        return 0
    return validate(args.files)


if __name__ == "__main__":
    raise SystemExit(main())
