#!/usr/bin/env python3
"""Synchronize bundled vocabularies and schema pins from OpenTide specifications."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import shutil
import subprocess
from dataclasses import dataclass
from pathlib import Path

from opentide.core.io import load_toml

SPECIFICATIONS_ENV = "OPENTIDE_SPECIFICATIONS_ROOT"
BASELINE_SHA = "baseline-bundled-state"
#: Lockfile keys that record provenance only. ``--check`` compares content digests, so a
#: lockfile synced from a specifications clone still passes where no clone exists (CI).
PROVENANCE_KEYS = frozenset({"specifications_git_sha"})

#: ``[schema::M.m]`` section -> dot-path -> ``field::M.m`` contract.
PinTables = dict[str, dict[str, str]]


@dataclass(frozen=True)
class SyncPaths:
    """Paths used by vocabulary synchronization."""

    source_vocabulary_dir: Path
    target_vocabulary_dir: Path
    source_pins_dir: Path
    target_pins_dir: Path
    lockfile_path: Path
    specifications_root: Path


def _repo_root() -> Path:
    return Path(__file__).resolve().parents[2]


def default_paths() -> SyncPaths:
    """Build default synchronization paths from environment/repository layout."""
    repo_root = _repo_root()
    specifications_root = Path(
        os.environ.get(SPECIFICATIONS_ENV, str(repo_root.parent / "specifications"))
    ).expanduser()
    return SyncPaths(
        source_vocabulary_dir=specifications_root / "vocabularies",
        target_vocabulary_dir=repo_root / "src" / "opentide" / "data" / "vocabulary",
        source_pins_dir=specifications_root / "schemas" / "pins",
        target_pins_dir=repo_root / "src" / "opentide" / "data" / "pins",
        lockfile_path=repo_root / "data" / "specifications.lock.json",
        specifications_root=specifications_root,
    )


def list_vocab_files(directory: Path) -> dict[str, Path]:
    """Return mapping of vocab filename -> absolute path."""
    if not directory.is_dir():
        return {}
    files = sorted(
        path for path in directory.iterdir() if path.is_file() and path.name.endswith(".vocab.toml")
    )
    return {path.name: path for path in files}


def vocabulary_digest(file_map: dict[str, Path]) -> str:
    """Return stable digest for vocabulary filenames and file contents."""
    digest = hashlib.sha256()
    for name in sorted(file_map):
        digest.update(name.encode("utf-8"))
        digest.update(b"\0")
        digest.update(file_map[name].read_bytes())
        digest.update(b"\0")
    return digest.hexdigest()


def list_pin_files(directory: Path) -> dict[str, Path]:
    """Return mapping of schema pin filename -> absolute path."""
    if not directory.is_dir():
        return {}
    files = sorted(
        path for path in directory.iterdir() if path.is_file() and path.suffix == ".toml"
    )
    return {path.name: path for path in files}


def load_pin_tables(path: Path) -> PinTables:
    """Return the pin tables of one file the way ``opentide.models.vocab_pins`` reads them."""
    return {
        str(section): {str(key): str(value) for key, value in pins.items()}
        for section, pins in load_toml(path).items()
        if isinstance(pins, dict)
    }


def pin_tables_digest(file_map: dict[str, Path]) -> str:
    """Return stable digest of parsed pin tables; comments and layout do not count."""
    tables = {name: load_pin_tables(path) for name, path in file_map.items()}
    return hashlib.sha256(json.dumps(tables, sort_keys=True).encode("utf-8")).hexdigest()


def diff_pin_tables(source: PinTables, target: PinTables) -> list[str]:
    """Describe how bundled pin tables (*target*) differ from specifications (*source*)."""
    problems = [
        f"[{section}] schema revision missing in bundled pins"
        for section in sorted(source.keys() - target.keys())
    ]
    problems.extend(
        f"[{section}] schema revision not in specifications"
        for section in sorted(target.keys() - source.keys())
    )
    for section in sorted(source.keys() & target.keys()):
        expected, actual = source[section], target[section]
        for key in sorted(expected.keys() | actual.keys()):
            if key not in actual:
                problems.append(f"[{section}] {key}: missing (specifications pins {expected[key]})")
            elif key not in expected:
                problems.append(
                    f"[{section}] {key}: not in specifications (bundled pins {actual[key]})"
                )
            elif expected[key] != actual[key]:
                problems.append(
                    f"[{section}] {key}: bundled {actual[key]}, specifications {expected[key]}"
                )
    return problems


@dataclass(frozen=True)
class PinDrift:
    """Pin files missing from, extra in, or semantically different in the bundle."""

    missing: list[str]
    extra: list[str]
    changed: dict[str, list[str]]

    def __bool__(self) -> bool:
        return bool(self.missing or self.extra or self.changed)


def pin_drift(source: dict[str, Path], target: dict[str, Path]) -> PinDrift:
    """Compare bundled pin files against specifications pin files table by table."""
    changed: dict[str, list[str]] = {}
    for name in sorted(source.keys() & target.keys()):
        problems = diff_pin_tables(load_pin_tables(source[name]), load_pin_tables(target[name]))
        if problems:
            changed[name] = problems
    return PinDrift(
        missing=sorted(source.keys() - target.keys()),
        extra=sorted(target.keys() - source.keys()),
        changed=changed,
    )


def resolve_specifications_sha(specifications_root: Path) -> str | None:
    """Resolve git SHA for a local specifications clone."""
    try:
        result = subprocess.run(
            ["git", "-C", str(specifications_root), "rev-parse", "HEAD"],
            check=True,
            capture_output=True,
            text=True,
        )
    except (subprocess.SubprocessError, FileNotFoundError):
        return None
    sha = result.stdout.strip()
    return sha if sha else None


def load_lockfile(lockfile_path: Path) -> dict[str, object] | None:
    """Read lockfile JSON if present."""
    if not lockfile_path.is_file():
        return None
    try:
        return json.loads(lockfile_path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        raise ValueError(f"Invalid lockfile JSON: {lockfile_path} ({exc})") from exc


def make_lock_payload(
    *,
    specifications_sha: str,
    bundled_digest: str,
    managed_files: list[str],
    pins_digest: str,
    managed_pin_files: list[str],
) -> dict[str, object]:
    """Construct lockfile payload."""
    return {
        "lock_version": 2,
        "specifications_repo": "OpenTideHQ/specifications",
        "specifications_git_sha": specifications_sha,
        "source_glob": "vocabularies/*.vocab.toml",
        "bundled_vocabulary_sha256": bundled_digest,
        "managed_files": managed_files,
        "pins_source_glob": "schemas/pins/*.toml",
        "bundled_pins_sha256": pins_digest,
        "managed_pin_files": managed_pin_files,
    }


def lock_matches(current: dict[str, object] | None, expected: dict[str, object]) -> bool:
    """Return whether the lockfile content matches, ignoring provenance keys."""
    if current is None:
        return False

    def content(lock: dict[str, object]) -> dict[str, object]:
        return {key: value for key, value in lock.items() if key not in PROVENANCE_KEYS}

    return content(current) == content(expected)


def write_lockfile(lockfile_path: Path, payload: dict[str, object]) -> None:
    """Write normalized lockfile JSON."""
    lockfile_path.parent.mkdir(parents=True, exist_ok=True)
    lockfile_path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def _report_drift(*, missing: list[str], extra: list[str], changed: list[str]) -> None:
    if not (missing or extra or changed):
        return
    print("Vocabulary drift detected:")
    if missing:
        print("  Missing in bundled data:")
        for name in missing:
            print(f"    - {name}")
    if extra:
        print("  Extra in bundled data:")
        for name in extra:
            print(f"    - {name}")
    if changed:
        print("  Content mismatch:")
        for name in changed:
            print(f"    - {name}")


def _report_pin_drift(drift: PinDrift) -> None:
    if not drift:
        return
    print("Pin drift detected:")
    if drift.missing:
        print("  Missing in bundled pins:")
        for name in drift.missing:
            print(f"    - {name}")
    if drift.extra:
        print("  Extra in bundled pins:")
        for name in drift.extra:
            print(f"    - {name}")
    for name, problems in drift.changed.items():
        print(f"  {name}:")
        for problem in problems:
            print(f"    - {problem}")


def _sync_pins(*, source: dict[str, Path], target_dir: Path, drift: PinDrift) -> None:
    """Copy specifications pins over the bundle; files that only differ in layout stay."""
    target_dir.mkdir(parents=True, exist_ok=True)
    for name in drift.missing:
        shutil.copy2(source[name], target_dir / name)
        print(f"Copied pins/{name}")
    for name in drift.changed:
        shutil.copy2(source[name], target_dir / name)
        print(f"Updated pins/{name}")
    for name in drift.extra:
        (target_dir / name).unlink()
        print(f"Removed pins/{name}")


def _sync_from_source(
    *,
    source: dict[str, Path],
    target: dict[str, Path],
    target_dir: Path,
) -> None:
    target_dir.mkdir(parents=True, exist_ok=True)
    source_names = set(source)
    target_names = set(target)
    for name in sorted(source_names - target_names):
        shutil.copy2(source[name], target_dir / name)
        print(f"Copied {name}")
    for name in sorted(source_names & target_names):
        if source[name].read_bytes() != target[name].read_bytes():
            shutil.copy2(source[name], target_dir / name)
            print(f"Updated {name}")
    for name in sorted(target_names - source_names):
        (target_dir / name).unlink()
        print(f"Removed {name}")


def sync_vocabularies(
    *,
    paths: SyncPaths,
    check: bool,
    specifications_sha: str | None = None,
) -> int:
    """Synchronize vocabularies and schema pins and maintain the lockfile.

    When source vocabularies are unavailable, falls back to checking/writing a lockfile
    against the currently bundled vocabularies and pins.
    """

    source_files = list_vocab_files(paths.source_vocabulary_dir)
    target_files = list_vocab_files(paths.target_vocabulary_dir)
    target_pins = list_pin_files(paths.target_pins_dir)

    if source_files:
        source_pins = list_pin_files(paths.source_pins_dir)
        if not source_pins:
            # Syncing against an empty pin directory would delete every bundled pin.
            print(f"Specifications schema pins not found at {paths.source_pins_dir}.")
            return 1
        pins = pin_drift(source_pins, target_pins)
        source_names = set(source_files)
        target_names = set(target_files)
        missing = sorted(source_names - target_names)
        extra = sorted(target_names - source_names)
        changed = sorted(
            name
            for name in (source_names & target_names)
            if source_files[name].read_bytes() != target_files[name].read_bytes()
        )
        drift = bool(missing or extra or changed)
        source_digest = vocabulary_digest(source_files)
        sha = (
            specifications_sha
            or resolve_specifications_sha(paths.specifications_root)
            or BASELINE_SHA
        )
        payload = make_lock_payload(
            specifications_sha=sha,
            bundled_digest=source_digest,
            managed_files=sorted(source_files),
            pins_digest=pin_tables_digest(source_pins),
            managed_pin_files=sorted(source_pins),
        )
        current_lock = load_lockfile(paths.lockfile_path)

        if check:
            if drift or pins:
                _report_drift(missing=missing, extra=extra, changed=changed)
                _report_pin_drift(pins)
                return 1
            if not lock_matches(current_lock, payload):
                print("Lockfile drift detected. Re-run sync to update:")
                print(f"  {paths.lockfile_path}")
                return 1
            print("Vocabulary sync check passed (source, pins and lockfile are in sync).")
            return 0

        if drift:
            _sync_from_source(
                source=source_files,
                target=target_files,
                target_dir=paths.target_vocabulary_dir,
            )
        else:
            print("Bundled vocabularies already match source.")
        if pins:
            _sync_pins(source=source_pins, target_dir=paths.target_pins_dir, drift=pins)
        else:
            print("Bundled schema pins already match source.")
        write_lockfile(paths.lockfile_path, payload)
        print(f"Wrote lockfile: {paths.lockfile_path}")
        return 0

    print(
        "Specifications source not found at "
        f"{paths.source_vocabulary_dir} (set {SPECIFICATIONS_ENV} to override)."
    )
    target_digest = vocabulary_digest(target_files)
    payload = make_lock_payload(
        specifications_sha=BASELINE_SHA,
        bundled_digest=target_digest,
        managed_files=sorted(target_files),
        pins_digest=pin_tables_digest(target_pins),
        managed_pin_files=sorted(target_pins),
    )
    current_lock = load_lockfile(paths.lockfile_path)

    if check:
        if not lock_matches(current_lock, payload):
            print("Bundled vocabulary or pin lockfile drift detected.")
            print(f"Expected lockfile at: {paths.lockfile_path}")
            return 1
        print("Vocabulary lockfile matches bundled vocabularies and pins.")
        return 0

    write_lockfile(paths.lockfile_path, payload)
    print(f"Wrote baseline lockfile from bundled state: {paths.lockfile_path}")
    return 0


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description=(
            "Sync bundled vocabulary TOML files from specifications/vocabularies and "
            "schema pins from specifications/schemas/pins, or validate drift with --check."
        )
    )
    parser.add_argument(
        "--check",
        action="store_true",
        help="Check for drift and return non-zero when out of sync.",
    )
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    return sync_vocabularies(paths=default_paths(), check=args.check)


if __name__ == "__main__":
    raise SystemExit(main())
