"""Fetch ATT&CK + MISP, regenerate versioned vocabs, and sync the bundle.

New keys open a minor contract (``actors::1.2``). The ingest never moves a
schema pin: a shipped revision keeps the contracts it pins, and adopting a new
one is a new schema revision (``threat::1.1``), made by hand in specifications.
"""

from __future__ import annotations

import argparse
import os
import subprocess
import sys
from dataclasses import dataclass, field
from pathlib import Path

from opentide.models.vocab_pins import pin_data_dir
from opentide.vocabulary.generate_actors import generate_actors_vocabs
from opentide.vocabulary.generate_attack import GenerateReport, generate_attack_vocabs
from opentide.vocabulary.pins import vocab_fields_in_pin_directories

SPECIFICATIONS_ENV = "OPENTIDE_SPECIFICATIONS_ROOT"


@dataclass
class SyncReport:
    """Aggregate result of an upstream vocabulary ingest."""

    attack: GenerateReport
    actors: GenerateReport
    new_contracts: dict[str, str] = field(default_factory=dict)
    wrote: bool = False

    @property
    def dirty(self) -> bool:
        return self.attack.dirty or self.actors.dirty

    def summary_lines(self) -> list[str]:
        lines: list[str] = []
        for name, report in ("attack", self.attack), ("actors", self.actors):
            lines.append(f"{name}:")
            for vocab_field, lifecycle in report.lifecycles.items():
                lines.append(
                    f"  {vocab_field}: {len(lifecycle.keys)} keys "
                    f"(+{len(lifecycle.added)} ~{len(lifecycle.updated)} "
                    f"-{len(lifecycle.removed)} backfill={len(lifecycle.backfilled)})"
                )
                if lifecycle.new_contract:
                    lines.append(f"    new contract {vocab_field}::{lifecycle.new_contract}")
            if report.source_changed:
                lines.append(f"  source provenance changed ({name})")
        if self.new_contracts:
            opened = ", ".join(
                f"{key}::{value}" for key, value in sorted(self.new_contracts.items())
            )
            lines.append(f"unpinned contracts: {opened} (adopting one is a new schema revision)")
        return lines


def _repo_root() -> Path:
    return Path(__file__).resolve().parents[3]


def specifications_root() -> Path:
    """Resolve the specifications clone (env or sibling directory)."""
    configured = os.environ.get(SPECIFICATIONS_ENV, str(_repo_root().parent / "specifications"))
    return Path(configured).expanduser().resolve()


def _sync_bundled_vocabularies(root: Path) -> None:
    sync_script = _repo_root() / "scripts" / "build" / "sync_vocabularies.py"
    env = os.environ.copy()
    env[SPECIFICATIONS_ENV] = str(root)
    subprocess.run([sys.executable, str(sync_script)], check=True, env=env)


def pin_directories(root: Path) -> list[Path]:
    """Pin file locations in specifications (canonical) and the opentide bundle."""
    return [root / "schemas" / "pins", pin_data_dir()]


def _schema_pinned_versions(
    new_contracts: dict[str, str], directories: list[Path]
) -> dict[str, str]:
    """Keep new contracts for vocab fields that appear in schema pin files.

    Catalog vocabs such as ``att&ck.groups`` and ``mitigations`` have no
    ``field::M.m`` pin. ATT&CK groups still version-gate live objects through
    ``threat.actors.name`` → ``actors::*`` after ``generate_actors`` merges STIX
    intrusion-sets into ``actors``.
    """
    pinned_fields = vocab_fields_in_pin_directories(directories)
    if not pinned_fields:
        return new_contracts
    return {field: version for field, version in new_contracts.items() if field in pinned_fields}


def sync_upstream(
    *,
    fetch: bool = True,
    apply: bool = False,
    misp_url: str | None = None,
    specifications: Path | None = None,
) -> SyncReport:
    """Fetch upstream datasets, merge vocabs, and optionally write them; pins stay."""
    root = specifications if specifications is not None else specifications_root()
    vocab_dir = root / "vocabularies"
    attack = generate_attack_vocabs(fetch=fetch, vocab_dir=vocab_dir, write=False)
    actors = generate_actors_vocabs(misp_url=misp_url, vocab_dir=vocab_dir, write=False)
    new_contracts = dict(attack.new_contracts)
    new_contracts.update(actors.new_contracts)
    report = SyncReport(
        attack=attack,
        actors=actors,
        new_contracts=_schema_pinned_versions(new_contracts, pin_directories(root)),
    )
    if not (apply and report.dirty):
        return report

    generate_attack_vocabs(fetch=False, vocab_dir=vocab_dir, write=True)
    generate_actors_vocabs(misp_url=misp_url, vocab_dir=vocab_dir, write=True)
    _sync_bundled_vocabularies(root)
    report.wrote = True
    return report


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description=(
            "Fetch the latest MITRE ATT&CK STIX release and MISP threat-actor galaxy, "
            "merge them into specifications vocabularies with per-key versions, "
            "and sync the opentide bundle. Schema pins never move."
        )
    )
    parser.add_argument(
        "--check",
        action="store_true",
        help="Compute the ingest without writing; exit 1 when vocabularies would change.",
    )
    parser.add_argument(
        "--apply",
        action="store_true",
        help="Write vocabularies and refresh the bundled copy + lockfile.",
    )
    parser.add_argument(
        "--no-fetch",
        action="store_true",
        help="Reuse STIX already on disk instead of downloading the latest release.",
    )
    parser.add_argument("--misp-url", default=None, help="Override MISP galaxy URL")
    return parser.parse_args(argv)


def cli_main(argv: list[str] | None = None) -> int:
    """CLI entry used by ``scripts/vocabulary/sync_upstream.py``."""
    args = parse_args(argv)
    if args.check and args.apply:
        print("ERROR: use either --check or --apply, not both", file=sys.stderr)
        return 2
    report = sync_upstream(
        fetch=not args.no_fetch,
        apply=args.apply,
        misp_url=args.misp_url,
    )
    for line in report.summary_lines():
        print(line)
    if args.apply:
        print("wrote" if report.wrote else "no changes to write")
        return 0
    if report.dirty:
        print("Upstream vocabulary ingest would change files. Re-run with --apply.")
        return 1
    print("Already up to date.")
    return 0
