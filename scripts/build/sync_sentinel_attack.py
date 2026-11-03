"""Write the ATT&CK ids Sentinel accepts in ``configurations.sentinel.alert.techniques``.

Microsoft Sentinel is aligned to ATT&CK v18 (the "MITRE ATT&CK framework version"
section of Microsoft's "Understand security coverage by the MITRE ATT&CK
framework" page), while opentide's ``att&ck`` vocabulary follows the current
release. The Sentinel field therefore carries its own list, kept apart from the
vocabulary: every technique and sub-technique of the ATT&CK 18.1 Enterprise,
Mobile and ICS matrices that is neither revoked nor deprecated. 18.0 carries the
same ids, names and tactics, so the list is "v18" either way (#686).

So that ``validate`` can say what to write instead, the file also lists:

- ``later``: the ids of the release the ``att&ck`` vocabulary pins (its
  ``source_version``) that 18.1 does not have, each with the v18 ids revoked in
  its favour (``T1685`` replaces ``T1562``, ``T1562.001`` and ``T1562.006``);
- ``retired``: the ids 18.1 lists as revoked or deprecated, each with the v18 ids
  that replace it (``T1086``, PowerShell, is ``T1059.001``) or none.

Revocations are followed through every hop, so an id revoked twice still names
its v18 counterpart. The list is generated from MITRE's STIX bundles into
``src/opentide/data/sentinel/attack-v18.json``::

    uv run python scripts/build/sync_sentinel_attack.py            # download and write
    uv run python scripts/build/sync_sentinel_attack.py --check    # exit 1 when it would change
    uv run python scripts/build/sync_sentinel_attack.py --stix-dir <attack-stix-data checkout>

``--stix-dir`` reads ``{domain}-attack/{domain}-attack-{release}.json`` from a local
checkout of mitre-attack/attack-stix-data instead of downloading them.
"""

from __future__ import annotations

import argparse
import json
import re
import sys
import tempfile
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any
from urllib.request import Request, urlopen

from opentide.vocabulary.stix_attack import _mitre_external_id, load_stix_bundle

if sys.version_info >= (3, 11):
    import tomllib
else:  # pragma: no cover - Python 3.10
    import tomli as tomllib

ROOT = Path(__file__).resolve().parents[2]
OUTPUT = ROOT / "src" / "opentide" / "data" / "sentinel" / "attack-v18.json"
VOCABULARY = ROOT / "src" / "opentide" / "data" / "vocabulary" / "att&ck.vocab.toml"
ATTACK_RELEASE = "18.1"
DOMAINS = ("enterprise", "mobile", "ics")
SOURCE = (
    "https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/"
    "{domain}-attack/{domain}-attack-{release}.json"
)
TECHNIQUE_ID = re.compile(r"^T\d{4}(\.\d{3})?$")


def vocabulary_release() -> str:
    """The ATT&CK release the bundled ``att&ck`` vocabulary was generated from."""
    data = tomllib.loads(VOCABULARY.read_text(encoding="utf-8"))
    return str(data["source_version"])


@dataclass
class Release:
    """One ATT&CK release's techniques across the three matrices."""

    names: dict[str, str] = field(default_factory=dict)
    """Active ids to their names, a sub-technique's prefixed with its parent's."""
    retired: dict[str, str] = field(default_factory=dict)
    """Revoked or deprecated ids to their names."""
    revoked_by: dict[str, set[str]] = field(default_factory=dict)
    """Each revoked id to the ids its revoked-by relationships name."""

    def successors(self, identifier: str) -> list[str]:
        """The active ids *identifier* was revoked in favour of, through every hop."""
        found: set[str] = set()
        seen: set[str] = set()
        todo = [identifier]
        while todo:
            current = todo.pop()
            if current in seen:
                continue
            seen.add(current)
            if current in self.names and current != identifier:
                found.add(current)
                continue
            todo.extend(self.revoked_by.get(current, ()))
        return sorted(found)


def _bundle_path(stix_dir: Path, domain: str, release: str) -> Path:
    return stix_dir / f"{domain}-attack" / f"{domain}-attack-{release}.json"


def _download(directory: Path, releases: tuple[str, ...]) -> Path:
    for release in releases:
        for domain in DOMAINS:
            url = SOURCE.format(domain=domain, release=release)
            destination = _bundle_path(directory, domain, release)
            destination.parent.mkdir(parents=True, exist_ok=True)
            with urlopen(Request(url), timeout=300) as response:
                destination.write_bytes(response.read())
    return directory


def load_release(stix_dir: Path, release: str) -> Release:
    """Read one release's Enterprise, Mobile and ICS bundles."""
    loaded = Release()
    by_stix: dict[str, str] = {}
    relationships: list[tuple[str, str]] = []
    raw_names: dict[str, str] = {}
    for domain in DOMAINS:
        for obj in load_stix_bundle(_bundle_path(stix_dir, domain, release)):
            if obj.get("type") == "relationship" and obj.get("relationship_type") == "revoked-by":
                relationships.append((str(obj["source_ref"]), str(obj["target_ref"])))
                continue
            if obj.get("type") != "attack-pattern":
                continue
            identifier = _mitre_external_id(obj)
            if identifier is None or not TECHNIQUE_ID.match(identifier):
                continue
            by_stix[str(obj["id"])] = identifier
            name = str(obj.get("name", "")).strip()
            if obj.get("revoked") or obj.get("x_mitre_deprecated"):
                loaded.retired.setdefault(identifier, name)
            else:
                raw_names.setdefault(identifier, name)
    for identifier, name in raw_names.items():
        parent = identifier.split(".")[0]
        if "." in identifier and parent in raw_names:
            name = f"{raw_names[parent]}: {name}"
        loaded.names[identifier] = name
    # An id can be both active in one matrix and retired in another; active wins.
    loaded.retired = {k: v for k, v in loaded.retired.items() if k not in loaded.names}
    for source, target in relationships:
        if source in by_stix and target in by_stix:
            loaded.revoked_by.setdefault(by_stix[source], set()).add(by_stix[target])
    loaded.names = dict(sorted(loaded.names.items()))
    return loaded


def document(stix_dir: Path, later_release: str) -> str:
    """The data file's text."""
    v18 = load_release(stix_dir, ATTACK_RELEASE)
    later = load_release(stix_dir, later_release)
    # For each later id, the v18 ids whose revocation chain (in the later release) ends at it.
    replaces: dict[str, set[str]] = {}
    for old in v18.names:
        for new in later.successors(old):
            replaces.setdefault(new, set()).add(old)
    payload: dict[str, Any] = {
        "attack": ATTACK_RELEASE,
        "domains": list(DOMAINS),
        "source": SOURCE.replace("{release}", ATTACK_RELEASE),
        "generator": "scripts/build/sync_sentinel_attack.py",
        "techniques": v18.names,
        "retired": {
            identifier: {
                "name": name,
                "replaced_by": [new for new in v18.successors(identifier) if new in v18.names],
            }
            for identifier, name in sorted(v18.retired.items())
        },
        "later": {
            "attack": later_release,
            "techniques": {
                identifier: {"name": name, "replaces": sorted(replaces.get(identifier, ()))}
                for identifier, name in later.names.items()
                if identifier not in v18.names
            },
        },
    }
    return json.dumps(payload, indent=1, ensure_ascii=False) + "\n"


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--check", action="store_true", help="exit 1 when the file would change")
    parser.add_argument("--stix-dir", type=Path, help="a local attack-stix-data checkout")
    args = parser.parse_args(argv)
    later_release = vocabulary_release()
    with tempfile.TemporaryDirectory() as scratch:
        stix_dir = args.stix_dir or _download(Path(scratch), (ATTACK_RELEASE, later_release))
        expected = document(stix_dir, later_release)
    current = OUTPUT.read_text(encoding="utf-8") if OUTPUT.exists() else ""
    if args.check:
        if current != expected:
            print(f"error: {OUTPUT.relative_to(ROOT)} is stale", file=sys.stderr)
            print("  help: uv run python scripts/build/sync_sentinel_attack.py", file=sys.stderr)
            return 1
        print(f"{OUTPUT.relative_to(ROOT)} is current")
        return 0
    OUTPUT.parent.mkdir(parents=True, exist_ok=True)
    OUTPUT.write_text(expected, encoding="utf-8", newline="\n")
    count = len(json.loads(expected)["techniques"])
    print(f"wrote {OUTPUT.relative_to(ROOT)} ({count} ids, ATT&CK {ATTACK_RELEASE})")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
