"""Write the ATT&CK ids Sentinel accepts in ``configurations.sentinel.alert.techniques``.

Microsoft Sentinel is aligned to ATT&CK v18 (the "MITRE ATT&CK framework version"
section of Microsoft's "Understand security coverage by the MITRE ATT&CK
framework" page), while opentide's ``att&ck`` vocabulary follows the current
release. The Sentinel field therefore carries its own list, kept apart from the
vocabulary: every technique and sub-technique of the ATT&CK 18.1 Enterprise,
Mobile and ICS matrices that is neither revoked nor deprecated. 18.0 carries the
same ids, names and tactics, so the list is "v18" either way (#686).

So that ``validate`` can say what to write instead, the file also lists the ids
the ATT&CK release opentide's vocabulary pins (20.0) has and 18.1 does not, each
with the v18 ids it revoked in their favour (``T1685`` replaces ``T1562``,
``T1562.001`` and ``T1562.006``).

The list is generated from MITRE's STIX bundles into
``src/opentide/data/sentinel/attack-v18.json``::

    uv run python scripts/build/sync_sentinel_attack.py            # download and write
    uv run python scripts/build/sync_sentinel_attack.py --check    # exit 1 when it would change
    uv run python scripts/build/sync_sentinel_attack.py --stix-dir <attack-stix-data checkout>

``--stix-dir`` reads ``{domain}-attack/{domain}-attack-{18.1,20.0}.json`` from a local
checkout of mitre-attack/attack-stix-data instead of downloading them.
"""

from __future__ import annotations

import argparse
import json
import re
import sys
import tempfile
from pathlib import Path
from typing import Any
from urllib.request import Request, urlopen

from opentide.vocabulary.stix_attack import load_stix_bundle

ROOT = Path(__file__).resolve().parents[2]
OUTPUT = ROOT / "src" / "opentide" / "data" / "sentinel" / "attack-v18.json"
ATTACK_RELEASE = "18.1"
#: The release opentide's ``att&ck`` vocabulary pins (``att&ck::1.2``).
LATER_RELEASE = "20.0"
DOMAINS = ("enterprise", "mobile", "ics")
SOURCE = (
    "https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/"
    "{domain}-attack/{domain}-attack-{release}.json"
)
TECHNIQUE_ID = re.compile(r"^T\d{4}(\.\d{3})?$")


def _bundle_path(stix_dir: Path, domain: str, release: str) -> Path:
    return stix_dir / f"{domain}-attack" / f"{domain}-attack-{release}.json"


def _download(directory: Path) -> Path:
    for release in (ATTACK_RELEASE, LATER_RELEASE):
        for domain in DOMAINS:
            url = SOURCE.format(domain=domain, release=release)
            destination = _bundle_path(directory, domain, release)
            destination.parent.mkdir(parents=True, exist_ok=True)
            with urlopen(Request(url), timeout=300) as response:
                destination.write_bytes(response.read())
    return directory


def _mitre_id(obj: dict[str, Any]) -> str | None:
    for reference in obj.get("external_references") or []:
        if reference.get("source_name") == "mitre-attack" and reference.get("external_id"):
            return str(reference["external_id"])
    return None


def _active(stix_dir: Path, release: str) -> tuple[dict[str, str], dict[str, list[str]]]:
    """``({id: name}, {id: [ids it revoked]})`` for one release's three matrices.

    A sub-technique's name is prefixed with its parent's (``Modify Authentication
    Process: Conditional Access Policies``), as the ``att&ck`` vocabulary names them.
    """
    names: dict[str, str] = {}
    by_stix: dict[str, str] = {}
    revoked_by: list[tuple[str, str]] = []
    for domain in DOMAINS:
        for obj in load_stix_bundle(_bundle_path(stix_dir, domain, release)):
            if obj.get("type") == "relationship" and obj.get("relationship_type") == "revoked-by":
                revoked_by.append((str(obj["source_ref"]), str(obj["target_ref"])))
                continue
            if obj.get("type") != "attack-pattern":
                continue
            identifier = _mitre_id(obj)
            if identifier is None or not TECHNIQUE_ID.match(identifier):
                continue
            by_stix[str(obj["id"])] = identifier
            if obj.get("revoked") or obj.get("x_mitre_deprecated"):
                continue
            names.setdefault(identifier, str(obj["name"]).strip())
    labelled = {
        identifier: (
            f"{names[identifier.split('.')[0]]}: {name}"
            if "." in identifier and identifier.split(".")[0] in names
            else name
        )
        for identifier, name in names.items()
    }
    replaces: dict[str, list[str]] = {}
    for source, target in revoked_by:
        if source in by_stix and target in by_stix:
            replaces.setdefault(by_stix[target], []).append(by_stix[source])
    return dict(sorted(labelled.items())), replaces


def techniques(stix_dir: Path) -> dict[str, str]:
    """``{id: name}`` for the active ATT&CK 18.1 techniques and sub-techniques, sorted by id."""
    return _active(stix_dir, ATTACK_RELEASE)[0]


def later(stix_dir: Path, v18: dict[str, str]) -> dict[str, dict[str, Any]]:
    """The ids active in ATT&CK 20.0 but not in 18.1, with the v18 ids each replaces."""
    names, replaces = _active(stix_dir, LATER_RELEASE)
    return {
        identifier: {
            "name": name,
            "replaces": sorted({old for old in replaces.get(identifier, []) if old in v18}),
        }
        for identifier, name in names.items()
        if identifier not in v18
    }


def document(stix_dir: Path) -> str:
    """The data file's text."""
    payload = {
        "attack": ATTACK_RELEASE,
        "domains": list(DOMAINS),
        "source": SOURCE.replace("{release}", ATTACK_RELEASE),
        "generator": "scripts/build/sync_sentinel_attack.py",
        "techniques": (v18 := techniques(stix_dir)),
        "later": {"attack": LATER_RELEASE, "techniques": later(stix_dir, v18)},
    }
    return json.dumps(payload, indent=1, ensure_ascii=False) + "\n"


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--check", action="store_true", help="exit 1 when the file would change")
    parser.add_argument("--stix-dir", type=Path, help="a local attack-stix-data checkout")
    args = parser.parse_args(argv)
    with tempfile.TemporaryDirectory() as scratch:
        stix_dir = args.stix_dir or _download(Path(scratch))
        expected = document(stix_dir)
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
