"""Generate ATT&CK vocabulary TOML files from STIX bundles."""

from __future__ import annotations

from pathlib import Path
from typing import Any

from opentide.core.files import resolve_paths
from opentide.core.io import load_json
from opentide.core.time import utc_now_iso
from opentide.vocabulary.io import read_vocab_document, write_vocab_file
from opentide.vocabulary.stix_attack import (
    load_stix_bundle,
    merge_technique_bundles,
    parse_datasources,
    parse_groups,
    parse_mitigations,
)


def _resources_root() -> Path:
    paths = resolve_paths()
    return Path(paths["resources"])


def _vocab_dir() -> Path:
    paths = resolve_paths()
    return Path(paths["vocabularies"])


def _resolve_vocab_dir(vocab_dir: Path | None) -> Path:
    return vocab_dir if vocab_dir is not None else _vocab_dir()


def _stix_dir() -> Path:
    return _resources_root() / "attack" / "stix"


def _manifest() -> dict[str, Any]:
    manifest_path = _stix_dir() / "manifest.json"
    if manifest_path.is_file():
        return load_json(manifest_path)
    return {}


def _load_template(field: str, *, vocab_dir: Path | None = None) -> dict[str, Any]:
    output_dir = _resolve_vocab_dir(vocab_dir)
    path = output_dir / f"{field}.vocab.toml"
    if path.is_file():
        doc = read_vocab_document(path)
        doc["keys"] = []
        return doc
    yaml_legacy = output_dir / f"{field}.yaml"
    if yaml_legacy.is_file():
        import yaml

        doc = yaml.safe_load(yaml_legacy.read_text(encoding="utf-8"))
        doc["keys"] = []
        return doc
    raise FileNotFoundError(f"No vocabulary template for field '{field}'")


def _stamp_source(doc: dict[str, Any], manifest: dict[str, Any]) -> None:
    doc["source"] = "mitre-attack"
    doc["source_version"] = manifest.get("version", "unknown")
    doc["source_fetched_at"] = manifest.get("fetched_at") or utc_now_iso()


def generate_attack_vocabs(*, fetch: bool = False, vocab_dir: Path | None = None) -> dict[str, int]:
    """Regenerate ATT&CK-related vocabulary files from STIX."""
    if fetch:
        from opentide.vocabulary.fetch_stix import fetch_latest_attack_stix

        fetch_latest_attack_stix(_stix_dir())

    manifest = _manifest()
    stix_dir = _stix_dir()
    output_dir = _resolve_vocab_dir(vocab_dir)
    counts: dict[str, int] = {}

    enterprise = stix_dir / "enterprise-attack.json"
    mobile = stix_dir / "mobile-attack.json"
    ics = stix_dir / "ics-attack.json"

    if not enterprise.is_file():
        raise FileNotFoundError(
            f"STIX bundle not found: {enterprise}. Run fetch_attack_stix first."
        )

    techniques_doc = _load_template("att&ck", vocab_dir=output_dir)
    techniques_doc["key"] = "id"
    techniques_doc.pop("model", None)
    bundles = [(enterprise, "")]
    if mobile.is_file():
        bundles.append((mobile, "Mobile"))
    if ics.is_file():
        bundles.append((ics, "Industrial"))
    techniques_doc["keys"] = merge_technique_bundles(bundles)
    _stamp_source(techniques_doc, manifest)
    write_vocab_file(output_dir / "att&ck.vocab.toml", techniques_doc)
    counts["att&ck"] = len(techniques_doc["keys"])

    groups_doc = _load_template("att&ck.groups", vocab_dir=output_dir)
    groups_doc["key"] = "id"
    groups_doc.pop("model", None)
    all_groups: list[dict[str, Any]] = []
    for path, prefix in [(enterprise, ""), (ics, "ICS"), (mobile, "Mobile")]:
        if path.is_file():
            all_groups.extend(parse_groups(load_stix_bundle(path), prefix=prefix))
    groups_doc["keys"] = all_groups
    _stamp_source(groups_doc, manifest)
    write_vocab_file(output_dir / "att&ck.groups.vocab.toml", groups_doc)
    counts["att&ck.groups"] = len(all_groups)

    mitigations_doc = _load_template("mitigations", vocab_dir=output_dir)
    mitigations_doc["key"] = "name"
    all_mitigations: list[dict[str, Any]] = []
    for path, prefix in [(enterprise, ""), (mobile, "Mobile"), (ics, "Industrial")]:
        if path.is_file():
            all_mitigations.extend(parse_mitigations(load_stix_bundle(path), prefix=prefix))
    mitigations_doc["keys"] = all_mitigations
    _stamp_source(mitigations_doc, manifest)
    write_vocab_file(output_dir / "mitigations.vocab.toml", mitigations_doc)
    counts["mitigations"] = len(all_mitigations)

    datasources_doc = _load_template("datasources", vocab_dir=output_dir)
    datasources_doc["key"] = "name"
    datasources_doc["keys"] = parse_datasources(load_stix_bundle(enterprise))
    _stamp_source(datasources_doc, manifest)
    write_vocab_file(output_dir / "datasources.vocab.toml", datasources_doc)
    counts["datasources"] = len(datasources_doc["keys"])

    return counts
