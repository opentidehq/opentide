"""Generate ATT&CK vocabulary TOML files from STIX bundles."""

from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from opentide.core.files import resolve_paths
from opentide.core.io import load_json
from opentide.core.time import utc_now_iso
from opentide.vocabulary.io import read_vocab_document, write_vocab_file
from opentide.vocabulary.lifecycle import LifecycleResult, merge_vocab_keys
from opentide.vocabulary.stix_attack import (
    load_stix_bundle,
    merge_technique_bundles,
    parse_datasources,
    parse_groups,
    parse_mitigations,
)

STIX_DIR_ENV = "OPENTIDE_ATTACK_STIX_DIR"


@dataclass(frozen=True)
class GenerateReport:
    """Per-field lifecycle results from a vocabulary generation run."""

    lifecycles: dict[str, LifecycleResult]
    source_changed: bool = False

    @property
    def counts(self) -> dict[str, int]:
        return {field: len(result.keys) for field, result in self.lifecycles.items()}

    @property
    def pin_versions(self) -> dict[str, str]:
        """Field → new minor contract for fields that opened a pin bump."""
        versions: dict[str, str] = {}
        for field, result in self.lifecycles.items():
            contract = result.pin_contract
            if contract is not None:
                versions[field] = contract
        return versions

    @property
    def dirty(self) -> bool:
        return self.source_changed or any(result.dirty for result in self.lifecycles.values())


def _resources_root() -> Path:
    paths = resolve_paths()
    return Path(paths["resources"])


def _vocab_dir() -> Path:
    paths = resolve_paths()
    return Path(paths["vocabularies"])


def _resolve_vocab_dir(vocab_dir: Path | None) -> Path:
    return vocab_dir if vocab_dir is not None else _vocab_dir()


def _stix_dir() -> Path:
    override = os.environ.get(STIX_DIR_ENV)
    if override:
        return Path(override).expanduser().resolve()
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
        doc.setdefault("keys", [])
        if doc["keys"] is None:
            doc["keys"] = []
        return doc
    yaml_legacy = output_dir / f"{field}.yaml"
    if yaml_legacy.is_file():
        import yaml

        doc = yaml.safe_load(yaml_legacy.read_text(encoding="utf-8"))
        if not isinstance(doc, dict):
            doc = {}
        doc.setdefault("keys", [])
        if doc["keys"] is None:
            doc["keys"] = []
        return doc
    raise FileNotFoundError(f"No vocabulary template for field '{field}'")


def _stamp_source(doc: dict[str, Any], manifest: dict[str, Any]) -> None:
    doc.pop("version", None)
    doc["source"] = "mitre-attack"
    doc["source_version"] = manifest.get("version", "unknown")
    doc["source_fetched_at"] = manifest.get("fetched_at") or utc_now_iso()


def _merge_and_write(
    *,
    key_field: str,
    existing: list[dict[str, Any]],
    upstream: list[dict[str, Any]],
    doc: dict[str, Any],
    output_path: Path,
    manifest: dict[str, Any],
    write: bool,
) -> LifecycleResult:
    lifecycle = merge_vocab_keys(existing, upstream, key_field=key_field)
    doc["keys"] = list(lifecycle.keys)
    _stamp_source(doc, manifest)
    if write:
        write_vocab_file(output_path, doc)
    return lifecycle


def generate_attack_vocabs(
    *,
    fetch: bool = False,
    vocab_dir: Path | None = None,
    write: bool = True,
) -> GenerateReport:
    """Regenerate ATT&CK-related vocabulary files from STIX with per-key lifecycle."""
    if fetch:
        from opentide.vocabulary.fetch_stix import fetch_latest_attack_stix

        fetch_latest_attack_stix(_stix_dir())

    manifest = _manifest()
    stix_dir = _stix_dir()
    output_dir = _resolve_vocab_dir(vocab_dir)
    lifecycles: dict[str, LifecycleResult] = {}

    enterprise = stix_dir / "enterprise-attack.json"
    mobile = stix_dir / "mobile-attack.json"
    ics = stix_dir / "ics-attack.json"

    if not enterprise.is_file():
        raise FileNotFoundError(
            f"STIX bundle not found: {enterprise}. Run fetch_attack_stix first."
        )

    techniques_doc = _load_template("att&ck", vocab_dir=output_dir)
    previous_source = techniques_doc.get("source_version")
    techniques_doc["key"] = "id"
    techniques_doc.pop("model", None)
    bundles = [(enterprise, "")]
    if mobile.is_file():
        bundles.append((mobile, "Mobile"))
    if ics.is_file():
        bundles.append((ics, "Industrial"))
    lifecycles["att&ck"] = _merge_and_write(
        key_field="id",
        existing=list(techniques_doc.get("keys") or []),
        upstream=merge_technique_bundles(bundles),
        doc=techniques_doc,
        output_path=output_dir / "att&ck.vocab.toml",
        manifest=manifest,
        write=write,
    )

    # Catalog-only MITRE groups. Live threat objects pin G-ids via actors;
    # generate_actors merges the same STIX intrusion-sets into actors.vocab.toml.
    groups_doc = _load_template("att&ck.groups", vocab_dir=output_dir)
    groups_doc["key"] = "id"
    groups_doc.pop("model", None)
    all_groups: list[dict[str, Any]] = []
    for path, prefix in [(enterprise, ""), (ics, "ICS"), (mobile, "Mobile")]:
        if path.is_file():
            all_groups.extend(parse_groups(load_stix_bundle(path), prefix=prefix))
    lifecycles["att&ck.groups"] = _merge_and_write(
        key_field="id",
        existing=list(groups_doc.get("keys") or []),
        upstream=all_groups,
        doc=groups_doc,
        output_path=output_dir / "att&ck.groups.vocab.toml",
        manifest=manifest,
        write=write,
    )

    mitigations_doc = _load_template("mitigations", vocab_dir=output_dir)
    mitigations_doc["key"] = "name"
    mitigations_doc.pop("model", None)
    all_mitigations: list[dict[str, Any]] = []
    for path, prefix in [(enterprise, ""), (mobile, "Mobile"), (ics, "Industrial")]:
        if path.is_file():
            all_mitigations.extend(parse_mitigations(load_stix_bundle(path), prefix=prefix))
    lifecycles["mitigations"] = _merge_and_write(
        key_field="name",
        existing=list(mitigations_doc.get("keys") or []),
        upstream=all_mitigations,
        doc=mitigations_doc,
        output_path=output_dir / "mitigations.vocab.toml",
        manifest=manifest,
        write=write,
    )

    datasources_doc = _load_template("datasources", vocab_dir=output_dir)
    datasources_doc["key"] = "name"
    datasources_doc.pop("model", None)
    lifecycles["datasources"] = _merge_and_write(
        key_field="name",
        existing=list(datasources_doc.get("keys") or []),
        upstream=parse_datasources(load_stix_bundle(enterprise)),
        doc=datasources_doc,
        output_path=output_dir / "datasources.vocab.toml",
        manifest=manifest,
        write=write,
    )

    return GenerateReport(
        lifecycles=lifecycles,
        source_changed=str(previous_source or "") != str(manifest.get("version", "unknown")),
    )
