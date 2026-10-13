"""Scope resolution and the `migrate vocab-scope` migration.

The decisive test here is :func:`test_every_emitted_value_is_accepted`: a
migration that writes a value ``validate`` rejects is worse than no migration,
so every value the resolver can emit is checked against the live enum
resolver rather than against a second copy of the same arithmetic.
"""

from __future__ import annotations

from pathlib import Path

import pytest
import yaml

from opentide.cli.services.migrate_vocab_scope import (
    SCOPED_FIELDS,
    ScopedField,
    load_scoped_vocabularies,
    run_migrate_vocab_scope,
)
from opentide.validation.vocab_scope import VocabScopeIndex

ENTITIES = "signal.entities"
SURFACE = "surface"
ENTITIES_FIELD = {"entities": SCOPED_FIELDS["entities"]}


@pytest.fixture(scope="module")
def vocabs() -> dict:
    return load_scoped_vocabularies()


@pytest.fixture(scope="module")
def entities(vocabs: dict) -> VocabScopeIndex:
    return VocabScopeIndex(vocabs[ENTITIES])


@pytest.fixture(scope="module")
def surface(vocabs: dict) -> VocabScopeIndex:
    return VocabScopeIndex(vocabs[SURFACE])


# --------------------------------------------------------------------------
# The vocabulary contract #509 asks for
# --------------------------------------------------------------------------


def test_entities_stages_are_capitalised(entities: VocabScopeIndex) -> None:
    """#509: entities stages match `surface`'s capitalised convention."""
    assert entities.stages == ("Host", "Network", "Cloud")


def test_entities_scoped_enum_recovers_the_seven_lost_values(entities: VocabScopeIndex) -> None:
    """#509 acceptance: 35 scoped values, not the 28 flattened ones."""
    values = set(entities.scoped_values())
    assert len(values) == 35
    assert {"Host::Account", "Cloud::Account"} <= values
    assert "Host::Process" in values


@pytest.mark.parametrize(
    "key",
    ["Account", "User", "Email", "Token", "Authentication", "Permissions", "API Call"],
)
def test_the_seven_multi_stage_keys_are_ambiguous(entities: VocabScopeIndex, key: str) -> None:
    """A bare multi-stage key is reported, never guessed."""
    outcome = entities.resolve(key)
    assert outcome.status == "ambiguous"
    assert not outcome.is_resolved
    assert len(outcome.candidates) == 2
    assert key in outcome.detail


# --------------------------------------------------------------------------
# Resolution order
# --------------------------------------------------------------------------


def test_single_stage_key_is_prefixed(entities: VocabScopeIndex) -> None:
    outcome = entities.resolve("Process")
    assert (outcome.status, outcome.resolved) == ("prefixed", "Host::Process")
    assert outcome.changed


def test_stage_casing_is_normalised(entities: VocabScopeIndex) -> None:
    """The form every existing corpus carries: lowercase stage prefixes."""
    outcome = entities.resolve("host::Process")
    assert (outcome.status, outcome.resolved) == ("rescoped", "Host::Process")
    assert outcome.changed


def test_lowercase_multi_stage_prefix_is_recovered(entities: VocabScopeIndex) -> None:
    """`cloud::Account` keeps the distinction `Account` alone would lose."""
    outcome = entities.resolve("cloud::Account")
    assert (outcome.status, outcome.resolved) == ("rescoped", "Cloud::Account")


def test_already_scoped_value_is_left_alone(entities: VocabScopeIndex) -> None:
    outcome = entities.resolve("Host::Process")
    assert outcome.status == "scoped"
    assert not outcome.changed


def test_key_whose_head_is_a_stage_resolves_raw_first(surface: VocabScopeIndex) -> None:
    """`Security::Kerberos` is a Protocol key, not stage Security + Kerberos.

    Reading the prefix first would resolve it to the unrelated
    `Authentication::Kerberos`. This is the A1/#516 precedence, enforced here
    for the migration path too.
    """
    outcome = surface.resolve("Security::Kerberos")
    assert (outcome.status, outcome.resolved) == ("prefixed", "Protocol::Security::Kerberos")

    bare = surface.resolve("Kerberos")
    assert bare.resolved == "Authentication::Kerberos"
    assert bare.resolved != outcome.resolved


def test_key_containing_separator_is_not_split(surface: VocabScopeIndex) -> None:
    """`::` inside a key name is hierarchy, not a stage prefix."""
    outcome = surface.resolve("AWS::Compute::EC2")
    assert (outcome.status, outcome.resolved) == ("prefixed", "Cloud::AWS::Compute::EC2")


def test_real_key_under_the_wrong_stage_is_distinguished(entities: VocabScopeIndex) -> None:
    """`invalid_stage` tells 'wrong stage' apart from 'unknown key'."""
    outcome = entities.resolve("Cloud::Process")
    assert outcome.status == "invalid_stage"
    assert outcome.candidates == ("Host::Process",)
    assert "valid" in outcome.detail


def test_unknown_value_is_unknown(entities: VocabScopeIndex) -> None:
    outcome = entities.resolve("Nonexistent Entity")
    assert outcome.status == "unknown"
    assert not outcome.is_resolved


def test_blank_value_is_unknown(entities: VocabScopeIndex) -> None:
    assert entities.resolve("   ").status == "unknown"


# --------------------------------------------------------------------------
# The property that matters
# --------------------------------------------------------------------------


@pytest.mark.parametrize("vocab_name", [ENTITIES, SURFACE])
def test_every_emitted_value_is_accepted(vocabs: dict, vocab_name: str) -> None:
    """No value this resolver emits may be one `validate` would reject.

    Checked against the live enum resolver, which is the code `validate`
    actually runs, not a reimplementation of the prefix arithmetic.
    """
    from opentide.validation.vocab_resolver import RuntimeEnumResolver

    index = VocabScopeIndex(vocabs[vocab_name])
    resolver = RuntimeEnumResolver(vocabs, object_types=(), icons={})
    allowed = set(resolver.enum_values(vocab_name, scoped=True))

    assert set(index.scoped_values()) == allowed, "index and generated enum disagree"

    emitted = set()
    for key in {value.split("::", 1)[1] for value in index.scoped_values()}:
        for candidate in (key, key.lower(), key.upper()):
            outcome = index.resolve(candidate)
            if outcome.is_resolved and outcome.resolved is not None:
                emitted.add(outcome.resolved)
    for value in index.scoped_values():
        for candidate in (value, value.lower()):
            outcome = index.resolve(candidate)
            if outcome.is_resolved and outcome.resolved is not None:
                emitted.add(outcome.resolved)

    assert emitted, "resolver emitted nothing, so the assertion proves nothing"
    rejected = {value for value in emitted if not resolver.is_valid(value, vocab_name, scoped=True)}
    assert not rejected, f"{vocab_name}: migration would emit invalid values {sorted(rejected)}"


# --------------------------------------------------------------------------
# The migration
# --------------------------------------------------------------------------

OBJECTIVE = """\
metadata:
  uuid: 3f2b1c4d-0000-4000-8000-000000000001
  schema: objective::1.0
name: Example
objective:
  signals:
    - name: Host side
      uuid: 3f2b1c4d-0000-4000-8000-000000000002
      # a comment that must survive
      description: |-
        A block scalar
        across two lines.
      entities:
        - host::Process
        - Hostname
        - "network::URL"
"""


def _write(repo: Path, relative: str, text: str) -> Path:
    path = repo / relative
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")
    return path


def test_dry_run_changes_nothing(tmp_path: Path, vocabs: dict) -> None:
    path = _write(tmp_path, "objects/objectives/example.yaml", OBJECTIVE)
    report = run_migrate_vocab_scope(tmp_path, vocabs, fields=ENTITIES_FIELD)

    assert report["applied"] is False
    assert report["changed_files"] == ["objects/objectives/example.yaml"]
    assert path.read_text(encoding="utf-8") == OBJECTIVE


def test_apply_rewrites_and_preserves_formatting(tmp_path: Path, vocabs: dict) -> None:
    path = _write(tmp_path, "objects/objectives/example.yaml", OBJECTIVE)
    report = run_migrate_vocab_scope(tmp_path, vocabs, apply=True, fields=ENTITIES_FIELD)

    text = path.read_text(encoding="utf-8")
    assert report["applied"] is True
    assert "- Host::Process" in text
    assert "- Host::Hostname" in text
    assert '- "Network::URL"' in text, "original quote style must be kept"
    assert "# a comment that must survive" in text
    assert "A block scalar\n        across two lines." in text

    payload = yaml.safe_load(text)
    assert payload["objective"]["signals"][0]["entities"] == [
        "Host::Process",
        "Host::Hostname",
        "Network::URL",
    ]
    assert payload["objective"]["signals"][0]["description"] == "A block scalar\nacross two lines."


def test_flow_sequence_is_rewritten_in_place(tmp_path: Path, vocabs: dict) -> None:
    """`entities: [Hostname]` is the form the packaged tutorial uses."""
    source = OBJECTIVE.replace(
        '      entities:\n        - host::Process\n        - Hostname\n        - "network::URL"\n',
        "      entities: [Hostname, host::Process]\n",
    )
    path = _write(tmp_path, "objects/objectives/flow.yaml", source)
    run_migrate_vocab_scope(tmp_path, vocabs, apply=True, fields=ENTITIES_FIELD)

    text = path.read_text(encoding="utf-8")
    assert "entities: [Host::Hostname, Host::Process]" in text
    assert yaml.safe_load(text)["objective"]["signals"][0]["entities"] == [
        "Host::Hostname",
        "Host::Process",
    ]


def test_platform_entities_block_is_never_touched(tmp_path: Path, vocabs: dict) -> None:
    """A Sentinel `entities:` block holds mappings, not vocabulary values.

    This is why values are located by path. A leaf-key rewrite would corrupt
    platform configuration that happens to share the field name.
    """
    source = (
        OBJECTIVE
        + """\
configurations:
  sentinel:
    status: production
    entities:
      - entity: Account
        mappings:
          - identifier: Name
            column: Hostname
"""
    )
    path = _write(tmp_path, "objects/objectives/platform.yaml", source)
    run_migrate_vocab_scope(tmp_path, vocabs, apply=True, fields=ENTITIES_FIELD)

    payload = yaml.safe_load(path.read_text(encoding="utf-8"))
    sentinel = payload["configurations"]["sentinel"]["entities"][0]
    assert sentinel["entity"] == "Account", "platform entity must not be rescoped"
    assert sentinel["mappings"][0]["column"] == "Hostname", "a column name is not a vocab value"
    # The real vocabulary field in the same file still migrated.
    assert payload["objective"]["signals"][0]["entities"][0] == "Host::Process"


def test_ambiguous_value_is_reported_and_left_untouched(tmp_path: Path, vocabs: dict) -> None:
    source = OBJECTIVE.replace("        - Hostname\n", "        - Account\n")
    path = _write(tmp_path, "objects/objectives/example.yaml", source)
    report = run_migrate_vocab_scope(tmp_path, vocabs, apply=True, fields=ENTITIES_FIELD)

    blocked = report["fields"]["entities"]["blocked"]
    assert "Account" in blocked
    assert "several stages" in blocked["Account"]
    text = path.read_text(encoding="utf-8")
    assert "- Account\n" in text
    # The unambiguous neighbours in the same file still migrate.
    assert "- Host::Process" in text


def test_values_outside_the_declared_path_are_untouched(tmp_path: Path, vocabs: dict) -> None:
    source = OBJECTIVE.replace("name: Example", "name: Process")
    path = _write(tmp_path, "objects/objectives/example.yaml", source)
    run_migrate_vocab_scope(tmp_path, vocabs, apply=True, fields=ENTITIES_FIELD)

    payload = yaml.safe_load(path.read_text(encoding="utf-8"))
    assert payload["name"] == "Process", "a scalar sharing a key value must be untouched"


def test_surface_and_entities_migrate_together(tmp_path: Path, vocabs: dict) -> None:
    threat = """\
metadata:
  uuid: 3f2b1c4d-0000-4000-8000-000000000003
  schema: threat::1.0
name: Example threat
threat:
  terrain: Prose about the terrain.
  surface:
    - Routers
    - Security::Kerberos
"""
    threat_path = _write(tmp_path, "objects/threats/example.yaml", threat)
    objective_path = _write(tmp_path, "objects/objectives/example.yaml", OBJECTIVE)
    report = run_migrate_vocab_scope(tmp_path, vocabs, apply=True)

    assert set(report["fields"]) == {"surface", "entities"}
    surface = yaml.safe_load(threat_path.read_text(encoding="utf-8"))["threat"]["surface"]
    assert surface == ["Infrastructure::Routers", "Protocol::Security::Kerberos"]
    entities = yaml.safe_load(objective_path.read_text(encoding="utf-8"))
    assert entities["objective"]["signals"][0]["entities"][0] == "Host::Process"


def test_unreadable_file_is_reported_not_fatal(tmp_path: Path, vocabs: dict) -> None:
    _write(tmp_path, "objects/objectives/example.yaml", OBJECTIVE)
    _write(tmp_path, "objects/objectives/broken.yaml", "entities: [\n  unclosed")
    report = run_migrate_vocab_scope(tmp_path, vocabs, fields=ENTITIES_FIELD)

    assert "objects/objectives/broken.yaml" in report["failed_files"]
    assert report["changed_files"] == ["objects/objectives/example.yaml"]


def test_empty_corpus_is_a_clean_no_op(tmp_path: Path, vocabs: dict) -> None:
    (tmp_path / "objects").mkdir()
    report = run_migrate_vocab_scope(tmp_path, vocabs, fields=ENTITIES_FIELD)
    assert report["scanned"] == 0
    assert report["changed_files"] == []


def test_unstaged_vocabulary_is_refused(tmp_path: Path, vocabs: dict) -> None:
    """A vocabulary with no stages cannot be scoped, so the run refuses it."""
    from opentide.core.root import get_data_root
    from opentide.vocabulary.io import load_vocab_file

    unstaged = load_vocab_file(get_data_root() / "vocabulary" / "severity.vocab.toml")
    assert not VocabScopeIndex(unstaged).is_staged, "severity must be unstaged for this test"

    with pytest.raises(ValueError, match="declares no stages"):
        run_migrate_vocab_scope(
            tmp_path,
            {**vocabs, "severity": unstaged},
            fields={"severity": ScopedField(vocab="severity", path=("threat", "severity"))},
        )


def test_missing_vocabulary_is_refused(tmp_path: Path, vocabs: dict) -> None:
    with pytest.raises(ValueError, match="not loaded"):
        run_migrate_vocab_scope(
            tmp_path, vocabs, fields={"nope": ScopedField(vocab="nope", path=("nope",))}
        )


def test_scoped_fields_cover_every_scoped_model_field() -> None:
    """A field that becomes `scoped=True` must be added to SCOPED_FIELDS.

    Read from the models rather than restated, so a future scoped field
    cannot be silently left out of the migration.
    """
    from opentide.models.objective import DetectionSignal
    from opentide.models.threat import ThreatBody

    declared = set()
    for model in (DetectionSignal, ThreatBody):
        for name, info in model.model_fields.items():
            extra = info.json_schema_extra
            if isinstance(extra, dict) and extra.get("tide.vocab.scoped"):
                declared.add(name)

    assert declared, "no scoped field found, so this assertion proves nothing"
    assert declared <= set(SCOPED_FIELDS), (
        f"scoped model fields missing from SCOPED_FIELDS: {sorted(declared - set(SCOPED_FIELDS))}"
    )


def test_scoped_fields_match_the_pins() -> None:
    """Each declared path must be the pin key the engine validates against."""
    from opentide.core.io import load_toml
    from opentide.core.root import get_data_root

    pins: dict[str, str] = {}
    for name in ("threat", "objective", "rule"):
        for contract in load_toml(get_data_root() / "pins" / f"{name}.toml").values():
            pins.update(contract)

    for field_name, spec in SCOPED_FIELDS.items():
        pin_key = ".".join(part for part in spec.path if part != "*")
        assert pin_key in pins, f"{field_name}: {pin_key!r} is not a pinned field"
        assert pins[pin_key].split("::")[0] == spec.vocab, (
            f"{field_name}: pinned to {pins[pin_key]!r}, declared {spec.vocab!r}"
        )
