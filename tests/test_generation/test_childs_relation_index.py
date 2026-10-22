"""`childs()` is index-backed, and must stay equivalent to the forward scan.

`childs()` used to scan every object of each child type on every call. Its
callers are per-object (`TableExporter` rows, `DocumentationCatalog`
per-signal, `relations_downstream()` recursing), so the catalogue-wide cost was
quadratic. The scan is now inverted into an index built once per models-index
generation.

These tests pin the two things that could go wrong: the indexed answer must
equal what the original traversal produced, and the index must not survive a
registry reload.
"""

from __future__ import annotations

from typing import Any

import pytest

from opentide.generation import framework as fw


def _reference_childs(model_id: str, models_index: dict[str, Any]) -> list[str]:
    """The pre-index implementation, kept verbatim as the oracle.

    Deliberately a copy of the original nested scan. If `childs()` ever
    disagrees with this, the optimisation changed behaviour.
    """
    implementations: list[str] = []
    mappings = {
        "threat": {
            "child_types": ["objective"],
            "data_sections": ["detection", "objective"],
            "references": ["vectors", "threats"],
        },
        "objective": {
            "child_types": ["signal", "rule"],
            "references": ["detection_model", "owner"],
        },
        "signal": {"child_types": ["rule"], "references": ["detection_model"]},
    }
    model_type = _type_of(model_id, models_index)
    if model_type not in mappings:
        return []
    child_types = mappings[model_type]["child_types"]
    data_sections = mappings[model_type].get("data_sections", None)
    references = mappings[model_type]["references"]
    for child_type in child_types:
        childs_index = models_index.get(child_type, {})
        for child in childs_index:
            if data_sections:
                for section in data_sections:
                    for reference in references:
                        if model_id in childs_index[child].get(section, {}).get(reference, []):
                            implementations.append(child)
            else:
                for reference in references:
                    if model_id in childs_index[child].get(reference, []):
                        implementations.append(child)
    return implementations


def _type_of(uuid: str, models_index: dict[str, Any]) -> str:
    for object_type, bodies in models_index.items():
        if uuid in bodies:
            return object_type
    return ""


# A corpus exercising every relation shape: a threat referenced through both
# data sections, an objective with signal and rule children, a signal whose
# rule names it by a BARE STRING `detection_model`, and a rule naming an
# objective directly. The last two are what make the parent-type keying
# load-bearing: `detection_model` is a reference under both mappings.
CORPUS: dict[str, Any] = {
    "threat": {"t-1": {}, "t-2": {}},
    "objective": {
        "o-1": {"detection": {"vectors": ["t-1"]}, "objective": {"threats": ["t-1"]}},
        "o-2": {"detection": {"vectors": ["t-2"]}},
        "o-3": {},
    },
    "signal": {
        "s-1": {"owner": "o-1"},
        "s-2": {"owner": ["o-2"]},
    },
    "rule": {
        "r-1": {"detection_model": "s-1"},
        "r-2": {"detection_model": ["o-1"]},
        "r-3": {"detection_model": ["s-2"]},
        "r-4": {},
    },
}


@pytest.fixture
def corpus(monkeypatch: pytest.MonkeyPatch) -> dict[str, Any]:
    """Point the framework's lazy models view at CORPUS and clear the index.

    `get_type()` resolves through `Opentide.Models.FlatIndex` rather than the
    lazy view, so it is stubbed against the same corpus. Type resolution has
    its own cover; these tests are about the relation traversal.
    """
    monkeypatch.setattr(fw.MODELS_INDEX, "_loader", lambda: CORPUS)
    monkeypatch.setattr(fw, "_RELATION_INDEX", {"_source": None, "childs": {}})
    monkeypatch.setattr(fw, "get_type", lambda uuid, mute=False: _type_of(uuid, CORPUS) or None)
    return CORPUS


class TestEquivalence:
    """The indexed result must equal the original forward scan, exactly."""

    @pytest.mark.parametrize(
        "uuid",
        ["t-1", "t-2", "o-1", "o-2", "o-3", "s-1", "s-2", "r-1", "r-4"],
    )
    def test_matches_the_reference_implementation(self, uuid: str, corpus: dict[str, Any]) -> None:
        assert fw.childs(uuid) == _reference_childs(uuid, corpus)

    def test_a_threat_referenced_twice_keeps_both_appends(self, corpus: dict[str, Any]) -> None:
        # o-1 names t-1 under BOTH data sections, so the original appended it
        # twice. The index must reproduce that rather than silently dedupe.
        assert fw.childs("t-1") == _reference_childs("t-1", corpus)
        assert fw.childs("t-1").count("o-1") == 2

    def test_a_rule_naming_a_signal_is_not_double_counted(self, corpus: dict[str, Any]) -> None:
        # The regression a flat index would introduce: `detection_model` is a
        # reference under the objective AND signal mappings, so s-1's child r-1
        # would appear twice if the index were not keyed by parent type.
        assert fw.childs("s-1") == ["r-1"]

    def test_a_bare_string_reference_resolves(self, corpus: dict[str, Any]) -> None:
        assert "r-1" in fw.childs("s-1")
        assert "s-1" in fw.childs("o-1")

    def test_a_last_line_object_has_no_children(self, corpus: dict[str, Any]) -> None:
        assert fw.childs("r-1") == []

    def test_an_unknown_uuid_has_no_children(self, corpus: dict[str, Any]) -> None:
        assert fw.childs("does-not-exist") == []


class TestSubstringMatchingFixed:
    """The index compares references by equality, not substring.

    The pre-index code tested ``model_id in value``. When a reference holds a
    bare STRING (``owner``, ``detection_model``) that is a substring test, so
    any id that happened to be a prefix of another id matched it. Measured on a
    1497-object corpus with short ids: ``childs('o-1')`` returned 113 children,
    including signals that actually referenced ``o-186``.

    Real UUIDs cannot trigger it -- two UUID4s are the same length, so neither
    is a strict substring of the other, and old and new agree on 0 mismatches
    across such a corpus. It is still wrong for any non-UUID identifier, and
    equality is unambiguously the intended meaning.
    """

    OVERLAPPING: dict[str, Any] = {
        "objective": {"o-1": {}, "o-186": {}},
        "signal": {"s-0": {"owner": "o-186"}},
        "rule": {},
    }

    @pytest.fixture
    def overlapping(self, monkeypatch: pytest.MonkeyPatch) -> dict[str, Any]:
        monkeypatch.setattr(fw.MODELS_INDEX, "_loader", lambda: self.OVERLAPPING)
        monkeypatch.setattr(fw, "_RELATION_INDEX", {"_source": None, "childs": {}})
        monkeypatch.setattr(
            fw, "get_type", lambda uuid, mute=False: _type_of(uuid, self.OVERLAPPING) or None
        )
        return self.OVERLAPPING

    def test_a_prefix_is_no_longer_treated_as_a_reference(
        self, overlapping: dict[str, Any]
    ) -> None:
        # `o-1` is a substring of `o-186` but references nothing.
        assert fw.childs("o-1") == []

    def test_the_real_parent_still_resolves(self, overlapping: dict[str, Any]) -> None:
        assert fw.childs("o-186") == ["s-0"]

    def test_the_old_scan_did_match_the_prefix(self, overlapping: dict[str, Any]) -> None:
        # Documents the behaviour being corrected: the oracle still over-matches.
        assert _reference_childs("o-1", overlapping) == ["s-0"]


class TestIndexLifecycle:
    def test_the_index_is_built_once_per_generation(self, corpus: dict[str, Any]) -> None:
        fw.childs("t-1")
        first = fw._child_relation_index()
        fw.childs("o-1")
        assert fw._child_relation_index() is first

    def test_a_new_index_object_invalidates_the_cache(
        self, monkeypatch: pytest.MonkeyPatch, corpus: dict[str, Any]
    ) -> None:
        assert fw.childs("t-1") == _reference_childs("t-1", corpus)
        # `Opentide.reload()` swaps in a fresh mapping; staleness is detected by
        # identity, so a DIFFERENT object with different content must be seen.
        replacement: dict[str, Any] = {
            "threat": {"t-1": {}},
            "objective": {"o-9": {"detection": {"vectors": ["t-1"]}}},
        }
        monkeypatch.setattr(fw.MODELS_INDEX, "_loader", lambda: replacement)
        assert fw.childs("t-1") == ["o-9"]

    def test_a_mutated_result_cannot_corrupt_the_index(self, corpus: dict[str, Any]) -> None:
        got = fw.childs("o-1")
        got.append("injected")
        assert "injected" not in fw.childs("o-1")


class TestCost:
    def test_lookups_do_not_rescan_the_catalogue(
        self, monkeypatch: pytest.MonkeyPatch, corpus: dict[str, Any]
    ) -> None:
        """One build, then O(1) lookups -- the property that fixes the phases.

        Counts how often the models index is resolved. The old implementation
        resolved it once per reference per child type on EVERY call; the index
        resolves it once per call to check staleness and never rescans.
        """
        builds = {"n": 0}
        real = fw._child_relation_index

        def counting() -> Any:
            before = fw._RELATION_INDEX["_source"]
            result = real()
            if fw._RELATION_INDEX["_source"] is not before:
                builds["n"] += 1
            return result

        monkeypatch.setattr(fw, "_child_relation_index", counting)
        for uuid in ("t-1", "t-2", "o-1", "o-2", "s-1", "s-2"):
            fw.childs(uuid)
        assert builds["n"] == 1
