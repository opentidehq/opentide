"""Vocabulary identifier resolution is raw-first, and shared by both paths.

`get_vocab_entry()` stripped the stage prefix unconditionally before looking a
value up, while `is_valid()` in the validation path guarded raw-first. Two
resolution rules for one vocabulary.

Scope, because the 0.13.0 defect report overstated this: in a scoped
vocabulary the authored value is `<stage>::<key>`, so for the six `surface`
keys whose own NAME begins with `Security::` the authored form is
`Protocol::Security::Kerberos`. Stripping the stage leaves
`Security::Kerberos`, which is the correct entry -- so authored content always
resolved correctly and documentation was never degraded.

The defect is latent rather than active: it fires when a **bare key name** is
passed, which internal callers may legitimately do, and then
`Security::Kerberos` strips to `Kerberos` -- a different key under stage
`Authentication`. Unifying both paths on one helper is the durable fix.
"""

from __future__ import annotations

import pytest

from opentide.core.registry import Opentide
from opentide.generation.framework import (
    get_vocab_entry,
    resolve_vocab_identifier,
    strip_vocab_stage_prefix,
)
from opentide.validation.vocab_resolver import RuntimeEnumResolver

# Stage `Protocol`, but the key name's first `::` token is the stage id
# `Security`. Three strip to a real key under `Authentication`; three to nothing.
COLLIDING = ("Security::Kerberos", "Security::NTLM", "Security::SAML")
MISSING = ("Security::TLS", "Security::OAuth", "Security::OpenID Connect")


def _surface_keys() -> set[str]:
    return set(Opentide.Vocabularies.Index["surface"].entries)


class TestTheBundledVocabularyStillHasTheseShapes:
    """If the vocabulary changes, the rest of this module needs revisiting."""

    def test_the_colliding_keys_exist(self) -> None:
        keys = _surface_keys()
        for name in COLLIDING:
            assert name in keys
            # The bare form exists too -- that is what made it silent.
            assert name.split("::", 1)[1] in keys

    def test_the_missing_keys_strip_to_nothing(self) -> None:
        keys = _surface_keys()
        for name in MISSING:
            assert name in keys
            assert name.split("::", 1)[1] not in keys


class TestResolveRawFirst:
    @pytest.mark.parametrize("identifier", COLLIDING + MISSING)
    def test_a_real_key_resolves_to_itself(self, identifier: str) -> None:
        assert resolve_vocab_identifier("surface", identifier) == identifier

    @pytest.mark.parametrize("identifier", COLLIDING)
    def test_the_old_strip_would_have_picked_another_key(self, identifier: str) -> None:
        # Documents the bug: stripping alone lands on a different entry.
        stripped = strip_vocab_stage_prefix("surface", identifier)
        assert stripped != identifier
        assert stripped in _surface_keys()

    def test_a_genuinely_prefixed_value_is_still_stripped(self) -> None:
        # The fallback must keep working: `OS::Windows` is not itself a key.
        assert "OS::Windows" not in _surface_keys()
        assert resolve_vocab_identifier("surface", "OS::Windows") == "Windows"

    def test_a_versioned_contract_resolves(self) -> None:
        # Callers pass `surface::1.0`; the index is keyed by field name.
        assert resolve_vocab_identifier("surface::1.0", "OS::Windows") == "Windows"

    def test_an_unknown_value_falls_through_unchanged(self) -> None:
        assert resolve_vocab_identifier("surface", "Nope::Nothing") == "Nope::Nothing"


class TestGenerationResolvesTheRightEntry:
    @pytest.mark.parametrize("identifier", COLLIDING)
    def test_a_colliding_key_returns_its_own_entry(self, identifier: str) -> None:
        entry = get_vocab_entry("surface", identifier)
        assert isinstance(entry, dict)
        assert entry.get("name") == identifier

    @pytest.mark.parametrize("identifier", MISSING)
    def test_a_previously_missed_key_now_resolves(self, identifier: str) -> None:
        entry = get_vocab_entry("surface", identifier)
        assert isinstance(entry, dict)
        assert entry.get("name") == identifier

    def test_a_prefixed_value_still_resolves(self) -> None:
        entry = get_vocab_entry("surface", "OS::Windows")
        assert isinstance(entry, dict)
        assert entry.get("name") == "Windows"


class TestTheAuthoredFormWasNeverBroken:
    """Scoped authored values resolved correctly before and after.

    This is the correction to the defect report's framing. In a scoped
    vocabulary the authored value is ``<stage>::<key>``, so for these keys it is
    ``Protocol::Security::Kerberos`` -- stripping the stage leaves
    ``Security::Kerberos``, which is the right entry. The hot path was fine.
    """

    @pytest.mark.parametrize("key", COLLIDING + MISSING)
    def test_the_authored_value_resolves_to_its_own_entry(self, key: str) -> None:
        authored = f"Protocol::{key}"
        entry = get_vocab_entry("surface", authored)
        assert isinstance(entry, dict)
        assert entry.get("name") == key

    @pytest.mark.parametrize("key", COLLIDING + MISSING)
    def test_the_old_strip_also_handled_the_authored_value(self, key: str) -> None:
        # Both old and new agree here; nothing regressed and nothing was fixed.
        authored = f"Protocol::{key}"
        assert strip_vocab_stage_prefix("surface", authored) == key
        assert resolve_vocab_identifier("surface", authored) == key

    @pytest.mark.parametrize("key", COLLIDING + MISSING)
    def test_the_authored_value_is_what_validation_accepts(self, key: str) -> None:
        resolver = RuntimeEnumResolver(
            {"surface": Opentide.Vocabularies.Index["surface"]}, object_types=("surface",)
        )
        assert resolver.is_valid(f"Protocol::{key}", "surface", scoped=True)
        # The bare key is NOT a valid authored value in a scoped vocabulary.
        assert not resolver.is_valid(key, "surface", scoped=True)


class TestBothPathsShareOneHelper:
    """The durable fix: one resolution rule, so the paths cannot drift."""

    def test_validation_uses_the_shared_helper(self) -> None:
        import inspect

        from opentide.validation import vocab_resolver

        source = inspect.getsource(vocab_resolver.RuntimeEnumResolver.is_valid)
        assert "resolve_vocab_identifier" in source
        assert "strip_vocab_stage_prefix" not in source
