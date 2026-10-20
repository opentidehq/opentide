"""`response.responders` is configurable, not a vocabulary.

Regression cover for the 0.13.0 blocker: ``responders.vocab.toml`` shipped with
``keys = []`` while ``response.responders`` was pinned to it, so every authored
value failed validation and no instance could fix it (vocabularies are not
locally extensible). The field is now free text with a repository-wide default.
"""

from __future__ import annotations

from types import SimpleNamespace

import pytest

from opentide.core.responders import resolve_responders
from opentide.models.vocab_pins import get_pins


class TestResponderPinRemoved:
    """The field must not be bound to a vocabulary contract."""

    @pytest.mark.parametrize("schema_id", ["rule::1.0", "rule::1.1"])
    def test_responders_is_not_pinned(self, schema_id: str) -> None:
        assert "response.responders" not in get_pins(schema_id)

    @pytest.mark.parametrize("schema_id", ["rule::1.0", "rule::1.1"])
    def test_sibling_pins_are_untouched(self, schema_id: str) -> None:
        # Removing one pin must not disturb the rest of the contract.
        pins = get_pins(schema_id)
        assert pins["response.alert_severity"] == "alert_severity::1.0"
        assert pins["metadata.tlp"] == "tlp::1.0"

    def test_no_responders_vocabulary_is_shipped(self) -> None:
        from pathlib import Path

        import opentide

        vocab_dir = Path(opentide.__file__).parent / "data" / "vocabulary"
        assert not (vocab_dir / "responders.vocab.toml").exists()


class TestResolveResponders:
    """The authored value wins; a blank one falls back to configuration."""

    def test_authored_value_is_used(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr("opentide.core.responders.default_responders", lambda: "SOC Tier 1")
        response = SimpleNamespace(responders="CSIRC")
        assert resolve_responders(response) == "CSIRC"

    def test_authored_value_is_stripped(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr("opentide.core.responders.default_responders", lambda: "SOC Tier 1")
        assert resolve_responders(SimpleNamespace(responders="  CATCH  ")) == "CATCH"

    @pytest.mark.parametrize("authored", [None, "", "   "])
    def test_blank_falls_back_to_default(
        self, authored: str | None, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setattr("opentide.core.responders.default_responders", lambda: "SOC Tier 1")
        assert resolve_responders(SimpleNamespace(responders=authored)) == "SOC Tier 1"

    def test_absent_response_block_falls_back(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr("opentide.core.responders.default_responders", lambda: "SOC Tier 1")
        assert resolve_responders(None) == "SOC Tier 1"

    def test_no_owner_configured_is_empty(self, monkeypatch: pytest.MonkeyPatch) -> None:
        # Neither authored nor defaulted: one representable "no owner" case.
        monkeypatch.setattr("opentide.core.responders.default_responders", lambda: "")
        assert resolve_responders(SimpleNamespace(responders=None)) == ""

    def test_default_survives_missing_deployment_config(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        # Documentation generation must not require a deployment block.
        from opentide.core import responders as module

        class _Raises:
            @property
            def Configurations(self) -> object:
                raise KeyError("deployment")

        monkeypatch.setattr("opentide.core.registry.Opentide", _Raises())
        assert module.default_responders() == ""
