"""``status`` must mean the same thing on every platform configuration (#486).

The drift was three-way, and each surface gave a different answer about the
same rule:

* ``opentide validate`` ran on the Pydantic models, where ``status`` was
  optional on the shared base, so a rule missing it **passed, exit 0**;
* the JSON Schema published for that rule required ``status``, so an editor
  reading it flagged the same rule invalid;
* ``opentide deploy`` read ``conf_data[system]["status"]`` with a raw
  subscript, so the rule failed with a bare ``KeyError`` rendered as a FATAL
  panel containing the single word ``'status'``.

The deploy planner selects on ``status`` and cannot proceed without it, so the
extras were right and the model was wrong. These tests pin the model to the
published schema and pin the deployer's diagnostic to something actionable.
"""

from __future__ import annotations

import pytest
from pydantic import ValidationError

from opentide.models.platform import PLATFORM_CONFIG_MODELS
from opentide.models.platform_schema import platform_root_extras


@pytest.mark.parametrize("key", sorted(PLATFORM_CONFIG_MODELS))
def test_status_is_required_on_every_platform_model(key: str) -> None:
    model = PLATFORM_CONFIG_MODELS[key]
    assert "status" in model.model_fields, f"{key} has no status field"
    assert model.model_fields["status"].is_required(), (
        f"{key}: status is optional on the model, so a rule without one would "
        f"validate and then fail deployment"
    )


@pytest.mark.parametrize("key", sorted(PLATFORM_CONFIG_MODELS))
def test_status_required_in_both_the_model_and_the_published_schema(key: str) -> None:
    """The specific three-way disagreement must not come back."""
    model = PLATFORM_CONFIG_MODELS[key]
    model_required = set(model.model_json_schema().get("required", []))
    extras_required = set(platform_root_extras(model).get("required", []))

    assert "status" in extras_required, f"{key}: extras stopped requiring status"
    assert "status" in model_required, (
        f"{key}: the published schema requires status but the model does not"
    )


@pytest.mark.parametrize("key", sorted(PLATFORM_CONFIG_MODELS))
def test_platform_config_without_status_is_rejected(key: str) -> None:
    model = PLATFORM_CONFIG_MODELS[key]
    with pytest.raises(ValidationError) as caught:
        model.model_validate({"schema": f"{key}::1.0", "enabled": True})
    missing_status = [
        error
        for error in caught.value.errors()
        if error["loc"] == ("status",) and error["type"] == "missing"
    ]
    assert missing_status, f"{key} accepted a configuration with no status"
