"""Legacy Tide 1 → Tide 2 object patching for staging reconciliation."""

from __future__ import annotations

import json
import os
import uuid
from pathlib import Path
from typing import Any

from opentide.core.root import repository_root


class LegacyObjectPatch:
    """Patch Tide 1 staging objects with schema identifiers and UUIDs."""

    def __init__(self, index_path: Path | None = None) -> None:
        paths = repository_root() / "Schemas" / "Indexes"
        mapping_file = index_path or paths / "legacy_uuid_mapping.json"
        try:
            self.legacy_uuid_mapping: dict[str, Any] | None = json.loads(
                mapping_file.read_text(encoding="utf-8")
            )
        except OSError:
            self.legacy_uuid_mapping = None

    def tide_1_patch(self, model: dict[str, Any], model_type: str) -> dict[str, Any]:
        """Apply on-the-fly micro-patching for staging validation."""
        legacy_uuid_mapping = self.legacy_uuid_mapping

        if (
            os.getenv("CI_COMMIT_REF_NAME") == "main"
            and os.getenv("DEPLOYMENT_PLAN") not in ["PRODUCTION", "STAGING"]
            and model_type != "mdr"
        ):
            return model

        if model.get("metadata", {}).get("schema"):
            return model

        if not model.get("metadata"):
            model["metadata"] = model.pop("meta")

        if not model.get("metadata", {}).get("schema"):
            model["metadata"]["schema"] = f"{model_type.lower()}::2.0"

        if not model.get("metadata", {}).get("uuid"):
            if "uuid" in model:
                model["metadata"]["uuid"] = model.pop("uuid")
            elif "id" in model:
                old_id = model.pop("id")
                if legacy_uuid_mapping and old_id in legacy_uuid_mapping:
                    model["metadata"]["uuid"] = legacy_uuid_mapping[old_id]["uuid"]
                else:
                    model["metadata"]["uuid"] = str(uuid.uuid4())
            else:
                model["metadata"]["uuid"] = str(uuid.uuid4())

        if legacy_uuid_mapping:
            if old_ids := model.get("threat", {}).get("actors"):
                model["threat"]["actors"] = [
                    legacy_uuid_mapping[old]["uuid"] if old in legacy_uuid_mapping else old
                    for old in old_ids
                ]

            if old_ids := model.get("detection", {}).get("vectors"):
                model["detection"]["vectors"] = [
                    legacy_uuid_mapping[old]["uuid"] if old in legacy_uuid_mapping else old
                    for old in old_ids
                ]

            if (old := model.get("detection_model")) and old in legacy_uuid_mapping:
                model["detection_model"] = legacy_uuid_mapping[old]["uuid"]

        return model
