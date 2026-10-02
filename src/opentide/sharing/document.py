"""A Tide object kept as verbatim YAML plus the parsed mapping.

The MISP ``opentide-object`` attribute must be the file bytes. Parsing is only
for the envelope (name, metadata, relations) and must not be written back.
"""

from __future__ import annotations

import hashlib
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import yaml

from opentide.sharing.constants import OBJECT_FAMILIES


@dataclass(frozen=True)
class TideDocument:
    """One threat, objective, or rule document selected for sharing."""

    document: str
    body: Mapping[str, Any]
    path: Path | None = None
    parse_error: str | None = None

    @property
    def content_hash(self) -> str:
        """SHA-256 of the verbatim UTF-8 document, lowercase hex."""
        return hashlib.sha256(self.document.encode("utf-8")).hexdigest()

    @property
    def metadata(self) -> Mapping[str, Any]:
        value = self.body.get("metadata")
        if isinstance(value, Mapping):
            return value
        return {}

    @property
    def uuid(self) -> str | None:
        value = self.metadata.get("uuid")
        if isinstance(value, str) and value:
            return value
        return None

    @property
    def schema_id(self) -> str | None:
        value = self.metadata.get("schema")
        if isinstance(value, str) and value:
            return value
        return None

    @property
    def family(self) -> str | None:
        schema = self.schema_id
        if schema is None or "::" not in schema:
            return None
        family = schema.split("::", 1)[0]
        if family in OBJECT_FAMILIES:
            return family
        return None

    @property
    def name(self) -> str | None:
        value = self.body.get("name")
        if isinstance(value, str):
            return value
        return None


def load_document(raw: str | bytes, *, path: Path | None = None) -> TideDocument:
    """Parse *raw* without changing the text stored for ``opentide-object``."""
    if isinstance(raw, bytes):
        try:
            text = raw.decode("utf-8")
        except UnicodeDecodeError:
            return TideDocument("", {}, path, "encoding")
    else:
        text = raw
    try:
        loaded = yaml.safe_load(text)
    except yaml.YAMLError:
        return TideDocument(text, {}, path, "yaml")
    if not isinstance(loaded, dict):
        return TideDocument(text, {}, path, "root")
    return TideDocument(text, loaded, path, None)
