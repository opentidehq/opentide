"""TOML serialization for vocabulary documents."""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any

import toml


def dump_vocab_document(document: Mapping[str, Any]) -> str:
    """Render a vocabulary document as valid TOML."""
    payload = dict(document)
    if "keys" not in payload:
        payload["keys"] = []
    return toml.dumps(payload)
