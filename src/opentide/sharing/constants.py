"""Normative constants for sharing 1.0."""

from __future__ import annotations

from typing import get_args

# The sharing 1.0 rules live on the `sharing::misp::1.0` model.
from opentide.models.configuration.sharing import DEFAULT_OBJECT_TYPES, MispIntegration, TlpName

REDACTION_MARKER = "[REDACTED]"

INTEGRATION_MISP = "misp"
KNOWN_INTEGRATIONS = frozenset({INTEGRATION_MISP})

OBJECT_FAMILIES = DEFAULT_OBJECT_TYPES

# Ceiling order. Bundled ``tlp`` vocabulary keys use this same sequence.
TLP_ORDER: tuple[str, ...] = get_args(TlpName)

# `${` + an uppercase letter + uppercase letters, digits or underscores + `}`.
# `$MISP_KEY` without braces is a literal.
API_KEY_ENV_PATTERN = r"^\$\{([A-Z][A-Z0-9_]*)\}$"
CANONICAL_UUID_PATTERN = r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$"
MISP_BLOCK_KEYS = frozenset(MispIntegration.model_fields)
REQUIRED_MISP_KEYS = frozenset(
    name for name, field in MispIntegration.model_fields.items() if field.is_required()
)

REQUEST_TIMEOUT_SECONDS = 30.0
SEARCH_PAGE_SIZE = 100

OPENTIDE_TEMPLATE_UUID = "892fd46a-f69e-455c-8c4f-843a4b8f4295"
OPENTIDE_TEMPLATE_VERSION = 5
OPENTIDE_TEMPLATE_NAME = "opentide"
OPENTIDE_META_CATEGORY = "misc"
REQUIRED_TEMPLATE_RELATIONS = (
    "name",
    "opentide-object",
    "opentide-type",
    "uuid",
    "version",
    "schema",
)

LEDGER_PATH = ".opentide/states/sharing.jsonl"
SHARING_CONFIG_NAME = "sharing.toml"
