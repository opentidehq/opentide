"""Normative constants for sharing 1.0."""

from __future__ import annotations

REDACTION_MARKER = "[REDACTED]"

INTEGRATION_MISP = "misp"
KNOWN_INTEGRATIONS = frozenset({INTEGRATION_MISP})

OBJECT_FAMILIES = ("threat", "objective", "rule")
DEFAULT_OBJECT_TYPES = OBJECT_FAMILIES
DEFAULT_RULE_STATUSES = ("PRODUCTION",)

# Ceiling order. Bundled ``tlp`` vocabulary keys use this same sequence.
TLP_ORDER = ("clear", "green", "amber", "amber+strict", "red")

NAME_PATTERN = r"^[a-z0-9_-]{1,64}$"
API_KEY_ENV_PATTERN = r"^\$\{([A-Za-z_][A-Za-z0-9_]*)\}$"
CANONICAL_UUID_PATTERN = r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$"

MISP_BLOCK_KEYS = frozenset(
    {
        "name",
        "enabled",
        "url",
        "api_key",
        "max_tlp",
        "object_types",
        "rule_statuses",
        "organisation_uuid",
        "publish",
        "verify_ssl",
    }
)
REQUIRED_MISP_KEYS = frozenset({"name", "url", "api_key", "max_tlp"})

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
