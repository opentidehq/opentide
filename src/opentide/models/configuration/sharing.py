"""`sharing.toml`: sharing destinations, one array of tables per connector.

The file has no global table. `[[misp]]` is the only connector in
sharing 1.0; each block is a `sharing::misp::1.0` item. A top-level array
naming another connector (`[[opencti]]`) is skipped with a warning, so the
document itself stays open; any other top-level value is rejected.
"""

from __future__ import annotations

from collections.abc import Mapping
from typing import Annotated, Any, ClassVar, Literal
from urllib.parse import urlparse

from pydantic import ConfigDict, Field, field_validator, model_validator

from opentide.models.configuration.base import ConfigurationModel

# Kept equal to `opentide.sharing.constants` by a test. Importing that package
# here would import the sharing loader, which imports this module.
NAME_PATTERN = r"^[a-z0-9_-]{1,64}$"
DEFAULT_OBJECT_TYPES = ("threat", "objective", "rule")
DEFAULT_RULE_STATUSES = ("PRODUCTION",)

#: `tlp` vocabulary names, in ceiling order.
TlpName = Literal["clear", "green", "amber", "amber+strict", "red"]
ObjectFamily = Literal["threat", "objective", "rule"]

#: The `8-4-4-4-12` hex form, hyphens required, either case.
ORGANISATION_UUID_PATTERN = (
    r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$"
)

MISP_SCHEMA_ID = "sharing::misp::1.0"
#: Annotation keyword carrying a schema identifier in exported JSON Schema.
SCHEMA_ID_KEYWORD = "x-opentide-schema-id"


class MispIntegration(ConfigurationModel):
    """One `[[misp]]` block: a MISP instance objects are shared to."""

    __schema_identifier__: ClassVar[str] = MISP_SCHEMA_ID
    model_config = ConfigDict(
        title="sharing::misp::1.0", json_schema_extra={SCHEMA_ID_KEYWORD: MISP_SCHEMA_ID}
    )

    name: str = Field(
        pattern=NAME_PATTERN,
        description=(
            "Block name: 1 to 64 lowercase letters, digits, hyphens or underscores. "
            "A later layer restating it overrides this block key by key."
        ),
    )
    enabled: bool = Field(default=False, description="Share to this instance.")
    url: str = Field(
        min_length=1,
        description="Base URL of the MISP instance (http or https).",
        json_schema_extra={"format": "uri"},
    )
    api_key: str = Field(
        min_length=1,
        description=(
            "MISP automation key. Write a ${NAME} reference to an environment variable; "
            "a literal key is reported as a warning."
        ),
    )
    max_tlp: TlpName = Field(
        description=(
            "Highest tlp an object may carry and still be shared here. There is no default."
        )
    )
    object_types: list[ObjectFamily] = Field(
        default=list(DEFAULT_OBJECT_TYPES),
        description="Object families shared to this instance.",
    )
    rule_statuses: list[Annotated[str, Field(min_length=1)]] = Field(
        default=list(DEFAULT_RULE_STATUSES),
        description=(
            "Deployment statuses a rule must have to be shared. Names from deployment.toml."
        ),
    )
    organisation_uuid: str | None = Field(
        default=None,
        pattern=ORGANISATION_UUID_PATTERN,
        description=(
            "UUID of the MISP organisation the events are created for. "
            "Omit to use the object's organisation."
        ),
    )
    publish: bool = Field(default=False, description="Publish events after writing them.")
    verify_ssl: bool = Field(default=True, description="Verify the instance's TLS certificate.")

    @field_validator("url")
    @classmethod
    def _http_url(cls, value: str) -> str:
        parsed = urlparse(value.strip())
        if parsed.scheme not in {"http", "https"} or not parsed.netloc:
            raise ValueError("url must be an http(s) URL")
        return value


def _is_table_array(value: object) -> bool:
    return isinstance(value, list) and all(isinstance(item, Mapping) for item in value)


class SharingConfiguration(ConfigurationModel):
    """Merged `sharing.toml`. Top-level keys are connector arrays; `[[misp]]` is the only one."""

    model_config = ConfigDict(
        extra="allow",
        json_schema_extra={
            "additionalProperties": {
                "type": "array",
                "items": {"type": "object"},
                "description": "Unknown connector: skipped with a warning.",
            }
        },
    )

    misp: list[MispIntegration] = Field(
        default_factory=list, description="MISP instances, one block each."
    )

    @model_validator(mode="before")
    @classmethod
    def _only_connector_arrays(cls, data: Any) -> Any:
        if isinstance(data, Mapping):
            for key, value in data.items():
                if key != "misp" and not _is_table_array(value):
                    raise ValueError(
                        f"{key!r} is not a connector array; the top level holds [[misp]] blocks"
                    )
        return data

    def unknown_connectors(self) -> list[str]:
        """Top-level arrays naming a connector opentide does not know."""
        return sorted((self.model_extra or {}).keys())
