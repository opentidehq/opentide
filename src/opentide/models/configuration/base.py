"""Shared base and field types for configuration TOML models."""

from __future__ import annotations

from typing import Annotated, Any, Literal

from pydantic import BaseModel, BeforeValidator, ConfigDict, Field, PlainSerializer, WithJsonSchema

from opentide.models.deployment_enums import DEPLOYABLE_STRATEGIES, StatusStrategy


class ConfigurationModel(BaseModel):
    """Base for one table of a configuration file.

    Unknown keys are rejected, values are checked strictly (TOML already
    types them, and the exported JSON Schema is strict), and the offending
    input is never repeated in an error: tenant `setup` tables carry
    credentials.
    """

    model_config = ConfigDict(
        extra="forbid",
        frozen=True,
        strict=True,
        hide_input_in_errors=True,
        populate_by_name=True,
    )


class OpenConfigurationModel(ConfigurationModel):
    """A table whose keys are not fixed by the specification."""

    model_config = ConfigDict(extra="allow")


def _status_strategy(value: Any) -> Any:
    if isinstance(value, str):
        member = StatusStrategy.__members__.get(value)
        if member is None:
            allowed = ", ".join(StatusStrategy.__members__)
            raise ValueError(f"strategy must be one of {allowed}")
        return member
    return value


#: `StatusStrategy` written by name in TOML (`strategy = "PREVIEW"`).
StatusStrategyName = Annotated[
    StatusStrategy,
    BeforeValidator(_status_strategy),
    PlainSerializer(lambda member: member.name, return_type=str),
    WithJsonSchema({"type": "string", "enum": list(StatusStrategy.__members__)}),
]


def _run_strategy(value: Any) -> Any:
    if isinstance(value, str):
        member = StatusStrategy.__members__.get(value.strip().upper())
        if member is None or member not in DEPLOYABLE_STRATEGIES:
            allowed = " or ".join(strategy.name for strategy in DEPLOYABLE_STRATEGIES)
            raise ValueError(f"a tenant strategy must be {allowed}")
        return member
    return value


def _any_case(word: str) -> str:
    return "".join(f"[{c.lower()}{c.upper()}]" if c.isalpha() else c for c in word)


def enum_or_any_case(names: list[str]) -> dict[str, Any]:
    """JSON Schema offering *names* for completion and accepting them in any case.

    The loaders read these values case-insensitively (`strategies = ["release"]`
    has always worked), so the schema must not reject what the CLI accepts.
    """
    pattern = r"^\s*(" + "|".join(_any_case(name) for name in names) + r")\s*$"
    return {"type": "string", "anyOf": [{"enum": names}, {"pattern": pattern}]}


#: A strategy a tenant accepts: `PREVIEW` or `RELEASE`, in any case.
RunStrategyName = Annotated[
    StatusStrategy,
    BeforeValidator(_run_strategy),
    PlainSerializer(lambda member: member.name, return_type=str),
    WithJsonSchema(enum_or_any_case([strategy.name for strategy in DEPLOYABLE_STRATEGIES])),
]

#: A `$NAME` placeholder the loader replaces with that environment variable.
EnvPlaceholder = Annotated[
    str,
    Field(
        pattern=r"^\$",
        description="Environment variable placeholder ($NAME), resolved when the tenant loads.",
    ),
]

#: The object families a configuration can scope.
OBJECT_FAMILY_NAMES = ("threat", "objective", "rule")
ObjectFamily = Literal["threat", "objective", "rule"]

#: Words a tenant `ssl` may be written as, in any case (the loader's `_SSL_WORDS`).
SSL_WORDS = ("true", "false", "yes", "no", "on", "off", "1", "0")


#: A tenant `ssl`: a boolean, a boolean word, or a `$NAME` placeholder.
SslValue = (
    bool
    | EnvPlaceholder
    | Annotated[
        str,
        Field(
            pattern="^(" + "|".join(_any_case(word) for word in SSL_WORDS) + ")$",
            description="A boolean written as a word: true/false, yes/no, on/off, 1/0.",
        ),
    ]
)
