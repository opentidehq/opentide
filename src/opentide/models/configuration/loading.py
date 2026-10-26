"""Validate a merged configuration document against its model on the load path."""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar

from pydantic import BaseModel, ValidationError

M = TypeVar("M", bound=BaseModel)


class ConfigurationError(ValueError):
    """A merged configuration file does not match its model.

    The message names the file and each failing key. It never repeats a
    value: tenant `setup` tables hold credentials.
    """

    def __init__(
        self, file_key: str, errors: list[tuple[tuple[str, ...], str]], *, prefix: str = ""
    ) -> None:
        self.file_key = file_key
        self.errors = errors
        lines = [f"{'.'.join(loc) or '(document)'}: {message}" for loc, message in errors]
        super().__init__(f"{prefix}{file_key} is invalid: " + "; ".join(lines))


def _input_path(data: Any, loc: tuple[Any, ...], kind: str) -> tuple[tuple[str, ...], bool]:
    """The part of *loc* that names keys and indexes of *data*.

    Pydantic puts a union member's tag (`list[...]`, `FlavorSettings`) in the
    location of an error raised inside that member; those are not keys. The
    flag is true when a tag was dropped, that is, the error is one branch of a
    union.
    """
    path: list[str] = []
    node: Any = data
    branch = False
    for position, part in enumerate(loc):
        if (isinstance(node, Mapping) and part in node) or (
            isinstance(node, list) and isinstance(part, int) and 0 <= part < len(node)
        ):
            node = node[part]
            path.append(str(part))
        elif kind == "missing" and position == len(loc) - 1 and isinstance(node, Mapping):
            # The missing key itself: not in the input, but a key.
            path.append(str(part))
        else:
            branch = True
    return tuple(path), branch


def model_errors(exc: ValidationError, data: Any) -> list[tuple[tuple[str, ...], str, str]]:
    """`(key path, error type, message)` per error, inputs never included.

    Of the errors a failed union raises (one per member), the ones that reach
    deepest into the input are kept: an entry list whose second item is wrong
    is reported on that item, not also as "not a single strategy".
    """
    located: list[tuple[tuple[str, ...], str, str, bool]] = []
    for err in exc.errors(include_url=False):
        kind = str(err.get("type", ""))
        path, branch = _input_path(data, tuple(err.get("loc", ())), kind)
        located.append((path, kind, str(err.get("msg", "")), branch))
    kept: list[tuple[tuple[str, ...], str, str]] = []
    seen: set[tuple[str, ...]] = set()
    for path, kind, message, branch in sorted(located, key=_branch_rank):
        if branch:
            deeper = any(
                other[3] and len(other[0]) > len(path) and other[0][: len(path)] == path
                for other in located
            )
            if deeper or path in seen:
                continue
        seen.add(path)
        kept.append((path, kind, message))
    order = {path: index for index, (path, *_rest) in enumerate(located)}
    return sorted(kept, key=lambda item: order.get(item[0], 0))


#: Error types that only say "not this union member's type".
_TYPE_MISMATCH = ("_type", "is_instance_of", "model_attributes_type")


def _branch_rank(item: tuple[tuple[str, ...], str, str, bool]) -> int:
    """Among a union's errors on one key, report what was wrong before what was expected.

    `strategies = "DELETION"` fails both the list member ("Input should be a
    valid list") and the single-strategy member ("must be PREVIEW or
    RELEASE"); the second is the one that helps.
    """
    _path, kind, _message, branch = item
    if not branch:
        return 0
    return 2 if kind.endswith(_TYPE_MISMATCH) else 1


def error_locations(exc: ValidationError, data: Any = None) -> list[tuple[tuple[str, ...], str]]:
    """`(key path, message)` for each error, without the offending input."""
    located: list[tuple[tuple[str, ...], str]] = []
    for path, kind, message in model_errors(exc, data):
        if kind == "extra_forbidden":
            message = "unknown key"
        elif kind == "missing":
            message = "required key is missing"
        located.append((path, message or "invalid value"))
    return located


def validate_configuration(model: type[M], data: Mapping[str, Any], *, file_key: str) -> M:
    """`model.model_validate(data)`, raising `ConfigurationError` naming *file_key*."""
    try:
        return model.model_validate(dict(data))
    except ValidationError as exc:
        errors = error_locations(exc, data)
    # Raised outside the handler: the ValidationError holds the inputs, so it
    # must not ride along as the new exception's `__context__`.
    raise ConfigurationError(file_key, errors)
