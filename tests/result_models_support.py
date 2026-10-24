"""Check every ``--json`` document against its command's result model and output schema.

The models allow keys they do not name, because the JSON contract is
additive. These checks do not: a key no model names fails, so a service that
gains a key has to gain it in its model too, and ``opentide commands --json``
keeps describing what the commands print.

Registered as a plugin from the root ``conftest.py``. In every ``cli_e2e``
test, :func:`check_printed_documents` checks each document the CLI prints
in-process, so the whole E2E corpus runs through the models. Production code
never validates against them.
"""

from __future__ import annotations

from collections.abc import Iterator, Mapping
from functools import cache
from typing import Any

import pytest


@cache
def _schema(command: str) -> dict[str, Any]:
    from opentide.cli.ui.results import output_schemas

    schemas, defs = output_schemas([command])
    return {**(schemas[command] or {}), "$defs": defs}


def _undeclared(value: Any, path: str = "$") -> Iterator[str]:
    """Paths of keys a model accepted without naming them."""
    from pydantic import BaseModel

    if isinstance(value, BaseModel):
        for key in sorted(value.model_extra or {}):
            yield f"{path}.{key}"
        for name in type(value).model_fields:
            yield from _undeclared(getattr(value, name), f"{path}.{name}")
    elif isinstance(value, Mapping):
        for key, item in value.items():
            yield from _undeclared(item, f"{path}.{key}")
    elif isinstance(value, (list, tuple)):
        for index, item in enumerate(value):
            yield from _undeclared(item, f"{path}[{index}]")


def document_problems(document: Mapping[str, Any]) -> list[str]:
    """Why *document* does not match its command's model and schema; empty when it does."""
    import jsonschema
    from pydantic import ValidationError

    from opentide.cli.ui.results import (
        NO_DOCUMENT,
        PENDING_MODELS,
        RESULT_MODELS,
        CommandDocument,
        CommandError,
    )

    command = str(document.get("command", ""))
    if command in NO_DOCUMENT:
        return [f"{command!r} printed a JSON document; it is listed as printing none"]
    if not command or command.split(" ")[0] in PENDING_MODELS:
        # A library caller, or a command whose model is still to come: only
        # the envelope is known.
        try:
            CommandDocument.model_validate(document)
        except ValidationError as exc:
            return [f"{command!r} does not carry the envelope:\n{exc}"]
        return []
    model = RESULT_MODELS.get(command)
    if model is None:
        return [f"no result model for {command!r}: add it to RESULT_MODELS"]
    try:
        validated = model.model_validate(document)
    except ValidationError as own:
        try:
            validated = CommandError.model_validate(document)
        except ValidationError:
            return [f"{command!r} does not match {model.__name__}:\n{own}"]
    problems = [
        f"{command!r}: {key} is not in {type(validated).__name__}" for key in _undeclared(validated)
    ]
    try:
        jsonschema.validate(dict(document), _schema(command))
    except jsonschema.ValidationError as exc:
        problems.append(f"{command!r} does not match its output schema: {exc.message}")
    return problems


def assert_matches_model(document: Mapping[str, Any]) -> None:
    problems = document_problems(document)
    assert not problems, "\n".join(problems)


@pytest.fixture(autouse=True)
def check_printed_documents(
    request: pytest.FixtureRequest, monkeypatch: pytest.MonkeyPatch
) -> Iterator[list[str]]:
    """In a ``cli_e2e`` test, check each document the CLI prints; fail the test on a mismatch.

    Problems are collected and reported when the test ends: an assertion
    raised inside the command would surface as a confusing exit code.
    """
    problems: list[str] = []
    if request.node.get_closest_marker("cli_e2e") is None:
        yield problems
        return
    from opentide.cli import output

    original = output.print_document

    def checked(document: Mapping[str, Any]) -> None:
        problems.extend(document_problems(document))
        original(document)

    monkeypatch.setattr(output, "print_document", checked)
    yield problems
    assert not problems, "\n".join(problems)
