"""``OpentideError`` survives pickling and copying with every field (#1142).

Its ``args`` hold the message alone (``"code: message"``), so the default
exception pickling called ``OpentideError("code: message")`` and failed: a
process pool could not hand a failed deploy back to its caller.
"""

from __future__ import annotations

import copy
import multiprocessing
import pickle
from collections.abc import Callable
from concurrent.futures import ProcessPoolExecutor

import pytest

from opentide import DeployEvent, DeployOutcome, DeployWarning, OpentideError


def _failed() -> OpentideError:
    further = OpentideError(
        "google_secops_deployment_failed",
        "rule ru_1 is bound, but its run state could not be set",
        "down",
        scope="rule",
        status=500,
        fields={"platform": "google_secops", "detail": "down"},
    )
    return OpentideError(
        "google_secops_text_failed",
        "Google refused the rule's text",
        None,
        scope="rule",
        status=400,
        fields={"platform": "google_secops", "tenant": "soc"},
        partial=DeployOutcome(
            remote_id="ru_1",
            operation="create",
            warnings=[DeployWarning("google_secops_rule_recreated", "creating it again")],
            events=[DeployEvent("google_secops_rule_created", {"rule_id": "ru_1"})],
        ),
        more_failures=[further],
    )


def _fields(error: OpentideError) -> tuple[object, ...]:
    return (
        type(error),
        str(error),
        error.args,
        error.code,
        error.message,
        error.detail,
        error.scope,
        error.status,
        error.fields,
        list(error.fields),
        error.partial,
        [_fields(further) for further in error.more_failures],
    )


@pytest.mark.parametrize(
    "round_trip",
    [
        lambda error: pickle.loads(pickle.dumps(error)),
        copy.copy,
        copy.deepcopy,
    ],
    ids=["pickle", "copy", "deepcopy"],
)
def test_an_error_round_trips_with_every_field(
    round_trip: Callable[[OpentideError], OpentideError],
) -> None:
    error = _failed()
    again = round_trip(error)
    assert again is not error
    assert _fields(again) == _fields(error)


def test_a_plain_error_round_trips_too() -> None:
    error = OpentideError("usage_invalid_choice", "no such platform")
    again = pickle.loads(pickle.dumps(error))
    assert _fields(again) == _fields(error)
    assert (again.scope, again.status, again.fields, again.partial, again.more_failures) == (
        None,
        None,
        {},
        None,
        [],
    )


class _Named(OpentideError):
    """A subclass with a constructor of its own."""

    def __init__(self, name: str) -> None:
        super().__init__("named", f"{name} failed", scope="rule")
        self.name = name


def test_a_subclass_and_an_error_that_holds_itself_round_trip() -> None:
    named = _Named("rule-a")
    again = pickle.loads(pickle.dumps(named))
    assert _fields(again) == _fields(named)
    assert again.name == "rule-a"
    looped = _failed()
    looped.more_failures.append(looped)
    copied = copy.deepcopy(looped)
    assert copied.more_failures[-1] is copied
    unpickled = pickle.loads(pickle.dumps(looped))
    assert unpickled.more_failures[-1] is unpickled


def _raise_in_a_worker() -> None:
    raise _failed()


def test_a_process_pool_hands_the_error_back_to_its_caller() -> None:
    # `spawn`: the test process runs threads (the SDK's runtime), which a fork
    # would copy mid-flight.
    spawn = multiprocessing.get_context("spawn")
    with ProcessPoolExecutor(max_workers=1, mp_context=spawn) as pool:
        future = pool.submit(_raise_in_a_worker)
        with pytest.raises(OpentideError) as raised:
            future.result(timeout=60)
    assert _fields(raised.value) == _fields(_failed())
