"""The root conftest hands every test the structlog configuration it found."""

from __future__ import annotations

import sys
from types import ModuleType

import pytest
import structlog

pytest_plugins = ["pytester"]

_CONFTEST = """
import pytest
import structlog

from tests.conftest import pytest_runtest_protocol  # noqa: F401

_FOUND = (structlog.is_configured(), structlog.get_config())
# get_config() hands out the processor list itself, which an in-place edit changes.
_FOUND_CHAIN = list(_FOUND[1]["processors"])


@pytest.fixture
def structlog_as_found():
    return _FOUND


@pytest.fixture
def processors_as_found():
    return _FOUND_CHAIN
"""

_MODULE_LOGGER = """
import structlog

logger = structlog.get_logger(__name__)
"""

# What two in-process CLI calls do: the root callback runs init_logging each time.
_CLI_RUNS = """
import module_logger

from opentide.core.logging import LoggingConfig, init_logging


def test_a_cli_run_logs_through_a_module_logger():
    init_logging(LoggingConfig(), force=True)
    module_logger.logger.info("first_use")


def test_a_later_cli_run_configures_logging_again():
    init_logging(LoggingConfig(), force=True)
"""

_CAPTURE = """
import module_logger
from structlog.testing import capture_logs


def test_capture_logs_sees_the_module_logger():
    with capture_logs() as logs:
        module_logger.logger.error("captured")
    assert [entry["event"] for entry in logs] == ["captured"]
"""

_CLI_RUN_THEN_STAND_IN = """
import module_logger

from opentide.core.logging import LoggingConfig, init_logging


def test_a_cli_run_then_a_stand_in_for_the_module_logger(monkeypatch):
    init_logging(LoggingConfig(), force=True)
    module_logger.logger.info("first_use")
    monkeypatch.setattr(module_logger, "logger", None)
"""

_RECONFIGURES = """
import structlog


def test_resets_structlog():
    structlog.reset_defaults()


def test_configures_structlog():
    structlog.configure(processors=[], cache_logger_on_first_use=False)
"""

_LATER = """
import structlog


def test_structlog_is_as_the_session_found_it(structlog_as_found):
    configured, settings = structlog_as_found
    current = structlog.get_config()
    assert structlog.is_configured() is configured
    assert all(current[key] is value for key, value in settings.items())
"""

_EDITS_IN_PLACE = """
import structlog


def test_adds_a_processor_to_the_list_in_place():
    structlog.get_config()["processors"].append(lambda logger, method, event: event)
"""

_PROCESSORS_LATER = """
import structlog


def test_the_processor_list_is_as_the_session_found_it(structlog_as_found, processors_as_found):
    _, settings = structlog_as_found
    processors = structlog.get_config()["processors"]
    assert processors is settings["processors"]
    assert list(processors) == processors_as_found
"""


def _run(pytester: pytest.Pytester, **modules: str) -> pytest.RunResult:
    pytester.makeconftest(_CONFTEST)
    pytester.makepyfile(**modules)
    return pytester.runpytest_inprocess("-p", "no:randomly", "-p", "no:cacheprovider")


def test_capture_logs_sees_a_module_logger_first_used_before_two_cli_runs(
    pytester: pytest.Pytester,
) -> None:
    """The logger kept the first run's processors; capture_logs edited the second's."""
    result = _run(
        pytester, module_logger=_MODULE_LOGGER, test_a_cli_runs=_CLI_RUNS, test_b_capture=_CAPTURE
    )
    result.assert_outcomes(passed=3)


def test_capture_logs_sees_a_module_logger_monkeypatch_put_back(
    pytester: pytest.Pytester,
) -> None:
    """The root conftest's fixtures request monkeypatch first: it is torn down last."""
    result = _run(
        pytester,
        module_logger=_MODULE_LOGGER,
        test_a_cli_run=_CLI_RUN_THEN_STAND_IN,
        test_b_capture=_CAPTURE,
    )
    result.assert_outcomes(passed=2)


def test_a_test_cannot_leave_structlog_reconfigured_for_the_next(
    pytester: pytest.Pytester,
) -> None:
    result = _run(pytester, test_a_reconfigures=_RECONFIGURES, test_b_later=_LATER)
    result.assert_outcomes(passed=3)


def test_a_test_cannot_leave_the_processor_list_edited_in_place(
    pytester: pytest.Pytester,
) -> None:
    """An edit to the list itself leaves every setting the object it was.

    Loggers hold that list, and ``capture_logs()`` edits it in place: the hook
    puts its contents back, not only the objects.
    """
    result = _run(pytester, test_a_edits=_EDITS_IN_PLACE, test_b_later=_PROCESSORS_LATER)
    result.assert_outcomes(passed=2)


class _ClaimsToBeAModule:
    """Like cffi's ``Lib`` in ``sys.modules``: its ``__class__`` is ModuleType, no ``__dict__``."""

    __slots__ = ()

    @property
    def __class__(self) -> type:
        return ModuleType


def test_forgetting_cached_loggers_passes_over_what_only_claims_to_be_a_module(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """cryptography's ``_openssl.lib`` passes ``isinstance(..., ModuleType)``.

    Reading its ``__dict__`` raises, and an error in the protocol hook ends the session.
    """
    from tests.conftest import _forget_cached_loggers

    logger = structlog.wrap_logger(None, cache_logger_on_first_use=True)
    logger.bind()
    assert "bind" in vars(logger)
    holder = ModuleType("holds_a_cached_logger")
    vars(holder)["logger"] = logger
    monkeypatch.setitem(sys.modules, holder.__name__, holder)
    monkeypatch.setitem(sys.modules, "cffi_like.lib", _ClaimsToBeAModule())

    _forget_cached_loggers()

    assert "bind" not in vars(logger)
