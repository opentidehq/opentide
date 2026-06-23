"""Tests for opentide.core.logging configuration helpers."""

from __future__ import annotations

import logging
import os
from unittest import mock

import pytest
import structlog

from opentide.core import logging as tide_logging


@pytest.fixture(autouse=True)
def reset_logging_state() -> None:
    """Isolate logging configuration between tests."""
    tide_logging._configured = False
    structlog.reset_defaults()
    root = logging.getLogger()
    root.handlers.clear()
    yield
    tide_logging._configured = False
    structlog.reset_defaults()
    root.handlers.clear()


def test_is_debug_enabled_reads_env() -> None:
    with mock.patch.dict(os.environ, {"DEBUG_ENABLED": "True"}, clear=False):
        assert tide_logging.is_debug_enabled() is True
    with mock.patch.dict(os.environ, {}, clear=True):
        assert tide_logging.is_debug_enabled() is False


def test_is_plain_output_when_vscode() -> None:
    with mock.patch.dict(os.environ, {"TERM_PROGRAM": "vscode"}, clear=True):
        assert tide_logging.is_plain_output() is True


def test_configure_logging_is_idempotent() -> None:
    tide_logging.configure_logging()
    first_handlers = list(logging.getLogger().handlers)
    tide_logging.configure_logging()
    assert logging.getLogger().handlers == first_handlers


def test_configure_logging_force_reconfigures() -> None:
    tide_logging.configure_logging()
    tide_logging.configure_logging(force=True)
    assert tide_logging._configured is True
    assert logging.getLogger().handlers


def test_get_logger_returns_bound_logger() -> None:
    logger = tide_logging.get_logger("tests.logging")
    assert hasattr(logger, "info")
    assert hasattr(logger, "bind")


def test_bind_and_clear_context() -> None:
    tide_logging.configure_logging()
    tide_logging.bind_context(job_id="abc")
    tide_logging.clear_context()


def test_log_debug_suppressed_without_env() -> None:
    with mock.patch.dict(os.environ, {}, clear=True):
        tide_logging.log("DEBUG", "hidden debug event")


def test_log_info_emits_with_category() -> None:
    with mock.patch.object(tide_logging, "get_logger") as mock_get_logger:
        mock_logger = mock.MagicMock()
        mock_get_logger.return_value = mock_logger
        tide_logging.log("INFO", "progress", highlight="extra")
        mock_logger.log.assert_called_once()
        args, kwargs = mock_logger.log.call_args
        assert args[1] == "progress"
        assert kwargs["category"] == "INFO"
        assert kwargs["detail"] == "extra"


def test_log_title_uses_console_panel() -> None:
    with mock.patch.object(tide_logging._console, "print") as mock_print:
        tide_logging.log("TITLE", "Generate Schemas")
        mock_print.assert_called_once()


def test_print_banner_returns_text() -> None:
    with mock.patch.dict(os.environ, {"DEBUG_ENABLED": "True"}, clear=True):
        banner = tide_logging.print_banner()
        assert ":--==-:." in banner
