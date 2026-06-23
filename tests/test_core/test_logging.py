"""Tests for opentide.core.logging configuration helpers."""

from __future__ import annotations

import json
import logging
import os
from io import StringIO
from unittest import mock

import pytest
import structlog

from opentide.core.logging import (
    LoggingConfig,
    bind_context,
    clear_context,
    get_logger,
    init_logging,
    is_debug_enabled,
    is_json_output,
    is_plain_output,
    log,
    print_banner,
    reset_for_tests,
)
from opentide.core.logging.console import emit_fatal, emit_section


@pytest.fixture(autouse=True)
def reset_logging_state() -> None:
    """Isolate logging configuration between tests."""
    reset_for_tests()
    structlog.reset_defaults()
    root = logging.getLogger()
    root.handlers.clear()
    yield
    reset_for_tests()
    structlog.reset_defaults()
    root.handlers.clear()


def test_is_debug_enabled_reads_env() -> None:
    with mock.patch.dict(os.environ, {"DEBUG_ENABLED": "1"}, clear=False):
        init_logging(LoggingConfig(debug=True), force=True)
        assert is_debug_enabled() is True
    reset_for_tests()
    init_logging(LoggingConfig(debug=False), force=True)
    assert is_debug_enabled() is False


def test_is_plain_output_respects_no_color() -> None:
    init_logging(LoggingConfig(plain=True), force=True)
    assert is_plain_output() is True


def test_is_plain_output_when_vscode() -> None:
    with mock.patch.dict(os.environ, {"TERM_PROGRAM": "vscode"}, clear=True):
        init_logging(force=True)
        assert is_plain_output() is True


def test_is_json_output() -> None:
    init_logging(LoggingConfig(json_output=True), force=True)
    assert is_json_output() is True


def test_init_logging_is_idempotent() -> None:
    init_logging()
    first_handlers = list(logging.getLogger().handlers)
    init_logging()
    assert logging.getLogger().handlers == first_handlers


def test_init_logging_force_reconfigures() -> None:
    init_logging()
    init_logging(force=True)
    assert logging.getLogger().handlers


def test_get_logger_returns_bound_logger() -> None:
    logger = get_logger("tests.logging")
    assert hasattr(logger, "info")
    assert hasattr(logger, "bind")


def test_bind_and_clear_context() -> None:
    init_logging()
    bind_context(job_id="abc")
    clear_context()


def test_log_debug_suppressed_without_debug() -> None:
    init_logging(LoggingConfig(debug=False), force=True)
    with mock.patch("opentide.core.logging.compat.get_logger") as mock_get_logger:
        log("DEBUG", "hidden debug event")
        mock_get_logger.assert_not_called()


def test_log_info_emits_with_category() -> None:
    with mock.patch("opentide.core.logging.compat.get_logger") as mock_get_logger:
        mock_logger = mock.MagicMock()
        mock_get_logger.return_value = mock_logger
        log("INFO", "progress", highlight="extra")
        mock_logger.log.assert_called_once()
        args, kwargs = mock_logger.log.call_args
        assert args[1] == "progress"
        assert kwargs["category"] == "INFO"
        assert kwargs["detail"] == "extra"


def test_emit_section_uses_console_panel() -> None:
    from opentide.core.logging.config import get_console

    init_logging(LoggingConfig(plain=False), force=True)
    with mock.patch.object(get_console(), "print") as mock_print:
        emit_section("Generate Schemas")
        mock_print.assert_called_once()


def test_emit_fatal_plain_mode() -> None:
    from opentide.core.logging.config import get_console

    init_logging(LoggingConfig(plain=True), force=True)
    buffer = StringIO()
    with mock.patch.object(
        get_console(),
        "print",
        side_effect=lambda *a, **k: buffer.write(str(a)),
    ):
        emit_fatal("boom", detail="more")
    assert "FATAL" in buffer.getvalue() or "boom" in buffer.getvalue()


def test_json_logging_emits_structured_records() -> None:
    stream = StringIO()
    init_logging(LoggingConfig(json_output=True), force=True)
    handler = logging.StreamHandler(stream)
    handler.setFormatter(logging.getLogger().handlers[0].formatter)
    root = logging.getLogger()
    root.handlers.clear()
    root.addHandler(handler)
    log("INFO", "structured event", highlight="detail")
    payload = json.loads(stream.getvalue().strip())
    assert payload["event"] == "structured event"
    assert payload["category"] == "INFO"
    assert payload["detail"] == "detail"


def test_print_banner_returns_text() -> None:
    init_logging(LoggingConfig(plain=True), force=True)
    banner = print_banner()
    assert ":--==-:." in banner


def test_console_renderer_applies_category_style() -> None:
    from opentide.core.logging.render import OpenTideConsoleRenderer

    renderer = OpenTideConsoleRenderer(use_color=False)
    rendered = renderer.render(
        {
            "event": "deploying rule",
            "level": "info",
            "timestamp": "2026-06-23 12:00:00",
            "category": "ONGOING",
            "detail": "mdr-123",
        },
        "info",
    )
    assert "deploying rule" in rendered
    assert "ONGOING" in rendered
    assert "mdr-123" in rendered
