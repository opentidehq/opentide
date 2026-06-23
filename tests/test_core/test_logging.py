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


def test_debug_suppressed_without_debug_flag() -> None:
    init_logging(LoggingConfig(debug=False), force=True)
    stream = StringIO()
    handler = logging.StreamHandler(stream)
    handler.setFormatter(logging.getLogger().handlers[0].formatter)
    root = logging.getLogger()
    root.handlers.clear()
    root.addHandler(handler)
    logger = get_logger("tests.logging")
    logger.debug("hidden_debug_event")
    assert stream.getvalue() == ""


def test_info_emits_structured_event() -> None:
    stream = StringIO()
    init_logging(LoggingConfig(json_output=True), force=True)
    handler = logging.StreamHandler(stream)
    handler.setFormatter(logging.getLogger().handlers[0].formatter)
    root = logging.getLogger()
    root.handlers.clear()
    root.addHandler(handler)
    logger = get_logger("tests.logging")
    logger.info("deploy_started", platform="splunk", detail="extra")
    payload = json.loads(stream.getvalue().strip())
    assert payload["event"] == "deploy_started"
    assert payload["platform"] == "splunk"
    assert payload["detail"] == "extra"
    assert payload["level"] == "info"
    assert payload["logger"] == "tests.logging"


def test_emit_section_uses_console_panel() -> None:
    from opentide.core.logging.config import get_console

    init_logging(LoggingConfig(plain=False), force=True)
    with mock.patch.object(get_console(), "print") as mock_print:
        emit_section("Generate Schemas")
        mock_print.assert_called_once()


def test_emit_section_json_mode() -> None:
    stream = StringIO()
    init_logging(LoggingConfig(json_output=True), force=True)
    handler = logging.StreamHandler(stream)
    handler.setFormatter(logging.getLogger().handlers[0].formatter)
    root = logging.getLogger()
    root.handlers.clear()
    root.addHandler(handler)
    emit_section("Generate Schemas")
    payload = json.loads(stream.getvalue().strip())
    assert payload["event"] == "section_started"
    assert payload["section"] == "Generate Schemas"


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


def test_emit_fatal_json_mode() -> None:
    stream = StringIO()
    init_logging(LoggingConfig(json_output=True), force=True)
    handler = logging.StreamHandler(stream)
    handler.setFormatter(logging.getLogger().handlers[0].formatter)
    root = logging.getLogger()
    root.handlers.clear()
    root.addHandler(handler)
    emit_fatal("boom", detail="more", advice="fix it")
    payload = json.loads(stream.getvalue().strip())
    assert payload["event"] == "fatal_error"
    assert payload["error"] == "boom"
    assert payload["detail"] == "more"
    assert payload["advice"] == "fix it"


def test_print_banner_returns_text() -> None:
    init_logging(LoggingConfig(plain=True), force=True)
    banner = print_banner()
    assert ":--==-:." in banner


def test_console_renderer_uses_level_styling_only() -> None:
    from opentide.core.logging.render import OpenTideConsoleRenderer

    renderer = OpenTideConsoleRenderer(use_color=False)
    rendered = renderer.render(
        {
            "event": "deploying_rule",
            "level": "info",
            "timestamp": "2026-06-23 12:00:00",
            "mdr_name": "mdr-123",
        },
        "info",
    )
    assert "deploying_rule" in rendered
    assert "mdr-123" in rendered
    assert "ONGOING" not in rendered
