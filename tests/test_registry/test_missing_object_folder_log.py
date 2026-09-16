"""Missing object folders are expected before authors write YAML (issue #212)."""

from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest

from opentide.registry.builder import (
    RegistryBuilder,
    reset_missing_object_folder_log_cache,
)


class _RecordingLogger:
    def __init__(self) -> None:
        self.events: list[tuple[str, str, dict[str, Any]]] = []

    def debug(self, event: str, **kwargs: Any) -> None:
        self.events.append(("debug", event, kwargs))

    def error(self, event: str, **kwargs: Any) -> None:
        self.events.append(("error", event, kwargs))


def _folder_events(logger: _RecordingLogger) -> list[tuple[str, dict[str, Any]]]:
    return [
        (level, payload)
        for level, event, payload in logger.events
        if event == "could_not_find_object_folder"
    ]


def test_absent_object_folder_logs_debug_not_error(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from opentide.registry import builder as builder_mod

    reset_missing_object_folder_log_cache()
    recorder = _RecordingLogger()
    monkeypatch.setattr(builder_mod, "logger", recorder)

    missing = tmp_path / "objects" / "threats"
    RegistryBuilder()._load_objects({"threat": missing}, {"threat": "threat::1.0"})

    events = _folder_events(recorder)
    assert events
    assert all(level == "debug" for level, _ in events)


def test_absent_object_folder_is_logged_once_per_path(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from opentide.registry import builder as builder_mod

    reset_missing_object_folder_log_cache()
    recorder = _RecordingLogger()
    monkeypatch.setattr(builder_mod, "logger", recorder)

    missing = tmp_path / "objects" / "rules"
    builder = RegistryBuilder()
    builder._load_objects({"rule": missing}, {"rule": "rule::1.0"})
    builder._load_objects({"rule": missing}, {"rule": "rule::1.0"})

    events = _folder_events(recorder)
    assert len(events) == 1
    assert events[0][0] == "debug"


def test_path_that_exists_but_is_not_a_directory_logs_error(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from opentide.registry import builder as builder_mod

    reset_missing_object_folder_log_cache()
    recorder = _RecordingLogger()
    monkeypatch.setattr(builder_mod, "logger", recorder)

    file_path = tmp_path / "objects" / "objectives"
    file_path.parent.mkdir(parents=True)
    file_path.write_text("not a directory\n", encoding="utf-8")
    RegistryBuilder()._load_objects({"objective": file_path}, {"objective": "objective::1.0"})

    events = _folder_events(recorder)
    assert events
    assert events[0][0] == "error"
    assert events[0][1].get("reason") == "not_a_directory"
