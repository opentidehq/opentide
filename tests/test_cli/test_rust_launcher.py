"""``opentide.cli.rust``: what the launcher tells the Rust command line (UC-3.5c, #928)."""

from __future__ import annotations

import json

import pytest

from opentide.cli import rust
from opentide.cli.services.doctor import PLATFORM_SDKS


def test_doctor_gets_each_platform_module_import_status() -> None:
    modules = rust.python_modules(["--json", "doctor", "--offline"])
    assert modules is not None
    status = json.loads(modules)
    assert set(status) == {module for names in PLATFORM_SDKS.values() for module in names}
    # ``requests`` is a dependency of opentide: it imports.
    assert status["requests"] is None


def test_a_module_that_does_not_import_says_why(monkeypatch: pytest.MonkeyPatch) -> None:
    from opentide.cli.services import doctor

    monkeypatch.setitem(doctor.PLATFORM_SDKS, "splunk", ("opentide_no_such_module",))
    status = json.loads(rust.python_modules(["doctor"]) or "{}")
    assert status["opentide_no_such_module"].startswith("ModuleNotFoundError")


def test_other_commands_pay_for_no_imports() -> None:
    assert rust.python_modules(["info"]) is None
    assert rust.python_modules(["migrate", "vocab-scope"]) is None
