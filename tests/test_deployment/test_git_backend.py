"""Smoke tests for Dulwich git backend."""

from __future__ import annotations

from opentide.deployment.git_backend import rust_extensions_available


def test_rust_extensions_available_is_bool() -> None:
    """Dulwich Rust acceleration probe returns a boolean (CI diagnostic)."""
    assert isinstance(rust_extensions_available(), bool)
