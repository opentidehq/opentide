"""Smoke tests for the opentide package scaffold."""


def test_import_opentide() -> None:
    import opentide

    assert opentide.__version__
