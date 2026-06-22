"""Pytest configuration and shared fixtures."""

from __future__ import annotations

import os

# Engine modules expect a recognised CI/debug context at import time.
os.environ.setdefault("TERM_PROGRAM", "vscode")
