#!/usr/bin/env python3
"""Fetch latest ATT&CK STIX and MISP actors and regenerate vocabs; schema pins never move."""

from __future__ import annotations

from opentide.vocabulary.sync_upstream import cli_main

if __name__ == "__main__":
    raise SystemExit(cli_main())
