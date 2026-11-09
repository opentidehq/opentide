"""Diagnostic codes nothing reports any more, which stay explainable.

A code is a contract (plan §3, invariant 3): a suppression list, a SARIF
baseline or a script may still name one after the engine or opentide stops
emitting it. So a retired code keeps its ``opentide explain`` page, its entry
in MCP ``explain``, its rule in the SARIF rule catalogue of ``lint`` and
``validate --format sarif`` and its section in ``docs/cli/diagnostics.md``,
each saying when it was retired and what reports the problem now.

:mod:`opentide.cli.services.explain` builds the page from the entry here
(:func:`opentide.cli.services.explain.retired_page`), and
:func:`opentide.cli.ui.reports.sarif_rule` tags the rule ``retired``. Retiring a
code is one entry in :data:`RETIRED_CODES`.
"""

from __future__ import annotations

from dataclasses import dataclass
from types import MappingProxyType
from typing import Literal


@dataclass(frozen=True)
class RetiredCode:
    code: str
    #: The release that stopped reporting it, e.g. ``"engine 0.12.0"``.
    retired_in: str
    #: What reports the problem now, in one Markdown sentence fragment.
    successor: str
    #: What the code reported, in one Markdown sentence.
    meaning: str
    #: Who reported it and where, in one Markdown paragraph.
    reported_by: str
    #: A command that shows what reports the problem now.
    example: str
    #: Its severity while it was reported, SARIF's ``defaultConfiguration.level``.
    level: Literal["error", "warning", "note"]


RETIRED_CODES: MappingProxyType[str, RetiredCode] = MappingProxyType(
    {
        retired.code: retired
        for retired in (
            RetiredCode(
                code="crowdstrike_unsupported",
                retired_in="engine 0.12.0",
                successor="CrowdStrike queries are now checked as CQL: see the `cql_*` codes",
                meaning=(
                    "CrowdStrike queries were not validated, and the engine said so rather "
                    "than fake it."
                ),
                reported_by=(
                    "Until engine 0.12.0, the analysis engine reported it as a warning on a "
                    "CrowdStrike rule's `crowdstrike` block: an editor running "
                    "`opentide lsp start` and `opentide tui` showed it. Engine 0.12.0 checks "
                    "the query as the CrowdStrike Query Language (CQL) instead, and reports "
                    "what it finds with the `cql_*` codes (`opentide explain` lists them). "
                    "No command reports `crowdstrike_unsupported` now."
                ),
                example="opentide explain cql_unknown_function",
                level="warning",
            ),
        )
    }
)
