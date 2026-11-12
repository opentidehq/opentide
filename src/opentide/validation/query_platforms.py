"""Platforms whose queries can be checked against a tenant.

CrowdStrike, HarfangLab, Sysdig and Bitdefender have no tenant check, so their
capability entry is ``can_validate False``. HarfangLab's YARA is checked offline.
"""

from __future__ import annotations

QUERY_VALIDATION_PLATFORMS: frozenset[str] = frozenset(
    {
        "sentinel",
        "defender_for_endpoint",
        "splunk",
        "sentinel_one",
        "carbon_black_cloud",
        "elastic",
        "exabeam",
    }
)

#: Platforms whose rule queries the analysis engine checks offline, and their languages.
#: Sysdig's Falco condition is checked offline only: Sysdig has no rule preview.
#: HarfangLab's YARA (``yara.signature`` and the rule the decomposed form assembles) is
#: checked offline only: HarfangLab has no YARA dry run (harfanglab-1.0, yara-1.0).
#: Bitdefender's ``yara.signature`` is checked offline only, under the engine's
#: bitdefender profile (ASCII, 30,000 characters; bitdefender-1.0): GravityZone has
#: no dry run.
#: Exabeam's sequence queries are the Exabeam Query Language (``exabeam``, profile
#: ``rule``), checked offline and, the filter only, live through Search (exabeam-1.0).
#: SentinelOne (S1QL) is checked on the tenant only (``validate query --live``).
#: CrowdStrike is never checked: no fake validation.
OFFLINE_QUERY_LANGUAGES: dict[str, tuple[str, ...]] = {
    "sentinel": ("kql",),
    "defender_for_endpoint": ("kql",),
    "splunk": ("spl",),
    "elastic": ("esql", "eql", "kuery", "lucene"),
    "carbon_black_cloud": ("lucene",),
    "sysdig": ("falco",),
    "harfanglab": ("yara",),
    "bitdefender": ("yara",),
    "exabeam": ("exabeam",),
}
OFFLINE_QUERY_PLATFORMS = frozenset(OFFLINE_QUERY_LANGUAGES)
