"""Platforms whose queries can be checked against a tenant.

CrowdStrike and HarfangLab expose no query language, so their capability
entry is ``can_validate False``.
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
    }
)

#: Platforms whose rule queries the analysis engine checks offline, and their languages.
#: SentinelOne (S1QL) is checked on the tenant only (``validate query --live``).
#: CrowdStrike and HarfangLab are never checked: no fake validation.
OFFLINE_QUERY_LANGUAGES: dict[str, tuple[str, ...]] = {
    "sentinel": ("kql",),
    "defender_for_endpoint": ("kql",),
    "splunk": ("spl",),
    "elastic": ("esql", "eql", "kuery", "lucene"),
    "carbon_black_cloud": ("lucene",),
}
OFFLINE_QUERY_PLATFORMS = frozenset(OFFLINE_QUERY_LANGUAGES)
