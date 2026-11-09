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
#: Sysdig's Falco condition is checked offline only: Sysdig has no rule preview.
#: SentinelOne (S1QL) is checked on the tenant only (``validate query --live``).
#: CrowdStrike and HarfangLab are never checked: no fake validation.
OFFLINE_QUERY_LANGUAGES: dict[str, tuple[str, ...]] = {
    "sentinel": ("kql",),
    "defender_for_endpoint": ("kql",),
    "splunk": ("spl",),
    "elastic": ("esql", "eql", "kuery", "lucene"),
    "carbon_black_cloud": ("lucene",),
    "sysdig": ("falco",),
}
OFFLINE_QUERY_PLATFORMS = frozenset(OFFLINE_QUERY_LANGUAGES)
#: Every language the CLI checks offline. The engine reads more (CQL, for
#: CrowdStrike): a query in another language is the editor's, not ``validate``'s
#: or ``lint``'s, until its platform is in :data:`OFFLINE_QUERY_LANGUAGES`.
OFFLINE_LANGUAGES: frozenset[str] = frozenset(
    language for languages in OFFLINE_QUERY_LANGUAGES.values() for language in languages
)
