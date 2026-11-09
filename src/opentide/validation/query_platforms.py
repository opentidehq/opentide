"""Platforms whose queries can be checked against a tenant.

CrowdStrike, HarfangLab and Sysdig have no tenant-side query check, so their
capability entry is ``can_validate False``; the analysis engine checks
CrowdStrike's CQL and Sysdig's Falco conditions offline.
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
#: Sysdig's Falco condition and CrowdStrike's Next-Gen SIEM query (CQL) are checked
#: offline only: neither platform has a query check opentide can call.
#: SentinelOne (S1QL) is checked on the tenant only (``validate query --live``).
#: HarfangLab is never checked: no fake validation.
OFFLINE_QUERY_LANGUAGES: dict[str, tuple[str, ...]] = {
    "sentinel": ("kql",),
    "defender_for_endpoint": ("kql",),
    "splunk": ("spl",),
    "elastic": ("esql", "eql", "kuery", "lucene"),
    "carbon_black_cloud": ("lucene",),
    "sysdig": ("falco",),
    "crowdstrike": ("cql",),
}
OFFLINE_QUERY_PLATFORMS = frozenset(OFFLINE_QUERY_LANGUAGES)
