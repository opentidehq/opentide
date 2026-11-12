"""What the documentation knows about each detection platform.

One :class:`PlatformProfile` per ``RuleConfigurations`` field: the name a page
shows, and the language of each block setting that holds code, so a query is
fenced and captioned in its own language (KQL, SPL, ES|QL, YARA) rather than
as generic text. ``tests/test_documentation/test_facts.py`` fails when a
platform is added to the rule model without a profile here.
"""

from __future__ import annotations

from collections.abc import Callable, Mapping
from dataclasses import dataclass, field


@dataclass(frozen=True)
class CodeLanguage:
    """A query or rule language: its display name and its code-fence info string."""

    name: str
    fence: str


KQL = CodeLanguage("KQL", "kql")
SPL = CodeLanguage("SPL", "spl")
S1QL = CodeLanguage("S1QL", "sql")
CQL = CodeLanguage("CQL", "cql")
LUCENE = CodeLanguage("Lucene", "lucene")
KUERY = CodeLanguage("Kibana KQL", "kql")
EQL = CodeLanguage("EQL", "eql")
ESQL = CodeLanguage("ES|QL", "esql")
YARA = CodeLanguage("YARA", "yara")
FALCO = CodeLanguage("Falco condition", "text")
GRAYLOG = CodeLanguage("Graylog search", "lucene")
EXABEAM = CodeLanguage("Exabeam Query Language", "text")
MARKDOWN = CodeLanguage("Markdown", "markdown")
TEXT = CodeLanguage("Text", "text")

#: ``(setting path, platform block)`` to the language of that setting, or ``None``.
LanguageResolver = Callable[[str, object], CodeLanguage | None]


@dataclass(frozen=True)
class PlatformProfile:
    """Display name and code languages of one platform block."""

    key: str
    label: str
    #: Setting path (list indices removed: ``exclusions.query``) to its language.
    languages: Mapping[str, CodeLanguage] = field(default_factory=dict)
    #: For a language that depends on another setting (Elastic's ``type``).
    resolver: LanguageResolver | None = None

    def language(self, path: str, block: object) -> CodeLanguage | None:
        """The language of the setting at *path*, if it holds code."""
        if self.resolver is not None:
            resolved = self.resolver(path, block)
            if resolved is not None:
                return resolved
        return self.languages.get(path)


def _elastic_language(path: str, block: object) -> CodeLanguage | None:
    if path == "query":
        rule_type = getattr(block, "type", None)
        if rule_type == "eql":
            return EQL
        if rule_type == "esql":
            return ESQL
        return LUCENE if getattr(block, "language", None) == "lucene" else KUERY
    if path in {"filters.query", "threat.query"}:
        return KUERY
    if path.startswith("guide."):
        return MARKDOWN
    return None


PROFILES: dict[str, PlatformProfile] = {
    profile.key: profile
    for profile in (
        PlatformProfile("sentinel", "Microsoft Sentinel", {"query": KQL, "exclusions.query": KQL}),
        PlatformProfile(
            "defender_for_endpoint",
            "Microsoft Defender for Endpoint",
            {"query": KQL, "exclusions.query": KQL},
        ),
        PlatformProfile(
            "splunk",
            "Splunk Enterprise Security",
            {"query": SPL, "actions.notable.drilldown.search": SPL},
        ),
        PlatformProfile(
            "sentinel_one",
            "SentinelOne",
            {
                "condition.single_event.query": S1QL,
                "condition.correlation.sub_queries.query": S1QL,
            },
        ),
        PlatformProfile("crowdstrike", "CrowdStrike Falcon", {"query": CQL}),
        PlatformProfile("harfanglab", "HarfangLab", {"yara.signature": YARA}),
        PlatformProfile("carbon_black_cloud", "Carbon Black Cloud", {"query": LUCENE}),
        PlatformProfile("elastic", "Elastic Security", resolver=_elastic_language),
        PlatformProfile("sysdig", "Sysdig Secure", {"condition": FALCO, "macros.condition": FALCO}),
        PlatformProfile("bitdefender", "Bitdefender GravityZone", {"yara.signature": YARA}),
        PlatformProfile("graylog", "Graylog", {"query": GRAYLOG}),
        PlatformProfile("exabeam", "Exabeam New-Scale SIEM", {"sequences.query": EXABEAM}),
    )
}


def profile_for(platform: str) -> PlatformProfile:
    """The profile of *platform*, or a plain one named after the key."""
    return PROFILES.get(platform) or PlatformProfile(platform, platform.replace("_", " ").title())


def platform_label(platform: str) -> str:
    """``sentinel`` as ``Microsoft Sentinel``."""
    return profile_for(platform).label
