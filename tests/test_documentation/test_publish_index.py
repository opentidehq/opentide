"""Documentation index page rendering."""

from __future__ import annotations

from pathlib import Path
from unittest.mock import MagicMock, patch

from opentide.documentation.context import DocumentationContext
from opentide.documentation.format.factory import formatter_for
from opentide.documentation.publish.index import render_index, write_index
from opentide.documentation.types import DocumentFlavor, DocumentRecord, DocumentScope


def test_render_index_builds_table() -> None:
    formatter = formatter_for(DocumentFlavor.github)
    ctx = DocumentationContext(
        flavor=DocumentFlavor.github,
        output_dir=MagicMock(),
        formatter=formatter,
        folder_index_pages=True,
        uuid_permalinks=False,
    )
    records = [
        DocumentRecord(
            object_type=DocumentScope.rules,
            uuid="u1",
            name="Rule A",
            model=MagicMock(),
        ),
    ]
    with patch("opentide.documentation.publish.index.fw.relations_list", return_value={}):
        content = render_index(
            formatter,
            title="Detection Rules",
            folder="rules",
            records=records,
            ctx=ctx,
        )
    assert "Detection Rules" in content
    assert "Rule A" in content
    assert "[Rule A](rule-a.md)" in content
    assert "u1" in content
    assert "Related" in content
    assert "Platforms and status" in content
    assert "Severity" in content
    assert "`u1`" in content
    assert "0" in content


def test_write_index_skips_when_disabled() -> None:
    ctx = DocumentationContext(
        flavor=DocumentFlavor.github,
        output_dir=MagicMock(),
        formatter=formatter_for(DocumentFlavor.github),
        folder_index_pages=False,
        uuid_permalinks=False,
    )
    pub = MagicMock()
    write_index(ctx, pub, rules=[], objectives=[], threats=[])
    # No exception and no write when folder_index_pages is False


def test_write_index_writes_folder_pages(tmp_path: Path) -> None:
    formatter = formatter_for(DocumentFlavor.github)
    ctx = DocumentationContext(
        flavor=DocumentFlavor.github,
        output_dir=tmp_path,
        formatter=formatter,
        folder_index_pages=True,
        uuid_permalinks=False,
        index_relation_counts=False,
    )
    pub = MagicMock()
    pub.rules_dir = tmp_path / "rules"
    pub.objectives_dir = tmp_path / "objectives"
    pub.threats_dir = tmp_path / "threats"
    pub.output_root = tmp_path
    for folder in (pub.rules_dir, pub.objectives_dir, pub.threats_dir):
        folder.mkdir(parents=True)
    record = DocumentRecord(
        object_type=DocumentScope.rules,
        uuid="u1",
        name="Rule A",
        model=MagicMock(),
    )
    write_index(ctx, pub, rules=[record], objectives=[], threats=[])
    assert (pub.rules_dir / "README.md").is_file()
    assert (pub.objectives_dir / "README.md").is_file()
    assert (pub.threats_dir / "README.md").is_file()
    assert (pub.output_root / "README.md").is_file()
    assert "# Detection objectives" in (pub.objectives_dir / "README.md").read_text(
        encoding="utf-8"
    )


def test_write_index_writes_gitlab_order_file(tmp_path: Path) -> None:
    formatter = formatter_for(DocumentFlavor.gitlab)
    ctx = DocumentationContext(
        flavor=DocumentFlavor.gitlab,
        output_dir=tmp_path,
        formatter=formatter,
        folder_index_pages=True,
        uuid_permalinks=True,
        index_relation_counts=False,
    )
    pub = MagicMock()
    pub.rules_dir = tmp_path / "rules"
    pub.objectives_dir = tmp_path / "objectives"
    pub.threats_dir = tmp_path / "threats"
    pub.output_root = tmp_path
    for folder in (pub.rules_dir, pub.objectives_dir, pub.threats_dir):
        folder.mkdir(parents=True)
    record = DocumentRecord(
        object_type=DocumentScope.rules,
        uuid="rule-uuid",
        name="Rule A",
        model=MagicMock(),
    )
    write_index(ctx, pub, rules=[record], objectives=[], threats=[])
    assert (pub.rules_dir / ".order").read_text(encoding="utf-8") == "README\nrule-uuid\n"


def test_render_index_includes_icons_when_enabled() -> None:
    formatter = formatter_for(DocumentFlavor.github)
    ctx = DocumentationContext(
        flavor=DocumentFlavor.github,
        output_dir=MagicMock(),
        formatter=formatter,
        folder_index_pages=True,
        uuid_permalinks=False,
        index_icons=True,
    )
    records = [
        DocumentRecord(
            object_type=DocumentScope.rules,
            uuid="u1",
            name="Rule A",
            model=MagicMock(),
        ),
    ]
    with patch("opentide.documentation.publish.index.fw.relations_list", return_value={}):
        content = render_index(
            formatter,
            title="Detection Rules",
            folder="rules",
            records=records,
            ctx=ctx,
        )
    assert ":shield: Rule A" in content


def test_render_index_github_uses_slug_not_uuid_filename() -> None:
    """GitHub indexes must link to slugify(name).md even if uuid_permalinks leaked (#203)."""
    formatter = formatter_for(DocumentFlavor.github)
    ctx = DocumentationContext(
        flavor=DocumentFlavor.github,
        output_dir=MagicMock(),
        formatter=formatter,
        folder_index_pages=True,
        uuid_permalinks=True,
        index_relation_counts=False,
    )
    records = [
        DocumentRecord(
            object_type=DocumentScope.threats,
            uuid="00000000-0000-4000-8001-000000000001",
            name="Simulated Actor",
            model=MagicMock(),
        ),
    ]
    content = render_index(
        formatter,
        title="Threat Vectors",
        folder="threats",
        records=records,
        ctx=ctx,
    )
    assert "[Simulated Actor](simulated-actor.md)" in content
    assert "00000000-0000-4000-8001-000000000001.md" not in content


def test_write_index_github_root_uses_lowercase_folders(tmp_path: Path) -> None:
    formatter = formatter_for(DocumentFlavor.github)
    ctx = DocumentationContext(
        flavor=DocumentFlavor.github,
        output_dir=tmp_path,
        formatter=formatter,
        folder_index_pages=True,
        uuid_permalinks=False,
        index_relation_counts=False,
    )
    pub = MagicMock()
    pub.rules_dir = tmp_path / "rules"
    pub.objectives_dir = tmp_path / "objectives"
    pub.threats_dir = tmp_path / "threats"
    pub.output_root = tmp_path
    for folder in (pub.rules_dir, pub.objectives_dir, pub.threats_dir):
        folder.mkdir(parents=True)
    record = DocumentRecord(
        object_type=DocumentScope.threats,
        uuid="u1",
        name="Simulated Actor",
        model=MagicMock(),
    )
    write_index(ctx, pub, rules=[], objectives=[], threats=[record])
    root = (tmp_path / "README.md").read_text(encoding="utf-8")
    assert "threats/README.md" in root
    assert "Threats/" not in root
    assert (pub.threats_dir / "README.md").is_file()
    assert (pub.rules_dir / "README.md").is_file()
    assert (pub.objectives_dir / "README.md").is_file()


def test_write_index_writes_section_pages_when_every_folder_is_empty(tmp_path: Path) -> None:
    """#401: the root index links to section READMEs even when the count is 0."""
    formatter = formatter_for(DocumentFlavor.github)
    ctx = DocumentationContext(
        flavor=DocumentFlavor.github,
        output_dir=tmp_path,
        formatter=formatter,
        folder_index_pages=True,
        uuid_permalinks=False,
    )
    pub = MagicMock()
    pub.rules_dir = tmp_path / "rules"
    pub.objectives_dir = tmp_path / "objectives"
    pub.threats_dir = tmp_path / "threats"
    pub.output_root = tmp_path
    write_index(ctx, pub, rules=[], objectives=[], threats=[])
    root = (tmp_path / "README.md").read_text(encoding="utf-8")
    for folder, title in (
        ("rules", "Detection rules"),
        ("objectives", "Detection objectives"),
        ("threats", "Threat vectors"),
    ):
        page = tmp_path / folder / "README.md"
        assert page.is_file()
        text = page.read_text(encoding="utf-8")
        assert title in text
        assert f"{folder}/README.md" in root
        assert "| --- |" in text


def test_root_index_summarises_status_per_platform_and_coverage(
    tmp_path: Path, metadata: dict
) -> None:
    from opentide.documentation.facts.deployment import StaticEnvironment, StatusDefinition
    from opentide.documentation.publish.index import render_root_index
    from opentide.loading.objective_loader import load_objective_from_dict
    from opentide.models.deployment_enums import StatusStrategy
    from opentide.models.rule import DetectionRule

    signal_uuid = "00000000-0000-4000-8000-0000000000a1"
    objective = load_objective_from_dict(
        {
            "name": "Goal",
            "metadata": {
                **metadata,
                "uuid": "00000000-0000-4000-8000-0000000000b1",
                "schema": "objective::1.0",
            },
            "objective": {
                "priority": "High",
                "type": "Threat",
                "description": "d",
                "composition": {"strategy": "synergetic", "description": "c"},
                "threats": ["threat-1"],
                "signals": [
                    {
                        "name": "S",
                        "uuid": signal_uuid,
                        "description": "d",
                        "severity": "High",
                        "methodology": "Monitor process creation",
                        "entities": ["host"],
                        "data": {"availability": "Complete", "requirements": "logs"},
                    }
                ],
            },
        }
    )

    def rule(uuid: str, **blocks: dict) -> DetectionRule:
        return DetectionRule.from_yaml_dict(
            {
                "name": uuid,
                "metadata": {**metadata, "uuid": uuid},
                "description": "d",
                "techniques": ["T1059"],
                "detection_model": signal_uuid,
                "configurations": blocks,
            }
        )

    splunk = {"status": "PRODUCTION", "query": "index=main"}
    rules = [
        DocumentRecord(DocumentScope.rules, "r1", "r1", rule("r1", splunk=splunk)),
        DocumentRecord(
            DocumentScope.rules, "r2", "r2", rule("r2", splunk={**splunk, "status": "DRAFT"})
        ),
    ]
    ctx = DocumentationContext(
        flavor=DocumentFlavor.github,
        output_dir=tmp_path,
        formatter=formatter_for(DocumentFlavor.github),
        environment=StaticEnvironment(
            status_definitions=(
                StatusDefinition("DRAFT", "", StatusStrategy.INERT),
                StatusDefinition("PRODUCTION", "", StatusStrategy.RELEASE),
            )
        ),
    )
    page = render_root_index(
        ctx,
        rules=rules,
        objectives=[DocumentRecord(DocumentScope.objectives, "o", "Goal", objective)],
        threats=[
            DocumentRecord(DocumentScope.threats, "threat-1", "T1", MagicMock()),
            DocumentRecord(DocumentScope.threats, "threat-2", "T2", MagicMock()),
        ],
    )
    assert (
        "# Detection catalogue\n\n2 threat vectors, 1 detection objective and 2 detection rules"
        in page
    )
    assert "pie showData title Platform blocks by status" in page
    # Each slice takes its strategy's colour: grey for INERT, green for RELEASE.
    assert '"pie1":"#667085","pie2":"#039855"' in page
    assert "| Platform | `DRAFT` | `PRODUCTION` | Total |" in page
    assert "| Splunk Enterprise Security | 1 | 1 | 2 |" in page
    assert "| Threat vectors addressed by an objective | 1 of 2 (50%) |" in page
    assert "| Objectives implemented by a rule | 1 of 1 (100%) |" in page
    assert "| Signals implemented by a rule | 1 of 1 (100%) |" in page
    assert "| ATT&CK techniques detected by rules | 1 |" in page


def _threat_record(metadata: dict, uuid: str, phase: str, techniques: list[str]) -> DocumentRecord:
    from opentide.models.threat import ThreatVector

    model = ThreatVector.from_yaml_dict(
        {
            "name": f"Threat {uuid}",
            "criticality": "High",
            "metadata": {**metadata, "uuid": uuid, "schema": "threat::1.0"},
            "threat": {
                "description": "d",
                "severity": "Moderate incident",
                "impact": ["Data Breach"],
                "leverage": ["Spoofing"],
                "viability": "Likely",
                "terrain": "t",
                "surface": ["Entra ID"],
                "mitre_attack": techniques,
                "killchain": phase,
            },
        }
    )
    return DocumentRecord(DocumentScope.threats, uuid, model.name, model)


def test_threat_index_groups_threats_by_stage_then_phase(tmp_path: Path, metadata: dict) -> None:
    ctx = DocumentationContext(
        flavor=DocumentFlavor.github,
        output_dir=tmp_path,
        formatter=formatter_for(DocumentFlavor.github),
        index_relation_counts=False,
    )
    records = [
        _threat_record(metadata, "t-collect", "Collection", ["T1114.002"]),
        _threat_record(metadata, "t-deliver", "Delivery", ["T1566.002"]),
    ]
    page = render_index(
        ctx.formatter, title="Threat vectors", folder="threats", records=records, ctx=ctx
    )
    headings = [line for line in page.splitlines() if line.startswith("#")]
    assert headings == [
        "# Threat vectors",
        "## Initial Foothold",
        "### Delivery",
        "## Action on Objectives",
        "### Collection",
    ]


def test_root_index_maps_kill_chain_and_attack_coverage(tmp_path: Path, metadata: dict) -> None:
    from opentide.documentation.facts.deployment import StaticEnvironment
    from opentide.documentation.publish.index import render_root_index
    from opentide.models.rule import DetectionRule

    rule = DetectionRule.from_yaml_dict(
        {
            "name": "r",
            "metadata": {**metadata, "uuid": "r"},
            "description": "d",
            "techniques": ["T1114.002"],
        }
    )
    ctx = DocumentationContext(
        flavor=DocumentFlavor.github,
        output_dir=tmp_path,
        formatter=formatter_for(DocumentFlavor.github),
        environment=StaticEnvironment(),
    )
    page = render_root_index(
        ctx,
        rules=[DocumentRecord(DocumentScope.rules, "r", "r", rule)],
        objectives=[],
        threats=[
            _threat_record(metadata, "t-collect", "Collection", ["T1114.002"]),
            _threat_record(metadata, "t-deliver", "Delivery", ["T1566.002", "T1114"]),
        ],
    )
    assert "accTitle: Kill-chain coverage" in page
    assert "| Delivery | Initial Foothold | 1 | 0 | 0% |" in page
    assert (
        "| Tactic | Techniques in threat vectors | Detected by a rule | Coverage | Not detected |"
        in page
    )
    # T1114 is detected through its sub-technique T1114.002; the phishing technique is not.
    assert "| Collection | 2 | 2 | 100% | - |" in page
    assert "| Initial Access | 1 | 0 | 0% | `T1566.002` |" in page
