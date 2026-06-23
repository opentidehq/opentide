"""Validation pivot unit tests."""

from __future__ import annotations

from opentide.generation.vocabulary import VocabularyDefinition, VocabularyEntry, VocabularyMetadata
from opentide.validation.issues import ValidationIssue, ValidationReport
from opentide.validation.scope import ValidationScope
from opentide.validation.vocab_resolver import RuntimeEnumResolver


def test_validation_issue_legacy_string() -> None:
    issue = ValidationIssue(
        code="schema_validation",
        object_uuid="abc",
        field_path=("name",),
        message="field required",
    )
    assert issue.to_legacy_string() == "name: field required"


def test_validation_report_legacy_by_uuid() -> None:
    report = ValidationReport(
        ok=False,
        issues=[
            ValidationIssue(
                code="x",
                object_uuid="u1",
                field_path=("a",),
                message="bad",
            )
        ],
    )
    assert report.legacy_errors_by_uuid() == {"u1": ["a: bad"]}


def test_validation_scope_full() -> None:
    scope = ValidationScope.full()
    assert scope.includes_object("any", "rule")


def test_validation_scope_narrow_uuid() -> None:
    scope = ValidationScope.narrow(uuids=frozenset({"only-this"}))
    assert scope.includes_object("only-this", "rule")
    assert not scope.includes_object("other", "rule")


def test_runtime_enum_resolver_severity() -> None:
    meta = VocabularyMetadata(name="Severity", field="severity", key="name")
    entries = {
        "High": VocabularyEntry(name="High", description="High severity"),
        "Low": VocabularyEntry(name="Low", description="Low severity"),
    }
    vocab = VocabularyDefinition(metadata=meta, entries=entries)
    resolver = RuntimeEnumResolver({"severity": vocab})
    values, _ = resolver.resolve("severity")
    assert "High" in values
    assert resolver.is_valid("High", "severity")
    assert not resolver.is_valid("NotAValue", "severity")
    assert resolver.suggest("Hgh", "severity") == "High"
