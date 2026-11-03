"""Results of the commands that read the catalogue, and of explain and commands."""

from __future__ import annotations

from typing import Any, Literal

from pydantic import Field

from opentide.cli.ui.results.base import (
    CommandDocument,
    Counts,
    DiagnosticFields,
    EngineDiagnosticModel,
    EngineVersions,
    ResultModel,
    ValidationReportModel,
)

# --------------------------------------------------------------------------
# validate
# --------------------------------------------------------------------------


class CheckVerdict(ResultModel):
    """One check's verdict."""

    check: str
    status: Literal["passed", "failed"]


class FixedValue(ResultModel):
    """One value a safe fix replaces."""

    path: str
    line: int
    code: str
    before: str
    after: str


class ValidateSummary(ResultModel):
    objects: int = Field(0, description="Objects checked")
    errors: int = 0
    warnings: int = 0
    files: int = Field(0, description="Files with an error")
    warning_files: int = Field(0, description="Files with a warning")
    # From validate --fix (#646), declared ahead so either merge order stays green.
    fixable: int = Field(0, description="Findings a safe fix resolves")
    fixed: int = Field(0, description="With --fix: values replaced")
    queries: int | None = Field(None, description="Queries checked (absent with --queries off)")


class ValidateResult(CommandDocument):
    """``opentide validate``: every check's verdict and the full report."""

    checks: dict[str, CheckVerdict] = Field(
        default_factory=dict, description="Verdict by check name"
    )
    report: ValidationReportModel | None = Field(
        None, description="Issues (errors) and warnings, with diagnostic fields"
    )
    check: str | None = Field(None, description="The check selected with --check")
    workspace: str | None = Field(None, description="The workspace that was validated")
    # From validate --fix (#646).
    fixed: list[FixedValue] | None = Field(None, description="With --fix: the values replaced")
    would_fix: list[FixedValue] | None = Field(
        None, description="With --fix --dry-run: the values --fix would replace"
    )
    diff: str | None = Field(None, description="With --fix --dry-run: a unified diff")
    summary: ValidateSummary


class QueryChecked(ResultModel):
    """One query the offline check read."""

    path: str = Field(description="Workspace-relative path of the rule file or query file")
    platform: str | None = Field(
        description="The configurations block the query is in; null in a hunt or a query file"
    )
    language: Literal["kql", "spl", "esql", "eql", "kuery", "lucene", "falco"]
    field_path: list[str] = Field(description="YAML path of the query; empty for a query file")
    line: int = Field(description="1-based line where the query starts")
    column: int
    errors: int = Field(description="Errors the engine reports: the platform rejects the query")


class LiveRuleCheckModel(ResultModel):
    """One rule's query, checked on one tenant (``validate query --live``)."""

    rule: str = Field(description="The rule's UUID")
    name: str
    tenant: str
    status: Literal["passed", "failed"]
    label: str | None = Field(None, description="Which of a rule's queries this is")
    code: str | None = Field(
        None, description="query_check_timeout: the query got no answer within check_timeout"
    )
    errors: list[str] = Field(default_factory=list)
    warnings: list[str] = Field(default_factory=list)


class QueryValidationResult(CommandDocument):
    """``opentide validate query``: rule queries checked offline, or on one platform's tenants."""

    platform: str | None = None
    mode: Literal["live", "offline"] | None = Field(
        None, description="offline: the analysis engine; live: the tenants"
    )
    supported: bool | None = Field(None, description="Whether the platform has query validation")
    valid: None = Field(None, description="null when the platform has no query validation")
    platform_enabled: bool | None = None
    strategies: list[str] = Field(default_factory=list, description="The run's strategies")
    queries_validated: int | None = None
    queries_per_tenant: dict[str, int] = Field(
        default_factory=dict, description="Queries sent, by tenant"
    )
    scope: Literal["changed", "selected"] | None = Field(
        None, description="The narrowed rule scope, when --changed, --file or --uuid narrowed it"
    )
    unmatched: list[str] = Field(
        default_factory=list, description="--file or --uuid values that matched no rule"
    )
    check_timeout: float | None = Field(
        None, description="Live: the seconds each query could take, when one got no answer"
    )
    timed_out: list[LiveRuleCheckModel] = Field(
        default_factory=list,
        description="Live: the checks whose query got no answer within check_timeout",
    )
    tenant: str | None = Field(None, description="The tenant that could not be reached")
    host: str | None = None
    missing_tenants: dict[str, str] = Field(
        default_factory=dict, description="Platform configuration files with no tenant"
    )
    advice: str | None = None
    # Offline (the analysis engine).
    platforms: list[str] = Field(
        default_factory=list, description="Offline: the platforms whose queries were checked"
    )
    queries: list[QueryChecked] = Field(
        default_factory=list, description="Offline: every query checked, with its counts"
    )
    diagnostics: list[EngineDiagnosticModel] = Field(
        default_factory=list, description="Offline: what the engine found, in the rule files"
    )
    engine: EngineVersions | None = Field(None, description="Offline: the engine that ran")


# --------------------------------------------------------------------------
# query
# --------------------------------------------------------------------------


class QueryColumnModel(ResultModel):
    name: str
    type: str | None = Field(None, description="The platform's type name, when it reports one")


class QueryWindow(ResultModel):
    from_: str = Field(alias="from", description="Start of the window, UTC ISO-8601")
    to: str = Field(description="End of the window, UTC ISO-8601")


class QueryTenantResult(ResultModel):
    """One tenant's outcome for one query."""

    tenant: str
    status: Literal["ok", "failed"]
    label: str | None = Field(None, description="Which of a rule's queries this is")
    columns: list[QueryColumnModel] = Field(default_factory=list)
    rows: list[dict[str, Any]] = Field(default_factory=list)
    row_count: int | None = None
    truncated: bool | None = Field(None, description="More rows matched than --limit let through")
    partial: bool | None = Field(None, description="The platform stopped early")
    language: str | None = None
    sent: str | None = Field(None, description="The query as sent, when it differs")
    vendor_query_id: str | None = None
    error: str | None = Field(None, description="Why the tenant returned no rows")
    detail: str | None = Field(None, description="The platform's own message")
    warnings: list[str] = Field(default_factory=list)
    elapsed_ms: int


class QueryRuleRef(ResultModel):
    uuid: str
    name: str
    queries: list[str] = Field(description="The queries the rule sends to the platform")


class QueryCommandResult(CommandDocument):
    """``opentide query``: a read-only query's rows from each selected tenant."""

    platform: str | None = None
    source: Literal["query", "rule"] | None = None
    query: str | None = None
    rule: QueryRuleRef | None = None
    window: QueryWindow | None = None
    limit: int | None = None
    tenants: list[str] = Field(default_factory=list, description="The tenants queried")
    results: list[QueryTenantResult] = Field(default_factory=list)
    row_count: int | None = None
    detail: str | None = None
    choices: list[str] = Field(default_factory=list, description="Valid values of the flag")


# --------------------------------------------------------------------------
# lint
# --------------------------------------------------------------------------


class LintFinding(DiagnosticFields):
    """One lint finding, with the diagnostic fields."""

    check: str
    severity: Literal["error", "warning", "info"]
    path: str = Field(description="Workspace-relative path")
    yaml_line: int | None = Field(description="0-based")
    uuid: str | None
    expected: str | None = Field(None, description="The file name the object's name derives")
    fixed: bool | None = Field(None, description="true when --fix renamed the file")
    from_: str | None = Field(
        None, alias="from", description="The file's previous path, when --fix renamed it"
    )
    note: str | None = None


class LintSummary(ResultModel):
    files: int = 0
    findings: int = 0
    errors: int = 0
    warnings: int = 0
    notes: int = 0
    fixed: int = 0


class LintResult(CommandDocument):
    """``opentide lint``: catalogue hygiene findings."""

    path: str | None = None
    checks: list[str] = Field(default_factory=list)
    findings: list[LintFinding] = Field(default_factory=list)
    count: int | None = None
    fixed: int | None = None
    summary: LintSummary | None = None
    advice: str | None = Field(None, description="How to fix a failure that stopped the run")
    scope: Literal["changed", "selected"] | None = Field(
        None, description="What narrowed the run: --changed or --file. Absent on a full run"
    )
    unmatched: list[str] | None = Field(
        None, description="The --file targets that selected no object file"
    )


# --------------------------------------------------------------------------
# info
# --------------------------------------------------------------------------


class PlatformInfo(ResultModel):
    name: str
    enabled: bool
    can_deploy: bool
    can_validate: bool
    can_query: bool = Field(False, description="Whether opentide query runs on the platform")


class TechniqueCoverage(ResultModel):
    technique: str
    rules: list[str] = Field(description="UUIDs of the rules that cover the technique")
    count: int


class VocabularyOverview(ResultModel):
    """One vocabulary in ``info vocab``: the counts that need no pin lookup."""

    name: str = Field(description="The vocabulary's field, its file name without .vocab.toml")
    title: str | None = None
    entries: int = Field(description="Keys the vocabulary defines, removed ones included")
    removed: int = Field(description="Keys with a removed revision")
    latest_revision: str | None = Field(
        None, description="Newest revision the key lifecycle defines (major.minor)"
    )
    staged: bool = Field(description="Whether keys are authored as <stage>::<key>")


class VocabularyRevision(ResultModel):
    revision: str = Field(description="major.minor")
    introduced: int = Field(description="Keys whose version is this revision")
    removed: int = Field(description="Keys whose removed is this revision")
    admitted: int = Field(description="Keys a pin to this revision admits")


class VocabularyPin(ResultModel):
    schema_: str = Field(alias="schema", description="Object schema id, e.g. rule::1.0")
    field: str = Field(description="Dotted path of the pinned field")
    revision: str
    defined: bool = Field(description="Whether the key lifecycle defines this revision")
    admitted: int = Field(description="Keys the pin admits")
    scoped: bool | None = Field(
        None, description="Whether the field is authored <stage>::<key>; null when unknown"
    )


class VocabularyDetail(VocabularyOverview):
    """``info vocab <name>``: one vocabulary's revisions and pins."""

    key: str | None = None
    stages: list[str] = Field(default_factory=list)
    revisions: list[VocabularyRevision] = Field(default_factory=list)
    pins: list[VocabularyPin] = Field(default_factory=list)


class CatalogPlatform(ResultModel):
    """One platform block of a rule."""

    id: str = Field(description="The configurations key, such as sentinel")
    enabled: bool
    status: str | None = Field(description="The block's status, such as STAGING")
    strategy: str | None = Field(
        description="The strategy deployment.toml maps the status to; null when unknown"
    )


class CatalogDeployment(ResultModel):
    """One tenant binding in .opentide/states/deployment/."""

    platform: str
    tenant: str
    deployed: bool
    rule_id: str = Field(description="The id the platform assigned to the rule")


class CatalogTechniques(ResultModel):
    own: list[str] = Field(description="ATT&CK ids the object lists itself")
    inherited: list[str] = Field(
        description="ATT&CK ids from its objective or threats, not listed by the object"
    )


class CatalogLoadError(ResultModel):
    """Why a file did not load."""

    code: str = Field(description="yaml_parse, missing_uuid, …")
    message: str
    line: int | None = Field(description="1-based line of the problem, when known")


class CatalogObject(ResultModel):
    """One threat, objective or rule, or a file that should have been one."""

    uuid: str | None = Field(description="metadata.uuid; null when a file that failed has none")
    type: Literal["threat", "objective", "rule"] | None
    schema_: str | None = Field(alias="schema", description="metadata.schema, such as rule::1.0")
    name: str
    path: str | None = Field(description="Workspace-relative, with forward slashes")
    file_path: str | None = Field(description="Absolute")
    line: int = Field(description="1-based line of the name: key, or 1")
    tlp: str | None
    author: str | None
    created: str | None
    modified: str | None
    reviewed: str | None
    platforms: list[CatalogPlatform] = Field(description="A rule's platform blocks")
    deployment: list[CatalogDeployment] = Field(
        description="A rule's tenant bindings from deployment state"
    )
    techniques: CatalogTechniques
    tactics: list[str] = Field(description="ATT&CK tactic shortnames, in matrix order")
    actors: list[str] = Field(
        description="Actors of the threats the object is, covers, or implements an objective of"
    )
    load_error: CatalogLoadError | None = Field(description="null when the file loaded")


class CatalogEdge(ResultModel):
    """One reference between objects, or from an object to a technique or log source."""

    from_: str = Field(alias="from", description="The object or signal UUID that holds it")
    to: str = Field(description="An object or signal UUID, an ATT&CK id or a log source name")
    kind: Literal["covers", "implements", "parent", "chains", "technique", "logsource"]
    field_path: str = Field(description="Dotted path of the field holding the reference")
    relation: str | None = Field(description="A chains edge's relation, as written")
    missing: bool = Field(description="true when to should name an object and none has it")


class CatalogSignal(ResultModel):
    uuid: str
    name: str
    objective: str | None = Field(description="The objective that defines the signal")
    parent: str | None = Field(description="The parent signal's UUID")


class AttackTactic(ResultModel):
    id: str | None = Field(description="TA id, such as TA0006")
    shortname: str = Field(description="Such as credential-access")
    name: str
    techniques: list[str] = Field(description="Techniques (not sub-techniques) of the tactic")


class AttackTechnique(ResultModel):
    name: str
    parent: str | None
    subtechniques: list[str]


class AttackSkeleton(ResultModel):
    """The Enterprise matrix of the bundled att&ck vocabulary, at the revision pins admit."""

    tactics: list[AttackTactic] = Field(description="In matrix order")
    techniques: dict[str, AttackTechnique] = Field(description="By ATT&CK id")


class InfoSummary(ResultModel):
    rules: int = 0
    threats: int = 0
    objectives: int = 0
    load_errors: int = 0
    objects: int | None = Field(None, description="catalog: object rows, load errors included")
    signals: int | None = Field(None, description="catalog: signals")
    edges: int | None = Field(None, description="catalog: edges")


class InfoResult(CommandDocument):
    """``opentide info``: version, object counts and platforms."""

    version: str | None = None
    repo: str | None = None
    counts: Counts | None = None
    parse_error_count: int | None = None
    platforms: list[PlatformInfo] = Field(default_factory=list)
    rules: list[str] | None = Field(None, description="Rule UUIDs, for the rules section")
    threats: list[str] | None = Field(None, description="Threat UUIDs, for the threats section")
    objectives: list[str] | None = Field(
        None, description="Objective UUIDs, for the objectives section"
    )
    coverage: TechniqueCoverage | None = Field(None, description="For the coverage section")
    vocabularies: list[VocabularyOverview] | None = Field(
        None, description="For the vocab section without a name"
    )
    vocabulary: VocabularyDetail | None = Field(
        None, description="For the vocab section with a name"
    )
    objects: list[CatalogObject] | None = Field(None, description="For the catalog section")
    edges: list[CatalogEdge] | None = Field(None, description="For the catalog section")
    signals: list[CatalogSignal] | None = Field(None, description="For the catalog section")
    attack: AttackSkeleton | None = Field(None, description="For the catalog section")
    summary: InfoSummary


# --------------------------------------------------------------------------
# rules unreviewed
# --------------------------------------------------------------------------


class UnreviewedRule(ResultModel):
    path: str
    schema_: str = Field(alias="schema")
    reason: str
    reviewed: str | None


class UnreviewedResult(CommandDocument):
    """``opentide rules unreviewed``: rules due for review."""

    evaluated_at: str | None = None
    window: str | None = None
    count: int | None = None
    rules: list[UnreviewedRule] = Field(default_factory=list)


# --------------------------------------------------------------------------
# explain
# --------------------------------------------------------------------------


class CodeMeaning(ResultModel):
    code: str
    meaning: str


class ExplainResult(CommandDocument):
    """``opentide explain``: one code's page, or every code with no argument."""

    code: str | None = None
    meaning: str | None = None
    markdown: str | None = None
    codes: list[CodeMeaning] | None = Field(None, description="Every code, with no argument")


# --------------------------------------------------------------------------
# commands
# --------------------------------------------------------------------------


class ParameterInfo(ResultModel):
    name: str | None
    type: str
    choices: list[Any] | None
    default: Any
    required: bool
    multiple: bool
    envvars: list[str]
    help: str | None


class OptionInfo(ParameterInfo):
    flags: list[str]
    secondary_flags: list[str]
    is_flag: bool


class CommandInfo(ResultModel):
    path: str
    name: str
    summary: str
    help: str
    group: bool
    runs_alone: bool
    subcommands: list[str]
    deprecated: bool
    arguments: list[ParameterInfo]
    options: list[OptionInfo]
    example: str
    output_schema: dict[str, Any] | None = Field(
        description="The JSON Schema of the command's --json document; null when it prints none"
    )


class CommandsSummary(ResultModel):
    commands: int = 0
    groups: int = 0


class EnvironmentVariable(ResultModel):
    name: str
    meaning: str


class CommandsResult(CommandDocument):
    """``opentide commands``: the command tree, with each command's output schema."""

    program: str
    version: str = Field(description="The installed opentide version")
    global_options: list[OptionInfo]
    environment: list[EnvironmentVariable] = Field(
        description="Variables that change every command but are not options"
    )
    commands: list[CommandInfo]
    defs: dict[str, Any] = Field(
        alias="$defs", description="The schemas each output_schema refers to"
    )
    summary: CommandsSummary
