//! One model per configuration file, the oracle's Pydantic models
//! (`models/configuration/*`, `models/visibility.py`) field for field: names,
//! order, defaults, closure (`extra="forbid"` is `deny_unknown_fields`; a
//! model without it takes unknown keys, as `extra="allow"`), unions and
//! constraints ([`super::types`]).
//!
//! The configuration models are strict, as the oracle's are: a value takes its
//! declared type (TOML types every value already). `visibility.toml`'s are
//! Tide models (lax), which reads the same for every value TOML can hold.

use std::collections::BTreeMap;
use std::sync::Arc;

use schemars::JsonSchema;
use serde::Serialize;

use super::types::{
    ElasticVersionPattern, EnvPlaceholder, GravityZoneIdPattern, HttpUrlPattern, Matching,
    MispNamePattern, NonEmptyList, NonEmptyString, OrganisationUuidPattern, PositiveFloat,
    RunStrategyName, SslWordPattern, StatusStrategyName, TargetAliasPattern,
};
use crate::FromNode;
use crate::error::{ErrorKind, PathSegment};
use crate::from_node::{Context, Fields, Missing, model_entries};
use crate::node::{Node, Value};

fn yes() -> bool {
    true
}

/// The object families a configuration can scope (`ObjectFamily`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, FromNode, JsonSchema)]
#[serde(rename_all = "lowercase")]
#[from_node(literal)]
pub enum ObjectFamily {
    /// `threat`.
    Threat,
    /// `objective`.
    Objective,
    /// `rule`.
    Rule,
}

// --- deployment.toml -------------------------------------------------------------------

/// One `[[statuses]]` entry.
#[derive(Debug, Clone, PartialEq, Serialize, FromNode, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct DeploymentStatusEntry {
    /// Status name a rule's status field takes.
    pub name: NonEmptyString,
    /// What a rule in this status is.
    pub description: String,
    /// What `opentide deploy` does with a rule in this status.
    pub strategy: StatusStrategyName,
}

/// One `[[responders]]` entry.
#[derive(Debug, Clone, PartialEq, Serialize, FromNode, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct DeploymentResponder {
    /// Team name a rule's `response.responders` takes.
    pub name: NonEmptyString,
    /// What the team does.
    #[serde(default)]
    pub description: String,
}

fn production() -> NonEmptyString {
    NonEmptyString("PRODUCTION".to_owned())
}

/// `[promotion]`.
#[derive(Debug, Clone, PartialEq, Serialize, FromNode, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct PromotionSettings {
    /// Whether status promotion is allowed.
    #[serde(default = "yes")]
    pub enabled: bool,
    /// Status a promotable rule is rewritten to.
    #[serde(default = "production")]
    pub promotion_target: NonEmptyString,
}

impl Default for PromotionSettings {
    fn default() -> Self {
        Self {
            enabled: true,
            promotion_target: production(),
        }
    }
}

/// `[debug]`.
#[derive(Debug, Clone, PartialEq, Serialize, FromNode, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct DebugSettings {
    /// UUIDs of rules usable for debugging.
    #[serde(default)]
    pub mdr_test_uuids: Vec<String>,
    /// Whether TLS certificates are verified in debug mode.
    #[serde(default = "yes")]
    pub ssl_enabled: bool,
}

impl Default for DebugSettings {
    fn default() -> Self {
        Self {
            mdr_test_uuids: Vec::new(),
            ssl_enabled: true,
        }
    }
}

/// Merged `deployment.toml`.
#[derive(Debug, Clone, PartialEq, Serialize, FromNode, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct DeploymentConfiguration {
    /// Team applied when a rule sets no `response.responders`.
    #[serde(default)]
    pub default_responders: String,
    /// The statuses a rule may carry.
    pub statuses: NonEmptyList<DeploymentStatusEntry>,
    /// Status promotion on deploy.
    #[serde(default)]
    pub promotion: PromotionSettings,
    /// Settings read in debug mode.
    #[serde(default)]
    pub debug: DebugSettings,
    /// Alert-handling teams.
    #[serde(default)]
    pub responders: Vec<DeploymentResponder>,
}

impl DeploymentConfiguration {
    /// The `[[statuses]]` names.
    pub fn status_names(&self) -> Vec<&str> {
        self.statuses
            .0
            .iter()
            .map(|status| status.name.0.as_str())
            .collect()
    }
}

// --- documentation.toml ----------------------------------------------------------------

/// A markdown flavor (`DocumentFlavor`), read by value; `azure-devops` is read
/// as `azure_devops`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum Flavor {
    /// `github`.
    Github,
    /// `gitlab`.
    Gitlab,
    /// `azure_devops`.
    AzureDevops,
    /// `generic`.
    Generic,
}

impl FromNode for Flavor {
    fn from_node(node: &Node, cx: &mut Context) -> Option<Self> {
        if let Value::Str(text) = &node.value {
            match text.replace('-', "_").as_str() {
                "github" => return Some(Self::Github),
                "gitlab" => return Some(Self::Gitlab),
                "azure_devops" => return Some(Self::AzureDevops),
                "generic" => return Some(Self::Generic),
                _ => {}
            }
        }
        let expected = "'github', 'gitlab', 'azure_devops' or 'generic'";
        cx.error_with(
            ErrorKind::InvalidValue("enum"),
            format!("Input should be {expected}"),
            node,
            &[("expected", expected.to_owned())],
        );
        None
    }
}

fn generic_flavor() -> Flavor {
    Flavor::Generic
}

/// `[flavor]`.
#[derive(Debug, Clone, PartialEq, Serialize, FromNode, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct FlavorSettings {
    /// Flavor used when `opentide generate docs` gets no `--flavor`.
    #[serde(default = "generic_flavor")]
    pub default: Flavor,
}

/// `flavor`: a `[flavor]` table, or the flavor name itself.
#[derive(Debug, Clone, PartialEq, Serialize, FromNode, JsonSchema)]
#[serde(untagged)]
#[from_node(union)]
pub enum FlavorChoice {
    /// The name.
    #[from_node(tag = "function-before[<lambda>(), lax-or-strict[...]]")]
    Name(Flavor),
    /// The table.
    #[from_node(tag = "FlavorSettings")]
    Settings(FlavorSettings),
}

fn flavor_settings() -> FlavorChoice {
    FlavorChoice::Settings(FlavorSettings {
        default: Flavor::Generic,
    })
}

/// `[gitlab]`.
#[derive(Debug, Clone, Default, PartialEq, Serialize, FromNode, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct GitlabSettings {
    /// Link object pages by UUID instead of by name.
    #[serde(default)]
    pub uuid_permalinks: bool,
}

/// Which relations an object page diagram draws.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, FromNode, JsonSchema)]
#[serde(rename_all = "lowercase")]
#[from_node(literal)]
pub enum RelationsDirection {
    /// `upstream`.
    Upstream,
    /// `downstream`.
    Downstream,
    /// `both`.
    Both,
}

fn both() -> RelationsDirection {
    RelationsDirection::Both
}

/// `[diagrams]`.
#[derive(Debug, Clone, PartialEq, Serialize, FromNode, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct DiagramSettings {
    /// Which relations an object page diagram draws.
    #[serde(default = "both")]
    pub relations_direction: RelationsDirection,
}

/// `[index]`.
#[derive(Debug, Clone, PartialEq, Serialize, FromNode, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct IndexSettings {
    /// Show how many objects each object relates to.
    #[serde(default = "yes")]
    pub relation_counts: bool,
    /// Prefix index entries with the family icon.
    #[serde(default)]
    pub icons: bool,
}

fn circl() -> String {
    "https://vulnerability.circl.lu".to_owned()
}

fn fifteen() -> PositiveFloat {
    PositiveFloat(15.0)
}

/// `[cve]`.
#[derive(Debug, Clone, PartialEq, Serialize, FromNode, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct CveSettings {
    /// Base URL of the Vulnerability-Lookup API.
    #[serde(default = "circl")]
    pub base_url: String,
    /// Prefix of the page a CVE reference links to.
    #[serde(default)]
    pub default_db_link: String,
    /// Fetch CVE details while generating documentation.
    #[serde(default = "yes")]
    pub retrieve_details: bool,
    /// Lookup timeout in seconds.
    #[serde(default = "fifteen")]
    pub timeout: PositiveFloat,
}

/// `[object_names]`.
#[derive(Debug, Clone, Default, PartialEq, Serialize, FromNode, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ObjectNames {
    /// Display name of threat vectors.
    #[serde(default)]
    pub threat: Option<String>,
    /// Display name of detection objectives.
    #[serde(default)]
    pub objective: Option<String>,
    /// Display name of detection objective signals.
    #[serde(default)]
    pub signal: Option<String>,
    /// Display name of detection rules.
    #[serde(default)]
    pub rule: Option<String>,
}

fn all_families() -> Vec<ObjectFamily> {
    vec![
        ObjectFamily::Threat,
        ObjectFamily::Objective,
        ObjectFamily::Rule,
    ]
}

fn diagram_settings() -> DiagramSettings {
    DiagramSettings {
        relations_direction: RelationsDirection::Both,
    }
}

fn index_settings() -> IndexSettings {
    IndexSettings {
        relation_counts: true,
        icons: false,
    }
}

fn cve_settings() -> CveSettings {
    CveSettings {
        base_url: circl(),
        default_db_link: String::new(),
        retrieve_details: true,
        timeout: fifteen(),
    }
}

/// Merged `documentation.toml`.
#[derive(Debug, Clone, PartialEq, Serialize, FromNode, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct DocumentationConfiguration {
    /// Object families that get documentation pages.
    #[serde(default = "all_families")]
    pub scope: Vec<ObjectFamily>,
    /// Object keys left out of the rendered pages.
    #[serde(default)]
    pub skip_model_keys: Vec<String>,
    /// Write an index page in every documentation folder.
    #[serde(default = "yes")]
    pub folder_index_pages: bool,
    /// Output folder, relative to the repository.
    #[serde(default)]
    pub output: Option<String>,
    /// Markdown flavor.
    #[serde(default = "flavor_settings")]
    pub flavor: FlavorChoice,
    /// Settings for the gitlab flavor.
    #[serde(default)]
    pub gitlab: GitlabSettings,
    /// Relation diagrams.
    #[serde(default = "diagram_settings")]
    pub diagrams: DiagramSettings,
    /// Index pages.
    #[serde(default = "index_settings")]
    pub index: IndexSettings,
    /// CVE lookups.
    #[serde(default = "cve_settings")]
    pub cve: CveSettings,
    /// Display names of each object family.
    #[serde(default)]
    pub object_names: ObjectNames,
    /// Icon shown for each object family.
    #[serde(default)]
    pub icons: BTreeMap<String, String>,
}

// --- paths.toml ------------------------------------------------------------------------

/// `[paths.opentide]`.
#[derive(Debug, Clone, PartialEq, Serialize, FromNode, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct OpentidePaths {
    /// The `.opentide` folder.
    #[serde(default)]
    pub root: Option<String>,
    /// Generated JSON Schemas.
    #[serde(default)]
    pub schemas: Option<String>,
    /// Generated templates.
    #[serde(default)]
    pub templates: Option<String>,
}

/// `[paths.objects]`.
#[derive(Debug, Clone, PartialEq, Serialize, FromNode, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ObjectPaths {
    /// Threat vector folder.
    #[serde(default)]
    pub threat: Option<String>,
    /// Detection objective folder.
    #[serde(default)]
    pub objective: Option<String>,
    /// Detection rule folder.
    #[serde(default)]
    pub rule: Option<String>,
    /// Generated VS Code snippet file.
    #[serde(default)]
    pub snippet_file: Option<String>,
}

/// `[paths.exports]`.
#[derive(Debug, Clone, PartialEq, Serialize, FromNode, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ExportPaths {
    /// Exports folder.
    #[serde(default)]
    pub root: Option<String>,
}

/// `[paths.docs]`.
#[derive(Debug, Clone, PartialEq, Serialize, FromNode, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct DocsPaths {
    /// Documentation root.
    #[serde(default)]
    pub root: Option<String>,
    /// Rule pages.
    #[serde(default)]
    pub rules: Option<String>,
    /// Objective pages.
    #[serde(default)]
    pub objectives: Option<String>,
    /// Threat pages.
    #[serde(default)]
    pub threats: Option<String>,
}

/// `[paths]`.
#[derive(Debug, Clone, PartialEq, Serialize, FromNode, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct WorkspacePaths {
    /// The `.opentide` folder.
    #[serde(default)]
    pub opentide: Option<OpentidePaths>,
    /// Object folders.
    #[serde(default)]
    pub objects: Option<ObjectPaths>,
    /// Exports folder.
    #[serde(default)]
    pub exports: Option<ExportPaths>,
    /// Documentation folders.
    #[serde(default)]
    pub docs: Option<DocsPaths>,
}

/// `[artifacts.schemas]`.
#[derive(Debug, Clone, PartialEq, Serialize, FromNode, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct SchemaArtifacts {
    /// Threat vector schema file name.
    #[serde(default)]
    pub threat: Option<String>,
    /// Detection objective schema file name.
    #[serde(default)]
    pub objective: Option<String>,
    /// Detection rule schema file name.
    #[serde(default)]
    pub rule: Option<String>,
    /// `visibility.toml` schema file name.
    #[serde(default)]
    pub visibility: Option<String>,
    /// Object router schema file name.
    #[serde(default)]
    pub router: Option<String>,
}

/// `[artifacts.templates]`.
#[derive(Debug, Clone, PartialEq, Serialize, FromNode, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct TemplateArtifacts {
    /// Threat vector template file name.
    #[serde(default)]
    pub threat: Option<String>,
    /// Detection objective template file name.
    #[serde(default)]
    pub objective: Option<String>,
    /// Detection rule template file name.
    #[serde(default)]
    pub rule: Option<String>,
}

/// `[artifacts.exports]`.
#[derive(Debug, Clone, PartialEq, Serialize, FromNode, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ExportArtifacts {
    /// Revisions export file name.
    #[serde(default)]
    pub revisions: Option<String>,
    /// Objects export file name.
    #[serde(default)]
    pub objects: Option<String>,
    /// ATT&CK Navigator layer file name.
    #[serde(default)]
    pub attack_layer: Option<String>,
}

/// `[artifacts]`.
#[derive(Debug, Clone, PartialEq, Serialize, FromNode, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct Artifacts {
    /// JSON Schema files.
    #[serde(default)]
    pub schemas: Option<SchemaArtifacts>,
    /// Template files.
    #[serde(default)]
    pub templates: Option<TemplateArtifacts>,
    /// Export files.
    #[serde(default)]
    pub exports: Option<ExportArtifacts>,
}

/// Merged `paths.toml`.
#[derive(Debug, Clone, PartialEq, Serialize, FromNode, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct PathsConfiguration {
    /// Object families the workspace holds.
    #[serde(default)]
    pub objects: Option<Vec<ObjectFamily>>,
    /// Workspace directories.
    #[serde(default)]
    pub paths: Option<WorkspacePaths>,
    /// Generated file names.
    #[serde(default)]
    pub artifacts: Option<Artifacts>,
    /// Model family of each object family.
    #[serde(default)]
    pub metaschemas: Option<BTreeMap<String, String>>,
}

// --- platforms/<id>.toml ---------------------------------------------------------------

/// `[platform]`.
#[derive(Debug, Clone, Default, PartialEq, Serialize, FromNode, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct PlatformIdentity {
    /// Load and deploy to this platform.
    #[serde(default)]
    pub enabled: bool,
    /// Display name of the platform.
    #[serde(default)]
    pub name: Option<String>,
    /// What the platform is.
    #[serde(default)]
    pub description: String,
}

/// `[modifiers.conditions]`.
#[derive(Debug, Clone, PartialEq, Serialize, FromNode, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ModifierConditions {
    /// Deployment statuses.
    #[serde(default)]
    pub status: Option<Vec<String>>,
    /// Rule flags.
    #[serde(default)]
    pub flags: Option<Vec<String>>,
    /// Tenants.
    #[serde(default)]
    pub tenants: Option<Vec<String>>,
    /// Apply to every rule.
    #[serde(default)]
    pub default: Option<bool>,
}

/// `[[modifiers]]`.
#[derive(Debug, Clone, PartialEq, Serialize, FromNode, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct Modifier {
    /// Modifier name.
    #[serde(default)]
    pub name: Option<String>,
    /// What the modifier is for.
    #[serde(default)]
    pub description: Option<String>,
    /// When the modifier applies.
    pub conditions: ModifierConditions,
    /// Rule values to set, keyed by dotted platform field path.
    #[serde(skip_serializing)]
    #[schemars(with = "BTreeMap<String, serde_json::Value>")]
    pub modifications: BTreeMap<String, Arc<Node>>,
}

/// A tenant `ssl`: a boolean, a `$NAME` placeholder, or a boolean word.
#[derive(Debug, Clone, PartialEq, Serialize, FromNode, JsonSchema)]
#[serde(untagged)]
#[from_node(union)]
pub enum SslValue {
    /// A boolean.
    #[from_node(tag = "bool")]
    Bool(bool),
    /// A placeholder.
    #[from_node(tag = "constrained-str")]
    Placeholder(EnvPlaceholder),
    /// A word.
    #[from_node(tag = "constrained-str")]
    Word(Matching<SslWordPattern>),
}

/// A boolean, or a `$NAME` placeholder.
#[derive(Debug, Clone, PartialEq, Serialize, FromNode, JsonSchema)]
#[serde(untagged)]
#[from_node(union)]
pub enum BoolOrPlaceholder {
    /// A boolean.
    #[from_node(tag = "bool")]
    Bool(bool),
    /// A placeholder.
    #[from_node(tag = "constrained-str")]
    Placeholder(EnvPlaceholder),
}

/// An integer, or a `$NAME` placeholder.
#[derive(Debug, Clone, PartialEq, Serialize, FromNode, JsonSchema)]
#[serde(untagged)]
#[from_node(union)]
pub enum IntOrPlaceholder {
    /// An integer.
    #[from_node(tag = "int")]
    Int(i64),
    /// A placeholder.
    #[from_node(tag = "constrained-str")]
    Placeholder(EnvPlaceholder),
}

/// An integer or a string.
#[derive(Debug, Clone, PartialEq, Serialize, FromNode, JsonSchema)]
#[serde(untagged)]
#[from_node(union)]
pub enum IntOrString {
    /// An integer.
    #[from_node(tag = "int")]
    Int(i64),
    /// A string.
    #[from_node(tag = "str")]
    Str(String),
}

/// Splunk `allow_skew`: a string, an integer or a number.
#[derive(Debug, Clone, PartialEq, Serialize, FromNode, JsonSchema)]
#[serde(untagged)]
#[from_node(union)]
pub enum Skew {
    /// A string.
    #[from_node(tag = "str")]
    Str(String),
    /// An integer.
    #[from_node(tag = "int")]
    Int(i64),
    /// A number.
    #[from_node(tag = "float")]
    Float(f64),
}

/// A tenant's `strategies`: a list of at least one, or one strategy.
#[derive(Debug, Clone, PartialEq, Serialize, FromNode, JsonSchema)]
#[serde(untagged)]
#[from_node(union)]
pub enum Strategies {
    /// A list.
    #[from_node(tag = "list[function-before[_run_strategy(), enum[StatusStrategy]]]")]
    List(NonEmptyList<RunStrategyName>),
    /// One strategy.
    #[from_node(tag = "function-before[_run_strategy(), enum[StatusStrategy]]")]
    One(RunStrategyName),
}

fn ssl_true() -> SslValue {
    SslValue::Bool(true)
}

/// The fields every tenant has (`TenantBase`), then its own `setup` (and,
/// for Defender, `parameters`).
macro_rules! tenant {
    ($(#[$meta:meta])* $name:ident, $model:literal, $setup:ty $(, $extra:ident : $extra_ty:ty)?) => {
        $(#[$meta])*
        #[derive(Debug, Clone, PartialEq, Serialize, FromNode, JsonSchema)]
        #[serde(deny_unknown_fields)]
        #[from_node(model = $model)]
        pub struct $name {
            /// Tenant name a rule's platform block may list.
            pub name: NonEmptyString,
            /// What the tenant is.
            #[serde(default)]
            pub description: String,
            /// Status strategies the tenant accepts; `None` for both.
            #[serde(default)]
            pub strategies: Option<Strategies>,
            /// Only rules whose platform block lists this tenant reach it.
            #[serde(default)]
            pub manual: bool,
            /// Connection settings.
            pub setup: $setup,
            $(
                /// Values rules can select from.
                #[serde(default)]
                pub $extra: $extra_ty,
            )?
        }
    };
}

/// A platform file: `[platform]`, `[[modifiers]]`, then its `[[tenants]]`.
macro_rules! platform {
    ($(#[$meta:meta])* $name:ident, $model:literal, $tenant:ty) => {
        $(#[$meta])*
        #[derive(Debug, Clone, PartialEq, Serialize, FromNode, JsonSchema)]
        #[serde(deny_unknown_fields)]
        #[from_node(model = $model)]
        pub struct $name {
            /// Platform identity.
            #[serde(default)]
            pub platform: PlatformIdentity,
            /// Deploy-time rule modifiers.
            #[serde(default)]
            pub modifiers: Vec<Modifier>,
            /// The tenants.
            #[serde(default)]
            pub tenants: Vec<$tenant>,
        }
    };
}

/// `[tenants.setup]` for Microsoft Sentinel.
#[derive(Debug, Clone, PartialEq, Serialize, FromNode, JsonSchema)]
#[serde(deny_unknown_fields)]
#[from_node(model = "SentinelSetup")]
pub struct SentinelSetup {
    /// Verify the tenant's TLS certificate.
    #[serde(default = "ssl_true")]
    pub ssl: SslValue,
    /// Azure resource group of the workspace.
    pub resource_group: String,
    /// Log Analytics workspace name.
    pub workspace_name: String,
    /// Log Analytics workspace ID.
    pub workspace_id: String,
    /// Entra ID tenant ID.
    pub azure_tenant_id: String,
    /// Azure subscription ID.
    pub azure_subscription_id: String,
    /// App registration client ID.
    pub azure_client_id: String,
    /// App registration client secret.
    #[serde(skip_serializing)]
    pub azure_client_secret: String,
}
tenant!(
    /// `[[tenants]]` for Microsoft Sentinel.
    SentinelTenant, "SentinelTenant", SentinelSetup
);
platform!(
    /// Merged `platforms/sentinel.toml`.
    SentinelConfiguration, "SentinelConfiguration", SentinelTenant
);

fn random() -> String {
    "random".to_owned()
}

fn zero_offset() -> IntOrPlaceholder {
    IntOrPlaceholder::Int(0)
}

fn bool_true() -> BoolOrPlaceholder {
    BoolOrPlaceholder::Bool(true)
}

fn bool_false() -> BoolOrPlaceholder {
    BoolOrPlaceholder::Bool(false)
}

/// `[tenants.setup]` for Splunk.
#[derive(Debug, Clone, PartialEq, Serialize, FromNode, JsonSchema)]
#[serde(deny_unknown_fields)]
#[from_node(model = "SplunkSetup")]
pub struct SplunkSetup {
    /// Verify the tenant's TLS certificate.
    #[serde(default = "ssl_true")]
    pub ssl: SslValue,
    /// Splunk management URL.
    pub url: String,
    /// Splunk management port.
    pub port: IntOrString,
    /// Splunk app the searches are saved in.
    pub app: String,
    /// Splunk authentication token.
    #[serde(default, skip_serializing)]
    pub token: String,
    /// Save rules as Enterprise Security correlation searches.
    #[serde(default = "bool_true")]
    pub correlation_searches: BoolOrPlaceholder,
    /// Splunk `allow_skew`.
    #[serde(default)]
    pub allow_skew: Option<Skew>,
    /// Minutes added to the computed schedule.
    #[serde(default = "zero_offset")]
    pub schedule_offset: IntOrPlaceholder,
    /// How a search's cron minute is chosen.
    #[serde(default = "random")]
    pub frequency_scheduling: String,
    /// Alert actions a rule may enable.
    #[serde(default)]
    pub actions_enabled: Option<Vec<String>>,
    /// Alert actions enabled when a rule names none.
    #[serde(default)]
    pub default_actions: Option<Vec<String>>,
    /// The instance runs Splunk Enterprise Security.
    #[serde(default = "bool_false")]
    pub enterprise_security: BoolOrPlaceholder,
}
tenant!(
    /// `[[tenants]]` for Splunk.
    SplunkTenant, "SplunkTenant", SplunkSetup
);
platform!(
    /// Merged `platforms/splunk.toml`.
    SplunkConfiguration, "SplunkConfiguration", SplunkTenant
);

/// `[tenants.setup]` for Carbon Black Cloud.
#[derive(Debug, Clone, PartialEq, Serialize, FromNode, JsonSchema)]
#[serde(deny_unknown_fields)]
#[from_node(model = "CarbonBlackCloudSetup")]
pub struct CarbonBlackCloudSetup {
    /// Verify the tenant's TLS certificate.
    #[serde(default = "ssl_true")]
    pub ssl: SslValue,
    /// Carbon Black Cloud API URL.
    pub url: String,
    /// Organisation key.
    pub org_key: String,
    /// API token.
    #[serde(skip_serializing)]
    pub token: String,
    /// Watchlist the rules are added to.
    #[serde(default)]
    pub watchlist: Option<String>,
    /// Organisations the watchlist applies to.
    #[serde(default)]
    pub organizations: Option<Vec<String>>,
}
tenant!(
    /// `[[tenants]]` for Carbon Black Cloud.
    CarbonBlackCloudTenant, "CarbonBlackCloudTenant", CarbonBlackCloudSetup
);
platform!(
    /// Merged `platforms/carbon_black_cloud.toml`.
    CarbonBlackCloudConfiguration, "CarbonBlackCloudConfiguration", CarbonBlackCloudTenant
);

/// `[tenants.setup]` for SentinelOne.
#[derive(Debug, Clone, PartialEq, Serialize, FromNode, JsonSchema)]
#[serde(deny_unknown_fields)]
#[from_node(model = "SentinelOneSetup")]
pub struct SentinelOneSetup {
    /// Verify the tenant's TLS certificate.
    #[serde(default = "ssl_true")]
    pub ssl: SslValue,
    /// SentinelOne console URL.
    pub url: String,
    /// Account ID the rules belong to.
    pub account_id: IntOrString,
    /// API token.
    #[serde(skip_serializing)]
    pub api_token: String,
    /// Site ID.
    #[serde(default)]
    pub site_id: Option<IntOrString>,
}
tenant!(
    /// `[[tenants]]` for SentinelOne.
    SentinelOneTenant, "SentinelOneTenant", SentinelOneSetup
);
platform!(
    /// Merged `platforms/sentinel_one.toml`.
    SentinelOneConfiguration, "SentinelOneConfiguration", SentinelOneTenant
);

/// `[tenants.setup]` for Microsoft Defender for Endpoint.
#[derive(Debug, Clone, PartialEq, Serialize, FromNode, JsonSchema)]
#[serde(deny_unknown_fields)]
#[from_node(model = "DefenderForEndpointSetup")]
pub struct DefenderForEndpointSetup {
    /// Verify the tenant's TLS certificate.
    #[serde(default = "ssl_true")]
    pub ssl: SslValue,
    /// Entra ID tenant ID.
    pub tenant_id: String,
    /// App registration client ID.
    pub client_id: String,
    /// App registration client secret.
    #[serde(skip_serializing)]
    pub client_secret: String,
}

/// `[tenants.parameters]` for Microsoft Defender for Endpoint.
#[derive(Debug, Clone, PartialEq, Serialize, FromNode, JsonSchema)]
#[serde(deny_unknown_fields)]
#[from_node(model = "DefenderForEndpointParameters")]
pub struct DefenderForEndpointParameters {
    /// Device groups a rule's scope may name.
    #[serde(default)]
    pub device_groups: Option<Vec<String>>,
}
tenant!(
    /// `[[tenants]]` for Microsoft Defender for Endpoint.
    DefenderForEndpointTenant,
    "DefenderForEndpointTenant",
    DefenderForEndpointSetup,
    parameters: Option<DefenderForEndpointParameters>
);
platform!(
    /// Merged `platforms/defender_for_endpoint.toml`.
    DefenderForEndpointConfiguration,
    "DefenderForEndpointConfiguration",
    DefenderForEndpointTenant
);

/// `[tenants.setup]` for CrowdStrike Falcon.
#[derive(Debug, Clone, PartialEq, Serialize, FromNode, JsonSchema)]
#[serde(deny_unknown_fields)]
#[from_node(model = "CrowdstrikeSetup")]
pub struct CrowdstrikeSetup {
    /// Verify the tenant's TLS certificate.
    #[serde(default = "ssl_true")]
    pub ssl: SslValue,
    /// Falcon API base URL.
    pub api: String,
    /// API client ID.
    pub client_id: String,
    /// API client secret.
    #[serde(skip_serializing)]
    pub client_secret: String,
    /// Customer ID (CID).
    pub customer_id: String,
}
tenant!(
    /// `[[tenants]]` for CrowdStrike Falcon.
    CrowdstrikeTenant, "CrowdstrikeTenant", CrowdstrikeSetup
);
platform!(
    /// Merged `platforms/crowdstrike.toml`.
    CrowdstrikeConfiguration, "CrowdstrikeConfiguration", CrowdstrikeTenant
);

/// `[tenants.setup]` for HarfangLab.
#[derive(Debug, Clone, PartialEq, Serialize, FromNode, JsonSchema)]
#[serde(deny_unknown_fields)]
#[from_node(model = "HarfangLabSetup")]
pub struct HarfangLabSetup {
    /// Verify the tenant's TLS certificate.
    #[serde(default = "ssl_true")]
    pub ssl: SslValue,
    /// Rule type the tenant receives.
    pub r#type: String,
    /// HarfangLab manager URL.
    pub url: String,
    /// API token.
    #[serde(skip_serializing)]
    pub api_token: String,
    /// Rule source the rules are written to.
    pub source_id: String,
}
tenant!(
    /// `[[tenants]]` for HarfangLab.
    HarfangLabTenant, "HarfangLabTenant", HarfangLabSetup
);
platform!(
    /// Merged `platforms/harfanglab.toml`.
    HarfangLabConfiguration, "HarfangLabConfiguration", HarfangLabTenant
);

fn default_space() -> String {
    "default".to_owned()
}

/// `[tenants.setup]` for Elastic Security.
#[derive(Debug, Clone, PartialEq, Serialize, FromNode, JsonSchema)]
#[serde(deny_unknown_fields)]
#[from_node(model = "ElasticSetup")]
pub struct ElasticSetup {
    /// Verify the tenant's TLS certificate.
    #[serde(default = "ssl_true")]
    pub ssl: SslValue,
    /// Kibana URL.
    pub url: String,
    /// Elasticsearch URL.
    pub elasticsearch_url: String,
    /// API key: a `$NAME` placeholder.
    pub api_key: EnvPlaceholder,
    /// Kibana space the rules are saved in.
    #[serde(default = "default_space")]
    pub space: String,
    /// Index patterns rules search.
    #[serde(default)]
    pub index: Option<Vec<String>>,
    /// Tags added to every rule.
    #[serde(default)]
    pub tags: Option<Vec<String>>,
    /// Apply alert suppression settings.
    #[serde(default = "bool_true")]
    pub suppression: BoolOrPlaceholder,
    /// Stack version the tenant runs.
    #[serde(default)]
    pub version: Option<Matching<ElasticVersionPattern>>,
}
tenant!(
    /// `[[tenants]]` for Elastic Security.
    ElasticTenant, "ElasticTenant", ElasticSetup
);
platform!(
    /// Merged `platforms/elastic.toml`.
    ElasticConfiguration, "ElasticConfiguration", ElasticTenant
);

/// `[tenants.setup]` for Sysdig Secure.
#[derive(Debug, Clone, PartialEq, Serialize, FromNode, JsonSchema)]
#[serde(deny_unknown_fields)]
#[from_node(model = "SysdigSetup")]
pub struct SysdigSetup {
    /// Verify the tenant's TLS certificate.
    #[serde(default = "ssl_true")]
    pub ssl: SslValue,
    /// Sysdig Secure base URL.
    pub url: String,
    /// API token: a `$NAME` placeholder.
    pub api_token: EnvPlaceholder,
    /// Runtime policies every new rule joins.
    #[serde(default)]
    pub policies: Vec<String>,
    /// Tags added to every rule.
    #[serde(default)]
    pub tags: Option<Vec<String>>,
}
tenant!(
    /// `[[tenants]]` for Sysdig Secure.
    SysdigTenant, "SysdigTenant", SysdigSetup
);
platform!(
    /// Merged `platforms/sysdig.toml`.
    SysdigConfiguration, "SysdigConfiguration", SysdigTenant
);

/// A GravityZone id, 24 lower-case hex digits (`GravityZoneId`).
pub type GravityZoneId = Matching<GravityZoneIdPattern>;

/// An `endpoint_tags` entry: the GravityZone tag and the company that owns
/// it (`BitdefenderEndpointTag`).
#[derive(Debug, Clone, PartialEq, Serialize, FromNode, JsonSchema)]
#[serde(deny_unknown_fields)]
#[from_node(model = "BitdefenderEndpointTag")]
pub struct BitdefenderEndpointTag {
    /// GravityZone tag id, 24 hex.
    pub tag_id: GravityZoneId,
    /// Company id of the tag, 24 hex.
    pub company_id: GravityZoneId,
}

/// `[tenants.setup.targets]`: default targets for blocks that set none
/// (`BitdefenderTenantTargets`). The same shape as a block's `targets`
/// (`bitdefender_targets_shape`): exactly one of the two lists, non-empty. A
/// default never means "no targets": a tenant that applies rules to the
/// whole company leaves `targets` out.
#[derive(Debug, Clone, PartialEq, Serialize, FromNode, JsonSchema)]
#[serde(deny_unknown_fields)]
#[from_node(model = "BitdefenderTenantTargets")]
pub struct BitdefenderTenantTargets {
    /// Aliases from the tenant's endpoint_tags table.
    #[serde(default)]
    pub endpoint_tags: Option<NonEmptyList<Matching<TargetAliasPattern>>>,
    /// Aliases from the tenant's companies table.
    #[serde(default)]
    pub companies: Option<NonEmptyList<Matching<TargetAliasPattern>>>,
}

/// `targets`: a [`BitdefenderTenantTargets`] that sets exactly one list
/// (`_exactly_one_list`, an after-validator).
pub fn tenant_targets(node: &Node, cx: &mut Context) -> Option<Option<BitdefenderTenantTargets>> {
    let targets = Option::<BitdefenderTenantTargets>::from_node(node, cx)?;
    if let Some(set) = &targets
        && set.endpoint_tags.is_none() == set.companies.is_none()
    {
        value_error(
            cx,
            "Value error, targets sets exactly one of endpoint_tags and companies \
             (bitdefender_targets_shape); leave targets out for the whole company",
            node,
        );
        return None;
    }
    Some(targets)
}

crate::objects::platform::literal_enum! {
    /// `personal` or `service`.
    BitdefenderKeyType { Personal = "personal", Service = "service", }
}

fn personal() -> BitdefenderKeyType {
    BitdefenderKeyType::Personal
}

/// `[tenants.setup]` for Bitdefender GravityZone.
#[derive(Debug, Clone, PartialEq, Serialize, FromNode, JsonSchema)]
#[serde(deny_unknown_fields)]
#[from_node(model = "BitdefenderSetup")]
pub struct BitdefenderSetup {
    /// Verify the tenant's TLS certificate.
    #[serde(default = "ssl_true")]
    pub ssl: SslValue,
    /// Control Center API Access URL, ending in /api. Calls go to
    /// `<url>/v1.0/jsonrpc/incidents`.
    pub url: String,
    /// GravityZone API key with the Incidents API. Must be a $NAME placeholder.
    pub api_key: EnvPlaceholder,
    /// personal: HTTP Basic with the key as user name; service: X-API-Key header.
    #[serde(default = "personal")]
    pub key_type: BitdefenderKeyType,
    /// Partner tenants: the company that owns created rules.
    #[serde(default)]
    pub company_id: Option<GravityZoneId>,
    /// false for subscriptions without automatic actions.
    #[serde(default = "yes")]
    pub automatic_actions: bool,
    /// Default targets for blocks that set none.
    #[serde(default)]
    #[from_node(with = "tenant_targets")]
    pub targets: Option<BitdefenderTenantTargets>,
    /// Alias to {tag_id, company_id}.
    #[serde(default)]
    pub endpoint_tags: indexmap::IndexMap<String, BitdefenderEndpointTag>,
    /// Alias to company id.
    #[serde(default)]
    pub companies: indexmap::IndexMap<String, GravityZoneId>,
    /// Tags added to every rule.
    #[serde(default)]
    pub tags: Vec<String>,
}
tenant!(
    /// `[[tenants]]` for Bitdefender GravityZone.
    BitdefenderTenant, "BitdefenderTenant", BitdefenderSetup
);
platform!(
    /// Merged `platforms/bitdefender.toml`.
    BitdefenderConfiguration, "BitdefenderConfiguration", BitdefenderTenant
);

/// `deletion`: what DELETION does to a Google SecOps rule.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, FromNode, JsonSchema)]
#[serde(rename_all = "lowercase")]
#[from_node(literal)]
pub enum GoogleSecopsDeletion {
    /// `archive`.
    Archive,
    /// `delete`.
    Delete,
}

fn archive() -> GoogleSecopsDeletion {
    GoogleSecopsDeletion::Archive
}

/// `[tenants.setup]` for Google Security Operations.
#[derive(Debug, Clone, PartialEq, Serialize, FromNode, JsonSchema)]
#[serde(deny_unknown_fields)]
#[from_node(model = "GoogleSecopsSetup")]
pub struct GoogleSecopsSetup {
    /// Verify the tenant's TLS certificate.
    #[serde(default = "ssl_true")]
    pub ssl: SslValue,
    /// The Google Cloud project bound to the SecOps instance, id or number.
    pub project: NonEmptyString,
    /// The instance's region: us, eu, europe, or a Google Cloud region such as europe-west2.
    pub location: NonEmptyString,
    /// The SecOps customer id (a UUID).
    pub instance: NonEmptyString,
    /// The regional service endpoint. Default: `https://<location>-chronicle.googleapis.com`.
    #[serde(default)]
    #[schemars(
        description = "The regional service endpoint. Default: https://<location>-chronicle.googleapis.com."
    )]
    pub endpoint: Option<String>,
    /// A $NAME placeholder for a service-account key, as a JSON document or a path to one.
    /// Without it, Application Default Credentials (workload identity, gcloud auth).
    #[serde(default)]
    pub credentials: Option<EnvPlaceholder>,
    /// A data access scope id, sent as scope on create and update.
    #[serde(default)]
    pub data_access_scope: Option<String>,
    /// DELETION: archive the rule (keeps its detections and the binding), or delete it without
    /// force.
    #[serde(default = "archive")]
    pub deletion: GoogleSecopsDeletion,
}
tenant!(
    /// `[[tenants]]` for Google Security Operations.
    GoogleSecopsTenant, "GoogleSecopsTenant", GoogleSecopsSetup
);
platform!(
    /// Merged `platforms/google_secops.toml`.
    GoogleSecopsConfiguration, "GoogleSecopsConfiguration", GoogleSecopsTenant
);

/// `[tenants.setup]` of a platform opentide has no model for: open.
#[derive(Debug, Clone, PartialEq, Serialize, FromNode, JsonSchema)]
#[from_node(model = "GenericTenantSetup")]
pub struct GenericTenantSetup {
    /// Verify the tenant's TLS certificate.
    #[serde(default = "ssl_true")]
    pub ssl: SslValue,
}

fn generic_setup() -> GenericTenantSetup {
    GenericTenantSetup { ssl: ssl_true() }
}

/// `[[tenants]]` of a platform opentide has no model for: open.
#[derive(Debug, Clone, PartialEq, Serialize, FromNode, JsonSchema)]
#[from_node(model = "GenericTenant")]
pub struct GenericTenant {
    /// Tenant name.
    pub name: NonEmptyString,
    /// What the tenant is.
    #[serde(default)]
    pub description: String,
    /// Status strategies the tenant accepts.
    #[serde(default)]
    pub strategies: Option<Strategies>,
    /// Only rules whose platform block lists this tenant reach it.
    #[serde(default)]
    pub manual: bool,
    /// Connection settings.
    #[serde(default = "generic_setup")]
    pub setup: GenericTenantSetup,
    /// Values rules can select from.
    #[serde(default, skip_serializing)]
    #[schemars(with = "Option<BTreeMap<String, serde_json::Value>>")]
    pub parameters: Option<BTreeMap<String, Arc<Node>>>,
}

/// Merged `platforms/<id>.toml` of a platform opentide has no model for: open.
#[derive(Debug, Clone, PartialEq, Serialize, FromNode, JsonSchema)]
#[from_node(model = "PlatformConfiguration")]
pub struct PlatformConfiguration {
    /// Platform identity.
    #[serde(default)]
    pub platform: PlatformIdentity,
    /// Deploy-time rule modifiers.
    #[serde(default)]
    pub modifiers: Vec<Modifier>,
    /// The tenants.
    #[serde(default)]
    pub tenants: Vec<GenericTenant>,
}

/// The platform identifiers with a model of their own, in the oracle's order
/// ([`crate::platforms::Order::Configuration`]).
pub const PLATFORMS: [&str; crate::platforms::COUNT] =
    crate::platforms::ordered(crate::platforms::Order::Configuration);

// --- visibility.toml -------------------------------------------------------------------

/// The opentide 0.20.0 dataset keys `visibility::1.0` refuses, each with what
/// to do instead.
pub const LEGACY_DATASET_KEYS: [(&str, &str); 7] = [
    (
        "tables",
        "`tables` was removed in 0.20.1: declare each table as its own [[logsources]] entry \
         whose `name` is the table",
    ),
    (
        "sourcetypes",
        "`sourcetypes` was removed in 0.20.1: declare each sourcetype as its own \
         [[logsources]] entry whose `name` is the sourcetype",
    ),
    (
        "indices",
        "`indices` was removed in 0.20.1: declare each index pattern as its own \
         [[logsources]] entry whose `name` is the index pattern",
    ),
    (
        "indexes",
        "`indexes` is no longer supported (Splunk indexes are not declared); remove it",
    ),
    (
        "macros",
        "`macros` is no longer supported (Splunk macros are not declared); remove it",
    ),
    (
        "data_views",
        "`data_views` is no longer supported (Elastic data views are not declared); remove it",
    ),
    ("ecs", "`ecs` is no longer supported; remove it"),
];

const KQL_TYPES: &[&str] = &[
    "bool", "datetime", "decimal", "dynamic", "guid", "int", "long", "real", "string", "timespan",
];

/// The column types each system takes in a log source's `columns`, in the
/// oracle's order.
pub const COLUMN_TYPES: [(&str, &[&str]); 4] = [
    ("sentinel", KQL_TYPES),
    ("splunk", &["string", "number", "boolean"]),
    (
        "elastic",
        &[
            "binary",
            "boolean",
            "byte",
            "constant_keyword",
            "date",
            "date_nanos",
            "double",
            "flattened",
            "float",
            "geo_point",
            "half_float",
            "integer",
            "ip",
            "keyword",
            "long",
            "match_only_text",
            "nested",
            "object",
            "scaled_float",
            "short",
            "text",
            "unsigned_long",
            "version",
            "wildcard",
        ],
    ),
    ("defender_for_endpoint", KQL_TYPES),
];

/// A `custom_details` value.
#[derive(Debug, Clone, PartialEq, Serialize, FromNode, JsonSchema)]
#[serde(untagged)]
#[from_node(union)]
pub enum DetailValue {
    /// A string.
    #[from_node(tag = "str")]
    Str(String),
    /// A boolean.
    #[from_node(tag = "bool")]
    Bool(bool),
    /// An integer.
    #[from_node(tag = "int")]
    Int(i64),
    /// A number.
    #[from_node(tag = "float")]
    Float(f64),
}

/// One `[[assets]]` entry.
#[derive(Debug, Clone, PartialEq, Serialize, FromNode, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct VisibilityAsset {
    /// Asset name.
    pub name: String,
    /// What the asset is.
    pub description: String,
    /// Criticality vocabulary value.
    pub criticality: String,
    /// Free-form keys.
    #[serde(default)]
    pub custom_details: Option<BTreeMap<String, DetailValue>>,
    /// Threat surface vocabulary values.
    #[serde(default)]
    pub surface: Option<Vec<String>>,
}

/// One column of a log source's dataset.
#[derive(Debug, Clone, PartialEq, Serialize, FromNode, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct VisibilityColumn {
    /// Column type, from the system's type set.
    pub r#type: String,
    /// What the column holds.
    #[serde(default)]
    pub description: Option<String>,
}

/// One `[[logsources]]` entry: one dataset.
#[derive(Debug, Clone, PartialEq, Serialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct VisibilityLogSource {
    /// The dataset, unique per `system`.
    pub name: String,
    /// What the log source records.
    pub description: String,
    /// Platform identifier of the system that holds the logs.
    pub system: String,
    /// Tenants of `system` that hold the logs.
    pub tenants: Option<Vec<String>>,
    /// Names of the `[[assets]]` that produce the logs.
    pub assets: Option<Vec<String>>,
    /// Reference links.
    pub references: Option<Vec<String>>,
    /// The dataset's columns, keyed by column name, in the file's order.
    #[schemars(with = "Option<BTreeMap<String, VisibilityColumn>>")]
    pub columns: Option<Vec<(String, VisibilityColumn)>>,
}

fn value_error(cx: &mut Context, message: impl Into<String>, node: &Node) {
    cx.error(ErrorKind::InvalidValue("value_error"), message, node);
}

/// `_no_legacy_keys`: every 0.20.0 dataset key fails on its key; `false`
/// stops the entry there.
fn no_legacy_keys(node: &Node, cx: &mut Context) -> bool {
    let Value::Map(entries) = &node.value else {
        return true;
    };
    let mut clean = true;
    for entry in entries {
        let Some(key) = entry.key.value.as_str() else {
            continue;
        };
        if let Some((_, message)) = LEGACY_DATASET_KEYS.iter().find(|(name, _)| *name == key) {
            cx.at_key(key, |cx| value_error(cx, *message, &entry.value));
            clean = false;
        }
    }
    clean
}

fn source_name(node: &Node, cx: &mut Context) -> Option<String> {
    let name = String::from_node(node, cx)?;
    if name.trim().is_empty() {
        value_error(cx, "`name` cannot be empty", node);
        return None;
    }
    Some(name)
}

/// `dict[str, VisibilityColumn]`, in the file's order.
fn columns(node: &Node, cx: &mut Context) -> Option<Vec<(String, VisibilityColumn)>> {
    let Value::Map(entries) = &node.value else {
        cx.error(
            ErrorKind::InvalidType("dict_type"),
            crate::from_node::messages::DICT_TYPE,
            node,
        );
        return None;
    };
    let mut out = Vec::with_capacity(entries.len());
    let mut ok = true;
    for entry in entries {
        let key = entry.key.value.to_string();
        let column = cx.at_key(&key, |cx| VisibilityColumn::from_node(&entry.value, cx));
        match column {
            Some(column) => out.push((key, column)),
            None => ok = false,
        }
    }
    ok.then_some(out)
}

/// `_columns_fit_system`: columns take the type set of the log source's
/// system; other systems take none.
fn columns_fit_system(
    columns: &[(String, VisibilityColumn)],
    system: &str,
    node: &Node,
    cx: &mut Context,
) -> bool {
    let Some((_, types)) = COLUMN_TYPES.iter().find(|(name, _)| *name == system) else {
        let systems: Vec<&str> = COLUMN_TYPES.iter().map(|(name, _)| *name).collect();
        value_error(
            cx,
            format!(
                "`columns` does not apply to system {}; it applies to a log source of {}",
                super::repr::quote(system),
                systems.join(", ")
            ),
            node,
        );
        return false;
    };
    let mut ok = true;
    for (name, _) in columns {
        if name.is_empty() {
            cx.at_key(name, |cx| {
                value_error(cx, "a column name cannot be empty", node);
            });
            ok = false;
        }
    }
    for (name, column) in columns {
        if !types.contains(&column.r#type.as_str()) {
            cx.at_key(name, |cx| {
                cx.at_key("type", |cx| {
                    value_error(
                        cx,
                        format!(
                            "column type {} is not a {system} type; use one of {}",
                            super::repr::quote(&column.r#type),
                            types.join(", ")
                        ),
                        node,
                    );
                });
            });
            ok = false;
        }
    }
    ok
}

impl FromNode for VisibilityLogSource {
    fn from_node(node: &Node, cx: &mut Context) -> Option<Self> {
        if !no_legacy_keys(node, cx) {
            return None;
        }
        let entries = model_entries(node, cx, "VisibilityLogSource")?;
        let mut fields = Fields::new(node, entries);
        let name = fields.field(cx, &["name"], Missing::Required, None, source_name);
        let description = fields.field(cx, &["description"], Missing::Required, None, |n, cx| {
            String::from_node(n, cx)
        });
        let system = fields.field(cx, &["system"], Missing::Required, None, |n, cx| {
            String::from_node(n, cx)
        });
        let optional_list = |n: &Node, cx: &mut Context| Option::<Vec<String>>::from_node(n, cx);
        let tenants = fields.field(
            cx,
            &["tenants"],
            Missing::Default(|| None),
            None,
            optional_list,
        );
        let assets = fields.field(
            cx,
            &["assets"],
            Missing::Default(|| None),
            None,
            optional_list,
        );
        let references = fields.field(
            cx,
            &["references"],
            Missing::Default(|| None),
            None,
            optional_list,
        );
        let system_name = system.clone();
        let columns = fields.field(
            cx,
            &["columns"],
            Missing::Default(|| None),
            None,
            |n: &Node, cx: &mut Context| {
                if matches!(n.value, Value::Null) {
                    return Some(None);
                }
                let columns = columns(n, cx)?;
                if let Some(system) = &system_name
                    && !columns_fit_system(&columns, system, n, cx)
                {
                    return None;
                }
                Some(Some(columns))
            },
        );
        fields.finish(cx, true, &[]);
        Some(Self {
            name: name?,
            description: description?,
            system: system?,
            tenants: tenants?,
            assets: assets?,
            references: references?,
            columns: columns?,
        })
    }
}

/// One `[[detectors]]` entry.
#[derive(Debug, Clone, PartialEq, Serialize, FromNode, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct VisibilityDetector {
    /// Detector name.
    pub name: String,
    /// What the detector covers.
    pub description: String,
    /// Reference links.
    #[serde(default)]
    pub references: Option<Vec<String>>,
    /// Names of the assets the detector monitors.
    #[serde(default)]
    pub assets: Option<Vec<String>>,
}

/// Merged `visibility.toml` (`visibility::1.0`).
#[derive(Debug, Clone, PartialEq, Serialize, FromNode, JsonSchema)]
#[serde(deny_unknown_fields)]
#[from_node(model = "VisibilityConfig")]
pub struct VisibilityFields {
    /// Assets that generate logs.
    #[serde(default)]
    pub assets: Option<Vec<VisibilityAsset>>,
    /// Log sources, one dataset each.
    pub logsources: Vec<VisibilityLogSource>,
    /// External detectors.
    #[serde(default)]
    pub detectors: Option<Vec<VisibilityDetector>>,
}

/// Merged `visibility.toml`, with `name` unique per `system`.
#[derive(Debug, Clone, PartialEq, Serialize, JsonSchema)]
#[serde(transparent)]
pub struct VisibilityConfig(pub VisibilityFields);

impl FromNode for VisibilityConfig {
    fn from_node(node: &Node, cx: &mut Context) -> Option<Self> {
        let fields = VisibilityFields::from_node(node, cx)?;
        let mut seen: Vec<((&str, &str), usize)> = Vec::new();
        let mut ok = true;
        for (position, source) in fields.logsources.iter().enumerate() {
            let key = (source.system.as_str(), source.name.as_str());
            match seen.iter().find(|(seen_key, _)| *seen_key == key) {
                Some((_, first)) => {
                    let first = *first;
                    cx.at_key("logsources", |cx| {
                        cx.at(PathSegment::Index(position), |cx| {
                            cx.at_key("name", |cx| {
                                value_error(
                                    cx,
                                    format!(
                                        "log source {} is already declared for {} by log \
                                         source {}; names are unique per system",
                                        super::repr::quote(&source.name),
                                        source.system,
                                        first + 1
                                    ),
                                    node,
                                );
                            });
                        });
                    });
                    ok = false;
                }
                None => seen.push((key, position)),
            }
        }
        ok.then_some(Self(fields))
    }
}

impl VisibilityConfig {
    /// Asset names a log source or detector uses that `[[assets]]` does not
    /// declare: `(table, index, entry name, position, asset)`.
    pub fn unknown_assets(&self) -> Vec<(&'static str, usize, String, usize, String)> {
        let known: Vec<&str> = self
            .0
            .assets
            .iter()
            .flatten()
            .map(|asset| asset.name.as_str())
            .collect();
        let mut found = Vec::new();
        for (index, source) in self.0.logsources.iter().enumerate() {
            for (position, asset) in source.assets.iter().flatten().enumerate() {
                if !known.contains(&asset.as_str()) {
                    found.push((
                        "logsources",
                        index,
                        source.name.clone(),
                        position,
                        asset.clone(),
                    ));
                }
            }
        }
        for (index, detector) in self.0.detectors.iter().flatten().enumerate() {
            for (position, asset) in detector.assets.iter().flatten().enumerate() {
                if !known.contains(&asset.as_str()) {
                    found.push((
                        "detectors",
                        index,
                        detector.name.clone(),
                        position,
                        asset.clone(),
                    ));
                }
            }
        }
        found
    }
}

// --- sharing.toml ----------------------------------------------------------------------

/// `tlp` vocabulary names, in ceiling order (`TlpName`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, FromNode, JsonSchema)]
#[from_node(literal)]
pub enum TlpName {
    /// `clear`.
    #[serde(rename = "clear")]
    Clear,
    /// `green`.
    #[serde(rename = "green")]
    Green,
    /// `amber`.
    #[serde(rename = "amber")]
    Amber,
    /// `amber+strict`.
    #[serde(rename = "amber+strict")]
    AmberStrict,
    /// `red`.
    #[serde(rename = "red")]
    Red,
}

impl TlpName {
    /// The name.
    pub const fn name(self) -> &'static str {
        match self {
            Self::Clear => "clear",
            Self::Green => "green",
            Self::Amber => "amber",
            Self::AmberStrict => "amber+strict",
            Self::Red => "red",
        }
    }
}

/// The `TlpName` values, in ceiling order.
pub const TLP_ORDER: [&str; 5] = ["clear", "green", "amber", "amber+strict", "red"];

fn production_statuses() -> Vec<NonEmptyString> {
    vec![production()]
}

/// One `[[misp]]` block (`sharing::misp::1.0`).
#[derive(Debug, Clone, PartialEq, Serialize, FromNode, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct MispIntegration {
    /// Block name.
    pub name: Matching<MispNamePattern>,
    /// Share to this instance.
    #[serde(default)]
    pub enabled: bool,
    /// Base URL of the MISP instance.
    pub url: Matching<HttpUrlPattern>,
    /// MISP automation key: a `${NAME}` reference.
    #[serde(skip_serializing)]
    pub api_key: NonEmptyString,
    /// Highest tlp an object may carry and still be shared here.
    pub max_tlp: TlpName,
    /// Object families shared to this instance.
    #[serde(default = "all_families")]
    pub object_types: Vec<ObjectFamily>,
    /// Deployment statuses a rule must have to be shared.
    #[serde(default = "production_statuses")]
    pub rule_statuses: Vec<NonEmptyString>,
    /// UUID of the MISP organisation the events are created for.
    #[serde(default)]
    pub organisation_uuid: Option<Matching<OrganisationUuidPattern>>,
    /// Publish events after writing them.
    #[serde(default)]
    pub publish: bool,
    /// Verify the instance's TLS certificate.
    #[serde(default = "yes")]
    pub verify_ssl: bool,
}

/// Merged `sharing.toml`: connector arrays; `[[misp]]` is the only one.
#[derive(Debug, Clone, PartialEq, Serialize, FromNode, JsonSchema)]
#[from_node(before = "only_connector_arrays")]
pub struct SharingConfiguration {
    /// MISP instances.
    #[serde(default)]
    pub misp: Vec<MispIntegration>,
}

/// A TOML array of tables (an empty array is one).
pub fn is_table_array(node: &Node) -> bool {
    match &node.value {
        Value::Seq(items) => items.iter().all(|item| matches!(item.value, Value::Map(_))),
        _ => false,
    }
}

fn only_connector_arrays(node: &Node, cx: &mut Context) -> bool {
    if let Value::Map(entries) = &node.value {
        for entry in entries {
            let key = entry.key.value.to_string();
            if key != "misp" && !is_table_array(&entry.value) {
                value_error(
                    cx,
                    format!(
                        "Value error, {} is not a connector array; the top level holds \
                         [[misp]] blocks",
                        super::repr::quote(&key)
                    ),
                    node,
                );
                return false;
            }
        }
    }
    true
}
