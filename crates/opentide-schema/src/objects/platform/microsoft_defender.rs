//! Microsoft Defender custom detection rule on the Microsoft Graph beta
//! custom detection API, `platform::microsoft_defender::1.0`
//! (`MicrosoftDefenderConfig` and its nested models, RFC 0021), with the
//! block's constraints ([`block_findings`]): every code of
//! microsoft-defender-1.0's Constraints, each reported by its own code
//! ([`ErrorKind::Constraint`]) at the path the specification fixes for it,
//! relative to the block, and its advisory ([`advisories`]).
//!
//! The entity kinds ([`ENTITY_KINDS`]) and automated actions ([`ACTIONS`])
//! are tables: the checks, the compiler's request body and the tests read
//! them, so a field is named once. The typed models below give the JSON
//! Schema and the Python classes the same fields.

pub mod checks;
pub mod required_columns;

use garde::Validate;
use indexmap::IndexMap;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::FromNode;
use crate::error::ErrorKind;
use crate::from_node::Context;
use crate::node::{Node, Value};
use crate::objects::any::Any;
use crate::objects::platform::{literal_enum, optional_literal, platform_block};
use crate::pins::Pins;

pub use checks::{CONSTRAINT_CODES, Finding, block_codes, block_findings};

/// The platform's key under `configurations`.
pub const PLATFORM: &str = "microsoft_defender";

/// The schema identifier.
pub const SCHEMA: &str = "platform::microsoft_defender::1.0";

/// The advisory of a block that maps no entity.
pub const NO_ENTITIES: &str = opentide_core::codes::MICROSOFT_DEFENDER_NO_ENTITIES;

/// The advisory of an impacted-asset mapping (`hosts`, `accounts`) that
/// sets none of the asset's identifiers ([`Identifiers::asset`]).
pub const IMPACTED_ASSET_IDENTIFIER: &str =
    opentide_core::codes::MICROSOFT_DEFENDER_IMPACTED_ASSET_IDENTIFIER;

/// Every advisory [`advisories`] reports.
pub const ADVISORY_CODES: [&str; 2] = [NO_ENTITIES, IMPACTED_ASSET_IDENTIFIER];

/// One entity kind or automated action: its key in the block, its Graph
/// name, and its fields, each the block's key and the Graph property it is
/// sent as, in the specification's order.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Kind {
    /// The key under `entities` or `actions` (`registry_values`).
    pub key: &'static str,
    /// The Graph name (`registryValues`).
    pub graph: &'static str,
    /// Each field: the block's key and the Graph property.
    pub fields: &'static [(&'static str, &'static str)],
}

impl Kind {
    /// The Graph property of the field `key`, when the kind has it.
    pub fn graph_field(&self, key: &str) -> Option<&'static str> {
        self.fields
            .iter()
            .find(|(field, _)| *field == key)
            .map(|(_, graph)| *graph)
    }
}

/// The seventeen kinds of Graph's `entityMappingConfiguration`
/// (microsoft-defender-1.0, `entities`).
pub const ENTITY_KINDS: [Kind; 17] = [
    Kind {
        key: "hosts",
        graph: "hosts",
        fields: &[
            ("device_id", "deviceIdColumn"),
            ("name", "nameColumn"),
            ("dns_domain", "dnsDomainColumn"),
            ("netbios_name", "netBiosNameColumn"),
            ("nt_domain", "ntDomainColumn"),
        ],
    },
    Kind {
        key: "accounts",
        graph: "accounts",
        fields: &[
            ("aad_user_id", "aadUserIdColumn"),
            ("sid", "sidColumn"),
            ("upn", "upnColumn"),
            ("upn_suffix", "upnSuffixColumn"),
            ("name", "nameColumn"),
            ("nt_domain", "ntDomainColumn"),
            ("dns_domain", "dnsDomainColumn"),
        ],
    },
    Kind {
        key: "mailboxes",
        graph: "mailboxes",
        fields: &[("primary_address", "primaryAddressColumn")],
    },
    Kind {
        key: "files",
        graph: "files",
        fields: &[
            ("name", "nameColumn"),
            ("sha1", "sha1Column"),
            ("sha256", "sha256Column"),
        ],
    },
    Kind {
        key: "processes",
        graph: "processes",
        fields: &[("sha1", "sha1Column"), ("sha256", "sha256Column")],
    },
    Kind {
        key: "ips",
        graph: "ips",
        fields: &[("address", "addressColumn"), ("scope", "scopeColumn")],
    },
    Kind {
        key: "urls",
        graph: "urls",
        fields: &[("address", "addressColumn")],
    },
    Kind {
        key: "dns",
        graph: "dns",
        fields: &[
            ("domain_name", "domainNameColumn"),
            ("host_ip_address", "hostIpAddressColumn"),
            ("server_ip", "serverIpColumn"),
        ],
    },
    Kind {
        key: "registry_values",
        graph: "registryValues",
        fields: &[("key", "keyColumn"), ("value_name", "valueNameColumn")],
    },
    Kind {
        key: "mail_messages",
        graph: "mailMessages",
        fields: &[
            ("network_message_id", "networkMessageIdColumn"),
            ("recipient", "recipientColumn"),
            ("sender", "senderColumn"),
            ("subject", "subjectColumn"),
        ],
    },
    Kind {
        key: "mail_clusters",
        graph: "mailClusters",
        fields: &[("query", "queryColumn"), ("source", "sourceColumn")],
    },
    Kind {
        key: "cloud_applications",
        graph: "cloudApplications",
        fields: &[("app_id", "appIdColumn"), ("name", "nameColumn")],
    },
    Kind {
        key: "oauth_applications",
        graph: "oAuthApplications",
        fields: &[("oauth_app_id", "oAuthAppIdColumn")],
    },
    Kind {
        key: "security_groups",
        graph: "securityGroups",
        fields: &[
            ("object_id", "objectIdColumn"),
            ("sid", "sidColumn"),
            ("distinguished_name", "distinguishedNameColumn"),
        ],
    },
    Kind {
        key: "azure_resources",
        graph: "azureResources",
        fields: &[("resource_id", "resourceIdColumn")],
    },
    Kind {
        key: "amazon_resources",
        graph: "amazonResources",
        fields: &[("amazon_resource_id", "amazonResourceIdColumn")],
    },
    Kind {
        key: "google_cloud_resources",
        graph: "googleCloudResources",
        fields: &[("full_resource_name", "fullResourceNameColumn")],
    },
];

/// Where a rule of [`ENTITY_IDENTIFIERS`] comes from, which decides whether
/// it is enforced: only an observed or documented rule is.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Evidence {
    /// Graph refused such a mapping on a tenant; the reference quotes its
    /// answer.
    Observed,
    /// Microsoft's documentation states it; the reference is the page.
    Documented,
    /// The kind has one field, which every mapping names already
    /// (`microsoft_defender_entity_mapping`): nothing more to require.
    OneField,
    /// Nothing published or observed says Graph requires more than one of the
    /// kind's fields: no rule until a tenant probe records one
    /// (`docs/internal/microsoft-defender-tenant-test.md`, check 11).
    Unprobed,
    /// Microsoft's documentation recommends it without saying Graph refuses
    /// anything else: a warning at most, never an error.
    Advised,
}

/// The provenance of a rule of [`ENTITY_IDENTIFIERS`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Source {
    /// What kind of evidence it is.
    pub evidence: Evidence,
    /// The page, or Graph's answer, the rule comes from.
    pub reference: &'static str,
    /// When the reference was read (ISO 8601 date).
    pub checked: &'static str,
}

/// What Graph requires of one entity kind's mapping beyond naming one of its
/// fields, and, for an impacted asset, the fields Defender identifies the
/// asset by. The checks read it: `microsoft_defender_entity_identifier`
/// (an error) for a missing required field,
/// `microsoft_defender_impacted_asset_identifier` (a warning) for an asset
/// mapping that sets none of its identifiers.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Identifiers {
    /// The kind's key under `entities` (`registry_values`).
    pub kind: &'static str,
    /// Each field every mapping must set, with the identifier Graph's error
    /// names it by (`("key", "RegKey")`). Empty: any one of the kind's fields
    /// will do.
    pub required: &'static [(&'static str, &'static str)],
    /// Where `required` comes from.
    pub source: Source,
    /// For a kind whose mapping should identify an impacted asset (`hosts`,
    /// `accounts`): the fields, or combinations of fields, that do. A mapping
    /// that sets all the fields of one of them is identified. Empty for every
    /// other kind.
    pub asset: &'static [AssetIdentifier],
}

/// One way an impacted-asset mapping identifies its device or user: the
/// fields it sets, all of them, and where that comes from.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AssetIdentifier {
    /// The fields, all set (`["name", "nt_domain"]`).
    pub fields: &'static [&'static str],
    /// The result columns the source names for it (`AccountSid,
    /// InitiatingProcessAccountSid`); empty when it names none.
    pub columns: &'static str,
    /// [`IMPACTED_ASSET_COLUMNS`] or [`STRONG_IDENTIFIERS`].
    pub source: Source,
}

/// The date the identifier rules were last checked against their sources.
pub const IDENTIFIERS_CHECKED: &str = "2026-11-26";

/// Microsoft's custom detection rules page: the result columns the rule
/// wizard maps to an impacted device, mailbox or user by itself, each "a
/// strong identifier for an impacted asset". It does not say what Graph
/// does with a mapping that sets none of them.
pub const IMPACTED_ASSET_COLUMNS: Source = Source {
    evidence: Evidence::Advised,
    reference: "https://learn.microsoft.com/en-us/defender-xdr/custom-detection-rules \
                (Required columns in the query results: the columns the wizard maps to an \
                impacted asset automatically)",
    checked: IDENTIFIERS_CHECKED,
};

/// Microsoft Sentinel's entity reference, whose Account and Host entities
/// are Defender's users and devices: the combinations that are strong
/// identifiers.
pub const STRONG_IDENTIFIERS: Source = Source {
    evidence: Evidence::Advised,
    reference: "https://learn.microsoft.com/en-us/azure/sentinel/entities-reference (strong \
                identifiers of an account: Name + UPNSuffix, Name + NTDomain, Name + DnsDomain; \
                of a host: HostName or NetBiosName + NTDomain or DnsDomain)",
    checked: IDENTIFIERS_CHECKED,
};

/// An identifier from the custom detection rules page's columns.
const fn column(fields: &'static [&'static str], columns: &'static str) -> AssetIdentifier {
    AssetIdentifier {
        fields,
        columns,
        source: IMPACTED_ASSET_COLUMNS,
    }
}

/// A strong combination from Sentinel's entity reference.
const fn strong(fields: &'static [&'static str]) -> AssetIdentifier {
    AssetIdentifier {
        fields,
        columns: "",
        source: STRONG_IDENTIFIERS,
    }
}

const UNPROBED: Source = Source {
    evidence: Evidence::Unprobed,
    reference: "the Graph beta entity mapping types list their columns, not which are \
                required; nothing observed",
    checked: IDENTIFIERS_CHECKED,
};

const ONE_FIELD: Source = Source {
    evidence: Evidence::OneField,
    reference: "the Graph beta entity mapping type has one column",
    checked: IDENTIFIERS_CHECKED,
};

/// A kind with no rule beyond one of its fields.
const fn unprobed(kind: &'static str) -> Identifiers {
    Identifiers {
        kind,
        required: &[],
        source: UNPROBED,
        asset: &[],
    }
}

/// A kind with one field.
const fn one_field(kind: &'static str) -> Identifiers {
    Identifiers {
        kind,
        required: &[],
        source: ONE_FIELD,
        asset: &[],
    }
}

/// The identifier rules of the seventeen kinds, in [`ENTITY_KINDS`]' order
/// (microsoft-defender-1.0, `entities`). A rule is enforced only when its
/// source is [`Evidence::Observed`] or [`Evidence::Documented`]: an error
/// that blocks a deploy Graph would accept is worse than a missed one.
pub const ENTITY_IDENTIFIERS: [Identifiers; 17] = [
    Identifiers {
        kind: "hosts",
        required: &[],
        source: UNPROBED,
        asset: &[
            column(&["device_id"], "DeviceId"),
            column(&["name"], "DeviceName, RemoteDeviceName"),
            strong(&["netbios_name", "nt_domain"]),
            strong(&["netbios_name", "dns_domain"]),
        ],
    },
    Identifiers {
        kind: "accounts",
        required: &[],
        source: UNPROBED,
        asset: &[
            column(&["aad_user_id"], "AccountObjectId"),
            column(&["sid"], "AccountSid, InitiatingProcessAccountSid"),
            column(&["upn"], "AccountUpn, InitiatingProcessAccountUpn"),
            strong(&["name", "upn_suffix"]),
            strong(&["name", "nt_domain"]),
            strong(&["name", "dns_domain"]),
        ],
    },
    one_field("mailboxes"),
    unprobed("files"),
    unprobed("processes"),
    unprobed("ips"),
    one_field("urls"),
    unprobed("dns"),
    Identifiers {
        kind: "registry_values",
        required: &[("key", "RegKey")],
        source: Source {
            evidence: Evidence::Observed,
            reference: "Graph beta detectionRules, a rule whose registryValues mapping sets \
                        valueNameColumn and no keyColumn, refused at deploy on a production \
                        tenant: \"HTTP 400 · Entity mapping for type 'RegistryValue' does not include a required \
                        identifier. Supported identifiers: RegKey | Name\" (opentide#1884); \
                        Microsoft Sentinel's entity reference agrees: a registry value's strong \
                        identifier is Key + Name, Name without Key is weak \
                        (https://learn.microsoft.com/en-us/azure/sentinel/entities-reference)",
            checked: IDENTIFIERS_CHECKED,
        },
        asset: &[],
    },
    unprobed("mail_messages"),
    unprobed("mail_clusters"),
    unprobed("cloud_applications"),
    one_field("oauth_applications"),
    unprobed("security_groups"),
    one_field("azure_resources"),
    one_field("amazon_resources"),
    one_field("google_cloud_resources"),
];

/// The identifier rules of the entity kind `key`.
pub fn entity_identifiers(key: &str) -> Option<&'static Identifiers> {
    ENTITY_IDENTIFIERS
        .iter()
        .find(|identifiers| identifiers.kind == key)
}

/// An action target's `isolation_type`, which is not a column.
pub const ISOLATION_TYPE: &str = "isolation_type";
/// An action target's `device_groups`, a list of device group names.
pub const DEVICE_GROUPS: &str = "device_groups";

const EMAIL_FIELDS: &[(&str, &str)] = &[
    ("network_message_id", "networkMessageIdColumn"),
    ("recipient", "recipientColumn"),
];
const FILE_FIELDS: &[(&str, &str)] = &[
    ("sha1", "sha1Column"),
    ("sha256", "sha256Column"),
    (DEVICE_GROUPS, "deviceGroupNames"),
];
const DEVICE_FIELDS: &[(&str, &str)] = &[("device_id", "deviceIdColumn")];

/// The sixteen actions of Graph's `automatedActionSet`
/// (microsoft-defender-1.0, `actions`).
pub const ACTIONS: [Kind; 16] = [
    Kind {
        key: "isolate_devices",
        graph: "isolateDevices",
        fields: &[
            ("device_id", "deviceIdColumn"),
            (ISOLATION_TYPE, "isolationType"),
        ],
    },
    Kind {
        key: "collect_investigation_packages",
        graph: "collectInvestigationPackages",
        fields: DEVICE_FIELDS,
    },
    Kind {
        key: "run_antivirus_scans",
        graph: "runAntivirusScans",
        fields: DEVICE_FIELDS,
    },
    Kind {
        key: "initiate_investigations",
        graph: "initiateInvestigations",
        fields: DEVICE_FIELDS,
    },
    Kind {
        key: "restrict_app_executions",
        graph: "restrictAppExecutions",
        fields: DEVICE_FIELDS,
    },
    Kind {
        key: "allow_files",
        graph: "allowFiles",
        fields: FILE_FIELDS,
    },
    Kind {
        key: "block_files",
        graph: "blockFiles",
        fields: FILE_FIELDS,
    },
    Kind {
        key: "stop_and_quarantine_files",
        graph: "stopAndQuarantineFiles",
        fields: &[("device_id", "deviceIdColumn"), ("sha1", "sha1Column")],
    },
    Kind {
        key: "disable_users",
        graph: "disableUsers",
        fields: &[("account_sid", "accountSidColumn")],
    },
    Kind {
        key: "force_user_password_resets",
        graph: "forceUserPasswordResets",
        fields: &[("account_sid", "accountSidColumn")],
    },
    Kind {
        key: "mark_users_as_compromised",
        graph: "markUsersAsCompromised",
        fields: &[("account_object_id", "accountObjectIdColumn")],
    },
    Kind {
        key: "soft_delete_emails",
        graph: "softDeleteEmails",
        fields: EMAIL_FIELDS,
    },
    Kind {
        key: "hard_delete_emails",
        graph: "hardDeleteEmails",
        fields: EMAIL_FIELDS,
    },
    Kind {
        key: "move_emails_to_deleted_items",
        graph: "moveEmailsToDeletedItems",
        fields: EMAIL_FIELDS,
    },
    Kind {
        key: "move_emails_to_inbox",
        graph: "moveEmailsToInbox",
        fields: EMAIL_FIELDS,
    },
    Kind {
        key: "move_emails_to_junk",
        graph: "moveEmailsToJunk",
        fields: EMAIL_FIELDS,
    },
];

/// The entity kind `key`.
pub fn entity_kind(key: &str) -> Option<&'static Kind> {
    ENTITY_KINDS.iter().find(|kind| kind.key == key)
}

/// The automated action `key`.
pub fn action(key: &str) -> Option<&'static Kind> {
    ACTIONS.iter().find(|kind| kind.key == key)
}

/// `alert.severity`'s values (opentide's severities, `Critical` included).
pub const SEVERITIES: [&str; 5] = crate::objects::platform::SEVERITIES;

/// `alert.grouping`'s values and the Graph `eventGroupingKind` each is sent
/// as.
pub const GROUPINGS: [(&str, &str); 2] = [
    ("alert_per_event", "alertPerEvent"),
    ("single_alert", "singleAlert"),
];

/// `isolation_type`'s values (Graph's `isolationType`, sent as written).
pub const ISOLATION_TYPES: [&str; 2] = ["full", "selective"];

/// The keys only the Graph beta API has, each with its path under the block
/// (microsoft-defender-1.0, Beta-only properties).
pub const BETA_ONLY: [&str; 3] = ["schedule.lookback", "alert.grouping", "incident"];

/// Why a Graph beta property is not a key of the block.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NotModelled {
    /// Deploy sets it from the rule.
    SetByDeploy,
    /// Graph sets it; a request does not.
    ReadOnly,
    /// Graph deprecated it; deploy never sends it.
    Deprecated,
}

/// Every writable property of the Graph beta API the block does not model,
/// as `type.property`, and why (microsoft-defender-1.0, Beta properties not
/// modelled). Every other property of the API's types is a key of the block.
pub const NOT_MODELLED: [(&str, NotModelled); 26] = [
    ("detectionRule.id", NotModelled::SetByDeploy),
    ("detectionRule.displayName", NotModelled::SetByDeploy),
    ("detectionRule.description", NotModelled::SetByDeploy),
    ("detectionRule.status", NotModelled::SetByDeploy),
    ("detectionRule.createdBy", NotModelled::ReadOnly),
    ("detectionRule.createdDateTime", NotModelled::ReadOnly),
    ("detectionRule.lastModifiedBy", NotModelled::ReadOnly),
    ("detectionRule.lastModifiedDateTime", NotModelled::ReadOnly),
    ("detectionRule.detectorId", NotModelled::Deprecated),
    ("detectionRule.isEnabled", NotModelled::Deprecated),
    ("detectionRule.lastRunDetails", NotModelled::Deprecated),
    ("queryCondition.queryText", NotModelled::SetByDeploy),
    (
        "queryCondition.lastModifiedDateTime",
        NotModelled::Deprecated,
    ),
    ("ruleSchedule.nextRunDateTime", NotModelled::Deprecated),
    ("ruleSchedule.period", NotModelled::Deprecated),
    ("alertTemplate.tactics", NotModelled::SetByDeploy),
    ("alertTemplate.category", NotModelled::Deprecated),
    ("alertTemplate.impactedAssets", NotModelled::Deprecated),
    ("alertTemplate.mitreTechniques", NotModelled::Deprecated),
    ("mitreTactic.tactic", NotModelled::SetByDeploy),
    ("mitreTactic.techniques", NotModelled::SetByDeploy),
    ("mitreTechnique.technique", NotModelled::SetByDeploy),
    ("mitreTechnique.subTechniques", NotModelled::SetByDeploy),
    ("detectionAction.responseActions", NotModelled::Deprecated),
    ("organizationalScope.scopeNames", NotModelled::Deprecated),
    ("organizationalScope.scopeType", NotModelled::Deprecated),
];

/// A `schedule` duration: its count and unit (`H` or `D`), or `NRT`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Duration {
    /// `NRT`: near real time, a zero frequency.
    NearRealTime,
    /// `<n>H`.
    Hours(u64),
    /// `<n>D`.
    Days(u64),
}

impl Duration {
    /// Reads `NRT`, `<n>H` or `<n>D`, `n` a positive integer without a
    /// leading zero; `None` for anything else (`0H`, `01H`, `1h`, `PT1H`).
    pub fn parse(text: &str) -> Option<Self> {
        if text == "NRT" {
            return Some(Self::NearRealTime);
        }
        let (count, unit) = text.split_at(text.len().checked_sub(1)?);
        if count.is_empty()
            || count.starts_with('0')
            || !count.bytes().all(|byte| byte.is_ascii_digit())
        {
            return None;
        }
        let count: u64 = count.parse().ok()?;
        match unit {
            "H" => Some(Self::Hours(count)),
            "D" => Some(Self::Days(count)),
            _ => None,
        }
    }

    /// The duration in hours (`1D` is `24`), `0` for `NRT`; `None` past
    /// `u64`.
    pub fn hours(self) -> Option<u64> {
        match self {
            Self::NearRealTime => Some(0),
            Self::Hours(hours) => Some(hours),
            Self::Days(days) => days.checked_mul(24),
        }
    }

    /// The ISO 8601 duration Graph takes: `PT0S` for `NRT`, `PT<n>H`,
    /// `P<n>D`.
    pub fn iso8601(self) -> String {
        match self {
            Self::NearRealTime => "PT0S".to_owned(),
            Self::Hours(hours) => format!("PT{hours}H"),
            Self::Days(days) => format!("P{days}D"),
        }
    }
}

/// Declares a model whose fields are all optional result columns, with the
/// derives every model here takes.
macro_rules! columns {
    (
        $(#[$doc:meta])*
        $name:ident {
            $( $(#[$field_doc:meta])* $field:ident, )*
        }
    ) => {
        #[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema, Validate, FromNode)]
        $(#[$doc])*
        #[serde(deny_unknown_fields)]
        #[garde(context(Pins))]
        #[garde(allow_unvalidated)]
        #[cfg_attr(
            feature = "python",
            pyo3::pyclass(frozen, get_all, eq, module = "opentide._native.models")
        )]
        #[cfg_attr(
            feature = "python",
            expect(
                clippy::unsafe_derive_deserialize,
                reason = "the `unsafe` is PyO3's FFI glue, which relies on no invariant of the fields"
            )
        )]
        pub struct $name {
            $(
                $(#[$field_doc])*
                #[serde(default, skip_serializing_if = "Option::is_none")]
                pub $field: Option<String>,
            )*
        }
    };
}

columns! {
    /// A device: `alertTemplate.entityMappings.hosts` (`DefenderHostMapping`).
    #[schemars(rename = "DefenderHostMapping", description = "")]
    #[from_node(model = "DefenderHostMapping")]
    DefenderHostMapping {
        /// Column holding the device id (`deviceIdColumn`).
        device_id,
        /// Column holding the device name (`nameColumn`).
        name,
        /// Column holding the DNS domain (`dnsDomainColumn`).
        dns_domain,
        /// Column holding the NetBIOS name (`netBiosNameColumn`).
        netbios_name,
        /// Column holding the NT domain (`ntDomainColumn`).
        nt_domain,
    }
}

columns! {
    /// A user account: `alertTemplate.entityMappings.accounts`
    /// (`DefenderAccountMapping`).
    #[schemars(rename = "DefenderAccountMapping", description = "")]
    #[from_node(model = "DefenderAccountMapping")]
    DefenderAccountMapping {
        /// Column holding the Microsoft Entra object id (`aadUserIdColumn`).
        aad_user_id,
        /// Column holding the SID (`sidColumn`).
        sid,
        /// Column holding the user principal name (`upnColumn`).
        upn,
        /// Column holding the UPN suffix (`upnSuffixColumn`).
        upn_suffix,
        /// Column holding the account name (`nameColumn`).
        name,
        /// Column holding the NT domain (`ntDomainColumn`).
        nt_domain,
        /// Column holding the DNS domain (`dnsDomainColumn`).
        dns_domain,
    }
}

columns! {
    /// A mailbox: `alertTemplate.entityMappings.mailboxes`
    /// (`DefenderMailboxMapping`).
    #[schemars(rename = "DefenderMailboxMapping", description = "")]
    #[from_node(model = "DefenderMailboxMapping")]
    DefenderMailboxMapping {
        /// Column holding the primary address (`primaryAddressColumn`).
        primary_address,
    }
}

columns! {
    /// A file: `alertTemplate.entityMappings.files` (`DefenderFileMapping`).
    #[schemars(rename = "DefenderFileMapping", description = "")]
    #[from_node(model = "DefenderFileMapping")]
    DefenderFileMapping {
        /// Column holding the file name (`nameColumn`).
        name,
        /// Column holding the SHA-1 (`sha1Column`).
        sha1,
        /// Column holding the SHA-256 (`sha256Column`).
        sha256,
    }
}

columns! {
    /// A process: `alertTemplate.entityMappings.processes`
    /// (`DefenderProcessMapping`).
    #[schemars(rename = "DefenderProcessMapping", description = "")]
    #[from_node(model = "DefenderProcessMapping")]
    DefenderProcessMapping {
        /// Column holding the image's SHA-1 (`sha1Column`).
        sha1,
        /// Column holding the image's SHA-256 (`sha256Column`).
        sha256,
    }
}

columns! {
    /// An IP address: `alertTemplate.entityMappings.ips` (`DefenderIpMapping`).
    #[schemars(rename = "DefenderIpMapping", description = "")]
    #[from_node(model = "DefenderIpMapping")]
    DefenderIpMapping {
        /// Column holding the address (`addressColumn`).
        address,
        /// Column holding the address's scope (`scopeColumn`).
        scope,
    }
}

columns! {
    /// A URL: `alertTemplate.entityMappings.urls` (`DefenderUrlMapping`).
    #[schemars(rename = "DefenderUrlMapping", description = "")]
    #[from_node(model = "DefenderUrlMapping")]
    DefenderUrlMapping {
        /// Column holding the URL (`addressColumn`).
        address,
    }
}

columns! {
    /// A DNS resolution: `alertTemplate.entityMappings.dns`
    /// (`DefenderDnsMapping`).
    #[schemars(rename = "DefenderDnsMapping", description = "")]
    #[from_node(model = "DefenderDnsMapping")]
    DefenderDnsMapping {
        /// Column holding the domain name (`domainNameColumn`).
        domain_name,
        /// Column holding the host's IP address (`hostIpAddressColumn`).
        host_ip_address,
        /// Column holding the DNS server's IP (`serverIpColumn`).
        server_ip,
    }
}

columns! {
    /// A registry value: `alertTemplate.entityMappings.registryValues`
    /// (`DefenderRegistryValueMapping`).
    #[schemars(rename = "DefenderRegistryValueMapping", description = "")]
    #[from_node(model = "DefenderRegistryValueMapping")]
    DefenderRegistryValueMapping {
        /// Column holding the registry key (`keyColumn`).
        key,
        /// Column holding the value name (`valueNameColumn`).
        value_name,
    }
}

columns! {
    /// A mail message: `alertTemplate.entityMappings.mailMessages`
    /// (`DefenderMailMessageMapping`).
    #[schemars(rename = "DefenderMailMessageMapping", description = "")]
    #[from_node(model = "DefenderMailMessageMapping")]
    DefenderMailMessageMapping {
        /// Column holding the network message id (`networkMessageIdColumn`).
        network_message_id,
        /// Column holding the recipient (`recipientColumn`).
        recipient,
        /// Column holding the sender (`senderColumn`).
        sender,
        /// Column holding the subject (`subjectColumn`).
        subject,
    }
}

columns! {
    /// A mail cluster: `alertTemplate.entityMappings.mailClusters`
    /// (`DefenderMailClusterMapping`).
    #[schemars(rename = "DefenderMailClusterMapping", description = "")]
    #[from_node(model = "DefenderMailClusterMapping")]
    DefenderMailClusterMapping {
        /// Column holding the cluster's query (`queryColumn`).
        #[schemars(extend("tide.template.multiline" = false))]
        query,
        /// Column holding the cluster's source (`sourceColumn`).
        source,
    }
}

columns! {
    /// A cloud application: `alertTemplate.entityMappings.cloudApplications`
    /// (`DefenderCloudApplicationMapping`).
    #[schemars(rename = "DefenderCloudApplicationMapping", description = "")]
    #[from_node(model = "DefenderCloudApplicationMapping")]
    DefenderCloudApplicationMapping {
        /// Column holding the application id (`appIdColumn`).
        app_id,
        /// Column holding the application name (`nameColumn`).
        name,
    }
}

columns! {
    /// An OAuth application: `alertTemplate.entityMappings.oAuthApplications`
    /// (`DefenderOAuthApplicationMapping`).
    #[schemars(rename = "DefenderOAuthApplicationMapping", description = "")]
    #[from_node(model = "DefenderOAuthApplicationMapping")]
    DefenderOAuthApplicationMapping {
        /// Column holding the OAuth application id (`oAuthAppIdColumn`).
        oauth_app_id,
    }
}

columns! {
    /// A security group: `alertTemplate.entityMappings.securityGroups`
    /// (`DefenderSecurityGroupMapping`).
    #[schemars(rename = "DefenderSecurityGroupMapping", description = "")]
    #[from_node(model = "DefenderSecurityGroupMapping")]
    DefenderSecurityGroupMapping {
        /// Column holding the group's object id (`objectIdColumn`).
        object_id,
        /// Column holding the group's SID (`sidColumn`).
        sid,
        /// Column holding the distinguished name (`distinguishedNameColumn`).
        distinguished_name,
    }
}

columns! {
    /// An Azure resource: `alertTemplate.entityMappings.azureResources`
    /// (`DefenderAzureResourceMapping`).
    #[schemars(rename = "DefenderAzureResourceMapping", description = "")]
    #[from_node(model = "DefenderAzureResourceMapping")]
    DefenderAzureResourceMapping {
        /// Column holding the resource id (`resourceIdColumn`).
        resource_id,
    }
}

columns! {
    /// An Amazon resource: `alertTemplate.entityMappings.amazonResources`
    /// (`DefenderAmazonResourceMapping`).
    #[schemars(rename = "DefenderAmazonResourceMapping", description = "")]
    #[from_node(model = "DefenderAmazonResourceMapping")]
    DefenderAmazonResourceMapping {
        /// Column holding the Amazon resource id (`amazonResourceIdColumn`).
        amazon_resource_id,
    }
}

columns! {
    /// A Google Cloud resource:
    /// `alertTemplate.entityMappings.googleCloudResources`
    /// (`DefenderGoogleCloudResourceMapping`).
    #[schemars(rename = "DefenderGoogleCloudResourceMapping", description = "")]
    #[from_node(model = "DefenderGoogleCloudResourceMapping")]
    DefenderGoogleCloudResourceMapping {
        /// Column holding the full resource name (`fullResourceNameColumn`).
        full_resource_name,
    }
}

columns! {
    /// A target of a device action (`DefenderDeviceTarget`).
    #[schemars(rename = "DefenderDeviceTarget", description = "")]
    #[from_node(model = "DefenderDeviceTarget")]
    DefenderDeviceTarget {
        /// Column holding the device id (`deviceIdColumn`).
        device_id,
    }
}

columns! {
    /// A target of `stop_and_quarantine_files` (`DefenderQuarantineTarget`).
    #[schemars(rename = "DefenderQuarantineTarget", description = "")]
    #[from_node(model = "DefenderQuarantineTarget")]
    DefenderQuarantineTarget {
        /// Column holding the device id (`deviceIdColumn`).
        device_id,
        /// Column holding the file's SHA-1 (`sha1Column`).
        sha1,
    }
}

columns! {
    /// A target of `disable_users` and `force_user_password_resets`
    /// (`DefenderAccountSidTarget`).
    #[schemars(rename = "DefenderAccountSidTarget", description = "")]
    #[from_node(model = "DefenderAccountSidTarget")]
    DefenderAccountSidTarget {
        /// Column holding the account's SID (`accountSidColumn`).
        account_sid,
    }
}

columns! {
    /// A target of `mark_users_as_compromised` (`DefenderAccountObjectTarget`).
    #[schemars(rename = "DefenderAccountObjectTarget", description = "")]
    #[from_node(model = "DefenderAccountObjectTarget")]
    DefenderAccountObjectTarget {
        /// Column holding the account's Microsoft Entra object id
        /// (`accountObjectIdColumn`).
        account_object_id,
    }
}

columns! {
    /// A target of an email action (`DefenderEmailTarget`).
    #[schemars(rename = "DefenderEmailTarget", description = "")]
    #[from_node(model = "DefenderEmailTarget")]
    DefenderEmailTarget {
        /// Column holding the network message id (`networkMessageIdColumn`).
        network_message_id,
        /// Column holding the recipient (`recipientColumn`).
        recipient,
    }
}

literal_enum! {
    /// `isolation_type`: `full` or `selective`.
    DefenderIsolationType { Full = "full", Selective = "selective", }
}

literal_enum! {
    /// `alert.grouping`: `alert_per_event` or `single_alert`.
    DefenderGrouping { AlertPerEvent = "alert_per_event", SingleAlert = "single_alert", }
}

impl DefenderGrouping {
    /// The Graph `eventGroupingKind`.
    pub const fn graph(self) -> &'static str {
        match self {
            Self::AlertPerEvent => "alertPerEvent",
            Self::SingleAlert => "singleAlert",
        }
    }
}

/// A target of `isolate_devices` (`DefenderIsolationTarget`).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema, Validate, FromNode)]
#[serde(deny_unknown_fields)]
#[garde(context(Pins))]
#[garde(allow_unvalidated)]
#[schemars(rename = "DefenderIsolationTarget", description = "")]
#[from_node(model = "DefenderIsolationTarget")]
#[cfg_attr(
    feature = "python",
    pyo3::pyclass(frozen, get_all, eq, module = "opentide._native.models")
)]
#[cfg_attr(
    feature = "python",
    expect(
        clippy::unsafe_derive_deserialize,
        reason = "the `unsafe` is PyO3's FFI glue, which relies on no invariant of the fields"
    )
)]
pub struct DefenderIsolationTarget {
    /// Column holding the device id (`deviceIdColumn`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub device_id: Option<String>,
    /// `full` or `selective` (`isolationType`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[schemars(schema_with = "optional_literal::<DefenderIsolationType>")]
    pub isolation_type: Option<DefenderIsolationType>,
}

/// A target of `allow_files` and `block_files` (`DefenderFileTarget`).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema, Validate, FromNode)]
#[serde(deny_unknown_fields)]
#[garde(context(Pins))]
#[garde(allow_unvalidated)]
#[schemars(rename = "DefenderFileTarget", description = "")]
#[from_node(model = "DefenderFileTarget")]
#[cfg_attr(
    feature = "python",
    pyo3::pyclass(frozen, get_all, eq, module = "opentide._native.models")
)]
#[cfg_attr(
    feature = "python",
    expect(
        clippy::unsafe_derive_deserialize,
        reason = "the `unsafe` is PyO3's FFI glue, which relies on no invariant of the fields"
    )
)]
pub struct DefenderFileTarget {
    /// Column holding the file's SHA-1 (`sha1Column`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sha1: Option<String>,
    /// Column holding the file's SHA-256 (`sha256Column`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sha256: Option<String>,
    /// Device group names the action applies to (`deviceGroupNames`). Omitted: every device group.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub device_groups: Option<Vec<String>>,
}

/// How often the rule runs and how far back each run reads
/// (`DefenderSchedule`).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema, Validate, FromNode)]
#[serde(deny_unknown_fields)]
#[garde(context(Pins))]
#[garde(allow_unvalidated)]
#[schemars(rename = "DefenderSchedule", description = "")]
#[from_node(model = "DefenderSchedule")]
#[cfg_attr(
    feature = "python",
    pyo3::pyclass(frozen, get_all, eq, module = "opentide._native.models")
)]
#[cfg_attr(
    feature = "python",
    expect(
        clippy::unsafe_derive_deserialize,
        reason = "the `unsafe` is PyO3's FFI glue, which relies on no invariant of the fields"
    )
)]
pub struct DefenderSchedule {
    /// `NRT`, `<n>H`, or `<n>D`, `n` a positive integer without a leading zero.
    #[schemars(extend("examples" = ["1H", "NRT", "1D"]))]
    pub frequency: String,
    /// **Beta-only.** `<n>H` or `<n>D`. Omitted, Defender derives the lookback from the frequency.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub lookback: Option<String>,
}

/// The alert template (`DefenderAlert`). Every field has a deploy-time
/// default.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema, Validate, FromNode)]
#[serde(deny_unknown_fields)]
#[garde(context(Pins))]
#[garde(allow_unvalidated)]
#[schemars(rename = "DefenderAlert", description = "")]
#[from_node(model = "DefenderAlert")]
#[cfg_attr(
    feature = "python",
    pyo3::pyclass(frozen, get_all, eq, module = "opentide._native.models")
)]
#[cfg_attr(
    feature = "python",
    expect(
        clippy::unsafe_derive_deserialize,
        reason = "the `unsafe` is PyO3's FFI glue, which relies on no invariant of the fields"
    )
)]
pub struct DefenderAlert {
    /// Alert title. No Graph constraint.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub title: Option<String>,
    /// Alert description. No Graph constraint.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    /// `Informational`, `Low`, `Medium`, `High`, or `Critical`, sent lower-cased; `Critical` is
    /// sent as `high`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub severity: Option<String>,
    /// Recommended actions text. Not sent when unset. No Graph constraint.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub recommendation: Option<String>,
    /// MITRE ATT&CK technique or sub-technique ids (`T1528`, `T1059.001`). An empty list counts
    /// as unset. Left out, the techniques of the rule's objective are used. Sent grouped by
    /// tactic (ATT&CK).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub techniques: Option<Vec<String>>,
    /// Alert custom details: detail name to result column. Not sent when unset.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub custom_details: Option<IndexMap<String, String>>,
    /// **Beta-only.** `alert_per_event` (sent as `alertPerEvent`) or `single_alert`
    /// (`singleAlert`). `single_alert` groups the events of one run into one alert; it does not
    /// merge alerts across runs. Omitted, Defender creates one alert per event.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[schemars(schema_with = "optional_literal::<DefenderGrouping>")]
    pub grouping: Option<DefenderGrouping>,
}

/// Result columns mapped to the alert's entities (`DefenderEntities`).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema, Validate, FromNode)]
#[serde(deny_unknown_fields)]
#[garde(context(Pins))]
#[garde(allow_unvalidated)]
#[schemars(rename = "DefenderEntities", description = "")]
#[from_node(model = "DefenderEntities")]
#[cfg_attr(
    feature = "python",
    pyo3::pyclass(frozen, get_all, eq, module = "opentide._native.models")
)]
#[cfg_attr(
    feature = "python",
    expect(
        clippy::unsafe_derive_deserialize,
        reason = "the `unsafe` is PyO3's FFI glue, which relies on no invariant of the fields"
    )
)]
pub struct DefenderEntities {
    /// Devices (`hosts`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub hosts: Option<Vec<DefenderHostMapping>>,
    /// User accounts (`accounts`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub accounts: Option<Vec<DefenderAccountMapping>>,
    /// Mailboxes (`mailboxes`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mailboxes: Option<Vec<DefenderMailboxMapping>>,
    /// Files (`files`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub files: Option<Vec<DefenderFileMapping>>,
    /// Processes (`processes`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub processes: Option<Vec<DefenderProcessMapping>>,
    /// IP addresses (`ips`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ips: Option<Vec<DefenderIpMapping>>,
    /// URLs (`urls`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub urls: Option<Vec<DefenderUrlMapping>>,
    /// DNS resolutions (`dns`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub dns: Option<Vec<DefenderDnsMapping>>,
    /// Registry values (`registryValues`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub registry_values: Option<Vec<DefenderRegistryValueMapping>>,
    /// Mail messages (`mailMessages`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mail_messages: Option<Vec<DefenderMailMessageMapping>>,
    /// Mail clusters (`mailClusters`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mail_clusters: Option<Vec<DefenderMailClusterMapping>>,
    /// Cloud applications (`cloudApplications`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cloud_applications: Option<Vec<DefenderCloudApplicationMapping>>,
    /// OAuth applications (`oAuthApplications`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub oauth_applications: Option<Vec<DefenderOAuthApplicationMapping>>,
    /// Security groups (`securityGroups`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub security_groups: Option<Vec<DefenderSecurityGroupMapping>>,
    /// Azure resources (`azureResources`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub azure_resources: Option<Vec<DefenderAzureResourceMapping>>,
    /// Amazon resources (`amazonResources`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub amazon_resources: Option<Vec<DefenderAmazonResourceMapping>>,
    /// Google Cloud resources (`googleCloudResources`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub google_cloud_resources: Option<Vec<DefenderGoogleCloudResourceMapping>>,
}

/// Automated actions run on the entities a detection finds
/// (`DefenderActions`).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema, Validate, FromNode)]
#[serde(deny_unknown_fields)]
#[garde(context(Pins))]
#[garde(allow_unvalidated)]
#[schemars(rename = "DefenderActions", description = "")]
#[from_node(model = "DefenderActions")]
#[cfg_attr(
    feature = "python",
    pyo3::pyclass(frozen, get_all, eq, module = "opentide._native.models")
)]
#[cfg_attr(
    feature = "python",
    expect(
        clippy::unsafe_derive_deserialize,
        reason = "the `unsafe` is PyO3's FFI glue, which relies on no invariant of the fields"
    )
)]
pub struct DefenderActions {
    /// Isolate the devices (`isolateDevices`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub isolate_devices: Option<Vec<DefenderIsolationTarget>>,
    /// Collect an investigation package (`collectInvestigationPackages`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub collect_investigation_packages: Option<Vec<DefenderDeviceTarget>>,
    /// Run an antivirus scan (`runAntivirusScans`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub run_antivirus_scans: Option<Vec<DefenderDeviceTarget>>,
    /// Start an automated investigation (`initiateInvestigations`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub initiate_investigations: Option<Vec<DefenderDeviceTarget>>,
    /// Restrict app execution (`restrictAppExecutions`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub restrict_app_executions: Option<Vec<DefenderDeviceTarget>>,
    /// Allow the files (`allowFiles`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub allow_files: Option<Vec<DefenderFileTarget>>,
    /// Block the files (`blockFiles`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub block_files: Option<Vec<DefenderFileTarget>>,
    /// Stop and quarantine the files (`stopAndQuarantineFiles`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub stop_and_quarantine_files: Option<Vec<DefenderQuarantineTarget>>,
    /// Disable the users (`disableUsers`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub disable_users: Option<Vec<DefenderAccountSidTarget>>,
    /// Force a password reset (`forceUserPasswordResets`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub force_user_password_resets: Option<Vec<DefenderAccountSidTarget>>,
    /// Mark the users as compromised (`markUsersAsCompromised`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mark_users_as_compromised: Option<Vec<DefenderAccountObjectTarget>>,
    /// Soft-delete the emails (`softDeleteEmails`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub soft_delete_emails: Option<Vec<DefenderEmailTarget>>,
    /// Hard-delete the emails (`hardDeleteEmails`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub hard_delete_emails: Option<Vec<DefenderEmailTarget>>,
    /// Move the emails to Deleted Items (`moveEmailsToDeletedItems`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub move_emails_to_deleted_items: Option<Vec<DefenderEmailTarget>>,
    /// Move the emails to the inbox (`moveEmailsToInbox`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub move_emails_to_inbox: Option<Vec<DefenderEmailTarget>>,
    /// Move the emails to Junk (`moveEmailsToJunk`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub move_emails_to_junk: Option<Vec<DefenderEmailTarget>>,
}

/// Device groups the rule applies to (`DefenderScope`).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema, Validate, FromNode)]
#[serde(deny_unknown_fields)]
#[garde(context(Pins))]
#[garde(allow_unvalidated)]
#[schemars(rename = "DefenderScope", description = "")]
#[from_node(model = "DefenderScope")]
#[cfg_attr(
    feature = "python",
    pyo3::pyclass(frozen, get_all, eq, module = "opentide._native.models")
)]
#[cfg_attr(
    feature = "python",
    expect(
        clippy::unsafe_derive_deserialize,
        reason = "the `unsafe` is PyO3's FFI glue, which relies on no invariant of the fields"
    )
)]
pub struct DefenderScope {
    /// Device group names.
    pub device_groups: Vec<String>,
}

/// Incident correlation (`DefenderIncident`). **Beta-only.**
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema, Validate, FromNode)]
#[serde(deny_unknown_fields)]
#[garde(context(Pins))]
#[garde(allow_unvalidated)]
#[schemars(rename = "DefenderIncident", description = "")]
#[from_node(model = "DefenderIncident")]
#[cfg_attr(
    feature = "python",
    pyo3::pyclass(frozen, get_all, eq, module = "opentide._native.models")
)]
#[cfg_attr(
    feature = "python",
    expect(
        clippy::unsafe_derive_deserialize,
        reason = "the `unsafe` is PyO3's FFI glue, which relies on no invariant of the fields"
    )
)]
pub struct DefenderIncident {
    /// `true`: each alert opens its own single-alert incident. `false`: alerts may be correlated
    /// with related alerts (Defender's default).
    pub exclude_from_correlation: bool,
}

/// A per-tenant KQL fragment (`DefenderExclusion`).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema, Validate, FromNode)]
#[serde(deny_unknown_fields)]
#[garde(context(Pins))]
#[garde(allow_unvalidated)]
#[schemars(rename = "DefenderExclusion", description = "")]
#[from_node(model = "DefenderExclusion")]
#[cfg_attr(
    feature = "python",
    pyo3::pyclass(frozen, get_all, eq, module = "opentide._native.models")
)]
#[cfg_attr(
    feature = "python",
    expect(
        clippy::unsafe_derive_deserialize,
        reason = "the `unsafe` is PyO3's FFI glue, which relies on no invariant of the fields"
    )
)]
pub struct DefenderExclusion {
    /// KQL fragment appended after the base query. The key is required. An empty string is
    /// accepted.
    #[schemars(extend("tide.template.multiline" = true))]
    pub query: String,
    /// Why the exclusion exists. Not sent to Defender.
    pub reason: String,
    /// Limit the exclusion to one tenant name.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tenant: Option<String>,
    /// KQL `let` bindings. String, number, or boolean.
    #[serde(rename = "let", default, skip_serializing_if = "Option::is_none")]
    pub r#let: Option<IndexMap<String, Any>>,
}

/// The before-validator: a block with a `status` is judged as authored, and
/// each finding is one error at its own path, typed by its code. With any
/// finding, the block's fields are not converted.
fn raw_block(node: &Node, cx: &mut Context) -> bool {
    if !matches!(node.value, Value::Map(_))
        || node
            .get("status")
            .is_none_or(|status| matches!(status.value, Value::Null))
        || !crate::objects::platform::within_budget(node)
    {
        return true;
    }
    let findings = block_findings(node);
    for finding in &findings {
        report_at(cx, &finding.path, finding, node);
    }
    findings.is_empty()
}

fn report_at(
    cx: &mut Context,
    path: &[crate::error::PathSegment],
    finding: &Finding,
    input: &Node,
) {
    match path.split_first() {
        None => cx.error(ErrorKind::Constraint(finding.code), &finding.message, input),
        Some((head, rest)) => cx.at(head.clone(), |cx| report_at(cx, rest, finding, input)),
    }
}

/// garde: the block's constraints, on a block built in memory.
fn garde_block(block: &MicrosoftDefenderConfig, _pins: &Pins) -> garde::Result {
    let value = serde_json::to_value(block).map_err(|error| {
        garde::Error::new(format!(
            "MicrosoftDefenderConfig does not serialise: {error}"
        ))
    })?;
    match block_findings(&super::json_node(&value)).first() {
        None => Ok(()),
        Some(first) => Err(garde::Error::new(format!(
            "{}: {}",
            first.code, first.message
        ))),
    }
}

platform_block! {
    /// Microsoft Defender custom detection rule, on the Microsoft Graph beta custom detection API
    /// (`MicrosoftDefenderConfig`).
    #[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema, Validate, FromNode)]
    #[serde(deny_unknown_fields)]
    #[garde(context(Pins))]
    #[garde(allow_unvalidated)]
    #[garde(custom(garde_block))]
    #[schemars(rename = "MicrosoftDefenderConfig", description = "")]
    #[from_node(model = "MicrosoftDefenderConfig", before = "raw_block")]
    #[cfg_attr(feature = "python", pyo3::pyclass(frozen, get_all, eq, name = "MicrosoftDefenderConfig", module = "opentide._native.models"))]
    #[cfg_attr(feature = "python", expect(clippy::unsafe_derive_deserialize, reason = "the `unsafe` is PyO3's FFI glue, which relies on no invariant of the fields"))]
    pub struct MicrosoftDefenderConfig ["platform::microsoft_defender::1.0"] {
        /// KQL. Multiline. Compiled with matching `exclusions` before deploy.
        #[schemars(extend("tide.template.multiline" = true, "tide.template.spacer" = true))]
        #[from_node(with = "crate::objects::platform::query_text")]
        #[garde(custom(crate::objects::platform::garde_query_text))]
        pub query: String,
        /// How often the rule runs, and how far back each run reads.
        pub schedule: DefenderSchedule,
        /// The alert template. Every field has a deploy-time default.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub alert: Option<DefenderAlert>,
        /// Result columns mapped to the alert's entities.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub entities: Option<DefenderEntities>,
        /// Automated actions run on the entities a detection finds.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub actions: Option<DefenderActions>,
        /// Device groups the rule applies to. Omitted: every device.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub scope: Option<DefenderScope>,
        /// **Beta-only.** Incident correlation.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub incident: Option<DefenderIncident>,
        /// Per-tenant KQL fragments appended to `query`.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub exclusions: Option<Vec<DefenderExclusion>>,
    }
}

/// The block's advisories (microsoft-defender-1.0, Advisories):
/// `microsoft_defender_no_entities` on a block that maps no entity, and
/// `microsoft_defender_impacted_asset_identifier` on each impacted-asset
/// mapping that sets none of its asset's identifiers. A block whose
/// `entities` breaks a constraint earns no `no_entities`, and a mapping that
/// is not a mapping of its kind's fields no asset advisory: the constraint's
/// finding says more.
pub fn advisories(rule: &Node) -> Vec<super::Advisory> {
    let Some(block) = rule
        .get("configurations")
        .and_then(|configurations| configurations.get(PLATFORM))
        .filter(|block| matches!(block.value, Value::Map(_)))
    else {
        return Vec::new();
    };
    let mut found = no_entities(block);
    found.extend(impacted_assets(block));
    found
}

/// `microsoft_defender_impacted_asset_identifier`, on `entities.<kind>.<N>`
/// of each `hosts` or `accounts` mapping that names only its kind's fields
/// and sets no identifier of the asset ([`AssetIdentifier`]): neither a
/// column the custom detection wizard maps to the asset nor a strong
/// combination of Sentinel's entity reference.
fn impacted_assets(block: &Node) -> Vec<super::Advisory> {
    let mut found = Vec::new();
    let Some(Value::Map(kinds)) = block.get("entities").map(|entities| &entities.value) else {
        return found;
    };
    for entry in kinds {
        let (Some(name), Value::Seq(mappings)) = (entry.key.value.as_str(), &entry.value.value)
        else {
            continue;
        };
        let (Some(kind), Some(rules)) = (entity_kind(name), entity_identifiers(name)) else {
            continue;
        };
        if rules.asset.is_empty() {
            continue;
        }
        for (index, mapping) in mappings.iter().enumerate() {
            let Value::Map(fields) = &mapping.value else {
                continue;
            };
            let keys: Vec<Option<&str>> = fields
                .iter()
                .map(|field| field.key.value.as_str())
                .collect();
            let shaped = !keys.is_empty()
                && keys
                    .iter()
                    .all(|key| key.is_some_and(|key| kind.graph_field(key).is_some()));
            let identified = rules.asset.iter().any(|identifier| {
                identifier
                    .fields
                    .iter()
                    .all(|field| keys.contains(&Some(*field)))
            });
            if !shaped || identified {
                continue;
            }
            let noun = asset_noun(name);
            let identifiers = rules
                .asset
                .iter()
                .map(|identifier| {
                    let fields = identifier.fields.join(" + ");
                    if identifier.columns.is_empty() {
                        fields
                    } else {
                        format!("{fields} ({})", identifier.columns)
                    }
                })
                .collect::<Vec<_>>()
                .join(", ");
            found.push(super::Advisory {
                code: IMPACTED_ASSET_IDENTIFIER,
                field_path: vec![
                    "configurations".to_owned(),
                    PLATFORM.to_owned(),
                    "entities".to_owned(),
                    name.to_owned(),
                    index.to_string(),
                ],
                message: format!(
                    "entities.{name}[{index}] sets no strong identifier of an impacted {noun}: \
                     map one of {identifiers}, so Defender can tell which {noun} the alert is \
                     about"
                ),
            });
        }
    }
    found
}

/// The impacted asset an entity kind maps, as Defender's wizard names it.
fn asset_noun(kind: &str) -> &'static str {
    match kind {
        "hosts" => "device",
        "accounts" => "user",
        _ => "asset",
    }
}

/// `microsoft_defender_no_entities`, when the block maps no entity.
fn no_entities(block: &Node) -> Vec<super::Advisory> {
    let entities = block.get("entities");
    let maps_one = match entities.map(|entities| &entities.value) {
        None | Some(Value::Null) => false,
        Some(Value::Map(kinds)) => kinds.iter().any(|kind| match &kind.value.value {
            Value::Seq(mappings) => !mappings.is_empty(),
            Value::Null => false,
            // Not a list: `microsoft_defender_entity_mapping` reports it.
            _ => true,
        }),
        // Not a mapping: `microsoft_defender_entity_kind` reports it.
        Some(_) => true,
    };
    if maps_one {
        return Vec::new();
    }
    let path = if entities.is_some() {
        vec!["configurations", PLATFORM, "entities"]
    } else {
        vec!["configurations", PLATFORM]
    };
    vec![super::Advisory {
        code: NO_ENTITIES,
        field_path: path.into_iter().map(str::to_owned).collect(),
        message: "the block maps no entity: the alert names no device, user or mailbox, so it \
                  cannot be triaged or acted on by entity"
            .to_owned(),
    }]
}

/// The bundled rule template's `microsoft_defender` block: every key of the
/// block, in the order of the specification's complete example, with its
/// column names. The required keys are set, every optional key is present but
/// commented out, and the keys only the Graph beta API has are marked.
pub const TEMPLATE: &str = include_str!("microsoft_defender/template.yaml");

/// [`TEMPLATE`] as the workspace template writes it: like every generated
/// platform template, a key without a value, and an empty list item, end in
/// a space where the value goes (the source file keeps no trailing space).
#[must_use]
pub fn template() -> String {
    let lines: Vec<&str> = TEMPLATE.lines().collect();
    let indent = |line: &str| line.len() - line.trim_start().len();
    let mut out = String::with_capacity(TEMPLATE.len() + 64);
    for (at, line) in lines.iter().enumerate() {
        out.push_str(line);
        let leaf = line.ends_with(':')
            && lines
                .get(at + 1)
                .is_none_or(|next| next.trim().is_empty() || indent(next) <= indent(line));
        if leaf || line.trim() == "#-" {
            out.push(' ');
        }
        out.push('\n');
    }
    out
}
