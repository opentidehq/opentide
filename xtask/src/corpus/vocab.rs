//! The values the generator draws from: a fixed, curated subset of
//! opentide's vocabularies (`src/opentide/data/vocabulary/`) and catalogs.
//! Copied rather than read at run time, so a vocabulary change in the
//! working tree cannot change a seed's output; the clean workspace
//! validating with zero findings in the oracle proves every value valid.

/// The platforms, in the order the generator assigns them (the platform
/// table's connector order).
pub const PLATFORMS: &[&str] =
    &opentide_schema::platforms::ordered(opentide_schema::platforms::Order::Connector);

/// The platforms the generator writes blocks and configurations for: the
/// connector order minus the platforms the recorded oracle (0.23.0) lacks
/// (`opentide_schema::platforms::SINCE_ORACLE`). A platform's registry row
/// added on the catch-up train would otherwise reshuffle the whole seeded
/// corpus (generation is seeded on this list's length and order), staling the
/// recorded lint cases, payload plans and the digest; leaving the new platform
/// out keeps the generated corpus the 0.23.0 one. The per-platform generator
/// arms stay in code, unused until O2 empties `SINCE_ORACLE`.
pub fn generated_platforms() -> Vec<&'static str> {
    PLATFORMS
        .iter()
        .copied()
        .filter(|id| !opentide_schema::platforms::after_oracle(id))
        .collect()
}

/// `tlp::1.0`.
pub const TLP: &[&str] = &["clear", "green", "amber", "amber+strict", "red"];
/// `criticality::1.0`.
pub const CRITICALITY: &[&str] = &[
    "Baseline - Negligible",
    "Baseline - Minor",
    "Low",
    "Medium",
    "High",
    "Severe",
    "Emergency",
];
/// `severity::1.0`.
pub const SEVERITY: &[&str] = &[
    "Localised incident",
    "Moderate incident",
    "Substantial incident",
    "Significant incident",
    "Highly significant incident",
];
/// `impact::1.0`.
pub const IMPACT: &[&str] = &[
    "Nuisance",
    "Data Breach",
    "IP Loss",
    "Reputational Damages",
    "Identity Theft",
    "Monetary Loss",
    "Lose Capabilities",
    "Business disruption",
    "Operating costs",
    "Legal and regulatory",
];
/// `leverage::1.0`.
pub const LEVERAGE: &[&str] = &[
    "Spoofing",
    "Tampering",
    "Repudiation",
    "Information Disclosure",
    "Dwelling",
    "Denial of Service",
    "Elevation of privilege",
    "New Accounts",
    "Log tampering",
    "Modify configuration",
    "Software installation",
    "Information Gathering",
];
/// `viability::1.0`.
pub const VIABILITY: &[&str] = &[
    "Environment dependent",
    "Unlikely",
    "Roughly even chance",
    "Likely",
    "Very Likely",
    "Almost certain",
];
/// `surface::1.0`, stage-scoped.
pub const SURFACE: &[&str] = &[
    "OS::Windows",
    "OS::Windows::Desktop",
    "OS::Windows::Server",
    "OS::Windows::Server::2022",
    "OS::macOS",
    "OS::Linux",
    "OS::Linux::Ubuntu",
    "OS::Linux::RHEL",
];
/// `killchain::1.0`.
pub const KILLCHAIN: &[&str] = &["Reconnaissance", "Weaponization", "Delivery"];
/// `chaining_relations::1.0`, stage-scoped as the chaining check reads it.
pub const CHAINING: &[&str] = &[
    "sequence::preceeds",
    "sequence::succeeds",
    "atomicity::implemented",
    "atomicity::implements",
    "support::enabled",
    "support::enabling",
    "support::synergize",
];
/// `alert_severity::1.0`.
pub const ALERT_SEVERITY: &[&str] = &["Informational", "Low", "Medium", "High", "Critical"];
/// `detection.methodology::1.0`.
pub const METHODOLOGY: &[&str] = &[
    "Artifacts",
    "Pattern Matching",
    "Event Search",
    "Statistical",
    "Behavioural",
    "Anomaly",
    "Heuristic",
];
/// `detection.composition::1.0`.
pub const COMPOSITION: &[&str] = &["Independent", "Combined", "Threshold", "Entity", "Sequence"];
/// `detection.types::1.0`.
pub const DETECTION_TYPES: &[&str] = &["Threat", "Compliance", "Utility", "Supportive"];
/// Objective priorities.
pub const PRIORITY: &[&str] = &["Low", "Medium", "High", "Critical"];
/// `signal.entities::1.0`, stage-scoped.
pub const ENTITIES: &[&str] = &[
    "Host::Hostname",
    "Host::Process",
    "Host::Command Line",
    "Host::File",
    "Host::Account",
    "Network::IP Address",
    "Network::URL",
    "Cloud::Account",
];
/// ATT&CK Enterprise techniques.
pub const TECHNIQUES: &[&str] = &[
    "T1059",
    "T1059.001",
    "T1059.003",
    "T1003",
    "T1003.001",
    "T1021",
    "T1021.001",
    "T1047",
    "T1053",
    "T1053.005",
    "T1055",
    "T1070",
    "T1078",
    "T1082",
    "T1083",
    "T1105",
    "T1110",
    "T1136",
    "T1190",
    "T1204",
    "T1218",
    "T1218.011",
    "T1543",
    "T1543.003",
    "T1547",
    "T1547.001",
    "T1548",
    "T1548.002",
    "T1566",
    "T1566.001",
    "T1569",
    "T1569.002",
    "T1486",
    "T1490",
];
/// ATT&CK groups, as `actors` values take them.
pub const GROUPS: &[&str] = &[
    "G1028", "G0099", "G0006", "G0005", "G0023", "G0025", "G0026", "G0073", "G0007", "G0016",
    "G0022", "G0013", "G0050", "G0064", "G0067", "G0082", "G0087", "G0096",
];
/// Process names the queries look for.
pub const PROCESSES: &[&str] = &[
    "cmd.exe",
    "powershell.exe",
    "rundll32.exe",
    "regsvr32.exe",
    "mshta.exe",
    "wmic.exe",
    "certutil.exe",
    "bitsadmin.exe",
    "schtasks.exe",
    "psexec.exe",
];
/// Linux shells, for Falco lists.
pub const SHELLS: &[&str] = &["bash", "sh", "zsh", "dash", "ksh"];
/// Words names are built from.
pub const ADJECTIVES: &[&str] = &[
    "Silent",
    "Rapid",
    "Hidden",
    "Remote",
    "Covert",
    "Lateral",
    "Staged",
    "Encoded",
    "Rogue",
    "Persistent",
    "Scheduled",
    "Elevated",
];
/// Words names are built from.
pub const NOUNS: &[&str] = &[
    "Loader",
    "Beacon",
    "Dropper",
    "Harvest",
    "Pivot",
    "Tunnel",
    "Implant",
    "Spray",
    "Relay",
    "Injection",
    "Exfiltration",
    "Downgrade",
];
/// Rule statuses (deployment.toml `[[statuses]]`), deployable ones first.
pub const STATUSES: &[&str] = &[
    "STAGING",
    "DEVELOPMENT",
    "IMPROVING",
    "ACCEPTANCE",
    "PRODUCTION",
];
/// Responding teams the generated deployment.toml declares.
pub const RESPONDERS: &[&str] = &["SOC Tier 1", "SOC Tier 2", "Incident Response"];
