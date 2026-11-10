//! Carbon Black Cloud watchlist report, `platform::carbon_black_cloud::1.0`
//! (`CarbonBlackConfig`).

use garde::Validate;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::FromNode;
use crate::objects::platform::platform_block;
use crate::pins::Pins;

platform_block! {
    /// Carbon Black Cloud watchlist report (`CarbonBlackConfig`).
    #[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema, Validate, FromNode)]
    #[serde(deny_unknown_fields)]
    #[garde(context(Pins))]
    #[garde(allow_unvalidated)]
    #[schemars(rename = "CarbonBlackConfig", description = "")]
    #[from_node(model = "CarbonBlackConfig")]
    pub struct CarbonBlackConfig ["platform::carbon_black_cloud::1.0"] {
        /// Lucene query. Multiline in YAML. Deploy joins lines with spaces.
        #[schemars(extend("tide.template.multiline" = true, "tide.template.spacer" = true))]
        #[from_node(with = "crate::objects::platform::query_text")]
        #[garde(custom(crate::objects::platform::garde_query_text))]
        pub query: String,
        /// Accepted. The current deployer targets the tenant
        /// the run selects and does not filter on this list.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub organizations: Option<Vec<String>>,
        /// Watchlist name. Deploy uses the tenant watchlist when omitted. The watchlist must already
        /// exist.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub watchlist: Option<String>,
        /// Report title. Deploy uses the Tide rule `name` when omitted.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub report: Option<String>,
        /// Extra report tags, appended after the tags opentide always writes.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub tags: Option<Vec<String>>,
    }
}
