//! The platform plugin host (`plugins` feature, UC-4.5, #835): the surface a
//! host embeds opentide to add platforms it does not build in.
//!
//! A platform plugin implements the connectors' traits ([`Deployer`],
//! [`LiveValidator`], [`QueryRunner`], [`ConfigurationCheck`], tied together by
//! [`Platform`]) and the host hands the command line a [`PluginHost`] through
//! [`set_host`] before a run, so `query`, `validate query --live` and `deploy`
//! reach the plugin's platforms, and `validate` runs their configuration checks
//! ([`configurations`]). The Python package is such a host: it bridges the
//! platforms registered in the `opentide.platforms` entry-point group
//! ([`ENTRY_POINT_GROUP`]).
//!
//! This is the plugin-authoring surface, not the tenant operations a workspace
//! configures; for those, see [`connectors`](crate::connectors). It brings the
//! connectors and the command line, so it is behind its own feature.

pub use crate::connectors::Json;
pub use opentide_cli::plugins::{configurations, set_host};
pub use opentide_connectors::connector::{
    BoxFuture, ConfigurationCheck, ConfigurationFinding, DeployOutcome, DeployRequest, Deployer,
    LiveCheck, LiveValidator, Operation, Platform, QueryColumn, QueryOutcome, QueryRequest,
    QueryRunner, Row, TenantContext, TimeWindow, columns_of,
};
pub use opentide_connectors::credentials::Credential;
pub use opentide_connectors::plugin::{ENTRY_POINT_GROUP, PluginError, PluginHost};
pub use opentide_connectors::{ConnectorError, Tenant};
