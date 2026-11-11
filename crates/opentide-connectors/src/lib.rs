//! opentide's tenant connectors (plan D-8, ADR 0008; UC-4.1, #831).
//!
//! One framework for every request opentide sends to a tenant or to the
//! network: the HTTP client ([`http::HttpClient`], reqwest on rustls), built
//! per tenant from that tenant's own settings, never another tenant's
//! (#742): TLS on or off, the CA bundles it trusts, the proxy it goes
//! through, its timeout and its retries. Around it: credentials resolved from
//! the environment and never printed ([`credentials`]), the connector traits
//! the platforms implement and their registry ([`connector`]), the tokio
//! runtime with a bounded fan-out over tenants and cancellation
//! ([`runtime`]), progress events ([`progress`]) and the errors with the
//! failure codes they map to ([`error`]).
//!
//! The platforms built on it (UC-4.2, #832): [`crowdstrike`], [`harfanglab`]
//! and [`sysdig`], each a request-for-request port of its Python client,
//! deployer and query runner.
//!
//! The recorded-HTTP harness that proves a connector sends what the Python
//! client sends is `opentide-cassette`, a test crate.

pub mod answer;
pub mod body;
pub mod connector;
pub mod credentials;
pub mod crowdstrike;
pub mod defender;
pub mod elastic;
pub mod encode;
pub mod env;
pub mod error;
pub mod harfanglab;
pub mod http;
pub mod progress;
pub mod proxy;
pub mod retry;
pub mod runtime;
pub mod search;
pub mod sentinel_one;
pub mod sysdig;
pub mod tenant;
pub mod tls;

pub use connector::{Platform, Registry};
pub use credentials::{Credential, Secret};
pub use env::Environment;
pub use error::ConnectorError;
pub use http::{HttpClient, HttpSettings};
pub use tenant::{Tenant, TenantLabel};
