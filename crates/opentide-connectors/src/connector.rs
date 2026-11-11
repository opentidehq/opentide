//! The traits a platform implements, and the registry of platforms.
//!
//! A platform is a [`Platform`]: its identifier and the capabilities it has,
//! each a trait of its own, so a platform that cannot validate a query live
//! (CrowdStrike, HarfangLab, Sysdig) has no [`LiveValidator`] rather than
//! one that pretends. Every operation takes a [`TenantContext`] (the tenant,
//! its client, the run's cancellation) and returns a [`ConnectorError`] on
//! failure. The methods return boxed futures so a registry holds platforms
//! as trait objects; UC-4.2 to UC-4.4 implement them, and UC-4.5 adds the
//! Python plugin hook through [`Registry::register`].

use std::future::Future;
use std::pin::Pin;

use tokio_util::sync::CancellationToken;

use crate::error::ConnectorError;
use crate::{HttpClient, Tenant};

/// A future a connector returns.
pub type BoxFuture<'a, T> = Pin<Box<dyn Future<Output = T> + Send + 'a>>;

/// What every operation on one tenant receives.
#[derive(Clone, Copy, Debug)]
pub struct TenantContext<'a> {
    /// The tenant.
    pub tenant: &'a Tenant,
    /// Its client.
    pub http: &'a HttpClient,
    /// Fires when the run is cancelled.
    pub cancel: &'a CancellationToken,
}

/// What a deploy does to one rule on one tenant.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Operation {
    /// The rule is new there.
    Create,
    /// The rule is there and changes.
    Update,
    /// The rule is there and is turned off.
    Disable,
    /// The rule is removed.
    Delete,
}

/// One compiled rule to deploy (the body `opentide-compile` built).
#[derive(Clone, Debug, PartialEq)]
pub struct DeployRequest {
    /// The rule's identifier on the platform (its UUID or name).
    pub rule_id: String,
    /// What to do.
    pub operation: Operation,
    /// The request body.
    pub body: serde_json::Value,
}

/// What a deploy did.
#[derive(Clone, Debug, PartialEq)]
pub struct DeployOutcome {
    /// The platform's identifier of the rule, kept in deployment state.
    pub remote_id: Option<String>,
    /// What was done.
    pub operation: Operation,
}

/// One query to run or check.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct QueryRequest {
    /// The query text.
    pub text: String,
    /// Its language (`kql`, `esql`).
    pub language: String,
}

/// What a query returned.
#[derive(Clone, Debug, PartialEq, Default)]
pub struct QueryOutcome {
    /// The rows.
    pub rows: Vec<serde_json::Value>,
}

/// A live check's verdict.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Validation {
    /// Whether the tenant accepted the query.
    pub ok: bool,
    /// The tenant's message.
    pub message: Option<String>,
}

/// Deploys rules.
pub trait Deployer: Send + Sync {
    /// Applies *request* to the tenant.
    fn deploy<'a>(
        &'a self,
        cx: TenantContext<'a>,
        request: &'a DeployRequest,
    ) -> BoxFuture<'a, Result<DeployOutcome, ConnectorError>>;
}

/// Checks queries on the tenant (`validate query --live`).
pub trait LiveValidator: Send + Sync {
    /// Checks *request*.
    fn validate<'a>(
        &'a self,
        cx: TenantContext<'a>,
        request: &'a QueryRequest,
    ) -> BoxFuture<'a, Result<Validation, ConnectorError>>;
}

/// Runs queries (`opentide query`). Saves nothing on the tenant.
pub trait QueryRunner: Send + Sync {
    /// Runs *request*. A search the runner stops waiting for (cancellation)
    /// is stopped on the tenant where the API allows it (CrowdStrike).
    fn run<'a>(
        &'a self,
        cx: TenantContext<'a>,
        request: &'a QueryRequest,
    ) -> BoxFuture<'a, Result<QueryOutcome, ConnectorError>>;
}

/// Shares objects (MISP).
pub trait Sharer: Send + Sync {
    /// Shares *object*, returning the remote identifier.
    fn share<'a>(
        &'a self,
        cx: TenantContext<'a>,
        object: &'a serde_json::Value,
    ) -> BoxFuture<'a, Result<Option<String>, ConnectorError>>;
}

/// Moves deployment state between formats with what the tenant knows
/// (`deploy migrate-state`).
pub trait StateMigrator: Send + Sync {
    /// The tenant's identifier of each rule named in *rule_ids*, in order.
    fn lookup<'a>(
        &'a self,
        cx: TenantContext<'a>,
        rule_ids: &'a [String],
    ) -> BoxFuture<'a, Result<Vec<Option<String>>, ConnectorError>>;
}

/// A platform and what it can do.
pub trait Platform: Send + Sync {
    /// Its identifier (`sentinel`, `elastic`).
    fn id(&self) -> &'static str;
    /// Its deployer.
    fn deployer(&self) -> Option<&dyn Deployer> {
        None
    }
    /// Its live validator; `None` where the API cannot check a query
    /// (`supported: False`, never a faked validation).
    fn live_validator(&self) -> Option<&dyn LiveValidator> {
        None
    }
    /// Its query runner.
    fn query_runner(&self) -> Option<&dyn QueryRunner> {
        None
    }
    /// Its sharer.
    fn sharer(&self) -> Option<&dyn Sharer> {
        None
    }
    /// Its state migrator.
    fn state_migrator(&self) -> Option<&dyn StateMigrator> {
        None
    }
}

/// The platforms a run knows: the built-in ones, then any registered.
#[derive(Default)]
pub struct Registry {
    platforms: Vec<Box<dyn Platform>>,
}

impl std::fmt::Debug for Registry {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_list()
            .entries(self.platforms.iter().map(|platform| platform.id()))
            .finish()
    }
}

impl Registry {
    /// An empty registry.
    pub fn new() -> Self {
        Self::default()
    }

    /// Adds *platform*. A second platform with an identifier already
    /// registered is refused: a plugin cannot replace a built-in platform.
    pub fn register(&mut self, platform: Box<dyn Platform>) -> Result<(), String> {
        if self.get(platform.id()).is_some() {
            return Err(format!("platform {} is already registered", platform.id()));
        }
        self.platforms.push(platform);
        Ok(())
    }

    /// The platform *id*.
    pub fn get(&self, id: &str) -> Option<&dyn Platform> {
        self.platforms
            .iter()
            .find(|platform| platform.id() == id)
            .map(AsRef::as_ref)
    }

    /// Every platform's identifier, in registration order.
    pub fn ids(&self) -> Vec<&'static str> {
        self.platforms
            .iter()
            .map(|platform| platform.id())
            .collect()
    }
}
