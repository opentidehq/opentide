//! One compile entry point per platform (#1952): the function both the dry
//! run ([`crate::preview`]) and the deploy (`opentide deploy`'s
//! `deploy_send`) call to compile a rule for a tenant, so what a dry run
//! shows is what a deploy sends.
//!
//! A platform's [`Compiler`] reads the rule and what its body depends on
//! besides the rule ([`Compiler::Target`]: the tenant, as far as the
//! platform reads it) and returns the compiled rule ([`Compiler::Compiled`]:
//! the body and what a caller reads beside it, such as warnings). A caller
//! never assembles a platform's compile from its parts: it calls
//! [`Compiler::compile`] and takes the body a deploy sends from
//! [`Compiler::body`].
//!
//! The platforms move here one by one; the issue's checklist lists the rest.

use opentide_schema::platforms::PlatformId;

use crate::json::Json;
use crate::rule::{CompileError, Rule};
use crate::strategy::StatusStrategy;
use crate::{Context, datadog, deploy, exabeam, google_secops, graylog, sentinel};

/// The compile of one platform's rules, shared by the dry run and the deploy.
pub trait Compiler {
    /// The platform this compiles for.
    const PLATFORM: PlatformId;

    /// What the body depends on besides the rule: the tenant, as far as the
    /// platform reads it.
    type Target<'t>;

    /// The compiled rule: the body and what a caller reads beside it.
    type Compiled;

    /// Compiles `rule` for `target`.
    ///
    /// # Errors
    ///
    /// A [`CompileError`] when the platform cannot take the rule; a dry run
    /// shows it as the rule's failure and a deploy fails the rule with it.
    fn compile(
        cx: &Context<'_>,
        rule: &Rule,
        target: Self::Target<'_>,
    ) -> Result<Self::Compiled, CompileError>;

    /// The body a deploy sends to create the rule, which the dry run shows.
    fn body(compiled: &Self::Compiled) -> Json;
}

/// Microsoft Sentinel: the `alertRules` body for one tenant, whose name
/// selects the exclusions scoped to it, with the warnings it earned.
#[derive(Debug, Clone, Copy)]
pub struct Sentinel;

impl Compiler for Sentinel {
    const PLATFORM: PlatformId = PlatformId::Sentinel;

    /// The tenant's name.
    type Target<'t> = &'t str;

    type Compiled = sentinel::Compiled;

    fn compile(
        cx: &Context<'_>,
        rule: &Rule,
        tenant: &str,
    ) -> Result<sentinel::Compiled, CompileError> {
        sentinel::compile_with_warnings(cx, rule, tenant)
    }

    fn body(compiled: &sentinel::Compiled) -> Json {
        compiled.0.clone()
    }
}

/// What a Graylog definition depends on besides the rule.
#[derive(Debug, Clone, Copy)]
pub struct GraylogTarget<'t> {
    /// The server's version: what it reads the definition as (a dry run asks
    /// no server, and compiles for [`graylog::PREVIEW_VERSION`]).
    pub version: graylog::Version,
    /// The tenant's table: its name, and the `setup` whose `stream_ids` and
    /// `notification_ids` resolve the block's aliases. `None` in a dry run
    /// that reaches no tenant: the aliases are left out and listed in
    /// [`graylog::CompiledDefinition::unresolved`].
    pub tenant: Option<&'t Json>,
}

/// Graylog: the event definition for one server version and tenant.
#[derive(Debug, Clone, Copy)]
pub struct Graylog;

impl Compiler for Graylog {
    const PLATFORM: PlatformId = PlatformId::Graylog;

    type Target<'t> = GraylogTarget<'t>;

    type Compiled = graylog::CompiledDefinition;

    fn compile(
        cx: &Context<'_>,
        rule: &Rule,
        target: GraylogTarget<'_>,
    ) -> Result<graylog::CompiledDefinition, CompileError> {
        let setup = target.tenant.and_then(graylog::tenant_setup);
        let name = target.tenant.map(deploy::tenant_name);
        graylog::compile_definition(cx, rule, target.version, setup, name)
    }

    fn body(compiled: &graylog::CompiledDefinition) -> Json {
        graylog::create_body(compiled)
    }
}

/// Exabeam: the correlation rule for one tenant, whose `test_mode` the body
/// reads, under its block's status.
#[derive(Debug, Clone, Copy)]
pub struct Exabeam;

impl Compiler for Exabeam {
    const PLATFORM: PlatformId = PlatformId::Exabeam;

    /// The tenant's table. `None` in a dry run that reaches no tenant:
    /// `testMode` is then the block's, else `false`.
    type Target<'t> = Option<&'t Json>;

    type Compiled = exabeam::ExabeamRule;

    fn compile(
        cx: &Context<'_>,
        rule: &Rule,
        tenant: Option<&Json>,
    ) -> Result<exabeam::ExabeamRule, CompileError> {
        exabeam::compile_deployment(cx, rule, tenant)
    }

    fn body(compiled: &exabeam::ExabeamRule) -> Json {
        compiled.body.clone()
    }
}

/// Datadog: the detection rule for one tenant, whose `notifications` resolve
/// the cases' aliases and whose tags it carries, under its block's status.
#[derive(Debug, Clone, Copy)]
pub struct Datadog;

impl Compiler for Datadog {
    const PLATFORM: PlatformId = PlatformId::Datadog;

    /// The tenant's table. `None` in a dry run that reaches no tenant: an
    /// alias is shown as `<tenant:notifications.ALIAS>` and the tenant's tags
    /// are left out.
    type Target<'t> = Option<&'t Json>;

    type Compiled = datadog::DatadogRule;

    /// A rule to disable is compiled without the tenant (RFC
    /// rfc-datadog-cloud-siem §8.2): a deploy sends `isEnabled: false`
    /// alone, so an alias the tenant lacks cannot keep the rule enabled.
    fn compile(
        cx: &Context<'_>,
        rule: &Rule,
        tenant: Option<&Json>,
    ) -> Result<datadog::DatadogRule, CompileError> {
        let strategy = datadog::strategy(cx, rule)?;
        let tenant = tenant.filter(|_| strategy != StatusStrategy::Disablement);
        datadog::compile_rule(cx, rule, strategy, tenant)
    }

    fn body(compiled: &datadog::DatadogRule) -> Json {
        compiled.body.clone()
    }
}

/// Google SecOps: what a deploy of the rule reads, the same on every tenant:
/// the `rules.create` text, and beside it the rule's name, the sections the
/// text was assembled from, the run state its status deploys and the
/// block's run frequency ([`google_secops::compile_deployment`]). The
/// tenant's scope is added as the rule is sent.
#[derive(Debug, Clone, Copy)]
pub struct GoogleSecops;

impl Compiler for GoogleSecops {
    const PLATFORM: PlatformId = PlatformId::GoogleSecops;

    /// Nothing: the text is the same on every tenant.
    type Target<'t> = ();

    type Compiled = Json;

    fn compile(cx: &Context<'_>, rule: &Rule, (): ()) -> Result<Json, CompileError> {
        google_secops::compile_deployment(cx, rule)
    }

    fn body(compiled: &Json) -> Json {
        compiled.clone()
    }
}
