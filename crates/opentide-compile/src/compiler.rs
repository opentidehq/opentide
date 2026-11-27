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
use crate::{Context, deploy, graylog, sentinel};

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
