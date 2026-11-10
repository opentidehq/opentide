//! Field types of the configuration models that carry a constraint or a
//! `mode="before"` validator, each reporting Pydantic's error type and
//! message (`pydantic-core` wording, which the CLI prints as is).

use std::borrow::Cow;
use std::sync::OnceLock;

use regex::Regex;
use schemars::{JsonSchema, Schema, SchemaGenerator, json_schema};
use serde::Serialize;

use crate::error::ErrorKind;
use crate::from_node::{Context, FromNode};
use crate::node::{Node, Value};

/// `string_type`, then `string_too_short` for an empty string.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(transparent)]
pub struct NonEmptyString(pub String);

impl FromNode for NonEmptyString {
    fn from_node(node: &Node, cx: &mut Context) -> Option<Self> {
        let text = String::from_node(node, cx)?;
        if text.is_empty() {
            cx.error(
                ErrorKind::InvalidValue("string_too_short"),
                "String should have at least 1 character",
                node,
            );
            return None;
        }
        Some(Self(text))
    }
}

impl JsonSchema for NonEmptyString {
    fn schema_name() -> Cow<'static, str> {
        "NonEmptyString".into()
    }

    fn inline_schema() -> bool {
        true
    }

    fn json_schema(_: &mut SchemaGenerator) -> Schema {
        json_schema!({"type": "string", "minLength": 1})
    }
}

/// A list with at least one item: `too_short` when empty.
#[derive(Debug, Clone, PartialEq, Serialize)]
#[serde(transparent)]
pub struct NonEmptyList<T>(pub Vec<T>);

impl<T: FromNode> FromNode for NonEmptyList<T> {
    fn from_node(node: &Node, cx: &mut Context) -> Option<Self> {
        let items = Vec::<T>::from_node(node, cx)?;
        if items.is_empty() {
            cx.error(
                ErrorKind::InvalidValue("too_short"),
                "List should have at least 1 item after validation, not 0",
                node,
            );
            return None;
        }
        Some(Self(items))
    }
}

impl<T: JsonSchema> JsonSchema for NonEmptyList<T> {
    fn schema_name() -> Cow<'static, str> {
        format!("NonEmptyList_{}", T::schema_name()).into()
    }

    fn inline_schema() -> bool {
        true
    }

    fn json_schema(generator: &mut SchemaGenerator) -> Schema {
        let items = generator.subschema_for::<T>();
        json_schema!({"type": "array", "items": items, "minItems": 1})
    }
}

/// A number greater than 0 (`gt=0`): `float_type`, then `greater_than`.
#[derive(Debug, Clone, Copy, PartialEq, Serialize)]
#[serde(transparent)]
pub struct PositiveFloat(pub f64);

impl FromNode for PositiveFloat {
    fn from_node(node: &Node, cx: &mut Context) -> Option<Self> {
        let number = f64::from_node(node, cx)?;
        if number > 0.0 {
            return Some(Self(number));
        }
        cx.error(
            ErrorKind::InvalidValue("greater_than"),
            "Input should be greater than 0",
            node,
        );
        None
    }
}

impl JsonSchema for PositiveFloat {
    fn schema_name() -> Cow<'static, str> {
        "PositiveFloat".into()
    }

    fn inline_schema() -> bool {
        true
    }

    fn json_schema(_: &mut SchemaGenerator) -> Schema {
        json_schema!({"type": "number", "exclusiveMinimum": 0})
    }
}

/// A string that must match a pattern (`Field(pattern=...)`, searched from
/// the start as `pydantic-core` does with the `regex` crate).
pub trait Pattern {
    /// The pattern, as the message prints it.
    const PATTERN: &'static str;
    /// The compiled pattern.
    fn regex() -> &'static Regex;
    /// The minimum length, when the field also has `min_length=1`.
    const NON_EMPTY: bool = false;
}

/// A string checked against `P`: `string_type`, `string_too_short` (when
/// `P::NON_EMPTY`), then `string_pattern_mismatch`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(transparent)]
pub struct Matching<P> {
    /// The text.
    pub text: String,
    #[serde(skip)]
    marker: std::marker::PhantomData<P>,
}

impl<P> Matching<P> {
    /// The text.
    pub fn as_str(&self) -> &str {
        &self.text
    }
}

impl<P: Pattern> FromNode for Matching<P> {
    fn from_node(node: &Node, cx: &mut Context) -> Option<Self> {
        let text = String::from_node(node, cx)?;
        if P::NON_EMPTY && text.is_empty() {
            cx.error(
                ErrorKind::InvalidValue("string_too_short"),
                "String should have at least 1 character",
                node,
            );
            return None;
        }
        if !P::regex().is_match(&text) {
            cx.error_with(
                ErrorKind::InvalidValue("string_pattern_mismatch"),
                format!("String should match pattern '{}'", P::PATTERN),
                node,
                &[("pattern", P::PATTERN.to_owned())],
            );
            return None;
        }
        Some(Self {
            text,
            marker: std::marker::PhantomData,
        })
    }
}

impl<P: Pattern> JsonSchema for Matching<P> {
    fn schema_name() -> Cow<'static, str> {
        format!("Matching_{}", P::PATTERN).into()
    }

    fn inline_schema() -> bool {
        true
    }

    fn json_schema(_: &mut SchemaGenerator) -> Schema {
        let mut schema = json_schema!({"type": "string", "pattern": P::PATTERN});
        if P::NON_EMPTY {
            schema.insert("minLength".to_owned(), 1.into());
        }
        schema
    }
}

/// `pattern`, compiled once into `cell`.
#[expect(
    clippy::expect_used,
    reason = "pattern literals, each compiled by a test"
)]
pub(crate) fn compiled(cell: &'static OnceLock<Regex>, pattern: &str) -> &'static Regex {
    cell.get_or_init(|| Regex::new(pattern).expect("a valid pattern"))
}

macro_rules! pattern {
    ($(#[$meta:meta])* $name:ident, $pattern:expr $(, non_empty = $non_empty:expr)?) => {
        $(#[$meta])*
        #[derive(Debug, Clone, PartialEq, Eq)]
        pub struct $name;

        impl Pattern for $name {
            const PATTERN: &'static str = $pattern;
            $(const NON_EMPTY: bool = $non_empty;)?
            fn regex() -> &'static Regex {
                static REGEX: OnceLock<Regex> = OnceLock::new();
                compiled(&REGEX, $pattern)
            }
        }
    };
}

pattern!(
    /// `$NAME`: an environment variable placeholder (`EnvPlaceholder`).
    EnvPattern,
    r"^\$"
);
pattern!(
    /// A boolean written as a word, in any case (`SslValue`'s third member).
    SslWordPattern,
    r"^\s*([tT][rR][uU][eE]|[yY][eE][sS]|[oO][nN]|1|[fF][aA][lL][sS][eE]|[nN][oO]|[oO][fF][fF]|0)\s*$"
);
pattern!(
    /// An Elastic stack version: `MAJOR.MINOR` or `serverless`.
    ElasticVersionPattern,
    r"^(?:[0-9]+\.[0-9]+|serverless)$"
);
pattern!(
    /// A `[[misp]]` block name.
    MispNamePattern,
    r"^[a-z0-9_-]{1,64}$"
);
pattern!(
    /// An http(s) URL with a host, not empty.
    HttpUrlPattern,
    r"^[Hh][Tt][Tt][Pp][Ss]?://[^/?#\s]+",
    non_empty = true
);
pattern!(
    /// The `8-4-4-4-12` hex form of a UUID.
    OrganisationUuidPattern,
    r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$"
);

/// `$NAME`, resolved when the tenant loads (never here).
pub type EnvPlaceholder = Matching<EnvPattern>;

/// What `opentide deploy` does with a rule in a status (`StatusStrategy`),
/// in the order the oracle declares the members.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize)]
pub enum StatusStrategy {
    /// Does not interact with deployment.
    #[serde(rename = "INERT")]
    Inert,
    /// Deployment from the default branch.
    #[serde(rename = "RELEASE")]
    Release,
    /// Deployment from pull or merge requests.
    #[serde(rename = "PREVIEW")]
    Preview,
    /// Deployment from the default branch, only to disable a rule.
    #[serde(rename = "DISABLEMENT")]
    Disablement,
    /// Deployment from the default branch, removing the rule.
    #[serde(rename = "DELETION")]
    Deletion,
    /// Deployment from both pull or merge requests and the default branch.
    #[serde(rename = "UNIVERSAL")]
    Universal,
}

impl StatusStrategy {
    /// Every member, in declaration order.
    pub const ALL: [Self; 6] = [
        Self::Inert,
        Self::Release,
        Self::Preview,
        Self::Disablement,
        Self::Deletion,
        Self::Universal,
    ];

    /// The member's name (`PREVIEW`).
    pub const fn name(self) -> &'static str {
        match self {
            Self::Inert => "INERT",
            Self::Release => "RELEASE",
            Self::Preview => "PREVIEW",
            Self::Disablement => "DISABLEMENT",
            Self::Deletion => "DELETION",
            Self::Universal => "UNIVERSAL",
        }
    }

    /// What the member does (the oracle's member value), which the editor
    /// schemas show beside a status.
    pub const fn description(self) -> &'static str {
        match self {
            Self::Inert => "Does not interact with deployment",
            Self::Release => {
                "Deployment from the default branch (also called trunk, or main branch)"
            }
            Self::Preview => "Deployment from Pull/Merge Requests",
            Self::Disablement => {
                "Deployment from the default branch, but only to disable an existing rule. If \
                 the target system does not have a concept of disabling rules, then defaults to \
                 deleting them."
            }
            Self::Deletion => {
                "Deployment from the default branch, but removes the rule from the target system."
            }
            Self::Universal => {
                "Deployment from both Pull/Merge Requests, and default branch pipelines."
            }
        }
    }

    /// The member named exactly `name`.
    pub fn from_name(name: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|member| member.name() == name)
    }
}

/// A value that is not a string is not a member (`is_instance_of`).
fn not_a_strategy(node: &Node, cx: &mut Context) {
    cx.error_with(
        ErrorKind::InvalidType("is_instance_of"),
        "Input should be an instance of StatusStrategy",
        node,
        &[("class", "StatusStrategy".to_owned())],
    );
}

/// A `[[statuses]]` strategy, written by its exact name (`StatusStrategyName`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(transparent)]
pub struct StatusStrategyName(pub StatusStrategy);

impl FromNode for StatusStrategyName {
    fn from_node(node: &Node, cx: &mut Context) -> Option<Self> {
        let Value::Str(text) = &node.value else {
            not_a_strategy(node, cx);
            return None;
        };
        if let Some(member) = StatusStrategy::from_name(text) {
            return Some(Self(member));
        }
        let allowed: Vec<&str> = StatusStrategy::ALL.iter().map(|m| m.name()).collect();
        cx.error(
            ErrorKind::InvalidValue("value_error"),
            format!(
                "Value error, strategy must be one of {}",
                allowed.join(", ")
            ),
            node,
        );
        None
    }
}

impl JsonSchema for StatusStrategyName {
    fn schema_name() -> Cow<'static, str> {
        "StatusStrategy".into()
    }

    fn json_schema(_: &mut SchemaGenerator) -> Schema {
        let names: Vec<&str> = StatusStrategy::ALL.iter().map(|m| m.name()).collect();
        json_schema!({"type": "string", "enum": names})
    }
}

/// A tenant strategy: `PREVIEW` or `RELEASE`, in any case, spaces around
/// ignored (`RunStrategyName`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(transparent)]
pub struct RunStrategyName(pub StatusStrategy);

impl FromNode for RunStrategyName {
    fn from_node(node: &Node, cx: &mut Context) -> Option<Self> {
        let Value::Str(text) = &node.value else {
            not_a_strategy(node, cx);
            return None;
        };
        match StatusStrategy::from_name(&text.trim().to_uppercase()) {
            Some(member @ (StatusStrategy::Preview | StatusStrategy::Release)) => {
                Some(Self(member))
            }
            _ => {
                cx.error(
                    ErrorKind::InvalidValue("value_error"),
                    "Value error, a tenant strategy must be PREVIEW or RELEASE",
                    node,
                );
                None
            }
        }
    }
}

impl JsonSchema for RunStrategyName {
    fn schema_name() -> Cow<'static, str> {
        "RunStrategy".into()
    }

    fn inline_schema() -> bool {
        true
    }

    /// Any string: the strategy is read in any case, spaces around ignored,
    /// which no `enum` says.
    fn json_schema(_: &mut SchemaGenerator) -> Schema {
        json_schema!({"type": "string"})
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::configuration::toml::parse;

    fn errors<T: FromNode>(text: &str) -> Vec<(String, &'static str)> {
        let doc = parse(&format!("v = {text}\n")).unwrap();
        let mut cx = Context::new();
        let _ = T::from_node(doc.get("v").unwrap(), &mut cx);
        cx.into_errors()
            .into_iter()
            .map(|e| (e.message, e.kind.pydantic_type().unwrap()))
            .collect()
    }

    #[test]
    fn each_constraint_reports_pydantics_type_and_message() {
        assert_eq!(
            errors::<NonEmptyString>("\"\""),
            [(
                "String should have at least 1 character".to_owned(),
                "string_too_short"
            )]
        );
        assert_eq!(errors::<NonEmptyList<String>>("[]")[0].1, "too_short");
        assert_eq!(errors::<PositiveFloat>("0")[0].1, "greater_than");
        assert!(errors::<PositiveFloat>("1").is_empty());
        assert_eq!(
            errors::<EnvPlaceholder>("\"x\""),
            [(
                "String should match pattern '^\\$'".to_owned(),
                "string_pattern_mismatch"
            )]
        );
        assert!(errors::<EnvPlaceholder>("\"$X\"").is_empty());
        assert_eq!(
            errors::<Matching<HttpUrlPattern>>("\"\"")[0].1,
            "string_too_short"
        );
        assert!(errors::<Matching<SslWordPattern>>("\" YES \"").is_empty());
    }

    #[test]
    fn strategies_are_read_by_name() {
        assert!(errors::<StatusStrategyName>("\"PREVIEW\"").is_empty());
        assert_eq!(
            errors::<StatusStrategyName>("\"preview\"")[0].0,
            "Value error, strategy must be one of INERT, RELEASE, PREVIEW, DISABLEMENT, \
             DELETION, UNIVERSAL"
        );
        assert_eq!(
            errors::<StatusStrategyName>("5")[0],
            (
                "Input should be an instance of StatusStrategy".to_owned(),
                "is_instance_of"
            )
        );
        assert!(errors::<RunStrategyName>("\" release \"").is_empty());
        assert_eq!(
            errors::<RunStrategyName>("\"DELETION\"")[0].0,
            "Value error, a tenant strategy must be PREVIEW or RELEASE"
        );
    }
}
