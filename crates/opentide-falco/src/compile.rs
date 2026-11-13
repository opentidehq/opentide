//! What libsinsp's filter compiler (`filter.cpp`, `sinsp_filtercheck*.cpp`,
//! `filter_compare.cpp`, `value_parser.cpp`, the transformers) checks once a
//! condition parses, over [`crate::parser::Expr`]:
//!
//! - **field resolution**, class by class in libsinsp's order: a name is
//!   resolved by the first class that knows a prefix of it, and only when that
//!   prefix is the whole name; the argument rules of each field (`proc.aname[N]`
//!   takes an index, `proc.env[KEY]` a key, `evt.arg.NAME` an event argument,
//!   `evt.type.is.NAME` an event, plugin fields their `Index` / `Key` /
//!   `Required` flags);
//! - **operator and type**: `flt_is_comparable` over the transformed type and
//!   list-ness of the left side, including modifiers on IP fields;
//! - **values**: parsed as the field's type (`string_to_rawval`): integers for
//!   numeric fields, `true` / `false`, IPv4 and IPv6 addresses and networks,
//!   ports, hex strings for `bcontains` and `bstartswith`, regex patterns;
//!   `evt.type` values against the event table and syscall names;
//! - **transformers**: the types each accepts (`tolower` on strings, `len` on
//!   strings, buffers and lists, `b64` on strings and buffers), fields that
//!   refuse transformers, `join` / `concat` / `getopt` arity and argument types,
//!   field arguments on transformers;
//! - **right-hand side fields** (`val(...)`, a transformer): not with `pmatch`
//!   or `regex`, not on networks, not on `EPF_NO_RHS` fields, and the same type
//!   on both sides;
//! - libsinsp's **compile warnings**: a regex a plain operator could replace, a
//!   value that is a field name or a transformer call;
//! - Falco's rule-loader warnings: deprecated fields, `<NA>` checks on
//!   `ka.` / `jevt.` fields.
//!
//! A field the catalogue does not know is a warning, not an error: plugins and
//! the Sysdig agent add fields.

use crate::catalog::{ArgRule, Catalog, Field};
use crate::parser::{Expr, Parser, Span, TRANSFORMERS};
use opentide_core::codes;
use std::net::{Ipv4Addr, Ipv6Addr};

/// How bad a finding is.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Level {
    Error,
    Warning,
}

/// One finding, with the span of the condition it is about.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Finding {
    pub code: &'static str,
    pub level: Level,
    pub message: String,
    pub span: Span,
    pub suggestion: Option<String>,
}

/// A field resolved for a source: the catalogue row and the type it extracts.
#[derive(Debug, Clone)]
pub struct Resolved<'c> {
    pub field: &'c Field,
    pub ty: String,
    pub list: bool,
}

/// Why a field does not resolve.
#[derive(Debug, Clone)]
pub enum FieldError {
    /// No class knows the name: libsinsp's "nonexistent field".
    Unknown,
    /// A known field, with an argument it refuses or a missing one.
    Argument(String),
}

/// The value type a check extracts: a libsinsp type name and list-ness.
#[derive(Debug, Clone, PartialEq, Eq)]
struct Ty {
    name: String,
    list: bool,
}

impl Ty {
    fn new(name: &str, list: bool) -> Ty {
        Ty {
            name: name.to_string(),
            list,
        }
    }
}

/// A compiled extraction: what libsinsp's `get_field_info` (`original`) and
/// `get_transformed_field_info` (`ty`) would return, with the flags that
/// matter to comparisons.
#[derive(Debug, Clone)]
struct Check {
    /// What the argument check of a multivalue transformer reads (`get_field_info`).
    original: Ty,
    /// After transformers (`get_transformed_field_info`).
    ty: Ty,
    no_rhs: bool,
    no_transformer: bool,
    /// The field, when the check is one (not a literal or a multivalue transformer).
    field: Option<String>,
    /// A plain field name: `evt.type`, `evt.around`, for the event checks.
    plain: Option<String>,
}

const NUMERIC: &[&str] = &[
    "INT8",
    "INT16",
    "INT32",
    "INT64",
    "UINT8",
    "UINT16",
    "UINT32",
    "UINT64",
    "ERRNO",
    "FD",
    "PID",
    "SYSCALLID",
    "SIGTYPE",
    "RELTIME",
    "ABSTIME",
    "PORT",
    "FLAGS8",
    "FLAGS16",
    "FLAGS32",
    "DOUBLE",
    "MODE",
    "ENUMFLAGS8",
    "ENUMFLAGS16",
    "ENUMFLAGS32",
];
const IP_TYPES: &[&str] = &[
    "IPV4ADDR", "IPV4NET", "IPV6ADDR", "IPV6NET", "IPADDR", "IPNET",
];
const NET_TYPES: &[&str] = &["IPNET", "IPV4NET", "IPV6NET"];
const STRING_TYPES: &[&str] = &["CHARBUF", "FSPATH", "FSRELPATH"];
const LIST_TYPES: &[&str] = &[
    "CHARBUF", "UINT64", "RELTIME", "ABSTIME", "BOOL", "IPADDR", "IPNET",
];

/// `(op, modifier)` from a parsed operator (`= anyof`, `contains`).
fn split_op(op: &str) -> (&str, Option<&str>) {
    match op.split_once(' ') {
        Some((o, m)) => (o, Some(m)),
        None => (op, None),
    }
}

/// libsinsp's `flt_is_comparable`, with its messages.
pub fn comparable(op: &str, ty: &str, list: bool) -> Result<(), String> {
    let (base, modifier) = split_op(op);
    let base = if base == "==" { "=" } else { base };
    if base == "exists" {
        return Ok(());
    }
    let refuse = |what: &str| Err(format!("'{op}' operator not supported for {what}"));
    if list {
        if !LIST_TYPES.contains(&ty) {
            return Err(format!("list filters are not supported for type '{ty}'"));
        }
        return if matches!(base, "in" | "intersects") {
            Ok(())
        } else {
            Err(format!("'{op}' operator not supported list filters"))
        };
    }
    if NUMERIC.contains(&ty) {
        return if matches!(
            base,
            "=" | "!=" | "<" | "<=" | ">" | ">=" | "in" | "intersects"
        ) {
            Ok(())
        } else {
            refuse("numeric filters")
        };
    }
    if ty == "BOOL" {
        return if matches!(base, "=" | "!=" | "in" | "intersects") {
            Ok(())
        } else {
            refuse("numeric filters")
        };
    }
    if IP_TYPES.contains(&ty) {
        let ok = matches!(base, "=" | "!=" | "in" | "intersects");
        if modifier.is_some() && !ok {
            return Err(format!(
                "'{op}' with modifier not supported for ip address and network filters"
            ));
        }
        return if ok {
            Ok(())
        } else {
            refuse("ip address and network filters")
        };
    }
    if STRING_TYPES.contains(&ty) {
        return if matches!(
            base,
            "=" | "!="
                | "<"
                | "<="
                | ">"
                | ">="
                | "contains"
                | "in"
                | "icontains"
                | "startswith"
                | "glob"
                | "pmatch"
                | "endswith"
                | "intersects"
                | "iglob"
                | "regex"
        ) {
            Ok(())
        } else {
            refuse("string filters")
        };
    }
    if ty == "BYTEBUF" {
        return if matches!(
            base,
            "=" | "!="
                | "contains"
                | "in"
                | "startswith"
                | "endswith"
                | "intersects"
                | "bcontains"
                | "bstartswith"
        ) {
            Ok(())
        } else {
            refuse("buffer filters")
        };
    }
    Err(format!("'{op}' operator not supported for type '{ty}'"))
}

/// sscanf `"%d%c" == 1` (or `%u`): optional leading whitespace, a sign, digits,
/// nothing after.
fn scanf_int(s: &str) -> bool {
    let t = s.trim_start_matches([' ', '\t', '\n', '\r', '\u{b}', '\u{c}']);
    let digits = t.strip_prefix(['+', '-']).unwrap_or(t);
    !digits.is_empty() && digits.bytes().all(|b| b.is_ascii_digit())
}

/// Service names libsinsp resolves with `getservbyname` on most hosts.
const SERVICES: &[&str] = &[
    "ftp",
    "ssh",
    "telnet",
    "smtp",
    "domain",
    "http",
    "https",
    "pop3",
    "imap",
    "ldap",
    "ldaps",
    "ntp",
    "snmp",
    "mysql",
    "postgresql",
    "redis",
    "kerberos",
    "rsync",
    "nfs",
    "smb",
    "microsoft-ds",
    "netbios-ssn",
    "sunrpc",
    "bgp",
    "irc",
    "imaps",
    "pop3s",
    "submission",
];

/// What `string_to_rawval` refuses for *ty*, if anything. `Ok(Some(_))` is a
/// warning: a port name the host may not resolve.
fn parse_value(value: &str, ty: &str) -> Result<Option<String>, String> {
    if value.contains('\0') {
        return Err("filter error: filter value cannot contain a NUL byte (\\x00)".into());
    }
    let number = |ok: bool| {
        if ok {
            Ok(None)
        } else {
            Err(format!("{value} is not a valid number"))
        }
    };
    match ty {
        "INT8" | "INT16" | "INT32" | "INT64" | "FD" | "ERRNO" | "PID" | "DOUBLE" | "L4PROTO"
        | "FLAGS8" | "UINT8" | "ENUMFLAGS8" | "FLAGS16" | "UINT16" | "ENUMFLAGS16" | "FLAGS32"
        | "UINT32" | "MODE" | "ENUMFLAGS32" | "UID" | "GID" | "UINT64" | "RELTIME" | "ABSTIME" => {
            number(scanf_int(value))
        }
        "PORT" => {
            if value.is_empty()
                || value.bytes().all(|b| b.is_ascii_digit())
                || SERVICES.contains(&value)
            {
                Ok(None)
            } else {
                Ok(Some(format!(
                    "`{value}` is not a port number; the agent resolves it as a service name \
                     (getservbyname), and refuses the rule if its host does not know it"
                )))
            }
        }
        "CHARBUF" | "SOCKADDR" | "SOCKTUPLE" | "SOCKFAMILY" | "FSPATH" | "FSRELPATH"
        | "BYTEBUF" => Ok(None),
        "BOOL" => {
            if value == "true" || value == "false" {
                Ok(None)
            } else {
                Err(format!("filter error: unrecognized boolean value {value}"))
            }
        }
        "IPADDR" => parse_value(
            value,
            if value.contains('.') {
                "IPV4ADDR"
            } else {
                "IPV6ADDR"
            },
        ),
        "IPV4ADDR" => value
            .parse::<Ipv4Addr>()
            .map(|_| None)
            .map_err(|_| format!("unrecognized IPv4 address {value}")),
        "IPV6ADDR" => value
            .parse::<Ipv6Addr>()
            .map(|_| None)
            .map_err(|_| format!("unrecognized IPv6 address {value}")),
        "IPNET" => parse_value(
            value,
            if value.contains('.') {
                "IPV4NET"
            } else {
                "IPV6NET"
            },
        ),
        "IPV4NET" => {
            let Some((ip, mask)) = value.split_once('/') else {
                return Err(format!("unrecognized IP network {value}"));
            };
            if ip.parse::<Ipv4Addr>().is_err() {
                return Err(format!("unrecognized IP address {value}"));
            }
            if !scanf_int(mask) || mask.trim_start().starts_with('-') {
                return Err(format!("{mask} is not a valid number"));
            }
            match mask.trim().trim_start_matches('+').parse::<u64>() {
                Ok(m) if m <= 32 => Ok(None),
                _ => Err(format!("invalid netmask {mask}")),
            }
        }
        "IPV6NET" => {
            let Some((ip, mask)) = value.split_once('/') else {
                return Err(format!("unrecognized IPv6 network {value}"));
            };
            if ip.parse::<Ipv6Addr>().is_err() {
                return Err(format!("unrecognized IPv6 address {value}"));
            }
            match mask.parse::<u32>() {
                Ok(m) if m <= 128 => Ok(None),
                _ => Err(format!("invalid netmask {mask}")),
            }
        }
        other => Err(format!("wrong parameter type {other}")),
    }
}

/// `sinsp_utils::unhex`: an even number of hex digits.
fn is_hex(value: &str) -> bool {
    value.len().is_multiple_of(2) && value.bytes().all(|b| b.is_ascii_hexdigit())
}

/// The libsinsp check classes a source resolves names through, in order.
fn classes_for(catalog: &Catalog, source: &str) -> Vec<String> {
    let plugin_classes = || {
        let mut seen: Vec<String> = Vec::new();
        for f in &catalog.fields {
            if f.origin == "plugin" && f.applies_to(source) && !seen.contains(&f.class) {
                seen.push(f.class.clone());
            }
        }
        seen
    };
    if source == "syscall" {
        let mut out = catalog.classes.clone();
        out.extend(plugin_classes());
        out
    } else {
        let mut out = vec!["gen_event".to_string()];
        out.extend(plugin_classes());
        out
    }
}

/// What one class's `parse_field_name` returns for *full*: `-1` as `None`, a
/// length, or an exception.
enum ClassParse<'c> {
    NoMatch,
    Len(usize, &'c Field, Option<String>),
    Throw(String),
}

fn longest_prefix<'c>(fields: &[&'c Field], full: &str) -> Option<&'c Field> {
    fields
        .iter()
        .filter(|f| full.starts_with(f.name.as_str()))
        .max_by_key(|f| f.name.len())
        .copied()
}

fn field_named<'c>(fields: &[&'c Field], name: &str) -> Option<&'c Field> {
    fields.iter().find(|f| f.name == name).copied()
}

/// `find_longest_matching_evt_param`.
fn longest_param<'c>(catalog: &'c Catalog, rest: &str) -> Option<&'c crate::catalog::Param> {
    let mut best: Option<&crate::catalog::Param> = None;
    for p in &catalog.params {
        if rest.starts_with(p.name.as_str()) && best.is_none_or(|b| p.name.len() > b.name.len()) {
            best = Some(p);
        }
    }
    best
}

fn class_parse<'c>(
    catalog: &'c Catalog,
    fields: &[&'c Field],
    class: &str,
    full: &str,
) -> ClassParse<'c> {
    let generic = || match longest_prefix(fields, full) {
        Some(f) => ClassParse::Len(f.name.len(), f, None),
        None => ClassParse::NoMatch,
    };
    let starts = |s: &str| full.starts_with(s);
    let after = |name: &str| full.as_bytes().get(name.len()).copied();
    let named = |name: &str| field_named(fields, name);
    match class {
        "event" => {
            let event_arg = |name: &str, raw: bool| -> ClassParse<'c> {
                let Some(field) = named(name) else {
                    return ClassParse::NoMatch;
                };
                match after(name) {
                    Some(b'[') => {
                        if raw {
                            return ClassParse::Throw(
                                "evt.arg fields must be expressed explicitly".into(),
                            );
                        }
                        let end = full.find(']').unwrap_or(full.len());
                        let num = &full[name.len() + 1..end.max(name.len() + 1)];
                        if name == "evt.around" {
                            if !scanf_int(num) {
                                return ClassParse::Throw(format!("{num} is not a valid number"));
                            }
                        } else if !scanf_int(num) {
                            return ClassParse::Throw(format!("{num} is not a valid number"));
                        }
                        ClassParse::Len((end + 1).min(full.len() + 1), field, None)
                    }
                    Some(b'.') => {
                        if name == "evt.around" {
                            return ClassParse::Throw("wrong syntax for evt.around".into());
                        }
                        let rest = &full[name.len() + 1..];
                        match longest_param(catalog, rest) {
                            Some(p) => ClassParse::Len(
                                name.len() + p.name.len() + 1,
                                field,
                                raw.then(|| p.param_type.clone()),
                            ),
                            None => ClassParse::Throw(format!("unknown event argument {rest}")),
                        }
                    }
                    _ => ClassParse::Throw(format!("filter syntax error: {full}")),
                }
            };
            if starts("evt.arg") && !starts("evt.args") {
                return event_arg("evt.arg", false);
            }
            if starts("evt.rawarg") {
                return event_arg("evt.rawarg", true);
            }
            if starts("evt.around") {
                return event_arg("evt.around", false);
            }
            if starts("evt.abspath") {
                let Some(field) = named("evt.abspath") else {
                    return ClassParse::NoMatch;
                };
                let len = if starts("evt.abspath.src") || starts("evt.abspath.dst") {
                    15
                } else {
                    11
                };
                return ClassParse::Len(len, field, None);
            }
            if starts("evt.type.is") {
                let Some(field) = named("evt.type.is") else {
                    return ClassParse::NoMatch;
                };
                if after("evt.type.is") != Some(b'.') {
                    return ClassParse::Throw(format!("filter syntax error: {full}"));
                }
                let itype = &full[12..];
                let known = (!itype.is_empty() && itype.bytes().all(|b| b.is_ascii_digit()))
                    || catalog.event(itype).is_some();
                return ClassParse::Len(if known { full.len() } else { 0 }, field, None);
            }
            generic()
        }
        "thread" => {
            const INDEXED: &[&str] = &[
                "proc.apid",
                "proc.aname",
                "proc.aexepath",
                "proc.aexe",
                "proc.acmdline",
                "proc.aargs",
            ];
            let indexed_arg = |name: &str| -> ClassParse<'c> {
                let Some(field) = named(name) else {
                    return ClassParse::NoMatch;
                };
                if after(name) == Some(b'[')
                    && let Some(end) = full.find(']')
                    && scanf_int(&full[name.len() + 1..end])
                {
                    return ClassParse::Len(end + 1, field, None);
                }
                ClassParse::Len(name.len(), field, None)
            };
            if starts("arg") {
                return ClassParse::Throw(
                    "filter error: proc.arg filter not implemented yet".into(),
                );
            }
            for name in INDEXED {
                if starts(name) {
                    return indexed_arg(name);
                }
            }
            for name in ["proc.env", "proc.args", "proc.aenv"] {
                if starts(name) {
                    if name == "proc.args" {
                        return indexed_arg(name);
                    }
                    let Some(field) = named(name) else {
                        return ClassParse::NoMatch;
                    };
                    if after(name) == Some(b'[')
                        && let Some(end) = full[name.len()..].find(']')
                    {
                        return ClassParse::Len(name.len() + end + 1, field, None);
                    }
                    return ClassParse::Len(name.len(), field, None);
                }
            }
            if starts("thread.cgroup") && !starts("thread.cgroups") {
                let Some(field) = named("thread.cgroup") else {
                    return ClassParse::NoMatch;
                };
                if after("thread.cgroup") != Some(b'.') {
                    return ClassParse::Throw(format!("filter syntax error: {full}"));
                }
                let n = full[14..]
                    .bytes()
                    .take_while(|b| b.is_ascii_alphabetic() || *b == b'_')
                    .count();
                return ClassParse::Len(14 + n, field, None);
            }
            generic()
        }
        "fd" => {
            if starts("fd.types") {
                let Some(field) = named("fd.types") else {
                    return ClassParse::NoMatch;
                };
                if after("fd.types") == Some(b'[') {
                    let end = full.find(']').unwrap_or(full.len());
                    let num = &full[9..end.max(9)];
                    if !scanf_int(num) {
                        return ClassParse::Throw(format!("{num} is not a valid number"));
                    }
                    return ClassParse::Len(end + 1, field, None);
                }
                return ClassParse::Len(8, field, None);
            }
            generic()
        }
        _ if fields.first().is_some_and(|f| f.origin == "plugin") => plugin_parse(fields, full),
        _ => generic(),
    }
}

/// `sinsp_filter_check_plugin::parse_field_name`.
fn plugin_parse<'c>(fields: &[&'c Field], full: &str) -> ClassParse<'c> {
    let Some(field) = longest_prefix(fields, full) else {
        return ClassParse::NoMatch;
    };
    let res = field.name.len();
    let val = full.split(' ').next().unwrap_or(full).trim();
    let Some(arg_pos) = val.find('[') else {
        if field.arg == ArgRule::Required {
            return ClassParse::Throw(format!(
                "filter '{val}': {} requires an argument but none provided",
                field.name
            ));
        }
        return ClassParse::Len(res, field, None);
    };
    if res != arg_pos {
        return ClassParse::NoMatch;
    }
    let argstart = arg_pos + 1;
    if argstart >= val.len() {
        return ClassParse::Throw(format!(
            "filter '{val}': {} terminates with incomplete argument brackets",
            field.name
        ));
    }
    let Some(arg_len) = val[argstart..].find(']') else {
        return ClassParse::Throw(format!(
            "filter '{val}': {} has unbalanced argument brackets",
            field.name
        ));
    };
    let arg = &val[argstart..argstart + arg_len];
    if field.arg == ArgRule::None {
        return ClassParse::Throw(format!(
            "filter '{val}': {} does not allow nor require an argument but one is provided: {arg}",
            field.name
        ));
    }
    if field.arg_index && !field.arg_key {
        let message = if arg.is_empty() || (arg.len() > 1 && arg.starts_with('0')) {
            Some(" has an invalid index argument starting with 0: ")
        } else if !arg.bytes().all(|b| b.is_ascii_digit()) {
            Some(" has an invalid index argument not composed only by digits: ")
        } else if arg.parse::<u64>().is_err() {
            Some(" has an invalid index argument not representable on 64 bit: ")
        } else {
            None
        };
        if let Some(m) = message {
            return ClassParse::Throw(format!("filter {val} {}{m}{arg}", field.name));
        }
    }
    ClassParse::Len(arg_pos + arg_len + 2, field, None)
}

/// Resolve `name[arg]` for *source*, as `filter_check_list::new_filter_check_from_fldname`.
pub fn resolve<'c>(
    catalog: &'c Catalog,
    source: &str,
    name: &str,
    arg: Option<&str>,
) -> Result<Resolved<'c>, FieldError> {
    let full = match arg {
        Some(a) => format!("{name}[{a}]"),
        None => name.to_string(),
    };
    for class in classes_for(catalog, source) {
        let fields: Vec<&Field> = catalog
            .fields
            .iter()
            .filter(|f| f.class == class && f.applies_to(source))
            .collect();
        if fields.is_empty() {
            continue;
        }
        match class_parse(catalog, &fields, &class, &full) {
            ClassParse::NoMatch => {}
            ClassParse::Throw(message) => return Err(FieldError::Argument(message)),
            ClassParse::Len(len, field, ty) => {
                if len != full.len() {
                    // A prefix: the field itself is known when the parsed name is.
                    return Err(
                        if field.name == name
                            || full.starts_with(&format!("{}.", field.name)) && field.takes_arg()
                        {
                            FieldError::Argument(argument_message(field, arg, &full))
                        } else {
                            FieldError::Unknown
                        },
                    );
                }
                let ty = ty.unwrap_or_else(|| field.field_type.clone());
                return Ok(Resolved {
                    field,
                    ty,
                    list: field.list,
                });
            }
        }
    }
    Err(FieldError::Unknown)
}

fn argument_message(field: &Field, arg: Option<&str>, full: &str) -> String {
    match (field.arg, arg) {
        (ArgRule::None, Some(a)) => {
            format!("`{}` takes no argument, but `[{a}]` is given", field.name)
        }
        (_, Some(a)) if field.arg_index && !field.arg_key => {
            format!("`{}` takes a numeric index, not `{a}`", field.name)
        }
        _ => format!("`{full}` is not a valid use of `{}`", field.name),
    }
}

/// Everything the compiler needs around a condition.
pub struct Compiler<'c> {
    pub catalog: &'c Catalog,
    pub source: String,
    /// Report fields of the condition (false for a source the catalogue lacks).
    pub check_fields: bool,
    pub findings: Vec<Finding>,
}

impl<'c> Compiler<'c> {
    pub fn new(catalog: &'c Catalog, source: &str) -> Self {
        Compiler {
            catalog,
            source: source.to_string(),
            check_fields: catalog.source(source).is_some(),
            findings: Vec::new(),
        }
    }

    fn error(&mut self, code: &'static str, message: impl Into<String>, span: Span) {
        self.findings.push(Finding {
            code,
            level: Level::Error,
            message: message.into(),
            span,
            suggestion: None,
        });
    }

    fn warn(&mut self, code: &'static str, message: impl Into<String>, span: Span) {
        self.findings.push(Finding {
            code,
            level: Level::Warning,
            message: message.into(),
            span,
            suggestion: None,
        });
    }

    /// Compile a condition (or a macro's).
    pub fn condition(&mut self, expr: &Expr) {
        match expr {
            Expr::And(children, _) | Expr::Or(children, _) => {
                for c in children {
                    self.condition(c);
                }
            }
            Expr::Not(child, _) => self.condition(child),
            // A macro: resolved by Falco, checked where it is defined.
            Expr::Identifier(..) => {}
            Expr::Unary {
                left, op, op_span, ..
            } => {
                if let Some(check) = self.extract(left) {
                    self.compare(&check, op, *op_span);
                }
            }
            Expr::Binary {
                left,
                op,
                op_span,
                right,
                ..
            } => {
                let Some(check) = self.extract(left) else {
                    return;
                };
                if !self.compare(&check, op, *op_span) {
                    return;
                }
                self.right_side(&check, op, right);
            }
            _ => {}
        }
    }

    /// `check_op_type_compatibility`; false when the operator is refused.
    fn compare(&mut self, check: &Check, op: &str, span: Span) -> bool {
        match comparable(op, &check.ty.name, check.ty.list) {
            Ok(()) => true,
            Err(message) => {
                let what = check.field.as_deref().unwrap_or("the transformed value");
                self.error(
                    codes::FALCO_OPERATOR_TYPE,
                    format!("{message} (`{what}` is {})", describe(&check.ty)),
                    span,
                );
                false
            }
        }
    }

    fn right_side(&mut self, check: &Check, op: &str, right: &Expr) {
        if let Expr::Transformer { .. } | Expr::Field { .. } = right {
            let Some(rhs) = self.extract(right) else {
                return;
            };
            let span = right.span();
            let (base, _) = split_op(op);
            if matches!(base, "pmatch" | "regex") {
                self.error(
                    codes::FALCO_RHS_FIELD,
                    format!("operator '{base}' doesn't support right-hand side fields"),
                    span,
                );
            } else if NET_TYPES.contains(&check.ty.name.as_str()) {
                self.error(
                    codes::FALCO_RHS_FIELD,
                    "field type 'IPNET' doesn't support right-hand side fields",
                    span,
                );
            } else if check.no_rhs {
                self.error(
                    codes::FALCO_RHS_FIELD,
                    format!(
                        "field '{}' doesn't support right-hand side fields",
                        check.field.as_deref().unwrap_or("NA")
                    ),
                    span,
                );
            } else if rhs.no_rhs {
                self.error(
                    codes::FALCO_RHS_FIELD,
                    format!(
                        "field '{}' can't be used as a right-hand side field",
                        rhs.field.as_deref().unwrap_or("NA")
                    ),
                    span,
                );
            } else if check.ty != rhs.ty {
                self.error(
                    codes::FALCO_RHS_FIELD,
                    format!(
                        "field '{}' has type '{}' while the right-hand side field '{}' has incompatible type '{}'",
                        check.field.as_deref().unwrap_or("NA"),
                        describe(&check.ty),
                        rhs.field.as_deref().unwrap_or("NA"),
                        describe(&rhs.ty)
                    ),
                    span,
                );
            }
            return;
        }
        let values: Vec<(String, Span)> = match right {
            Expr::Value(v, s) => vec![(v.clone(), *s)],
            Expr::List(values, _) => values.clone(),
            _ => Vec::new(),
        };
        let (base, _) = split_op(op);
        for (value, span) in values {
            self.value_warnings(base, &value, span);
            if matches!(base, "bcontains" | "bstartswith") {
                if !is_hex(&value) {
                    self.error(
                        codes::FALCO_VALUE_TYPE,
                        "filter error: bcontains and bstartswith operator support hex strings only",
                        span,
                    );
                }
                continue;
            }
            match parse_value(&value, &check.ty.name) {
                Ok(None) => {}
                Ok(Some(warning)) => self.warn(codes::FALCO_VALUE_TYPE, warning, span),
                Err(message) => {
                    self.error(
                        codes::FALCO_VALUE_TYPE,
                        format!(
                            "{message}: `{}` is {}",
                            check.field.as_deref().unwrap_or("the value"),
                            describe(&check.ty)
                        ),
                        span,
                    );
                    continue;
                }
            }
            if base == "regex"
                && let Err(e) = regex::Regex::new(&value)
            {
                let first = e
                    .to_string()
                    .lines()
                    .last()
                    .unwrap_or("")
                    .trim()
                    .to_string();
                self.error(
                    codes::FALCO_INVALID_REGEX,
                    format!("invalid regex pattern: {first}"),
                    span,
                );
            }
            match check.plain.as_deref() {
                Some("evt.type") => self.event_value(&value, span),
                Some("evt.around") if base != "=" => {
                    self.error(
                        codes::FALCO_OPERATOR_TYPE,
                        "evt.around supports only '=' comparison operator",
                        span,
                    );
                }
                _ => {}
            }
        }
    }

    fn event_value(&mut self, value: &str, span: Span) {
        if self.source != "syscall" {
            return;
        }
        if self.catalog.event(value).is_some() || self.catalog.syscalls.contains(value) {
            return;
        }
        let mut f = Finding {
            code: codes::FALCO_UNKNOWN_EVENT,
            level: Level::Error,
            message: format!("unknown event type {value}"),
            span,
            suggestion: None,
        };
        let names = self
            .catalog
            .events()
            .chain(self.catalog.syscalls.iter().map(String::as_str));
        f.suggestion = crate::near_miss(value, names);
        self.findings.push(f);
    }

    /// libsinsp's compile warnings on a constant value.
    fn value_warnings(&mut self, base: &str, value: &str, span: Span) {
        let nospaces: String = value.chars().filter(|c| !c.is_whitespace()).collect();
        if base == "regex"
            && let Some(message) = regex_simplifiable(value)
        {
            self.warn(codes::FALCO_REGEX_SIMPLE, message, span);
        }
        // A field name (resolved exactly), used as a string by mistake.
        let (fname, farg) = match nospaces.split_once('[') {
            Some((n, rest)) if rest.ends_with(']') => (n, Some(&rest[..rest.len() - 1])),
            _ => (nospaces.as_str(), None),
        };
        if fname.contains('.') && resolve(self.catalog, &self.source, fname, farg).is_ok() {
            self.warn(
                codes::FALCO_FIELD_AS_VALUE,
                format!("'{value}' may be a valid field misused as a const string value: compare with val({nospaces})"),
                span,
            );
        }
        for t in std::iter::once("val").chain(TRANSFORMERS.iter().copied()) {
            if nospaces.len() >= t.len() + 2
                && nospaces.starts_with(t)
                && nospaces.as_bytes()[t.len()] == b'('
                && nospaces.ends_with(')')
            {
                self.warn(
                    codes::FALCO_TRANSFORMER_AS_VALUE,
                    format!(
                        "'{value}' may be a valid field transformer misused as a const string value"
                    ),
                    span,
                );
            }
        }
    }

    /// Compile an extraction: a field, a transformer, a literal, a list.
    fn extract(&mut self, expr: &Expr) -> Option<Check> {
        match expr {
            Expr::Field {
                name,
                arg,
                name_span,
                span,
            } => self.field(name, arg.as_deref(), *name_span, *span),
            Expr::Value(..) => Some(literal(false)),
            Expr::List(..) => Some(literal(true)),
            Expr::TransformerList(children, _) => {
                for c in children {
                    self.extract(c)?;
                }
                Some(literal(true))
            }
            Expr::Transformer {
                name,
                values,
                arg,
                span,
            } => self.transformer(name, values, arg.as_deref(), *span),
            _ => None,
        }
    }

    /// An output token (`%field`, `%tolower(field)`): compiles as libsinsp's
    /// formatter compiles it, where a filter-only field is refused. True when
    /// it compiles (warnings aside).
    pub fn output_token(&mut self, expr: &Expr) -> bool {
        if let Expr::Field {
            name,
            arg,
            name_span,
            ..
        } = expr
            && let Ok(r) = resolve(self.catalog, &self.source, name, arg.as_deref())
            && r.field.filter_only
        {
            self.error(
                codes::FALCO_OUTPUT_SYNTAX,
                format!("{name} is filter only and cannot be used as a display field"),
                *name_span,
            );
            return false;
        }
        let check = self.extract(expr);
        check.is_some() && !self.findings.iter().any(|f| f.level == Level::Error)
    }

    fn field(
        &mut self,
        name: &str,
        arg: Option<&str>,
        name_span: Span,
        span: Span,
    ) -> Option<Check> {
        if !self.check_fields {
            return None;
        }
        match resolve(self.catalog, &self.source, name, arg) {
            Ok(r) => {
                if r.field.deprecated {
                    self.warn(
                        codes::FALCO_DEPRECATED_FIELD,
                        deprecated_message(&r.field.name),
                        name_span,
                    );
                }
                let full = match arg {
                    Some(a) => format!("{name}[{a}]"),
                    None => name.to_string(),
                };
                Some(Check {
                    original: Ty::new(&r.ty, r.list),
                    ty: Ty::new(&r.ty, r.list),
                    no_rhs: r.field.no_rhs,
                    no_transformer: r.field.no_transformer,
                    field: Some(full),
                    plain: (arg.is_none()).then(|| r.field.name.clone()),
                })
            }
            Err(FieldError::Argument(message)) => {
                self.error(codes::FALCO_FIELD_ARGUMENT, message, span);
                None
            }
            Err(FieldError::Unknown) => {
                let f = crate::unknown_field_finding(name, &self.source, name_span);
                self.findings.push(f);
                None
            }
        }
    }

    fn transformer(
        &mut self,
        name: &str,
        values: &[Expr],
        arg: Option<&str>,
        span: Span,
    ) -> Option<Check> {
        let mut args = Vec::new();
        for v in values {
            args.push(self.extract(v)?);
        }
        if name == "val" {
            if arg.is_some() {
                self.error(
                    codes::FALCO_TRANSFORMER,
                    "filter error: transformer 'val' does not support field arguments",
                    span,
                );
                return None;
            }
            return args.pop();
        }
        if args.len() == 1 {
            if arg.is_some() {
                self.error(
                    codes::FALCO_TRANSFORMER,
                    format!("filter error: transformer '{name}' does not support field arguments"),
                    span,
                );
                return None;
            }
            let mut check = args.pop()?;
            if !matches!(name, "toupper" | "tolower" | "b64" | "basename" | "len") {
                self.error(
                    codes::FALCO_TRANSFORMER,
                    format!(
                        "unknown field transfomer '{name}': `{name}()` takes more than one argument"
                    ),
                    span,
                );
                return None;
            }
            if check.no_transformer {
                self.error(
                    codes::FALCO_TRANSFORMER,
                    format!(
                        "field '{}' does not support transformers",
                        check.field.as_deref().unwrap_or("NA")
                    ),
                    span,
                );
                return None;
            }
            let t = check.ty.name.as_str();
            let new = match name {
                "tolower" | "toupper" | "basename" if STRING_TYPES.contains(&t) => {
                    Some(check.ty.clone())
                }
                "b64" if matches!(t, "CHARBUF" | "BYTEBUF") => Some(check.ty.clone()),
                "len" if check.ty.list => Some(Ty::new("UINT64", false)),
                "len" if matches!(t, "CHARBUF" | "BYTEBUF" | "FSPATH" | "FSRELPATH") => {
                    Some(Ty::new("UINT64", false))
                }
                _ => None,
            };
            let Some(ty) = new else {
                self.error(
                    codes::FALCO_TRANSFORMER,
                    format!(
                        "can't add field transformer: type '{}' is not supported by '{name}' transformer applied on {}field '{}'",
                        check.ty.name,
                        if check.ty.list { "list " } else { "" },
                        check.field.as_deref().unwrap_or("NA")
                    ),
                    span,
                );
                return None;
            };
            check.ty = ty;
            check.plain = None;
            return Some(check);
        }
        // Multivalue transformers read their arguments' untransformed types.
        let types: Vec<&Ty> = args.iter().map(|a| &a.original).collect();
        let problem = match name {
            "join" => {
                if types.len() != 2 {
                    Some("join() requires exactly 2 arguments: separator and list")
                } else if types[0].list {
                    Some("join() first argument (separator) must be a single value, not a list")
                } else if !types[1].list {
                    Some("join() second argument must be a list")
                } else if arg.is_some() {
                    Some("transformer 'join' does not support field arguments")
                } else {
                    None
                }
            }
            "concat" => {
                if types.len() < 2 {
                    Some("concat() requires at least 2 arguments")
                } else if types.iter().any(|t| t.name != "CHARBUF" || t.list) {
                    Some("concat() arguments must be strings")
                } else if arg.is_some() {
                    Some("transformer 'concat' does not support field arguments")
                } else {
                    None
                }
            }
            "getopt" => {
                if types.len() != 2 {
                    Some("getopt() requires exactly 2 arguments: args list and optstring")
                } else if !types[0].list {
                    Some("getopt() first argument must be a list")
                } else if types[1].list {
                    Some("getopt() second argument (optstring) must be a single value")
                } else if types[0].name != "CHARBUF" || types[1].name != "CHARBUF" {
                    Some("getopt() arguments must be strings")
                } else if arg.is_some_and(|a| a.len() != 1) {
                    Some("getopt() field argument must be a single option character")
                } else {
                    None
                }
            }
            _ => Some("unknown multivalue transformer"),
        };
        if let Some(message) = problem {
            self.error(codes::FALCO_TRANSFORMER, message, span);
            return None;
        }
        let list = name == "getopt" && arg.is_none();
        Some(Check {
            original: Ty::new("CHARBUF", false),
            ty: Ty::new("CHARBUF", list),
            no_rhs: false,
            no_transformer: false,
            field: None,
            plain: None,
        })
    }
}

fn literal(list: bool) -> Check {
    Check {
        original: Ty::new("CHARBUF", list),
        ty: Ty::new("CHARBUF", list),
        no_rhs: false,
        no_transformer: false,
        field: None,
        plain: None,
    }
}

fn describe(ty: &Ty) -> String {
    let name = match ty.name.as_str() {
        "CHARBUF" => "a string",
        "FSPATH" | "FSRELPATH" => "a path",
        "BYTEBUF" => "a buffer",
        "BOOL" => "a boolean",
        t if NUMERIC.contains(&t) => "a number",
        t if NET_TYPES.contains(&t) => "a network",
        t if IP_TYPES.contains(&t) => "an IP address",
        _ => "typed",
    };
    format!(
        "{name} ({}{})",
        ty.name,
        if ty.list { ", list" } else { "" }
    )
}

/// Falco's deprecation text (`falco_load_result.cpp`).
pub fn deprecated_message(field: &str) -> String {
    if field == "evt.dir" {
        "`evt.dir` is deprecated: due to the drop of enter events, 'evt.dir = <' always evaluates \
         to true, and 'evt.dir = >' always evaluates to false. The rule expression can be \
         simplified by removing the condition on 'evt.dir'"
            .into()
    } else if field.starts_with("evt.latency") || field == "evt.wait_latency" {
        format!("`{field}` is deprecated: field is not available due to the drop of enter events.")
    } else {
        format!("`{field}` is deprecated")
    }
}

/// `check_warnings_regex_value`: the message when a plain operator could do
/// what the regex does.
pub fn regex_simplifiable(v: &str) -> Option<String> {
    const SPECIAL: &[u8] = b".+*?^$()[]{}|\\";
    const OCCURRENCE: &[u8] = b"+*?";
    let b = v.as_bytes();
    let len = b.len();
    let mut i = 0;
    while i < len {
        if (i == 0 && b[i] == b'^') || (i == len - 1 && b[i] == b'$') {
            i += 1;
            continue;
        }
        if ((i == 0 && len > 1) || (len >= 2 && i == len - 2))
            && b[i] == b'.'
            && i + 1 < len
            && OCCURRENCE.contains(&b[i + 1])
        {
            i += 2;
            continue;
        }
        if SPECIAL.contains(&b[i]) {
            return None;
        }
        i += 1;
    }
    Some(format!(
        "regex check with '{v}' may be optimized with simpler operators such as '=', 'contains', 'startswith', 'endswith'"
    ))
}

/// Syntax only recent libsinsp releases parse, with the release that added
/// it: operator modifiers, `join`, `concat`, `getopt`, and a field argument on
/// a transformer. An older Falco or Sysdig agent refuses the rule.
pub fn newer_syntax(expr: &Expr, out: &mut Vec<(Span, String)>) {
    fn needs(out: &mut Vec<(Span, String)>, span: Span, what: &str, version: &str) {
        out.push((
            span,
            format!("{what} needs libsinsp {version} or later: an older Falco or Sysdig agent refuses the rule"),
        ));
    }
    fn walk(e: &Expr, out: &mut Vec<(Span, String)>) {
        match e {
            Expr::And(c, _) | Expr::Or(c, _) | Expr::TransformerList(c, _) => {
                for x in c {
                    walk(x, out);
                }
            }
            Expr::Not(c, _) => walk(c, out),
            Expr::Unary { left, .. } => walk(left, out),
            Expr::Binary {
                left,
                op,
                op_span,
                right,
                ..
            } => {
                if let Some((_, modifier)) = op.split_once(' ') {
                    needs(
                        out,
                        *op_span,
                        &format!("the `{modifier}` operator modifier"),
                        "0.25.0",
                    );
                }
                walk(left, out);
                walk(right, out);
            }
            Expr::Transformer {
                name,
                values,
                arg,
                span,
            } => {
                match name.as_str() {
                    "join" | "concat" => needs(out, *span, &format!("`{name}()`"), "0.24.0"),
                    "getopt" => needs(out, *span, "`getopt()`", "0.25.0"),
                    _ => {}
                }
                if arg.is_some() && name != "getopt" {
                    needs(out, *span, "a field argument on a transformer", "0.25.0");
                }
                for x in values {
                    walk(x, out);
                }
            }
            _ => {}
        }
    }
    walk(expr, out);
}

/// Falco's rule-loader warning on a `<NA>` comparison of `ka.` and `jevt.`
/// fields (`LOAD_UNSAFE_NA_CHECK`).
pub fn unsafe_na_checks(expr: &Expr, out: &mut Vec<Span>) {
    match expr {
        Expr::And(c, _) | Expr::Or(c, _) => c.iter().for_each(|e| unsafe_na_checks(e, out)),
        Expr::Not(c, _) => unsafe_na_checks(c, out),
        Expr::Binary {
            left, op, right, ..
        } => {
            let unsafe_field = matches!(&**left, Expr::Field { name, .. } if name.starts_with("ka.") || name.starts_with("jevt."));
            let equality = matches!(
                op.as_str(),
                "==" | "=" | "!=" | "in" | "intersects" | "pmatch"
            );
            if unsafe_field && equality {
                match &**right {
                    Expr::Value(v, s) if v == "<NA>" => out.push(*s),
                    Expr::List(values, _) => {
                        out.extend(values.iter().filter(|(v, _)| v == "<NA>").map(|(_, s)| *s));
                    }
                    _ => {}
                }
            }
        }
        _ => {}
    }
}

/// The longest prefix of *rest* that parses as a field or transformer (the
/// formatter shrinks the text from the end until one compiles).
pub fn output_prefixes(rest: &str) -> Vec<(Expr, usize)> {
    let mut found = Vec::new();
    let mut size = rest.len();
    while size > 0 {
        if rest.is_char_boundary(size) {
            let mut p = Parser::new(&rest[..size]);
            if let Ok(e) = p.parse_field_or_transformer() {
                let consumed = p.pos();
                found.push((e, consumed));
                // Every longer prefix parsed to the same token.
                size = consumed.min(size);
            }
        }
        size -= 1;
    }
    found
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::parser::parse;

    fn codes(text: &str, source: &str) -> Vec<&'static str> {
        let c = Catalog::cached();
        let mut comp = Compiler::new(c, source);
        comp.condition(&parse(text).unwrap());
        comp.findings.iter().map(|f| f.code).collect()
    }

    #[test]
    fn fields_resolve_with_their_arguments() {
        let c = Catalog::cached();
        for ok in [
            "proc.aname[2]",
            "proc.aname",
            "evt.arg.flags",
            "evt.arg[0]",
            "evt.rawarg.res",
            "evt.type.is.open",
            "proc.env[HOME]",
            "thread.cgroup.cpuset",
            "fd.types[0]",
            "evt.abspath.src",
        ] {
            let (n, a) = match ok.split_once('[') {
                Some((n, a)) => (n, Some(a.trim_end_matches(']'))),
                None => (ok, None),
            };
            assert!(resolve(c, "syscall", n, a).is_ok(), "{ok}");
        }
        assert!(matches!(
            resolve(c, "syscall", "proc.name", Some("2")),
            Err(FieldError::Argument(_))
        ));
        assert!(matches!(
            resolve(c, "syscall", "evt.arg.nosuchparam", None),
            Err(FieldError::Argument(_))
        ));
        assert!(matches!(
            resolve(c, "syscall", "proc.nmae", None),
            Err(FieldError::Unknown)
        ));
        assert_eq!(
            resolve(c, "syscall", "evt.rawarg.res", None).unwrap().ty,
            "ERRNO"
        );
        assert!(resolve(c, "k8s_audit", "ka.uri.param", Some("key")).is_ok());
        assert!(matches!(
            resolve(c, "k8s_audit", "ka.uri.param", None),
            Err(FieldError::Argument(_))
        ));
    }

    #[test]
    fn operators_values_and_transformers() {
        assert!(codes("proc.pid = 1 and proc.name contains x", "syscall").is_empty());
        assert_eq!(
            codes("proc.pid contains 1", "syscall"),
            [codes::FALCO_OPERATOR_TYPE]
        );
        assert_eq!(
            codes("proc.pid = abc", "syscall"),
            [codes::FALCO_VALUE_TYPE]
        );
        assert_eq!(
            codes("fd.net = 10.0.0.1", "syscall"),
            [codes::FALCO_VALUE_TYPE]
        );
        assert!(codes("fd.net = 10.0.0.0/8", "syscall").is_empty());
        assert_eq!(
            codes("evt.type = opne", "syscall"),
            [codes::FALCO_UNKNOWN_EVENT]
        );
        assert!(codes("evt.type in (open, execve)", "syscall").is_empty());
        assert_eq!(
            codes("tolower(proc.pid) = 1", "syscall"),
            [codes::FALCO_TRANSFORMER]
        );
        assert!(codes("len(proc.name) > 3", "syscall").is_empty());
        assert_eq!(
            codes("proc.name pmatch val(proc.pname)", "syscall"),
            [codes::FALCO_RHS_FIELD]
        );
        assert_eq!(
            codes("proc.name = val(proc.pid)", "syscall"),
            [codes::FALCO_RHS_FIELD]
        );
        assert_eq!(
            codes("proc.name regex bash", "syscall"),
            [codes::FALCO_REGEX_SIMPLE]
        );
        assert_eq!(
            codes("proc.name = proc.pname", "syscall"),
            [codes::FALCO_FIELD_AS_VALUE]
        );
        assert_eq!(
            codes("evt.dir = <", "syscall"),
            [codes::FALCO_DEPRECATED_FIELD]
        );
        assert!(codes("join(\",\", (proc.name, proc.pname)) = a", "syscall").is_empty());
        assert_eq!(
            codes("join(proc.name, proc.pname) = a", "syscall"),
            [codes::FALCO_TRANSFORMER]
        );
        assert_eq!(
            codes("proc.nmae = a", "syscall"),
            [codes::FALCO_UNKNOWN_FIELD]
        );
    }
}
