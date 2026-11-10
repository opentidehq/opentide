//! The semantic pass over yara-x-parser's AST: the symbol table (imports,
//! rules, strings, loop variables), types, and every yara-1.0 code that is
//! not a syntax error. Each check cites the libyara 4.5 behaviour it mirrors
//! (`docs/YARA.md`).

use crate::atoms::{self, MaskedByte};
use crate::catalog::{Catalog, Kind, Member};
use crate::{Context, Dialect, Finding, Profile, regexp};
use opentide_core::{Severity, codes};
use std::collections::{BTreeMap, BTreeSet};
use yara_x_parser::Span;
use yara_x_parser::ast::{
    AST, Expr, HexSubPattern, HexToken, Ident, Iterable, MatchAnchor, MetaValue, OfItems, Pattern,
    PatternModifier, PatternSet, Quantifier, Rule, RuleFlags, WithSpan,
};

/// The integer readers libyara builds in (`lexer.l`: `u?int(8|16|32)(be)?`).
const INTEGER_FUNCTIONS: &[&str] = &[
    "int8", "int16", "int32", "uint8", "uint16", "uint32", "int8be", "int16be", "int32be",
    "uint8be", "uint16be", "uint32be",
];

/// libyara's `YR_STRING_CHAINING_THRESHOLD`: the longest jump inside a hex
/// alternative.
const CHAINING_THRESHOLD: u32 = 200;

#[derive(Debug, Clone, PartialEq)]
enum Ty {
    Bool,
    Int,
    Float,
    Str,
    Regexp,
    /// A module, or a structure in one: `path` is `""` for the module.
    Object {
        module: String,
        path: String,
    },
    Array {
        module: String,
        path: String,
        element: Kind,
    },
    Dict {
        module: String,
        path: String,
        element: Kind,
    },
    Func {
        module: String,
        path: String,
    },
    /// Not known; checks on it are skipped rather than guessed.
    Unknown,
}

impl Ty {
    fn letter(&self) -> char {
        match self {
            Ty::Int => 'i',
            Ty::Float => 'f',
            Ty::Str => 's',
            Ty::Regexp => 'r',
            Ty::Bool => 'b',
            _ => '?',
        }
    }

    fn name(&self) -> &'static str {
        match self {
            Ty::Bool => "a boolean",
            Ty::Int => "an integer",
            Ty::Float => "a float",
            Ty::Str => "a string",
            Ty::Regexp => "a regular expression",
            Ty::Object { .. } => "a structure",
            Ty::Array { .. } => "an array",
            Ty::Dict { .. } => "a dictionary",
            Ty::Func { .. } => "a function",
            Ty::Unknown => "a value",
        }
    }

    fn is_numeric(&self) -> bool {
        matches!(self, Ty::Int | Ty::Float | Ty::Unknown)
    }

    fn is_int(&self) -> bool {
        matches!(self, Ty::Int | Ty::Unknown)
    }

    fn is_str(&self) -> bool {
        matches!(self, Ty::Str | Ty::Unknown)
    }
}

fn scalar(kind: Kind) -> Ty {
    match kind {
        Kind::Integer => Ty::Int,
        Kind::Float => Ty::Float,
        Kind::String => Ty::Str,
        // libyara has no boolean fields; YARA-X's are its own.
        Kind::Boolean => Ty::Bool,
        Kind::Regexp => Ty::Regexp,
        _ => Ty::Unknown,
    }
}

fn ret_ty(ret: &str) -> Ty {
    match ret {
        "integer" | "i" => Ty::Int,
        "float" | "f" => Ty::Float,
        "string" | "s" => Ty::Str,
        "boolean" | "b" => Ty::Bool,
        _ => Ty::Unknown,
    }
}

struct PatternInfo {
    name: String,
    span: (usize, usize),
    referenced: bool,
}

struct RuleState {
    patterns: Vec<PatternInfo>,
    uses_them: bool,
}

pub struct Checker<'a> {
    source: &'a str,
    ctx: &'a Context,
    catalog: &'static Catalog,
    imports: BTreeSet<String>,
    /// Rules defined before the current one.
    earlier_rules: BTreeSet<String>,
    rule_wildcards: &'a [(usize, usize)],
    scopes: Vec<BTreeMap<String, Ty>>,
    /// Depth of `for … of` bodies, where the anonymous `$` is the current string.
    in_for_of: usize,
    rule: RuleState,
    pub findings: Vec<Finding>,
}

fn span(s: &Span) -> (usize, usize) {
    (s.start(), s.end())
}

impl<'a> Checker<'a> {
    pub fn new(source: &'a str, ctx: &'a Context, rule_wildcards: &'a [(usize, usize)]) -> Self {
        Self {
            source,
            ctx,
            catalog: Catalog::cached(),
            imports: BTreeSet::new(),
            earlier_rules: BTreeSet::new(),
            rule_wildcards,
            scopes: Vec::new(),
            in_for_of: 0,
            rule: RuleState {
                patterns: Vec::new(),
                uses_them: false,
            },
            findings: Vec::new(),
        }
    }

    fn libyara(&self) -> bool {
        self.ctx.dialect == Dialect::Libyara4
    }

    fn push(
        &mut self,
        code: &'static str,
        severity: Severity,
        message: String,
        at: (usize, usize),
    ) {
        self.findings
            .push(Finding::new(code, severity, message, at.0, at.1));
    }

    fn error(&mut self, code: &'static str, message: String, at: (usize, usize)) {
        self.push(code, Severity::Error, message, at);
    }

    fn warn(&mut self, code: &'static str, message: String, at: (usize, usize)) {
        self.push(code, Severity::Warning, message, at);
    }

    /// What libyara accepts and YARA-X refuses: a warning under libyara, an
    /// error when the profile's dialect is YARA-X.
    fn yara_x(&mut self, message: String, at: (usize, usize)) {
        let severity = if self.libyara() {
            Severity::Warning
        } else {
            Severity::Error
        };
        self.push(codes::YARA_X_INCOMPATIBLE, severity, message, at);
    }

    /// Syntax only YARA-X accepts: an error under libyara.
    fn yara_x_only(&mut self, feature: &str, at: (usize, usize)) {
        if self.libyara() {
            self.error(
                codes::YARA_PARSE_ERROR,
                format!("{feature} is YARA-X syntax; libyara 4.5 refuses it"),
                at,
            );
        }
    }

    fn text(&self, at: (usize, usize)) -> &'a str {
        self.source.get(at.0..at.1).unwrap_or("")
    }

    // --- Signature level ---

    /// `parsed`: the text has no syntax error. A rule that does not parse is
    /// missing from the AST, so signature-wide counts are skipped then.
    pub fn signature(&mut self, ast: &AST, parsed: bool, broken: &dyn Fn((usize, usize)) -> bool) {
        for include in ast.items().filter_map(|i| match i {
            yara_x_parser::ast::Item::Include(include) => Some(include),
            _ => None,
        }) {
            let at = span(&include.span());
            self.error(
                codes::YARA_INCLUDE,
                format!(
                    "`include \"{}\"`: no platform resolves includes; write the included rules in the signature",
                    include.file_name
                ),
                at,
            );
        }
        let profile = self.ctx.profile.map(|p| &self.catalog.profiles[p.key()]);
        for import in ast.imports() {
            let at = span(&import.span());
            let name = import.module_name;
            if !self.catalog.known_modules.contains(name) {
                self.error(
                    codes::YARA_UNKNOWN_MODULE,
                    format!("libyara 4.5 has no module `{name}`"),
                    at,
                );
                continue;
            }
            self.imports.insert(name.to_string());
            if let Some(p) = profile
                && !p.confirmed_modules.iter().any(|m| m == name)
            {
                self.warn(
                    codes::YARA_MODULE_UNCONFIRMED,
                    format!(
                        "`{name}` is not confirmed on {} agents, which load {}",
                        self.ctx.profile.map_or("", |p| p.display()),
                        p.confirmed_modules.join(", ")
                    ),
                    at,
                );
            }
        }
        let rules: Vec<&Rule> = ast.rules().collect();
        let mut seen_rules: BTreeMap<&str, (usize, usize)> = BTreeMap::new();
        let mut public = 0;
        for rule in &rules {
            let name = rule.identifier.name;
            let at = span(&rule.identifier.span());
            if seen_rules.contains_key(name) {
                self.error(
                    codes::YARA_DUPLICATE_RULE,
                    format!("a rule named `{name}` is already defined in this signature"),
                    at,
                );
            } else {
                seen_rules.insert(name, at);
            }
            if !rule.flags.contains(RuleFlags::Private) && !rule.flags.contains(RuleFlags::Global) {
                public += 1;
            }
            if broken(at) {
                // A rule with a syntax error: libyara stops there.
                self.earlier_rules.insert(name.to_string());
                continue;
            }
            self.rule(rule);
            self.earlier_rules.insert(name.to_string());
        }
        if public == 0 && parsed {
            let at = rules.first().map_or((0, 0), |r| span(&r.identifier.span()));
            self.error(
                codes::YARA_EMPTY_SIGNATURE,
                if rules.is_empty() {
                    "the signature has no YARA rule".to_string()
                } else {
                    "every rule is private or global, so the signature can never match".to_string()
                },
                at,
            );
        }
    }

    // --- Rule level ---

    fn rule(&mut self, rule: &Rule) {
        let name = rule.identifier.name;
        let name_at = span(&rule.identifier.span());
        if self.imports.contains(name) {
            self.error(
                codes::YARA_RULE_IDENTIFIER_CONFLICT,
                format!("the rule `{name}` has the name of the imported module `{name}`"),
                name_at,
            );
        } else if self.catalog.keywords.contains(name) {
            self.error(
                codes::YARA_RULE_IDENTIFIER_CONFLICT,
                format!("`{name}` is a YARA keyword and cannot name a rule"),
                name_at,
            );
        }
        if let Some(tags) = &rule.tags {
            let mut seen = BTreeSet::new();
            for tag in tags {
                if !seen.insert(tag.name) {
                    self.error(
                        codes::YARA_DUPLICATE_TAG,
                        format!("the tag `{}` is repeated", tag.name),
                        span(&tag.span()),
                    );
                }
            }
        }
        self.meta(rule, name_at);
        self.rule = RuleState {
            patterns: Vec::new(),
            uses_them: false,
        };
        if let Some(patterns) = &rule.patterns {
            for pattern in patterns {
                self.pattern(pattern);
            }
        }
        let ty = self.expr(&rule.condition);
        let cond_at = span(&rule.condition.span());
        match ty {
            Ty::Int | Ty::Float => self.warn(
                codes::YARA_SUSPICIOUS_EXPRESSION,
                format!("the condition is {}, not a boolean: libyara reads any non-zero value as true", ty.name()),
                cond_at,
            ),
            Ty::Str => self.warn(
                codes::YARA_SUSPICIOUS_EXPRESSION,
                "the condition is a string, not a boolean: libyara reads any non-empty string as true".to_string(),
                cond_at,
            ),
            _ => {}
        }
        if !self.rule.uses_them {
            let unreferenced: Vec<(String, (usize, usize))> = self
                .rule
                .patterns
                .iter()
                .filter(|p| !p.referenced && !p.name.starts_with("$_"))
                .map(|p| (p.name.clone(), p.span))
                .collect();
            for (name, at) in unreferenced {
                self.error(
                    codes::YARA_UNREFERENCED_STRING,
                    format!(
                        "the string `{name}` is never used in the condition; use it, use `them`, or start its name with `$_`"
                    ),
                    at,
                );
            }
        }
    }

    fn meta(&mut self, rule: &Rule, name_at: (usize, usize)) {
        let metas = rule.meta.as_deref().unwrap_or(&[]);
        for meta in metas {
            match &meta.value {
                MetaValue::Float((_, s)) => self.yara_x_only("A float meta value", span(s)),
                MetaValue::String((raw, s)) if raw.starts_with("\"\"\"") => {
                    self.yara_x_only("A `\"\"\"` string", span(s))
                }
                _ => {}
            }
        }
        let Some(profile) = self.ctx.profile else {
            return;
        };
        let data = &self.catalog.profiles[profile.key()];
        if rule.flags.contains(RuleFlags::Private) {
            return;
        }
        for key in &data.recommended_meta {
            if !metas.iter().any(|m| m.identifier.name == key) {
                self.warn(
                    codes::YARA_META_MISSING,
                    format!(
                        "{} recommends meta `{key}` on every non-private rule",
                        profile.display()
                    ),
                    name_at,
                );
            }
        }
        if profile == Profile::Harfanglab {
            for meta in metas.iter().filter(|m| m.identifier.name == "context") {
                let (value, at) = match &meta.value {
                    MetaValue::String((raw, s)) => (raw.trim_matches('"').to_string(), span(s)),
                    MetaValue::Bytes((b, s)) => (b.to_string(), span(s)),
                    other => (other.to_string(), span(&meta.identifier.span())),
                };
                if !data.context_values.contains(&value) {
                    self.warn(
                        codes::HARFANGLAB_YARA_CONTEXT,
                        format!(
                            "HarfangLab's YARA rules use context {}; `{value}` is none of them",
                            data.context_values.join(", ")
                        ),
                        at,
                    );
                }
            }
        }
    }

    // --- Strings ---

    fn pattern(&mut self, pattern: &Pattern) {
        let ident = pattern.identifier();
        let at = span(&ident.span());
        let name = ident.name;
        if name != "$" && self.rule.patterns.iter().any(|p| p.name == name) {
            self.error(
                codes::YARA_DUPLICATE_STRING,
                format!("the string `{name}` is already defined in this rule"),
                at,
            );
        } else {
            self.rule.patterns.push(PatternInfo {
                name: name.to_string(),
                span: at,
                referenced: false,
            });
        }
        self.modifiers(pattern, at);
        match pattern {
            Pattern::Text(text) => {
                let value: &[u8] = text.text.value.as_ref();
                let text_at = span(&text.text.span());
                if text.text.literal.starts_with("\"\"\"") {
                    self.yara_x_only("A `\"\"\"` string", text_at);
                }
                if value.is_empty() {
                    self.error(
                        codes::YARA_PARSE_ERROR,
                        "libyara refuses an empty string".to_string(),
                        text_at,
                    );
                    return;
                }
                let base64 = pattern.modifiers().base64().is_some()
                    || pattern.modifiers().base64wide().is_some();
                if base64 && value.len() < 3 {
                    self.yara_x(
                        "YARA-X refuses `base64` on a string shorter than 3 bytes".to_string(),
                        text_at,
                    );
                }
                // libyara scores the atom before `wide` interleaves it.
                if !base64 && atoms::is_slow(&[atoms::text_run(value, false)]) {
                    self.slow(name, at);
                }
            }
            Pattern::Regexp(re) => {
                let re_at = span(&re.regexp.span());
                let check = regexp::check(re.regexp.src);
                let base = re_at.0 + 1;
                for f in &check.errors {
                    self.error(
                        codes::YARA_REGEXP,
                        format!("invalid regular expression: {}", f.message),
                        (base + f.start, base + f.end.max(f.start + 1)),
                    );
                }
                for f in &check.yara_x {
                    self.yara_x(f.message.clone(), (base + f.start, base + f.end));
                }
                if check.errors.is_empty() {
                    let q = check
                        .atoms
                        .best(&|r| atoms::best_quality(&[atoms::text_run(r, false)]));
                    if q.is_none_or(|q| q < atoms::WARNING_THRESHOLD) {
                        self.slow(name, at);
                    }
                }
            }
            Pattern::Hex(hex) => {
                self.hex(&hex.sub_patterns, false);
                let mut runs = Vec::new();
                hex_runs(&hex.sub_patterns, &mut runs);
                if atoms::is_slow(&runs) {
                    self.slow(name, at);
                }
            }
        }
    }

    fn slow(&mut self, name: &str, at: (usize, usize)) {
        self.warn(
            codes::YARA_SLOW_PATTERN,
            format!("libyara: string `{name}` may slow down scanning (it has no distinctive 2- to 4-byte atom)"),
            at,
        );
    }

    fn modifiers(&mut self, pattern: &Pattern, at: (usize, usize)) {
        let mods: Vec<&PatternModifier> = pattern.modifiers().iter().collect();
        let mut seen: BTreeSet<&str> = BTreeSet::new();
        for m in &mods {
            let name = m.as_text();
            let m_at = modifier_span(m);
            if !seen.insert(name) {
                self.error(
                    codes::YARA_STRING_MODIFIER,
                    format!("duplicated modifier `{name}`"),
                    m_at,
                );
            }
            let allowed = match pattern {
                Pattern::Text(_) => true,
                Pattern::Regexp(_) => matches!(
                    m,
                    PatternModifier::Ascii { .. }
                        | PatternModifier::Wide { .. }
                        | PatternModifier::Nocase { .. }
                        | PatternModifier::Fullword { .. }
                        | PatternModifier::Private { .. }
                ),
                Pattern::Hex(_) => matches!(m, PatternModifier::Private { .. }),
            };
            if !allowed {
                let kind = match pattern {
                    Pattern::Regexp(_) => "a regular expression",
                    _ => "a hex string",
                };
                self.error(
                    codes::YARA_STRING_MODIFIER,
                    format!("libyara refuses `{name}` on {kind}"),
                    m_at,
                );
            }
            if let PatternModifier::Xor { start, end, .. } = m
                && start > end
            {
                self.error(
                    codes::YARA_STRING_MODIFIER,
                    format!("invalid xor range: {start} is greater than {end}"),
                    m_at,
                );
            }
            if let PatternModifier::Base64 {
                alphabet: Some(a), ..
            }
            | PatternModifier::Base64Wide {
                alphabet: Some(a), ..
            } = m
            {
                let a_at = span(&a.span());
                let len = unescaped_len(self.text(a_at));
                if len != 64 {
                    self.error(
                        codes::YARA_STRING_MODIFIER,
                        format!("a base64 alphabet has 64 characters; this one has {len}"),
                        a_at,
                    );
                }
            }
        }
        let has = |n: &str| mods.iter().any(|m| m.as_text() == n);
        let base64 = has("base64") || has("base64wide");
        for (a, b) in [
            ("xor", "nocase"),
            ("base64", "nocase"),
            ("base64wide", "nocase"),
            ("base64", "fullword"),
            ("base64wide", "fullword"),
            ("base64", "xor"),
            ("base64wide", "xor"),
        ] {
            if has(a) && has(b) && matches!(pattern, Pattern::Text(_)) {
                self.error(
                    codes::YARA_STRING_MODIFIER,
                    format!("invalid modifier combination: {a} {b}"),
                    at,
                );
            }
        }
        if base64 {
            let alphabets: Vec<&str> = mods
                .iter()
                .filter_map(|m| match m {
                    PatternModifier::Base64 {
                        alphabet: Some(a), ..
                    }
                    | PatternModifier::Base64Wide {
                        alphabet: Some(a), ..
                    } => Some(self.text(span(&a.span()))),
                    _ => None,
                })
                .collect();
            if alphabets.len() == 2 && alphabets[0] != alphabets[1] {
                self.error(
                    codes::YARA_STRING_MODIFIER,
                    "libyara can not specify multiple alphabets: give base64 and base64wide the same one".to_string(),
                    at,
                );
            }
        }
    }

    /// `hex_grammar.y`'s jump checks, and the YARA-X-only jump bounds.
    fn hex(&mut self, sub: &HexSubPattern, inside_alternative: bool) {
        for token in sub.iter() {
            match token {
                HexToken::Jump(jump) => {
                    let at = span(&jump.span());
                    let text = self.text(at);
                    if text.contains("0x") || text.contains("0o") {
                        self.yara_x_only("A hex or octal jump bound", at);
                    }
                    match (jump.start, jump.end) {
                        (Some(0), Some(0)) => self.error(
                            codes::YARA_HEX_STRING,
                            "invalid jump length: [0]".to_string(),
                            at,
                        ),
                        (Some(a), Some(b)) if a > b => self.error(
                            codes::YARA_HEX_STRING,
                            format!("invalid jump range: {a} is greater than {b}"),
                            at,
                        ),
                        _ => {}
                    }
                    if inside_alternative {
                        if jump.end.is_none() {
                            self.error(
                                codes::YARA_HEX_STRING,
                                "unbounded jumps are not allowed inside an alternative".to_string(),
                                at,
                            );
                        } else if jump.end.is_some_and(|e| e > CHAINING_THRESHOLD) {
                            self.error(
                                codes::YARA_HEX_STRING,
                                format!("jumps over {CHAINING_THRESHOLD} are not allowed inside an alternative"),
                                at,
                            );
                        }
                    }
                }
                HexToken::Alternative(alt) => {
                    for branch in &alt.alternatives {
                        self.hex(branch, true);
                    }
                }
                HexToken::Byte(_) | HexToken::NotByte(_) => {}
            }
        }
    }

    // --- Condition ---

    fn lookup_var(&self, name: &str) -> Option<Ty> {
        self.scopes.iter().rev().find_map(|s| s.get(name).cloned())
    }

    /// `$a`, `#a`, `@a`, `!a`: the string they name.
    fn use_pattern(&mut self, ident: &Ident) {
        let at = span(&ident.span());
        let name = format!("${}", &ident.name[1..]);
        if name == "$" {
            if self.in_for_of == 0 {
                self.error(
                    codes::YARA_UNDEFINED_STRING,
                    format!(
                        "the anonymous `{}` names a string only inside `for … of`",
                        ident.name
                    ),
                    at,
                );
            }
            return;
        }
        match self.rule.patterns.iter_mut().find(|p| p.name == name) {
            Some(p) => p.referenced = true,
            None => self.error(
                codes::YARA_UNDEFINED_STRING,
                format!("the rule defines no string `{name}`"),
                at,
            ),
        }
    }

    fn pattern_set(&mut self, set: &PatternSet) -> usize {
        match set {
            PatternSet::Them { span: s } => {
                self.rule.uses_them = true;
                if self.rule.patterns.is_empty() {
                    self.error(
                        codes::YARA_UNDEFINED_STRING,
                        "`them` names no string: the rule has none".to_string(),
                        span(s),
                    );
                }
                self.rule.patterns.len()
            }
            PatternSet::Set(items) => {
                let mut count = 0;
                for item in items {
                    let at = span(&item.span());
                    let id = item.identifier.trim_start_matches('$');
                    let mut matched = 0;
                    for p in &mut self.rule.patterns {
                        let pid = p.name.trim_start_matches('$');
                        if (item.wildcard && pid.starts_with(id)) || (!item.wildcard && pid == id) {
                            p.referenced = true;
                            matched += 1;
                        }
                    }
                    if matched == 0 {
                        let shown = format!("${id}{}", if item.wildcard { "*" } else { "" });
                        self.error(
                            codes::YARA_UNDEFINED_STRING,
                            format!("no string of the rule matches `{shown}`"),
                            at,
                        );
                    }
                    count += matched;
                }
                count
            }
        }
    }

    fn expect(&mut self, ty: &Ty, ok: bool, what: &str, at: (usize, usize)) {
        if !ok {
            self.error(codes::YARA_TYPE, format!("{what}, not {}", ty.name()), at);
        }
    }

    fn boolean_operand(&mut self, e: &Expr) {
        let ty = self.expr(e);
        if let Expr::LiteralString(s) = e {
            self.warn(
                codes::YARA_SUSPICIOUS_EXPRESSION,
                format!(
                    "using the literal string {} in a boolean operation",
                    s.literal
                ),
                span(&s.span()),
            );
        } else if matches!(
            ty,
            Ty::Object { .. } | Ty::Array { .. } | Ty::Dict { .. } | Ty::Func { .. } | Ty::Regexp
        ) {
            self.error(
                codes::YARA_TYPE,
                format!("a boolean operand must be a value, not {}", ty.name()),
                span(&e.span()),
            );
        }
    }

    /// A comparison or arithmetic operand: libyara's `primary_expression`,
    /// which is never a boolean.
    fn primary(&mut self, e: &Expr) -> Ty {
        let ty = self.expr(e);
        if ty == Ty::Bool && is_syntactic_boolean(e) {
            self.error(
                codes::YARA_TYPE,
                "libyara compares and computes with integers, floats and strings; this operand is a boolean".to_string(),
                span(&e.span()),
            );
            return Ty::Unknown;
        }
        ty
    }

    fn expr(&mut self, e: &Expr) -> Ty {
        let at = span(&e.span());
        match e {
            Expr::True { .. } | Expr::False { .. } => Ty::Bool,
            Expr::Filesize { .. } => Ty::Int,
            Expr::Entrypoint { .. } => {
                self.warn(
                    codes::YARA_ENTRYPOINT_DEPRECATED,
                    "`entrypoint` is deprecated in libyara and refused by YARA-X: use `pe.entry_point` or `elf.entry_point`".to_string(),
                    at,
                );
                Ty::Int
            }
            Expr::LiteralString(s) => {
                if s.literal.starts_with("\"\"\"") {
                    self.yara_x_only("A `\"\"\"` string", at);
                }
                Ty::Str
            }
            Expr::LiteralInteger(i) => {
                if i.literal.contains('_') {
                    self.yara_x_only("A digit separator (`_`)", at);
                }
                Ty::Int
            }
            Expr::LiteralFloat(f) => {
                if f.literal.contains('_') {
                    self.yara_x_only("A digit separator (`_`)", at);
                }
                Ty::Float
            }
            Expr::Regexp(re) => {
                let check = regexp::check(re.src);
                let base = at.0 + 1;
                for f in &check.errors {
                    self.error(
                        codes::YARA_REGEXP,
                        format!("invalid regular expression: {}", f.message),
                        (base + f.start, base + f.end.max(f.start + 1)),
                    );
                }
                for f in &check.yara_x {
                    self.yara_x(f.message.clone(), (base + f.start, base + f.end));
                }
                Ty::Regexp
            }
            Expr::Ident(ident) => self.ident(ident),
            Expr::PatternMatch(m) => {
                self.use_pattern(&m.identifier);
                self.anchor(m.anchor.as_ref());
                Ty::Bool
            }
            Expr::PatternCount(c) => {
                self.use_pattern(&c.identifier);
                if let Some(range) = &c.range {
                    self.range(range);
                }
                Ty::Int
            }
            Expr::PatternOffset(p) | Expr::PatternLength(p) => {
                self.use_pattern(&p.identifier);
                if let Some(index) = &p.index {
                    let ty = self.primary(index);
                    self.expect(
                        &ty,
                        ty.is_int(),
                        "a string index is an integer",
                        span(&index.span()),
                    );
                    let negative = match index {
                        Expr::Minus(m) => matches!(m.operand, Expr::LiteralInteger(_)),
                        Expr::LiteralInteger(i) => i.value < 0,
                        _ => false,
                    };
                    if negative {
                        self.yara_x(
                            "YARA-X refuses a negative string index; in libyara it is always undefined".to_string(),
                            span(&index.span()),
                        );
                    }
                }
                Ty::Int
            }
            Expr::Lookup(lookup) => {
                let base = self.expr(&lookup.primary);
                self.index(base, &lookup.index, at)
            }
            Expr::FieldAccess(access) => {
                let mut operands = access.operands();
                let mut ty = match operands.next() {
                    Some(first) => self.expr(first),
                    None => Ty::Unknown,
                };
                for operand in operands {
                    ty = match operand {
                        Expr::Ident(ident) => self.member(ty, ident.name, span(&ident.span())),
                        Expr::Lookup(lookup) => match &lookup.primary {
                            Expr::Ident(ident) => {
                                let base = self.member(ty, ident.name, span(&ident.span()));
                                self.index(
                                    base,
                                    &lookup.index,
                                    span(&lookup.primary.span().combine(&lookup.index.span())),
                                )
                            }
                            other => {
                                self.expr(other);
                                Ty::Unknown
                            }
                        },
                        other => {
                            self.expr(other);
                            Ty::Unknown
                        }
                    };
                }
                ty
            }
            Expr::FuncCall(call) => self.call(call, at),
            Expr::Defined(u) => {
                self.expr(&u.operand);
                Ty::Bool
            }
            Expr::Not(u) => {
                self.boolean_operand(&u.operand);
                Ty::Bool
            }
            Expr::And(n) | Expr::Or(n) => {
                for operand in n.operands() {
                    self.boolean_operand(operand);
                }
                Ty::Bool
            }
            Expr::Minus(u) => {
                let ty = self.primary(&u.operand);
                self.expect(
                    &ty,
                    ty.is_numeric(),
                    "`-` takes a number",
                    span(&u.operand.span()),
                );
                if ty == Ty::Float { Ty::Float } else { Ty::Int }
            }
            Expr::BitwiseNot(u) => {
                let ty = self.primary(&u.operand);
                self.expect(
                    &ty,
                    ty.is_int(),
                    "`~` takes an integer",
                    span(&u.operand.span()),
                );
                Ty::Int
            }
            Expr::Add(n) | Expr::Sub(n) | Expr::Mul(n) | Expr::Div(n) => {
                let mut float = false;
                for operand in n.operands() {
                    let ty = self.primary(operand);
                    float |= ty == Ty::Float;
                    self.expect(
                        &ty,
                        ty.is_numeric(),
                        "arithmetic takes numbers",
                        span(&operand.span()),
                    );
                }
                if float { Ty::Float } else { Ty::Int }
            }
            Expr::Mod(n) => {
                for operand in n.operands() {
                    let ty = self.primary(operand);
                    self.expect(
                        &ty,
                        ty.is_int(),
                        "`%` takes integers",
                        span(&operand.span()),
                    );
                }
                Ty::Int
            }
            Expr::Shl(b)
            | Expr::Shr(b)
            | Expr::BitwiseAnd(b)
            | Expr::BitwiseOr(b)
            | Expr::BitwiseXor(b) => {
                for operand in [&b.lhs, &b.rhs] {
                    let ty = self.primary(operand);
                    self.expect(
                        &ty,
                        ty.is_int(),
                        "bitwise operators take integers",
                        span(&operand.span()),
                    );
                }
                Ty::Int
            }
            Expr::Eq(b) | Expr::Ne(b) | Expr::Lt(b) | Expr::Gt(b) | Expr::Le(b) | Expr::Ge(b) => {
                let (l, r) = (self.primary(&b.lhs), self.primary(&b.rhs));
                let comparable = (l.is_numeric() && r.is_numeric())
                    || (l.is_str() && r.is_str())
                    || l == Ty::Unknown
                    || r == Ty::Unknown
                    || (l == Ty::Bool && r == Ty::Bool);
                if (l == Ty::Bool && r.is_numeric() && r != Ty::Unknown)
                    || (r == Ty::Bool && l.is_numeric() && l != Ty::Unknown)
                {
                    self.warn(
                        codes::YARA_SUSPICIOUS_EXPRESSION,
                        "an integer compared with a boolean".to_string(),
                        at,
                    );
                } else if !comparable {
                    self.error(
                        codes::YARA_TYPE,
                        format!("type mismatch: {} compared with {}", l.name(), r.name()),
                        at,
                    );
                }
                Ty::Bool
            }
            Expr::Contains(b)
            | Expr::IContains(b)
            | Expr::StartsWith(b)
            | Expr::IStartsWith(b)
            | Expr::EndsWith(b)
            | Expr::IEndsWith(b)
            | Expr::IEquals(b) => {
                for operand in [&b.lhs, &b.rhs] {
                    let ty = self.primary(operand);
                    self.expect(
                        &ty,
                        ty.is_str(),
                        "string operators take strings",
                        span(&operand.span()),
                    );
                }
                Ty::Bool
            }
            Expr::Matches(b) => {
                let l = self.primary(&b.lhs);
                self.expect(
                    &l,
                    l.is_str(),
                    "`matches` takes a string on its left",
                    span(&b.lhs.span()),
                );
                let r = self.expr(&b.rhs);
                self.expect(
                    &r,
                    matches!(r, Ty::Regexp | Ty::Unknown),
                    "`matches` takes a regular expression on its right",
                    span(&b.rhs.span()),
                );
                Ty::Bool
            }
            Expr::Of(of) => {
                let size = match &of.items {
                    OfItems::PatternSet(set) => Some(self.pattern_set(set)),
                    OfItems::BoolExprTuple(items) => {
                        for item in items {
                            self.of_item(item);
                        }
                        Some(items.len())
                    }
                };
                self.quantifier(&of.quantifier, size);
                if let Some(MatchAnchor::At(a)) = &of.anchor {
                    let many = match &of.quantifier {
                        Quantifier::All { .. } => size.is_some_and(|s| s > 1),
                        Quantifier::Expr(Expr::LiteralInteger(i)) => i.value > 1,
                        _ => false,
                    };
                    if many {
                        self.warn(
                            codes::YARA_SUSPICIOUS_EXPRESSION,
                            "multiple strings at an offset is usually false".to_string(),
                            span(&a.expr.span()),
                        );
                    }
                }
                self.anchor(of.anchor.as_ref());
                Ty::Bool
            }
            Expr::ForOf(f) => {
                let size = self.pattern_set(&f.pattern_set);
                self.quantifier(&f.quantifier, Some(size));
                self.in_for_of += 1;
                self.boolean_operand(&f.body);
                self.in_for_of -= 1;
                Ty::Bool
            }
            Expr::ForIn(f) => {
                self.quantifier(&f.quantifier, None);
                let mut scope = BTreeMap::new();
                let vars: Vec<&Ident> = f.variables.iter().collect();
                let bound: Vec<Ty> = match &f.iterable {
                    Iterable::Range(range) => {
                        self.range(range);
                        vec![Ty::Int]
                    }
                    Iterable::ExprTuple(items) => {
                        let mut ty = Ty::Unknown;
                        for item in items {
                            let t = self.primary(item);
                            self.expect(
                                &t,
                                t.is_int() || t.is_str(),
                                "a loop enumerates integers or strings",
                                span(&item.span()),
                            );
                            ty = t;
                        }
                        vec![ty]
                    }
                    Iterable::Expr(expr) => match self.expr(expr) {
                        Ty::Array {
                            module,
                            path,
                            element,
                        } => vec![element_ty(module, format!("{path}[]"), element)],
                        Ty::Dict {
                            module,
                            path,
                            element,
                        } => vec![Ty::Str, element_ty(module, format!("{path}{{}}"), element)],
                        Ty::Unknown => vec![Ty::Unknown; vars.len()],
                        other => {
                            self.error(codes::YARA_TYPE, format!("a `for … in` loop iterates over an array or a dictionary, not {}", other.name()), span(&expr.span()));
                            vec![Ty::Unknown; vars.len()]
                        }
                    },
                };
                if bound.len() != vars.len() {
                    self.error(
                        codes::YARA_TYPE,
                        format!(
                            "this loop binds {} variable(s); it has {}",
                            bound.len(),
                            vars.len()
                        ),
                        span(&vars[0].span()),
                    );
                }
                for (i, var) in vars.iter().enumerate() {
                    scope.insert(
                        var.name.to_string(),
                        bound.get(i).cloned().unwrap_or(Ty::Unknown),
                    );
                }
                self.scopes.push(scope);
                self.boolean_operand(&f.body);
                self.scopes.pop();
                Ty::Bool
            }
            Expr::With(w) => {
                self.yara_x_only("The `with` statement", at);
                let mut scope = BTreeMap::new();
                for decl in &w.declarations {
                    let ty = self.expr(&decl.expression);
                    scope.insert(decl.identifier.name.to_string(), ty);
                }
                self.scopes.push(scope);
                let ty = self.expr(&w.body);
                self.scopes.pop();
                ty
            }
        }
    }

    fn of_item(&mut self, item: &Expr) {
        let Expr::Ident(ident) = item else {
            self.yara_x_only("A boolean expression in an `of` tuple", span(&item.span()));
            self.expr(item);
            return;
        };
        let at = span(&ident.span());
        let wildcard = self.rule_wildcards.contains(&at);
        if wildcard {
            if !self.earlier_rules.iter().any(|r| r.starts_with(ident.name)) {
                self.error(
                    codes::YARA_UNDEFINED_IDENTIFIER,
                    format!(
                        "no rule defined earlier in the signature matches `{}*`",
                        ident.name
                    ),
                    (at.0, at.1 + 1),
                );
            }
        } else if !self.earlier_rules.contains(ident.name) && self.lookup_var(ident.name).is_none()
        {
            self.error(
                codes::YARA_UNDEFINED_IDENTIFIER,
                format!(
                    "`{}` is not a rule defined earlier in the signature",
                    ident.name
                ),
                at,
            );
        }
    }

    fn quantifier(&mut self, q: &Quantifier, size: Option<usize>) {
        match q {
            Quantifier::Percentage(e) => {
                let ty = self.primary(e);
                self.expect(
                    &ty,
                    ty.is_int(),
                    "a percentage is an integer",
                    span(&e.span()),
                );
                if let Expr::LiteralInteger(i) = e
                    && !(1..=100).contains(&i.value)
                {
                    self.error(
                        codes::YARA_NUMBER_OUT_OF_RANGE,
                        format!("a percentage is between 1 and 100, not {}", i.value),
                        span(&e.span()),
                    );
                }
            }
            Quantifier::Expr(e) => {
                let ty = self.primary(e);
                self.expect(
                    &ty,
                    ty.is_int(),
                    "a quantifier is an integer",
                    span(&e.span()),
                );
                if let Expr::LiteralInteger(i) = e {
                    if i.value == 0 {
                        self.warn(
                            codes::YARA_SUSPICIOUS_EXPRESSION,
                            "consider using \"none\" keyword, it is less ambiguous".to_string(),
                            span(&e.span()),
                        );
                    } else if let Some(size) = size
                        && i.value as usize > size
                    {
                        self.warn(
                            codes::YARA_SUSPICIOUS_EXPRESSION,
                            format!("expression always false - requesting {} of {size}", i.value),
                            span(&e.span()),
                        );
                    }
                }
            }
            Quantifier::None { .. } | Quantifier::All { .. } | Quantifier::Any { .. } => {}
        }
    }

    fn anchor(&mut self, anchor: Option<&MatchAnchor>) {
        match anchor {
            Some(MatchAnchor::At(a)) => {
                let ty = self.primary(&a.expr);
                self.expect(
                    &ty,
                    ty.is_int(),
                    "`at` takes an integer offset",
                    span(&a.expr.span()),
                );
            }
            Some(MatchAnchor::In(i)) => self.range(&i.range),
            None => {}
        }
    }

    fn range(&mut self, range: &yara_x_parser::ast::Range) {
        for bound in [&range.lower_bound, &range.upper_bound] {
            let ty = self.primary(bound);
            self.expect(
                &ty,
                ty.is_int(),
                "a range bound is an integer",
                span(&bound.span()),
            );
        }
    }

    fn ident(&mut self, ident: &Ident) -> Ty {
        let name = ident.name;
        let at = span(&ident.span());
        if let Some(ty) = self.lookup_var(name) {
            return ty;
        }
        if self.imports.contains(name) {
            return Ty::Object {
                module: name.to_string(),
                path: String::new(),
            };
        }
        if self.earlier_rules.contains(name) {
            return Ty::Bool;
        }
        if self.catalog.known_modules.contains(name) {
            self.error(
                codes::YARA_MODULE_NOT_IMPORTED,
                format!("`{name}` is a module: add `import \"{name}\"` to the signature"),
                at,
            );
        } else {
            self.error(
                codes::YARA_UNDEFINED_IDENTIFIER,
                format!("`{name}` is neither a rule defined earlier in the signature nor an imported module"),
                at,
            );
        }
        Ty::Unknown
    }

    /// Whether a catalogue member is usable in the dialect, reporting it
    /// when it is not or when only libyara has it.
    fn available(&mut self, m: &Member, shown: &str, at: (usize, usize)) -> bool {
        let libyara_decls = self.catalog.has_libyara_declarations(&m.module);
        if self.libyara() && libyara_decls && !m.libyara {
            self.error(
                codes::YARA_UNKNOWN_MODULE_MEMBER,
                format!("`{shown}` is a YARA-X member; libyara 4.5 does not have it"),
                at,
            );
            return false;
        }
        if !self.libyara() && !m.yara_x {
            self.error(
                codes::YARA_UNKNOWN_MODULE_MEMBER,
                format!("YARA-X does not have `{shown}`"),
                at,
            );
            return false;
        }
        if self.libyara() && m.libyara && !m.yara_x {
            self.yara_x(format!("YARA-X does not have `{shown}`"), at);
        }
        true
    }

    fn member(&mut self, base: Ty, name: &str, at: (usize, usize)) -> Ty {
        let (module, path) = match base {
            Ty::Object { module, path } => (module, path),
            Ty::Unknown => return Ty::Unknown,
            other => {
                self.error(
                    codes::YARA_TYPE,
                    format!("`.{name}`: {} has no fields", other.name()),
                    at,
                );
                return Ty::Unknown;
            }
        };
        let child = if path.is_empty() {
            name.to_string()
        } else {
            format!("{path}.{name}")
        };
        let shown = format!(
            "{module}.{}",
            child.replace("[]", "[i]").replace("{}", "[k]")
        );
        let Some(m) = self.catalog.member(&module, &child) else {
            self.error(
                codes::YARA_UNKNOWN_MODULE_MEMBER,
                format!("the `{module}` module has no member `{shown}`"),
                at,
            );
            return Ty::Unknown;
        };
        if !self.available(m, &shown, at) {
            return Ty::Unknown;
        }
        match m.kind {
            Kind::Struct => Ty::Object {
                module,
                path: child,
            },
            Kind::Array => Ty::Array {
                module,
                path: child,
                element: m.element.unwrap_or(Kind::Struct),
            },
            Kind::Dict => Ty::Dict {
                module,
                path: child,
                element: m.element.unwrap_or(Kind::Struct),
            },
            Kind::Function => Ty::Func {
                module,
                path: child,
            },
            other => scalar(other),
        }
    }

    fn index(&mut self, base: Ty, index: &Expr, at: (usize, usize)) -> Ty {
        let ty = self.primary(index);
        match base {
            Ty::Array {
                module,
                path,
                element,
            } => {
                self.expect(
                    &ty,
                    ty.is_int(),
                    "an array index is an integer",
                    span(&index.span()),
                );
                element_ty(module, format!("{path}[]"), element)
            }
            Ty::Dict {
                module,
                path,
                element,
            } => {
                self.expect(
                    &ty,
                    ty.is_str(),
                    "a dictionary key is a string",
                    span(&index.span()),
                );
                element_ty(module, format!("{path}{{}}"), element)
            }
            Ty::Unknown => Ty::Unknown,
            other => {
                self.error(
                    codes::YARA_TYPE,
                    format!(
                        "only arrays and dictionaries take `[…]`, not {}",
                        other.name()
                    ),
                    at,
                );
                Ty::Unknown
            }
        }
    }

    fn call(&mut self, call: &yara_x_parser::ast::FuncCall, at: (usize, usize)) -> Ty {
        let name = call.identifier.name;
        let name_at = span(&call.identifier.span());
        let args: Vec<Ty> = call.args.iter().map(|a| self.expr(a)).collect();
        let Some(object) = &call.object else {
            if INTEGER_FUNCTIONS.contains(&name) {
                if args.len() != 1 || !args[0].is_int() {
                    self.error(
                        codes::YARA_TYPE,
                        format!("`{name}` takes one integer offset"),
                        at,
                    );
                }
                return Ty::Int;
            }
            self.error(
                codes::YARA_UNDEFINED_IDENTIFIER,
                format!("`{name}` is not a function: call a module's function (`pe.imphash()`) or an integer reader (`uint16(0)`)"),
                name_at,
            );
            return Ty::Unknown;
        };
        let base = self.expr(object);
        let Ty::Func { module, path } = self.member(base, name, name_at) else {
            return Ty::Unknown;
        };
        let Some(m) = self.catalog.member(&module, &path) else {
            return Ty::Unknown;
        };
        let use_libyara = self.libyara() && self.catalog.has_libyara_declarations(&module);
        let candidates: Vec<_> = m
            .overloads
            .iter()
            .filter(|o| if use_libyara { o.libyara } else { o.yara_x })
            .collect();
        let found = candidates.iter().find(|o| {
            o.args.len() == args.len()
                && o.args.chars().zip(&args).all(|(want, got)| {
                    let have = got.letter();
                    have == '?' || have == want || (want == 'f' && have == 'i')
                })
        });
        match found {
            Some(o) => ret_ty(&o.ret),
            None => {
                let shown: Vec<String> = candidates
                    .iter()
                    .map(|o| format!("({})", signature(&o.args)))
                    .collect();
                let got: Vec<&str> = args.iter().map(Ty::name).collect();
                self.error(
                    codes::YARA_UNKNOWN_MODULE_MEMBER,
                    format!(
                        "`{module}.{}` takes {}; it is called with ({})",
                        path.replace("[]", "[i]"),
                        if shown.is_empty() {
                            "no arguments".to_string()
                        } else {
                            shown.join(" or ")
                        },
                        got.join(", ")
                    ),
                    at,
                );
                Ty::Unknown
            }
        }
    }
}

fn element_ty(module: String, path: String, element: Kind) -> Ty {
    match element {
        Kind::Struct => Ty::Object { module, path },
        other => scalar(other),
    }
}

fn signature(args: &str) -> String {
    args.chars()
        .map(|c| match c {
            'i' => "integer",
            'f' => "float",
            's' => "string",
            'r' => "regexp",
            'b' => "boolean",
            _ => "?",
        })
        .collect::<Vec<_>>()
        .join(", ")
}

/// A boolean libyara's grammar builds, which is never a
/// `primary_expression`: `$a`, `true`, `a and b`, `x == y`, `any of them`.
fn is_syntactic_boolean(e: &Expr) -> bool {
    matches!(
        e,
        Expr::True { .. }
            | Expr::False { .. }
            | Expr::PatternMatch(_)
            | Expr::Not(_)
            | Expr::Defined(_)
            | Expr::And(_)
            | Expr::Or(_)
            | Expr::Eq(_)
            | Expr::Ne(_)
            | Expr::Lt(_)
            | Expr::Gt(_)
            | Expr::Le(_)
            | Expr::Ge(_)
            | Expr::Contains(_)
            | Expr::IContains(_)
            | Expr::StartsWith(_)
            | Expr::IStartsWith(_)
            | Expr::EndsWith(_)
            | Expr::IEndsWith(_)
            | Expr::IEquals(_)
            | Expr::Matches(_)
            | Expr::Of(_)
            | Expr::ForOf(_)
            | Expr::ForIn(_)
    )
}

fn modifier_span(m: &PatternModifier) -> (usize, usize) {
    match m {
        PatternModifier::Ascii { span: s }
        | PatternModifier::Wide { span: s }
        | PatternModifier::Nocase { span: s }
        | PatternModifier::Private { span: s }
        | PatternModifier::Fullword { span: s }
        | PatternModifier::Base64 { span: s, .. }
        | PatternModifier::Base64Wide { span: s, .. }
        | PatternModifier::Xor { span: s, .. } => span(s),
    }
}

/// The byte length of a YARA text literal (with its quotes) once its
/// escapes are read: `\"`, `\\`, `\t`, `\n`, `\r` one byte, `\xHH` one.
fn unescaped_len(literal: &str) -> usize {
    let inner = literal
        .strip_prefix('"')
        .and_then(|s| s.strip_suffix('"'))
        .unwrap_or(literal);
    let bytes = inner.as_bytes();
    let (mut i, mut n) = (0, 0);
    while i < bytes.len() {
        if bytes[i] == b'\\' {
            i += if bytes.get(i + 1) == Some(&b'x') {
                4
            } else {
                2
            };
        } else {
            i += 1;
        }
        n += 1;
    }
    n
}

/// The runs of fixed or masked bytes a hex string surely contains: a jump
/// or an alternative ends a run.
fn hex_runs(sub: &HexSubPattern, out: &mut Vec<Vec<MaskedByte>>) {
    let mut current = Vec::new();
    for token in sub.iter() {
        match token {
            HexToken::Byte(b) => current.push((b.value, b.mask)),
            HexToken::NotByte(b) => current.push((b.value, 0x00)),
            HexToken::Jump(_) | HexToken::Alternative(_) => {
                if !current.is_empty() {
                    out.push(std::mem::take(&mut current));
                }
            }
        }
    }
    if !current.is_empty() {
        out.push(current);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unescaped_lengths() {
        assert_eq!(unescaped_len("\"abc\""), 3);
        assert_eq!(unescaped_len("\"a\\x09b\""), 3);
        assert_eq!(unescaped_len("\"a\\\"b\""), 3);
    }
}
