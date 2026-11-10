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
    /// Modules imported before the current rule: libyara reads a signature
    /// top to bottom, so a module used above its `import` is undefined.
    imports: BTreeSet<String>,
    /// Every import and where it is.
    import_at: Vec<(String, usize)>,
    /// Module calls and fields YARA-X types as boolean though libyara
    /// declares an integer (`pe.is_dll()`): not a non-boolean condition.
    yara_x_bool: BTreeSet<(usize, usize)>,
    /// Whether the last field `member` resolved is such a boolean.
    last_member_yara_x_bool: bool,
    /// Identifiers past libyara's 128 characters already reported.
    long_identifiers: BTreeSet<String>,
    /// Rules defined before the current one.
    earlier_rules: BTreeSet<String>,
    rule_wildcards: &'a [(usize, usize)],
    scopes: Vec<BTreeMap<String, Ty>>,
    /// Depth of `for … of` bodies, where the anonymous `$` is the current string.
    in_for_of: usize,
    rule: RuleState,
    /// The current rule's name: a rule wildcard may match it.
    current_rule: String,
    /// Rule wildcards conditions used (`a*` as `a`): libyara refuses a rule
    /// defined after them that they would match.
    used_wildcards: Vec<String>,
    pub findings: Vec<Finding>,
}

/// The longest rule name, tag or meta key libyara 4.5's lexer accepts.
const MAX_IDENTIFIER: usize = 128;

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
            import_at: Vec::new(),
            yara_x_bool: BTreeSet::new(),
            last_member_yara_x_bool: false,
            long_identifiers: BTreeSet::new(),
            earlier_rules: BTreeSet::new(),
            rule_wildcards,
            scopes: Vec::new(),
            in_for_of: 0,
            rule: RuleState {
                patterns: Vec::new(),
                uses_them: false,
            },
            current_rule: String::new(),
            used_wildcards: Vec::new(),
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
            self.import_at.push((name.to_string(), at.0));
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
            self.imports = self
                .import_at
                .iter()
                .filter(|(_, offset)| *offset < at.0)
                .map(|(m, _)| m.clone())
                .collect();
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
        self.current_rule = name.to_string();
        if let Some(prefix) = self
            .used_wildcards
            .iter()
            .find(|p| name.starts_with(p.as_str()))
        {
            self.error(
                codes::YARA_RULE_IDENTIFIER_CONFLICT,
                format!("the rule `{name}` matches the rule wildcard `{prefix}*` an earlier condition uses: libyara refuses it"),
                name_at,
            );
        }
        if self.imports.contains(name) {
            // libyara 4.5 accepts it; the module is then unreachable by name.
            self.yara_x(
                format!("YARA-X refuses a rule named like the imported module `{name}`"),
                name_at,
            );
        } else if self.catalog.keywords.contains(name) {
            self.error(
                codes::YARA_RULE_IDENTIFIER_CONFLICT,
                format!("`{name}` is a YARA keyword and cannot name a rule"),
                name_at,
            );
        }
        self.identifier_length("rule name", name, name_at);
        if let Some(tags) = &rule.tags {
            let mut seen = BTreeSet::new();
            for tag in tags {
                self.identifier_length("tag", tag.name, span(&tag.span()));
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
        let findings_before = self.findings.len();
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
            Ty::Regexp => self.yara_x(
                "YARA-X refuses a regular expression as a condition; libyara reads it as true".to_string(),
                cond_at,
            ),
            // YARA-X's non_bool_expr: a predicate it types as boolean is not one.
            Ty::Int | Ty::Float if self.yara_x_bool.contains(&cond_at) => {}
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
        // A condition naming a string the rule lacks is already an error;
        // libyara stops there, so the strings it then leaves unused are not.
        let undefined = self.findings[findings_before..]
            .iter()
            .any(|f| f.code == codes::YARA_UNDEFINED_STRING);
        if !self.rule.uses_them && !undefined {
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

    /// libyara's lexer takes an identifier (every one but a string's: rule
    /// names, tags, meta keys, loop variables, any bare name) of at most 128 characters
    /// (a longer rule name, tag or meta key ends its token); a longer
    /// one is a syntax error there. YARA-X has no limit.
    fn identifier_length(&mut self, kind: &str, name: &str, at: (usize, usize)) {
        // Once per identifier: its first occurrence is libyara's error.
        if self.libyara()
            && name.len() > MAX_IDENTIFIER
            && self.long_identifiers.insert(name.to_string())
        {
            self.error(
                codes::YARA_PARSE_ERROR,
                format!(
                    "the {kind} `{}…` is {} characters long: libyara 4.5 refuses an identifier longer than {MAX_IDENTIFIER}",
                    &name[..24.min(name.len())],
                    name.len()
                ),
                at,
            );
        }
    }

    fn meta(&mut self, rule: &Rule, name_at: (usize, usize)) {
        let metas = rule.meta.as_deref().unwrap_or(&[]);
        for meta in metas {
            self.identifier_length(
                "meta key",
                meta.identifier.name,
                span(&meta.identifier.span()),
            );
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
                // A comma-joined list of known contexts (`file.pe,memory`).
                // A comma-joined list without blanks (harfanglab-1.0 1.3).
                if let Some(bad) = value
                    .split(',')
                    .find(|part| !data.context_values.iter().any(|v| v == part))
                {
                    // On the unknown part of the list, when it is there as written.
                    let written = self.text(at);
                    let part = bad.trim();
                    let at = match written.find(part).filter(|_| !part.is_empty()) {
                        Some(i) => (at.0 + i, at.0 + i + part.len()),
                        None => at,
                    };
                    self.warn(
                        codes::HARFANGLAB_YARA_CONTEXT,
                        format!(
                            "HarfangLab's YARA rules use contexts from {}, joined with commas and no blanks; `{bad}` is none of them",
                            data.context_values.join(", "),
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
                self.regexp_flags(re.regexp.literal, re_at);
                let check = regexp::check(re.regexp.src);
                if check.greedy && check.lazy {
                    self.error(
                        codes::YARA_REGEXP,
                        "greedy and ungreedy quantifiers can't be mixed in a regular expression"
                            .to_string(),
                        re_at,
                    );
                }
                if check.can_match_empty {
                    self.yara_x(
                        "YARA-X refuses a regular expression that can match the empty string"
                            .to_string(),
                        re_at,
                    );
                }
                if check.leading_unbounded_dot && re.regexp.dot_matches_new_line {
                    self.yara_x(
                        "YARA-X refuses a regular expression that starts with an arbitrary prefix (`.*`, `.+`, `.{n,}` under `/s`)".to_string(),
                        re_at,
                    );
                }
                if check.unbounded_dot {
                    self.warn(
                        codes::YARA_SLOW_PATTERN,
                        format!("libyara: {name} contains .*, .+ or .{{x,}}: consider .{{,N}}, .{{1,N}} or .{{x,N}} with a reasonable N"),
                        re_at,
                    );
                }
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
                // libyara splits a string at a long or unbounded jump and
                // needs an atom in every fragment.
                if hex_fragments(&hex.sub_patterns)
                    .iter()
                    .any(|runs| atoms::is_slow(runs))
                {
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
                    // libyara reads a jump bound into a 32-bit signed int:
                    // 2^31 and above wrap negative, which it refuses.
                    let negative = [jump.start, jump.end]
                        .iter()
                        .flatten()
                        .any(|&b| b > i32::MAX as u32);
                    if negative {
                        self.error(
                            codes::YARA_HEX_STRING,
                            if text.contains('-') {
                                format!("invalid negative jump length: libyara reads a bound above {} as negative", i32::MAX)
                            } else {
                                format!("invalid jump length: libyara reads a length above {} as negative", i32::MAX)
                            },
                            at,
                        );
                    }
                    match (jump.start, jump.end) {
                        _ if negative => {}
                        // `[0]` is refused; `[0-0]` libyara reads, YARA-X refuses.
                        // A bound past u32 that wrapped to 0 is reported already.
                        (Some(0), Some(0))
                            if text.contains('-')
                                && !text
                                    .split(|c: char| !c.is_ascii_digit())
                                    .filter_map(|d| d.parse::<u128>().ok())
                                    .any(|v| v > u128::from(u32::MAX)) =>
                        {
                            self.yara_x(
                                "YARA-X refuses the empty jump range `[0-0]`".to_string(),
                                at,
                            )
                        }
                        (Some(0), Some(0)) if text.contains('-') => {}
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
                HexToken::NotByte(b) if b.mask == 0 => self.error(
                    codes::YARA_HEX_STRING,
                    "invalid not operator (~) in hex string: `~??` matches nothing".to_string(),
                    span(&b.span()),
                ),
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
        let at = span(&e.span());
        if matches!(ty, Ty::Int | Ty::Float | Ty::Str)
            && !matches!(e, Expr::LiteralString(_))
            && !self.yara_x_bool.contains(&at)
        {
            // YARA-X's non_bool_expr, on an operand of `and`, `or`, `not`
            // or a loop's body (libyara reads any non-zero value as true).
            self.warn(
                codes::YARA_SUSPICIOUS_EXPRESSION,
                format!(
                    "{} used as a boolean: libyara reads any non-zero value as true",
                    match &ty {
                        Ty::Str => "a string".to_string(),
                        other => other.name().to_string(),
                    }
                ),
                at,
            );
        }
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

    /// F: a member YARA-X types as boolean (`pe.is_dll()`) in arithmetic or
    /// an ordering: libyara computes with its integer, YARA-X refuses it.
    fn yara_x_bool_arithmetic(&mut self, e: &Expr) {
        let at = span(&e.span());
        if self.yara_x_bool.contains(&at) {
            self.yara_x(
                format!(
                    "YARA-X refuses arithmetic or an ordering on `{}`: it is a boolean there",
                    self.text(at)
                ),
                at,
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
                if !self.libyara() {
                    self.yara_x("YARA-X does not support `entrypoint`".to_string(), at);
                }
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
                if (i.is_unsigned || literal_magnitude(i.literal).is_none()) && self.libyara() {
                    self.error(
                        codes::YARA_NUMBER_OUT_OF_RANGE,
                        format!("`{}` does not fit libyara's signed 64-bit integers (YARA-X reads it unsigned)", i.literal),
                        at,
                    );
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
                self.regexp_flags(re.literal, at);
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
            Expr::Ident(ident) => {
                self.identifier_length("identifier", ident.name, span(&ident.span()));
                self.ident(ident)
            }
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
                    // libyara takes a string too (`@a["1"]`).
                    self.expect(
                        &ty,
                        ty.is_int() || ty == Ty::Str,
                        "a string index is an integer",
                        span(&index.span()),
                    );
                    if ty == Ty::Str {
                        self.yara_x(
                            "YARA-X refuses a string as a string index".to_string(),
                            span(&index.span()),
                        );
                    }
                    if const_value(index).is_some_and(|v| v < 1) {
                        self.yara_x(
                            "YARA-X refuses a string index below 1; in libyara it is always undefined".to_string(),
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
                        Expr::Ident(ident) => {
                            self.identifier_length("identifier", ident.name, span(&ident.span()));
                            self.member(ty, ident.name, span(&ident.span()))
                        }
                        // `pe.signatures[0].valid_on(0)`: the call is on the
                        // value the access has reached.
                        Expr::FuncCall(call) if call.object.is_none() => {
                            self.call_on(Some(ty), call, span(&call.span()))
                        }
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
                // The access is what its last part is: a field or a call
                // YARA-X types as boolean.
                let last_call_bool = match access.operands().last() {
                    Some(Expr::FuncCall(call)) => self.yara_x_bool.contains(&span(&call.span())),
                    _ => false,
                };
                if self.last_member_yara_x_bool || last_call_bool {
                    self.yara_x_bool.insert(at);
                }
                ty
            }
            Expr::FuncCall(call) => self.call(call, at),
            Expr::Defined(u) => {
                self.boolean_operand(&u.operand);
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
                self.fold(e, at);
                let ty = self.primary(&u.operand);
                self.yara_x_bool_arithmetic(&u.operand);
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
                self.yara_x_bool_arithmetic(&u.operand);
                self.expect(
                    &ty,
                    ty.is_int(),
                    "`~` takes an integer",
                    span(&u.operand.span()),
                );
                Ty::Int
            }
            Expr::Add(n) | Expr::Sub(n) | Expr::Mul(n) | Expr::Div(n) => {
                self.fold(e, at);
                let mut float = false;
                for operand in n.operands() {
                    let ty = self.primary(operand);
                    self.yara_x_bool_arithmetic(operand);
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
                self.fold(e, at);
                for operand in n.operands() {
                    let ty = self.primary(operand);
                    self.yara_x_bool_arithmetic(operand);
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
                self.fold(e, at);
                for operand in [&b.lhs, &b.rhs] {
                    let ty = self.primary(operand);
                    self.yara_x_bool_arithmetic(operand);
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
                let op = match e {
                    Expr::Eq(_) => Cmp::Eq,
                    Expr::Ne(_) => Cmp::Ne,
                    Expr::Lt(_) => Cmp::Lt,
                    Expr::Gt(_) => Cmp::Gt,
                    Expr::Le(_) => Cmp::Le,
                    _ => Cmp::Ge,
                };
                // A YARA-X literal (`1_000`) is reported on its own.
                let separators = [&b.lhs, &b.rhs]
                    .iter()
                    .any(|e| self.text(span(&e.span())).contains('_'));
                if let Some(always) = constant_comparison(op, &b.lhs, &b.rhs)
                    && !separators
                {
                    self.warn(
                        codes::YARA_SUSPICIOUS_EXPRESSION,
                        if always {
                            "this comparison is always true: it does not depend on the scanned data"
                                .to_string()
                        } else {
                            "this comparison is always false: the rule can never match through it"
                                .to_string()
                        },
                        at,
                    );
                }
                let comparable = (l.is_numeric() && r.is_numeric())
                    || (l.is_str() && r.is_str())
                    || l == Ty::Unknown
                    || r == Ty::Unknown
                    || (l == Ty::Bool && r == Ty::Bool);
                // A member YARA-X types as boolean (`pe.is_dll()`) is one here.
                let (lx, rx) = (
                    self.yara_x_bool.contains(&span(&b.lhs.span())),
                    self.yara_x_bool.contains(&span(&b.rhs.span())),
                );
                let (lb, rb) = (l == Ty::Bool || lx, r == Ty::Bool || rx);
                if (lx || rx) && matches!(op, Cmp::Lt | Cmp::Gt | Cmp::Le | Cmp::Ge) {
                    self.yara_x_bool_arithmetic(&b.lhs);
                    self.yara_x_bool_arithmetic(&b.rhs);
                } else if (lb && !rb && r.is_numeric() && r != Ty::Unknown)
                    || (rb && !lb && l.is_numeric() && l != Ty::Unknown)
                {
                    // YARA-X's bool_int_comparison.
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
                if let (Quantifier::Percentage(e), Some(_)) = (&of.quantifier, &of.anchor) {
                    self.yara_x_only("A percentage with `at` or `in`", span(&e.span()));
                }
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
                if let Quantifier::Percentage(e) = &f.quantifier {
                    self.yara_x_only("A percentage in `for … of`", span(&e.span()));
                }
                let size = self.pattern_set(&f.pattern_set);
                self.quantifier(&f.quantifier, Some(size));
                self.in_for_of += 1;
                self.boolean_operand(&f.body);
                self.in_for_of -= 1;
                Ty::Bool
            }
            Expr::ForIn(f) => {
                if let Quantifier::Percentage(e) = &f.quantifier {
                    self.yara_x_only("A percentage in `for … in`", span(&e.span()));
                }
                self.quantifier(&f.quantifier, None);
                let mut scope = BTreeMap::new();
                let vars: Vec<&Ident> = f.variables.iter().collect();
                for v in &vars {
                    self.identifier_length("loop variable", v.name, span(&v.span()));
                }
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
            self.used_wildcards.push(ident.name.to_string());
            // libyara matches the rule being defined too.
            if !self.earlier_rules.iter().any(|r| r.starts_with(ident.name))
                && !self.current_rule.starts_with(ident.name)
            {
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
        if let Quantifier::Expr(e) | Quantifier::Percentage(e) = q
            && let Some(v) = const_value(e)
            && v < 0
        {
            self.error(
                codes::YARA_NUMBER_OUT_OF_RANGE,
                format!("invalid value in condition: a quantifier of {v}"),
                span(&e.span()),
            );
        }
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
                if const_value(&a.expr).is_some_and(|v| v < 0) {
                    self.yara_x(
                        "YARA-X refuses a negative offset; libyara never matches at one"
                            .to_string(),
                        span(&a.expr.span()),
                    );
                }
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
        let at = span(&range.lower_bound.span().combine(&range.upper_bound.span()));
        match (const_value(&range.lower_bound), const_value(&range.upper_bound)) {
            (Some(lo), _) if lo < 0 => self.error(
                codes::YARA_NUMBER_OUT_OF_RANGE,
                "invalid value in condition: a range lower bound can not be negative".to_string(),
                at,
            ),
            (Some(lo), Some(hi)) if lo > hi => self.error(
                codes::YARA_NUMBER_OUT_OF_RANGE,
                format!("invalid value in condition: the range lower bound {lo} is greater than its upper bound {hi}"),
                at,
            ),
            _ => {}
        }
    }

    /// libyara folds constant integer arithmetic and refuses what overflows
    /// 64 bits, a division by zero and a negative shift. Reported on the
    /// operation that fails, not on the ones around it.
    fn fold(&mut self, e: &Expr, at: (usize, usize)) {
        if let Err(problem) = fold_step(e) {
            let text = self.text(at).to_string();
            self.error(
                codes::YARA_NUMBER_OUT_OF_RANGE,
                format!("{problem} in `{text}`"),
                at,
            );
        }
    }

    /// Regexp modifiers libyara reads: `i`, `s`, `is`, in that order.
    fn regexp_flags(&mut self, literal: &str, at: (usize, usize)) {
        let flags = literal.rsplit_once('/').map_or("", |(_, f)| f);
        if !matches!(flags, "" | "i" | "s" | "is") {
            self.yara_x_only(
                &format!("The regexp modifiers `{flags}` (libyara reads `i`, `s` or `is`)"),
                at,
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
        self.last_member_yara_x_bool = m.yara_x_kind.as_deref() == Some("boolean");
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
        let base = call.object.as_ref().map(|object| self.expr(object));
        self.call_on(base, call, at)
    }

    /// A call on `base`, the value its object (`pe`, or `pe.signatures[0]`
    /// inside a field access) resolved to; `None` for a bare call.
    fn call_on(
        &mut self,
        base: Option<Ty>,
        call: &yara_x_parser::ast::FuncCall,
        at: (usize, usize),
    ) -> Ty {
        let name = call.identifier.name;
        let name_at = span(&call.identifier.span());
        let args: Vec<Ty> = call.args.iter().map(|a| self.expr(a)).collect();
        let Some(base) = base else {
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
        if name == "len" && matches!(base, Ty::Array { .. } | Ty::Dict { .. }) {
            self.yara_x_only("`.len()` on an array or a dictionary", name_at);
            return Ty::Int;
        }
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
            Some(o) => {
                if o.yara_x_ret.as_deref() == Some("boolean") {
                    self.yara_x_bool.insert(at);
                }
                ret_ty(&o.ret)
            }
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

/// The value of a constant integer expression, as libyara folds it; `None`
/// when it is not one or does not fold.
fn const_value(e: &Expr) -> Option<i64> {
    match e {
        Expr::LiteralInteger(i) if !i.is_unsigned => Some(i.value),
        _ => fold_step(e).ok().flatten(),
    }
}

#[derive(Clone, Copy)]
enum Cmp {
    Eq,
    Ne,
    Lt,
    Gt,
    Le,
    Ge,
}

impl Cmp {
    fn eval(self, a: i64, b: i64) -> bool {
        match self {
            Cmp::Eq => a == b,
            Cmp::Ne => a != b,
            Cmp::Lt => a < b,
            Cmp::Gt => a > b,
            Cmp::Le => a <= b,
            Cmp::Ge => a >= b,
        }
    }

    /// `b op a` as `a op' b`.
    fn swapped(self) -> Self {
        match self {
            Cmp::Lt => Cmp::Gt,
            Cmp::Gt => Cmp::Lt,
            Cmp::Le => Cmp::Ge,
            Cmp::Ge => Cmp::Le,
            other => other,
        }
    }
}

/// yara-1.0's invariant or unsatisfiable condition: a comparison of two
/// constants (`1 == 1`), or of `filesize`, never negative, with a constant
/// that decides it (`filesize < 0`, `filesize >= 0`). `Some(result)` when
/// the comparison does not depend on the scanned data.
fn constant_comparison(op: Cmp, lhs: &Expr, rhs: &Expr) -> Option<bool> {
    if let (Some(a), Some(b)) = (const_value(lhs), const_value(rhs)) {
        return Some(op.eval(a, b));
    }
    let (op, c) = match (lhs, rhs) {
        (Expr::Filesize { .. }, other) => (op, const_value(other)?),
        (other, Expr::Filesize { .. }) => (op.swapped(), const_value(other)?),
        _ => return None,
    };
    // `filesize op c` for every filesize >= 0.
    match op {
        Cmp::Lt if c <= 0 => Some(false),
        Cmp::Le if c < 0 => Some(false),
        Cmp::Eq if c < 0 => Some(false),
        Cmp::Gt if c < 0 => Some(true),
        Cmp::Ge if c <= 0 => Some(true),
        Cmp::Ne if c < 0 => Some(true),
        _ => None,
    }
}

/// libyara's product check (`grammar.y`): `|a| > INT64_MAX / |b|` is an
/// overflow, so `4611686018427387904 * -2` is one though `i64::MIN` fits.
fn libyara_mul(a: i64, b: i64) -> Option<i64> {
    if b != 0 && a.unsigned_abs() > i64::MAX as u64 / b.unsigned_abs() {
        return None;
    }
    Some(a.wrapping_mul(b))
}

/// The magnitude of an integer literal as libyara's lexer reads it, before
/// any sign: `None` when it does not fit `i64::MAX`.
fn literal_magnitude(literal: &str) -> Option<i64> {
    // Digit separators are YARA-X syntax, reported on their own.
    let digits = literal.trim_start_matches('-').replace('_', "");
    let digits = digits.as_str();
    let (digits, scale) = if let Some(d) = digits.strip_suffix("KB") {
        (d, 1024)
    } else if let Some(d) = digits.strip_suffix("MB") {
        (d, 1024 * 1024)
    } else {
        (digits, 1)
    };
    let value = if let Some(h) = digits.strip_prefix("0x") {
        i64::from_str_radix(h, 16).ok()
    } else if let Some(o) = digits.strip_prefix("0o") {
        i64::from_str_radix(o, 8).ok()
    } else {
        digits.parse::<i64>().ok()
    };
    value?.checked_mul(scale)
}

/// One folding step: `Ok(Some(v))` the value, `Ok(None)` not constant (or
/// an operand that fails on its own), `Err` this operation fails.
fn fold_step(e: &Expr) -> Result<Option<i64>, &'static str> {
    let nary = |operands: &[Expr], op: fn(i64, i64) -> Option<i64>, what: &'static str| {
        let mut values = operands.iter().map(const_value);
        let Some(Some(mut acc)) = values.next() else {
            return Ok(None);
        };
        for v in values {
            let Some(v) = v else {
                return Ok(None);
            };
            acc = op(acc, v).ok_or(what)?;
        }
        Ok(Some(acc))
    };
    let binary = |l: &Expr, r: &Expr| match (const_value(l), const_value(r)) {
        (Some(a), Some(b)) => Some((a, b)),
        _ => None,
    };
    match e {
        Expr::LiteralInteger(i) if !i.is_unsigned => Ok(Some(i.value)),
        Expr::Minus(u) => match const_value(&u.operand) {
            Some(v) => v.checked_neg().map(Some).ok_or("integer overflow"),
            None => Ok(None),
        },
        Expr::BitwiseNot(u) => Ok(const_value(&u.operand).map(|v| !v)),
        Expr::Add(n) => nary(n.as_slice(), i64::checked_add, "integer overflow"),
        Expr::Sub(n) => nary(n.as_slice(), i64::checked_sub, "integer overflow"),
        Expr::Mul(n) => nary(n.as_slice(), libyara_mul, "integer overflow"),
        Expr::Div(n) => nary(
            n.as_slice(),
            i64::checked_div,
            "division by zero or overflow",
        ),
        Expr::Mod(n) => nary(
            n.as_slice(),
            i64::checked_rem,
            "division by zero or overflow",
        ),
        Expr::Shl(b) | Expr::Shr(b) => match binary(&b.lhs, &b.rhs) {
            Some((_, s)) if s < 0 => Err("a negative shift"),
            Some((a, s)) if s >= 64 => Ok(Some(if matches!(e, Expr::Shr(_)) && a < 0 {
                -1
            } else {
                0
            })),
            Some((a, s)) => Ok(Some(if matches!(e, Expr::Shl(_)) {
                a << s
            } else {
                a >> s
            })),
            None => Ok(None),
        },
        Expr::BitwiseAnd(b) => Ok(binary(&b.lhs, &b.rhs).map(|(x, y)| x & y)),
        Expr::BitwiseOr(b) => Ok(binary(&b.lhs, &b.rhs).map(|(x, y)| x | y)),
        Expr::BitwiseXor(b) => Ok(binary(&b.lhs, &b.rhs).map(|(x, y)| x ^ y)),
        _ => Ok(None),
    }
}

/// A hex string's chain fragments, as libyara splits it at a jump that is
/// unbounded or spans more than `YR_STRING_CHAINING_THRESHOLD` bytes: each
/// fragment's runs of fixed or masked bytes.
fn hex_fragments(sub: &HexSubPattern) -> Vec<Vec<Vec<MaskedByte>>> {
    let mut fragments = vec![Vec::new()];
    let mut current = Vec::new();
    for token in sub.iter() {
        match token {
            HexToken::Byte(b) => current.push((b.value, b.mask)),
            HexToken::NotByte(b) => current.push((b.value, 0x00)),
            HexToken::Jump(j) => {
                if !current.is_empty() {
                    fragments
                        .last_mut()
                        .unwrap()
                        .push(std::mem::take(&mut current));
                }
                let long = j.end.is_none_or(|end| {
                    end.saturating_sub(j.start.unwrap_or(0)) > CHAINING_THRESHOLD
                });
                if long {
                    fragments.push(Vec::new());
                }
            }
            HexToken::Alternative(_) => {
                if !current.is_empty() {
                    fragments
                        .last_mut()
                        .unwrap()
                        .push(std::mem::take(&mut current));
                }
            }
        }
    }
    if !current.is_empty() {
        fragments.last_mut().unwrap().push(current);
    }
    fragments
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
