//! The semantic pass over yara-x-parser's AST: the symbol table (imports,
//! rules, strings, loop variables), types, and every yara-1.0 code that is
//! not a syntax error. The language is YARA-X 1.x (#1225): each check
//! refuses what YARA-X's compiler refuses (`docs/engine/YARA.md`); the
//! warnings follow libyara's and YARA-X's.

use crate::atoms::{self, MaskedByte};
use crate::catalog::{Catalog, Kind, Member};
use crate::{Context, Finding, Profile, regexp};
use opentide_core::{Severity, codes};
use std::cell::RefCell;
use std::collections::{BTreeMap, BTreeSet, HashMap};
use yara_x_parser::Span;
use yara_x_parser::ast::{
    AST, Expr, HexSubPattern, HexToken, Ident, Iterable, MatchAnchor, MetaValue, OfItems, Pattern,
    PatternModifier, PatternSet, Quantifier, Rule, RuleFlags, WithSpan,
};

/// The integer readers libyara and YARA-X build in (`u?int(8|16|32)(be)?`).
const INTEGER_FUNCTIONS: &[&str] = &[
    "int8", "int16", "int32", "uint8", "uint16", "uint32", "int8be", "int16be", "int32be",
    "uint8be", "uint16be", "uint32be",
];

/// The readers only YARA-X builds in: 64-bit integers and floats.
const YARA_X_READERS: &[(&str, Ty)] = &[
    ("int64", Ty::Int),
    ("uint64", Ty::Int),
    ("int64be", Ty::Int),
    ("uint64be", Ty::Int),
    ("float32", Ty::Float),
    ("float64", Ty::Float),
    ("float32be", Ty::Float),
    ("float64be", Ty::Float),
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
    /// Loop variables bound to what YARA-X types as boolean.
    yara_x_bool_vars: BTreeSet<String>,
    /// The parser's parenthesis pairs: `(` to its `)`, and back.
    paren_open: BTreeMap<usize, usize>,
    paren_close: BTreeMap<usize, usize>,
    /// Rules defined before the current one.
    earlier_rules: BTreeSet<String>,
    scopes: Vec<BTreeMap<String, Ty>>,
    /// Depth of `for … of` bodies, where the anonymous `$` is the current string.
    in_for_of: usize,
    rule: RuleState,
    pub findings: Vec<Finding>,
    /// Constant folds, one per node.
    folds: Folds,
}

fn span(s: &Span) -> (usize, usize) {
    (s.start(), s.end())
}

impl<'a> Checker<'a> {
    pub fn new(source: &'a str, ctx: &'a Context) -> Self {
        let pairs = crate::cst::paren_pairs(source);
        Self {
            paren_open: pairs.iter().copied().collect(),
            paren_close: pairs.iter().map(|&(o, c)| (c, o)).collect(),
            source,
            ctx,
            catalog: Catalog::cached(),
            imports: BTreeSet::new(),
            import_at: Vec::new(),
            yara_x_bool: BTreeSet::new(),
            last_member_yara_x_bool: false,
            yara_x_bool_vars: BTreeSet::new(),
            earlier_rules: BTreeSet::new(),
            scopes: Vec::new(),
            in_for_of: 0,
            rule: RuleState {
                patterns: Vec::new(),
                uses_them: false,
            },
            findings: Vec::new(),
            folds: Folds::default(),
        }
    }

    /// `e`'s range as written: from its leftmost operand to its rightmost
    /// ([`start_of`], [`end_of`]), widened to the enclosing parentheses it
    /// cuts through. The pairs are the parser's own `(` and `)` tokens, so a
    /// parenthesis in a string, a regexp or a comment is none, and a range
    /// only ever widens to a pair that matches.
    fn written(&self, e: &Expr) -> (usize, usize) {
        let (mut start, mut end) = (start_of(e), end_of(e));
        loop {
            let open = self
                .paren_open
                .range(start..end)
                .filter_map(|(_, &c)| (c >= end).then_some(c + 1))
                .max();
            let close = self
                .paren_close
                .range(start..end)
                .filter_map(|(_, &o)| (o < start).then_some(o))
                .min();
            if open.is_none() && close.is_none() {
                return (start, end);
            }
            end = open.unwrap_or(end).max(end);
            start = close.unwrap_or(start).min(start);
        }
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

    /// A code the engine only ever warns about (`crate::WARNING_CODES`).
    fn warn(&mut self, code: &'static str, message: String, at: (usize, usize)) {
        debug_assert!(
            crate::always_warning(code),
            "{code} is not in WARNING_CODES"
        );
        self.push(code, Severity::Warning, message, at);
    }

    /// Syntax only YARA-X accepts: an error while the context refuses it
    /// (`yara_x_syntax`), naming the construct and the profile.
    fn yara_x_only(&mut self, feature: &str, at: (usize, usize)) {
        if self.ctx.yara_x_syntax == crate::YaraXSyntax::Refused {
            let who = self.ctx.profile.map_or("this context", Profile::display);
            self.error(
                codes::YARA_X_ONLY_SYNTAX,
                format!("{feature} is YARA-X syntax, and {who} has `yara_x_syntax: refused`: its engine is not known to take it"),
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
                    format!(
                        "YARA has no module `{name}`: yara-1.0 knows {}",
                        self.catalog
                            .known_modules
                            .iter()
                            .cloned()
                            .collect::<Vec<_>>()
                            .join(", ")
                    ),
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
                // A rule with a syntax error: the compiler stops there.
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
                format!("a rule cannot be named like the imported module `{name}`"),
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
        let cond_key = span(&rule.condition.span());
        let cond_at = self.written(&rule.condition);
        match ty {
            Ty::Regexp => self.error(
                codes::YARA_TYPE,
                "a regular expression is not a condition: match it against a string with `matches`"
                    .to_string(),
                cond_at,
            ),
            // YARA-X's non_bool_expr: a predicate it types as boolean is not one.
            Ty::Int | Ty::Float if self.yara_x_bool.contains(&cond_key) => {}
            Ty::Int | Ty::Float => self.warn(
                codes::YARA_SUSPICIOUS_EXPRESSION,
                format!(
                    "the condition is {}, not a boolean: any non-zero value reads as true",
                    ty.name()
                ),
                cond_at,
            ),
            Ty::Str => self.warn(
                codes::YARA_SUSPICIOUS_EXPRESSION,
                "the condition is a string, not a boolean: any non-empty string reads as true"
                    .to_string(),
                cond_at,
            ),
            _ => {}
        }
        // A condition naming a string the rule lacks is already an error;
        // the compiler stops there, so the strings it then leaves unused are not.
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

    fn meta(&mut self, rule: &Rule, name_at: (usize, usize)) {
        let metas = rule.meta.as_deref().unwrap_or(&[]);
        for meta in metas {
            match &meta.value {
                MetaValue::Float((_, s)) => self.yara_x_only("A float meta value", span(s)),
                // The value is unescaped: the quotes are in the source text.
                MetaValue::String((_, s)) | MetaValue::Bytes((_, s))
                    if self.text(span(s)).starts_with("\"\"\"") =>
                {
                    self.yara_x_only("A `\"\"\"` string", span(s));
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
                        "a text string cannot be empty".to_string(),
                        text_at,
                    );
                    return;
                }
                let base64 = pattern.modifiers().base64().is_some()
                    || pattern.modifiers().base64wide().is_some();
                if base64 && value.len() < 3 {
                    self.error(
                        codes::YARA_STRING_MODIFIER,
                        "`base64` and `base64wide` take a string of at least 3 bytes".to_string(),
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
                    self.error(
                        codes::YARA_REGEXP,
                        "a string's regular expression cannot match the empty string".to_string(),
                        re_at,
                    );
                }
                if check.leading_unbounded_dot && re.regexp.dot_matches_new_line {
                    self.error(
                        codes::YARA_REGEXP,
                        "a string's regular expression cannot start with an arbitrary prefix (`.*`, `.+`, `.{n,}` under `/s`)".to_string(),
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
                self.regexp_findings(&check, re_at.0 + 1);
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
                self.hex(&hex.sub_patterns);
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
                    format!("`{name}` does not apply to {kind}"),
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
                self.yara_x_only("Different alphabets for `base64` and `base64wide`", at);
            }
        }
    }

    /// A hex string's jump checks, and the YARA-X-only jump bounds.
    fn hex(&mut self, sub: &HexSubPattern) {
        for token in sub.iter() {
            match token {
                HexToken::Jump(jump) => {
                    let at = span(&jump.span());
                    let text = self.text(at);
                    if text.contains("0x") || text.contains("0o") {
                        self.yara_x_only("A hex or octal jump bound", at);
                    }
                    // A bound past `u32` is the parser's error. YARA-X takes
                    // any jump inside an alternative, unbounded or long.
                    match (jump.start, jump.end) {
                        (Some(0), Some(0)) => {
                            self.error(
                                codes::YARA_HEX_STRING,
                                format!("invalid jump length: `{text}` skips no byte"),
                                at,
                            );
                        }
                        (Some(a), Some(b)) if a > b => {
                            self.error(
                                codes::YARA_HEX_STRING,
                                format!("invalid jump range: {a} is greater than {b}"),
                                at,
                            );
                        }
                        _ => {}
                    }
                }
                HexToken::Alternative(alt) => {
                    for branch in &alt.alternatives {
                        self.hex(branch);
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

    /// An operand of `and`, `or`, `not`, or a loop's body.
    fn boolean_operand(&mut self, e: &Expr) {
        self.operand(e, true);
    }

    /// `e` where YARA takes any value as a truth value: a boolean
    /// operand, or (`non_bool` false) the operand of `defined`, which YARA-X
    /// does not call a non-boolean.
    fn operand(&mut self, e: &Expr, non_bool: bool) {
        let ty = self.expr(e);
        let at = self.written(e);
        if non_bool
            && matches!(ty, Ty::Int | Ty::Float | Ty::Str)
            && !matches!(e, Expr::LiteralString(_))
            && !self.yara_x_bool.contains(&span(&e.span()))
        {
            // YARA-X's non_bool_expr (any non-zero number, any non-empty
            // string, reads as true).
            self.warn(
                codes::YARA_SUSPICIOUS_EXPRESSION,
                match &ty {
                    Ty::Str => {
                        "a string used as a boolean: any non-empty string reads as true".to_string()
                    }
                    other => format!(
                        "{} used as a boolean: any non-zero value reads as true",
                        other.name()
                    ),
                },
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

    /// A member YARA-X types as boolean (`pe.is_dll()`) in arithmetic or an
    /// ordering.
    fn yara_x_bool_arithmetic(&mut self, e: &Expr) {
        self.yara_x_number(e, "in arithmetic or an ordering");
    }

    /// `e` where YARA-X needs an integer or a float (an operand of
    /// arithmetic, an ordering or `!=`, an offset, a range bound, an index,
    /// a quantifier, a function argument): a member YARA-X types as boolean
    /// is refused there.
    fn yara_x_number(&mut self, e: &Expr, place: &str) -> bool {
        let refused = self.yara_x_bool.contains(&span(&e.span()));
        if refused {
            let at = self.written(e);
            self.error(
                codes::YARA_TYPE,
                format!("`{}` is a boolean, not a number {place}", self.text(at)),
                at,
            );
        }
        refused
    }

    /// A comparison or arithmetic operand: YARA's `primary_expression`,
    /// which is never a syntactic boolean.
    fn primary(&mut self, e: &Expr) -> Ty {
        let ty = self.expr(e);
        if ty == Ty::Bool && is_syntactic_boolean(e) {
            self.error(
                codes::YARA_TYPE,
                "YARA compares and computes with integers, floats and strings; this operand is a boolean".to_string(),
                span(&e.span()),
            );
            return Ty::Unknown;
        }
        ty
    }

    fn expr(&mut self, e: &Expr) -> Ty {
        // `key` is the parser's span, which `yara_x_bool` is keyed by; `at`
        // the range as written, which findings use.
        let key = span(&e.span());
        let at = self.written(e);
        match e {
            Expr::True { .. } | Expr::False { .. } => Ty::Bool,
            Expr::Filesize { .. } => Ty::Int,
            Expr::Entrypoint { .. } => {
                self.warn(
                    codes::YARA_ENTRYPOINT_DEPRECATED,
                    "`entrypoint` is deprecated in libyara and refused by YARA-X: use `pe.entry_point` or `elf.entry_point`".to_string(),
                    at,
                );
                self.error(
                    codes::YARA_UNDEFINED_IDENTIFIER,
                    "`entrypoint` is unsupported: use `pe.entry_point` or `elf.entry_point`"
                        .to_string(),
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
                self.regexp_flags(re.literal, at);
                self.regexp_findings(&regexp::check(re.src), at.0 + 1);
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
                    self.yara_x_number(index, "as a string index");
                    self.expect(
                        &ty,
                        ty.is_int(),
                        "a string index is an integer",
                        span(&index.span()),
                    );
                    if let Some(v) = self.folds.value(index).filter(|&v| v < 1) {
                        self.error(
                            codes::YARA_NUMBER_OUT_OF_RANGE,
                            format!("a string's matches are numbered from 1; `{v}` is no index"),
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
                    self.yara_x_bool.insert(key);
                }
                if let Ty::Func { path, .. } = &ty {
                    // A function named, not called (`pe.imphash`): "wrong
                    // usage of identifier".
                    let name = path.rsplit('.').next().unwrap_or(path);
                    self.error(
                        codes::YARA_UNDEFINED_IDENTIFIER,
                        format!("wrong usage of identifier `{name}`: it is a function, call it"),
                        at,
                    );
                    return Ty::Unknown;
                }
                ty
            }
            Expr::FuncCall(call) => self.call(call, at),
            Expr::Defined(u) => {
                self.operand(&u.operand, false);
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
                if let Some(always) = constant_comparison(&self.folds, op, &b.lhs, &b.rhs)
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
                // YARA-X types the member as boolean: it orders no boolean,
                // has no `!=` on one, and compares one with no float.
                let float = l == Ty::Float || r == Ty::Float;
                let place = match op {
                    Cmp::Lt | Cmp::Gt | Cmp::Le | Cmp::Ge => Some("in an ordering"),
                    Cmp::Ne => Some("in `!=`"),
                    Cmp::Eq if float => Some("compared with a float"),
                    Cmp::Eq => None,
                };
                // Once per comparison, as YARA-X reports it.
                if let Some(place) = place
                    && !self.yara_x_number(&b.lhs, place)
                {
                    self.yara_x_number(&b.rhs, place);
                }
                // An ordering on one is refused above, not also suspicious.
                let refused = (lx || rx) && matches!(op, Cmp::Lt | Cmp::Gt | Cmp::Le | Cmp::Ge);
                if !refused
                    && ((lb && !rb && r.is_numeric() && r != Ty::Unknown)
                        || (rb && !lb && l.is_numeric() && l != Ty::Unknown))
                {
                    // yara-1.0: an integer (or float) compared with a boolean.
                    self.warn(
                        codes::YARA_SUSPICIOUS_EXPRESSION,
                        format!(
                            "{} compared with a boolean",
                            if float { "a float" } else { "an integer" }
                        ),
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
                // The variables are what YARA-X types as boolean.
                let mut bool_vars = false;
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
                                t.is_numeric() || t.is_str(),
                                "a loop enumerates integers, floats or strings",
                                span(&item.span()),
                            );
                            // YARA-X's E003: one type for every item.
                            if t != Ty::Unknown && ty != Ty::Unknown && t != ty {
                                self.error(
                                    codes::YARA_TYPE,
                                    format!("a loop enumerates values of one type: this is {}, the first is {}", t.name(), ty.name()),
                                    span(&item.span()),
                                );
                            }
                            if ty == Ty::Unknown {
                                ty = t;
                            }
                        }
                        // YARA-X types `pe.is_dll()` as boolean: it refuses
                        // one among integers (E003); all booleans bind one.
                        let booleans = items
                            .iter()
                            .filter(|i| self.yara_x_bool.contains(&span(&i.span())))
                            .count();
                        if booleans == items.len() {
                            bool_vars = true;
                        } else if booleans > 0 {
                            let first = items
                                .iter()
                                .find(|i| self.yara_x_bool.contains(&span(&i.span())))
                                .unwrap_or(&items[0]);
                            self.yara_x_number(first, "among integers in an enumeration");
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
                let saved = self.yara_x_bool_vars.clone();
                for var in &vars {
                    if bool_vars {
                        self.yara_x_bool_vars.insert(var.name.to_string());
                    } else {
                        self.yara_x_bool_vars.remove(var.name);
                    }
                }
                self.scopes.push(scope);
                self.boolean_operand(&f.body);
                self.scopes.pop();
                self.yara_x_bool_vars = saved;
                Ty::Bool
            }
            Expr::With(w) => {
                self.yara_x_only("The `with` statement", at);
                // Each declaration sees the ones before it.
                self.scopes.push(BTreeMap::new());
                for decl in &w.declarations {
                    let ty = self.expr(&decl.expression);
                    if let Some(scope) = self.scopes.last_mut() {
                        scope.insert(decl.identifier.name.to_string(), ty);
                    }
                }
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
        if !self.earlier_rules.contains(ident.name) && self.lookup_var(ident.name).is_none() {
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
            && let Some(v) = self.folds.value(e)
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
                self.yara_x_number(e, "as a percentage");
                self.expect(
                    &ty,
                    ty.is_int(),
                    "a percentage is an integer",
                    span(&e.span()),
                );
                if let Expr::LiteralInteger(i) = e
                    && !(0..=100).contains(&i.value)
                {
                    self.error(
                        codes::YARA_NUMBER_OUT_OF_RANGE,
                        format!("a percentage is between 0 and 100, not {}", i.value),
                        span(&e.span()),
                    );
                }
            }
            Quantifier::Expr(e) => {
                let ty = self.primary(e);
                self.yara_x_number(e, "as a quantifier");
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
                        && !usize::try_from(i.value).is_ok_and(|v| v <= size)
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
                self.yara_x_number(&a.expr, "as an offset");
                self.expect(
                    &ty,
                    ty.is_int(),
                    "`at` takes an integer offset",
                    span(&a.expr.span()),
                );
                if self.folds.value(&a.expr).is_some_and(|v| v < 0) || is_unsigned(&a.expr) {
                    self.error(
                        codes::YARA_NUMBER_OUT_OF_RANGE,
                        "an offset is between 0 and 2^63 - 1".to_string(),
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
            self.yara_x_number(bound, "as a range bound");
            self.expect(
                &ty,
                ty.is_int(),
                "a range bound is an integer",
                span(&bound.span()),
            );
        }
        let at = span(&range.lower_bound.span().combine(&range.upper_bound.span()));
        if is_unsigned(&range.lower_bound) || is_unsigned(&range.upper_bound) {
            self.error(
                codes::YARA_NUMBER_OUT_OF_RANGE,
                "a range bound is between 0 and 2^63 - 1".to_string(),
                at,
            );
            return;
        }
        match (
            self.folds.value(&range.lower_bound),
            self.folds.value(&range.upper_bound),
        ) {
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

    /// YARA-X folds constant integer arithmetic and refuses what overflows 64
    /// bits and a negative shift (a division by zero is `undefined`, no
    /// error). Reported on the operation that fails, not the ones around it.
    fn fold(&mut self, e: &Expr, at: (usize, usize)) {
        if let Err(problem) = self.folds.step(e).0 {
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

    /// A regexp's findings, `base` the offset of its first byte.
    fn regexp_findings(&mut self, check: &regexp::Check, base: usize) {
        for f in &check.errors {
            self.error(
                codes::YARA_REGEXP,
                format!("invalid regular expression: {}", f.message),
                (base + f.start, base + f.end.max(f.start + 1)),
            );
        }
        for f in &check.refused {
            self.error(
                codes::YARA_REGEXP,
                format!("invalid regular expression: {}", f.message),
                (base + f.start, base + f.end),
            );
        }
        for f in &check.yara_x_only {
            self.yara_x_only(&f.message, (base + f.start, base + f.end));
        }
    }

    fn ident(&mut self, ident: &Ident) -> Ty {
        let name = ident.name;
        let at = span(&ident.span());
        if let Some(ty) = self.lookup_var(name) {
            if self.yara_x_bool_vars.contains(name) {
                self.yara_x_bool.insert(at);
            }
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

    /// Whether a catalogue member is YARA-X's, reporting it when it is not.
    fn available(&mut self, m: &Member, shown: &str, at: (usize, usize)) -> bool {
        if !m.yara_x {
            self.error(
                codes::YARA_UNKNOWN_MODULE_MEMBER,
                format!("YARA-X does not have `{shown}`"),
                at,
            );
        }
        m.yara_x
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
        self.yara_x_number(index, "as an index");
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
            let reader = YARA_X_READERS.iter().find(|(r, _)| *r == name);
            if reader.is_some() {
                self.yara_x_only(&format!("The reader `{name}`"), name_at);
            }
            if INTEGER_FUNCTIONS.contains(&name) || reader.is_some() {
                for a in &call.args {
                    self.yara_x_number(a, "as a function argument");
                }
                if args.len() != 1 || !args[0].is_int() {
                    self.error(
                        codes::YARA_TYPE,
                        format!("`{name}` takes one integer offset"),
                        at,
                    );
                }
                return reader.map_or(Ty::Int, |(_, ty)| ty.clone());
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
        let (module, path) = match self.member(base, name, name_at) {
            Ty::Func { module, path } => (module, path),
            Ty::Unknown => return Ty::Unknown,
            other => {
                // A field, not a function: "is not a function".
                self.error(
                    codes::YARA_UNDEFINED_IDENTIFIER,
                    format!("`{name}` is not a function: it is {}", other.name()),
                    name_at,
                );
                return Ty::Unknown;
            }
        };
        let Some(m) = self.catalog.member(&module, &path) else {
            return Ty::Unknown;
        };
        let candidates: Vec<_> = m.overloads.iter().filter(|o| o.yara_x).collect();
        let found = candidates.iter().find(|o| {
            o.args.len() == args.len()
                && o.args.chars().zip(&args).all(|(want, got)| {
                    let have = got.letter();
                    have == '?' || have == want || (want == 'f' && have == 'i')
                })
        });
        match found {
            Some(o) => {
                // A YARA-X boolean in a number's place, unless a YARA-X
                // overload takes a boolean there (`console.log(pe.is_dll())`).
                for (k, (want, a)) in o.args.chars().zip(&call.args).enumerate() {
                    let boolean_overload = m.overloads.iter().any(|x| {
                        x.yara_x
                            && x.args.len() == call.args.len()
                            && x.args.chars().nth(k) == Some('b')
                    });
                    if matches!(want, 'i' | 'f') && !boolean_overload {
                        self.yara_x_number(a, "as a function argument");
                    }
                }
                if o.yara_x_ret.as_deref() == Some("boolean") {
                    self.yara_x_bool.insert(span(&call.span()));
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

/// Where `e` starts as written: yara-x-parser spans a method call
/// (`pe.is_dll()`) from its name, and an expression whose left operand is
/// one (`pe.is_dll() == 1`) from there too.
fn start_of(e: &Expr) -> usize {
    let own = e.span().start();
    let left = match e {
        Expr::FuncCall(call) => call.object.as_ref().map(start_of),
        Expr::FieldAccess(access) => access.operands().next().map(start_of),
        Expr::Lookup(lookup) => Some(start_of(&lookup.primary)),
        Expr::And(n)
        | Expr::Or(n)
        | Expr::Add(n)
        | Expr::Sub(n)
        | Expr::Mul(n)
        | Expr::Div(n)
        | Expr::Mod(n) => n.operands().next().map(start_of),
        Expr::Eq(b)
        | Expr::Ne(b)
        | Expr::Lt(b)
        | Expr::Gt(b)
        | Expr::Le(b)
        | Expr::Ge(b)
        | Expr::Shl(b)
        | Expr::Shr(b)
        | Expr::BitwiseAnd(b)
        | Expr::BitwiseOr(b)
        | Expr::BitwiseXor(b)
        | Expr::Contains(b)
        | Expr::IContains(b)
        | Expr::StartsWith(b)
        | Expr::IStartsWith(b)
        | Expr::EndsWith(b)
        | Expr::IEndsWith(b)
        | Expr::IEquals(b)
        | Expr::Matches(b) => Some(start_of(&b.lhs)),
        _ => None,
    };
    left.map_or(own, |l| l.min(own))
}

/// Where `e` ends as written: the mirror of [`start_of`], through the
/// right operand.
fn end_of(e: &Expr) -> usize {
    let own = e.span().end();
    let right = match e {
        Expr::FieldAccess(access) => access.operands().last().map(end_of),
        Expr::And(n)
        | Expr::Or(n)
        | Expr::Add(n)
        | Expr::Sub(n)
        | Expr::Mul(n)
        | Expr::Div(n)
        | Expr::Mod(n) => n.operands().last().map(end_of),
        Expr::Eq(b)
        | Expr::Ne(b)
        | Expr::Lt(b)
        | Expr::Gt(b)
        | Expr::Le(b)
        | Expr::Ge(b)
        | Expr::Shl(b)
        | Expr::Shr(b)
        | Expr::BitwiseAnd(b)
        | Expr::BitwiseOr(b)
        | Expr::BitwiseXor(b)
        | Expr::Contains(b)
        | Expr::IContains(b)
        | Expr::StartsWith(b)
        | Expr::IStartsWith(b)
        | Expr::EndsWith(b)
        | Expr::IEndsWith(b)
        | Expr::IEquals(b)
        | Expr::Matches(b) => Some(end_of(&b.rhs)),
        Expr::Not(u) | Expr::Defined(u) | Expr::Minus(u) | Expr::BitwiseNot(u) => {
            Some(end_of(&u.operand))
        }
        _ => None,
    };
    right.map_or(own, |r| r.max(own))
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

/// The value of a constant integer expression that fits `i64`, as YARA-X
/// folds it; `None` when it is not one or does not fold.

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
fn constant_comparison(folds: &Folds, op: Cmp, lhs: &Expr, rhs: &Expr) -> Option<bool> {
    if let (Some(a), Some(b)) = (folds.value(lhs), folds.value(rhs)) {
        return Some(op.eval(a, b));
    }
    let (op, c) = match (lhs, rhs) {
        (Expr::Filesize { .. }, other) => (op, folds.value(other)?),
        (other, Expr::Filesize { .. }) => (op.swapped(), folds.value(other)?),
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

/// A literal above `i64::MAX` (`0xFFFFFFFFFFFFFFFF`), which YARA-X reads as
/// the `i64` of the same bits.
fn is_unsigned(e: &Expr) -> bool {
    matches!(e, Expr::LiteralInteger(i) if i.is_unsigned)
}

/// One folding step's result: `Ok(Some(v))` the value, `Ok(None)` not
/// constant (or an operand that fails on its own), `Err` this operation
/// fails; and whether the expression computes from YARA-X's unsigned
/// integers (a literal above `i64::MAX`: `(0xFFFFFFFFFFFFFFFF \\ 2) * 2`
/// reaches `u64::MAX`).
type Folded = (Result<Option<i128>, &'static str>, bool);

/// Constant folding, as YARA-X folds, with each node folded once: the
/// checker folds at every arithmetic node, and each fold reads its
/// operands' folds, so without the memo a nested expression is folded
/// once per level above it (#1405 review). Keyed by node address: a
/// checker reads one AST, which outlives it.
#[derive(Default)]
struct Folds(RefCell<HashMap<usize, Folded>>);

#[cfg(test)]
thread_local! {
    static COMPUTES: std::cell::Cell<usize> = const { std::cell::Cell::new(0) };
}

impl Folds {
    /// `e`'s constant value as YARA-X's `i64`.
    fn value(&self, e: &Expr) -> Option<i64> {
        self.step(e)
            .0
            .ok()
            .flatten()
            .and_then(|v| i64::try_from(v).ok())
    }

    /// One folding step. Values are `i128`: a literal above `i64::MAX`
    /// (`0xFFFFFFFFFFFFFFFF`) is YARA-X's unsigned integer, and a sum,
    /// difference or product with one may reach `u64::MAX`; without one,
    /// and for a negation, the result must fit `i64`.
    fn step(&self, e: &Expr) -> Folded {
        let key = std::ptr::from_ref(e) as usize;
        if let Some(done) = self.0.borrow().get(&key) {
            return *done;
        }
        let done = self.compute(e);
        self.0.borrow_mut().insert(key, done);
        done
    }

    fn compute(&self, e: &Expr) -> Folded {
        #[cfg(test)]
        COMPUTES.set(COMPUTES.get() + 1);
        const SIGNED: (i128, i128) = (i64::MIN as i128, i64::MAX as i128);
        const UNSIGNED: (i128, i128) = (i64::MIN as i128, u64::MAX as i128);
        let nary = |operands: &[Expr], op: fn(i128, i128) -> Option<i128>| -> Folded {
            let folded: Vec<Folded> = operands.iter().map(|o| self.step(o)).collect();
            let unsigned = folded.iter().any(|f| f.1);
            let values: Option<Vec<i128>> = folded.iter().map(|f| f.0.ok().flatten()).collect();
            let Some(values) = values else {
                return (Ok(None), unsigned);
            };
            let (lo, hi) = if unsigned { UNSIGNED } else { SIGNED };
            let mut acc = values[0];
            for &v in &values[1..] {
                match op(acc, v).filter(|r| (lo..=hi).contains(r)) {
                    Some(r) => acc = r,
                    None => return (Err("integer overflow"), unsigned),
                }
            }
            (Ok(Some(acc)), unsigned)
        };
        let signed = |v: Folded| {
            (
                v.0.map(|v| v.filter(|v| (SIGNED.0..=SIGNED.1).contains(v))),
                v.1,
            )
        };
        let binary = |l: &Expr, r: &Expr| match (self.value(l), self.value(r)) {
            (Some(a), Some(b)) => Some((a, b)),
            _ => None,
        };
        let wide = |v: Option<i64>| (Ok(v.map(i128::from)), false);
        match e {
            Expr::LiteralInteger(i) if i.is_unsigned => (
                Ok(Some(i128::from(u64::from_ne_bytes(i.value.to_ne_bytes())))),
                true,
            ),
            Expr::LiteralInteger(i) => (Ok(Some(i128::from(i.value))), false),
            Expr::Minus(u) => {
                let (v, unsigned) = self.step(&u.operand);
                let v = match v.ok().flatten() {
                    Some(v) if (SIGNED.0..=SIGNED.1).contains(&-v) => Ok(Some(-v)),
                    Some(_) => Err("integer overflow"),
                    None => Ok(None),
                };
                (v, unsigned)
            }
            Expr::BitwiseNot(u) => (
                Ok(self.value(&u.operand).map(|v| i128::from(!v))),
                self.step(&u.operand).1,
            ),
            Expr::Add(n) => nary(n.as_slice(), i128::checked_add),
            Expr::Sub(n) => nary(n.as_slice(), i128::checked_sub),
            Expr::Mul(n) => nary(n.as_slice(), i128::checked_mul),
            // A division by zero or `i64::MIN \\ -1` is `undefined`, no error.
            Expr::Div(n) => {
                let (v, u) = nary(n.as_slice(), |a, b| a.checked_div(b));
                signed((Ok(v.unwrap_or(None)), u))
            }
            Expr::Mod(n) => {
                let (v, u) = nary(n.as_slice(), |a, b| a.checked_rem(b));
                signed((Ok(v.unwrap_or(None)), u))
            }
            Expr::Shl(b) | Expr::Shr(b) => match binary(&b.lhs, &b.rhs) {
                Some((_, s)) if s < 0 => (Err("a negative shift"), false),
                Some((a, s)) if s >= 64 => wide(Some(if matches!(e, Expr::Shr(_)) && a < 0 {
                    -1
                } else {
                    0
                })),
                Some((a, s)) => wide(Some(if matches!(e, Expr::Shl(_)) {
                    a << s
                } else {
                    a >> s
                })),
                None => wide(None),
            },
            Expr::BitwiseAnd(b) => wide(binary(&b.lhs, &b.rhs).map(|(x, y)| x & y)),
            Expr::BitwiseOr(b) => wide(binary(&b.lhs, &b.rhs).map(|(x, y)| x | y)),
            Expr::BitwiseXor(b) => wide(binary(&b.lhs, &b.rhs).map(|(x, y)| x ^ y)),
            _ => wide(None),
        }
    }
}

/// A hex string's chain fragments, as libyara splits it at a jump that is
/// unbounded or spans more than `YR_STRING_CHAINING_THRESHOLD` bytes: each
/// fragment's runs of fixed or masked bytes.
#[expect(
    clippy::unwrap_used,
    reason = "`fragments` starts with one fragment and only grows"
)]
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

    /// Each arithmetic node is folded once, however deep it nests: the
    /// checker folds at every level, and folding read the whole subtree
    /// each time (a 4 KB condition took 1.6 s).
    #[test]
    fn a_nested_expression_is_folded_once_per_node() {
        let depth = 100;
        let condition = format!("{}1{} == 1", "(".repeat(depth), " + 1 - 1)".repeat(depth));
        let source = format!("rule a {{ condition: {condition} }}");
        let before = COMPUTES.get();
        let diagnostics = crate::diagnostics(&source, &crate::Context::default());
        let folds = COMPUTES.get() - before;
        // One `1` and one `+ 1 - 1` (an add, a sub, two literals) per level,
        // and the `== 1`.
        assert!(folds <= 4 * depth + 4, "{folds} folds");
        assert!(
            diagnostics
                .iter()
                .all(|d| d.severity != opentide_core::Severity::Error),
            "{diagnostics:?}"
        );
    }

    #[test]
    fn unescaped_lengths() {
        assert_eq!(unescaped_len("\"abc\""), 3);
        assert_eq!(unescaped_len("\"a\\x09b\""), 3);
        assert_eq!(unescaped_len("\"a\\\"b\""), 3);
    }
}
