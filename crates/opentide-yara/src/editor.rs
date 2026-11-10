//! Editor features over a YARA signature, in byte offsets: symbols, folding,
//! definitions, references and rename of strings and rules, hover,
//! completion and signature help. Strings and rules come from the AST;
//! module chains (`pe.sections[0].name`) are read from the text around the
//! cursor, so they work in a rule that does not parse yet.

use crate::catalog::{Catalog, Kind, Member, leaf_name};
use crate::syntax;
use opentide_core::{CompletionItem, ParameterInformation, SignatureHelp, SignatureInformation};
use std::collections::BTreeSet;
use yara_x_parser::Parser;
use yara_x_parser::ast::{
    AST, Expr, Iterable, MatchAnchor, OfItems, PatternSet, Rule, RuleFlags, WithSpan,
};

pub type Span = (usize, usize);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SymbolKind {
    Rule,
    String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Symbol {
    pub name: String,
    pub kind: SymbolKind,
    /// The whole definition: a rule from its name to its condition, a
    /// string's identifier.
    pub span: Span,
    /// The name itself.
    pub selection: Span,
    pub detail: Option<String>,
    /// The rule a string belongs to.
    pub parent: Option<String>,
}

/// A string identifier written somewhere: `$a`, `#a`, `@a`, `!a`, or a set
/// item `$a` / `$a*`.
#[derive(Debug, Clone)]
struct StringUse {
    /// The name without its sigil (`a`).
    name: String,
    /// The identifier, sigil included.
    span: Span,
    wildcard: bool,
    definition: bool,
}

struct RuleInfo {
    name: String,
    name_span: Span,
    /// From the rule's name to the end of its condition.
    span: Span,
    strings: Vec<StringUse>,
    /// Rule names its condition uses: `(name, span)`.
    rule_refs: Vec<(String, Span)>,
    detail: String,
}

fn span_of(s: &yara_x_parser::Span) -> Span {
    (s.start(), s.end())
}

fn rules(source: &str) -> Vec<RuleInfo> {
    let prepared = syntax::prepare(source);
    let ast = AST::from(Parser::new(prepared.text.as_bytes()));
    ast.rules().map(|r| rule_info(r)).collect()
}

fn rule_info(rule: &Rule) -> RuleInfo {
    let name_span = span_of(&rule.identifier.span());
    let mut info = RuleInfo {
        name: rule.identifier.name.to_string(),
        name_span,
        span: (name_span.0, rule.condition.span().end()),
        strings: Vec::new(),
        rule_refs: Vec::new(),
        detail: {
            let mut d = String::new();
            if rule.flags.contains(RuleFlags::Global) {
                d.push_str("global ");
            }
            if rule.flags.contains(RuleFlags::Private) {
                d.push_str("private ");
            }
            d.push_str("rule");
            if let Some(tags) = &rule.tags {
                d.push_str(" : ");
                d.push_str(&tags.iter().map(|t| t.name).collect::<Vec<_>>().join(" "));
            }
            d
        },
    };
    for pattern in rule.patterns.iter().flatten() {
        let ident = pattern.identifier();
        info.strings.push(StringUse {
            name: ident.name[1..].to_string(),
            span: span_of(&ident.span()),
            wildcard: false,
            definition: true,
        });
    }
    walk(&rule.condition, &mut info);
    info
}

fn string_use(name: &str, span: Span) -> StringUse {
    StringUse {
        name: name[1..].to_string(),
        span,
        wildcard: false,
        definition: false,
    }
}

fn pattern_set(set: &PatternSet, info: &mut RuleInfo) {
    if let PatternSet::Set(items) = set {
        for item in items {
            info.strings.push(StringUse {
                name: item.identifier.trim_start_matches('$').to_string(),
                span: span_of(&item.span()),
                wildcard: item.wildcard,
                definition: false,
            });
        }
    }
}

fn walk(e: &Expr, info: &mut RuleInfo) {
    match e {
        Expr::PatternMatch(m) => {
            info.strings
                .push(string_use(m.identifier.name, span_of(&m.identifier.span())));
            match &m.anchor {
                Some(MatchAnchor::At(a)) => walk(&a.expr, info),
                Some(MatchAnchor::In(i)) => {
                    walk(&i.range.lower_bound, info);
                    walk(&i.range.upper_bound, info);
                }
                None => {}
            }
        }
        Expr::PatternCount(c) => {
            info.strings
                .push(string_use(c.identifier.name, span_of(&c.identifier.span())));
            if let Some(r) = &c.range {
                walk(&r.lower_bound, info);
                walk(&r.upper_bound, info);
            }
        }
        Expr::PatternOffset(p) | Expr::PatternLength(p) => {
            info.strings
                .push(string_use(p.identifier.name, span_of(&p.identifier.span())));
            if let Some(i) = &p.index {
                walk(i, info);
            }
        }
        Expr::Ident(i) => info
            .rule_refs
            .push((i.name.to_string(), span_of(&i.span()))),
        Expr::FieldAccess(_) | Expr::FuncCall(_) | Expr::Lookup(_) => {
            // Module chains: their first identifier is a module, or a loop
            // variable; neither is a rule.
            for child in e.children() {
                if !matches!(child, Expr::Ident(_)) {
                    walk(child, info);
                }
            }
        }
        Expr::Of(of) => {
            match &of.items {
                OfItems::PatternSet(set) => pattern_set(set, info),
                OfItems::BoolExprTuple(items) => items.iter().for_each(|i| walk(i, info)),
            }
            match &of.anchor {
                Some(MatchAnchor::At(a)) => walk(&a.expr, info),
                Some(MatchAnchor::In(i)) => {
                    walk(&i.range.lower_bound, info);
                    walk(&i.range.upper_bound, info);
                }
                None => {}
            }
        }
        Expr::ForOf(f) => {
            pattern_set(&f.pattern_set, info);
            walk(&f.body, info);
        }
        Expr::ForIn(f) => {
            if let Iterable::Range(r) = &f.iterable {
                walk(&r.lower_bound, info);
                walk(&r.upper_bound, info);
            }
            walk(&f.body, info);
        }
        other => other.children().for_each(|c| walk(c, info)),
    }
}

/// Rules and their strings.
pub fn symbols(source: &str) -> Vec<Symbol> {
    let mut out = Vec::new();
    for rule in rules(source) {
        out.push(Symbol {
            name: rule.name.clone(),
            kind: SymbolKind::Rule,
            span: rule.span,
            selection: rule.name_span,
            detail: Some(rule.detail.clone()),
            parent: None,
        });
        for s in rule.strings.iter().filter(|s| s.definition) {
            out.push(Symbol {
                name: format!("${}", s.name),
                kind: SymbolKind::String,
                span: s.span,
                selection: s.span,
                detail: line_at(source, s.span.0).map(|l| l.trim().to_string()),
                parent: Some(rule.name.clone()),
            });
        }
    }
    out
}

fn line_at(source: &str, offset: usize) -> Option<&str> {
    let start = source[..offset].rfind('\n').map_or(0, |i| i + 1);
    let end = source[offset..]
        .find('\n')
        .map_or(source.len(), |i| offset + i);
    source.get(start..end)
}

/// What sits at `offset`: a string of a rule, or a rule.
enum Target {
    String { rule: usize, name: String },
    Rule { name: String },
}

fn contains(span: Span, offset: usize) -> bool {
    offset >= span.0 && offset <= span.1
}

fn target(rules: &[RuleInfo], offset: usize) -> Option<Target> {
    for (i, rule) in rules.iter().enumerate() {
        if contains(rule.name_span, offset) {
            return Some(Target::Rule {
                name: rule.name.clone(),
            });
        }
        if let Some(s) = rule.strings.iter().find(|s| contains(s.span, offset)) {
            if s.name.is_empty() {
                return None;
            }
            return Some(Target::String {
                rule: i,
                name: s.name.clone(),
            });
        }
        if let Some((name, _)) = rule.rule_refs.iter().find(|(_, s)| contains(*s, offset))
            && rules.iter().any(|r| r.name == *name)
        {
            return Some(Target::Rule { name: name.clone() });
        }
    }
    None
}

/// The definition of the string or rule at `offset`.
pub fn definition(source: &str, offset: usize) -> Option<Span> {
    let rules = rules(source);
    match target(&rules, offset)? {
        Target::String { rule, name } => rules[rule]
            .strings
            .iter()
            .find(|s| s.definition && s.name == name)
            .map(|s| s.span),
        Target::Rule { name } => rules.iter().find(|r| r.name == name).map(|r| r.name_span),
    }
}

/// Every place the string or rule at `offset` is written, its definition
/// first when `with_definition`. A wildcard set item (`$a*`) that covers the
/// string counts.
pub fn references(source: &str, offset: usize, with_definition: bool) -> Vec<Span> {
    let rules = rules(source);
    let mut out = Vec::new();
    match target(&rules, offset) {
        Some(Target::String { rule, name }) => {
            for s in &rules[rule].strings {
                let hit = if s.wildcard {
                    name.starts_with(&s.name)
                } else {
                    s.name == name
                };
                if hit && (with_definition || !s.definition) {
                    out.push(s.span);
                }
            }
        }
        Some(Target::Rule { name }) => {
            for rule in &rules {
                if rule.name == name && with_definition {
                    out.push(rule.name_span);
                }
                out.extend(
                    rule.rule_refs
                        .iter()
                        .filter(|(n, _)| *n == name)
                        .map(|(_, s)| *s),
                );
            }
        }
        None => {}
    }
    out.sort();
    out.dedup();
    out
}

/// The edits that rename the string at `offset` to `new_name` (with or
/// without its `$`): each identifier keeps its sigil. An error explains a
/// rename that is refused.
pub fn rename(source: &str, offset: usize, new_name: &str) -> Result<Vec<(Span, String)>, String> {
    let rules = rules(source);
    let Some(Target::String { rule, name }) = target(&rules, offset) else {
        return Err("only a string identifier (`$name`) can be renamed".into());
    };
    let new = new_name.trim_start_matches(['$', '#', '@', '!']);
    if new.is_empty() || !new.chars().all(|c| c.is_ascii_alphanumeric() || c == '_') {
        return Err(format!(
            "`${new}` is not a string identifier: use letters, digits and `_`"
        ));
    }
    let rule = &rules[rule];
    if rule.strings.iter().any(|s| s.definition && s.name == new) {
        return Err(format!("the rule already has a string `${new}`"));
    }
    let mut edits = Vec::new();
    for s in &rule.strings {
        if s.wildcard {
            if name.starts_with(&s.name) && !new.starts_with(&s.name) {
                return Err(format!(
                    "`${}*` matches `${name}` and would not match `${new}`",
                    s.name
                ));
            }
            continue;
        }
        if s.name == name {
            // Keep the sigil: `$`, `#`, `@` or `!`.
            edits.push(((s.span.0 + 1, s.span.1), new.to_string()));
        }
    }
    Ok(edits)
}

/// Fold ranges as byte spans: each rule, each section, and each multi-line
/// hex string or comment.
pub fn folding(source: &str) -> Vec<Span> {
    let Some(tree) = opentide_syntax::parse(opentide_core::LanguageId::Yara, source) else {
        return Vec::new();
    };
    let mut out = Vec::new();
    let mut stack = vec![tree.root_node()];
    while let Some(node) = stack.pop() {
        if matches!(
            node.kind(),
            "rule"
                | "meta_section"
                | "strings_section"
                | "condition_section"
                | "hex_string"
                | "comment"
        ) && node.start_position().row < node.end_position().row
        {
            out.push((node.start_byte(), node.end_byte()));
        }
        let mut cursor = node.walk();
        stack.extend(node.children(&mut cursor));
    }
    out.sort();
    out
}

// --- Module chains ---

/// The dotted chain ending at `offset` (`pe.sections[0].na`), as the text
/// before the cursor, and where it starts.
fn chain_before(source: &str, offset: usize) -> (usize, &str) {
    let bytes = source.as_bytes();
    let mut i = offset.min(source.len());
    let mut depth = 0i32;
    while i > 0 {
        let c = bytes[i - 1];
        match c {
            b']' => depth += 1,
            b'[' if depth > 0 => depth -= 1,
            b'[' => break,
            _ if depth > 0 => {}
            c if c.is_ascii_alphanumeric() || c == b'_' || c == b'.' => {}
            _ => break,
        }
        i -= 1;
    }
    (i, &source[i..offset.min(source.len())])
}

/// `pe.sections[0].name` -> (`pe`, `sections[].name`).
fn chain_path(chain: &str) -> Option<(String, String)> {
    let mut parts = Vec::new();
    let mut depth = 0;
    let mut current = String::new();
    for c in chain.chars() {
        match c {
            '[' => {
                depth += 1;
                if depth == 1 {
                    current.push_str("[]");
                }
            }
            ']' => depth -= 1,
            '.' if depth == 0 => parts.push(std::mem::take(&mut current)),
            c if depth == 0 => current.push(c),
            _ => {}
        }
    }
    parts.push(current);
    let module = parts.first()?.clone();
    Some((module, parts[1..].join(".")))
}

/// The member path for a chain written with indexes: `[]` may be a
/// dictionary's `{}` in the catalogue.
fn resolve<'c>(catalog: &'c Catalog, module: &str, path: &str) -> Option<&'c Member> {
    catalog
        .member(module, path)
        .or_else(|| catalog.member(module, &path.replace("[]", "{}")))
        .or_else(|| {
            // Mixed arrays and dictionaries along the path.
            let segments: Vec<&str> = path.split('.').collect();
            let mut built = String::new();
            for (i, seg) in segments.iter().enumerate() {
                if i > 0 {
                    built.push('.');
                }
                let plain = seg.trim_end_matches("[]");
                built.push_str(plain);
                if seg.ends_with("[]") {
                    let as_dict = format!("{built}{{}}");
                    if catalog
                        .member(module, &built)
                        .is_some_and(|m| m.kind == Kind::Dict)
                    {
                        built = as_dict;
                    } else {
                        built.push_str("[]");
                    }
                }
            }
            catalog.member(module, &built)
        })
}

fn kind_name(m: &Member) -> String {
    match (m.kind, m.element) {
        (Kind::Array, Some(e)) => format!("array of {}", kind_word(e)),
        (Kind::Dict, Some(e)) => format!("dictionary of {}", kind_word(e)),
        (k, _) => kind_word(k).to_string(),
    }
}

fn kind_word(k: Kind) -> &'static str {
    match k {
        Kind::Integer => "integer",
        Kind::Float => "float",
        Kind::String => "string",
        Kind::Boolean => "boolean",
        Kind::Regexp => "regexp",
        Kind::Struct => "structure",
        Kind::Array => "array",
        Kind::Dict => "dictionary",
        Kind::Function => "function",
    }
}

fn arg_names(args: &str) -> Vec<&'static str> {
    args.chars()
        .map(|c| match c {
            'i' => "integer",
            'f' => "float",
            's' => "string",
            'r' => "regexp",
            'b' => "boolean",
            _ => "?",
        })
        .collect()
}

fn engines(m: &Member) -> &'static str {
    match (m.libyara, m.yara_x) {
        (true, true) => "libyara 4.5 and YARA-X",
        (true, false) => "libyara 4.5 only: YARA-X refuses it",
        (false, true) => "YARA-X only: libyara 4.5 refuses it",
        (false, false) => "neither engine",
    }
}

fn member_hover(module: &str, m: &Member) -> String {
    let shown = format!(
        "{module}.{}",
        m.path.replace("[]", "[i]").replace("{}", "[key]")
    );
    let mut out = if m.kind == Kind::Function {
        let sigs: Vec<String> = m
            .overloads
            .iter()
            .map(|o| {
                format!(
                    "{}({}) -> {}",
                    leaf_name(&m.path),
                    arg_names(&o.args).join(", "),
                    o.ret
                )
            })
            .collect();
        format!("```yara\n{}\n```\n\n`{shown}`: function", sigs.join("\n"))
    } else {
        format!("`{shown}`: {}", kind_name(m))
    };
    out.push_str(&format!(" ({})", engines(m)));
    let doc = m
        .doc
        .as_deref()
        .or_else(|| m.overloads.iter().find_map(|o| o.doc.as_deref()));
    if let Some(doc) = doc {
        out.push_str("\n\n");
        out.push_str(doc);
    }
    out
}

/// Short notes on the words libyara builds in.
const BUILTINS: &[(&str, &str)] = &[
    (
        "filesize",
        "`filesize`: the size of the scanned file, in bytes. Undefined when scanning process memory.",
    ),
    (
        "entrypoint",
        "`entrypoint`: deprecated in libyara and refused by YARA-X (`yara_entrypoint_deprecated`). Use `pe.entry_point` or `elf.entry_point`.",
    ),
    ("them", "`them`: every string of the rule."),
    ("all", "`all`: every item of the set."),
    ("any", "`any`: at least one item of the set."),
    ("none", "`none`: no item of the set."),
    ("defined", "`defined x`: true when `x` is not undefined."),
    ("matches", "`string matches /regexp/`"),
    (
        "contains",
        "`string contains string`; `icontains` ignores case.",
    ),
    (
        "startswith",
        "`string startswith string`; `istartswith` ignores case.",
    ),
    (
        "endswith",
        "`string endswith string`; `iendswith` ignores case.",
    ),
    ("iequals", "`string iequals string`: equal, ignoring case."),
    ("at", "`$a at offset`: the string matches at that offset."),
    (
        "in",
        "`$a in (start..end)`: the string matches in that range.",
    ),
    (
        "of",
        "`quantifier of (set)`: how many strings or rules of the set match.",
    ),
    (
        "for",
        "`for quantifier of (set) : ( … )`, `for quantifier x in iterable : ( … )`",
    ),
    ("nocase", "`nocase`: match ignoring case."),
    (
        "wide",
        "`wide`: match the string encoded as two bytes per character.",
    ),
    (
        "ascii",
        "`ascii`: match the string as written (the default without `wide`).",
    ),
    (
        "fullword",
        "`fullword`: match only delimited by non-alphanumeric characters.",
    ),
    (
        "private",
        "`private`: a private rule or string is not reported on its own.",
    ),
    (
        "global",
        "`global`: a global rule must match for any rule of the namespace to match.",
    ),
    (
        "xor",
        "`xor`, `xor(n)`, `xor(a-b)`: match the string xored with each one-byte key.",
    ),
    (
        "base64",
        "`base64`, `base64(\"alphabet\")`: match the base64 encodings of the string.",
    ),
    ("base64wide", "`base64wide`: `base64`, then `wide`."),
];

const KEYWORDS: &[&str] = &[
    "and",
    "or",
    "not",
    "defined",
    "all",
    "any",
    "none",
    "of",
    "them",
    "for",
    "in",
    "at",
    "filesize",
    "entrypoint",
    "matches",
    "contains",
    "icontains",
    "startswith",
    "istartswith",
    "endswith",
    "iendswith",
    "iequals",
    "true",
    "false",
];

const INTEGER_READERS: &[&str] = &[
    "int8", "int16", "int32", "uint8", "uint16", "uint32", "int8be", "int16be", "int32be",
    "uint8be", "uint16be", "uint32be",
];

fn word_at(source: &str, offset: usize) -> (usize, &str) {
    let bytes = source.as_bytes();
    let mut start = offset.min(source.len());
    while start > 0 && (bytes[start - 1].is_ascii_alphanumeric() || bytes[start - 1] == b'_') {
        start -= 1;
    }
    let mut end = offset.min(source.len());
    while end < bytes.len() && (bytes[end].is_ascii_alphanumeric() || bytes[end] == b'_') {
        end += 1;
    }
    (start, &source[start..end])
}

/// Hover at `offset`: a module member, a module, a string, a rule, or a
/// built-in word.
pub fn hover(source: &str, offset: usize) -> Option<String> {
    let catalog = Catalog::cached();
    let (start, word) = word_at(source, offset);
    if word.is_empty() {
        return None;
    }
    // `import "pe"`.
    let line = line_at(source, start).unwrap_or("");
    if line.trim_start().starts_with("import") && catalog.known_modules.contains(word) {
        return Some(module_hover(word));
    }
    // A module chain up to the end of this word.
    let end = start + word.len();
    let (chain_start, chain) = chain_before(source, end);
    if chain.contains('.')
        && let Some((module, path)) = chain_path(chain)
        && catalog.known_modules.contains(&module)
    {
        if start == chain_start {
            return Some(module_hover(&module));
        }
        if let Some(m) = resolve(catalog, &module, &path) {
            return Some(member_hover(&module, m));
        }
    }
    let sigil = start
        .checked_sub(1)
        .and_then(|i| source.as_bytes().get(i))
        .copied();
    let rules = rules(source);
    if let Some(Target::String { rule, name }) = target(
        &rules,
        if matches!(sigil, Some(b'$' | b'#' | b'@' | b'!')) {
            start - 1
        } else {
            start
        },
    ) {
        let r = &rules[rule];
        let def = r.strings.iter().find(|s| s.definition && s.name == name)?;
        let text = line_at(source, def.span.0).unwrap_or("").trim();
        let what = match sigil {
            Some(b'#') => "the number of matches of",
            Some(b'@') => "the offset of a match of",
            Some(b'!') => "the length of a match of",
            _ => "the string",
        };
        return Some(format!(
            "{what} `${name}` in rule `{}`\n\n```yara\n{text}\n```",
            r.name
        ));
    }
    if let Some(r) = rules.iter().find(|r| r.name == word) {
        return Some(format!("```yara\n{} {}\n```", r.detail, r.name));
    }
    if catalog.known_modules.contains(word) {
        return Some(module_hover(word));
    }
    if INTEGER_READERS.contains(&word) {
        let bytes = word
            .trim_start_matches('u')
            .trim_start_matches("int")
            .trim_end_matches("be");
        return Some(format!(
            "`{word}(offset)`: the {}{bytes}-bit integer at `offset` of the file, {}.",
            if word.starts_with('u') {
                "unsigned "
            } else {
                "signed "
            },
            if word.ends_with("be") {
                "big-endian"
            } else {
                "little-endian"
            }
        ));
    }
    BUILTINS
        .iter()
        .find(|(w, _)| *w == word)
        .map(|(_, d)| d.to_string())
}

fn module_hover(module: &str) -> String {
    let catalog = Catalog::cached();
    let count = catalog.children(module, "").count();
    let engines = if catalog.has_libyara_declarations(module) {
        "libyara 4.5"
    } else {
        "YARA-X only (libyara 4.5.4 has no such module)"
    };
    format!(
        "YARA module `{module}`: {count} top-level members ({engines}). Needs `import \"{module}\"`."
    )
}

// --- Completion ---

fn item(label: &str, kind: &str, detail: Option<String>, doc: Option<String>) -> CompletionItem {
    let mut i = CompletionItem::new(label, kind);
    i.detail = detail;
    i.documentation = doc;
    i
}

fn imported(source: &str) -> BTreeSet<String> {
    let mut out = BTreeSet::new();
    for line in source.lines() {
        let t = line.trim_start();
        if let Some(rest) = t.strip_prefix("import") {
            let m = rest.trim().trim_matches('"');
            if !m.is_empty() {
                out.insert(m.to_string());
            }
        }
    }
    out
}

/// The strings defined in the rule whose text holds `offset`, read from the
/// text so a half-written condition still completes.
fn strings_in_rule(source: &str, offset: usize) -> Vec<String> {
    let head = &source[..offset.min(source.len())];
    let rule_start = head.rfind("rule ").unwrap_or(0);
    let tail_end = source[offset.min(source.len())..]
        .find("\nrule ")
        .map_or(source.len(), |i| offset + i);
    let region = &source[rule_start..tail_end];
    let mut out = Vec::new();
    for line in region.lines() {
        let t = line.trim_start();
        if let Some(rest) = t.strip_prefix('$') {
            let name: String = rest
                .chars()
                .take_while(|c| c.is_ascii_alphanumeric() || *c == '_')
                .collect();
            if rest[name.len()..].trim_start().starts_with('=') && !out.contains(&name) {
                out.push(name);
            }
        }
    }
    out
}

/// Completion at `offset`.
pub fn completions(source: &str, offset: usize) -> Vec<CompletionItem> {
    let catalog = Catalog::cached();
    let offset = offset.min(source.len());
    let line_start = source[..offset].rfind('\n').map_or(0, |i| i + 1);
    let before = &source[line_start..offset];
    // `import "`.
    if before.trim_start().starts_with("import") {
        return catalog
            .known_modules
            .iter()
            .map(|m| {
                item(
                    m,
                    "module",
                    Some("YARA module".into()),
                    Some(module_hover(m)),
                )
            })
            .collect();
    }
    // `$`, `#`, `@`, `!` and a partial name.
    let (word_start, _) = word_at(source, offset);
    if let Some(&sigil) = word_start
        .checked_sub(1)
        .and_then(|i| source.as_bytes().get(i))
        && matches!(sigil, b'$' | b'#' | b'@' | b'!')
    {
        let s = sigil as char;
        return strings_in_rule(source, offset)
            .into_iter()
            .map(|n| item(&format!("{s}{n}"), "reference", Some("string".into()), None))
            .collect();
    }
    // A member of a module chain.
    let (_, chain) = chain_before(source, offset);
    if let Some(dot) = chain.rfind('.') {
        let parent = &chain[..dot];
        if let Some((module, path)) = chain_path(parent)
            && catalog.known_modules.contains(&module)
        {
            let parent_path = if path.is_empty() {
                String::new()
            } else if let Some(m) = resolve(catalog, &module, &path) {
                m.path.clone()
            } else if let Some(container) = path.strip_suffix("[]") {
                // An element: `sections[0].` lists `sections[].*`.
                match resolve(catalog, &module, container) {
                    Some(m) if m.kind == Kind::Array => format!("{}[]", m.path),
                    Some(m) if m.kind == Kind::Dict => format!("{}{{}}", m.path),
                    _ => return Vec::new(),
                }
            } else {
                return Vec::new();
            };
            return catalog
                .children(&module, &parent_path)
                .filter(|m| m.libyara || !catalog.has_libyara_declarations(&module))
                .map(|m| {
                    let label = leaf_name(&m.path).to_string();
                    let kind = if m.kind == Kind::Function {
                        "function"
                    } else {
                        "property"
                    };
                    item(
                        &label,
                        kind,
                        Some(kind_name(m)),
                        Some(member_hover(&module, m)),
                    )
                })
                .collect();
        }
    }
    // Anywhere else in a rule: keywords, readers, modules, rules.
    let mut out: Vec<CompletionItem> = KEYWORDS
        .iter()
        .map(|k| {
            item(
                k,
                "keyword",
                None,
                BUILTINS
                    .iter()
                    .find(|(w, _)| w == k)
                    .map(|(_, d)| d.to_string()),
            )
        })
        .collect();
    out.extend(
        INTEGER_READERS
            .iter()
            .map(|f| item(f, "function", Some("integer reader".into()), None)),
    );
    out.extend(
        imported(source)
            .into_iter()
            .map(|m| item(&m, "module", Some("imported module".into()), None)),
    );
    let rule_start = source[..offset].rfind("rule ").unwrap_or(0);
    out.extend(
        rules(source)
            .into_iter()
            .filter(|r| r.name_span.0 < rule_start)
            .map(|r| item(&r.name, "reference", Some(r.detail.clone()), None)),
    );
    out
}

/// Signature help inside a module function call or an integer reader.
pub fn signature_help(source: &str, offset: usize) -> Option<SignatureHelp> {
    let offset = offset.min(source.len());
    let bytes = source.as_bytes();
    // The innermost `(` still open before the cursor.
    let mut depth = 0i32;
    let mut commas = 0u32;
    let mut i = offset;
    while i > 0 {
        i -= 1;
        match bytes[i] {
            b')' => depth += 1,
            b'(' if depth == 0 => break,
            b'(' => depth -= 1,
            b',' if depth == 0 => commas += 1,
            b'\n' if depth == 0 && source[i..offset].contains("condition") => return None,
            _ => {}
        }
        if i == 0 {
            return None;
        }
    }
    if bytes.get(i) != Some(&b'(') {
        return None;
    }
    let (_, chain) = chain_before(source, i);
    let catalog = Catalog::cached();
    let signatures: Vec<SignatureInformation> = if INTEGER_READERS.contains(&chain) {
        vec![SignatureInformation {
            label: format!("{chain}(offset)"),
            documentation: hover(source, i - 1),
            parameters: vec![ParameterInformation {
                label: "offset".into(),
                documentation: Some("integer".into()),
            }],
        }]
    } else {
        let (module, path) = chain_path(chain)?;
        let m = resolve(catalog, &module, &path)?;
        if m.kind != Kind::Function {
            return None;
        }
        m.overloads
            .iter()
            .filter(|o| o.libyara || !catalog.has_libyara_declarations(&module))
            .map(|o| {
                let args = arg_names(&o.args);
                SignatureInformation {
                    label: format!("{}({}) -> {}", leaf_name(&m.path), args.join(", "), o.ret),
                    documentation: o.doc.clone().or_else(|| m.doc.clone()),
                    parameters: args
                        .iter()
                        .map(|a| ParameterInformation {
                            label: a.to_string(),
                            documentation: None,
                        })
                        .collect(),
                }
            })
            .collect()
    };
    if signatures.is_empty() {
        return None;
    }
    let active = signatures
        .iter()
        .position(|s| s.parameters.len() > commas as usize)
        .unwrap_or(0) as u32;
    Some(SignatureHelp {
        signatures,
        active_signature: active,
        active_parameter: commas,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    const SIG: &str = "import \"pe\"\n\nprivate rule mz {\n  condition:\n    uint16(0) == 0x5A4D\n}\n\nrule loader : apt {\n  strings:\n    $cfg = \"CFG!\"\n    $cfg2 = \"CFG2\"\n  condition:\n    mz and #cfg > 1 and @cfg[1] < 100 and any of ($cfg*) and pe.sections[0].name == \".text\" and pe.exports(\"x\")\n}\n";

    fn at(s: &str) -> usize {
        SIG.find(s).unwrap()
    }

    #[test]
    fn symbols_list_rules_and_strings() {
        let names: Vec<String> = symbols(SIG).into_iter().map(|s| s.name).collect();
        assert_eq!(names, ["mz", "loader", "$cfg", "$cfg2"]);
    }

    #[test]
    fn definition_and_references_of_a_string() {
        let def = definition(SIG, at("#cfg") + 1).unwrap();
        assert_eq!(&SIG[def.0..def.1], "$cfg");
        let refs = references(SIG, at("@cfg") + 2, true);
        let texts: Vec<&str> = refs.iter().map(|s| &SIG[s.0..s.1]).collect();
        assert_eq!(texts, ["$cfg", "#cfg", "@cfg", "$cfg*"]);
    }

    #[test]
    fn definition_of_a_rule() {
        let def = definition(SIG, at("mz and") + 1).unwrap();
        assert_eq!(def, (at("mz {"), at("mz {") + 2));
        assert_eq!(references(SIG, at("mz {"), false).len(), 1);
    }

    #[test]
    fn rename_keeps_sigils_and_guards_wildcards() {
        let edits = rename(SIG, at("$cfg2"), "$config2").unwrap_err();
        assert!(edits.contains("$cfg*"), "{edits}");
        let edits = rename(SIG, at("$cfg2"), "cfg_extra").unwrap();
        assert_eq!(edits.len(), 1);
        assert_eq!(edits[0].1, "cfg_extra");
        let edits = rename(SIG, at("#cfg"), "cfgx").unwrap();
        let mut out = SIG.to_string();
        for ((s, e), t) in edits.iter().rev() {
            out.replace_range(*s..*e, t);
        }
        assert!(out.contains("$cfgx = ") && out.contains("#cfgx > 1") && out.contains("@cfgx[1]"));
        assert!(rename(SIG, at("$cfg2"), "cfg").is_err());
        assert!(rename(SIG, at("mz {"), "x").is_err());
    }

    #[test]
    fn hover_members_strings_and_builtins() {
        let h = hover(SIG, at("name ==") + 1).unwrap();
        assert!(
            h.contains("pe.sections[i].name") && h.contains("string"),
            "{h}"
        );
        let h = hover(SIG, at("exports") + 2).unwrap();
        assert!(h.contains("exports(string) -> integer"), "{h}");
        let h = hover(SIG, at("#cfg") + 2).unwrap();
        assert!(
            h.contains("number of matches") && h.contains("$cfg = \"CFG!\""),
            "{h}"
        );
        assert!(hover(SIG, at("uint16") + 1).unwrap().contains("16-bit"));
        assert!(
            hover(SIG, at("\"pe\"") + 1)
                .unwrap()
                .contains("YARA module `pe`")
        );
    }

    #[test]
    fn completion_contexts() {
        let labels = |text: &str| -> Vec<String> {
            completions(text, text.len())
                .into_iter()
                .map(|i| i.label)
                .collect()
        };
        assert!(labels("import \"").contains(&"pe".to_string()));
        let l = labels("import \"pe\"\nrule a { condition: pe.");
        assert!(
            l.contains(&"number_of_sections".to_string()) && l.contains(&"imphash".to_string())
        );
        let l = labels("import \"pe\"\nrule a { condition: pe.sections[0].");
        assert!(l.contains(&"name".to_string()), "{l:?}");
        let l = labels("rule a {\n  strings:\n    $ab = \"x\"\n  condition:\n    #a");
        assert_eq!(l, ["#ab"]);
        let l = labels("rule p { condition: true }\nrule a { condition: ");
        assert!(l.contains(&"p".to_string()) && l.contains(&"filesize".to_string()));
    }

    #[test]
    fn signature_help_for_calls() {
        let text = "import \"pe\"\nrule a { condition: pe.exports(";
        let h = signature_help(text, text.len()).unwrap();
        assert!(
            h.signatures
                .iter()
                .any(|s| s.label == "exports(string) -> integer")
        );
        let text = "import \"math\"\nrule a { condition: math.entropy(0, ";
        let h = signature_help(text, text.len()).unwrap();
        assert_eq!(h.active_parameter, 1);
        assert_eq!(
            h.signatures[h.active_signature as usize].parameters.len(),
            2
        );
        let text = "rule a { condition: uint16(";
        assert_eq!(
            signature_help(text, text.len()).unwrap().signatures[0].label,
            "uint16(offset)"
        );
    }

    #[test]
    fn folding_rules_and_sections() {
        let spans = folding(SIG);
        assert!(spans.iter().any(|s| &SIG[s.0..s.0 + 4] == "rule"));
        assert!(spans.iter().any(|s| SIG[s.0..].starts_with("strings:")));
    }
}
