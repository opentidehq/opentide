//! The checks that read one node at a time, over the whole text: calls,
//! field paths, comparisons, literals, variables.

use super::checker::{Checker, section_name};
use super::nav::{
    At, at, at_token, field_segments, is_literal, is_string, literal_kind, literal_text, unparen,
};
use super::support::{GROUPED_FIELDS, closest, leading_wildcard, regex_problem};
use crate::Profile;
use crate::ast::{Comparison, FunctionCall, InExpr, QuantifiedField, TableCall};
use crate::catalog::{Functions, Segment, TypeKind, Udm, is_keyword};
use crate::syntax::{SyntaxKind as K, SyntaxNode, SyntaxToken};
use opentide_core::{Severity, codes};
use opentide_parse::ast::AstNode;
use rowan::NodeOrToken;

impl Checker<'_> {
    /// The checks that read one node at a time, in the order of the tree.
    pub(super) fn walk_all(&mut self, root: &SyntaxNode) {
        for element in root.descendants_with_tokens() {
            match element {
                NodeOrToken::Node(n) => self.node(&n),
                NodeOrToken::Token(t) => match t.kind() {
                    K::STRING => self.escapes(&t),
                    K::REGEX_LIT => {
                        let text = t.text();
                        let pattern = &text[1..text.len().saturating_sub(1).max(1)];
                        self.pattern(pattern, at_token(&t));
                    }
                    _ => {}
                },
            }
        }
    }

    fn node(&mut self, n: &SyntaxNode) {
        match n.kind() {
            K::FUNCTION_CALL => self.call(n),
            K::TABLE_CALL => {
                let section = n.ancestors().skip(1).find_map(|a| section_name(a.kind()));
                self.table_call(n, section);
            }
            K::NAME_REF
                if !n.ancestors().skip(1).any(|a| {
                    matches!(
                        a.kind(),
                        K::NAMED_ARGUMENT | K::META_ENTRY | K::OPTION_ENTRY
                    )
                }) =>
            {
                self.bare_name(n);
            }
            K::UDM_FIELD | K::BARE_FIELD => self.field(n),
            K::COMPARISON => self.comparison(n),
            K::QUANTIFIED_FIELD => self.quantified(n),
            K::VARIABLE => {
                let text = self.text(n);
                let bare = &text[1..];
                if matches!(
                    bare.to_ascii_lowercase().as_str(),
                    "window_start" | "window_end"
                ) {
                    self.error(
                        codes::YARAL_RESERVED_IDENTIFIER,
                        format!("`{text}` is reserved: window_start and window_end are the match window's bounds"),
                        at(n),
                    );
                } else if is_keyword(bare) {
                    self.error(
                        codes::YARAL_RESERVED_IDENTIFIER,
                        format!("`{bare}` is a YARA-L keyword, not a variable name"),
                        at(n),
                    );
                }
            }
            K::IN_EXPR => {
                if let Some(right) = InExpr::cast(n.clone()).and_then(|i| i.right())
                    && right.syntax().kind() == K::REFERENCE_LIST
                {
                    self.warning(
                        codes::YARAL_REFERENCE_LIST_DEPRECATED,
                        format!(
                            "`{}` is a reference list: Google deprecates reference lists from May 2027; use a data table (`%table.column`)",
                            self.text(right.syntax())
                        ),
                        at(right.syntax()),
                    );
                }
            }
            _ => {}
        }
    }

    /// A bare name as a term: a search's grouped field or `raw`
    /// (search-syntax-reference); a metric field only inside a `metrics.*`
    /// argument, which `walk_all` leaves alone.
    fn bare_name(&mut self, node: &SyntaxNode) {
        let name = self.text(node);
        if self.profile == Profile::Search && (GROUPED_FIELDS.contains(&name) || name == "raw") {
            return;
        }
        let message = match self.profile {
            Profile::Search => format!(
                "`{name}` is not a UDM field: a search names a full path (`principal.hostname`), a grouped field ({}) or `raw`",
                GROUPED_FIELDS.join(", ")
            ),
            Profile::Rule => format!(
                "`{name}` is not a field: a rule reads fields through an event variable (`$e.principal.hostname`); grouped fields and `raw` are search only"
            ),
        };
        self.error(codes::YARAL_UNKNOWN_UDM_FIELD, message, at(node));
    }

    /// A call's name, without blanks.
    pub(super) fn function_name(&self, call: &SyntaxNode) -> String {
        call.children()
            .find(|n| n.kind() == K::FUNCTION_NAME)
            .map(|f| self.text(&f).split_whitespace().collect::<String>())
            .unwrap_or_default()
    }

    fn call(&mut self, call: &SyntaxNode) {
        let name = self.function_name(call);
        let at_name = call
            .children()
            .find(|n| n.kind() == K::FUNCTION_NAME)
            .map_or_else(|| at(call), |f| at(&f));
        let arguments: Vec<SyntaxNode> = FunctionCall::cast(call.clone())
            .and_then(|c| c.arguments())
            .map(|a| a.syntax().children().collect())
            .unwrap_or_default();
        let functions = Functions::cached();
        let Some(function) = functions.get(&name) else {
            let namespace = name.split_once('.').map(|(ns, _)| ns);
            let message = match namespace {
                Some(ns) if functions.is_namespace(ns) => {
                    let short = name.rsplit('.').next().unwrap_or(&name);
                    let suggestion =
                        closest(short, functions.in_namespace(ns).map(|f| f.short_name()));
                    match suggestion {
                        Some(s) => format!(
                            "`{name}` is not a function of `{ns}`; did you mean `{ns}.{s}`?"
                        ),
                        None => format!("`{name}` is not a function of `{ns}`"),
                    }
                }
                Some(ns) => format!("`{ns}` is not a YARA-L function namespace"),
                None => {
                    match closest(
                        &name,
                        functions
                            .all()
                            .filter(|f| f.namespace.is_none())
                            .map(|f| f.name.as_str()),
                    ) {
                        Some(s) => {
                            format!("`{name}` is not a YARA-L function; did you mean `{s}`?")
                        }
                        None => format!("`{name}` is not a YARA-L function"),
                    }
                }
            };
            self.error(codes::YARAL_UNKNOWN_FUNCTION, message, at_name);
            return;
        };
        let count = arguments.len();
        let too_few = count < function.min_args;
        let too_many = function.max_args.is_some_and(|max| count > max);
        if too_few || too_many {
            let expected = match function.max_args {
                Some(max) if max == function.min_args => format!("{max}"),
                Some(max) => format!("{} to {max}", function.min_args),
                None => format!("at least {}", function.min_args),
            };
            self.error(
                codes::YARAL_UNKNOWN_FUNCTION,
                format!(
                    "`{name}` takes {expected} argument{}, not {count}: {}",
                    if expected == "1" { "" } else { "s" },
                    function.signature
                ),
                at_name,
            );
        }
        if !function.available_in(self.profile) {
            let instead = match name.as_str() {
                "avg" | "stddev" => format!("; a rule writes `window.{name}`"),
                _ => String::new(),
            };
            self.error(
                codes::YARAL_FUNCTION_UNAVAILABLE,
                format!(
                    "`{name}` is not available in a {}{instead}",
                    self.profile.noun()
                ),
                at_name,
            );
        }
        // re.* patterns.
        if matches!(
            name.as_str(),
            "re.regex" | "re.capture" | "re.capture_all" | "re.replace"
        ) && let Some(pattern) = arguments.get(1)
            && is_string(pattern)
            && let Some(text) = literal_text(pattern)
        {
            self.pattern(&text, at(pattern));
        }
    }

    fn table_call(&mut self, call: &SyntaxNode, section: Option<&str>) {
        let Some(function) = TableCall::cast(call.clone()).and_then(|c| c.function()) else {
            return;
        };
        let name = function.text();
        if name != "write_row" {
            self.error(
                codes::YARAL_UNKNOWN_FUNCTION,
                format!("`{name}` is not a data table function: `export` writes rows with `%table.write_row(column: $value, ...)`"),
                at_token(&function),
            );
        } else if section != Some("export") {
            self.error(
                codes::YARAL_UNKNOWN_FUNCTION,
                "`write_row` writes a data table row in `export`, the last section".into(),
                at_token(&function),
            );
        }
    }

    fn pattern(&mut self, pattern: &str, at: At) {
        if let Some(problem) = regex_problem(pattern) {
            self.error(
                codes::YARAL_REGEX,
                format!("not a valid RE2 regular expression: {problem}"),
                at,
            );
        } else if leading_wildcard(pattern) {
            self.warning(
                codes::YARAL_LEADING_WILDCARD_REGEX,
                "the regex starts with `.*`: RE2 matches anywhere in the value already, and the prefix only costs time".into(),
                at,
            );
        }
    }

    /// `yaral_string_escape` on one string token.
    pub(crate) fn escapes(&mut self, token: &SyntaxToken) {
        let text = token.text();
        let start_of_token = usize::from(token.text_range().start());
        let bytes = text.as_bytes();
        let mut i = 1;
        while i + 1 < bytes.len() {
            if bytes[i] == b'\\' {
                let next = text[i + 1..].chars().next().unwrap_or(' ');
                if !matches!(next, '\\' | '"' | 'n' | 'r' | 't') {
                    let start = start_of_token + i;
                    self.push(
                        codes::YARAL_STRING_ESCAPE,
                        Severity::Warning,
                        format!("`\\{next}` is not an escape: a double-quoted string takes \\\\, \\\", \\n, \\r and \\t; write `\\\\{next}`, or a back-quoted string for a regex"),
                        (start, start + 1 + next.len_utf8()),
                    );
                }
                i += 1 + text[i + 1..].chars().next().map_or(1, char::len_utf8);
                continue;
            }
            i += 1;
        }
    }

    fn field(&mut self, field: &SyntaxNode) {
        if self.stage_field(field) {
            return;
        }
        // A `metrics.*` argument names the metric's fields bare
        // (`principal.asset.ip: $ip`, `filter: principal.hostname = "h"`).
        let in_argument = field
            .ancestors()
            .skip(1)
            .any(|n| n.kind() == K::NAMED_ARGUMENT);
        if self.profile == Profile::Rule && field.kind() == K::BARE_FIELD && !in_argument {
            let path = self.text(field);
            self.error(
                codes::YARAL_UNKNOWN_UDM_FIELD,
                format!(
                    "`{path}` is not a field: a rule reads fields through an event variable (`$e.{path}`)"
                ),
                at(field),
            );
            return;
        }
        let segs = field_segments(field);
        let udm = Udm::cached();
        let resolution = udm.resolve(&segs);
        if self.profile == Profile::Search
            && resolution.unknown.is_some_and(|(index, _)| index == 0)
        {
            // `$zzz.u`: a stage reference the tenant checks (yara-l-1.0
            // 1.1, "Checked by the tenant only"); `labels["k"]`: a search's
            // top-level map.
            let top_map = field.kind() == K::BARE_FIELD
                && matches!(segs.as_slice(), [Segment::Name(n, _), Segment::Key(_), ..] if n == "labels");
            if field.kind() == K::UDM_FIELD || top_map {
                return;
            }
        }
        if let Some((index, message)) = resolution.unknown
            && let Some(Segment::Name(name, at)) = segs.get(index)
        {
            let candidates = udm
                .message(message)
                .map(|m| m.fields.iter().map(|f| f.name.as_str()).collect::<Vec<_>>())
                .unwrap_or_default();
            let path: Vec<&str> = segs[..index]
                .iter()
                .filter_map(|s| match s {
                    Segment::Name(n, _) => Some(n.as_str()),
                    _ => None,
                })
                .collect();
            let under = if path.is_empty() {
                "the UDM event".to_string()
            } else {
                format!("`{}` ({message})", path.join("."))
            };
            let mut message = format!("`{name}` is not a field of {under}");
            if let Some(s) = closest(name, candidates.into_iter()) {
                message.push_str(&format!("; did you mean `{s}`?"));
            }
            self.push(
                codes::YARAL_UNKNOWN_UDM_FIELD,
                Severity::Error,
                message,
                *at,
            );
        }
        for (index, f) in resolution.deprecated {
            if let Some(Segment::Name(name, at)) = segs.get(index) {
                let doc = f.doc.as_deref().unwrap_or("");
                self.push(
                    codes::YARAL_DEPRECATED_FIELD,
                    Severity::Warning,
                    format!("`{name}` is deprecated in the UDM. {doc}")
                        .trim_end()
                        .to_string(),
                    *at,
                );
            }
        }
    }

    /// The UDM type of an operand, when it is a field path the catalogue has.
    fn operand_kind(&self, node: &SyntaxNode) -> Option<(TypeKind<'static>, bool)> {
        let node = unparen(node.clone());
        let field = match node.kind() {
            K::UDM_FIELD | K::BARE_FIELD => node,
            K::QUANTIFIED_FIELD => QuantifiedField::cast(node)?.field()?.syntax().clone(),
            _ => return None,
        };
        if !matches!(field.kind(), K::UDM_FIELD | K::BARE_FIELD) || self.stage_field(&field) {
            return None;
        }
        let r = Udm::cached().resolve(&field_segments(&field));
        if r.unknown.is_some() || r.free {
            return None;
        }
        Some((r.kind?, r.map_key))
    }

    fn comparison(&mut self, node: &SyntaxNode) {
        let Some(comparison) = Comparison::cast(node.clone()) else {
            return;
        };
        let (Some(left), Some(right)) = (comparison.left(), comparison.right()) else {
            return;
        };
        let nocase = comparison.nocase_token();
        let (left, right) = (
            unparen(left.syntax().clone()),
            unparen(right.syntax().clone()),
        );
        // #e > "5": a count is a number.
        for (a, b) in [(&left, &right), (&right, &left)] {
            if a.kind() == K::COUNT_REF
                && matches!(
                    literal_kind(b),
                    Some(K::STRING | K::RAW_STRING | K::REGEX_LIT)
                )
            {
                self.error(
                    codes::YARAL_TYPE,
                    format!(
                        "`{}` counts events: compare it with a number, not `{}`",
                        self.text(a),
                        self.text(b)
                    ),
                    at(b),
                );
            }
        }
        for (field, other) in [(&left, &right), (&right, &left)] {
            let Some((kind, _)) = self.operand_kind(field) else {
                continue;
            };
            match kind {
                TypeKind::Enum(name, values) => {
                    if let Some(n) = &nocase {
                        self.error(
                            codes::YARAL_NOCASE_ON_ENUM,
                            format!("`{}` is an enumerated field ({name}): its values are exact, so `nocase` does not apply", self.text(field)),
                            at_token(n),
                        );
                    }
                    if is_string(other)
                        && let Some(value) = literal_text(other)
                        && !values.is_empty()
                        && !values.contains(&value)
                    {
                        let mut message = format!("`{value}` is not a value of {name}");
                        if let Some(s) = closest(&value, values.iter().map(String::as_str)) {
                            message.push_str(&format!("; did you mean `{s}`?"));
                        } else if let Some(s) =
                            values.iter().find(|v| v.eq_ignore_ascii_case(&value))
                        {
                            message.push_str(&format!("; did you mean `{s}`?"));
                        }
                        self.error(codes::YARAL_ENUM_VALUE, message, at(other));
                    }
                }
                TypeKind::Scalar(scalar)
                    if nocase.is_some() && scalar != "string" && scalar != "bytes" =>
                {
                    self.error(
                        codes::YARAL_TYPE,
                        format!(
                            "`{}` is a {scalar}: `nocase` applies to strings and regexes",
                            self.text(field)
                        ),
                        nocase.as_ref().map_or_else(|| at(node), at_token),
                    );
                    // One finding per `nocase`.
                    return;
                }
                _ => {}
            }
        }
        if let Some(n) = &nocase
            && (is_literal(&right, K::INTEGER) || is_literal(&right, K::FLOAT))
        {
            self.error(
                codes::YARAL_TYPE,
                "`nocase` applies to strings and regexes, not to a number".into(),
                at_token(n),
            );
        }
    }

    /// `any`/`all` on a map index: a Label (`ingestion_labels["k"]`) or a
    /// Struct (`additional.fields["k"]`, Google's own unsupported example in
    /// expressions, "Unsupported use of maps").
    fn quantified(&mut self, node: &SyntaxNode) {
        let Some(quantified) = QuantifiedField::cast(node.clone()) else {
            return;
        };
        let Some(field) = quantified.field() else {
            return;
        };
        let field = field.syntax().clone();
        let keyed = matches!(field.kind(), K::UDM_FIELD | K::BARE_FIELD)
            && field_segments(&field)
                .iter()
                .any(|s| matches!(s, Segment::Key(_)));
        if keyed {
            let q = quantified
                .quantifier()
                .map_or_else(|| "any".to_owned(), |q| q.text().to_owned());
            self.error(
                codes::YARAL_TYPE,
                format!(
                    "`{q}` applies to a repeated field, not to a map key (`{}`)",
                    self.text(&field)
                ),
                at(node),
            );
        }
    }
}
