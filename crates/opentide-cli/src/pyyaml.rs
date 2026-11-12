//! YAML written as PyYAML 6's `yaml.dump` writes it (UC-4.4b, #834): the
//! emitter's block style, its scalar analysis and style choice, its YAML 1.1
//! implicit resolver and its line folding at 80 columns, so a file another
//! command wrote through PyYAML is written here byte for byte.
//!
//! [`Options`] holds the dumper's settings this crate uses: `allow_unicode`
//! (`False` escapes every non-ASCII character in double quotes), the width,
//! and the two customisations of `elastic_importer.IndentedYamlDumper`: a
//! sequence under a mapping key indented, and a multi-line string written as
//! a literal block. Keys keep their order (`sort_keys=False`).

use std::sync::OnceLock;

use opentide_compile::json::Json;
use regex::Regex;

/// The dumper's settings.
#[derive(Clone, Copy, Debug)]
pub struct Options {
    /// `allow_unicode`.
    pub allow_unicode: bool,
    /// `width`: where plain and quoted scalars fold.
    pub width: usize,
    /// A sequence under a key indented (`increase_indent(..., False)`).
    pub indent_sequences: bool,
    /// A string with a line break written as a `|` block.
    pub literal_multiline: bool,
}

impl Options {
    /// `elastic_importer.IndentedYamlDumper`, `yaml.dump`'s defaults.
    pub const INDENTED: Options = Options {
        allow_unicode: false,
        width: 80,
        indent_sequences: true,
        literal_multiline: true,
    };

    /// `yaml.safe_dump(text, allow_unicode=True, width=sys.maxsize)`.
    pub const SCALAR: Options = Options {
        allow_unicode: true,
        width: usize::MAX / 2,
        indent_sequences: false,
        literal_multiline: false,
    };
}

const BEST_INDENT: usize = 2;

fn is_break(c: char) -> bool {
    matches!(c, '\n' | '\u{85}' | '\u{2028}' | '\u{2029}')
}

fn is_space_or_break(c: char) -> bool {
    matches!(
        c,
        '\0' | ' ' | '\t' | '\r' | '\n' | '\u{85}' | '\u{2028}' | '\u{2029}'
    )
}

/// What a scalar allows (`ScalarAnalysis`).
#[derive(Clone, Copy, Debug, Default)]
#[expect(
    clippy::struct_excessive_bools,
    reason = "PyYAML's `ScalarAnalysis`, flag for flag"
)]
struct Analysis {
    empty: bool,
    multiline: bool,
    allow_flow_plain: bool,
    allow_block_plain: bool,
    allow_single_quoted: bool,
    allow_block: bool,
}

#[expect(
    clippy::too_many_lines,
    reason = "PyYAML's `analyze_scalar`, step by step"
)]
fn analyze(scalar: &str, allow_unicode: bool) -> Analysis {
    if scalar.is_empty() {
        return Analysis {
            empty: true,
            multiline: false,
            allow_flow_plain: false,
            allow_block_plain: true,
            allow_single_quoted: true,
            allow_block: false,
        };
    }
    let chars: Vec<char> = scalar.chars().collect();
    let (mut block_indicators, mut flow_indicators) = (false, false);
    let (mut line_breaks, mut special_characters) = (false, false);
    let (mut leading_space, mut leading_break) = (false, false);
    let (mut trailing_space, mut trailing_break) = (false, false);
    let (mut break_space, mut space_break) = (false, false);
    if scalar.starts_with("---") || scalar.starts_with("...") {
        block_indicators = true;
        flow_indicators = true;
    }
    let mut preceded_by_whitespace = true;
    let mut followed_by_whitespace = chars.len() == 1 || is_space_or_break(chars[1]);
    let (mut previous_space, mut previous_break) = (false, false);
    let last = chars.len() - 1;
    for (index, &ch) in chars.iter().enumerate() {
        if index == 0 {
            if "#,[]{}&*!|>'\"%@`".contains(ch) {
                flow_indicators = true;
                block_indicators = true;
            }
            if ch == '?' || ch == ':' {
                flow_indicators = true;
                if followed_by_whitespace {
                    block_indicators = true;
                }
            }
            if ch == '-' && followed_by_whitespace {
                flow_indicators = true;
                block_indicators = true;
            }
        } else {
            if ",?[]{}".contains(ch) {
                flow_indicators = true;
            }
            if ch == ':' {
                flow_indicators = true;
                if followed_by_whitespace {
                    block_indicators = true;
                }
            }
            if ch == '#' && preceded_by_whitespace {
                flow_indicators = true;
                block_indicators = true;
            }
        }
        if is_break(ch) {
            line_breaks = true;
        }
        if !(ch == '\n' || ('\x20'..='\x7e').contains(&ch)) {
            let unicode = (ch == '\u{85}'
                || ('\u{a0}'..='\u{d7ff}').contains(&ch)
                || ('\u{e000}'..='\u{fffd}').contains(&ch)
                || ('\u{10000}'..'\u{10ffff}').contains(&ch))
                && ch != '\u{feff}';
            if !unicode || !allow_unicode {
                special_characters = true;
            }
        }
        if ch == ' ' {
            if index == 0 {
                leading_space = true;
            }
            if index == last {
                trailing_space = true;
            }
            if previous_break {
                break_space = true;
            }
            previous_space = true;
            previous_break = false;
        } else if is_break(ch) {
            if index == 0 {
                leading_break = true;
            }
            if index == last {
                trailing_break = true;
            }
            if previous_space {
                space_break = true;
            }
            previous_space = false;
            previous_break = true;
        } else {
            previous_space = false;
            previous_break = false;
        }
        preceded_by_whitespace = is_space_or_break(ch);
        followed_by_whitespace = index + 2 >= chars.len() || is_space_or_break(chars[index + 2]);
    }
    let mut analysis = Analysis {
        empty: false,
        multiline: line_breaks,
        allow_flow_plain: true,
        allow_block_plain: true,
        allow_single_quoted: true,
        allow_block: true,
    };
    if leading_space || leading_break || trailing_space || trailing_break {
        analysis.allow_flow_plain = false;
        analysis.allow_block_plain = false;
    }
    if trailing_space {
        analysis.allow_block = false;
    }
    if break_space {
        analysis.allow_flow_plain = false;
        analysis.allow_block_plain = false;
        analysis.allow_single_quoted = false;
    }
    if space_break || special_characters {
        analysis.allow_flow_plain = false;
        analysis.allow_block_plain = false;
        analysis.allow_single_quoted = false;
        analysis.allow_block = false;
    }
    if line_breaks {
        analysis.allow_flow_plain = false;
        analysis.allow_block_plain = false;
    }
    if flow_indicators {
        analysis.allow_flow_plain = false;
    }
    if block_indicators {
        analysis.allow_block_plain = false;
    }
    analysis
}

/// The tags PyYAML's YAML 1.1 resolver gives a plain scalar.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Tag {
    Str,
    Other,
}

#[expect(
    clippy::expect_used,
    reason = "literal patterns, compiled once; they cannot fail"
)]
fn resolvers() -> &'static [(Regex, &'static str)] {
    static RESOLVERS: OnceLock<Vec<(Regex, &'static str)>> = OnceLock::new();
    RESOLVERS.get_or_init(|| {
        let compile = |pattern: &str| Regex::new(pattern).expect("a valid pattern");
        vec![
            (
                compile(
                    r"^(?:yes|Yes|YES|no|No|NO|true|True|TRUE|false|False|FALSE|on|On|ON|off|Off|OFF)\n?$",
                ),
                "yYnNtTfFoO",
            ),
            (
                compile(
                    r"^(?:[-+]?(?:[0-9][0-9_]*)\.[0-9_]*(?:[eE][-+][0-9]+)?|\.[0-9_]+(?:[eE][-+][0-9]+)?|[-+]?[0-9][0-9_]*(?::[0-5]?[0-9])+\.[0-9_]*|[-+]?\.(?:inf|Inf|INF)|\.(?:nan|NaN|NAN))\n?$",
                ),
                "-+0123456789.",
            ),
            (
                compile(
                    r"^(?:[-+]?0b[0-1_]+|[-+]?0[0-7_]+|[-+]?(?:0|[1-9][0-9_]*)|[-+]?0x[0-9a-fA-F_]+|[-+]?[1-9][0-9_]*(?::[0-5]?[0-9])+)\n?$",
                ),
                "-+0123456789",
            ),
            (compile(r"^(?:<<)\n?$"), "<"),
            (compile(r"^(?:~|null|Null|NULL|)\n?$"), "~nN"),
            (
                compile(
                    r"^(?:[0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9]|[0-9][0-9][0-9][0-9]-[0-9][0-9]?-[0-9][0-9]?(?:[Tt]|[ \t]+)[0-9][0-9]?:[0-9][0-9]:[0-9][0-9](?:\.[0-9]*)?(?:[ \t]*(?:Z|[-+][0-9][0-9]?(?::[0-9][0-9])?))?)\n?$",
                ),
                "0123456789",
            ),
            (compile(r"^(?:=)\n?$"), "="),
            (compile(r"^(?:!|&|\*)\n?$"), "!&*"),
        ]
    })
}

/// The tag a plain `value` resolves to (`Resolver.resolve`).
fn resolve(value: &str) -> Tag {
    let first = value.chars().next();
    for (pattern, starts) in resolvers() {
        let applies = match first {
            None => starts.contains('~'),
            Some(first) => starts.contains(first),
        };
        if applies && pattern.is_match(value) {
            return Tag::Other;
        }
    }
    Tag::Str
}

/// A scalar to write: its text, whether the plain text reads back as the
/// same type (`implicit[0]`), and the style asked for.
struct Scalar<'a> {
    text: &'a str,
    implicit: bool,
    style: Option<char>,
}

/// The emitter's state (`Emitter`): the column, the indents, and whether the
/// last thing written was whitespace or an indentation.
struct Emitter {
    out: String,
    options: Options,
    indent: Option<usize>,
    indents: Vec<Option<usize>>,
    column: usize,
    whitespace: bool,
    indention: bool,
    open_ended: bool,
}

impl Emitter {
    fn new(options: Options) -> Self {
        Self {
            out: String::new(),
            options,
            indent: None,
            indents: Vec::new(),
            column: 0,
            whitespace: true,
            indention: true,
            open_ended: false,
        }
    }

    fn increase_indent(&mut self, flow: bool, indentless: bool) {
        self.indents.push(self.indent);
        self.indent = match self.indent {
            None => Some(if flow { BEST_INDENT } else { 0 }),
            Some(indent) if !indentless => Some(indent + BEST_INDENT),
            some => some,
        };
    }

    fn decrease_indent(&mut self) {
        self.indent = self.indents.pop().flatten();
    }

    fn write(&mut self, data: &str) {
        self.out.push_str(data);
    }

    fn write_counted(&mut self, data: &str) {
        self.column += data.chars().count();
        self.out.push_str(data);
    }

    fn write_indicator(
        &mut self,
        indicator: &str,
        need_whitespace: bool,
        whitespace: bool,
        indention: bool,
    ) {
        let data = if self.whitespace || !need_whitespace {
            indicator.to_owned()
        } else {
            format!(" {indicator}")
        };
        self.whitespace = whitespace;
        self.indention = self.indention && indention;
        self.open_ended = false;
        self.write_counted(&data);
    }

    fn write_line_break(&mut self, data: Option<char>) {
        self.whitespace = true;
        self.indention = true;
        self.column = 0;
        self.out.push(data.unwrap_or('\n'));
    }

    fn write_indent(&mut self) {
        let indent = self.indent.unwrap_or(0);
        if !self.indention || self.column > indent || (self.column == indent && !self.whitespace) {
            self.write_line_break(None);
        }
        if self.column < indent {
            self.whitespace = true;
            let data = " ".repeat(indent - self.column);
            self.column = indent;
            self.write(&data);
        }
    }

    // ---- nodes

    fn node(&mut self, value: &Json, root: bool, mapping_context: bool, simple_key: bool) {
        match value {
            Json::Object(object) if !object.is_empty() => self.block_mapping(object),
            Json::Array(items) if !items.is_empty() => self.block_sequence(items, mapping_context),
            Json::Object(_) => self.empty_flow("{", "}"),
            Json::Array(_) => self.empty_flow("[", "]"),
            scalar => {
                let (text, implicit, style) = represent(scalar, self.options);
                self.increase_indent(true, false);
                self.scalar(
                    &Scalar {
                        text: &text,
                        implicit,
                        style,
                    },
                    root,
                    simple_key,
                );
                self.decrease_indent();
            }
        }
    }

    fn empty_flow(&mut self, open: &str, close: &str) {
        self.write_indicator(open, true, true, false);
        self.increase_indent(true, false);
        self.decrease_indent();
        self.write_indicator(close, false, false, false);
    }

    fn block_mapping(&mut self, object: &opentide_compile::json::Object) {
        self.increase_indent(false, false);
        for (key, value) in object {
            self.write_indent();
            let style = (self.options.literal_multiline && key.contains('\n')).then_some('|');
            let implicit = resolve(key) == Tag::Str;
            let analysis = analyze(key, self.options.allow_unicode);
            // `check_simple_key`: the key with its tag, `!!str`, under 128.
            let simple = key.chars().count() + 5 < 128 && !analysis.empty && !analysis.multiline;
            if simple {
                self.increase_indent(true, false);
                self.scalar(
                    &Scalar {
                        text: key,
                        implicit,
                        style,
                    },
                    false,
                    true,
                );
                self.decrease_indent();
                self.write_indicator(":", false, false, false);
            } else {
                self.write_indicator("?", true, false, true);
                self.increase_indent(true, false);
                self.scalar(
                    &Scalar {
                        text: key,
                        implicit,
                        style,
                    },
                    false,
                    false,
                );
                self.decrease_indent();
                self.write_indent();
                self.write_indicator(":", true, false, true);
            }
            self.node(value, false, true, false);
        }
        self.decrease_indent();
    }

    fn block_sequence(&mut self, items: &[Json], mapping_context: bool) {
        let indentless = mapping_context && !self.indention && !self.options.indent_sequences;
        self.increase_indent(false, indentless);
        for item in items {
            self.write_indent();
            self.write_indicator("-", true, false, true);
            self.node(item, false, false, false);
        }
        self.decrease_indent();
    }

    fn scalar(&mut self, scalar: &Scalar<'_>, root: bool, simple_key: bool) {
        let analysis = analyze(scalar.text, self.options.allow_unicode);
        let style = choose_style(scalar, analysis, simple_key);
        let split = !simple_key;
        match style {
            '"' => self.write_double_quoted(scalar.text, split),
            '\'' => self.write_single_quoted(scalar.text, split),
            '|' => self.write_literal(scalar.text),
            _ => self.write_plain(scalar.text, split, root),
        }
    }

    fn write_plain(&mut self, text: &str, split: bool, root: bool) {
        if root {
            self.open_ended = true;
        }
        if text.is_empty() {
            return;
        }
        if !self.whitespace {
            self.write_counted(" ");
        }
        self.whitespace = false;
        self.indention = false;
        let chars: Vec<char> = text.chars().collect();
        let (mut spaces, mut breaks) = (false, false);
        let (mut start, mut end) = (0, 0);
        while end <= chars.len() {
            let ch = chars.get(end).copied();
            if spaces {
                if ch != Some(' ') {
                    if start + 1 == end && self.column > self.options.width && split {
                        self.write_indent();
                        self.whitespace = false;
                        self.indention = false;
                    } else {
                        let data: String = chars[start..end].iter().collect();
                        self.write_counted(&data);
                    }
                    start = end;
                }
            } else if breaks {
                if ch.is_none_or(|ch| !is_break(ch)) {
                    if chars[start] == '\n' {
                        self.write_line_break(None);
                    }
                    for &br in &chars[start..end] {
                        self.write_line_break((br != '\n').then_some(br));
                    }
                    self.write_indent();
                    self.whitespace = false;
                    self.indention = false;
                    start = end;
                }
            } else if ch.is_none_or(|ch| ch == ' ' || is_break(ch)) {
                let data: String = chars[start..end].iter().collect();
                self.write_counted(&data);
                start = end;
            }
            if let Some(ch) = ch {
                spaces = ch == ' ';
                breaks = is_break(ch);
            }
            end += 1;
        }
    }

    fn write_single_quoted(&mut self, text: &str, split: bool) {
        self.write_indicator("'", true, false, false);
        let chars: Vec<char> = text.chars().collect();
        let (mut spaces, mut breaks) = (false, false);
        let (mut start, mut end) = (0, 0);
        while end <= chars.len() {
            let ch = chars.get(end).copied();
            if spaces {
                if ch != Some(' ') {
                    if start + 1 == end
                        && self.column > self.options.width
                        && split
                        && start != 0
                        && end != chars.len()
                    {
                        self.write_indent();
                    } else {
                        let data: String = chars[start..end].iter().collect();
                        self.write_counted(&data);
                    }
                    start = end;
                }
            } else if breaks {
                if ch.is_none_or(|ch| !is_break(ch)) {
                    if chars[start] == '\n' {
                        self.write_line_break(None);
                    }
                    for &br in &chars[start..end] {
                        self.write_line_break((br != '\n').then_some(br));
                    }
                    self.write_indent();
                    start = end;
                }
            } else if ch.is_none_or(|ch| ch == ' ' || is_break(ch) || ch == '\'') && start < end {
                let data: String = chars[start..end].iter().collect();
                self.write_counted(&data);
                start = end;
            }
            if ch == Some('\'') {
                self.write_counted("''");
                start = end + 1;
            }
            if let Some(ch) = ch {
                spaces = ch == ' ';
                breaks = is_break(ch);
            }
            end += 1;
        }
        self.write_indicator("'", false, false, false);
    }

    fn write_double_quoted(&mut self, text: &str, split: bool) {
        self.write_indicator("\"", true, false, false);
        let chars: Vec<char> = text.chars().collect();
        let allow_unicode = self.options.allow_unicode;
        let (mut start, mut end) = (0, 0);
        while end <= chars.len() {
            let ch = chars.get(end).copied();
            let escape = ch.is_none_or(|ch| {
                "\"\\\u{85}\u{2028}\u{2029}\u{feff}".contains(ch)
                    || !(('\x20'..='\x7e').contains(&ch)
                        || (allow_unicode
                            && (('\u{a0}'..='\u{d7ff}').contains(&ch)
                                || ('\u{e000}'..='\u{fffd}').contains(&ch))))
            });
            if escape {
                if start < end {
                    let data: String = chars[start..end].iter().collect();
                    self.write_counted(&data);
                    start = end;
                }
                if let Some(ch) = ch {
                    let data = match ch {
                        '\0' => "\\0".to_owned(),
                        '\x07' => "\\a".to_owned(),
                        '\x08' => "\\b".to_owned(),
                        '\t' => "\\t".to_owned(),
                        '\n' => "\\n".to_owned(),
                        '\x0b' => "\\v".to_owned(),
                        '\x0c' => "\\f".to_owned(),
                        '\r' => "\\r".to_owned(),
                        '\x1b' => "\\e".to_owned(),
                        '"' => "\\\"".to_owned(),
                        '\\' => "\\\\".to_owned(),
                        '\u{85}' => "\\N".to_owned(),
                        '\u{a0}' => "\\_".to_owned(),
                        '\u{2028}' => "\\L".to_owned(),
                        '\u{2029}' => "\\P".to_owned(),
                        c if u32::from(c) <= 0xff => format!("\\x{:02X}", u32::from(c)),
                        c if u32::from(c) <= 0xffff => format!("\\u{:04X}", u32::from(c)),
                        c => format!("\\U{:08X}", u32::from(c)),
                    };
                    self.write_counted(&data);
                    start = end + 1;
                }
            }
            if end > 0
                && end + 1 < chars.len()
                && (ch == Some(' ') || start >= end)
                && self.column + end.saturating_sub(start) > self.options.width
                && split
            {
                let mut data: String = chars[start.min(end)..end].iter().collect();
                data.push('\\');
                if start < end {
                    start = end;
                }
                self.write_counted(&data);
                self.write_indent();
                self.whitespace = false;
                self.indention = false;
                if chars.get(start) == Some(&' ') {
                    self.write_counted("\\");
                }
            }
            end += 1;
        }
        self.write_indicator("\"", false, false, false);
    }

    fn write_literal(&mut self, text: &str) {
        let chars: Vec<char> = text.chars().collect();
        let mut hints = String::new();
        if let (Some(&first), Some(&last)) = (chars.first(), chars.last()) {
            if first == ' ' || is_break(first) {
                hints.push_str(&BEST_INDENT.to_string());
            }
            if !is_break(last) {
                hints.push('-');
            } else if chars.len() == 1 || is_break(chars[chars.len() - 2]) {
                hints.push('+');
            }
        }
        self.write_indicator(&format!("|{hints}"), true, false, false);
        if hints.ends_with('+') {
            self.open_ended = true;
        }
        self.write_line_break(None);
        let mut breaks = true;
        let (mut start, mut end) = (0, 0);
        while end <= chars.len() {
            let ch = chars.get(end).copied();
            if breaks {
                if ch.is_none_or(|ch| !is_break(ch)) {
                    for &br in &chars[start..end] {
                        self.write_line_break((br != '\n').then_some(br));
                    }
                    if ch.is_some() {
                        self.write_indent();
                    }
                    start = end;
                }
            } else if ch.is_none_or(is_break) {
                let data: String = chars[start..end].iter().collect();
                self.write(&data);
                if ch.is_none() {
                    self.write_line_break(None);
                }
                start = end;
            }
            if let Some(ch) = ch {
                breaks = is_break(ch);
            }
            end += 1;
        }
    }
}

/// The style a scalar is written in (`choose_scalar_style`).
fn choose_style(scalar: &Scalar<'_>, analysis: Analysis, simple_key: bool) -> char {
    if scalar.style == Some('"') {
        return '"';
    }
    if scalar.style.is_none()
        && scalar.implicit
        && !(simple_key && (analysis.empty || analysis.multiline))
        && analysis.allow_block_plain
    {
        return ' ';
    }
    if scalar.style == Some('|') && !simple_key && analysis.allow_block {
        return '|';
    }
    if (scalar.style.is_none() || scalar.style == Some('\''))
        && analysis.allow_single_quoted
        && !(simple_key && analysis.multiline)
    {
        return '\'';
    }
    '"'
}

/// A value's text, whether it reads back plain, and its style
/// (`SafeRepresenter`, with the importer's string representer).
fn represent(value: &Json, options: Options) -> (String, bool, Option<char>) {
    match value {
        Json::Null => ("null".to_owned(), true, None),
        Json::Bool(flag) => (if *flag { "true" } else { "false" }.to_owned(), true, None),
        Json::Int(number) => (number.to_string(), true, None),
        Json::Float(number) => (float_text(*number), true, None),
        Json::Str(text) => {
            let style = (options.literal_multiline && text.contains('\n')).then_some('|');
            (text.clone(), resolve(text) == Tag::Str, style)
        }
        // Collections are nodes, never scalars.
        Json::Array(_) | Json::Object(_) => (String::new(), true, None),
    }
}

/// `represent_float`: `repr` lowered, `.inf`, `.nan`, an exponent with `.0`.
fn float_text(value: f64) -> String {
    if value.is_nan() {
        return ".nan".to_owned();
    }
    if value.is_infinite() {
        return if value > 0.0 { ".inf" } else { "-.inf" }.to_owned();
    }
    let text = opentide_schema::configuration::repr::float_text(value).to_lowercase();
    if !text.contains('.') && text.contains('e') {
        return text.replacen('e', ".0e", 1);
    }
    text
}

/// `yaml.dump(value, ...)`: the document's text.
pub fn dump(value: &Json, options: Options) -> String {
    let mut emitter = Emitter::new(options);
    emitter.node(value, true, false, false);
    // The document's end (`expect_document_end`): a line break, then `...`
    // after an open-ended root scalar.
    emitter.write_indent();
    if emitter.open_ended {
        emitter.write("...");
        emitter.write_line_break(None);
    }
    emitter.out
}

/// `yaml.safe_dump(text, allow_unicode=True, width=sys.maxsize)` of one
/// string, without its document end (`sentinel_importer._scalar`).
pub fn scalar(text: &str) -> String {
    let dumped = dump(&Json::Str(text.to_owned()), Options::SCALAR);
    let dumped = dumped.strip_suffix("\n...\n").unwrap_or(&dumped);
    dumped.strip_suffix('\n').unwrap_or(dumped).to_owned()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn json(text: &str) -> Json {
        serde_json::from_str(text).unwrap()
    }

    #[test]
    fn scalars_are_plain_quoted_or_blocks_as_pyyaml_writes_them() {
        let doc = json(
            r#"{"name": "A rule", "n": 1, "b": true, "f": 0.5, "e": "", "yes": "yes", "num": "12",
                "date": "2026-01-01", "colon": "a: b", "hash": "a #b", "quote": "it's",
                "lead": " x", "unicode": "é", "tab": "a\tb", "multi": "a\nb\n", "dash": "- x",
                "list": ["a", {"k": "v", "l": [1]}], "empty": [], "obj": {}, "null": null,
                "1": "key that resolves to an int"}"#,
        );
        let text = dump(&doc, Options::INDENTED);
        assert_eq!(
            text,
            "name: A rule\nn: 1\nb: true\nf: 0.5\ne: ''\n'yes': 'yes'\nnum: '12'\n\
             date: '2026-01-01'\ncolon: 'a: b'\nhash: 'a #b'\nquote: it's\nlead: ' x'\n\
             unicode: \"\\xE9\"\ntab: \"a\\tb\"\nmulti: |\n  a\n  b\ndash: '- x'\nlist:\n  - a\n  - k: v\n    l:\n      - 1\n\
             empty: []\nobj: {}\n'null': null\n'1': key that resolves to an int\n"
        );
    }

    #[test]
    fn long_scalars_fold_at_the_width() {
        let long = "word ".repeat(30);
        let doc = Json::Object(
            [("k".to_owned(), Json::Str(long.trim_end().to_owned()))]
                .into_iter()
                .collect(),
        );
        let text = dump(&doc, Options::INDENTED);
        let lines: Vec<&str> = text.lines().collect();
        assert!(lines.len() > 1, "{text}");
        assert!(lines[1].starts_with("  word"), "{text}");
        assert_eq!(
            dump(&Json::Str("plain".into()), Options::INDENTED),
            "plain\n...\n"
        );
    }

    #[test]
    fn literal_blocks_carry_their_hints() {
        let doc = |text: &str| {
            Json::Object(
                [("k".to_owned(), Json::Str(text.to_owned()))]
                    .into_iter()
                    .collect(),
            )
        };
        assert_eq!(dump(&doc("a\nb"), Options::INDENTED), "k: |-\n  a\n  b\n");
        assert_eq!(
            dump(&doc(" a\nb\n"), Options::INDENTED),
            "k: |2\n   a\n  b\n"
        );
        assert_eq!(
            dump(&doc("a\n\n"), Options::INDENTED),
            "k: |+\n  a\n\n...\n"
        );
        assert_eq!(dump(&doc("a \nb"), Options::INDENTED), "k: \"a \\nb\"\n");
    }

    #[test]
    fn one_scalar_as_the_sentinel_importer_writes_it() {
        assert_eq!(scalar("{{Computer}} logged on"), "'{{Computer}} logged on'");
        assert_eq!(scalar("plain é"), "plain é");
        assert_eq!(scalar("true"), "'true'");
        assert_eq!(scalar("a\nb"), "'a\n\n  b'");
    }

    /// Every document and scalar of the corpus PyYAML 6 wrote
    /// (`tests/fixtures/pyyaml/corpus.json`, `scripts/engine/pyyaml_corpus.py`).
    #[test]
    fn the_corpus_is_written_as_pyyaml_wrote_it() {
        let text = std::fs::read_to_string(
            std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
                .join("tests/fixtures/pyyaml/corpus.json"),
        )
        .unwrap();
        let cases: Vec<Json> = serde_json::from_str(&text).unwrap();
        let mut failures = Vec::new();
        for case in &cases {
            if let Some(input) = case.get("input") {
                let expected = case.get("indented").and_then(Json::as_str).unwrap();
                let actual = dump(input, Options::INDENTED);
                if actual != expected {
                    let at = expected
                        .lines()
                        .zip(actual.lines())
                        .position(|(a, b)| a != b)
                        .unwrap_or(0);
                    let window = |text: &str| {
                        text.lines()
                            .skip(at.saturating_sub(2))
                            .take(5)
                            .collect::<Vec<_>>()
                            .join("\n")
                    };
                    failures.push(format!(
                        "line {at}\n--- expected\n{}\n--- actual\n{}",
                        window(expected),
                        window(&actual)
                    ));
                }
            } else {
                let atom = case.get("scalar").and_then(Json::as_str).unwrap();
                let expected = case.get("out").and_then(Json::as_str).unwrap();
                let actual = scalar(atom);
                if actual != expected {
                    failures.push(format!("{atom:?}: expected {expected:?}, got {actual:?}"));
                }
            }
        }
        assert!(
            failures.is_empty(),
            "{} of {}:\n{}",
            failures.len(),
            cases.len(),
            failures
                .iter()
                .take(12)
                .cloned()
                .collect::<Vec<_>>()
                .join("\n\n")
        );
    }
}
