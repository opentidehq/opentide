//! The pure-Rust analysis against the tree-sitter engine it replaces, over
//! every `.yaral` file of `crates/testdata`, its prefixes, seeded token
//! mutations, random sentences and generated valid rules and searches
//! (`opentide_parse::differential`, #1227).
//!
//! The old engine is the production one, reached through its public API; the
//! new one is `opentide_yaral::testing`. Compared: the diagnostics of the
//! three contexts (a file, a Tide block's sections, a hunt), the highlight
//! tokens, and at offsets the hover and the completions. Completions and
//! signature help read the text, not the tree, so both sides run the same
//! code; they are compared anyway so that a change cannot split them.
//!
//! Gates: valid input, zero differences; broken input, the same verdict.
//! Two scales of one gate. The default (one seed, a sample of the corpus) runs
//! in well under 120 s in a debug build, for CI. `OPENTIDE_DIFF_SCALE=full`
//! runs every file, 40 mutations per input, 300 sentences and 250 generated
//! texts per seed; `OPENTIDE_DIFF_SEEDS=1,2,3` picks the seeds (default `1`).
//! `OPENTIDE_YARAL_DIFF=<file>` writes the JSON report of every seed.

#![expect(
    clippy::expect_used,
    reason = "test helpers outside #[test] functions: a panic fails the test"
)]

use opentide_parse::differential::{Class, Config, Engine, Source, Surfaces, assert_gates, run};
use opentide_yaral::editor::{completions, hover};
use opentide_yaral::testing::{analyze_new, hover_new, lex_spans};
use opentide_yaral::{Context, analyze_with};
use std::path::{Path, PathBuf};

const CONTEXTS: [(&str, Context); 3] = [
    ("file", Context::FILE),
    ("sections", Context::SECTIONS),
    ("search", Context::SEARCH),
];

/// What a diagnostic says, on one line.
fn line(d: &opentide_core::Diagnostic) -> String {
    format!(
        "{} {:?} {}:{}-{}:{} {}",
        d.code,
        d.severity,
        d.range.start.line,
        d.range.start.character,
        d.range.end.line,
        d.range.end.character,
        d.message,
    )
}

fn tokens_text(tokens: &[opentide_highlight::HighlightToken]) -> String {
    tokens
        .iter()
        .map(|t| format!("{}..{} {}", t.span.start, t.span.end, t.capture))
        .collect::<Vec<_>>()
        .join("\n")
}

struct Old;
struct New;

impl Engine for Old {
    fn observe(&self, input: &str) -> Surfaces {
        let mut out = Vec::new();
        for (name, ctx) in CONTEXTS {
            let analysis = analyze_with(input, &ctx);
            let lines: Vec<String> = analysis.diagnostics.iter().map(line).collect();
            out.push((format!("diagnostics.{name}"), lines.join("\n")));
            if name == "file" {
                out.push(("tokens".to_owned(), tokens_text(&analysis.tokens)));
            }
        }
        out
    }

    fn observe_at(&self, input: &str, offset: usize) -> Surfaces {
        vec![
            ("hover".to_owned(), hover(input, offset).unwrap_or_default()),
            (
                "completions".to_owned(),
                completions(input, offset)
                    .iter()
                    .map(|c| c.label.clone())
                    .collect::<Vec<_>>()
                    .join(","),
            ),
        ]
    }
}

impl Engine for New {
    fn observe(&self, input: &str) -> Surfaces {
        let mut out = Vec::new();
        for (name, ctx) in CONTEXTS {
            let analysis = analyze_new(input, &ctx);
            let lines: Vec<String> = analysis.diagnostics.iter().map(line).collect();
            out.push((format!("diagnostics.{name}"), lines.join("\n")));
            if name == "file" {
                out.push(("tokens".to_owned(), tokens_text(&analysis.tokens)));
            }
        }
        out
    }

    fn observe_at(&self, input: &str, offset: usize) -> Surfaces {
        vec![
            (
                "hover".to_owned(),
                hover_new(input, offset).unwrap_or_default(),
            ),
            (
                "completions".to_owned(),
                completions(input, offset)
                    .iter()
                    .map(|c| c.label.clone())
                    .collect::<Vec<_>>()
                    .join(","),
            ),
        ]
    }
}

/// Valid unless the diagnostics hold a syntax error (a comma between
/// condition terms is one too, under the condition-shape code).
fn verdict(surfaces: &Surfaces) -> bool {
    !surfaces.iter().any(|(name, text)| {
        name.starts_with("diagnostics")
            && text.lines().any(|l| {
                l.contains("the YARA-L text")
                    || l.contains("YARA-L expects")
                    || l.contains("never a comma")
            })
    })
}

fn tokens(text: &str) -> Vec<std::ops::Range<usize>> {
    lex_spans(text)
        .into_iter()
        .filter(|(_, _, trivia)| !trivia)
        .map(|(start, end, _)| start..end)
        .collect()
}

const SAMPLES: &[&str] = &[
    "rule",
    "r",
    "{",
    "}",
    "meta:",
    "events:",
    "match:",
    "outcome:",
    "condition:",
    "options:",
    "export:",
    "setup:",
    "dedup:",
    "order:",
    "limit:",
    "select:",
    "unselect:",
    "stage",
    "$e",
    "$e.metadata.event_type",
    "$e.principal.hostname",
    "$e.target.ip[0]",
    "$e.additional.fields[\"k\"]",
    "$h",
    "$risk_score",
    "#e",
    "%list",
    "%t.col",
    "principal.hostname",
    "=",
    "!=",
    "<",
    "<=",
    ">",
    ">=",
    "+",
    "-",
    "*",
    "/",
    "%",
    "!",
    "and",
    "AND",
    "or",
    "not",
    "nocase",
    "in",
    "regex",
    "cidr",
    "any",
    "all",
    "of",
    "over",
    "by",
    "before",
    "after",
    "every",
    "first",
    "cross",
    "join",
    "if",
    "asc",
    "desc",
    "true",
    "false",
    "window_start",
    "window_end",
    "graph_append",
    "(",
    ")",
    "[",
    "]",
    ",",
    ":",
    ".",
    "1",
    "1.5",
    "5m",
    "1h",
    "\"USER_LOGIN\"",
    "\"a\\d\"",
    "`x`",
    "/x+/",
    "strings.to_lower($e.a)",
    "max($e.a)",
    "count(x)",
    "re.regex($e.a, `x`)",
    "write_row(a: $v)",
    "//c\n",
    "/*c*/",
    "\n",
    "\u{e9}",
];

fn walk(dir: &Path, out: &mut Vec<PathBuf>) {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        if path.is_dir() {
            walk(&path, out);
        } else if path.extension().is_some_and(|e| e == "yaral") {
            out.push(path);
        }
    }
}

/// The deterministic generator of valid texts: splitmix64.
struct Rng(u64);

impl Rng {
    fn next(&mut self) -> u64 {
        self.0 = self.0.wrapping_add(0x9E37_79B9_7F4A_7C15);
        let mut z = self.0;
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
        z ^ (z >> 31)
    }

    fn below(&mut self, n: usize) -> usize {
        usize::try_from(self.next() % (n as u64)).unwrap_or(0)
    }

    fn pick<'a>(&mut self, items: &[&'a str]) -> &'a str {
        items[self.below(items.len())]
    }

    fn chance(&mut self, percent: usize) -> bool {
        self.below(100) < percent
    }
}

const PATHS: &[&str] = &[
    "metadata.event_type",
    "metadata.product_name",
    "metadata.log_type",
    "principal.hostname",
    "principal.user.userid",
    "principal.ip",
    "principal.process.file.full_path",
    "target.process.command_line",
    "target.ip[0]",
    "target.port",
    "network.dhcp.options",
    "additional.fields[\"k\"]",
    "security_result.severity",
    "src.hostname",
    "extensions.auth.type",
    "metadata.event_timestamp.seconds",
    "bogus.field",
];

const VALUES: &[&str] = &[
    "\"USER_LOGIN\"",
    "\"PROCESS_LAUNCH\"",
    "\"x\"",
    "\"a\\\\b\"",
    "\"a\\d\"",
    "`c:\\\\x`",
    "/ab+c/",
    "/.*x/",
    "/(/",
    "1",
    "443",
    "0",
    "1.5",
    "true",
    "$h",
    "$e2.principal.hostname",
    "%bad_list",
    "strings.to_lower($e.principal.hostname)",
];

const FUNCTIONS: &[&str] = &[
    "max($e.target.port)",
    "min($e.target.port)",
    "sum($e.target.port)",
    "count($e.principal.hostname)",
    "count_distinct($e.principal.hostname)",
    "array_distinct($e.principal.hostname)",
    "strings.concat($e.principal.hostname, \"x\")",
    "strings.to_lower($e.principal.hostname)",
    "re.regex($e.principal.hostname, `^a.*`)",
    "math.abs($e.target.port)",
    "window.avg($e.target.port)",
    "nosuch.func(1)",
    "if($e.target.port > 1, 1, 2)",
    "max()",
];

fn comparison(rng: &mut Rng, var: &str) -> String {
    let path = rng.pick(PATHS);
    let op = rng.pick(&["=", "!=", "<", "<=", ">", ">="]);
    let value = rng.pick(VALUES);
    let nocase = if rng.chance(15) { " nocase" } else { "" };
    format!("${var}.{path} {op} {value}{nocase}")
}

fn events(rng: &mut Rng, vars: &[&str]) -> String {
    let mut out = String::new();
    for var in vars {
        out.push_str(&format!(
            "    ${var}.metadata.event_type = \"USER_LOGIN\"\n"
        ));
        for _ in 0..rng.below(3) {
            out.push_str(&format!("    {}\n", comparison(rng, var)));
        }
        if rng.chance(40) {
            out.push_str(&format!(
                "    $h = {}\n",
                rng.pick(&[
                    "$e.principal.hostname",
                    "strings.to_lower($e.principal.hostname)"
                ])
            ));
        }
        if rng.chance(15) {
            out.push_str(&format!(
                "    $e.principal.ip in {}\n",
                rng.pick(&["%l", "regex %l", "cidr %l", "%t.col"])
            ));
        }
        if rng.chance(15) {
            out.push_str(&format!(
                "    any $e.target.ip = \"1.2.3.4\" {}\n",
                rng.pick(&["", "and ($e.target.port > 1 or $e.target.port < 0)"])
            ));
        }
    }
    out
}

fn condition(rng: &mut Rng, vars: &[&str]) -> String {
    let terms: Vec<String> = vars
        .iter()
        .map(|v| match rng.below(5) {
            0 => format!("#{v} > {}", rng.below(5)),
            1 => format!("!${v}"),
            2 => format!("#{v} = 0"),
            3 => format!("(${v} or ${v})"),
            _ => format!("${v}"),
        })
        .collect();
    let op = rng.pick(&[" and ", " or ", " and not "]);
    terms.join(op)
}

/// A rule with a random subset of sections, each valid text.
fn rule(rng: &mut Rng) -> String {
    let two = rng.chance(30);
    let vars: Vec<&str> = if two { vec!["e", "e2"] } else { vec!["e"] };
    let mut out = format!(
        "rule {}{} {{\n",
        rng.pick(&["r", "my_rule", "limit", "Match"]),
        rng.below(9)
    );
    if rng.chance(85) {
        out.push_str("  meta:\n    author = \"a\"\n");
        if rng.chance(30) {
            out.push_str("    severity = 5\n");
        }
    }
    out.push_str("  events:\n");
    out.push_str(&events(rng, &vars));
    if two || rng.chance(40) {
        let window = rng.pick(&["5m", "1h", "2d", "30s", "15d", "0m", "90m"]);
        let how = rng.pick(&["over", "by", "over"]);
        let pivot = if rng.chance(20) { " before $e" } else { "" };
        out.push_str(&format!("  match:\n    $h {how} {window}{pivot}\n"));
    }
    if rng.chance(60) {
        out.push_str("  outcome:\n");
        for i in 0..rng.below(4) {
            out.push_str(&format!("    $o{i} = {}\n", rng.pick(FUNCTIONS)));
        }
        out.push_str("    $risk_score = max(5)\n");
    }
    out.push_str("  condition:\n    ");
    out.push_str(&condition(rng, &vars));
    out.push('\n');
    if rng.chance(30) {
        out.push_str(&format!(
            "  options:\n    {}\n",
            rng.pick(&[
                "allow_zero_values = true",
                "suppression_window = 1h",
                "allow_zero_values = 1",
                "other = 2",
            ])
        ));
    }
    if rng.chance(10) {
        out.push_str("  export:\n    %t.write_row(c: $o0)\n");
    }
    out.push_str("}\n");
    out
}

/// A search: events, then the sections a search takes.
fn search(rng: &mut Rng) -> String {
    let mut out = String::new();
    if rng.chance(25) {
        out.push_str(&format!(
            "stage s {{\n  {}\n  match:\n    principal.hostname over 1h\n}}\n",
            comparison_bare(rng)
        ));
    }
    for _ in 0..=rng.below(3) {
        out.push_str(&comparison_bare(rng));
        out.push('\n');
    }
    if rng.chance(50) {
        out.push_str(&format!(
            "match:\n  principal.hostname {} {}\n",
            rng.pick(&["over", "by", "by first", "over every"]),
            rng.pick(&["1h", "1 hour", "day", "2d", "1w", "30d"])
        ));
    }
    if rng.chance(50) {
        out.push_str("outcome:\n  $c = count(principal.hostname)\n");
    }
    if rng.chance(40) {
        out.push_str("order:\n  principal.hostname desc\n");
    }
    if rng.chance(40) {
        out.push_str(&format!("limit: {}\n", rng.below(100)));
    }
    out
}

fn comparison_bare(rng: &mut Rng) -> String {
    let path = rng.pick(PATHS);
    let op = rng.pick(&["=", "!=", ">"]);
    let value = rng.pick(&VALUES[..11]);
    format!("{path} {op} {value}")
}

/// Whether `OPENTIDE_DIFF_SCALE=full` asks for the whole run.
fn full() -> bool {
    std::env::var("OPENTIDE_DIFF_SCALE").is_ok_and(|v| v == "full")
}

fn sources(seed: u64) -> Vec<Source> {
    let mut paths = Vec::new();
    walk(
        &Path::new(env!("CARGO_MANIFEST_DIR")).join("../testdata"),
        &mut paths,
    );
    paths.sort();
    let stride = if full() { 1 } else { 4 };
    let mut out: Vec<Source> = paths
        .into_iter()
        .step_by(stride)
        .map(|path| Source {
            name: path
                .strip_prefix(env!("CARGO_MANIFEST_DIR"))
                .unwrap_or(&path)
                .display()
                .to_string(),
            text: std::fs::read_to_string(&path).expect("corpus file"),
        })
        .collect();
    let (rules, searches) = if full() { (150, 100) } else { (30, 20) };
    let mut rng = Rng(seed.wrapping_mul(0x2545_F491_4F6C_DD1D));
    for i in 0..rules {
        out.push(Source {
            name: format!("generated-rule-{i}"),
            text: rule(&mut rng),
        });
    }
    for i in 0..searches {
        out.push(Source {
            name: format!("generated-search-{i}"),
            text: search(&mut rng),
        });
    }
    out
}

fn differential(seed: u64) {
    let files = sources(seed);
    assert!(files.len() > 100, "{} files", files.len());
    let mut config = Config::new(&verdict, &tokens, SAMPLES);
    config.seed = seed;
    if full() {
        config.max_prefixes = 12;
        config.mutations_per_input = 40;
        config.sentences = 300;
        config.max_offsets = 24;
    } else {
        config.max_prefixes = 3;
        config.mutations_per_input = 4;
        config.sentences = 40;
        config.max_offsets = 6;
    }
    let report = run(&Old, &New, &files, &config);
    eprintln!(
        "seed {seed}: {} inputs, {} valid; valid {}, broken {}, verdict {}",
        report.inputs,
        report.valid,
        report.total(Class::Valid),
        report.total(Class::Broken),
        report.total(Class::Verdict),
    );
    if let Ok(path) = std::env::var("OPENTIDE_YARAL_DIFF") {
        let path = format!("{path}.{seed}.json");
        std::fs::write(path, report.to_json_string()).expect("write the report");
    }
    assert_gates(&report);
}

#[test]
fn differential_seeds() {
    let seeds = std::env::var("OPENTIDE_DIFF_SEEDS").unwrap_or_else(|_| "1".to_owned());
    for seed in seeds.split(',').filter_map(|s| s.trim().parse().ok()) {
        differential(seed);
    }
}
