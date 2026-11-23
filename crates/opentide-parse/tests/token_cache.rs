//! #1616: names crafted to collide under FxHash do not make [`build`]
//! quadratic.
//!
//! rowan 0.17's `GreenNodeBuilder` interned tokens in a table hashed with Fx,
//! a fixed function: names whose hashes share their low bits all start their
//! probe at one bucket, and each insert walks past every earlier one. The
//! 20,000 names in `crates/testdata/parse/fx-colliding-names.txt` (`x` and
//! eleven of `[a-z0-9]`) share the low 15 bits of rowan's token hash for
//! kind 4, enough to fill one probe sequence of a table that size: built
//! with rowan's builder, they took about 20 times as long as ordinary names
//! (its node cache hashed the tokens' hashes, so nodes of one name collided
//! too; 1 MB of them, in a KQL `project` list, about 24 times).
//! opentide-parse's own builder (`src/green.rs`) hashes with a per-map seed
//! and stops interning at 4,096 tokens, so the two take about as long.
//!
//! The names took a search over hundreds of millions of hashes; the ignored
//! test below writes them again (`cargo test --release -p opentide-parse
//! --test token_cache -- --ignored regenerate`).

#![expect(
    clippy::unwrap_used,
    reason = "test helpers outside #[test] functions: a panic fails the test"
)]

use opentide_parse::{Event, Grammar, Input, Lexeme, TokenSet, build};
use rowan::{SyntaxKind, TextRange, TextSize};
use std::time::{Duration, Instant};

const WS: SyntaxKind = SyntaxKind(0);
/// The names' kind: rowan hashed it with the text (KQL's IDENT is raw 4).
const IDENT: SyntaxKind = SyntaxKind(4);
const EOF: SyntaxKind = SyntaxKind(5);
const ERROR: SyntaxKind = SyntaxKind(6);
const NAME: SyntaxKind = SyntaxKind(7);
const ROOT: SyntaxKind = SyntaxKind(8);

const NAMES: &str = include_str!("../../testdata/parse/fx-colliding-names.txt");
const COUNT: usize = 20_000;
const BITS: u32 = 15;

/// FxHash as rustc-hash 1.1 (rowan's) computes it on 64-bit targets.
struct Fx(u64);

impl Fx {
    const K: u64 = 0x51_7c_c1_b7_27_22_0a_95;

    fn add(&mut self, word: u64) {
        self.0 = (self.0.rotate_left(5) ^ word).wrapping_mul(Self::K);
    }

    fn bytes(&mut self, mut bytes: &[u8]) {
        while let Some((word, rest)) = bytes.split_first_chunk::<8>() {
            self.add(u64::from_le_bytes(*word));
            bytes = rest;
        }
        if let Some((word, rest)) = bytes.split_first_chunk::<4>() {
            self.add(u64::from(u32::from_le_bytes(*word)));
            bytes = rest;
        }
        if let Some((word, rest)) = bytes.split_first_chunk::<2>() {
            self.add(u64::from(u16::from_le_bytes(*word)));
            bytes = rest;
        }
        if let Some(&byte) = bytes.first() {
            self.add(u64::from(byte));
        }
    }
}

/// rowan's token hash: the kind (`u16`), then the text (`str`: its bytes
/// and `0xff`).
fn rowan_token_hash(kind: SyntaxKind, text: &str) -> u64 {
    let mut h = Fx(0);
    h.add(u64::from(kind.0));
    h.bytes(text.as_bytes());
    h.add(0xff);
    h.0
}

/// A name from xorshift64*: `x` and eleven of `[a-z0-9]`.
fn name(state: &mut u64) -> String {
    const ALPHABET: &[u8] = b"abcdefghijklmnopqrstuvwxyz0123456789";
    let mut name = String::from("x");
    for _ in 0..11 {
        *state ^= *state >> 12;
        *state ^= *state << 25;
        *state ^= *state >> 27;
        let r = state.wrapping_mul(0x2545_f491_4f6c_dd1d) >> 32;
        name.push(char::from(
            ALPHABET[usize::try_from(r).unwrap() % ALPHABET.len()],
        ));
    }
    name
}

/// `a b c …`, each name a node of one token, and its events.
fn input(names: &[&str]) -> (String, Vec<Lexeme>, Vec<Event>) {
    let at = |s: usize, e: usize| {
        TextRange::new(
            TextSize::try_from(s).unwrap(),
            TextSize::try_from(e).unwrap(),
        )
    };
    let (mut source, mut lexemes) = (String::new(), Vec::new());
    let mut events = vec![Event::Start {
        kind: ROOT,
        forward_parent: None,
    }];
    for name in names {
        if !source.is_empty() {
            lexemes.push(Lexeme {
                kind: WS,
                range: at(source.len(), source.len() + 1),
            });
            source.push(' ');
        }
        lexemes.push(Lexeme {
            kind: IDENT,
            range: at(source.len(), source.len() + name.len()),
        });
        source.push_str(name);
        events.push(Event::Start {
            kind: NAME,
            forward_parent: None,
        });
        events.push(Event::Token { kind: IDENT });
        events.push(Event::Finish);
    }
    events.push(Event::Finish);
    (source, lexemes, events)
}

/// A build of `names`, timed.
struct Timed {
    input: (String, Vec<Lexeme>, Vec<Event>),
}

impl Timed {
    fn new(names: &[&str]) -> Self {
        Self {
            input: input(names),
        }
    }

    fn run(&self) -> Duration {
        let grammar = Grammar {
            eof: EOF,
            error: ERROR,
            trivia: TokenSet::new(&[WS]),
            max_depth: 8,
        };
        let (source, lexemes, events) = &self.input;
        let input = Input::new(source, lexemes.clone(), grammar);
        let events = events.clone();
        let start = Instant::now();
        let parse = build(&input, events);
        let elapsed = start.elapsed();
        assert!(parse.errors.is_empty(), "{:?}", parse.errors);
        assert_eq!(&parse.green.to_string(), source);
        elapsed
    }
}

fn colliding() -> Vec<&'static str> {
    NAMES.lines().collect()
}

#[test]
fn the_names_collide_under_rowans_hash() {
    let names = colliding();
    assert_eq!(names.len(), COUNT);
    let mut distinct = names.clone();
    distinct.sort_unstable();
    distinct.dedup();
    assert_eq!(distinct.len(), COUNT, "the names are distinct");
    let mask = (1 << BITS) - 1;
    for name in names {
        assert_eq!(rowan_token_hash(IDENT, name) & mask, 0, "{name}");
    }
}

#[test]
fn colliding_names_build_about_as_fast_as_ordinary_ones() {
    let attack = colliding();
    let mut state = 42;
    let control: Vec<String> = (0..attack.len()).map(|_| name(&mut state)).collect();
    let control: Vec<&str> = control.iter().map(String::as_str).collect();
    let (attack, control) = (Timed::new(&attack), Timed::new(&control));
    // The fastest of five builds each, in turns, so load on the machine
    // weighs on both alike; up to three rounds, so one burst of load on a
    // shared runner does not fail it. rowan's builder: about 20×, every
    // round. Ours: about 1×.
    let mut rounds = Vec::new();
    for _ in 0..3 {
        let (mut fastest_attack, mut fastest_control) = (Duration::MAX, Duration::MAX);
        for _ in 0..5 {
            fastest_attack = fastest_attack.min(attack.run());
            fastest_control = fastest_control.min(control.run());
        }
        if fastest_attack < fastest_control * 2 {
            return;
        }
        rounds.push((fastest_attack, fastest_control));
    }
    panic!("colliding names took twice as long as ordinary ones or more, each round: {rounds:?}");
}

/// Writes `fx-colliding-names.txt` again: the first [`COUNT`] distinct
/// names, in order, whose hash has its low [`BITS`] bits clear, from four
/// xorshift streams. Minutes in a release build.
#[test]
#[ignore = "a search over hundreds of millions of hashes: run it to regenerate the test data"]
fn regenerate_colliding_names() {
    let mask = (1 << BITS) - 1;
    let threads: Vec<_> = (1..=4u64)
        .map(|stream| {
            std::thread::spawn(move || {
                let mut state = 0x9e37_79b9_7f4a_7c15 ^ stream.wrapping_mul(0xd1b5_4a32_d192_ed03);
                let mut found = Vec::new();
                while found.len() < COUNT / 4 {
                    let name = name(&mut state);
                    if rowan_token_hash(IDENT, &name) & mask == 0 {
                        found.push(name);
                    }
                }
                found
            })
        })
        .collect();
    let mut names: Vec<String> = threads
        .into_iter()
        .flat_map(|t| t.join().unwrap())
        .collect();
    names.sort_unstable();
    names.dedup();
    let path = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../testdata/parse/fx-colliding-names.txt"
    );
    std::fs::write(path, names.join("\n") + "\n").unwrap();
}
