//! A `--x` / `--no-x` flag pair read as one tri-state option (#1967).
//!
//! Each flag of a pair is its own clap argument, with its id, long name and
//! help, so the catalogue and `--help` show both as before. The struct a
//! command parses into holds one [`Toggle`] instead of two booleans: the
//! flag typed last decides, and neither leaves it `None`.

use std::fmt;
use std::marker::PhantomData;

use clap::{Arg, ArgAction, ArgMatches, Args, Command, FromArgMatches};

/// The two flags of a pair: each one's id, long name and help.
pub trait Pair {
    /// The id of the flag that turns the option on (`staging`).
    const ON: &'static str;
    /// Its long name (`staging`).
    const ON_LONG: &'static str;
    /// The help of the flag that turns the option on.
    const ON_HELP: &'static str;
    /// The id of the flag that turns it off (`no_staging`).
    const OFF: &'static str;
    /// Its long name (`no-staging`).
    const OFF_LONG: &'static str;
    /// The help of the flag that turns the option off.
    const OFF_HELP: &'static str;
}

/// What a flag pair was given: `Some(true)` when the flag that turns it on
/// came last, `Some(false)` when the one that turns it off did, `None` when
/// neither was typed.
pub struct Toggle<P> {
    value: Option<bool>,
    pair: PhantomData<P>,
}

impl<P> Toggle<P> {
    /// A pair given `value`.
    pub const fn new(value: Option<bool>) -> Self {
        Toggle {
            value,
            pair: PhantomData,
        }
    }

    /// What was given; `None` when neither flag was.
    pub const fn get(&self) -> Option<bool> {
        self.value
    }

    /// What was given, or `default` when neither flag was.
    pub const fn or(&self, default: bool) -> bool {
        match self.value {
            Some(value) => value,
            None => default,
        }
    }
}

// Written out rather than derived: a derive would ask the same of `P`, a
// marker type that is never a value.
impl<P> Clone for Toggle<P> {
    fn clone(&self) -> Self {
        *self
    }
}

impl<P> Copy for Toggle<P> {}

impl<P> Default for Toggle<P> {
    fn default() -> Self {
        Toggle::new(None)
    }
}

impl<P> PartialEq for Toggle<P> {
    fn eq(&self, other: &Self) -> bool {
        self.value == other.value
    }
}

impl<P> Eq for Toggle<P> {}

impl<P: Pair> fmt::Debug for Toggle<P> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_tuple(P::ON).field(&self.value).finish()
    }
}

/// Whether the flag `id` was given, as clap's derive reads a `bool` field.
fn flag(matches: &ArgMatches, id: &str) -> Result<bool, clap::Error> {
    matches
        .try_get_one::<bool>(id)
        .map(|value| value.copied().unwrap_or(false))
        .map_err(|error| {
            clap::Error::raw(
                clap::error::ErrorKind::InvalidValue,
                format!("{id}: {error}\n"),
            )
        })
}

impl<P: Pair> FromArgMatches for Toggle<P> {
    fn from_arg_matches(matches: &ArgMatches) -> Result<Self, clap::Error> {
        // Each flag overrides the other: at most one of them is set.
        let value = match (flag(matches, P::ON)?, flag(matches, P::OFF)?) {
            (true, _) => Some(true),
            (_, true) => Some(false),
            _ => None,
        };
        Ok(Toggle::new(value))
    }

    fn update_from_arg_matches(&mut self, matches: &ArgMatches) -> Result<(), clap::Error> {
        *self = Self::from_arg_matches(matches)?;
        Ok(())
    }
}

/// The two arguments as clap's derive writes a `bool` field, the value name
/// (the id in capitals) included.
impl<P: Pair> Args for Toggle<P> {
    fn augment_args(command: Command) -> Command {
        command
            .arg(
                Arg::new(P::ON)
                    .value_name(P::ON.to_uppercase())
                    .long(P::ON_LONG)
                    .help(P::ON_HELP)
                    .action(ArgAction::SetTrue)
                    .overrides_with(P::OFF),
            )
            .arg(
                Arg::new(P::OFF)
                    .value_name(P::OFF.to_uppercase())
                    .long(P::OFF_LONG)
                    .help(P::OFF_HELP)
                    .action(ArgAction::SetTrue)
                    .overrides_with(P::ON),
            )
    }

    fn augment_args_for_update(command: Command) -> Command {
        Self::augment_args(command)
    }
}

/// A [`Pair`]: a marker type and its two flags, each as
/// `(id, long name, help)`.
macro_rules! pair {
    (
        $(#[$doc:meta])*
        $name:ident {
            on: ($on:literal, $on_long:literal, $on_help:expr $(,)?),
            off: ($off:literal, $off_long:literal, $off_help:expr $(,)?) $(,)?
        }
    ) => {
        $(#[$doc])*
        #[derive(Debug)]
        pub struct $name;

        impl $crate::tree::toggle::Pair for $name {
            const ON: &'static str = $on;
            const ON_LONG: &'static str = $on_long;
            const ON_HELP: &'static str = $on_help;
            const OFF: &'static str = $off;
            const OFF_LONG: &'static str = $off_long;
            const OFF_HELP: &'static str = $off_help;
        }
    };
}
pub(crate) use pair;

/// Test support: every way the command line spells a pair, through the
/// command line's own parser.
#[cfg(test)]
pub(crate) mod spellings {
    /// Each spelling clap accepts, as the flags typed in order (`true` the
    /// one that turns the option on), and what the pair then gives: the flag
    /// typed last wins, and a flag typed twice counts once.
    pub(crate) const SPELLINGS: [(&[bool], Option<bool>); 7] = [
        (&[], None),
        (&[true], Some(true)),
        (&[false], Some(false)),
        (&[true, false], Some(false)),
        (&[false, true], Some(true)),
        (&[true, true], Some(true)),
        (&[false, false], Some(false)),
    ];

    /// `words`, then the flags of `typed`, parsed by the command line's
    /// parser (its settings included: a repeated flag is accepted).
    pub(crate) fn matches<P: super::Pair>(words: &[&str], typed: &[bool]) -> clap::ArgMatches {
        let flags = typed.iter().map(|on| {
            let long = if *on { P::ON_LONG } else { P::OFF_LONG };
            format!("--{long}")
        });
        let line: Vec<String> = std::iter::once("opentide".to_owned())
            .chain(words.iter().map(|word| (*word).to_owned()))
            .chain(flags)
            .collect();
        crate::catalog::root()
            .try_get_matches_from(&line)
            .unwrap_or_else(|error| panic!("{line:?}: {error}"))
    }

    /// The matches of the last command of `words` (a word that is a value,
    /// not a command, is passed over).
    pub(crate) fn innermost<'m>(
        matches: &'m clap::ArgMatches,
        words: &[&str],
    ) -> &'m clap::ArgMatches {
        words
            .iter()
            .fold(matches, |current, word| match current.subcommand() {
                Some((name, sub)) if name == *word => sub,
                _ => current,
            })
    }
}

#[cfg(test)]
mod tests {
    use super::spellings::{SPELLINGS, innermost, matches};
    use super::*;
    use crate::tree::{
        AppToken, ExplorerPages, IncludePrebuilt, Inflight, Install, KeepDeprecated, LintChanged,
        Promotion, Prune, Publish, Sharing, Staging,
    };

    /// Every spelling of `P` on `words` gives what the flag typed last says.
    fn check<P: Pair>(words: &[&str]) {
        for (typed, want) in SPELLINGS {
            let matches = matches::<P>(words, typed);
            let toggle = Toggle::<P>::from_arg_matches(innermost(&matches, words))
                .unwrap_or_else(|error| panic!("{words:?} {typed:?}: {error}"));
            assert_eq!(toggle.get(), want, "{words:?} {}: {typed:?}", P::ON);
        }
    }

    #[test]
    fn every_pair_gives_the_flag_typed_last_or_none() {
        for words in [&["setup"][..], &["setup", "ci", "github"]] {
            check::<Staging>(words);
            check::<Inflight>(words);
            check::<Sharing>(words);
            check::<LintChanged>(words);
            check::<Promotion>(words);
            check::<ExplorerPages>(words);
            check::<AppToken>(words);
            check::<Prune>(words);
        }
        check::<Install>(&["setup", "hooks"]);
        check::<Publish>(&["share"]);
        check::<Publish>(&["share", "push"]);
        check::<KeepDeprecated>(&["deploy"]);
        check::<IncludePrebuilt>(&["generate", "extract", "elastic"]);
    }

    #[test]
    fn a_pair_not_given_falls_back_to_its_default() {
        for (value, default, want) in [
            (None, true, true),
            (None, false, false),
            (Some(true), false, true),
            (Some(false), true, false),
        ] {
            assert_eq!(Toggle::<Staging>::new(value).or(default), want);
        }
        assert_eq!(Toggle::<Staging>::default().get(), None);
        assert_eq!(
            format!("{:?}", Toggle::<Staging>::new(Some(false))),
            "staging(Some(false))"
        );
    }
}
