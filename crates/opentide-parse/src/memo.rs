//! The last parse of a text, kept on its thread: an editor asks a language
//! for the highlighting, the fields and the diagnostics of one text, and the
//! three share one parse (epic #1219's one-parse memo).

use std::cell::RefCell;
use std::rc::Rc;

/// The largest text a [`LastParse`] keeps, in bytes. Detection queries are a
/// few kilobytes.
pub const MEMO_MAX: usize = 64 * 1024;

/// The last parse made through it and the text it is of. A language holds one
/// in a `thread_local!` of its own:
///
/// ```
/// use std::rc::Rc;
/// use opentide_parse::LastParse;
///
/// fn parse_memo(source: &str) -> Rc<usize> {
///     thread_local! {
///         static LAST: LastParse<usize> = const { LastParse::new() };
///     }
///     LAST.with(|last| last.get(source, str::len))
/// }
///
/// let first = parse_memo("a:1 é😀");
/// assert!(Rc::ptr_eq(&first, &parse_memo("a:1 é😀")));
/// assert!(!Rc::ptr_eq(&first, &parse_memo("a:2")));
/// ```
#[derive(Debug, Default)]
pub struct LastParse<T> {
    last: RefCell<Option<(String, Rc<T>)>>,
}

impl<T> LastParse<T> {
    /// Nothing kept yet.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            last: RefCell::new(None),
        }
    }

    /// The parse of `source`: the one kept when it is of the same text, else
    /// `parse(source)`, which is then kept in place of the last one. A text
    /// past [`MEMO_MAX`] is not kept: an idle thread would hold it and its
    /// tree until its next query.
    pub fn get(&self, source: &str, parse: impl FnOnce(&str) -> T) -> Rc<T> {
        let mut last = self.last.borrow_mut();
        if let Some((text, parsed)) = last.as_ref()
            && text == source
        {
            return Rc::clone(parsed);
        }
        let parsed = Rc::new(parse(source));
        *last = (source.len() <= MEMO_MAX).then(|| (source.to_owned(), Rc::clone(&parsed)));
        parsed
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_same_text_shares_a_parse_and_a_text_past_the_cap_is_not_kept() {
        let memo = LastParse::new();
        let parses = std::cell::Cell::new(0);
        let parse = |source: &str| {
            parses.set(parses.get() + 1);
            source.chars().count()
        };
        let first = memo.get("é😀", parse);
        assert_eq!(*first, 2);
        assert!(Rc::ptr_eq(&first, &memo.get("é😀", parse)));
        assert_eq!(parses.get(), 1);
        assert!(!Rc::ptr_eq(&first, &memo.get("é", parse)));
        let large = "é".repeat(MEMO_MAX / 2 + 1);
        let once = memo.get(&large, parse);
        assert!(!Rc::ptr_eq(&once, &memo.get(&large, parse)));
        assert_eq!(parses.get(), 4);
    }
}
