//! Query strings and form bodies as `requests` encodes them (`urlencode`
//! with `quote_plus`): letters, digits and `_.-~` kept, a space as `+`,
//! every other byte of the UTF-8 text as `%XX`. The `percent-encoding`
//! crate does the encoding; `form_urlencoded` keeps `*` and escapes `~`,
//! which would change the bytes a tenant receives.

use percent_encoding::{AsciiSet, NON_ALPHANUMERIC, utf8_percent_encode};

/// What `quote_plus` escapes, the space aside (written `+`).
const QUOTE_PLUS: &AsciiSet = &NON_ALPHANUMERIC
    .remove(b'_')
    .remove(b'.')
    .remove(b'-')
    .remove(b'~')
    .remove(b' ');

/// What `quote(value, safe='')` escapes: a path segment.
const QUOTE: &AsciiSet = &NON_ALPHANUMERIC
    .remove(b'_')
    .remove(b'.')
    .remove(b'-')
    .remove(b'~');

/// *value* as one path segment (`urllib.parse.quote(value, safe="")`).
pub fn segment(value: &str) -> String {
    utf8_percent_encode(value, QUOTE).to_string()
}

/// *value* as `quote_plus` writes it.
pub fn quote_plus(value: &str) -> String {
    utf8_percent_encode(value, QUOTE_PLUS)
        .to_string()
        .replace(' ', "+")
}

/// `key=value&...` in the pairs' order (`urlencode`).
pub fn urlencode<'a>(pairs: impl IntoIterator<Item = (&'a str, &'a str)>) -> String {
    pairs
        .into_iter()
        .map(|(key, value)| format!("{}={}", quote_plus(key), quote_plus(value)))
        .collect::<Vec<_>>()
        .join("&")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encodes_as_requests_does() {
        assert_eq!(
            urlencode([
                ("@event_create_date__gte", "2026-10-26T08:00:00.000Z"),
                ("q", "a b*~/é")
            ]),
            "%40event_create_date__gte=2026-10-26T08%3A00%3A00.000Z&q=a+b%2A~%2F%C3%A9"
        );
        assert_eq!(segment("a b/c~"), "a%20b%2Fc~");
    }
}
