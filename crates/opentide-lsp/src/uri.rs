//! `file:` URIs ↔ filesystem paths, with the `url` crate (#185 P0.3).
//!
//! `url` reads drive letters, UNC hosts and percent-encoding the way the
//! platform's paths need them: on Windows `file:///c%3A/x` is `c:\x` and
//! `file://server/share/x` is `\\server\share\x`, so a URI the editor sends
//! names the same file as the path a directory walk finds. A URI that is not
//! a `file:` URI (`untitled:Untitled-1`) is kept as it is, both ways.

/// The filesystem path of a `file:` URI, or the URI itself for any other
/// scheme (an unsaved buffer).
pub fn uri_to_path(uri: &str) -> String {
    let Ok(url) = url::Url::parse(uri) else {
        return uri.to_string();
    };
    if url.scheme() != "file" {
        return uri.to_string();
    }
    if let Some(path) = file_path_of(&url) {
        // A Windows drive URI read on another platform (`/c:/x`): the drive
        // path, as a Windows editor means it.
        let bytes = path.as_bytes();
        if bytes.len() >= 3
            && bytes[0] == b'/'
            && bytes[1].is_ascii_alphabetic()
            && bytes[2] == b':'
        {
            return path.strip_prefix('/').unwrap_or(&path).to_string();
        }
        return path;
    }
    // A UNC URI on a platform without UNC paths: `//server/share/x`.
    let decoded = percent_decode(url.path());
    match url.host_str() {
        Some(host) if !host.is_empty() && host != "localhost" => format!("//{host}{decoded}"),
        _ => decoded,
    }
}

/// A filesystem path as a `file:` URI, the inverse of [`uri_to_path`]. A
/// URI of another scheme, which [`uri_to_path`] keeps as it is
/// (`vscode-vfs://github/org/repo` on vscode.dev, `untitled:Untitled-1`, an
/// `opentide-object:<uuid>` a host supplied), is that URI. A drive letter
/// (`c:/x`) is not a scheme.
pub fn path_to_uri(path: &str) -> String {
    if path.starts_with("file://") {
        return path.to_string();
    }
    if url::Url::parse(path).is_ok_and(|url| url.scheme().len() > 1) {
        return path.to_string();
    }
    if let Some(uri) = file_uri_of(path) {
        return uri;
    }
    // Not an absolute path on this platform (a Windows drive path read
    // elsewhere): encode it by hand, as a Windows host would write it.
    let normalized = path.replace('\\', "/");
    let slash = if normalized.starts_with('/') { "" } else { "/" };
    let encoded = percent_encoding::utf8_percent_encode(&normalized, PATH_ESCAPED);
    format!("file://{slash}{encoded}")
}

/// What [`path_to_uri`] escapes: every byte but the unreserved characters,
/// the sub-delimiters, `/`, `:` and `@` (RFC 3986's `pchar` and `/`).
const PATH_ESCAPED: &percent_encoding::AsciiSet = &percent_encoding::NON_ALPHANUMERIC
    .remove(b'/')
    .remove(b'-')
    .remove(b'.')
    .remove(b'_')
    .remove(b'~')
    .remove(b':')
    .remove(b'!')
    .remove(b'$')
    .remove(b'&')
    .remove(b'\'')
    .remove(b'(')
    .remove(b')')
    .remove(b'*')
    .remove(b'+')
    .remove(b',')
    .remove(b';')
    .remove(b'=')
    .remove(b'@');

/// What `url` makes of a `file:` URL on a platform with file paths.
/// `wasm32-unknown-unknown` (the browser build) has none: [`uri_to_path`]
/// decodes the URL's path by hand there, as it does for a UNC URI.
#[cfg(any(unix, windows, target_os = "redox", target_os = "wasi"))]
fn file_path_of(url: &url::Url) -> Option<String> {
    url.to_file_path()
        .ok()
        .map(|path| path.display().to_string())
}

#[cfg(not(any(unix, windows, target_os = "redox", target_os = "wasi")))]
fn file_path_of(_url: &url::Url) -> Option<String> {
    None
}

/// What `url` makes of an absolute path on a platform with file paths; the
/// browser build encodes it by hand ([`path_to_uri`]).
#[cfg(any(unix, windows, target_os = "redox", target_os = "wasi"))]
fn file_uri_of(path: &str) -> Option<String> {
    url::Url::from_file_path(std::path::Path::new(path))
        .ok()
        .map(|url| url.to_string())
}

#[cfg(not(any(unix, windows, target_os = "redox", target_os = "wasi")))]
fn file_uri_of(_path: &str) -> Option<String> {
    None
}

/// `text` with its `%XX` escapes decoded; a `%` not followed by two hex
/// digits is kept, and a path that does not decode to UTF-8 is kept as it is.
fn percent_decode(text: &str) -> String {
    percent_encoding::percent_decode_str(text)
        .decode_utf8()
        .map_or_else(|_| text.to_string(), std::borrow::Cow::into_owned)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn file_uris_become_paths_and_back() {
        assert_eq!(
            uri_to_path("file:///home/u/My%20Detections"),
            "/home/u/My Detections"
        );
        assert_eq!(uri_to_path("file://localhost/srv/d%C3%A9t"), "/srv/dét");
        assert_eq!(uri_to_path("untitled:Untitled-1"), "untitled:Untitled-1");
        assert_eq!(uri_to_path("file:///a/100%"), "/a/100%");
        for path in ["/home/u/My Detections/a#1.yaml", "/srv/dét/r.yaml"] {
            assert_eq!(uri_to_path(&path_to_uri(path)), path, "{path}");
        }
        assert_eq!(path_to_uri("/a b"), "file:///a%20b");
        assert_eq!(uri_to_path("file:///C:/d%C3%A9t/%F0%9F%98%80"), "C:/dét/😀");
    }

    #[test]
    fn escapes_decode_to_the_end_and_bad_ones_are_kept() {
        assert_eq!(percent_decode("/a%20b%20"), "/a b ");
        assert_eq!(percent_decode("/r%23"), "/r#");
        assert_eq!(percent_decode("/d%C3%A9t"), "/dét");
        // Not an escape: `%` with fewer than two hex digits after it.
        assert_eq!(percent_decode("/100%"), "/100%");
        assert_eq!(percent_decode("/a%2"), "/a%2");
        assert_eq!(percent_decode("/a%zz"), "/a%zz");
        // Not UTF-8 once decoded: the path as it came.
        assert_eq!(percent_decode("/a%FF"), "/a%FF");
    }

    #[cfg(not(windows))]
    #[test]
    fn a_drive_path_read_elsewhere_is_escaped_as_a_windows_host_writes_it() {
        assert_eq!(
            path_to_uri(r"c:\Users\u\My Detections\dét (1)#~.yaml"),
            "file:///c:/Users/u/My%20Detections/d%C3%A9t%20(1)%23~.yaml"
        );
        assert_eq!(
            uri_to_path("file://server/share/My%20Rule%20"),
            "//server/share/My Rule "
        );
    }

    #[test]
    fn a_uri_of_another_scheme_stays_that_uri() {
        for uri in [
            "vscode-vfs://github/org/repo",
            "vscode-vfs://github/org/repo/objects/rules/r.yaml",
            "untitled:Untitled-1",
            "opentide-object:00000000-0000-4000-8002-000000000001",
        ] {
            assert_eq!(path_to_uri(&uri_to_path(uri)), uri);
        }
    }

    #[cfg(not(windows))]
    #[test]
    fn windows_and_unc_uris_read_elsewhere_keep_their_shape() {
        assert_eq!(uri_to_path("file:///c%3A/Users/u/det"), "c:/Users/u/det");
        assert_eq!(uri_to_path("file:///C:/Users/u/det"), "C:/Users/u/det");
        assert_eq!(
            uri_to_path("file://server/share/r.yaml"),
            "//server/share/r.yaml"
        );
        assert_eq!(path_to_uri("c:/x"), "file:///c:/x");
        assert_eq!(
            uri_to_path(&path_to_uri("c:/Users/u/r.yaml")),
            "c:/Users/u/r.yaml"
        );
    }

    /// #185 P0.3: on Windows a URI and a walked path name one file.
    #[cfg(windows)]
    #[test]
    fn windows_uris_are_native_paths() {
        assert_eq!(uri_to_path("file:///c%3A/Users/u/det"), r"c:\Users\u\det");
        assert_eq!(uri_to_path("file:///C:/Users/u/det"), r"C:\Users\u\det");
        assert_eq!(
            uri_to_path("file://server/share/r.yaml"),
            r"\\server\share\r.yaml"
        );
        let path = r"C:\Users\u\My Detections\r.yaml";
        assert_eq!(uri_to_path(&path_to_uri(path)), path);
        assert_eq!(
            path_to_uri(r"\\server\share\r.yaml"),
            "file://server/share/r.yaml"
        );
    }
}
