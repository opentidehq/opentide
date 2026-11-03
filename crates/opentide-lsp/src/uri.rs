//! `file:` URIs ↔ filesystem paths, with the `url` crate (#185 P0.3).
//!
//! `url` reads drive letters, UNC hosts and percent-encoding the way the
//! platform's paths need them: on Windows `file:///c%3A/x` is `c:\x` and
//! `file://server/share/x` is `\\server\share\x`, so a URI the editor sends
//! names the same file as the path a directory walk finds. A URI that is not
//! a `file:` URI (`untitled:Untitled-1`) is kept as it is.

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
            return path[1..].to_string();
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

/// A filesystem path as a `file:` URI, the inverse of [`uri_to_path`].
pub fn path_to_uri(path: &str) -> String {
    if path.starts_with("file://") {
        return path.to_string();
    }
    if let Some(uri) = file_uri_of(path) {
        return uri;
    }
    // Not an absolute path on this platform (a Windows drive path read
    // elsewhere): encode it by hand, as a Windows host would write it.
    let normalized = path.replace('\\', "/");
    let mut out = String::from("file://");
    if !normalized.starts_with('/') {
        out.push('/');
    }
    for ch in normalized.chars() {
        let keep = ch.is_ascii_alphanumeric() || "/-._~:!$&'()*+,;=@".contains(ch);
        if keep {
            out.push(ch);
        } else {
            let mut buf = [0u8; 4];
            for byte in ch.encode_utf8(&mut buf).bytes() {
                out.push_str(&format!("%{byte:02X}"));
            }
        }
    }
    out
}

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

fn percent_decode(text: &str) -> String {
    let bytes = text.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%' && i + 2 < bytes.len() {
            let hex = std::str::from_utf8(&bytes[i + 1..i + 3]).ok();
            if let Some(value) = hex.and_then(|h| u8::from_str_radix(h, 16).ok()) {
                out.push(value);
                i += 3;
                continue;
            }
        }
        out.push(bytes[i]);
        i += 1;
    }
    String::from_utf8(out).unwrap_or_else(|_| text.to_string())
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
