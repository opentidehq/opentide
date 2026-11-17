//! Following the next-page links a platform answers (Sentinel's `nextLink`,
//! Graph's `@odata.nextLink`).
//!
//! A next-page link is the server's URL, and the request that follows it
//! carries the tenant's bearer token. [`NextLinks`] follows a link only to
//! the origin (scheme, host and port) of the first page, so a link to another
//! host never receives the token; it refuses a link it has already followed,
//! so a link that points back never loops; and it stops after
//! [`MAX_PAGES`] pages with an error, never an endless listing.

use std::collections::HashSet;

use url::Url;

/// How many pages a listing may take: far more than any workspace's rules
/// (ARM and Graph answer 100 or more a page).
pub const MAX_PAGES: usize = 1000;

/// Why a next-page link is not followed.
#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
pub enum LinkError {
    /// The link is not a URL.
    #[error("the next-page link is not a URL")]
    NotAUrl,
    /// The link leaves the first page's origin: the token is not sent there.
    #[error(
        "the next-page link points to {link}, not to {first}, where the listing started; it is \
         not followed, so the tenant's token is not sent there"
    )]
    OtherOrigin {
        /// `scheme://host[:port]` of the first page.
        first: String,
        /// `scheme://host[:port]` of the link.
        link: String,
    },
    /// The link was followed before: the listing would loop.
    #[error("the next-page link repeats one already followed; the listing would never end")]
    Repeated,
    /// The listing took [`MAX_PAGES`] pages and still has another.
    #[error("the listing still has a next page after {0} pages; it is stopped there")]
    TooManyPages(usize),
}

/// The pages of one listing, from its first page's URL.
#[derive(Debug)]
pub struct NextLinks {
    first: Url,
    current: Url,
    seen: HashSet<String>,
    pages: usize,
    limit: usize,
}

impl NextLinks {
    /// A listing whose first page is `first`.
    ///
    /// # Errors
    ///
    /// `first` is not a URL.
    pub fn new(first: &str) -> Result<Self, LinkError> {
        Self::with_limit(first, MAX_PAGES)
    }

    /// [`NextLinks::new`], stopping after `limit` pages.
    ///
    /// # Errors
    ///
    /// `first` is not a URL.
    pub fn with_limit(first: &str, limit: usize) -> Result<Self, LinkError> {
        let first = Url::parse(first).map_err(|_| LinkError::NotAUrl)?;
        let mut seen = HashSet::new();
        seen.insert(first.as_str().to_owned());
        Ok(Self {
            current: first.clone(),
            first,
            seen,
            pages: 1,
            limit: limit.max(1),
        })
    }

    /// The URL of the page after the current one, from the server's `link`
    /// (absolute, or relative to the current page).
    ///
    /// # Errors
    ///
    /// The link is not a URL, leaves the first page's origin, was followed
    /// before, or the listing already took its pages.
    pub fn follow(&mut self, link: &str) -> Result<String, LinkError> {
        let next = self.current.join(link).map_err(|_| LinkError::NotAUrl)?;
        if next.origin() != self.first.origin() {
            return Err(LinkError::OtherOrigin {
                first: crate::error::origin(&self.first),
                link: crate::error::origin(&next),
            });
        }
        if !self.seen.insert(next.as_str().to_owned()) {
            return Err(LinkError::Repeated);
        }
        if self.pages >= self.limit {
            return Err(LinkError::TooManyPages(self.pages));
        }
        self.pages += 1;
        self.current = next;
        Ok(self.current.as_str().to_owned())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const FIRST: &str = "https://management.azure.com/rules?api-version=1";

    #[test]
    fn a_link_on_the_same_origin_is_followed() {
        let mut links = NextLinks::new(FIRST).unwrap_or_else(|error| panic!("{error}"));
        assert_eq!(
            links.follow("https://management.azure.com/rules?api-version=1&$skipToken=2"),
            Ok("https://management.azure.com/rules?api-version=1&$skipToken=2".to_owned())
        );
        assert_eq!(
            links.follow("/rules?api-version=1&$skipToken=3"),
            Ok("https://management.azure.com/rules?api-version=1&$skipToken=3".to_owned()),
            "a relative link is the current page's"
        );
    }

    #[test]
    fn a_link_to_another_origin_is_refused() {
        for link in [
            "https://evil.example/loop",
            "http://management.azure.com/rules",
            "https://management.azure.com:8443/rules",
            "https://management.azure.com.evil.example/rules",
            "//evil.example/rules",
        ] {
            let mut links = NextLinks::new(FIRST).unwrap_or_else(|error| panic!("{error}"));
            assert!(
                matches!(links.follow(link), Err(LinkError::OtherOrigin { .. })),
                "{link}"
            );
        }
        let mut links = NextLinks::new(FIRST).unwrap_or_else(|error| panic!("{error}"));
        assert_eq!(
            links
                .follow("https://evil.example/loop")
                .map_err(|e| e.to_string()),
            Err("the next-page link points to https://evil.example, not to \
                 https://management.azure.com, where the listing started; it is not followed, \
                 so the tenant's token is not sent there"
                .to_owned())
        );
    }

    #[test]
    fn a_repeated_link_is_refused() {
        let mut links = NextLinks::new(FIRST).unwrap_or_else(|error| panic!("{error}"));
        assert_eq!(links.follow(FIRST), Err(LinkError::Repeated), "itself");
        let mut links = NextLinks::new(FIRST).unwrap_or_else(|error| panic!("{error}"));
        let second = "https://management.azure.com/rules?page=2";
        assert!(links.follow(second).is_ok());
        assert!(
            links
                .follow("https://management.azure.com/rules?page=3")
                .is_ok()
        );
        assert_eq!(links.follow(second), Err(LinkError::Repeated), "a cycle");
    }

    #[test]
    fn the_pages_are_capped() {
        let mut links = NextLinks::with_limit(FIRST, 3).unwrap_or_else(|error| panic!("{error}"));
        assert!(links.follow("/rules?page=2").is_ok());
        assert!(links.follow("/rules?page=3").is_ok());
        assert_eq!(
            links.follow("/rules?page=4"),
            Err(LinkError::TooManyPages(3))
        );
    }

    #[test]
    fn a_first_page_that_is_not_a_url_is_refused() {
        assert!(matches!(NextLinks::new("rules"), Err(LinkError::NotAUrl)));
    }
}
