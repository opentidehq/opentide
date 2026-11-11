//! The four Markdown flavours (`documentation/format/`): what each changes in
//! a page, file names, links, heading anchors and diagrams. The layout of a
//! page is the templates'; this is what differs from one forge to another.

use unicode_properties::{GeneralCategoryGroup, UnicodeGeneralCategory};

/// A Markdown flavour (`DocumentFlavor`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Flavor {
    /// GitHub.
    Github,
    /// A GitLab wiki.
    Gitlab,
    /// An Azure DevOps wiki.
    AzureDevops,
    /// Plain CommonMark.
    Generic,
}

impl Flavor {
    /// The flavour a name gives (`azure-devops` read as `azure_devops`).
    pub fn from_name(name: &str) -> Option<Self> {
        match name.replace('-', "_").as_str() {
            "github" => Some(Self::Github),
            "gitlab" => Some(Self::Gitlab),
            "azure_devops" => Some(Self::AzureDevops),
            "generic" => Some(Self::Generic),
            _ => None,
        }
    }

    /// The flavour's name, as the templates test it.
    pub fn name(self) -> &'static str {
        match self {
            Self::Github => "github",
            Self::Gitlab => "gitlab",
            Self::AzureDevops => "azure_devops",
            Self::Generic => "generic",
        }
    }

    /// Whether object links are wiki links (GitLab and Azure DevOps wikis).
    pub fn wiki_links(self) -> bool {
        matches!(self, Self::Gitlab | Self::AzureDevops)
    }

    /// The file name of a page: its slug, or its UUID on GitLab with UUID
    /// permalinks (`page_filename`).
    pub fn page_filename(self, slug: &str, uuid: Option<&str>) -> String {
        match self {
            Self::Github | Self::Generic => format!("{slug}.md"),
            Self::Gitlab => format!("{}.md", uuid.unwrap_or(slug)),
            Self::AzureDevops => format!("{}.md", slug.replace(' ', "-")),
        }
    }

    /// A Markdown link.
    pub fn link(text: &str, target: &str) -> String {
        format!("[{text}]({target})")
    }

    /// A link to a page of the wiki: GitLab drops `.md`, Azure DevOps links
    /// the page by its name from the wiki's root.
    pub fn wiki_link(self, text: &str, target: &str) -> String {
        match self {
            Self::Gitlab => Self::link(text, target.strip_suffix(".md").unwrap_or(target)),
            Self::AzureDevops => {
                let page = target.replace(".md", "");
                let page = page.rsplit('/').next().unwrap_or_default();
                Self::link(text, &format!("/{page}"))
            }
            Self::Github | Self::Generic => Self::link(text, target),
        }
    }

    /// A link, as a wiki link when `wiki` (`render_link`).
    pub fn render_link(self, text: &str, target: &str, wiki: bool) -> String {
        if wiki {
            self.wiki_link(text, target)
        } else {
            Self::link(text, target)
        }
    }

    /// The anchor a heading gets: GitHub's (github-slugger's rule, without
    /// its numbering of repeated headings), else the page slug of the title.
    pub fn heading_anchor(self, title: &str) -> String {
        match self {
            Self::Github => title
                .trim()
                .to_lowercase()
                .chars()
                .filter(|c| {
                    matches!(c, ' ' | '-' | '_')
                        || matches!(
                            c.general_category_group(),
                            GeneralCategoryGroup::Letter
                                | GeneralCategoryGroup::Mark
                                | GeneralCategoryGroup::Number
                        )
                })
                .collect::<String>()
                .replace(' ', "-"),
            _ => slugify(title),
        }
    }

    /// Mermaid's diagram keyword: Azure DevOps renders `graph`, not
    /// `flowchart`.
    pub fn diagram_type(self) -> &'static str {
        match self {
            Self::AzureDevops => "graph",
            _ => "flowchart",
        }
    }

    /// Whether diagrams may group nodes in subgraphs (not on Azure DevOps).
    pub fn subgraphs(self) -> bool {
        self != Self::AzureDevops
    }

    /// The diagram as the flavour renders it: Azure DevOps fails on the
    /// `flowchart` keyword and on arrows longer than `-->`.
    pub fn diagram(self, diagram: &str) -> String {
        if self != Self::AzureDevops {
            return diagram.to_owned();
        }
        let downgraded = diagram.replacen("flowchart", "graph", 1);
        shorten_arrows(&downgraded)
    }
}

/// `---->` (four dashes or more before `>`) as `-->`.
fn shorten_arrows(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    let mut rest = text;
    while let Some(start) = rest.find("----") {
        let dashes = rest[start..].bytes().take_while(|b| *b == b'-').count();
        let end = start + dashes;
        out.push_str(&rest[..start]);
        if rest[end..].starts_with('>') {
            out.push_str("-->");
            rest = &rest[end + 1..];
        } else {
            out.push_str(&rest[start..end]);
            rest = &rest[end..];
        }
    }
    out.push_str(rest);
    out
}

/// A file name's stem from an object's name: ASCII letters and digits, each
/// other run a `-`, lowercase; `object` when nothing is left (`slugify`).
pub fn slugify(name: &str) -> String {
    let mut slug = String::with_capacity(name.len());
    let mut gap = false;
    for c in name.trim().chars() {
        if c.is_ascii_alphanumeric() {
            if gap && !slug.is_empty() {
                slug.push('-');
            }
            gap = false;
            slug.push(c.to_ascii_lowercase());
        } else {
            gap = true;
        }
    }
    if slug.is_empty() {
        "object".to_owned()
    } else {
        slug
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn slugs() {
        assert_eq!(slugify("Sentinel KQL Rule"), "sentinel-kql-rule");
        assert_eq!(slugify("  --Sentinel-KQL  rule!! "), "sentinel-kql-rule");
        assert_eq!(slugify("éé"), "object");
        assert_eq!(slugify("a.b"), "a-b");
    }

    #[test]
    fn file_names_and_links() {
        assert_eq!(Flavor::Generic.page_filename("a-b", None), "a-b.md");
        assert_eq!(Flavor::Gitlab.page_filename("a-b", Some("u")), "u.md");
        assert_eq!(Flavor::Gitlab.page_filename("a-b", None), "a-b.md");
        assert_eq!(
            Flavor::AzureDevops.page_filename("a b", Some("u")),
            "a-b.md"
        );
        assert_eq!(
            Flavor::Gitlab.wiki_link("X", "../rules/x.md"),
            "[X](../rules/x)"
        );
        assert_eq!(
            Flavor::AzureDevops.wiki_link("X", "../rules/x.md"),
            "[X](/x)"
        );
        assert_eq!(Flavor::Github.render_link("X", "x.md", true), "[X](x.md)");
    }

    #[test]
    fn anchors() {
        assert_eq!(
            Flavor::Github.heading_anchor("Suspicious logon: signal (v2)"),
            "suspicious-logon-signal-v2"
        );
        assert_eq!(Flavor::Github.heading_anchor("a  b_c"), "a--b_c");
        assert_eq!(Flavor::Generic.heading_anchor("a  b_c"), "a-b-c");
    }

    #[test]
    fn azure_diagrams() {
        assert_eq!(
            Flavor::AzureDevops.diagram("flowchart TB\na ----> b\nc --- d\nflowchart"),
            "graph TB\na --> b\nc --- d\nflowchart"
        );
        assert_eq!(Flavor::Github.diagram("flowchart TB"), "flowchart TB");
    }
}
