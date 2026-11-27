//! Small file helpers the kept commands share: a directory tree copied with
//! its links, and a SHA-256 digest in hex (`opentide_core::text`'s). Moved
//! from `xtask::golden` (deleted with the golden recordings, #1142).

use std::fs;
use std::path::Path;

use anyhow::{Context, Result};

pub use opentide_core::text::sha256_hex;

/// Copies a directory tree: regular files with their permissions, directories,
/// and symbolic links as links.
///
/// # Errors
///
/// A file or directory that cannot be read, created or linked.
pub fn copy_tree(from: &Path, to: &Path) -> Result<()> {
    fs::create_dir_all(to).with_context(|| format!("create {}", to.display()))?;
    let mut entries: Vec<_> = fs::read_dir(from)
        .with_context(|| format!("read {}", from.display()))?
        .collect::<Result<_, _>>()
        .with_context(|| format!("read {}", from.display()))?;
    entries.sort_by_key(fs::DirEntry::file_name);
    for entry in entries {
        let source = entry.path();
        let target = to.join(entry.file_name());
        let kind = entry
            .file_type()
            .with_context(|| format!("stat {}", source.display()))?;
        if kind.is_dir() {
            copy_tree(&source, &target)?;
        } else if kind.is_symlink() {
            let link = fs::read_link(&source)
                .with_context(|| format!("read link {}", source.display()))?;
            symlink_dir(&link, &target)?;
        } else {
            fs::copy(&source, &target)
                .with_context(|| format!("copy {} to {}", source.display(), target.display()))?;
        }
    }
    Ok(())
}

#[cfg(unix)]
fn symlink_dir(link: &Path, target: &Path) -> Result<()> {
    std::os::unix::fs::symlink(link, target)
        .with_context(|| format!("link {} to {}", target.display(), link.display()))
}

/// Windows creates a directory symbolic link; that needs Developer Mode or
/// an elevated shell, which GitHub's Windows runners have.
#[cfg(windows)]
fn symlink_dir(link: &Path, target: &Path) -> Result<()> {
    std::os::windows::fs::symlink_dir(link, target).with_context(|| {
        format!(
            "link {} to {} (directory symbolic links on Windows need Developer Mode or an elevated shell)",
            target.display(),
            link.display()
        )
    })
}

#[cfg(not(any(unix, windows)))]
fn symlink_dir(_link: &Path, target: &Path) -> Result<()> {
    anyhow::bail!(
        "{}: symbolic links need a Unix or Windows host",
        target.display()
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fips_180_4_vectors() {
        assert_eq!(
            sha256_hex(b""),
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
        assert_eq!(
            sha256_hex(b"abc"),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
        assert_eq!(
            sha256_hex(b"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq"),
            "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1"
        );
    }
}
