//! The blob store, `tests/golden/blobs/<sha256>`: a recorded file of
//! [`THRESHOLD`] bytes or more is stored once by its SHA-256 and referenced
//! from `outcome.toml`, so the same generated schema written by forty cases
//! takes its size once.
//!
//! The SHA-256 here addresses content; it guards against nothing. It is
//! RustCrypto's FIPS 180-4 implementation, checked against the standard's
//! test vectors below.

use anyhow::{Context, Result, ensure};
use std::collections::BTreeSet;
use std::fs;
use std::path::Path;

/// Files this large or larger go to the blob store.
pub const THRESHOLD: usize = 16 * 1024;

/// Stores `bytes` under its hash in `dir` (once) and returns the hash.
pub fn put(dir: &Path, bytes: &[u8]) -> Result<String> {
    let hash = sha256_hex(bytes);
    let path = dir.join(&hash);
    if !path.is_file() {
        fs::create_dir_all(dir).with_context(|| format!("create {}", dir.display()))?;
        fs::write(&path, bytes).with_context(|| format!("write {}", path.display()))?;
    }
    Ok(hash)
}

/// Reads the blob `hash` from `dir`, checking that its bytes still have that hash.
pub fn get(dir: &Path, hash: &str) -> Result<Vec<u8>> {
    let path = dir.join(hash);
    let bytes = fs::read(&path).with_context(|| format!("read the blob {}", path.display()))?;
    ensure!(
        sha256_hex(&bytes) == hash,
        "the blob {} does not match its name: never edit a blob",
        path.display()
    );
    Ok(bytes)
}

/// The blobs in `dir` that `used` does not name.
pub fn unused(dir: &Path, used: &BTreeSet<String>) -> Result<Vec<String>> {
    let mut out = Vec::new();
    if !dir.is_dir() {
        return Ok(out);
    }
    for entry in fs::read_dir(dir).with_context(|| format!("read {}", dir.display()))? {
        let entry = entry.with_context(|| format!("read {}", dir.display()))?;
        let name = entry.file_name().to_string_lossy().into_owned();
        ensure!(
            entry.file_type().is_ok_and(|t| t.is_file()),
            "blobs/{name}: only blob files belong in the blob store"
        );
        if !used.contains(&name) {
            out.push(name);
        }
    }
    out.sort();
    Ok(out)
}

/// SHA-256 of `data`, as 64 lower-case hex digits: RustCrypto's (`sha2`,
/// through opentide-compare), which keeps its speed in a debug build. A
/// hand-written one, unoptimised there, made every blob read cost
/// milliseconds: `codegen --check` spent most of Engine lint's minutes
/// hashing the recordings it compares (#841).
pub fn sha256_hex(data: &[u8]) -> String {
    opentide_compare::ledger::sha256_hex(data)
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
        assert_eq!(
            sha256_hex(&vec![b'a'; 1_000_000]),
            "cdc76e5c9914fb9281a1c7e284d73e67f1809a48a497200e046d39ccc7112cd0"
        );
        // 55 and 56 bytes: the padding boundary.
        assert_eq!(sha256_hex(&[b'x'; 55]).len(), 64);
        assert_ne!(sha256_hex(&[b'x'; 55]), sha256_hex(&[b'x'; 56]));
    }

    #[test]
    fn stores_once_and_rejects_an_edited_blob() {
        let dir = tempfile::tempdir().unwrap();
        let hash = put(dir.path(), b"abc").unwrap();
        assert_eq!(put(dir.path(), b"abc").unwrap(), hash);
        assert_eq!(get(dir.path(), &hash).unwrap(), b"abc");
        fs::write(dir.path().join(&hash), b"abd").unwrap();
        assert!(get(dir.path(), &hash).is_err());
        put(dir.path(), b"other").unwrap();
        let used = BTreeSet::from([hash]);
        assert_eq!(unused(dir.path(), &used).unwrap(), [sha256_hex(b"other")]);
        fs::create_dir(dir.path().join("stray")).unwrap();
        assert!(
            unused(dir.path(), &used)
                .unwrap_err()
                .to_string()
                .contains("stray")
        );
    }
}
