//! Shell scripts written to run at once: launchers, and the stand-ins the
//! tests put in place of `python`, `opentide` or a language server.
//!
//! A script written with `std::fs::write` and executed straight after can
//! fail with `ETXTBSY` ("Text file busy") when another thread of the same
//! process forks while the file is open for writing: the child inherits the
//! writable descriptor and holds it until its own `exec`, and the kernel
//! refuses to execute a file someone has open for writing. Closing,
//! syncing or renaming the file does not help, since the inherited
//! descriptor is on the same inode. [`write_executable`] never opens the
//! file in this process: a `/bin/sh` child writes it and makes it
//! executable, so no fork of this process can hold it open.

use std::io::Write as _;
use std::path::Path;
use std::process::{Command, Stdio};

use anyhow::{Context as _, Result, ensure};

/// Writes `text` to `path` (replacing it) with mode `0o755`, from a child
/// process, so that this process never holds the file open for writing and
/// can execute it as soon as this returns, whatever its other threads spawn.
pub fn write_executable(path: &Path, text: &str) -> Result<()> {
    let mut child = Command::new("/bin/sh")
        .args(["-c", "cat > \"$1\" && chmod 755 \"$1\"", "sh"])
        .arg(path)
        .stdin(Stdio::piped())
        .spawn()
        .with_context(|| format!("start /bin/sh to write {}", path.display()))?;
    let written = child
        .stdin
        .take()
        .context("the shell's stdin")?
        .write_all(text.as_bytes());
    // stdin is dropped (closed) above, so `cat` sees the end of the text.
    let status = child
        .wait()
        .with_context(|| format!("wait for the shell writing {}", path.display()))?;
    written.with_context(|| format!("send {} to the shell", path.display()))?;
    ensure!(
        status.success(),
        "write {}: the shell {status}",
        path.display()
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::os::unix::fs::PermissionsExt as _;

    use super::write_executable;

    #[test]
    fn the_script_is_executable_and_runs_at_once_from_many_threads() {
        let dir = tempfile::tempdir().unwrap();
        // Threads that write and run scripts at once: with `std::fs::write`
        // some runs fail with ETXTBSY, as one thread's fork holds another's
        // file open for writing.
        std::thread::scope(|scope| {
            for thread in 0..8 {
                let dir = dir.path();
                scope.spawn(move || {
                    for run in 0..25 {
                        let path = dir.join(format!("script-{thread}-{run}"));
                        write_executable(&path, &format!("#!/bin/sh\necho {thread}-{run}\n"))
                            .unwrap();
                        let mode = std::fs::metadata(&path).unwrap().permissions().mode();
                        assert_eq!(mode & 0o777, 0o755);
                        let output = std::process::Command::new(&path).output().unwrap();
                        assert_eq!(
                            String::from_utf8_lossy(&output.stdout),
                            format!("{thread}-{run}\n")
                        );
                    }
                });
            }
        });
        // An existing file is replaced, not appended to.
        let path = dir.path().join("script-0-0");
        write_executable(&path, "#!/bin/sh\necho again\n").unwrap();
        assert_eq!(
            std::fs::read_to_string(&path).unwrap(),
            "#!/bin/sh\necho again\n"
        );
    }

    #[test]
    fn a_path_that_cannot_be_written_is_an_error() {
        let dir = tempfile::tempdir().unwrap();
        let error = write_executable(&dir.path().join("no/such/dir/script"), "").unwrap_err();
        assert!(
            format!("{error:#}").contains("the shell exit status"),
            "{error:#}"
        );
    }
}
