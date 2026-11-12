//! `--show-completion` and `--install-completion` (#841, decision D2): a
//! shell's completion script for `opentide`, written by `clap_complete` from
//! the command tree.
//!
//! The options are the Python CLI's: each takes the shell as the word after
//! it (`opentide --show-completion zsh`), or completes for the shell it runs
//! in. `--install-completion` writes the script where Typer wrote it and adds
//! the line that loads it to the shell's start-up file, once:
//!
//! | Shell | Script | Loaded by |
//! |-------|--------|-----------|
//! | bash | `~/.bash_completions/opentide.sh` | `source '<script>'` in `~/.bashrc` |
//! | zsh | `~/.zfunc/_opentide` | `fpath+=~/.zfunc; autoload -Uz compinit; compinit` in `~/.zshrc` |
//! | fish | `~/.config/fish/completions/opentide.fish` | fish itself |
//! | powershell, pwsh | appended to the shell's `$PROFILE` | the profile |
//!
//! The scripts are clap's, which complete the commands, options and choices
//! from the script itself: they no longer run opentide on each Tab press, so
//! they keep working whatever Python is installed.

use std::io::Write as _;
use std::path::{Path, PathBuf};

use crate::catalog::PROGRAM;

/// The shells a script is written for, as the options name them.
pub const SHELLS: &[&str] = &["bash", "zsh", "fish", "powershell", "pwsh"];

/// `opentide <option> [bash|zsh|fish|powershell|pwsh]`: the form a usage
/// error names.
pub fn form(option: &str) -> String {
    format!("{PROGRAM} {option} [{}]", SHELLS.join("|"))
}

/// The shell named by the words after the option, or `Err` with the usage
/// error's message: `None` words means none were typed.
///
/// # Errors
///
/// The words are not exactly one shell's name.
pub fn named_shell(words: &[String], option: &str) -> Result<Option<&'static str>, String> {
    match words {
        [] => Ok(None),
        [word] if SHELLS.contains(&word.as_str()) => {
            Ok(SHELLS.iter().copied().find(|shell| shell == word))
        }
        _ => Err(format!(
            "Invalid value for '{option}': '{}' is not a supported shell. Use: {}",
            words.join(" "),
            form(option)
        )),
    }
}

/// The shell this process runs under: the nearest shell among its parent
/// processes (Linux), else `SHELL`'s program.
pub fn detect(shell_env: Option<&str>) -> Option<&'static str> {
    parent_shells()
        .into_iter()
        .find_map(|name| shell_named(&name))
        .or_else(|| shell_env.and_then(shell_named))
}

/// The shell a program is (`/usr/bin/zsh`, `-bash`, `pwsh.exe`), if it is one.
pub fn shell_named(program: &str) -> Option<&'static str> {
    let name = program.trim().trim_start_matches('-');
    let name = name.rsplit(['/', '\\']).next().unwrap_or(name);
    let name = name.strip_suffix(".exe").unwrap_or(name);
    SHELLS.iter().copied().find(|shell| *shell == name)
}

/// The names of this process's ancestors, nearest first (Linux's `/proc`;
/// nothing elsewhere).
fn parent_shells() -> Vec<String> {
    let mut names = Vec::new();
    let mut pid = std::process::id().to_string();
    for _ in 0..16 {
        let Ok(stat) = std::fs::read_to_string(format!("/proc/{pid}/stat")) else {
            break;
        };
        // `pid (comm) state ppid …`: comm may hold spaces and parentheses.
        let Some(after) = stat.rfind(')').and_then(|end| stat.get(end + 1..)) else {
            break;
        };
        let Some(parent) = after.split_whitespace().nth(1) else {
            break;
        };
        if parent == "0" || parent == pid {
            break;
        }
        if let Ok(comm) = std::fs::read_to_string(format!("/proc/{parent}/comm")) {
            names.push(comm.trim().to_owned());
        }
        parent.clone_into(&mut pid);
    }
    names
}

/// The completion script of `shell` for the command tree `root`.
pub fn script(root: &clap::Command, shell: &str) -> String {
    let generator = match shell {
        "zsh" => clap_complete::Shell::Zsh,
        "fish" => clap_complete::Shell::Fish,
        "powershell" | "pwsh" => clap_complete::Shell::PowerShell,
        _ => clap_complete::Shell::Bash,
    };
    let mut command = root.clone();
    let mut bytes = Vec::new();
    clap_complete::generate(generator, &mut command, PROGRAM, &mut bytes);
    String::from_utf8_lossy(&bytes).into_owned()
}

/// Where `--install-completion` put a script, and how to load it now.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Installed {
    /// The script's file (the profile, for PowerShell).
    pub path: PathBuf,
    /// The command that loads it in the running shell (`source ~/.bashrc`),
    /// empty where only a restart does.
    pub reload: &'static str,
    /// What the next step says beside it.
    pub reason: &'static str,
}

/// Appends `line` to the start-up file `rc` unless a line of it already is
/// `line`, keeping every byte the file has.
fn add_line(rc: &Path, line: &str) -> std::io::Result<()> {
    let existing = match std::fs::read(rc) {
        Ok(bytes) => bytes,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Vec::new(),
        Err(error) => return Err(error),
    };
    let text = String::from_utf8_lossy(&existing);
    if text
        .lines()
        .any(|found| found.trim_end_matches('\r') == line)
    {
        return Ok(());
    }
    if let Some(parent) = rc.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let mut file = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(rc)?;
    let newline = if text.contains("\r\n") { "\r\n" } else { "\n" };
    let lead = if existing.is_empty() || existing.ends_with(b"\n") {
        ""
    } else {
        newline
    };
    write!(file, "{lead}{line}{newline}")?;
    file.flush()
}

fn write_script(path: &Path, text: &str) -> std::io::Result<()> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    std::fs::write(path, text)
}

/// Installs `script` (the script of `shell`) under `home`. `profile` names
/// PowerShell's profile when the shell is PowerShell: [`powershell_profile`].
///
/// # Errors
///
/// A file cannot be read or written.
pub fn install(
    shell: &str,
    script: &str,
    home: &Path,
    profile: Option<&Path>,
) -> std::io::Result<Installed> {
    match shell {
        "zsh" => {
            let path = home.join(".zfunc").join(format!("_{PROGRAM}"));
            write_script(&path, script)?;
            add_line(
                &home.join(".zshrc"),
                "fpath+=~/.zfunc; autoload -Uz compinit; compinit",
            )?;
            Ok(Installed {
                path,
                reload: "source ~/.zshrc",
                reason: "or restart your shell",
            })
        }
        "fish" => {
            let path = home
                .join(".config")
                .join("fish")
                .join("completions")
                .join(format!("{PROGRAM}.fish"));
            write_script(&path, script)?;
            Ok(Installed {
                path,
                reload: "exec fish",
                reason: "restart your shell",
            })
        }
        "powershell" | "pwsh" => {
            let path = profile.map_or_else(
                || {
                    home.join("Documents")
                        .join("PowerShell")
                        .join("Microsoft.PowerShell_profile.ps1")
                },
                Path::to_path_buf,
            );
            let marker = format!("Register-ArgumentCompleter -Native -CommandName '{PROGRAM}'");
            let existing = std::fs::read_to_string(&path).unwrap_or_default();
            if !existing.contains(&marker) {
                if let Some(parent) = path.parent() {
                    std::fs::create_dir_all(parent)?;
                }
                let mut file = std::fs::OpenOptions::new()
                    .create(true)
                    .append(true)
                    .open(&path)?;
                writeln!(file, "{script}")?;
            }
            Ok(Installed {
                path,
                reload: ". $PROFILE",
                reason: "or restart your shell",
            })
        }
        _ => {
            let path = home.join(".bash_completions").join(format!("{PROGRAM}.sh"));
            write_script(&path, script)?;
            add_line(
                &home.join(".bashrc"),
                &format!("source '{}'", path.display()),
            )?;
            Ok(Installed {
                path,
                reload: "source ~/.bashrc",
                reason: "or restart your shell",
            })
        }
    }
}

/// PowerShell's profile, as `<shell> -NoProfile -Command echo $profile`
/// prints it; `None` when the shell does not answer.
pub fn powershell_profile(shell: &str) -> Option<PathBuf> {
    let output = std::process::Command::new(shell)
        .args(["-NoProfile", "-Command", "echo", "$profile"])
        .stdin(std::process::Stdio::null())
        .output()
        .ok()?;
    let text = String::from_utf8_lossy(&output.stdout).trim().to_owned();
    (output.status.success() && !text.is_empty()).then(|| PathBuf::from(text))
}

/// `path` as a person types it from `cwd`: relative inside it, else `~/…`
/// under `home`, else whole.
pub fn person_path(path: &Path, cwd: &Path, home: Option<&Path>) -> String {
    if let Ok(relative) = path.strip_prefix(cwd)
        && !relative.as_os_str().is_empty()
    {
        return relative.to_string_lossy().replace('\\', "/");
    }
    if let Some(home) = home
        && let Ok(relative) = path.strip_prefix(home)
    {
        return format!("~/{}", relative.to_string_lossy().replace('\\', "/"));
    }
    path.to_string_lossy().into_owned()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_shell_is_the_one_word_after_the_option() {
        let words =
            |text: &str| -> Vec<String> { text.split_whitespace().map(str::to_owned).collect() };
        assert_eq!(named_shell(&words(""), "--show-completion"), Ok(None));
        assert_eq!(
            named_shell(&words("pwsh"), "--show-completion"),
            Ok(Some("pwsh"))
        );
        assert_eq!(
            named_shell(&words("bash zsh"), "--show-completion"),
            Err(
                "Invalid value for '--show-completion': 'bash zsh' is not a supported shell. \
                 Use: opentide --show-completion [bash|zsh|fish|powershell|pwsh]"
                    .to_owned()
            )
        );
        assert!(named_shell(&words("bosh"), "--install-completion").is_err());
    }

    #[test]
    fn a_shell_is_named_by_its_program() {
        assert_eq!(shell_named("/usr/bin/zsh"), Some("zsh"));
        assert_eq!(shell_named("-bash"), Some("bash"));
        assert_eq!(
            shell_named("C:\\Program Files\\PowerShell\\pwsh.exe"),
            Some("pwsh")
        );
        assert_eq!(shell_named("python3"), None);
        // A shell is found, from the process tree or `SHELL`.
        assert!(detect(Some("/usr/bin/zsh")).is_some());
    }

    #[test]
    fn each_shell_gets_clap_s_script() {
        let root = crate::catalog::root();
        assert!(script(&root, "bash").contains("complete -F _opentide"));
        assert!(script(&root, "zsh").starts_with("#compdef opentide"));
        assert!(script(&root, "fish").contains("complete -c opentide"));
        assert!(
            script(&root, "pwsh")
                .contains("Register-ArgumentCompleter -Native -CommandName 'opentide'")
        );
        // The commands and their options are in it.
        let bash = script(&root, "bash");
        assert!(bash.contains("validate") && bash.contains("--dry-run"));
    }

    #[test]
    fn install_writes_the_script_and_loads_it_once() {
        let home = tempfile::tempdir().unwrap();
        let rc = home.path().join(".bashrc");
        std::fs::write(&rc, "alias ll='ls -l'").unwrap();
        for _ in 0..2 {
            let installed = install("bash", "SCRIPT", home.path(), None).unwrap();
            assert_eq!(
                installed.path,
                home.path().join(".bash_completions/opentide.sh")
            );
            assert_eq!(installed.reload, "source ~/.bashrc");
        }
        let text = std::fs::read_to_string(&rc).unwrap();
        assert_eq!(
            text,
            format!(
                "alias ll='ls -l'\nsource '{}'\n",
                home.path().join(".bash_completions/opentide.sh").display()
            )
        );
        install("zsh", "Z", home.path(), None).unwrap();
        install("zsh", "Z", home.path(), None).unwrap();
        assert_eq!(
            std::fs::read_to_string(home.path().join(".zshrc")).unwrap(),
            "fpath+=~/.zfunc; autoload -Uz compinit; compinit\n"
        );
        let fish = install("fish", "F", home.path(), None).unwrap();
        assert_eq!(std::fs::read_to_string(fish.path).unwrap(), "F");
        let profile = home.path().join("profile.ps1");
        let script = "Register-ArgumentCompleter -Native -CommandName 'opentide' {}";
        install("pwsh", script, home.path(), Some(&profile)).unwrap();
        install("pwsh", script, home.path(), Some(&profile)).unwrap();
        assert_eq!(
            std::fs::read_to_string(&profile).unwrap(),
            format!("{script}\n")
        );
    }

    #[test]
    fn a_path_is_shown_from_where_the_person_is() {
        let cwd = Path::new("/w");
        let home = Path::new("/h");
        assert_eq!(person_path(Path::new("/w/a/b"), cwd, Some(home)), "a/b");
        assert_eq!(
            person_path(Path::new("/h/.zfunc/_x"), cwd, Some(home)),
            "~/.zfunc/_x"
        );
        assert_eq!(person_path(Path::new("/o/x"), cwd, Some(home)), "/o/x");
    }
}
