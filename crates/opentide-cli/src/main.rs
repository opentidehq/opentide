//! The `opentide` binary.

fn main() {
    let argv: Vec<String> = std::env::args_os()
        .skip(1)
        .map(|arg| arg.to_string_lossy().into_owned())
        .collect();
    opentide_cli::exit(&argv, opentide_cli::VERSION);
}
