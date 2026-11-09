//! The `opentide` binary.

fn main() {
    let argv: Vec<String> = std::env::args_os()
        .skip(1)
        .map(|arg| arg.to_string_lossy().into_owned())
        .collect();
    let version = option_env!("OPENTIDE_VERSION").unwrap_or(env!("CARGO_PKG_VERSION"));
    std::process::exit(opentide_cli::main(&argv, version));
}
