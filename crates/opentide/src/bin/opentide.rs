//! The `opentide` command line (`cargo install opentide --features cli`): the
//! same program as the PyPI and npm packages' `opentide`.

fn main() {
    let argv: Vec<String> = std::env::args_os()
        .skip(1)
        .map(|arg| arg.to_string_lossy().into_owned())
        .collect();
    opentide::cli::exit(&argv);
}
