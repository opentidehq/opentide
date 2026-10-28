// The module is loaded by a Python interpreter, which provides the symbols
// the extension uses: macOS needs `-undefined dynamic_lookup` to link it.
fn main() {
    pyo3_build_config::add_extension_module_link_args();
}
