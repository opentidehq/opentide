//! The addon is loaded by Node, which provides the N-API symbols it uses:
//! napi-build passes the link arguments that leave them to load time.
fn main() {
    napi_build::setup();
}
