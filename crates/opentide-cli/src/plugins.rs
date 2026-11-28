//! Platform plugins on the command line (UC-4.5, #835): the process's plugin
//! host, [`opentide_connectors::plugin::host`], which `query`,
//! `validate query --live`, `deploy` and `validate` read. It lives in the
//! connectors so a host that embeds them without the command line installs
//! the same one.

pub use opentide_connectors::plugin::host::*;
