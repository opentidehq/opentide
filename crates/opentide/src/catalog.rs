//! What [`Workspace::info`](crate::Workspace::info),
//! [`Workspace::catalog`](crate::Workspace::catalog) and
//! [`Workspace::coverage`](crate::Workspace::coverage) return: the documents
//! of `opentide info`, `info catalog` and `info coverage`. Each serialises
//! (`serde`) to the command line's JSON.

pub use opentide_workspace::catalogue::{
    Catalogue, Edge, LoadErrorDetail, LoadErrorRow, ObjectRow, PlatformBlock, Row, SignalRow,
    Summary, Techniques,
};
pub use opentide_workspace::coverage::TechniqueMatch as Coverage;
pub use opentide_workspace::info::{PlatformInfo, Tenant, Variable};
