//! The SDK's registry semantics (`core/registry.py` `OpentideRegistry`):
//! an explicit lifecycle around one shared index. `initialise` loads the
//! workspace once and later calls reuse it; `reload` drops it and loads
//! again; the accessors initialise on first use, as Python's do.
//!
//! The typed objects of Python's `Rules`, `Threats` and `Objectives` are the
//! model structs of `opentide-schema` (the rules' platform blocks included,
//! UC-1.4); until the models are exposed to Python (UC-1.9) the accessors
//! hand out the index's [`Object`]s, whose documents those models read.

use std::sync::Arc;

use indexmap::IndexMap;

use crate::config::Configuration;
use crate::fs::FileSystem;
use crate::index::{Index, Object, Signal};
use crate::workspace::{OpenError, Options, Workspace};

/// A workspace with Python's registry lifecycle.
pub struct Registry {
    fs: Arc<dyn FileSystem>,
    options: Options,
    workspace: Option<Workspace>,
}

impl std::fmt::Debug for Registry {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Registry")
            .field("workspace", &self.workspace)
            .finish_non_exhaustive()
    }
}

impl Registry {
    /// A registry that has loaded nothing yet.
    pub fn new(fs: Arc<dyn FileSystem>, options: Options) -> Self {
        Self {
            fs,
            options,
            workspace: None,
        }
    }

    /// Whether the index has been loaded (`is_initialised`).
    pub fn is_initialised(&self) -> bool {
        self.workspace.is_some()
    }

    /// Loads the index, once: a second call returns the same workspace
    /// (`initialise`).
    ///
    /// # Errors
    ///
    /// The configuration does not resolve.
    pub fn initialise(&mut self) -> Result<&mut Workspace, OpenError> {
        let workspace = match self.workspace.take() {
            Some(workspace) => workspace,
            None => Workspace::open(Arc::clone(&self.fs), self.options.clone())?,
        };
        Ok(self.workspace.insert(workspace))
    }

    /// Drops the index and loads it again (`reload`).
    ///
    /// # Errors
    ///
    /// The configuration does not resolve; the registry is then not
    /// initialised.
    pub fn reload(&mut self) -> Result<&mut Workspace, OpenError> {
        self.workspace = None;
        self.initialise()
    }

    /// The index, loading it first if need be (`Index`).
    ///
    /// # Errors
    ///
    /// The configuration does not resolve.
    pub fn index(&mut self) -> Result<Arc<Index>, OpenError> {
        Ok(Arc::clone(self.initialise()?.index()))
    }

    /// The configuration (`Configuration`).
    ///
    /// # Errors
    ///
    /// The configuration does not resolve.
    pub fn configuration(&mut self) -> Result<Arc<Configuration>, OpenError> {
        Ok(Arc::clone(self.initialise()?.configuration()))
    }

    /// The rules by UUID (`Rules`).
    ///
    /// # Errors
    ///
    /// The configuration does not resolve.
    pub fn rules(&mut self) -> Result<IndexMap<String, Object>, OpenError> {
        self.family("rule")
    }

    /// The threat vectors by UUID (`Threats`).
    ///
    /// # Errors
    ///
    /// The configuration does not resolve.
    pub fn threats(&mut self) -> Result<IndexMap<String, Object>, OpenError> {
        self.family("threat")
    }

    /// The detection objectives by UUID (`Objectives`).
    ///
    /// # Errors
    ///
    /// The configuration does not resolve.
    pub fn objectives(&mut self) -> Result<IndexMap<String, Object>, OpenError> {
        self.family("objective")
    }

    /// The signals by UUID (`Models.signals`).
    ///
    /// # Errors
    ///
    /// The configuration does not resolve.
    pub fn signals(&mut self) -> Result<IndexMap<String, Signal>, OpenError> {
        Ok(self.index()?.signals.clone())
    }

    /// The object `uuid` among the rules, threats and objectives, in that
    /// order (`lookup`).
    ///
    /// # Errors
    ///
    /// The configuration does not resolve.
    pub fn lookup(&mut self, uuid: &str) -> Result<Option<Object>, OpenError> {
        Ok(self.index()?.lookup(uuid).cloned())
    }

    fn family(&mut self, family: &str) -> Result<IndexMap<String, Object>, OpenError> {
        Ok(self
            .index()?
            .objects
            .get(family)
            .cloned()
            .unwrap_or_default())
    }
}
