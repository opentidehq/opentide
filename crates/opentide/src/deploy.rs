//! The deploy plan: what `opentide deploy --dry-run` would send, computed
//! locally. Nothing is sent and nothing is written.

use std::path::Path;

use opentide_compile::Owned;
use opentide_compile::dry_run::{self, Request};
use opentide_compile::plan::Scope;
use opentide_schema::vocab::Vocabularies;

use crate::{Document, Error, Workspace};

/// A deploy run's strategy: which rules it deploys, by the strategy their
/// status maps to (`deployment.toml`'s `[[statuses]]`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum Strategy {
    /// The pull or merge request job: the rules whose status maps to
    /// `PREVIEW` or `UNIVERSAL`.
    Preview,
    /// The default branch's job: the rules whose status maps to `RELEASE` or
    /// `UNIVERSAL`, and the retirements (`DISABLEMENT`, `DELETION`).
    Release,
}

impl Strategy {
    /// Its name, as `--strategy` takes it.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Preview => "PREVIEW",
            Self::Release => "RELEASE",
        }
    }
}

impl std::fmt::Display for Strategy {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// What [`Workspace::deploy_plan`] plans: `opentide deploy --dry-run`'s
/// options. Without a selection it reads every rule file (`--all`).
///
/// ```
/// use opentide::deploy::{DeployPlanOptions, Strategy};
///
/// let options = DeployPlanOptions::new(Strategy::Preview).uuid("11111111-1111-4111-8111-111111111111");
/// assert_eq!(options.strategies, [Strategy::Preview]);
/// ```
#[derive(Debug, Clone, Default, PartialEq, Eq)]
#[non_exhaustive]
pub struct DeployPlanOptions {
    /// `--strategy`: at least one.
    pub strategies: Vec<Strategy>,
    /// `--uuid`: rules by UUID.
    pub uuids: Vec<String>,
    /// `--file`: rule files, by path (from the workspace folder) or by name.
    pub files: Vec<String>,
    /// `--platform`: one platform only.
    pub platform: Option<String>,
    /// `--keep-deprecated` (`true`) or `--drop-deprecated` (`false`); by
    /// default a run over every rule drops deprecated rules and a selection
    /// keeps them.
    pub keep_deprecated: Option<bool>,
}

impl DeployPlanOptions {
    /// A plan for `strategy`, over every rule file.
    pub fn new(strategy: Strategy) -> Self {
        Self {
            strategies: vec![strategy],
            ..Self::default()
        }
    }

    /// Adds `strategy`.
    pub fn strategy(mut self, strategy: Strategy) -> Self {
        self.strategies.push(strategy);
        self
    }

    /// Selects the rule `uuid` (repeatable).
    pub fn uuid(mut self, uuid: impl Into<String>) -> Self {
        self.uuids.push(uuid.into());
        self
    }

    /// Selects the rule file `file` (repeatable).
    pub fn file(mut self, file: impl Into<String>) -> Self {
        self.files.push(file.into());
        self
    }

    /// Plans for `platform` only.
    pub fn platform(mut self, platform: impl Into<String>) -> Self {
        self.platform = Some(platform.into());
        self
    }
}

/// A deploy plan: the result `opentide deploy --dry-run --json` reports.
#[derive(Debug, Clone, PartialEq)]
pub struct DeployPlan {
    document: Document,
    summary: Option<Document>,
    ok: bool,
}

impl DeployPlan {
    /// The result's payload (`deployed`, `dry_run`, `plan`, `payloads`,
    /// `tenants`, ...), keys in the command line's order: each rule's request
    /// body for each tenant, and the warnings a real run would hit.
    pub fn document(&self) -> &Document {
        &self.document
    }

    /// The counts (`summary` in the command line's envelope), when the run
    /// planned.
    pub fn summary(&self) -> Option<&Document> {
        self.summary.as_ref()
    }

    /// Whether the dry run completed (the command line's exit code 0):
    /// `false` when it stops (a rule file that does not read, a selection that
    /// matches nothing), as the document's `message` says. What would stop a
    /// real run (a platform without tenants, an unset variable) is in the
    /// document's `warnings`.
    pub fn ok(&self) -> bool {
        self.ok
    }
}

impl Workspace {
    /// Plans a deploy (`opentide deploy --dry-run`): the rules the
    /// strategies select, the tenants each reaches, and the request bodies a
    /// real run would send. Nothing is sent and nothing is written.
    ///
    /// ```
    /// use opentide::deploy::{DeployPlanOptions, Strategy};
    ///
    /// let ws = opentide::Workspace::from_files("/ws", [("objects/rules/.keep", "")])?;
    /// let plan = ws.deploy_plan(&DeployPlanOptions::new(Strategy::Preview))?;
    /// assert_eq!(plan.document().value()["dry_run"], true);
    /// # Ok::<(), opentide::Error>(())
    /// ```
    ///
    /// # Errors
    ///
    /// [`Error::Usage`] when `options` has no strategy (`usage_missing_option`)
    /// or a strategy the configured statuses refuse (`usage_invalid_choice`).
    pub fn deploy_plan(&self, options: &DeployPlanOptions) -> Result<DeployPlan, Error> {
        let ws = self.inner();
        let owned = Owned::new(&Vocabularies::bundled(), &ws.configuration().resolved);
        let request = Request {
            strategies: options
                .strategies
                .iter()
                .map(|strategy| strategy.as_str().to_owned())
                .collect(),
            all: options.uuids.is_empty() && options.files.is_empty(),
            uuids: options.uuids.clone(),
            files: options.files.clone(),
            platform: options.platform.clone(),
            wide: false,
            keep_deprecated: options.keep_deprecated,
            removed_plan: None,
            cwd: ws.cwd().to_path_buf(),
            // The facade has no plugin host: plugins load only in the Python
            // package (UC-4.5).
            plugins: Vec::new(),
        };
        // A plan reads every rule file or a selection, never a git diff.
        let changed = |_: &Path, _: &str| -> Result<(Scope, Option<String>), String> {
            Err("the facade plans every rule file or a selection".to_owned())
        };
        let is_set = |name: &str| std::env::var_os(name).is_some_and(|value| !value.is_empty());
        let outcome = dry_run::run(ws, &owned, &request, &changed, &is_set);
        let message = || {
            outcome
                .payload
                .get("message")
                .and_then(opentide_compile::Json::as_str)
                .unwrap_or_default()
                .to_owned()
        };
        if let Some(usage) = &outcome.usage {
            return Err(Error::Usage {
                code: usage.code,
                message: message(),
            });
        }
        Ok(DeployPlan {
            document: compact(&opentide_compile::Json::Object(outcome.payload.clone())),
            summary: outcome.summary.as_ref().map(compact),
            ok: outcome.exit_code == 0,
        })
    }
}

/// `json` as one line, its keys in order, and its value. Serialising an
/// ordered value to a `serde_json::Value` cannot fail (its keys are strings).
fn compact(json: &opentide_compile::Json) -> Document {
    Document::from_parts(
        json.to_compact(),
        serde_json::to_value(json).unwrap_or_default(),
    )
}
