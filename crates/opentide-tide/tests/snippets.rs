//! The object snippets the editor offers are the templates `opentide
//! generate templates` writes for the bundled configuration (#814).
//!
//! The editor compiles in `data/catalogs/tide/templates/`, which `cargo
//! xtask codegen` writes from opentide-schema's generator and `cargo xtask
//! codegen --check` holds to it. Until #814 the files were hand-kept and had
//! drifted: no Sysdig block in the rule template, and `author` and
//! `organisation` commented out where the bundled `lint.toml` requires them.

use opentide_schema::configuration::resolve::{Instance, resolve};
use opentide_schema::generate::workspace::templates;
use std::path::Path;

#[test]
fn each_snippet_is_the_generated_template() {
    let resolved = resolve(&Instance {
        skip_parent: true,
        ..Instance::default()
    })
    .expect("the bundled configuration resolves");
    let generated = templates(&resolved.tree).expect("`generate templates` runs");
    for (family, name) in [
        ("rule", "rule.1.0.template.yaml"),
        ("objective", "objective.1.0.template.yaml"),
        ("threat", "threat.1.0.template.yaml"),
    ] {
        let template = generated
            .iter()
            .find(|artifact| Path::new(&artifact.path).file_name() == Some(name.as_ref()))
            .unwrap_or_else(|| panic!("`generate templates` writes no {name}"));
        assert_eq!(
            opentide_tide::snippet(family),
            Some(template.text.as_str()),
            "the {family} snippet is not what `generate templates` writes: run `cargo xtask codegen`"
        );
    }
    assert_eq!(opentide_tide::snippet("hunt"), None);
}
