//! A renamed Splunk rule's old saved search (#1657): once the rule is
//! written under its name now, the saved searches of the tenant's app whose
//! description names the rule (its last line, `opentide rule <uuid>`) under
//! another name are deleted. Served
//! by an in-memory Splunk installed as the run's transport, so each test
//! scripts the saved searches the tenant holds and the calls it refuses. A
//! test binary of its own: the transport is the process's while installed.

#![expect(clippy::unwrap_used, reason = "a test: a failed set-up is a failure")]

use std::collections::BTreeMap;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use opentide_compile::json::{Json, Object};
use opentide_compile::splunk as splunk_rule;
use opentide_connectors::connector::{
    BoxFuture, DeployRequest, Deployer, Operation, TenantContext,
};
use opentide_connectors::credentials::Mode as Resolve;
use opentide_connectors::runtime::block_on;
use opentide_connectors::splunk::{self, RENAMED_CLEANUP_FAILED, RENAMED_DELETED, Splunk};
use opentide_connectors::transport::{
    self, HeaderMap, Method, Request, Response, StatusCode, Transport, TransportFactory,
    TransportFailure, TransportSpec,
};
use opentide_connectors::{Environment, HttpClient, Tenant};
use tokio_util::sync::CancellationToken;

const SAVED: &str = "/servicesNS/nobody/search/saved/searches";

/// The tenant's saved searches (name, description), the app and owner of
/// those not the `search` app's `nobody` (name, (app, owner)), the calls it
/// saw, and the (method, name) it refuses with a 500.
#[derive(Debug, Default)]
struct State {
    saved: BTreeMap<String, String>,
    /// The settings an update wrote to a saved search, besides its
    /// description, as the lookup answers them (#1711).
    settings: BTreeMap<String, BTreeMap<String, String>>,
    acl: BTreeMap<String, (String, String)>,
    seen: Vec<String>,
    refuse: Vec<(Method, String)>,
    /// How `authentication/current-context` answers (#1727).
    context: Context,
    /// The answers for the tokens named here, in place of `context`.
    by_token: BTreeMap<String, Context>,
}

/// How `authentication/current-context` answers a request.
#[derive(Debug, Clone, Default)]
enum Context {
    /// A 500 (the default).
    #[default]
    Refused,
    /// The user the token signs in as.
    User(String),
    /// A 200 whose `entry` is empty.
    NoEntry,
    /// A 200 whose `username` is empty.
    EmptyUsername,
    /// An HTML page, as a gateway answers.
    Html,
    /// No answer at all: the connection fails.
    Unreachable,
}

#[derive(Debug, Clone, Default)]
struct FakeSplunk(Arc<Mutex<State>>);

/// A saved search as the feed shows it: name, description, (app, owner)
/// and the other settings written to it.
type Shown<'a> = (
    &'a String,
    &'a String,
    (&'a str, &'a str),
    &'a BTreeMap<String, String>,
);

/// No settings written.
static NO_SETTINGS: BTreeMap<String, String> = BTreeMap::new();

fn escaped(text: &str) -> String {
    text.replace('&', "&amp;").replace('<', "&lt;")
}

/// An Atom feed of *entries*, each with its ACL as Splunk answers it.
fn feed(entries: &[Shown<'_>]) -> Vec<u8> {
    let mut text = String::new();
    for (name, description, (app, owner), settings) in entries {
        let path = format!("{SAVED}/{}", urlencoding(name));
        let mut others = String::new();
        for (key, value) in *settings {
            others.push_str(&format!("<s:key name=\"{key}\">{}</s:key>", escaped(value)));
        }
        text.push_str(&format!(
            "<entry><title>{name}</title><link href=\"{path}\" rel=\"alternate\"/>\
             <content type=\"text/xml\"><s:dict><s:key name=\"description\">{}</s:key>{others}\
             <s:key name=\"eai:acl\"><s:dict><s:key name=\"app\">{app}</s:key>\
             <s:key name=\"owner\">{owner}</s:key>\
             </s:dict></s:key></s:dict></content></entry>",
            escaped(description)
        ));
    }
    let entries = text;
    format!(
        "<feed xmlns=\"http://www.w3.org/2005/Atom\" \
         xmlns:s=\"http://dev.splunk.com/ns/rest\">{entries}</feed>"
    )
    .into_bytes()
}

fn urlencoding(name: &str) -> String {
    url::form_urlencoded::byte_serialize(name.as_bytes())
        .collect::<String>()
        .replace('+', "%20")
}

impl State {
    /// The saved search *name*'s feed entry: its description and ACL.
    fn entry<'a>(&'a self, name: &'a String) -> Option<Shown<'a>> {
        let description = self.saved.get(name)?;
        let acl = self
            .acl
            .get(name)
            .map_or(("search", "nobody"), |(app, owner)| {
                (app.as_str(), owner.as_str())
            });
        let settings = self.settings.get(name).unwrap_or(&NO_SETTINGS);
        Some((name, description, acl, settings))
    }
}

impl FakeSplunk {
    /// How the lookup of the user answers *request*, when it is that
    /// request: by the request's token, else the default.
    fn lookup(&self, request: &Request) -> Option<Context> {
        if request.url().path() != "/services/authentication/current-context" {
            return None;
        }
        let state = self.0.lock().unwrap();
        let token = request
            .headers()
            .get("authorization")
            .and_then(|value| value.to_str().ok())
            .and_then(|value| value.strip_prefix("Splunk "))
            .unwrap_or_default();
        Some(state.by_token.get(token).unwrap_or(&state.context).clone())
    }

    fn answer(&self, request: &Request) -> (u16, Vec<u8>) {
        let context = self.lookup(request);
        let mut state = self.0.lock().unwrap();
        let url = request.url();
        let path = url.path().to_owned();
        let form: BTreeMap<String, String> = request
            .body()
            .map(|body| url::form_urlencoded::parse(body).into_owned().collect())
            .unwrap_or_default();
        let query: BTreeMap<String, String> = url.query_pairs().into_owned().collect();
        let name = path
            .strip_prefix(SAVED)
            .map(|rest| rest.trim_start_matches('/'))
            .map(|rest| {
                percent_encoding::percent_decode_str(&rest.replace('+', " "))
                    .decode_utf8_lossy()
                    .into_owned()
            })
            .unwrap_or_default();
        let method = request.method().clone();
        if let Some(context) = context {
            state.seen.push("GET current-context".to_owned());
            assert_eq!(url.query(), Some("output_mode=json"));
            let user = |user: &str| {
                format!(
                    "{{\"entry\":[{{\"name\":\"current-context\",\"content\":\
                     {{\"username\":\"{user}\",\"roles\":[\"admin\"]}}}}]}}"
                )
                .into_bytes()
            };
            return match context {
                Context::User(name) => (200, user(&name)),
                Context::EmptyUsername => (200, user("")),
                Context::NoEntry => (200, b"{\"entry\":[]}".to_vec()),
                Context::Html => (200, b"<html><title>Sign in</title></html>".to_vec()),
                Context::Refused | Context::Unreachable => (500, b"{\"messages\":[]}".to_vec()),
            };
        }
        state.seen.push(format!("{method} {name}"));
        if state
            .refuse
            .iter()
            .any(|(refused, refused_name)| *refused == method && *refused_name == name)
        {
            return (
                500,
                b"<response><messages><msg type=\"ERROR\">refused</msg></messages></response>"
                    .to_vec(),
            );
        }
        match (method, name.as_str()) {
            (Method::GET, "") => {
                let needle = query.get("search").cloned().unwrap_or_default();
                let found: Vec<_> = state
                    .saved
                    .iter()
                    .filter(|(name, description)| {
                        name.contains(&needle) || description.contains(&needle)
                    })
                    .filter_map(|(name, _)| state.entry(name))
                    .collect();
                (200, feed(&found))
            }
            (Method::GET, name) => match state.entry(&name.to_owned()) {
                Some(found) => (200, feed(&[found])),
                None => (404, Vec::new()),
            },
            (Method::POST, "") => {
                let name = form.get("name").cloned().unwrap();
                let description = form.get("description").cloned().unwrap_or_default();
                state.saved.insert(name.clone(), description);
                (201, feed(&[state.entry(&name).unwrap()]))
            }
            (Method::POST, name) => {
                let name = name.to_owned();
                let Some(description) = state.saved.get_mut(&name) else {
                    return (404, Vec::new());
                };
                if let Some(updated) = form.get("description") {
                    description.clone_from(updated);
                }
                let written = state.settings.entry(name.clone()).or_default();
                for (key, value) in &form {
                    if key != "description" && key != "name" {
                        written.insert(key.clone(), value.clone());
                    }
                }
                (200, feed(&[state.entry(&name).unwrap()]))
            }
            (Method::DELETE, name) => match state.saved.remove(name) {
                Some(_) => {
                    state.settings.remove(name);
                    (200, feed(&[]))
                }
                None => (404, Vec::new()),
            },
            _ => (405, Vec::new()),
        }
    }
}

impl Transport for FakeSplunk {
    fn execute<'a>(
        &'a self,
        request: Request,
        _cancel: &'a CancellationToken,
    ) -> BoxFuture<'a, Result<Response, TransportFailure>> {
        let (status, body) = self.answer(&request);
        if matches!(self.lookup(&request), Some(Context::Unreachable)) {
            return Box::pin(async {
                Err(TransportFailure::Unreachable {
                    reason: "the connection dropped".to_owned(),
                })
            });
        }
        let url = request.url().clone();
        Box::pin(async move {
            Ok(Response::new(
                StatusCode::from_u16(status).unwrap(),
                HeaderMap::new(),
                url,
                (Duration::ZERO, Duration::ZERO),
                Ok(body),
            ))
        })
    }
}

impl TransportFactory for FakeSplunk {
    fn make(&self, _spec: &TransportSpec<'_>) -> Result<Arc<dyn Transport>, String> {
        Ok(Arc::new(self.clone()))
    }
}

/// One installed fake at a time: the transport is the process's.
static ONE_AT_A_TIME: Mutex<()> = Mutex::new(());

/// A step's warnings (code, message), or its failure's code and message and
/// the warnings of what it did before it failed.
type Done = Result<Vec<(String, String)>, (String, String, Vec<(String, String)>)>;

fn warnings(outcome: &opentide_connectors::connector::DeployOutcome) -> Vec<(String, String)> {
    outcome
        .warnings
        .iter()
        .map(|warning| (warning.code.clone(), warning.message.clone()))
        .collect()
}

/// The body `opentide deploy` sends for a step: the saved search's settings,
/// or, for a retirement, the description that names the rule.
fn body(operation: Operation, uuid: &str, query: &str) -> Vec<u8> {
    let mut settings = Object::new();
    if operation != Operation::Delete {
        settings.insert("search".into(), Json::Str(query.to_owned()));
    }
    settings.insert(
        "description".into(),
        Json::Str(splunk_rule::described("A rule.", uuid)),
    );
    if operation != Operation::Delete {
        settings.insert("is_scheduled".into(), Json::Int(1));
    }
    Json::Object(settings).to_compact().into_bytes()
}

/// Runs *steps* (rule name, rule UUID, query) as deploys on a tenant served
/// by *fake*.
fn deploy(fake: &FakeSplunk, steps: &[(&str, &str, &str)]) -> Vec<Done> {
    let requests: Vec<DeployRequest> = steps
        .iter()
        .map(|(name, uuid, query)| {
            DeployRequest::new(
                *name,
                Operation::Update,
                body(Operation::Update, uuid, query),
            )
        })
        .collect();
    send(fake, &requests)
}

/// Sends *requests* on a tenant served by *fake*.
fn send(fake: &FakeSplunk, requests: &[DeployRequest]) -> Vec<Done> {
    send_outcomes(fake, requests)
        .into_iter()
        .map(|done| {
            done.map(|done| warnings(&done)).map_err(|failed| {
                (
                    failed.failure.code.to_owned(),
                    failed.failure.message.clone(),
                    failed.partial.as_deref().map(warnings).unwrap_or_default(),
                )
            })
        })
        .collect()
}

/// [`send`], with each step's outcome as the deployer returned it, on the
/// tenant `lab`.
fn send_outcomes(fake: &FakeSplunk, requests: &[DeployRequest]) -> Vec<Outcome> {
    send_outcomes_on(fake, &["lab"], requests).remove(0)
}

type Outcome = Result<
    opentide_connectors::connector::DeployOutcome,
    opentide_connectors::connector::DeployError,
>;

/// *requests* sent in turn to each of *tenants* (named, each with the token
/// `t-<name>`) by one connector, as one run does; each tenant's outcomes.
fn send_outcomes_on(
    fake: &FakeSplunk,
    tenants: &[&str],
    requests: &[DeployRequest],
) -> Vec<Vec<Outcome>> {
    let _one = ONE_AT_A_TIME
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let _installed = transport::install(Arc::new(fake.clone()));
    let connector = Splunk::new();
    tenants
        .iter()
        .map(|name| {
            let env = Environment::from_pairs([("SPLUNK_TOKEN", format!("t-{name}"))]);
            let setup: opentide_core::json::Object = toml::from_str(
                "url = \"splunk.invalid\"\napp = \"search\"\ntoken = \"$SPLUNK_TOKEN\"\n",
            )
            .unwrap();
            let tenant = Tenant::from_setup(
                splunk::PLATFORM,
                name,
                &setup,
                &env,
                Resolve::Required,
                &splunk::http_settings(Duration::from_secs(5)),
            )
            .unwrap();
            let http = HttpClient::new(&tenant.label, &tenant.http, &env, None).unwrap();
            let cancel = CancellationToken::new();
            let cx = TenantContext {
                tenant: &tenant,
                http: &http,
                cancel: &cancel,
            };
            requests
                .iter()
                .map(|request| block_on(async { connector.deploy(cx, request).await }).unwrap())
                .collect()
        })
        .collect()
}

const A: &str = "00000000-0000-4000-8099-0000000000a1";
const B: &str = "00000000-0000-4000-8099-0000000000b2";

fn holding(saved: &[(&str, &str)]) -> FakeSplunk {
    let fake = FakeSplunk::default();
    fake.0.lock().unwrap().saved = saved
        .iter()
        .map(|(name, uuid)| ((*name).to_owned(), splunk_rule::described("Old.", uuid)))
        .collect();
    fake
}

fn names(fake: &FakeSplunk) -> Vec<String> {
    fake.0.lock().unwrap().saved.keys().cloned().collect()
}

/// A renamed rule's old saved search is deleted once the new one is
/// written, and the outcome says so; another rule's saved search, and a
/// rule deployed under its own name, are left alone.
#[test]
fn a_renamed_rules_old_saved_search_is_deleted() {
    let fake = holding(&[("Old name", A), ("Other rule", B)]);
    let done = deploy(&fake, &[("New name", A, "index=main")]);
    assert_eq!(
        done,
        [Ok(vec![(
            RENAMED_DELETED.to_owned(),
            "Old name".to_owned()
        )])]
    );
    assert_eq!(names(&fake), ["New name", "Other rule"]);
    // The same name again: the listing finds nothing else to delete.
    let again = deploy(&fake, &[("New name", A, "index=main")]);
    assert_eq!(again, [Ok(Vec::new())]);
    assert_eq!(names(&fake), ["New name", "Other rule"]);
}

/// Two rules that swap names in one run keep both saved searches: the
/// cleanup is keyed by each rule's own UUID, never by a name.
#[test]
fn rules_that_swap_names_keep_both_saved_searches() {
    let fake = holding(&[("First", A), ("Second", B)]);
    let done = deploy(
        &fake,
        &[("Second", A, "index=main"), ("First", B, "index=main")],
    );
    assert!(done.iter().all(Result::is_ok), "{done:?}");
    assert_eq!(names(&fake), ["First", "Second"]);
    let saved = fake.0.lock().unwrap().saved.clone();
    assert!(saved["Second"].contains(A), "{saved:?}");
    assert!(saved["First"].contains(B), "{saved:?}");
}

/// A write the tenant refuses deletes nothing: the old saved search keeps
/// running until the rule is written under its new name.
#[test]
fn a_refused_write_deletes_nothing() {
    let fake = holding(&[("Old name", A)]);
    fake.0
        .lock()
        .unwrap()
        .refuse
        .push((Method::POST, String::new()));
    let done = deploy(&fake, &[("New name", A, "index=main")]);
    assert!(done[0].is_err(), "{done:?}");
    assert_eq!(names(&fake), ["Old name"]);
    assert!(
        !fake
            .0
            .lock()
            .unwrap()
            .seen
            .iter()
            .any(|call| call.starts_with("DELETE")),
        "{:?}",
        fake.0.lock().unwrap().seen
    );
}

/// A delete the tenant refuses fails the rule, naming the old saved search
/// and saying the new one was written; the next deploy finds the old one
/// again and deletes it.
#[test]
fn a_refused_delete_fails_the_rule_and_the_next_deploy_retries() {
    let fake = holding(&[("Old name", A)]);
    fake.0
        .lock()
        .unwrap()
        .refuse
        .push((Method::DELETE, "Old name".to_owned()));
    let done = deploy(&fake, &[("New name", A, "index=main")]);
    let Err((code, message, _)) = &done[0] else {
        panic!("{done:?}")
    };
    assert_eq!(code, RENAMED_CLEANUP_FAILED);
    assert!(
        message.contains("\"New name\" was written") && message.contains("\"Old name\""),
        "{message}"
    );
    assert_eq!(names(&fake), ["New name", "Old name"]);
    fake.0.lock().unwrap().refuse.clear();
    let retried = deploy(&fake, &[("New name", A, "index=main")]);
    assert_eq!(
        retried,
        [Ok(vec![(
            RENAMED_DELETED.to_owned(),
            "Old name".to_owned()
        )])]
    );
    assert_eq!(names(&fake), ["New name"]);
}

/// Only a description whose last line is the rule's marker counts: a saved
/// search that merely mentions the rule's UUID (a note, another rule's
/// description) is left alone.
#[test]
fn a_saved_search_that_only_mentions_the_uuid_is_kept() {
    let fake = holding(&[("Old name", A)]);
    fake.0.lock().unwrap().saved.insert(
        "Mentions it".to_owned(),
        format!("Tuned after rule {A} fired.\n\nopentide rule {B}"),
    );
    let done = deploy(&fake, &[("New name", A, "index=main")]);
    assert_eq!(
        done,
        [Ok(vec![(
            RENAMED_DELETED.to_owned(),
            "Old name".to_owned()
        )])]
    );
    assert_eq!(names(&fake), ["Mentions it", "New name"]);
}

/// The tenant app's `nobody` user is the only owner whose saved searches the
/// cleanup deletes: a saved search another app shares (which the app's
/// listing also holds) and a private copy an analyst cloned in Splunk (the
/// clone keeps the description, marker included) survive the rename.
#[test]
fn another_apps_and_an_analysts_saved_searches_are_kept() {
    let fake = holding(&[
        ("Old name", A),
        ("Shared from another app", A),
        ("Analyst clone", A),
    ]);
    {
        let mut state = fake.0.lock().unwrap();
        state.acl.insert(
            "Shared from another app".to_owned(),
            ("other_app".to_owned(), "nobody".to_owned()),
        );
        state.acl.insert(
            "Analyst clone".to_owned(),
            ("search".to_owned(), "admin".to_owned()),
        );
    }
    let done = deploy(&fake, &[("New name", A, "index=main")]);
    assert_eq!(
        done,
        [Ok(vec![(
            RENAMED_DELETED.to_owned(),
            "Old name".to_owned()
        )])]
    );
    assert_eq!(
        names(&fake),
        ["Analyst clone", "New name", "Shared from another app"]
    );
}

/// A retired rule deletes its saved search, then the copies an earlier name
/// left: a rule renamed and retired in one commit leaves nothing behind,
/// even though its new name was never written. A bare delete (no body, as
/// an SDK may send) deletes the named saved search alone.
#[test]
fn a_retired_rule_deletes_the_copies_an_earlier_name_left() {
    let fake = holding(&[("Old name", A), ("Other rule", B)]);
    let done = send(
        &fake,
        &[DeployRequest::new(
            "New name",
            Operation::Delete,
            body(Operation::Delete, A, ""),
        )],
    );
    assert_eq!(
        done,
        [Ok(vec![(
            RENAMED_DELETED.to_owned(),
            "Old name".to_owned()
        )])]
    );
    assert_eq!(names(&fake), ["Other rule"]);

    let fake = holding(&[("Name now", A), ("Old name", A)]);
    let done = send(&fake, &[DeployRequest::delete("Name now")]);
    assert_eq!(
        done,
        [Ok(vec![(
            "splunk_alert_deleted".to_owned(),
            "Name now".to_owned()
        )])]
    );
    assert_eq!(names(&fake), ["Old name"]);
}

/// When a later delete fails, the copies already deleted are still said:
/// in the failure's message and in its `partial` warnings, which `opentide
/// deploy` lists under `removed`.
#[test]
fn copies_deleted_before_a_failed_delete_are_kept_in_the_failure() {
    let fake = holding(&[("Old name 1", A), ("Old name 2", A)]);
    fake.0
        .lock()
        .unwrap()
        .refuse
        .push((Method::DELETE, "Old name 2".to_owned()));
    let done = deploy(&fake, &[("New name", A, "index=main")]);
    let Err((code, message, partial)) = &done[0] else {
        panic!("{done:?}")
    };
    assert_eq!(code, RENAMED_CLEANUP_FAILED);
    assert!(
        message.contains("\"Old name 2\"") && message.contains("deleted before it: \"Old name 1\""),
        "{message}"
    );
    assert_eq!(
        partial,
        &[(RENAMED_DELETED.to_owned(), "Old name 1".to_owned())]
    );
    assert_eq!(names(&fake), ["New name", "Old name 2"]);
}

/// A rule the tenant already holds as the request has it is unchanged, and
/// writes nothing (#1711); the rename cleanup runs all the same, so the
/// copy an earlier name left is deleted, and a failed delete is found again
/// by the next deploy of the rule, though it reads unchanged too.
#[test]
fn an_unchanged_rule_still_has_its_old_copies_deleted() {
    let fake = FakeSplunk::default();
    let request = DeployRequest::new(
        "New name",
        Operation::Update,
        body(Operation::Update, A, "index=main"),
    );
    let first = send_outcomes(&fake, std::slice::from_ref(&request));
    assert!(!first[0].as_ref().unwrap().unchanged());
    // An earlier name of the rule is still on the tenant, which refuses its
    // delete the first time.
    fake.0
        .lock()
        .unwrap()
        .saved
        .insert("Old name".to_owned(), splunk_rule::described("Old.", A));
    fake.0
        .lock()
        .unwrap()
        .refuse
        .push((Method::DELETE, "Old name".to_owned()));
    fake.0.lock().unwrap().seen.clear();
    let refused = send(&fake, std::slice::from_ref(&request));
    assert_eq!(refused[0].as_ref().unwrap_err().0, RENAMED_CLEANUP_FAILED);
    assert!(
        !fake
            .0
            .lock()
            .unwrap()
            .seen
            .contains(&"POST New name".to_owned()),
        "nothing is written to a saved search the tenant already holds"
    );
    fake.0.lock().unwrap().refuse.clear();
    fake.0.lock().unwrap().seen.clear();
    let again = send_outcomes(&fake, std::slice::from_ref(&request));
    let again = again[0].as_ref().unwrap();
    assert!(again.unchanged());
    assert_eq!(
        warnings(again),
        [(RENAMED_DELETED.to_owned(), "Old name".to_owned())]
    );
    assert_eq!(names(&fake), ["New name"]);
    assert!(
        !fake
            .0
            .lock()
            .unwrap()
            .seen
            .contains(&"POST New name".to_owned()),
        "{:?}",
        fake.0.lock().unwrap().seen
    );
}

/// How many times the deploy asked who the token signs in as.
fn context_reads(fake: &FakeSplunk) -> usize {
    fake.0
        .lock()
        .unwrap()
        .seen
        .iter()
        .filter(|call| *call == "GET current-context")
        .count()
}

/// Splunk records the user the token signs in as, not the `nobody` of the
/// namespace opentide writes through, as the owner of a saved search it
/// creates: a copy owned by that user is opentide's, and is deleted; the
/// user is read once for the run, not once per rule (#1727).
#[test]
fn a_copy_owned_by_the_authenticated_user_is_deleted() {
    let fake = holding(&[("Old name", A), ("Other old name", B)]);
    {
        let mut state = fake.0.lock().unwrap();
        state.context = Context::User("admin".to_owned());
        for name in ["Old name", "Other old name"] {
            state
                .acl
                .insert(name.to_owned(), ("search".to_owned(), "admin".to_owned()));
        }
    }
    let done = deploy(
        &fake,
        &[
            ("New name", A, "index=main"),
            ("Other new name", B, "index=main"),
        ],
    );
    assert_eq!(
        done,
        [
            Ok(vec![(RENAMED_DELETED.to_owned(), "Old name".to_owned())]),
            Ok(vec![(
                RENAMED_DELETED.to_owned(),
                "Other old name".to_owned()
            )]),
        ]
    );
    assert_eq!(names(&fake), ["New name", "Other new name"]);
    assert_eq!(context_reads(&fake), 1);
}

/// A copy another user owns is an analyst's, and is kept, beside the copy
/// the authenticated user owns, which is deleted.
#[test]
fn a_copy_owned_by_another_user_is_kept() {
    let fake = holding(&[("Old name", A), ("Analyst clone", A)]);
    {
        let mut state = fake.0.lock().unwrap();
        state.context = Context::User("admin".to_owned());
        state.acl.insert(
            "Old name".to_owned(),
            ("search".to_owned(), "admin".to_owned()),
        );
        state.acl.insert(
            "Analyst clone".to_owned(),
            ("search".to_owned(), "alice".to_owned()),
        );
    }
    let done = deploy(&fake, &[("New name", A, "index=main")]);
    assert_eq!(
        done,
        [Ok(vec![(
            RENAMED_DELETED.to_owned(),
            "Old name".to_owned()
        )])]
    );
    assert_eq!(names(&fake), ["Analyst clone", "New name"]);
}

/// When the lookup of the authenticated user fails, only `nobody`'s copies
/// are deleted: an `admin`-owned copy is kept, and the deploy still succeeds.
#[test]
fn a_failed_user_lookup_falls_back_to_nobody() {
    let fake = holding(&[("Old name", A), ("Admin copy", A)]);
    {
        let mut state = fake.0.lock().unwrap();
        state.context = Context::Refused;
        state.acl.insert(
            "Admin copy".to_owned(),
            ("search".to_owned(), "admin".to_owned()),
        );
    }
    let done = deploy(&fake, &[("New name", A, "index=main")]);
    assert_eq!(
        done,
        [Ok(vec![(
            RENAMED_DELETED.to_owned(),
            "Old name".to_owned()
        )])]
    );
    assert_eq!(names(&fake), ["Admin copy", "New name"]);
    assert_eq!(context_reads(&fake), 1);
}

/// Copies `nobody` owns need no lookup: the request is sent only when a
/// copy of another owner is listed.
#[test]
fn nobodys_copies_are_deleted_without_asking_who_signs_in() {
    let fake = holding(&[("Old name", A)]);
    let done = deploy(&fake, &[("New name", A, "index=main")]);
    assert_eq!(
        done,
        [Ok(vec![(
            RENAMED_DELETED.to_owned(),
            "Old name".to_owned()
        )])]
    );
    assert_eq!(context_reads(&fake), 0);
}

/// Every tracing event's level and its fields, one text each, from the
/// first test that asks.
#[derive(Clone, Default)]
struct Logs(Arc<Mutex<Vec<(tracing::Level, String)>>>);

impl<S: tracing::Subscriber> tracing_subscriber::Layer<S> for Logs {
    fn on_event(&self, event: &tracing::Event<'_>, _: tracing_subscriber::layer::Context<'_, S>) {
        struct Fields<'a>(&'a mut String);
        impl tracing::field::Visit for Fields<'_> {
            fn record_debug(&mut self, field: &tracing::field::Field, value: &dyn std::fmt::Debug) {
                self.0.push_str(&format!("{}={value:?} ", field.name()));
            }
        }
        let mut text = String::new();
        event.record(&mut Fields(&mut text));
        self.0
            .lock()
            .unwrap()
            .push((*event.metadata().level(), text));
    }
}

/// The global subscriber, installed once, before any request.
fn logs() -> &'static Logs {
    use tracing_subscriber::layer::SubscriberExt as _;
    static LOGS: std::sync::OnceLock<Logs> = std::sync::OnceLock::new();
    LOGS.get_or_init(|| {
        let logs = Logs::default();
        tracing::subscriber::set_global_default(tracing_subscriber::registry().with(logs.clone()))
            .unwrap();
        logs
    })
}

/// The warnings that say the user could not be read, on *tenant*.
fn lookup_warnings(tenant: &str) -> Vec<String> {
    logs()
        .0
        .lock()
        .unwrap()
        .iter()
        .filter(|(level, text)| {
            *level == tracing::Level::WARN
                && text.contains(&format!("tenant={tenant} "))
                && text.contains("could not read the user")
        })
        .map(|(_, text)| text.clone())
        .collect()
}

/// A rule's deploy under *name*.
fn request(name: &str, uuid: &str) -> DeployRequest {
    DeployRequest::new(
        name,
        Operation::Update,
        body(Operation::Update, uuid, "index=main"),
    )
}

/// A lookup that answers *context* on a tenant of its own: only `nobody`'s
/// copy of the rule is deleted, the `admin`-owned one is kept, the deploy
/// succeeds, and exactly one warning on the tenant says why.
fn falls_back_to_nobody(context: Context, tenant: &str) {
    logs();
    let fake = holding(&[("Old name", A), ("Admin copy", A)]);
    {
        let mut state = fake.0.lock().unwrap();
        state.context = context;
        state.acl.insert(
            "Admin copy".to_owned(),
            ("search".to_owned(), "admin".to_owned()),
        );
    }
    let done = send_outcomes_on(&fake, &[tenant], &[request("New name", A)]).remove(0);
    let done = done[0].as_ref().unwrap();
    assert_eq!(
        warnings(done),
        [(RENAMED_DELETED.to_owned(), "Old name".to_owned())]
    );
    assert_eq!(names(&fake), ["Admin copy", "New name"]);
    assert_eq!(context_reads(&fake), 1);
    let warned = lookup_warnings(tenant);
    assert_eq!(warned.len(), 1, "{warned:?}");
}

#[test]
fn an_answer_without_a_user_falls_back_to_nobody() {
    falls_back_to_nobody(Context::NoEntry, "no-entry");
}

#[test]
fn an_empty_username_falls_back_to_nobody() {
    falls_back_to_nobody(Context::EmptyUsername, "empty-username");
}

#[test]
fn an_html_answer_falls_back_to_nobody() {
    falls_back_to_nobody(Context::Html, "html");
}

#[test]
fn a_refused_lookup_falls_back_to_nobody() {
    falls_back_to_nobody(Context::Refused, "refused");
}

#[test]
fn a_lookup_that_cannot_connect_falls_back_to_nobody() {
    falls_back_to_nobody(Context::Unreachable, "unreachable");
}

/// A user that is read is not warned about.
#[test]
fn a_lookup_that_answers_logs_no_warning() {
    logs();
    let fake = holding(&[("Old name", A)]);
    fake.0.lock().unwrap().acl.insert(
        "Old name".to_owned(),
        ("search".to_owned(), "admin".to_owned()),
    );
    fake.0.lock().unwrap().context = Context::User("admin".to_owned());
    let done = send_outcomes_on(&fake, &["answers"], &[request("New name", A)]).remove(0);
    assert!(done[0].is_ok());
    assert_eq!(names(&fake), ["New name"]);
    assert!(lookup_warnings("answers").is_empty());
}

/// Two tenants of one run each have their own user read: one lookup per
/// tenant, and a tenant's user never applies to the other's copies.
#[test]
fn each_tenant_has_its_own_user_read() {
    let fake = holding(&[("East copy", A), ("West copy", A)]);
    {
        let mut state = fake.0.lock().unwrap();
        state
            .by_token
            .insert("t-east".to_owned(), Context::User("admin".to_owned()));
        state
            .by_token
            .insert("t-west".to_owned(), Context::User("svc".to_owned()));
        state.acl.insert(
            "East copy".to_owned(),
            ("search".to_owned(), "admin".to_owned()),
        );
        state.acl.insert(
            "West copy".to_owned(),
            ("search".to_owned(), "svc".to_owned()),
        );
    }
    let requests = [request("New name", A), request("New name", A)];
    let east = send_outcomes_on(&fake, &["east"], &requests[..1]);
    assert!(east[0][0].is_ok());
    assert_eq!(names(&fake), ["New name", "West copy"]);
    // A second tenant of the same run, on the same connector.
    let both = send_outcomes_on(&fake, &["east", "west"], &requests[1..]);
    assert!(both.iter().flatten().all(Result::is_ok));
    assert_eq!(names(&fake), ["New name"]);
    // One read for the first run, then one per tenant of the second.
    assert_eq!(context_reads(&fake), 3);
}
