//! A renamed Splunk rule's old saved search (#1657): once the rule is
//! written under its name now, the saved searches of the tenant's app whose
//! search names the rule's `MDR_UUID` under another name are deleted. Served
//! by an in-memory Splunk installed as the run's transport, so each test
//! scripts the saved searches the tenant holds and the calls it refuses. A
//! test binary of its own: the transport is the process's while installed.

#![expect(clippy::unwrap_used, reason = "a test: a failed set-up is a failure")]

use std::collections::BTreeMap;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use opentide_compile::json::{Json, Object};
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

/// The tenant's saved searches (name, search), the calls it saw, and the
/// (method, name) it refuses with a 500.
#[derive(Debug, Default)]
struct State {
    saved: BTreeMap<String, String>,
    seen: Vec<String>,
    refuse: Vec<(Method, String)>,
}

#[derive(Debug, Clone, Default)]
struct FakeSplunk(Arc<Mutex<State>>);

fn feed(entries: &[(&String, &String)]) -> Vec<u8> {
    let entries: String = entries
        .iter()
        .map(|(name, search)| {
            let path = format!("{SAVED}/{}", urlencoding(name));
            format!(
                "<entry><title>{name}</title><link href=\"{path}\" rel=\"alternate\"/>\
                 <content type=\"text/xml\"><s:dict><s:key name=\"search\">{}</s:key>\
                 <s:key name=\"eai:acl\"><s:dict><s:key name=\"app\">search</s:key>\
                 </s:dict></s:key></s:dict></content></entry>",
                search.replace('&', "&amp;").replace('<', "&lt;")
            )
        })
        .collect();
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

impl FakeSplunk {
    fn answer(&self, request: &Request) -> (u16, Vec<u8>) {
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
                let found: Vec<(&String, &String)> = state
                    .saved
                    .iter()
                    .filter(|(name, search)| name.contains(&needle) || search.contains(&needle))
                    .collect();
                (200, feed(&found))
            }
            (Method::GET, name) => match state.saved.get_key_value(name) {
                Some(found) => (200, feed(&[found])),
                None => (404, Vec::new()),
            },
            (Method::POST, "") => {
                let name = form.get("name").cloned().unwrap();
                let search = form.get("search").cloned().unwrap_or_default();
                state.saved.insert(name.clone(), search);
                let found = state.saved.get_key_value(&name).unwrap();
                (201, feed(&[found]))
            }
            (Method::POST, name) => {
                let Some(search) = state.saved.get_mut(name) else {
                    return (404, Vec::new());
                };
                if let Some(updated) = form.get("search") {
                    search.clone_from(updated);
                }
                let found = state.saved.get_key_value(name).unwrap();
                (200, feed(&[found]))
            }
            (Method::DELETE, name) => match state.saved.remove(name) {
                Some(_) => (200, feed(&[])),
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

/// Runs *steps* (rule name, rule UUID, query) as deploys on a tenant served
/// by *fake*: each step's `Ok` (its warnings' codes and messages) or the
/// failure's code and message.
fn deploy(
    fake: &FakeSplunk,
    steps: &[(&str, &str, &str)],
) -> Vec<Result<Vec<(String, String)>, (String, String)>> {
    let _one = ONE_AT_A_TIME
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let _installed = transport::install(Arc::new(fake.clone()));
    let env = Environment::from_pairs([("SPLUNK_TOKEN", "token")]);
    let setup: toml::Table =
        toml::from_str("url = \"splunk.invalid\"\napp = \"search\"\ntoken = \"$SPLUNK_TOKEN\"\n")
            .unwrap();
    let tenant = Tenant::from_setup(
        splunk::PLATFORM,
        "lab",
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
    let connector = Splunk::new();
    steps
        .iter()
        .map(|(name, uuid, query)| {
            let mut settings = Object::new();
            settings.insert(
                "search".into(),
                Json::Str(format!(
                    "{query}\n| eval MDR_UUID=\"{uuid}\", MDR_status=\"PRODUCTION\""
                )),
            );
            settings.insert("is_scheduled".into(), Json::Int(1));
            let request = DeployRequest::new(
                *name,
                Operation::Update,
                Json::Object(settings).to_compact().into_bytes(),
            );
            block_on(async { connector.deploy(cx, &request).await })
                .map(|done| {
                    done.warnings
                        .iter()
                        .map(|warning| (warning.code.clone(), warning.message.clone()))
                        .collect()
                })
                .map_err(|failed| {
                    (
                        failed.failure.code.to_owned(),
                        failed.failure.message.clone(),
                    )
                })
        })
        .collect()
}

const A: &str = "00000000-0000-4000-8099-0000000000a1";
const B: &str = "00000000-0000-4000-8099-0000000000b2";

fn holding(saved: &[(&str, &str)]) -> FakeSplunk {
    let fake = FakeSplunk::default();
    fake.0.lock().unwrap().saved = saved
        .iter()
        .map(|(name, uuid)| {
            (
                (*name).to_owned(),
                format!("index=main\n| eval MDR_UUID=\"{uuid}\", MDR_status=\"STAGING\""),
            )
        })
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
        [Ok(vec![(RENAMED_DELETED.to_owned(), "Old name".to_owned())])]
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
    let Err((code, message)) = &done[0] else {
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
        [Ok(vec![(RENAMED_DELETED.to_owned(), "Old name".to_owned())])]
    );
    assert_eq!(names(&fake), ["New name"]);
}
