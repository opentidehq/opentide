//! MISP's REST client against the cassettes the oracle's `share push` and
//! `share retract` recorded on the stand-in of `tests/cassettes/misp/`
//! (UC-4.4b, #834): the calls the engine makes, in its order, each request
//! the oracle's (PyMISP's), bodies included (as the same JSON data).

#![expect(clippy::unwrap_used, reason = "a test: a failed set-up is a failure")]

mod cassette_support;

use cassette_support::{replay, repo};
use opentide_compile::json::Json;
use opentide_connectors::misp::{GALAXY_ACTOR, GALAXY_ATTACK, Kind, Misp, MispClient};

const KEY: (&str, &str) = ("MISP_API_KEY", "misp-test-key-only");

/// The bodies the oracle sent, in order, by path.
fn bodies(name: &str, path: &str) -> Vec<Json> {
    let text =
        std::fs::read_to_string(repo().join(format!("tests/cassettes/{name}.json"))).unwrap();
    let cassette: serde_json::Value = serde_json::from_str(&text).unwrap();
    cassette["interactions"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|interaction| {
            interaction["request"]["url"]
                .as_str()
                .unwrap()
                .ends_with(path)
        })
        .map(|interaction| {
            serde_json::from_str(interaction["request"]["body"].as_str().unwrap()).unwrap()
        })
        .collect()
}

fn client(env: &opentide_connectors::Environment, url: &str) -> MispClient {
    MispClient::new("misp-prod", url, KEY.1, true, env, None, "0.0.0").unwrap()
}

#[test]
fn a_push_sends_what_pymisp_sent() {
    let replay = replay("golden/share-push", &[KEY]);
    let prod = client(&replay.env, "https://misp.invalid");
    assert_eq!(prod.get_version().unwrap(), "2.5.17");
    assert_eq!(
        prod.current_organisation_uuid().unwrap(),
        "11111111-1111-4111-8111-111111111111"
    );
    let template = prod.object_template().unwrap();
    assert!(template.found);
    assert_eq!(template.version, Some(5));
    let locked = client(&replay.env, "https://misp.invalid/locked/");
    let refused = locked.get_version().unwrap_err();
    assert_eq!(refused.kind, Kind::Authentication);
    assert_eq!(refused.status, Some(403));

    let attack = prod.galaxy_clusters(GALAXY_ATTACK).unwrap();
    assert_eq!(attack[0].external_ids, ["T1059"]);
    let actors = prod.galaxy_clusters(GALAXY_ACTOR).unwrap();
    assert_eq!(actors[0].ref_tails, ["G0006"]);
    // Read once per client.
    assert_eq!(prod.galaxy_clusters(GALAXY_ATTACK).unwrap(), attack);

    let adds = bodies("golden/share-push", "/events/add");
    let found = prod
        .search_opentide_events("00000000-0000-4000-8048-000000000001")
        .unwrap();
    assert_eq!(found.len(), 1, "another organisation's event");
    let created = prod.add_event(&adds[0]).unwrap();
    assert_eq!(created.event_id, Some(100));
    prod.publish_event(&created.address()).unwrap();
    assert!(
        prod.search_opentide_events("00000000-0000-4000-8048-000000000011")
            .unwrap()
            .is_empty()
    );
    let created = prod.add_event(&adds[1]).unwrap();
    prod.publish_event(&created.address()).unwrap();
    let found = prod
        .search_opentide_events("00000000-0000-4000-8048-000000000012")
        .unwrap();
    assert_eq!(found[0].objects.len(), 2);
    let edits = bodies("golden/share-push", "/events/edit/7");
    let edited = prod.edit_event("7", &edits[0]).unwrap();
    assert_eq!(edited.event_uuid, "e0000000-0000-4000-8048-000000000012");
    prod.publish_event("7").unwrap();
    let unchanged = prod
        .search_opentide_events("00000000-0000-4000-8048-000000000013")
        .unwrap();
    assert!(unchanged[0].published);
    assert_eq!(replay.proxy.verify(), Vec::new());
}

#[test]
fn a_retract_sends_what_pymisp_sent() {
    let replay = replay("golden/share-retract", &[KEY]);
    let prod = client(&replay.env, "https://misp.invalid/");
    prod.get_version().unwrap();
    prod.current_organisation_uuid().unwrap();
    prod.object_template().unwrap();
    let found = prod
        .search_opentide_events("00000000-0000-4000-8048-000000000012")
        .unwrap();
    assert!(found[0].published);
    prod.unpublish_event(&found[0].address()).unwrap();
    assert!(
        prod.search_opentide_events("00000000-0000-4000-8048-000000000020")
            .unwrap()
            .is_empty()
    );
    assert_eq!(replay.proxy.verify(), Vec::new());
}

#[test]
fn an_unreachable_instance_is_a_connectivity_failure() {
    let env = opentide_connectors::Environment::from_pairs([("NO_PROXY", "*")]);
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    drop(listener);
    let client = MispClient::new(
        "gone",
        &format!("http://127.0.0.1:{port}"),
        "key",
        false,
        &env,
        None,
        "0.0.0",
    )
    .unwrap();
    let failed = client.get_version().unwrap_err();
    assert_eq!(failed.kind, Kind::Connectivity);
    assert_eq!(failed.reason, "connectivity_failed");
    assert!(client.delete_event("1").is_err());
}
