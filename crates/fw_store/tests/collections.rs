use fw_store::{
    collections::{CollectionKey, CollectionKind as Kind, CollectionSnapshot},
    Store, StoreError, Tenant,
};
use serde_json::{json, Value};
use uuid::Uuid;
#[path = "support/enrolled_target.rs"]
mod enrolled_target;
const NOW: i64 = 1_800_000_000;
fn id() -> String {
    Uuid::new_v4().to_string()
}
fn setup(s: &Store) -> (Tenant, String) {
    let t = s.ensure_tenant(&id(), &id(), "Pages", NOW).unwrap();
    let p = id();
    s.ensure_principal(&t, &p, "human", NOW).unwrap();
    (t, p)
}
fn asset(p: &str, name: &str) -> Value {
    json!({"definition":{"name":name,"asset_kind":"host","owner_id":p,"addresses":[{"family":"ipv4","cidr":"192.0.2.1/32","interface":null}],"criticality":"normal","isolation":"host","provenance":"manual","source_evidence":null},"state":"active"})
}
fn service(p: &str, a: &str, target: &str, name: &str) -> Value {
    json!({"service_id":name,"definition":{"name":name,"owner_id":p,"destination_asset_ids":[a],"target_ids":[target],"transport":{"protocol":"tcp","destination_ports":[{"start":443,"end":443}]},"description":"HTTPS","criticality":"normal"}})
}
fn remaining(
    s: &Store,
    t: &Tenant,
    kind: Kind,
    snapshot: CollectionSnapshot,
    mut after: Option<CollectionKey>,
    limit: usize,
    now: i64,
) -> Vec<Value> {
    let mut all = vec![];
    let mut pages = 0;
    while let Some(key) = after {
        pages += 1;
        assert!(pages < 200, "cursor loop");
        let page = s
            .list_collection_page(
                t,
                kind,
                Some(snapshot.clone()),
                Some(key),
                limit,
                false,
                now,
            )
            .unwrap();
        all.extend(page.items);
        after = page.next_after;
    }
    all
}
#[test]
fn immutable_catalogue_snapshot_excludes_new_rows_and_retains_old_revisions() {
    let s = Store::in_memory().unwrap();
    let (t, p) = setup(&s);
    let mut expected = vec![];
    for n in 0..31 {
        expected.push(
            s.create_asset(&t, &p, &asset(&p, &format!("Host{n}")), &id(), NOW)
                .unwrap()
                .value,
        );
    }
    expected.sort_by_key(|v| v["asset_id"].as_str().unwrap().to_owned());
    let first = s
        .list_collection_page(&t, Kind::Assets, None, None, 10, false, NOW)
        .unwrap();
    let old = &expected[15];
    let mut changed = json!({"definition":old["definition"],"state":"retired"});
    changed["definition"]["name"] = json!("Changed");
    s.revise_asset(
        &t,
        &p,
        old["asset_id"].as_str().unwrap(),
        &changed,
        1,
        old["content_hash"].as_str().unwrap(),
        &id(),
        NOW,
    )
    .unwrap();
    s.create_asset(&t, &p, &asset(&p, "New"), &id(), NOW)
        .unwrap();
    let mut actual = first.items;
    actual.extend(remaining(
        &s,
        &t,
        Kind::Assets,
        first.snapshot.clone(),
        first.next_after.clone(),
        10,
        NOW,
    ));
    assert_eq!(actual, expected);
    let filtered = s
        .list_collection_page(
            &t,
            Kind::Assets,
            Some(first.snapshot),
            first.next_after,
            10,
            true,
            NOW,
        )
        .unwrap();
    assert!(!filtered
        .items
        .iter()
        .any(|v| v["asset_id"] == old["asset_id"]));
    let current = s
        .list_collection_page(&t, Kind::Assets, None, None, 100, false, NOW)
        .unwrap();
    assert_eq!(current.items.len(), 32);
    assert!(current.snapshot.version > 0);
    let other = s.ensure_tenant(&id(), &id(), "Other", NOW).unwrap();
    assert!(s
        .list_collection_page(&other, Kind::Assets, None, None, 100, false, NOW)
        .unwrap()
        .items
        .is_empty());
}
#[test]
fn request_and_operation_snapshots_survive_state_changes_and_large_catalogues() {
    let s = Store::in_memory().unwrap();
    let (t, p) = setup(&s);
    let mut submissions = vec![];
    for n in 0..125 {
        submissions.push(
            s.submit_request(&t, &p, "access_request", &json!({"number":n}), &id(), NOW)
                .unwrap(),
        );
    }
    let first = s
        .list_collection_page(&t, Kind::Requests, None, None, 50, false, NOW)
        .unwrap();
    assert_eq!(first.items.len(), 50);
    let operations = s
        .list_collection_page(&t, Kind::Operations, None, None, 100, false, NOW)
        .unwrap();
    assert_eq!(operations.items.len(), 100);
    for submission in &submissions {
        s.compare_and_swap_request_state(&t, &submission.request.request_id, 1, "cancelled", NOW)
            .unwrap();
    }
    let mut requests = first.items;
    requests.extend(remaining(
        &s,
        &t,
        Kind::Requests,
        first.snapshot,
        first.next_after,
        50,
        NOW,
    ));
    assert_eq!(requests.len(), 125);
    assert!(requests.iter().all(|v| v["state"] == "submitted"));
    let mut ops = operations.items;
    ops.extend(remaining(
        &s,
        &t,
        Kind::Operations,
        operations.snapshot,
        operations.next_after,
        100,
        NOW,
    ));
    assert_eq!(ops.len(), 125);
    assert!(ops.iter().all(|v| v["state"] == "queued"));
    let ids = requests
        .iter()
        .map(|v| v["request_id"].as_str().unwrap())
        .collect::<std::collections::BTreeSet<_>>();
    assert_eq!(ids.len(), 125);
}
#[test]
fn byte_limited_pages_continue_without_omissions_or_cursor_loops() {
    let s = Store::in_memory().unwrap();
    let (t, p) = setup(&s);
    let mut expected = vec![];
    for n in 0..11 {
        let row = s
            .submit_request(
                &t,
                &p,
                "access_request",
                &json!({"n":n,"large":"x".repeat(60_000)}),
                &id(),
                NOW,
            )
            .unwrap();
        expected.push(row.request.request_id);
    }
    let first = s
        .list_collection_page(&t, Kind::Requests, None, None, 100, false, NOW)
        .unwrap();
    assert_eq!(first.items.len(), 3);
    assert!(first.next_after.is_some());
    assert!(serde_json::to_vec(&first.items).unwrap().len() <= fw_store::collections::PAGE_BYTES);
    let mut rows = first.items;
    rows.extend(remaining(
        &s,
        &t,
        Kind::Requests,
        first.snapshot,
        first.next_after,
        100,
        NOW,
    ));
    let actual = rows
        .iter()
        .map(|v| v["request_id"].as_str().unwrap().to_owned())
        .collect::<Vec<_>>();
    expected.sort();
    assert_eq!(actual, expected);
}
#[test]
fn expired_snapshot_rejected_after_pruning_and_clock_rollback_fails_closed() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("db");
    let s = Store::open(&path).unwrap();
    let (t, p) = setup(&s);
    let a = s
        .create_asset(&t, &p, &asset(&p, "Host"), &id(), NOW)
        .unwrap()
        .value;
    let first = s
        .list_collection_page(&t, Kind::Assets, None, None, 1, false, NOW)
        .unwrap();
    let mut current = a;
    for offset in [1, 2, 901, 902] {
        let body = asset(&p, &format!("Updated{offset}"));
        current = s
            .revise_asset(
                &t,
                &p,
                current["asset_id"].as_str().unwrap(),
                &body,
                current["revision"].as_i64().unwrap() as i32,
                current["content_hash"].as_str().unwrap(),
                &id(),
                NOW + offset,
            )
            .unwrap()
            .value;
    }
    assert!(matches!(
        s.list_collection_page(
            &t,
            Kind::Assets,
            Some(first.snapshot),
            None,
            1,
            false,
            NOW + 902
        ),
        Err(StoreError::Conflict("SNAPSHOT_EXPIRED"))
    ));
    let raw = rusqlite::Connection::open(&path).unwrap();
    let count: i64 = raw
        .query_row("SELECT count(*) FROM collection_versions", [], |r| r.get(0))
        .unwrap();
    assert_eq!(count, 4); // cutoff=NOW+2 retains predecessor NOW+1, plus NOW+2/901/902
    s.list_collection_page(&t, Kind::Assets, None, None, 1, false, NOW + 2000)
        .unwrap();
    let count: i64 = raw
        .query_row("SELECT count(*) FROM collection_versions", [], |r| r.get(0))
        .unwrap();
    assert_eq!(count, 1);
    assert!(matches!(
        s.list_collection_page(&t, Kind::Assets, None, None, 1, false, NOW + 1999),
        Err(StoreError::InvalidInput("collection clock regressed"))
    ));
    assert!(matches!(
        s.revise_asset(
            &t,
            &p,
            current["asset_id"].as_str().unwrap(),
            &asset(&p, "Rollback"),
            current["revision"].as_i64().unwrap() as i32,
            current["content_hash"].as_str().unwrap(),
            &id(),
            NOW + 1999
        ),
        Err(StoreError::InvalidInput("collection clock regressed"))
    ));
    assert_eq!(
        s.get_asset(&t, current["asset_id"].as_str().unwrap())
            .unwrap(),
        current
    );
}
#[test]
fn target_selection_and_service_writes_share_current_certificate_and_report_checks() {
    let s = Store::in_memory().unwrap();
    let (t, p) = setup(&s);
    let a = s
        .create_asset(&t, &p, &asset(&p, "Host"), &id(), NOW)
        .unwrap()
        .value;
    let bare = id();
    s.register_observe_target(&t, &bare, "linux").unwrap();
    assert!(matches!(
        s.create_service(
            &t,
            &p,
            &service(&p, a["asset_id"].as_str().unwrap(), &bare, "bare"),
            &id(),
            NOW
        ),
        Err(StoreError::NotFound)
    ));
    let (target, fp) = enrolled_target::enrolled(&s, &t, &p, NOW);
    let (revoked, _) = enrolled_target::enrolled(&s, &t, &p, NOW);
    let first = s
        .list_collection_page(&t, Kind::Targets, None, None, 100, true, NOW)
        .unwrap();
    assert_eq!(first.items.len(), 2);
    s.create_service(
        &t,
        &p,
        &service(&p, a["asset_id"].as_str().unwrap(), &target, "fresh"),
        &id(),
        NOW,
    )
    .unwrap();
    s.revoke_enrollment(&t, &p, &revoked, NOW).unwrap();
    let same = s
        .list_collection_page(
            &t,
            Kind::Targets,
            Some(first.snapshot.clone()),
            None,
            100,
            true,
            NOW,
        )
        .unwrap();
    assert_eq!(same.items.len(), 1);
    assert_eq!(same.items[0]["target_id"], target);
    assert!(matches!(
        s.create_service(
            &t,
            &p,
            &service(&p, a["asset_id"].as_str().unwrap(), &revoked, "revoked"),
            &id(),
            NOW
        ),
        Err(StoreError::NotFound)
    ));
    let stale = s
        .list_collection_page(&t, Kind::Targets, None, None, 100, true, NOW + 300)
        .unwrap();
    assert!(stale.items.is_empty());
    assert!(matches!(
        s.create_service(
            &t,
            &p,
            &service(&p, a["asset_id"].as_str().unwrap(), &target, "stale"),
            &id(),
            NOW + 300
        ),
        Err(StoreError::NotFound)
    ));
    let identity = s.authenticate_enrollment(&fp, NOW + 300).unwrap();
    s.save_target_capability(
        &identity,
        &enrolled_target::capability(&target, NOW + 300),
        NOW + 300,
    )
    .unwrap();
    assert!(
        s.list_collection_page(
            &t,
            Kind::Targets,
            Some(first.snapshot),
            None,
            100,
            true,
            NOW + 300
        )
        .unwrap()
        .items
        .is_empty(),
        "a new report must not revive the expired report inside an old snapshot"
    );
    assert_eq!(
        s.list_collection_page(&t, Kind::Targets, None, None, 100, true, NOW + 300)
            .unwrap()
            .items
            .len(),
        1
    );
    assert!(s
        .list_collection_page(&t, Kind::Targets, None, None, 100, true, NOW + 86400)
        .unwrap()
        .items
        .is_empty());
}
#[test]
fn service_target_and_enrollment_pages_traverse_more_than_one_hundred_rows() {
    let s = Store::in_memory().unwrap();
    let (t, p) = setup(&s);
    let a = s
        .create_asset(&t, &p, &asset(&p, "Host"), &id(), NOW)
        .unwrap()
        .value;
    for n in 0..105 {
        let (target, _) = enrolled_target::enrolled(&s, &t, &p, NOW);
        s.create_service(
            &t,
            &p,
            &service(
                &p,
                a["asset_id"].as_str().unwrap(),
                &target,
                &format!("service-{n:03}"),
            ),
            &id(),
            NOW,
        )
        .unwrap();
    }
    for kind in [Kind::Services, Kind::Targets, Kind::Enrollments] {
        let first = s
            .list_collection_page(&t, kind, None, None, 25, false, NOW)
            .unwrap();
        assert_eq!(first.items.len(), 25);
        let mut all = first.items;
        all.extend(remaining(
            &s,
            &t,
            kind,
            first.snapshot,
            first.next_after,
            25,
            NOW,
        ));
        assert_eq!(all.len(), 105);
    }
}
#[test]
fn migration_backfills_existing_rows_in_chunks_and_preserves_evidence() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("db");
    let s = Store::open(&path).unwrap();
    let (t, p) = setup(&s);
    for n in 0..130 {
        s.create_asset(&t, &p, &asset(&p, &format!("Host{n}")), &id(), NOW)
            .unwrap();
    }
    let audits = s.verify_audit_chain(&t).unwrap();
    drop(s);
    let raw = rusqlite::Connection::open(&path).unwrap();
    raw.execute_batch("DROP TABLE collection_versions; DROP TABLE collection_clocks; DELETE FROM schema_migrations WHERE version=6; PRAGMA user_version=5;").unwrap();
    drop(raw);
    let s = Store::open(&path).unwrap();
    assert_eq!(s.verify_audit_chain(&t).unwrap(), audits);
    let first = s
        .list_collection_page(&t, Kind::Assets, None, None, 100, false, NOW)
        .unwrap();
    let mut all = first.items;
    all.extend(remaining(
        &s,
        &t,
        Kind::Assets,
        first.snapshot,
        first.next_after,
        100,
        NOW,
    ));
    assert_eq!(all.len(), 130);
    assert!(matches!(
        s.list_collection_page(&t, Kind::Assets, None, None, 0, false, NOW),
        Err(StoreError::InvalidInput(_))
    ));
    assert!(matches!(
        s.list_collection_page(&t, Kind::Assets, None, None, 101, false, NOW),
        Err(StoreError::InvalidInput(_))
    ));
}
#[test]
fn capability_renewals_have_atomic_monotonic_outbox_revisions_and_exact_retries() {
    use std::sync::{Arc, Barrier};
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("db");
    let s = Store::open(&path).unwrap();
    let (t, p) = setup(&s);
    let (target, fp) = enrolled_target::enrolled(&s, &t, &p, NOW);
    let identity = s.authenticate_enrollment(&fp, NOW).unwrap();
    let cap = enrolled_target::capability(&target, NOW + 1);
    s.save_target_capability(&identity, &cap, NOW + 1).unwrap();
    let audit = s.verify_audit_chain(&t).unwrap();
    s.save_target_capability(&identity, &cap, NOW + 1).unwrap();
    assert_eq!(s.verify_audit_chain(&t).unwrap(), audit);
    let gate = Arc::new(Barrier::new(3));
    let mut threads = vec![];
    for checked in [NOW + 2, NOW + 3] {
        let path = path.clone();
        let fp = fp.clone();
        let gate = gate.clone();
        let target = target.clone();
        threads.push(std::thread::spawn(move || {
            let store = Store::open(path).unwrap();
            let identity = store.authenticate_enrollment(&fp, NOW + 3).unwrap();
            gate.wait();
            store.save_target_capability(
                &identity,
                &enrolled_target::capability(&target, checked),
                NOW + 3,
            )
        }));
    }
    gate.wait();
    let mut accepted = 0;
    for thread in threads {
        match thread.join().unwrap() {
            Ok(_) => accepted += 1,
            Err(StoreError::Conflict("STALE_CAPABILITY")) => {}
            other => panic!("unexpected report result: {other:?}"),
        }
    }
    assert!((1..=2).contains(&accepted));
    let raw = rusqlite::Connection::open(&path).unwrap();
    let mut q=raw.prepare("SELECT aggregate_revision FROM outbox WHERE aggregate_id=?1 AND event_kind='target.capability_reported' ORDER BY aggregate_revision").unwrap();
    let revisions = q
        .query_map([&target], |r| r.get::<_, i32>(0))
        .unwrap()
        .collect::<Result<Vec<_>, _>>()
        .unwrap();
    assert_eq!(revisions, (1..=2 + accepted).collect::<Vec<_>>());
    let reports: i32 = raw
        .query_row(
            "SELECT count(*) FROM enrolled_capabilities WHERE target_id=?1",
            [&target],
            |r| r.get(0),
        )
        .unwrap();
    assert_eq!(reports, 2 + accepted);
    assert_eq!(
        s.get_target(&t, &target, NOW + 3).unwrap()["capability_hash"],
        fw_contracts::hash_bytes(
            &fw_contracts::canonical_bytes(&enrolled_target::capability(&target, NOW + 3)).unwrap()
        )
    );
}
#[test]
fn corrupt_legacy_content_rolls_back_the_entire_projection_migration() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("db");
    let s = Store::open(&path).unwrap();
    let (t, p) = setup(&s);
    s.create_asset(&t, &p, &asset(&p, "Host"), &id(), NOW)
        .unwrap();
    drop(s);
    let raw = rusqlite::Connection::open(&path).unwrap();
    raw.execute_batch("DROP TABLE collection_versions; DROP TABLE collection_clocks; DELETE FROM schema_migrations WHERE version=6; PRAGMA user_version=5; DROP TRIGGER asset_revision_no_update; UPDATE asset_revisions SET canonical_bytes=x'7b7d';").unwrap();
    drop(raw);
    assert!(matches!(Store::open(&path), Err(StoreError::Integrity(_))));
    let raw = rusqlite::Connection::open(&path).unwrap();
    assert_eq!(
        raw.pragma_query_value(None, "user_version", |r| r.get::<_, i64>(0))
            .unwrap(),
        5
    );
    assert_eq!(
        raw.query_row(
            "SELECT count(*) FROM sqlite_master WHERE name='collection_versions'",
            [],
            |r| r.get::<_, i64>(0)
        )
        .unwrap(),
        0
    );
    assert_eq!(
        raw.query_row("SELECT count(*) FROM audit_events", [], |r| r
            .get::<_, i64>(0))
            .unwrap(),
        1
    );
}
#[test]
fn changed_projection_identity_and_creation_metadata_fail_closed() {
    for field in ["resource_id", "sort_created_at"] {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("db");
        let s = Store::open(&path).unwrap();
        let (t, p) = setup(&s);
        s.create_asset(&t, &p, &asset(&p, "Host"), &id(), NOW)
            .unwrap();
        let raw = rusqlite::Connection::open(&path).unwrap();
        raw.execute_batch("DROP TRIGGER collection_version_no_update")
            .unwrap();
        if field == "resource_id" {
            raw.execute("UPDATE collection_versions SET resource_id=?1", [id()])
                .unwrap();
        } else {
            raw.execute(
                "UPDATE collection_versions SET sort_created_at=sort_created_at-1",
                [],
            )
            .unwrap();
        }
        assert!(
            matches!(
                s.list_collection_page(&t, Kind::Assets, None, None, 50, false, NOW),
                Err(StoreError::Integrity(_))
            ),
            "{field}"
        );
    }
}
