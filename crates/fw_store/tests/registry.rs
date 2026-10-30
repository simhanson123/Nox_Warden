use fw_contracts::{canonical_hash, hash_bytes};
use fw_store::{Store, StoreError, Tenant};
use rusqlite::{params, Connection};
use serde_json::{json, Value};
use std::sync::{Arc, Barrier};
use uuid::Uuid;
const NOW: i64 = 1_793_318_400;
fn id() -> String {
    Uuid::new_v4().to_string()
}
fn setup(store: &Store) -> (Tenant, String) {
    let tenant = store.ensure_tenant(&id(), &id(), "Lab", NOW).unwrap();
    let principal = id();
    store
        .ensure_principal(&tenant, &principal, "human", NOW)
        .unwrap();
    (tenant, principal)
}
fn asset(owner: &str, name: &str) -> Value {
    json!({"definition":{"name":name,"asset_kind":"host","owner_id":owner,"addresses":[{"family":"ipv4","cidr":"10.20.0.1/32","interface":null}],"criticality":"normal","isolation":"host","provenance":"manual","source_evidence":null},"state":"active"})
}
fn service(owner: &str, asset: &str, target: &str) -> Value {
    json!({"service_id":"database","definition":{"name":"Database","owner_id":owner,"destination_asset_ids":[asset],"target_ids":[target],"transport":{"protocol":"tcp","destination_ports":[{"start":5432,"end":5432}]},"description":"Manual database catalog","criticality":"normal"}})
}
fn make_service(store: &Store, t: &Tenant, p: &str) -> (Value, Value) {
    let a = store
        .create_asset(t, p, &asset(p, "DB host"), &id(), NOW)
        .unwrap()
        .value;
    let target = id();
    store.register_observe_target(t, &target, "linux").unwrap();
    let body = service(p, a["asset_id"].as_str().unwrap(), &target);
    let s = store.create_service(t, p, &body, &id(), NOW).unwrap().value;
    (a, s)
}
fn revision_body(value: &Value) -> Value {
    json!({"definition":value["definition"],"state":value["state"]})
}

#[test]
fn creates_server_owned_hashed_immutable_asset_revision_and_replay() {
    let store = Store::in_memory().unwrap();
    let (t, p) = setup(&store);
    let key = id();
    let body = asset(&p, "Host");
    let first = store.create_asset(&t, &p, &body, &key, NOW).unwrap();
    let value = &first.value;
    assert_eq!(value["created_by"], p);
    assert_eq!(value["org_id"], t.org_id);
    assert_eq!(value["revision"], 1);
    assert_eq!(value["previous_revision_hash"], Value::Null);
    let mut payload = value.clone();
    payload.as_object_mut().unwrap().remove("content_hash");
    assert_eq!(value["content_hash"], canonical_hash(&payload).unwrap());
    let replay = store.create_asset(&t, &p, &body, &key, NOW + 5).unwrap();
    assert!(replay.replayed);
    assert_eq!(replay.value, first.value);
    let mut changed = body;
    changed["definition"]["name"] = json!("Other");
    assert!(matches!(
        store.create_asset(&t, &p, &changed, &key, NOW),
        Err(StoreError::IdempotencyConflict)
    ));
    assert_eq!(store.count_assets(&t).unwrap(), 1);
    assert_eq!(store.verify_audit_chain(&t).unwrap(), 1);
    assert_eq!(store.security_revision(&t).unwrap(), 2);
    let audit = store.list_audit(&t, 0, 10).unwrap();
    assert_eq!(audit[0]["evidence_hashes"][0], value["content_hash"]);
}
#[test]
fn nfc_name_collision_is_case_sensitive_and_normalized_replay_is_stable() {
    let store = Store::in_memory().unwrap();
    let (t, p) = setup(&store);
    let key = id();
    let a = store
        .create_asset(&t, &p, &asset(&p, "Cafe\u{301}"), &key, NOW)
        .unwrap();
    assert_eq!(a.value["definition"]["name"], "Café");
    assert!(
        store
            .create_asset(&t, &p, &asset(&p, "Café"), &key, NOW)
            .unwrap()
            .replayed
    );
    assert!(matches!(
        store.create_asset(&t, &p, &asset(&p, "Café"), &id(), NOW),
        Err(StoreError::Conflict("NAME_EXISTS"))
    ));
    store
        .create_asset(&t, &p, &asset(&p, "CAFÉ"), &id(), NOW)
        .unwrap();
}
#[test]
fn exact_cas_preserves_history_and_replays_revision_response() {
    let store = Store::in_memory().unwrap();
    let (t, p) = setup(&store);
    let first = store
        .create_asset(&t, &p, &asset(&p, "Host"), &id(), NOW)
        .unwrap()
        .value;
    let aid = first["asset_id"].as_str().unwrap();
    let hash = first["content_hash"].as_str().unwrap();
    let key = id();
    let body = asset(&p, "Renamed");
    let second = store
        .revise_asset(&t, &p, aid, &body, 1, hash, &key, NOW + 1)
        .unwrap()
        .value;
    assert_eq!(second["revision"], 2);
    assert_eq!(second["previous_revision_hash"], hash);
    assert_eq!(store.get_asset_revision(&t, aid, 1).unwrap(), first);
    assert_eq!(store.get_asset(&t, aid).unwrap(), second);
    assert!(
        store
            .revise_asset(&t, &p, aid, &body, 1, hash, &key, NOW + 2)
            .unwrap()
            .replayed
    );
    assert!(matches!(
        store.revise_asset(&t, &p, aid, &body, 1, hash, &id(), NOW + 2),
        Err(StoreError::PreconditionFailed)
    ));
    assert_eq!(store.verify_audit_chain(&t).unwrap(), 2);
}
#[test]
fn retired_assets_are_visible_historically_but_cannot_reactivate_or_join_new_services() {
    let store = Store::in_memory().unwrap();
    let (t, p) = setup(&store);
    let first = store
        .create_asset(&t, &p, &asset(&p, "Host"), &id(), NOW)
        .unwrap()
        .value;
    let aid = first["asset_id"].as_str().unwrap();
    let mut body = asset(&p, "Host");
    body["state"] = json!("retired");
    let retired = store
        .revise_asset(
            &t,
            &p,
            aid,
            &body,
            1,
            first["content_hash"].as_str().unwrap(),
            &id(),
            NOW,
        )
        .unwrap()
        .value;
    assert_eq!(store.get_asset(&t, aid).unwrap()["state"], "retired");
    assert!(matches!(
        store.revise_asset(
            &t,
            &p,
            aid,
            &asset(&p, "Host"),
            2,
            retired["content_hash"].as_str().unwrap(),
            &id(),
            NOW
        ),
        Err(StoreError::Retired)
    ));
    let target = id();
    store.register_observe_target(&t, &target, "linux").unwrap();
    assert!(matches!(
        store.create_service(&t, &p, &service(&p, aid, &target), &id(), NOW),
        Err(StoreError::Retired)
    ));
    assert_eq!(
        store.get_asset_revision(&t, aid, 1).unwrap()["state"],
        "active"
    );
}
#[test]
fn asset_tenant_owner_and_authority_fields_are_rejected() {
    let store = Store::in_memory().unwrap();
    let (t, p) = setup(&store);
    let (other, op) = setup(&store);
    assert!(matches!(
        store.create_asset(&t, &p, &asset(&op, "Foreign"), &id(), NOW),
        Err(StoreError::NotFound)
    ));
    let a = store
        .create_asset(&t, &p, &asset(&p, "Host"), &id(), NOW)
        .unwrap()
        .value;
    assert!(matches!(
        store.get_asset(&other, a["asset_id"].as_str().unwrap()),
        Err(StoreError::NotFound)
    ));
    let mut claim = asset(&p, "Impostor");
    claim["definition"]["provenance"] = json!("trusted_inventory");
    assert!(store.create_asset(&t, &p, &claim, &id(), NOW).is_err());
    let mut injected = asset(&p, "Injected");
    injected["created_by"] = json!(op);
    assert!(store.create_asset(&t, &p, &injected, &id(), NOW).is_err());
    assert_eq!(store.count_assets(&t).unwrap(), 1);
}
#[test]
fn addresses_require_canonical_family_and_unique_entries() {
    let store = Store::in_memory().unwrap();
    let (t, p) = setup(&store);
    for cidr in ["10.0.0.1/24", "::ffff:10.0.0.1/128", "2001:0db8::/32"] {
        let mut body = asset(&p, "Host");
        body["definition"]["addresses"][0]["cidr"] = json!(cidr);
        assert!(store.create_asset(&t, &p, &body, &id(), NOW).is_err());
    }
    let mut body = asset(&p, "Host");
    let a = body["definition"]["addresses"][0].clone();
    body["definition"]["addresses"]
        .as_array_mut()
        .unwrap()
        .push(a);
    assert!(store.create_asset(&t, &p, &body, &id(), NOW).is_err());
    let mut body = asset(&p, "Host");
    body["definition"]["addresses"][0]["family"] = json!("ipv6");
    assert!(store.create_asset(&t, &p, &body, &id(), NOW).is_err());
}
#[test]
fn services_store_normalized_relations_ports_and_exact_revisions() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("db");
    let store = Store::open(&path).unwrap();
    let (t, p) = setup(&store);
    let (_, s) = make_service(&store, &t, &p);
    assert_eq!(s["service_id"], "database");
    assert_eq!(s["created_by"], p);
    let raw = Connection::open(&path).unwrap();
    for table in ["service_destinations", "service_targets", "service_ports"] {
        assert_eq!(
            raw.query_row(&format!("SELECT count(*) FROM {table}"), [], |r| r
                .get::<_, i64>(0))
                .unwrap(),
            1
        );
    }
    let mut body = revision_body(&s);
    body["definition"]["description"] = json!("Revised description");
    let second = store
        .revise_service(
            &t,
            &p,
            "database",
            &body,
            1,
            s["content_hash"].as_str().unwrap(),
            &id(),
            NOW + 1,
        )
        .unwrap()
        .value;
    assert_eq!(second["previous_revision_hash"], s["content_hash"]);
    assert_eq!(store.get_service_revision(&t, "database", 1).unwrap(), s);
    assert_eq!(store.get_service(&t, "database").unwrap(), second);
    assert!(raw.execute("DELETE FROM service_ports", []).is_err());
    assert!(raw
        .execute("UPDATE asset_revisions SET state='retired'", [])
        .is_err());
}
#[test]
fn services_reject_cross_tenant_destinations_and_unknown_targets() {
    let store = Store::in_memory().unwrap();
    let (t, p) = setup(&store);
    let (other, op) = setup(&store);
    let a = store
        .create_asset(&other, &op, &asset(&op, "Foreign"), &id(), NOW)
        .unwrap()
        .value;
    let target = id();
    store.register_observe_target(&t, &target, "linux").unwrap();
    assert!(matches!(
        store.create_service(
            &t,
            &p,
            &service(&p, a["asset_id"].as_str().unwrap(), &target),
            &id(),
            NOW
        ),
        Err(StoreError::NotFound)
    ));
    let own = store
        .create_asset(&t, &p, &asset(&p, "Own"), &id(), NOW)
        .unwrap()
        .value;
    let foreign_target = id();
    store
        .register_observe_target(&other, &foreign_target, "linux")
        .unwrap();
    assert!(matches!(
        store.create_service(
            &t,
            &p,
            &service(&p, own["asset_id"].as_str().unwrap(), &foreign_target),
            &id(),
            NOW
        ),
        Err(StoreError::NotFound)
    ));
    assert_eq!(store.count_services(&t).unwrap(), 0);
}
#[test]
fn services_preserve_slug_identity_and_reject_overlap_and_duplicate_names() {
    let store = Store::in_memory().unwrap();
    let (t, p) = setup(&store);
    let (_, s) = make_service(&store, &t, &p);
    let mut body = json!({"service_id":"other","definition":s["definition"]});
    assert!(matches!(
        store.create_service(&t, &p, &body, &id(), NOW),
        Err(StoreError::Conflict("NAME_EXISTS"))
    ));
    body["definition"]["name"] = json!("Other");
    body["definition"]["transport"]["destination_ports"] =
        json!([{"start":80,"end":90},{"start":90,"end":100}]);
    assert!(store.create_service(&t, &p, &body, &id(), NOW).is_err());
    body["service_id"] = json!("../other");
    assert!(store.create_service(&t, &p, &body, &id(), NOW).is_err());
    let mut retired = revision_body(&s);
    retired["state"] = json!("retired");
    let r = store
        .revise_service(
            &t,
            &p,
            "database",
            &retired,
            1,
            s["content_hash"].as_str().unwrap(),
            &id(),
            NOW,
        )
        .unwrap()
        .value;
    assert!(matches!(
        store.revise_service(
            &t,
            &p,
            "database",
            &revision_body(&s),
            2,
            r["content_hash"].as_str().unwrap(),
            &id(),
            NOW
        ),
        Err(StoreError::Retired)
    ));
}
#[test]
fn full_lists_refuse_partial_results() {
    let store = Store::in_memory().unwrap();
    let (t, p) = setup(&store);
    store
        .create_asset(&t, &p, &asset(&p, "One"), &id(), NOW)
        .unwrap();
    store
        .create_asset(&t, &p, &asset(&p, "Two"), &id(), NOW)
        .unwrap();
    assert!(matches!(
        store.list_assets(&t, 1),
        Err(StoreError::Conflict("RESULT_TOO_LARGE"))
    ));
    assert_eq!(store.list_assets(&t, 2).unwrap().len(), 2);
}
#[test]
fn concurrent_registry_cas_has_one_winner_with_independent_connections() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("db");
    let store = Store::open(&path).unwrap();
    let (t, p) = setup(&store);
    let first = store
        .create_asset(&t, &p, &asset(&p, "Host"), &id(), NOW)
        .unwrap()
        .value;
    let stores = (0..12)
        .map(|_| Store::open(&path).unwrap())
        .collect::<Vec<_>>();
    let barrier = Arc::new(Barrier::new(12));
    let handles = stores
        .into_iter()
        .map(|s| {
            let t = t.clone();
            let p = p.clone();
            let first = first.clone();
            let b = barrier.clone();
            std::thread::spawn(move || {
                b.wait();
                s.revise_asset(
                    &t,
                    &p,
                    first["asset_id"].as_str().unwrap(),
                    &asset(&p, "Revised"),
                    1,
                    first["content_hash"].as_str().unwrap(),
                    &id(),
                    NOW + 1,
                )
            })
        })
        .collect::<Vec<_>>();
    let result = handles
        .into_iter()
        .map(|h| h.join().unwrap())
        .collect::<Vec<_>>();
    assert_eq!(result.iter().filter(|r| r.is_ok()).count(), 1);
    assert_eq!(
        result
            .iter()
            .filter(|r| matches!(r, Err(StoreError::PreconditionFailed)))
            .count(),
        11
    );
    assert_eq!(store.verify_audit_chain(&t).unwrap(), 2);
}
#[test]
fn registry_audit_failure_rolls_back_revision_head_relations_outbox_and_idempotency() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("db");
    let store = Store::open(&path).unwrap();
    let (t, p) = setup(&store);
    let raw = Connection::open(&path).unwrap();
    raw.execute_batch("CREATE TRIGGER fail_audit BEFORE INSERT ON audit_events BEGIN SELECT RAISE(ABORT,'injected');END;").unwrap();
    assert!(store
        .create_asset(&t, &p, &asset(&p, "Host"), &id(), NOW)
        .is_err());
    for table in [
        "assets",
        "asset_revisions",
        "asset_addresses",
        "registry_idempotency",
        "outbox",
    ] {
        assert_eq!(
            raw.query_row(&format!("SELECT count(*) FROM {table}"), [], |r| r
                .get::<_, i64>(0))
                .unwrap(),
            0
        );
    }
    assert_eq!(store.security_revision(&t).unwrap(), 1);
}
#[test]
fn v1_migration_preserves_existing_data_and_marks_version_three() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("db");
    let raw = Connection::open(&path).unwrap();
    let sql = include_str!("../migrations/0001_lite.sql");
    raw.execute_batch("CREATE TABLE schema_migrations(version INTEGER PRIMARY KEY,checksum TEXT NOT NULL,app_compat_min INTEGER NOT NULL,app_compat_max INTEGER NOT NULL) STRICT;").unwrap();
    raw.execute_batch(sql).unwrap();
    raw.execute(
        "INSERT INTO schema_migrations VALUES(1,?1,1,1)",
        [hash_bytes(sql.as_bytes())],
    )
    .unwrap();
    let org = id();
    raw.execute(
        "INSERT INTO organizations(org_id,name,created_at) VALUES(?1,'Preserved',?2)",
        params![org, NOW],
    )
    .unwrap();
    drop(raw);
    let store = Store::open(&path).unwrap();
    drop(store);
    let raw = Connection::open(&path).unwrap();
    assert_eq!(
        raw.pragma_query_value(None, "user_version", |r| r.get::<_, i64>(0))
            .unwrap(),
        3
    );
    assert_eq!(
        raw.query_row(
            "SELECT name FROM organizations WHERE org_id=?1",
            [org],
            |r| r.get::<_, String>(0)
        )
        .unwrap(),
        "Preserved"
    );
    assert_eq!(
        raw.query_row("SELECT count(*) FROM schema_migrations", [], |r| r
            .get::<_, i64>(0))
            .unwrap(),
        3
    );
}
#[test]
fn unknown_version_or_old_migration_checksum_prevents_upgrade() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("db");
    drop(Store::open(&path).unwrap());
    let raw = Connection::open(&path).unwrap();
    raw.pragma_update(None, "user_version", 99).unwrap();
    assert!(matches!(Store::open(&path), Err(StoreError::Integrity(_))));
    raw.pragma_update(None, "user_version", 3).unwrap();
    raw.execute(
        "UPDATE schema_migrations SET checksum='tampered' WHERE version=1",
        [],
    )
    .unwrap();
    assert!(matches!(Store::open(&path), Err(StoreError::Integrity(_))));
}

#[test]
fn creation_replay_returns_original_revision_after_retirement_and_service_conflicts_are_exact() {
    let store = Store::in_memory().unwrap();
    let (t, p) = setup(&store);
    let key = id();
    let body = asset(&p, "Host");
    let first = store.create_asset(&t, &p, &body, &key, NOW).unwrap().value;
    let aid = first["asset_id"].as_str().unwrap();
    let target = id();
    store.register_observe_target(&t, &target, "linux").unwrap();
    let service_body = service(&p, aid, &target);
    let service_key = id();
    let service_first = store
        .create_service(&t, &p, &service_body, &service_key, NOW)
        .unwrap()
        .value;
    let mut changed = service_body.clone();
    changed["definition"]["description"] = json!("Changed");
    assert!(matches!(
        store.create_service(&t, &p, &changed, &service_key, NOW),
        Err(StoreError::IdempotencyConflict)
    ));
    let mut retire = revision_body(&first);
    retire["state"] = json!("retired");
    store
        .revise_asset(
            &t,
            &p,
            aid,
            &retire,
            1,
            first["content_hash"].as_str().unwrap(),
            &id(),
            NOW,
        )
        .unwrap();
    assert_eq!(
        store
            .create_asset(&t, &p, &body, &key, NOW + 10)
            .unwrap()
            .value,
        first
    );
    assert_eq!(
        store
            .create_service(&t, &p, &service_body, &service_key, NOW + 10)
            .unwrap()
            .value,
        service_first
    );
    let mut retire_service = revision_body(&service_first);
    retire_service["state"] = json!("retired");
    store
        .revise_service(
            &t,
            &p,
            "database",
            &retire_service,
            1,
            service_first["content_hash"].as_str().unwrap(),
            &id(),
            NOW,
        )
        .unwrap();
    assert_eq!(
        store
            .create_service(&t, &p, &service_body, &service_key, NOW + 10)
            .unwrap()
            .value,
        service_first
    );
    assert!(matches!(
        store.create_service(&t, &p, &service_body, &id(), NOW),
        Err(StoreError::Conflict("RESOURCE_EXISTS"))
    ));
}
#[test]
fn icmp_protocol_family_is_checked_against_destination_catalog() {
    let store = Store::in_memory().unwrap();
    let (t, p) = setup(&store);
    let a = store
        .create_asset(&t, &p, &asset(&p, "Host"), &id(), NOW)
        .unwrap()
        .value;
    let target = id();
    store.register_observe_target(&t, &target, "linux").unwrap();
    let mut body = service(&p, a["asset_id"].as_str().unwrap(), &target);
    body["definition"]["transport"] = json!({"protocol":"icmpv6","type":128,"code":0});
    assert!(matches!(
        store.create_service(&t, &p, &body, &id(), NOW),
        Err(StoreError::InvalidInput("service protocol/family mismatch"))
    ));
    body["definition"]["transport"] = json!({"protocol":"icmp","type":8,"code":0});
    let value = store
        .create_service(&t, &p, &body, &id(), NOW)
        .unwrap()
        .value;
    assert_eq!(store.get_service(&t, "database").unwrap(), value);
}
#[test]
fn normalized_projection_tampering_is_detected_even_when_content_hash_is_unchanged() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("db");
    let store = Store::open(&path).unwrap();
    let (t, p) = setup(&store);
    let (a, _) = make_service(&store, &t, &p);
    let raw = Connection::open(&path).unwrap();
    raw.execute_batch(
        "DROP TRIGGER service_destination_no_delete; DELETE FROM service_destinations;",
    )
    .unwrap();
    assert!(matches!(
        store.get_service(&t, "database"),
        Err(StoreError::Integrity(
            "service relation projection mismatch"
        ))
    ));
    raw.execute_batch(
        "DROP TRIGGER asset_address_no_update; UPDATE asset_addresses SET prefix=24;",
    )
    .unwrap();
    assert!(matches!(
        store.get_asset(&t, a["asset_id"].as_str().unwrap()),
        Err(StoreError::Integrity("asset address projection mismatch"))
    ));
}
