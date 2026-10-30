use fw_store::{decode_u64, encode_u64, Store, StoreError, Tenant};
use rusqlite::{params, Connection};
use serde_json::{json, Value};
use std::sync::{Arc, Barrier};
use uuid::Uuid;

const NOW: i64 = 1_793_318_400;
fn id() -> String {
    Uuid::new_v4().to_string()
}
fn prepare(store: &Store) -> (Tenant, String) {
    let t = store.ensure_tenant(&id(), &id(), "Test", NOW).unwrap();
    let principal = id();
    store
        .ensure_principal(&t, &principal, "human", NOW)
        .unwrap();
    (t, principal)
}
fn submit(store: &Store, t: &Tenant, p: &str, key: &str) -> fw_store::Submission {
    store
        .submit_request(
            t,
            p,
            "access_request",
            &json!({"intent":"test only"}),
            key,
            NOW,
        )
        .unwrap()
}

#[test]
fn request_audit_outbox_and_original_response_are_atomic_and_replayable() {
    let store = Store::in_memory().unwrap();
    let (t, p) = prepare(&store);
    let key = id();
    let a = submit(&store, &t, &p, &key);
    assert!(!a.replayed);
    assert_eq!(a.request.revision, 1);
    assert_eq!(store.count_requests(&t).unwrap(), 1);
    let current = store
        .compare_and_swap_request_state(&t, &a.request.request_id, 1, "needs_info", NOW + 1)
        .unwrap();
    assert_eq!(current.state, "needs_info");
    let b = submit(&store, &t, &p, &key);
    assert!(b.replayed);
    assert_eq!(b.request.state, "submitted");
    assert_eq!(b.request.request_id, a.request.request_id);
    assert_eq!(store.verify_audit_chain(&t).unwrap(), 2);
    let events = store.list_audit(&t, 0, 100).unwrap();
    assert_eq!(events[1]["previous_event_hash"], events[0]["event_hash"]);
    let operation = store.get_operation(&t, &a.operation.operation_id).unwrap();
    assert_eq!(operation.state, "failed");
    assert_eq!(operation.view()["reason_code"], "CAPABILITY_UNSUPPORTED");
}

#[test]
fn same_key_different_body_conflicts_without_side_effects() {
    let store = Store::in_memory().unwrap();
    let (t, p) = prepare(&store);
    let key = id();
    submit(&store, &t, &p, &key);
    assert!(matches!(
        store.submit_request(
            &t,
            &p,
            "access_request",
            &json!({"intent":"changed"}),
            &key,
            NOW
        ),
        Err(StoreError::IdempotencyConflict)
    ));
    assert_eq!(store.verify_audit_chain(&t).unwrap(), 1);
    assert_eq!(store.count_operations(&t).unwrap(), 1);
    assert_eq!(store.claim_outbox(&t, NOW, 30, 50).unwrap().len(), 1);
}

#[test]
fn canonical_key_order_does_not_conflict() {
    let store = Store::in_memory().unwrap();
    let (t, p) = prepare(&store);
    let key = id();
    let a: Value = serde_json::from_str(r#"{"z":1,"a":2}"#).unwrap();
    let b: Value = serde_json::from_str(r#"{"a":2,"z":1}"#).unwrap();
    store
        .submit_request(&t, &p, "access_request", &a, &key, NOW)
        .unwrap();
    assert!(
        store
            .submit_request(&t, &p, "access_request", &b, &key, NOW)
            .unwrap()
            .replayed
    );
}

#[test]
fn idempotency_is_scoped_to_principal_and_route() {
    let store = Store::in_memory().unwrap();
    let (t, p) = prepare(&store);
    let key = id();
    let other = id();
    store.ensure_principal(&t, &other, "human", NOW).unwrap();
    let a = submit(&store, &t, &p, &key);
    let b = submit(&store, &t, &other, &key);
    let c = store
        .submit_request(
            &t,
            &p,
            "policy_change",
            &json!({"intent":"test only"}),
            &key,
            NOW,
        )
        .unwrap();
    assert_ne!(a.request.request_id, b.request.request_id);
    assert_ne!(a.request.request_id, c.request.request_id);
    assert_eq!(store.count_requests(&t).unwrap(), 3);
}

#[test]
fn cross_tenant_ids_and_principals_do_not_leak() {
    let store = Store::in_memory().unwrap();
    let (t, p) = prepare(&store);
    let (other, other_p) = prepare(&store);
    let a = submit(&store, &t, &p, &id());
    assert!(matches!(
        store.get_request(&other, &a.request.request_id),
        Err(StoreError::NotFound)
    ));
    assert!(matches!(
        store.get_operation(&other, &a.operation.operation_id),
        Err(StoreError::NotFound)
    ));
    assert!(matches!(
        store.submit_request(&t, &other_p, "access_request", &json!({}), &id(), NOW),
        Err(StoreError::NotFound)
    ));
    assert!(store.list_requests(&other, None, 100).unwrap().is_empty());
    assert!(store.list_audit(&other, 0, 100).unwrap().is_empty());
}

#[test]
fn outbox_expired_claims_are_fenced() {
    let store = Store::in_memory().unwrap();
    let (t, p) = prepare(&store);
    submit(&store, &t, &p, &id());
    let first = store.claim_outbox(&t, NOW, 10, 50).unwrap().remove(0);
    assert!(store.claim_outbox(&t, NOW + 9, 10, 50).unwrap().is_empty());
    let second = store.claim_outbox(&t, NOW + 10, 10, 50).unwrap().remove(0);
    assert_eq!(second.generation, first.generation + 1);
    assert!(matches!(
        store.acknowledge_outbox(&t, &first.event_id, first.generation, NOW + 11),
        Err(StoreError::ClaimStale)
    ));
    store
        .acknowledge_outbox(&t, &second.event_id, second.generation, NOW + 11)
        .unwrap();
    assert!(store
        .claim_outbox(&t, NOW + 100, 10, 50)
        .unwrap()
        .is_empty());
}

#[test]
fn outbox_claim_expiry_is_exclusive() {
    let store = Store::in_memory().unwrap();
    let (t, p) = prepare(&store);
    submit(&store, &t, &p, &id());
    let claim = store.claim_outbox(&t, NOW, 10, 1).unwrap().remove(0);
    assert!(matches!(
        store.acknowledge_outbox(&t, &claim.event_id, claim.generation, NOW + 10),
        Err(StoreError::ClaimStale)
    ));
}

#[test]
fn one_hundred_concurrent_duplicates_create_one_request() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("store.db");
    let store = Store::open(&path).unwrap();
    let (t, p) = prepare(&store);
    let key = id();
    let stores = (0..100)
        .map(|_| Store::open(&path).unwrap())
        .collect::<Vec<_>>();
    let barrier = Arc::new(Barrier::new(100));
    let threads = stores
        .into_iter()
        .map(|s| {
            let t = t.clone();
            let p = p.clone();
            let key = key.clone();
            let barrier = barrier.clone();
            std::thread::spawn(move || {
                barrier.wait();
                submit(&s, &t, &p, &key)
            })
        })
        .collect::<Vec<_>>();
    let results = threads
        .into_iter()
        .map(|t| t.join().unwrap())
        .collect::<Vec<_>>();
    assert_eq!(results.iter().filter(|r| !r.replayed).count(), 1);
    assert!(results
        .iter()
        .all(|r| r.request.request_id == results[0].request.request_id));
    assert_eq!(store.count_requests(&t).unwrap(), 1);
    assert_eq!(store.verify_audit_chain(&t).unwrap(), 1);
}

#[test]
fn concurrent_cas_has_exactly_one_winner() {
    let store = Arc::new(Store::in_memory().unwrap());
    let (t, p) = prepare(&store);
    let request = submit(&store, &t, &p, &id()).request;
    let threads = (0..16)
        .map(|_| {
            let s = store.clone();
            let t = t.clone();
            let id = request.request_id.clone();
            std::thread::spawn(move || {
                s.compare_and_swap_request_state(&t, &id, 1, "needs_info", NOW + 1)
            })
        })
        .collect::<Vec<_>>();
    let results = threads
        .into_iter()
        .map(|t| t.join().unwrap())
        .collect::<Vec<_>>();
    assert_eq!(results.iter().filter(|r| r.is_ok()).count(), 1);
    assert_eq!(
        results
            .iter()
            .filter(|r| matches!(r, Err(StoreError::PreconditionFailed)))
            .count(),
        15
    );
    assert_eq!(store.verify_audit_chain(&t).unwrap(), 2);
}

#[test]
fn injected_outbox_failure_rolls_back_business_and_audit() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("db");
    let store = Store::open(&path).unwrap();
    let (t, p) = prepare(&store);
    let raw = Connection::open(&path).unwrap();
    raw.execute_batch("CREATE TRIGGER fail_enqueue BEFORE INSERT ON outbox BEGIN SELECT RAISE(ABORT,'injected'); END;").unwrap();
    assert!(store
        .submit_request(&t, &p, "access_request", &json!({}), &id(), NOW)
        .is_err());
    assert_eq!(store.count_requests(&t).unwrap(), 0);
    assert_eq!(store.count_operations(&t).unwrap(), 0);
    assert_eq!(store.verify_audit_chain(&t).unwrap(), 0);
    assert_eq!(
        raw.query_row("SELECT count(*) FROM idempotency", [], |r| r
            .get::<_, u64>(0))
            .unwrap(),
        0
    );
}

#[test]
fn injected_audit_failure_rolls_back_outbox_and_request() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("db");
    let store = Store::open(&path).unwrap();
    let (t, p) = prepare(&store);
    let raw = Connection::open(&path).unwrap();
    raw.execute_batch("CREATE TRIGGER fail_audit BEFORE INSERT ON audit_events BEGIN SELECT RAISE(ABORT,'injected'); END;").unwrap();
    assert!(store
        .submit_request(&t, &p, "access_request", &json!({}), &id(), NOW)
        .is_err());
    assert_eq!(store.count_requests(&t).unwrap(), 0);
    assert_eq!(store.verify_audit_chain(&t).unwrap(), 0);
    assert_eq!(
        raw.query_row("SELECT count(*) FROM outbox", [], |r| r.get::<_, u64>(0))
            .unwrap(),
        0
    );
}

#[test]
fn append_only_database_constraints_and_tamper_detection() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("db");
    let store = Store::open(&path).unwrap();
    let (t, p) = prepare(&store);
    submit(&store, &t, &p, &id());
    let raw = Connection::open(&path).unwrap();
    assert!(raw.execute("DELETE FROM audit_events", []).is_err());
    assert!(raw
        .execute("UPDATE request_revisions SET canonical_bytes=x'7b7d'", [])
        .is_err());
    raw.execute_batch(
        "DROP TRIGGER audit_no_update; UPDATE audit_events SET canonical_bytes=x'7b7d';",
    )
    .unwrap();
    assert!(matches!(
        store.verify_audit_chain(&t),
        Err(StoreError::Integrity(_))
    ));
}

#[test]
fn durable_reopen_and_online_backup_preserve_chain_and_replay() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("db");
    let backup = dir.path().join("backup");
    let store = Store::open(&path).unwrap();
    let (t, p) = prepare(&store);
    let key = id();
    let request = submit(&store, &t, &p, &key);
    store.backup(&backup).unwrap();
    assert!(store.backup(&backup).is_err());
    drop(store);
    for path in [&path, &backup] {
        let store = Store::open(path).unwrap();
        assert_eq!(store.verify_audit_chain(&t).unwrap(), 1);
        assert_eq!(
            submit(&store, &t, &p, &key).request.request_id,
            request.request.request_id
        );
    }
}

#[test]
fn changed_migration_checksum_prevents_startup() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("db");
    drop(Store::open(&path).unwrap());
    let raw = Connection::open(&path).unwrap();
    raw.execute("UPDATE schema_migrations SET checksum='wrong'", [])
        .unwrap();
    assert!(matches!(Store::open(&path), Err(StoreError::Integrity(_))));
}

#[test]
fn unsigned_u64_encodings_preserve_full_range_and_order() {
    let values = [0, (1u64 << 63) - 1, 1u64 << 63, u64::MAX];
    let raw = Connection::open_in_memory().unwrap();
    raw.execute_batch("CREATE TABLE counters(value BLOB CHECK(length(value)=8));")
        .unwrap();
    for n in values.iter().rev() {
        raw.execute(
            "INSERT INTO counters VALUES(?1)",
            params![encode_u64(*n).as_slice()],
        )
        .unwrap();
        assert_eq!(decode_u64(&encode_u64(*n)).unwrap(), *n);
    }
    let mut q = raw
        .prepare("SELECT value FROM counters ORDER BY value")
        .unwrap();
    let actual = q
        .query_map([], |r| r.get::<_, Vec<u8>>(0))
        .unwrap()
        .map(|v| decode_u64(&v.unwrap()).unwrap())
        .collect::<Vec<_>>();
    assert_eq!(actual, values);
    assert!(decode_u64(&[0; 7]).is_err());
}

#[test]
fn strict_identifiers_limits_and_state_transitions() {
    assert!(Tenant::new("NOT-UUID", id()).is_err());
    let store = Store::in_memory().unwrap();
    let (t, p) = prepare(&store);
    let request = submit(&store, &t, &p, &id()).request;
    assert!(store.list_requests(&t, None, 101).is_err());
    assert!(store
        .submit_request(&t, &p, "access_request", &json!({"f":1.5}), &id(), NOW)
        .is_err());
    assert!(store
        .submit_request(
            &t,
            &p,
            "access_request",
            &json!({"oversize":"a".repeat(65536)}),
            &id(),
            NOW
        )
        .is_err());
    assert!(store
        .compare_and_swap_request_state(&t, &request.request_id, 1, "ready", NOW)
        .is_err());
    assert_eq!(store.verify_audit_chain(&t).unwrap(), 1);
}

fn fixture_policy(t: &Tenant, principal: &str) -> fw_domain::Policy {
    let fixtures: Value = serde_json::from_str(include_str!(
        "../../../docs/specs/F_기준자료/F_개발계약/F_계약_예제.json"
    ))
    .unwrap();
    let mut policy: fw_domain::Policy =
        serde_json::from_value(fixtures["requested_policies"][0].clone()).unwrap();
    policy.org_id = t.org_id.clone();
    policy.project_id = t.project_id.clone();
    policy.owner_id = principal.to_owned();
    policy
}

#[test]
fn policy_drafts_preserve_revisions_and_reject_allow_expansion() {
    let store = Store::in_memory().unwrap();
    let (t, p) = prepare(&store);
    let mut policy = fixture_policy(&t, &p);
    store
        .register_observe_target(&t, &policy.target_id, "linux")
        .unwrap();
    let hash = store.save_policy_draft(&t, &policy, None, NOW).unwrap();
    policy.policy_revision = 2;
    policy.reason = "A narrowed revision".into();
    if let fw_domain::Lifetime::Lease {
        ref mut expires_at, ..
    } = policy.lifetime
    {
        *expires_at = "2026-10-30T09:20:00Z".into();
    }
    let next = store
        .save_policy_draft(&t, &policy, Some(&hash), NOW + 1)
        .unwrap();
    assert_ne!(hash, next);
    assert_eq!(
        store.list_draft_policies(&t, 100).unwrap()[0]["policy_revision"],
        2
    );
    assert!(matches!(
        store.save_policy_draft(&t, &policy, Some(&hash), NOW + 2),
        Err(StoreError::PreconditionFailed)
    ));
    policy.policy_revision = 3;
    policy.scope.destination_cidrs = vec!["10.20.2.0/24".into()];
    assert!(matches!(
        store.save_policy_draft(&t, &policy, Some(&next), NOW + 2),
        Err(StoreError::InvalidInput(_))
    ));
    assert_eq!(store.verify_audit_chain(&t).unwrap(), 2);
}

#[test]
fn policy_drafts_cannot_cross_tenant_or_target_foreign_keys() {
    let store = Store::in_memory().unwrap();
    let (t, p) = prepare(&store);
    let (other, _) = prepare(&store);
    let policy = fixture_policy(&t, &p);
    store
        .register_observe_target(&other, &policy.target_id, "linux")
        .unwrap();
    assert!(store.save_policy_draft(&t, &policy, None, NOW).is_err());
    assert!(matches!(
        store.save_policy_draft(&other, &policy, None, NOW),
        Err(StoreError::NotFound)
    ));
    assert!(store.list_draft_policies(&t, 100).unwrap().is_empty());
    assert_eq!(store.verify_audit_chain(&t).unwrap(), 0);
}

#[test]
fn denials_do_not_elevate_untrusted_actor_and_clock_regression_rolls_back() {
    let store = Store::in_memory().unwrap();
    let (t, p) = prepare(&store);
    store
        .record_denied_action(&t, None, "AUTH_REQUIRED", NOW)
        .unwrap();
    let event = store.list_audit(&t, 0, 100).unwrap().remove(0);
    assert_eq!(event["actor_id"], Value::Null);
    assert_eq!(event["outcome"], "denied");
    assert!(store
        .record_denied_action(&t, None, "user supplied text", NOW)
        .is_err());
    assert!(store
        .submit_request(&t, &p, "access_request", &json!({}), &id(), NOW - 1)
        .is_err());
    assert_eq!(store.count_requests(&t).unwrap(), 0);
    assert_eq!(store.verify_audit_chain(&t).unwrap(), 1);
}

#[test]
fn generation_exhaustion_fails_closed() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("db");
    let store = Store::open(&path).unwrap();
    let (t, p) = prepare(&store);
    submit(&store, &t, &p, &id());
    let raw = Connection::open(&path).unwrap();
    raw.execute(
        "UPDATE outbox SET claim_generation=?1",
        params![encode_u64(u64::MAX).as_slice()],
    )
    .unwrap();
    assert!(matches!(
        store.claim_outbox(&t, NOW, 30, 1),
        Err(StoreError::Integrity(_))
    ));
    raw.execute(
        "UPDATE audit_heads SET sequence=?1",
        params![encode_u64(u64::MAX).as_slice()],
    )
    .unwrap();
    assert!(matches!(
        store.record_denied_action(&t, None, "AUTH_REQUIRED", NOW),
        Err(StoreError::Integrity(_))
    ));
}

#[test]
fn unenrolled_requests_commit_terminal_failure_and_replay_atomically() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("db");
    let store = Store::open(&path).unwrap();
    let (t, p) = prepare(&store);
    let key = id();
    let submission = store
        .submit_unenrolled_request(&t, &p, "access_request", &json!({}), &key, NOW)
        .unwrap();
    assert_eq!(submission.request.state, "needs_info");
    assert_eq!(submission.operation.state, "failed");
    assert_eq!(
        submission.operation.reason_code.as_deref(),
        Some("CAPABILITY_UNSUPPORTED")
    );
    assert_eq!(store.verify_audit_chain(&t).unwrap(), 2);
    let claims = store.claim_outbox(&t, NOW, 30, 50).unwrap();
    assert_eq!(claims.len(), 1);
    assert_eq!(claims[0].event_kind, "request.validation_failed");
    drop(store);
    let reopened = Store::open(&path).unwrap();
    let replay = reopened
        .submit_unenrolled_request(&t, &p, "access_request", &json!({}), &key, NOW + 1)
        .unwrap();
    assert!(replay.replayed);
    assert_eq!(replay.request.state, "needs_info");
    assert_eq!(
        replay.operation.completed_at,
        submission.operation.completed_at
    );
    assert_eq!(
        reopened
            .get_request(&t, &submission.request.request_id)
            .unwrap()
            .state,
        "needs_info"
    );
}
