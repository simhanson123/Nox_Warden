use fw_contracts::hash_bytes;
use fw_store::{Store, StoreError, Tenant};
use serde_json::json;
use uuid::Uuid;

const NOW: i64 = 1_793_318_400;
fn setup(store: &Store) -> (Tenant, String) {
    let tenant = store
        .ensure_tenant(
            &Uuid::new_v4().to_string(),
            &Uuid::new_v4().to_string(),
            "Audit tests",
            NOW,
        )
        .unwrap();
    let principal = Uuid::new_v4().to_string();
    store
        .ensure_principal(&tenant, &principal, "human", NOW)
        .unwrap();
    (tenant, principal)
}
fn add(store: &Store, t: &Tenant, count: usize, now: i64) {
    for _ in 0..count {
        store
            .record_denied_action(t, None, "SESSION_EXPIRED", now)
            .unwrap();
    }
}

#[test]
fn more_than_one_hundred_events_traverse_without_omissions_and_appends_stay_outside_snapshot() {
    let store = Store::in_memory().unwrap();
    let (t, _) = setup(&store);
    add(&store, &t, 237, NOW);
    let first = store.list_audit_page(&t, 0, None, 25).unwrap();
    assert_eq!(first.events.len(), 25);
    assert_eq!(first.snapshot_sequence, 237);
    add(&store, &t, 5, NOW + 1);
    let mut events = first.events;
    let mut next = first.next_after_sequence;
    while let Some(after) = next {
        let page = store.list_audit_page(&t, after, Some(237), 25).unwrap();
        assert_eq!(page.snapshot_sequence, 237);
        next = page.next_after_sequence;
        events.extend(page.events);
    }
    assert_eq!(events.len(), 237);
    for (index, event) in events.iter().enumerate() {
        assert_eq!(event["sequence"], (index + 1).to_string());
    }
    for pair in events.windows(2) {
        assert_eq!(pair[1]["previous_event_hash"], pair[0]["event_hash"]);
    }
    let appended = store.list_audit_page(&t, 237, None, 100).unwrap();
    assert_eq!(appended.events.len(), 5);
    assert_eq!(appended.snapshot_sequence, 242);
    assert!(appended.next_after_sequence.is_none());
    assert_eq!(store.verify_audit_chain(&t).unwrap(), 242);
}

#[test]
fn audit_pages_preserve_tenant_isolation_empty_results_and_explicit_bounds() {
    let store = Store::in_memory().unwrap();
    let (a, _) = setup(&store);
    let (b, _) = setup(&store);
    add(&store, &a, 101, NOW);
    add(&store, &b, 3, NOW);
    let page = store.list_audit_page(&a, 0, None, 100).unwrap();
    assert_eq!(page.events.len(), 100);
    assert_eq!(page.next_after_sequence, Some(100));
    assert!(page.events.iter().all(|v| v["org_id"] == a.org_id));
    let other = store.list_audit_page(&b, 0, None, 100).unwrap();
    assert_eq!(other.events.len(), 3);
    assert!(store.list_audit_page(&b, 0, Some(101), 100).is_err());
    assert!(store
        .list_audit_page(&a, u64::MAX, None, 100)
        .unwrap()
        .events
        .is_empty());
    assert!(store.list_audit_page(&a, 0, None, 0).is_err());
    assert!(store.list_audit_page(&a, 0, None, 101).is_err());
    let (empty, _) = setup(&store);
    let page = store.list_audit_page(&empty, 0, None, 100).unwrap();
    assert!(page.events.is_empty());
    assert_eq!(page.snapshot_sequence, 0);
    assert!(page.next_after_sequence.is_none());
}

#[test]
fn coalesced_denial_evidence_preserves_closed_events_and_is_tenant_bound_immutable_and_idempotent()
{
    let store = Store::in_memory().unwrap();
    let (t, _) = setup(&store);
    let (other, _) = setup(&store);
    store
        .record_denied_action(&t, None, "SESSION_EXPIRED", NOW)
        .unwrap();
    store
        .record_denied_summary(&t, None, "SESSION_EXPIRED", 99, NOW, NOW + 59, NOW + 60)
        .unwrap();
    store
        .record_denied_summary(&t, None, "SESSION_EXPIRED", 99, NOW, NOW + 59, NOW + 61)
        .unwrap();
    let page = store.list_audit_page(&t, 0, None, 100).unwrap();
    assert_eq!(page.events.len(), 2);
    let summary_event = &page.events[1];
    assert_eq!(summary_event["event_type"], "denied_action");
    assert!(summary_event.get("count").is_none());
    assert!(summary_event["actor_id"].is_null());
    let hash = summary_event["evidence_hashes"][0].as_str().unwrap();
    let value = store.get_denial_summary(&t, hash).unwrap();
    assert_eq!(
        value["schema_version"],
        "fw.authentication-denial-summary/v1"
    );
    assert_eq!(value["count"], "99");
    assert_eq!(value["scope"], "suppressed_followup_denials");
    assert_eq!(
        hash_bytes(&fw_contracts::canonical_bytes(&value).unwrap()),
        hash
    );
    assert!(matches!(
        store.get_denial_summary(&other, hash),
        Err(StoreError::NotFound)
    ));
    assert!(store.get_denial_summary(&t, "not a hash").is_err());
    assert_eq!(store.verify_audit_chain(&t).unwrap(), 2);
}

#[test]
fn denial_summary_rejects_untrusted_reasons_invalid_windows_zero_counts_and_inactive_actors() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("db");
    let store = Store::open(&path).unwrap();
    let (t, p) = setup(&store);
    for (reason, count, start, end, now) in [
        ("TOKEN_STOLEN_USER_TEXT", 1, NOW, NOW, NOW),
        ("SESSION_EXPIRED", 0, NOW, NOW, NOW),
        ("SESSION_EXPIRED", 1, NOW + 1, NOW, NOW + 2),
        ("SESSION_EXPIRED", 1, NOW, NOW + 1, NOW),
    ] {
        assert!(store
            .record_denied_summary(&t, None, reason, count, start, end, now)
            .is_err());
    }
    let raw = rusqlite::Connection::open(path).unwrap();
    raw.execute(
        "UPDATE principals SET state='suspended' WHERE principal_id=?1",
        [&p],
    )
    .unwrap();
    assert!(matches!(
        store.record_denied_summary(&t, Some(&p), "SESSION_EXPIRED", 1, NOW, NOW, NOW),
        Err(StoreError::NotFound)
    ));
    assert_eq!(store.count_audit(&t, 0).unwrap(), 0);
    let count: i64 = raw
        .query_row("SELECT count(*) FROM audit_denial_summaries", [], |r| {
            r.get(0)
        })
        .unwrap();
    assert_eq!(count, 0);
}

#[test]
fn denial_summary_and_audit_commit_atomically_and_tampered_evidence_is_rejected() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("db");
    let store = Store::open(&path).unwrap();
    let (t, _) = setup(&store);
    let raw = rusqlite::Connection::open(path).unwrap();
    raw.execute_batch("CREATE TRIGGER injected_audit_failure BEFORE INSERT ON audit_events BEGIN SELECT RAISE(ABORT,'injected'); END;").unwrap();
    assert!(store
        .record_denied_summary(&t, None, "SESSION_EXPIRED", 2, NOW, NOW, NOW)
        .is_err());
    let count: i64 = raw
        .query_row("SELECT count(*) FROM audit_denial_summaries", [], |r| {
            r.get(0)
        })
        .unwrap();
    assert_eq!(count, 0);
    raw.execute_batch("DROP TRIGGER injected_audit_failure;")
        .unwrap();
    store
        .record_denied_summary(&t, None, "SESSION_EXPIRED", 2, NOW, NOW, NOW)
        .unwrap();
    let event = store
        .list_audit_page(&t, 0, None, 100)
        .unwrap()
        .events
        .remove(0);
    let hash = event["evidence_hashes"][0].as_str().unwrap();
    assert!(raw
        .execute("DELETE FROM audit_denial_summaries", [])
        .is_err());
    assert!(raw
        .execute(
            "UPDATE audit_denial_summaries SET canonical_bytes=x'7b7d'",
            []
        )
        .is_err());
    raw.execute_batch("DROP TRIGGER audit_denial_summary_no_update; UPDATE audit_denial_summaries SET canonical_bytes=x'7b7d';").unwrap();
    assert!(matches!(
        store.get_denial_summary(&t, hash),
        Err(StoreError::Integrity(_))
    ));
}

#[test]
fn audit_page_checks_database_projection_against_canonical_evidence() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("db");
    let store = Store::open(&path).unwrap();
    let (t, _) = setup(&store);
    add(&store, &t, 2, NOW);
    let raw = rusqlite::Connection::open(path).unwrap();
    let mut first = store.list_audit(&t, 0, 1).unwrap().remove(0);
    first.as_object_mut().unwrap().remove("event_hash");
    first["sequence"] = json!("7");
    let bytes = fw_contracts::canonical_bytes(&first).unwrap();
    let hash = hash_bytes(&bytes);
    let raw_hash: Vec<u8> = (0..32)
        .map(|i| u8::from_str_radix(&hash[7 + i * 2..9 + i * 2], 16).unwrap())
        .collect();
    raw.execute_batch("DROP TRIGGER audit_no_update;").unwrap();
    raw.execute(
        "UPDATE audit_events SET canonical_bytes=?1,event_hash=?2 WHERE sequence=?3",
        rusqlite::params![bytes, raw_hash, fw_store::encode_u64(1).as_slice()],
    )
    .unwrap();
    assert!(matches!(
        store.list_audit_page(&t, 0, None, 100),
        Err(StoreError::Integrity(_))
    ));
}
