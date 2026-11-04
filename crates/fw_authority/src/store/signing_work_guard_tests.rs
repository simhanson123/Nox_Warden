use super::super::signing_test_support::{Fixture, NOW};
use super::*;

const WORKER: &str = "dddddddd-dddd-4ddd-8ddd-dddddddddddd";

// Keep deliberate source corruption and unsafe SQLite settings outside the
// live connection, so the original SQL/history checks remain directly tested.
fn forensic_connection(fixture: &Fixture) -> Connection {
    let db = Connection::open(&fixture.path).unwrap();
    db.execute_batch("PRAGMA foreign_keys=ON; PRAGMA recursive_triggers=OFF")
        .unwrap();
    db
}

fn assert_public_read_refused(fixture: &mut Fixture, job: &str) {
    let intent: String = fixture
        .store
        .connection
        .query_row(
            "SELECT intent_id FROM authority_signing_jobs WHERE job_id=?",
            [job],
            |row| row.get(0),
        )
        .unwrap();
    assert!(
        fixture
            .store
            .read_signing_intent(&fixture.tenant, &intent, NOW)
            .is_err()
    );
}

fn prepared() -> (Fixture, String) {
    let mut f = Fixture::new();
    let outcome = signing_intents::test_prepare(&mut f, NOW);
    (f, outcome.intent.job_id)
}

fn ready() -> (Fixture, String) {
    let (mut f, job) = prepared();
    let tx = f.store.connection.transaction().unwrap();
    let claim = fixture_claim(&tx, &f.tenant, &job, "signer", WORKER, 0, 60, NOW).unwrap();
    tx.commit().unwrap();
    signing_intents::test_finalize(&mut f, &claim, NOW).unwrap();
    (f, job)
}

#[test]
fn intact_guards_reject_claude_f1_skipped_claim_delivery_sequence() {
    let (mut f, job) = ready();
    let events = f.count("authority_signing_work_events");
    let audits = f.count("authority_audit");
    let tx = f.store.connection.transaction().unwrap();
    let next = 2u64.to_be_bytes();
    // This was the first step of the independently reproduced five-statement
    // counterexample: queued -> delivered without ever obtaining a claim.
    assert!(tx.execute("INSERT INTO authority_signing_work_events SELECT org_id,project_id,job_id,phase,'delivered',?1,claim_generation,NULL,NULL,NULL,attempts,available_at,?2,'delivered' FROM authority_signing_work_heads WHERE job_id=?3 AND phase='dispatch'", params![next.as_slice(), NOW, job]).is_err());
    assert!(tx.execute("UPDATE authority_signing_work_heads SET state='delivered',revision=?1 WHERE job_id=?2 AND phase='dispatch'", params![next.as_slice(), job]).is_err());
    let invented = b"ordinary SQL unsigned delivery";
    assert!(tx.execute("INSERT INTO authority_signing_deliveries SELECT org_id,project_id,job_id,grant_hash,?1,?2,?3 FROM authority_signing_outbox WHERE job_id=?4", params![hash(&hash_bytes(invented)).unwrap(),invented.as_slice(),NOW,job]).is_err());
    assert!(
        tx.execute(
            "DELETE FROM authority_signing_work_heads WHERE job_id=?",
            [&job]
        )
        .is_err()
    );
    tx.commit().unwrap();
    assert_eq!(f.count("authority_signing_work_events"), events);
    assert_eq!(f.count("authority_audit"), audits);
    f.reopen();
    let tx = f.store.connection.transaction().unwrap();
    let status = lifecycle_status(&tx, &f.tenant, &job, NOW).unwrap();
    assert_eq!(status.dispatch_state.as_deref(), Some("queued"));
    assert!(status.quota_held);
}

#[test]
fn event_sequence_guards_bind_renewal_to_exact_existing_claim_and_revision() {
    let (mut f, job) = prepared();
    let tx = f.store.connection.transaction().unwrap();
    fixture_claim(&tx, &f.tenant, &job, "signer", WORKER, 0, 60, NOW).unwrap();
    for (revision, generation, claim_hash, worker, until) in [
        (4u64, 1u64, None, None, NOW + 61),
        (3, 2, None, None, NOW + 61),
        (3, 1, Some(vec![0u8; 32]), None, NOW + 61),
        (
            3,
            1,
            None,
            Some("eeeeeeee-eeee-4eee-8eee-eeeeeeeeeeee"),
            NOW + 61,
        ),
        (3, 1, None, None, NOW + 60),
    ] {
        assert!(tx.execute("INSERT INTO authority_signing_work_events SELECT org_id,project_id,job_id,phase,'claimed',?1,?2,COALESCE(?3,claim_hash),COALESCE(?4,worker_id),?5,attempts,available_at,updated_at,'renewed' FROM authority_signing_work_heads WHERE job_id=?6 AND phase='signer'", params![revision.to_be_bytes().as_slice(),generation.to_be_bytes().as_slice(),claim_hash,worker,until,job]).is_err());
    }
    let saved = head(&tx, &f.tenant, &job, "signer").unwrap().unwrap();
    assert_eq!(saved.revision, 2);
    assert_eq!(saved.until, Some(NOW + 60));
    validate_work_histories(&tx).unwrap();
}

#[test]
fn replacement_cannot_delete_work_history_or_heads_through_hidden_rowid() {
    let (mut f, job) = prepared();
    let before = f.count("authority_signing_work_events");
    let mut db = forensic_connection(&f);
    let tx = db.transaction().unwrap();
    // All successor fields are valid. Only the explicit conflict with the old
    // event's hidden rowid attempts to erase the retained created event.
    assert!(tx.execute("INSERT OR REPLACE INTO authority_signing_work_events(rowid,org_id,project_id,job_id,phase,state,revision,claim_generation,claim_hash,worker_id,claim_until,attempts,available_at,updated_at,kind) SELECT rowid,org_id,project_id,job_id,phase,'claimed',?1,?2,?3,?4,?5,1,available_at,updated_at,'claimed' FROM authority_signing_work_events WHERE job_id=?6 AND phase='signer'", params![2u64.to_be_bytes().as_slice(),1u64.to_be_bytes().as_slice(),vec![1u8;32],WORKER,NOW+60,job]).is_err());
    assert!(tx.execute("INSERT OR REPLACE INTO authority_signing_work_heads SELECT * FROM authority_signing_work_heads WHERE job_id=?", [&job]).is_err());
    assert!(
        tx.execute(
            "UPDATE authority_signing_work_heads SET rowid=rowid+100 WHERE job_id=?",
            [&job]
        )
        .is_err()
    );
    tx.commit().unwrap();
    assert_eq!(f.count("authority_signing_work_events"), before);
    f.reopen();
    let tx = f.store.connection.transaction().unwrap();
    validate_work_histories(&tx).unwrap();
}

#[test]
fn restored_guards_do_not_hide_a_legacy_skipped_state_history() {
    let (mut f, job) = ready();
    migrations::legacy::restore_v10(&f.path);
    let mut db = forensic_connection(&f);
    let mut guards = Vec::new();
    for name in [
        "authority_signing_work_events_sequence",
        "authority_signing_work_heads_update",
    ] {
        let sql: String = db
            .query_row("SELECT sql FROM sqlite_schema WHERE name=?", [name], |r| {
                r.get(0)
            })
            .unwrap();
        guards.push(sql);
        db.execute_batch(&format!("DROP TRIGGER {name}")).unwrap();
    }
    db.execute("INSERT INTO authority_signing_work_events SELECT org_id,project_id,job_id,phase,'unknown',?1,claim_generation,NULL,NULL,NULL,attempts,available_at,updated_at,'unknown' FROM authority_signing_work_heads WHERE job_id=?2 AND phase='dispatch'", params![2u64.to_be_bytes().as_slice(),job]).unwrap();
    db.execute("UPDATE authority_signing_work_heads SET state='unknown',revision=?1 WHERE job_id=?2 AND phase='dispatch'", params![2u64.to_be_bytes().as_slice(),job]).unwrap();
    for guard in guards {
        db.execute_batch(&guard).unwrap();
    }
    assert_public_read_refused(&mut f, &job);
    let tx = db.transaction().unwrap();
    assert!(validate_work_histories(&tx).is_err());
    assert!(lifecycle_status(&tx, &f.tenant, &job, NOW).is_err());
}

#[test]
fn five_claims_with_thirty_two_renewals_each_fit_the_complete_history_bound() {
    let (mut f, job) = ready();
    let mut now = NOW;
    for attempt in 0..5 {
        f.store.observe_signing_quota_time(&f.tenant, now).unwrap();
        let tx = f.store.connection.transaction().unwrap();
        let mut claim =
            fixture_claim(&tx, &f.tenant, &job, "dispatch", WORKER, attempt, 1, now).unwrap();
        for lease in 2..=33 {
            claim = fixture_renew(&tx, &f.tenant, &claim, lease, now).unwrap();
        }
        assert!(fixture_renew(&tx, &f.tenant, &claim, 34, now).is_err());
        unknown_in_tx(&tx, &f.tenant, &claim, now).unwrap();
        now = head(&tx, &f.tenant, &job, "dispatch")
            .unwrap()
            .unwrap()
            .available;
        tx.commit().unwrap();
    }
    f.reopen();
    let tx = f.store.connection.transaction().unwrap();
    validate_work_histories(&tx).unwrap();
    let total: i64 = tx.query_row("SELECT count(*) FROM authority_signing_work_events WHERE job_id=? AND phase='dispatch'", [&job], |r| r.get(0)).unwrap();
    assert_eq!(total, 171);
    assert!(matches!(
        fixture_claim(&tx, &f.tenant, &job, "dispatch", WORKER, 5, 1, now),
        Err(AuthorityError::Quota)
    ));
    assert!(
        lifecycle_status(&tx, &f.tenant, &job, now)
            .unwrap()
            .quota_held
    );
}

#[test]
fn malformed_old_inactive_event_worker_is_not_erased_by_bounded_projection() {
    let (mut f, job) = prepared();
    let tx = f.store.connection.transaction().unwrap();
    fixture_claim(&tx, &f.tenant, &job, "signer", WORKER, 0, 60, NOW).unwrap();
    tx.commit().unwrap();
    let mut db = forensic_connection(&f);
    let guard: String = db.query_row(
        "SELECT sql FROM sqlite_schema WHERE name='authority_signing_work_events_immutable_update'",
        [], |r| r.get(0),
    ).unwrap();
    db.execute_batch("DROP TRIGGER authority_signing_work_events_immutable_update")
        .unwrap();
    db.execute(
        "UPDATE authority_signing_work_events SET worker_id=? WHERE job_id=? AND phase='signer' AND kind='created'",
        params!["x".repeat(37), job],
    ).unwrap();
    db.execute_batch(&guard).unwrap();
    assert_public_read_refused(&mut f, &job);
    let tx = db.transaction().unwrap();
    assert!(validate_work_histories(&tx).is_err());
    assert!(lifecycle_status(&tx, &f.tenant, &job, NOW).is_err());
}
