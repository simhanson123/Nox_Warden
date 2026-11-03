use super::super::signing_test_support::{Fixture, NOW};
use super::*;

const WORKER: &str = "dddddddd-dddd-4ddd-8ddd-dddddddddddd";

fn prepared() -> (Fixture, String) {
    let mut fixture = Fixture::new();
    let outcome = signing_intents::test_prepare(&mut fixture, NOW);
    (fixture, outcome.intent.job_id)
}

fn ready() -> (Fixture, String) {
    let (mut f, job) = prepared();
    let tx = f.store.connection.transaction().unwrap();
    let signer = fixture_claim(&tx, &f.tenant, &job, "signer", WORKER, 0, 60, NOW).unwrap();
    tx.commit().unwrap();
    signing_intents::test_finalize(&mut f, &signer, NOW).unwrap();
    (f, job)
}

fn snapshot(db: &Connection) -> Vec<Vec<Vec<rusqlite::types::Value>>> {
    let mut tables = vec![
        "authority_signing_work_events",
        "authority_signing_work_heads",
        "authority_signing_quota_reservations",
        "authority_signing_quota_transitions",
        "authority_signing_quota_transition_heads",
        "authority_signing_outbox",
        "authority_signing_deliveries",
        "authority_audit",
        "authority_audit_heads",
    ];
    if db.query_row("SELECT EXISTS(SELECT 1 FROM sqlite_schema WHERE name='authority_signing_work_audits' AND type='table')",[],|r|r.get::<_,bool>(0)).unwrap() {
        tables.push("authority_signing_work_audits");
    }
    tables
        .into_iter()
        .map(|table| table_rows(db, table))
        .collect()
}

fn table_rows(db: &Connection, table: &str) -> Vec<Vec<rusqlite::types::Value>> {
    let mut statement = db
        .prepare(&format!("SELECT rowid,* FROM {table} ORDER BY rowid"))
        .unwrap();
    let columns = statement.column_count();
    statement
        .query_map([], |r| (0..columns).map(|i| r.get(i)).collect())
        .unwrap()
        .collect::<rusqlite::Result<Vec<_>>>()
        .unwrap()
}

fn bind(
    tx: &Transaction<'_>,
    tenant: &AuthorityTenant,
    job: &str,
    phase: &str,
    revision: u64,
    kind: &str,
    now: i64,
) -> rusqlite::Result<usize> {
    tx.execute("INSERT INTO authority_signing_work_audits SELECT ?1,?2,?3,?4,?5,?6,?7,sequence,event_hash FROM authority_audit_heads WHERE org_id=?1 AND project_id=?2", params![tenant.org_id,tenant.project_id,job,phase,revision.to_be_bytes().as_slice(),kind,now])
}

fn raw_claim(tx: &Transaction<'_>, job: &str, worker: &str) -> rusqlite::Result<usize> {
    tx.execute("INSERT INTO authority_signing_work_events SELECT org_id,project_id,job_id,phase,'claimed',?1,?2,?3,?4,?5,1,available_at,updated_at,'claimed' FROM authority_signing_work_heads WHERE job_id=?6 AND phase='signer'", params![2u64.to_be_bytes().as_slice(),1u64.to_be_bytes().as_slice(),vec![1u8;32],worker,NOW+60,job])
}

#[test]
fn published_schema10_accepts_unaudited_cancel_but_upgrade_refuses_missing_evidence() {
    let (mut f, job) = prepared();
    migrations::legacy::restore_v10(&f.path);
    let audits = f.count("authority_audit");
    let tx = f.store.connection.transaction().unwrap();
    tx.execute("INSERT INTO authority_signing_work_events SELECT org_id,project_id,job_id,phase,'cancelled',?1,claim_generation,NULL,NULL,NULL,attempts,available_at,updated_at,'cancelled' FROM authority_signing_work_heads WHERE job_id=?2 AND phase='signer'", params![2u64.to_be_bytes().as_slice(),job]).unwrap();
    tx.execute("UPDATE authority_signing_work_heads SET state='cancelled',revision=?1 WHERE job_id=?2 AND phase='signer'", params![2u64.to_be_bytes().as_slice(),job]).unwrap();
    let intent = signing_intents::intent_at(
        &tx,
        &f.tenant,
        &signing_intents::job_at(&tx, &f.tenant, &job)
            .unwrap()
            .job()
            .intent_id,
    )
    .unwrap();
    signing_quota::cancel_unissued(&tx, &f.tenant, &intent.reservation_id, NOW).unwrap();
    tx.commit().unwrap();
    assert_eq!(f.count("authority_audit"), audits);
    let tx = f.store.connection.transaction().unwrap();
    assert_eq!(
        lifecycle_status(&tx, &f.tenant, &job, NOW).unwrap().state,
        "cancelled"
    );
    tx.commit().unwrap();
    let before = snapshot(&f.store.connection);
    let backup = f.directory.path().join("missing-audit-backup.sqlite3");
    assert!(AuthorityStore::migrate(&f.path, &backup).is_err());
    assert_eq!(snapshot(&f.store.connection), before);
    assert_eq!(snapshot(&Connection::open(backup).unwrap()), before);
    assert_eq!(
        f.store
            .connection
            .pragma_query_value(None, "user_version", |r| r.get::<_, i64>(0))
            .unwrap(),
        10
    );
}

#[test]
fn published_schema10_accepts_invalid_uuid_and_event_only_commit_but_upgrade_refuses() {
    let (mut f, job) = prepared();
    migrations::legacy::restore_v10(&f.path);
    f.store
        .connection
        .execute_batch("PRAGMA foreign_keys=ON; PRAGMA recursive_triggers=OFF")
        .unwrap();
    let tx = f.store.connection.transaction().unwrap();
    raw_claim(&tx, &job, &"x".repeat(36)).unwrap();
    tx.commit().unwrap();
    let tx = f.store.connection.transaction().unwrap();
    assert!(work_history(&tx, &f.tenant, &job, "signer").is_err());
    assert_eq!(
        tx.query_row::<i64, _, _>(
            "SELECT count(*) FROM authority_signing_work_events WHERE job_id=?",
            [&job],
            |r| r.get(0)
        )
        .unwrap(),
        2
    );
    tx.commit().unwrap();
    let before = snapshot(&f.store.connection);
    let backup = f.directory.path().join("invalid-worker-backup.sqlite3");
    assert!(AuthorityStore::migrate(&f.path, &backup).is_err());
    assert_eq!(snapshot(&f.store.connection), before);
    assert_eq!(snapshot(&Connection::open(backup).unwrap()), before);
}

#[test]
fn direct_cancel_and_delivery_without_bound_audit_preserve_every_retained_row() {
    for delivered in [false, true] {
        let (mut f, job) = if delivered { ready() } else { prepared() };
        if delivered {
            let tx = f.store.connection.transaction().unwrap();
            fixture_claim(&tx, &f.tenant, &job, "dispatch", WORKER, 0, 60, NOW).unwrap();
            tx.commit().unwrap();
        }
        f.store
            .connection
            .execute_batch("PRAGMA foreign_keys=ON; PRAGMA recursive_triggers=OFF")
            .unwrap();
        let before = snapshot(&f.store.connection);
        let tx = f.store.connection.transaction().unwrap();
        if delivered {
            let result = b"diagnostic delivery";
            tx.execute("INSERT INTO authority_signing_deliveries SELECT org_id,project_id,job_id,grant_hash,?1,?2,?3 FROM authority_signing_outbox WHERE job_id=?4",params![hash(&hash_bytes(result)).unwrap(),result.as_slice(),NOW,job]).unwrap();
        }
        let (phase, state, kind, revision) = if delivered {
            ("dispatch", "delivered", "delivered", 3u64)
        } else {
            ("signer", "cancelled", "cancelled", 2)
        };
        assert!(tx.execute("INSERT INTO authority_signing_work_events SELECT org_id,project_id,job_id,phase,?1,?2,claim_generation,NULL,NULL,NULL,attempts,available_at,updated_at,?3 FROM authority_signing_work_heads WHERE job_id=?4 AND phase=?5",params![state,revision.to_be_bytes().as_slice(),kind,job,phase]).is_err());
        tx.rollback().unwrap();
        assert_eq!(snapshot(&f.store.connection), before);
        f.reopen();
        assert_eq!(snapshot(&f.store.connection), before);
        let tx = f.store.connection.transaction().unwrap();
        let status = lifecycle_status(&tx, &f.tenant, &job, NOW).unwrap();
        assert!(status.quota_held);
        assert_ne!(status.state, "cancelled");
        assert_ne!(status.dispatch_state.as_deref(), Some("delivered"));
    }
}

#[test]
fn work_audit_binding_requires_exact_tenant_job_phase_revision_kind_time_and_one_use() {
    let (mut f, job) = prepared();
    let tx = f.store.connection.transaction().unwrap();
    audit(&tx, &f.tenant, "signing_signer_claimed", &job, NOW).unwrap();
    for (candidate_job, phase, revision, kind, now) in [
        (
            "eeeeeeee-eeee-4eee-8eee-eeeeeeeeeeee",
            "signer",
            2,
            "claimed",
            NOW,
        ),
        (job.as_str(), "dispatch", 2, "claimed", NOW),
        (job.as_str(), "signer", 3, "claimed", NOW),
        (job.as_str(), "signer", 2, "cancelled", NOW),
        (job.as_str(), "signer", 2, "claimed", NOW + 1),
    ] {
        assert!(bind(&tx, &f.tenant, candidate_job, phase, revision, kind, now).is_err());
    }
    assert!(tx.execute("INSERT INTO authority_signing_work_audits SELECT ?1,project_id,?2,'signer',?3,'claimed',?4,sequence,event_hash FROM authority_audit_heads WHERE org_id=?5 AND project_id=?6",params!["eeeeeeee-eeee-4eee-8eee-eeeeeeeeeeee",job,2u64.to_be_bytes().as_slice(),NOW,f.tenant.org_id,f.tenant.project_id]).is_err());
    bind(&tx, &f.tenant, &job, "signer", 2, "claimed", NOW).unwrap();
    raw_claim(&tx, &job, WORKER).unwrap();
    assert!(bind(&tx, &f.tenant, &job, "signer", 3, "claimed", NOW).is_err());
    tx.commit().unwrap();
    f.reopen();
    let tx = f.store.connection.transaction().unwrap();
    validate_work_histories(&tx).unwrap();
}

#[test]
fn canonical_worker_uuid_sql_matches_rust_and_event_only_statement_projects_head() {
    let (mut f, job) = prepared();
    f.store
        .connection
        .execute_batch("PRAGMA foreign_keys=ON; PRAGMA recursive_triggers=OFF")
        .unwrap();
    let mut workers = vec![
        WORKER.to_owned(),
        "00000000-0000-0000-0000-000000000000".into(),
        "ffffffff-ffff-ffff-ffff-ffffffffffff".into(),
        WORKER.to_uppercase(),
        "x".repeat(36),
        "é".repeat(36),
        format!("{}é", &WORKER[..34]),
        format!("{}\0", &WORKER[..35]),
    ];
    for position in [8, 13, 18, 23] {
        let mut changed = WORKER.to_owned();
        changed.replace_range(position..=position, "0");
        workers.push(changed);
    }
    for position in (0..36).filter(|position| ![8, 13, 18, 23].contains(position)) {
        let mut changed = WORKER.to_owned();
        changed.replace_range(position..=position, "-");
        workers.push(changed);
    }
    for worker in workers {
        let tx = f.store.connection.transaction().unwrap();
        audit(&tx, &f.tenant, "signing_signer_claimed", &job, NOW).unwrap();
        bind(&tx, &f.tenant, &job, "signer", 2, "claimed", NOW).unwrap();
        assert_eq!(
            raw_claim(&tx, &job, &worker).is_ok(),
            identifier(&worker).is_ok(),
            "{worker:?}"
        );
        tx.rollback().unwrap();
    }
    let audits = f.count("authority_audit");
    let tx = f.store.connection.transaction().unwrap();
    audit(&tx, &f.tenant, "signing_signer_claimed", &job, NOW).unwrap();
    bind(&tx, &f.tenant, &job, "signer", 2, "claimed", NOW).unwrap();
    raw_claim(&tx, &job, WORKER).unwrap();
    tx.commit().unwrap();
    assert_eq!(f.count("authority_audit"), audits + 1);
    f.reopen();
    let tx = f.store.connection.transaction().unwrap();
    assert_eq!(
        head(&tx, &f.tenant, &job, "signer")
            .unwrap()
            .unwrap()
            .revision,
        2
    );
    validate_work_histories(&tx).unwrap();
}

#[test]
fn signer_renew_retry_cancel_and_exact_noops_each_retain_one_audit_per_mutation() {
    let (mut f, job) = prepared();
    let tx = f.store.connection.transaction().unwrap();
    let claim = fixture_claim(&tx, &f.tenant, &job, "signer", WORKER, 0, 10, NOW).unwrap();
    let claim = fixture_renew(&tx, &f.tenant, &claim, 11, NOW).unwrap();
    let before: i64 = tx
        .query_row("SELECT count(*) FROM authority_audit", [], |r| r.get(0))
        .unwrap();
    fixture_renew(&tx, &f.tenant, &claim, 11, NOW).unwrap();
    assert_eq!(
        tx.query_row::<i64, _, _>("SELECT count(*) FROM authority_audit", [], |r| r.get(0))
            .unwrap(),
        before
    );
    retry_in_tx(&tx, &f.tenant, &claim, NOW).unwrap();
    cancel_in_tx(&tx, &f.tenant, &job, NOW).unwrap();
    let before: i64 = tx
        .query_row("SELECT count(*) FROM authority_audit", [], |r| r.get(0))
        .unwrap();
    cancel_in_tx(&tx, &f.tenant, &job, NOW).unwrap();
    assert_eq!(
        tx.query_row::<i64, _, _>("SELECT count(*) FROM authority_audit", [], |r| r.get(0))
            .unwrap(),
        before
    );
    tx.commit().unwrap();
    let audits:i64=f.store.connection.query_row("SELECT count(*) FROM authority_audit WHERE resource_id=? AND kind GLOB 'signing_signer_*'",[&job],|r|r.get(0)).unwrap();
    assert_eq!(f.count("authority_signing_work_events"), audits);
    assert_eq!(f.count("authority_signing_work_audits"), audits);
    f.reopen();
    let tx = f.store.connection.transaction().unwrap();
    validate_work_histories(&tx).unwrap();
    assert!(
        !lifecycle_status(&tx, &f.tenant, &job, NOW)
            .unwrap()
            .quota_held
    );
}

#[test]
fn unconsumed_binding_cannot_commit_and_projection_failure_rolls_back_all_mutations() {
    let (mut f, job) = prepared();
    let before = snapshot(&f.store.connection);
    let tx = f.store.connection.transaction().unwrap();
    audit(&tx, &f.tenant, "signing_signer_claimed", &job, NOW).unwrap();
    bind(&tx, &f.tenant, &job, "signer", 2, "claimed", NOW).unwrap();
    assert!(tx.commit().is_err());
    assert_eq!(snapshot(&f.store.connection), before);
    for target in [
        "authority_signing_work_events",
        "authority_signing_work_heads",
    ] {
        let tx = f.store.connection.transaction().unwrap();
        audit(&tx, &f.tenant, "signing_signer_claimed", &job, NOW).unwrap();
        bind(&tx, &f.tenant, &job, "signer", 2, "claimed", NOW).unwrap();
        let timing = if target == "authority_signing_work_events" {
            "INSERT"
        } else {
            "UPDATE"
        };
        // Install after the audit's live-schema check, so the failure actually
        // occurs during event insertion or its AFTER-trigger head projection.
        tx.execute_batch(&format!("CREATE TRIGGER fixture_fail BEFORE {timing} ON {target} BEGIN SELECT RAISE(ABORT,'fixture failure'); END;")).unwrap();
        let error = raw_claim(&tx, &job, WORKER).unwrap_err();
        assert!(error.to_string().contains("fixture failure"));
        assert_eq!(
            tx.query_row::<i64, _, _>(
                "SELECT count(*) FROM authority_signing_work_events WHERE job_id=?",
                [&job],
                |r| r.get(0)
            )
            .unwrap(),
            1
        );
        tx.rollback().unwrap();
        assert_eq!(snapshot(&f.store.connection), before);
    }
    use rusqlite::hooks::{AuthAction, AuthContext, Authorization};
    let hit = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
    let observed = hit.clone();
    f.store
        .connection
        .authorizer(Some(move |context: AuthContext<'_>| {
            if matches!(
                context.action,
                AuthAction::Update {
                    table_name: "authority_audit_heads",
                    ..
                }
            ) {
                observed.store(true, std::sync::atomic::Ordering::SeqCst);
                Authorization::Deny
            } else {
                Authorization::Allow
            }
        }));
    let tx = f.store.connection.transaction().unwrap();
    assert!(fixture_claim(&tx, &f.tenant, &job, "signer", WORKER, 0, 60, NOW).is_err());
    tx.rollback().unwrap();
    f.store
        .connection
        .authorizer(None::<fn(AuthContext<'_>) -> Authorization>);
    assert!(hit.load(std::sync::atomic::Ordering::SeqCst));
    assert_eq!(snapshot(&f.store.connection), before);
}

#[test]
fn actual_mutations_have_one_audit_and_exact_retries_have_none_after_unknown_delivery_reopen() {
    let (mut f, job) = ready();
    let tx = f.store.connection.transaction().unwrap();
    let claim = fixture_claim(&tx, &f.tenant, &job, "dispatch", WORKER, 0, 60, NOW).unwrap();
    unknown_in_tx(&tx, &f.tenant, &claim, NOW).unwrap();
    let later = head(&tx, &f.tenant, &job, "dispatch")
        .unwrap()
        .unwrap()
        .available;
    tx.commit().unwrap();
    f.store
        .observe_signing_quota_time(&f.tenant, later)
        .unwrap();
    let tx = f.store.connection.transaction().unwrap();
    let claim = fixture_claim(&tx, &f.tenant, &job, "dispatch", WORKER, 1, 60, later).unwrap();
    fixture_deliver(&tx, &f.tenant, &claim, later).unwrap();
    tx.commit().unwrap();
    let before = snapshot(&f.store.connection);
    let tx = f.store.connection.transaction().unwrap();
    fixture_deliver(&tx, &f.tenant, &claim, later + 1).unwrap();
    tx.commit().unwrap();
    assert_eq!(snapshot(&f.store.connection), before);
    let events = f.count("authority_signing_work_events");
    let links = f.count("authority_signing_work_audits");
    let audit_events:i64=f.store.connection.query_row("SELECT count(*) FROM authority_audit WHERE resource_id=? AND kind GLOB 'signing_signer_*' OR resource_id=? AND kind GLOB 'signing_dispatch_*'",params![job,job],|r|r.get(0)).unwrap();
    assert_eq!(events, links);
    assert_eq!(events, audit_events);
    f.reopen();
    let tx = f.store.connection.transaction().unwrap();
    assert!(dispatch_unknown_seen(&tx, &f.tenant, &job).unwrap());
    let status = lifecycle_status(&tx, &f.tenant, &job, later + 7200).unwrap();
    assert_eq!(status.dispatch_state.as_deref(), Some("delivered"));
    assert!(status.quota_held);
    let intent = signing_intents::intent_at(
        &tx,
        &f.tenant,
        &signing_intents::job_at(&tx, &f.tenant, &job)
            .unwrap()
            .job()
            .intent_id,
    )
    .unwrap();
    assert_eq!(
        signing_quota::read(&tx, &f.tenant, &intent.reservation_id)
            .unwrap()
            .effective_dispatch_slots(),
        1
    );
    tx.commit().unwrap();
    let status = f
        .store
        .signing_readiness_v2(
            &f.tenant,
            super::super::signing_test_support::native::PLAN,
            &f.verifier,
            later + 1,
        )
        .unwrap();
    assert_eq!(status.latest_dispatch_unknown_seen, Some(true));
    assert!(!status.snapshot.signing_allowed);
    assert!(!status.snapshot.dispatch_allowed);
}

#[test]
fn ambiguous_legacy_same_time_renewals_are_refused_without_rewriting_evidence() {
    let (mut f, job) = prepared();
    let tx = f.store.connection.transaction().unwrap();
    let claim = fixture_claim(&tx, &f.tenant, &job, "signer", WORKER, 0, 10, NOW).unwrap();
    let claim = fixture_renew(&tx, &f.tenant, &claim, 11, NOW).unwrap();
    fixture_renew(&tx, &f.tenant, &claim, 12, NOW).unwrap();
    tx.commit().unwrap();
    migrations::legacy::restore_v10(&f.path);
    let before = snapshot(&f.store.connection);
    let backup = f.directory.path().join("ambiguous-audit-backup.sqlite3");
    assert!(AuthorityStore::migrate(&f.path, &backup).is_err());
    assert_eq!(snapshot(&f.store.connection), before);
    assert_eq!(snapshot(&Connection::open(backup).unwrap()), before);
}

#[test]
fn missing_or_mismatched_work_audit_links_fail_startup_scoped_reads_and_admission() {
    for damage in ["missing", "kind", "time", "audit"] {
        let (mut f, job) = prepared();
        f.store
            .connection
            .execute_batch("PRAGMA foreign_keys=ON; PRAGMA recursive_triggers=OFF")
            .unwrap();
        let reservation: String = f
            .store
            .connection
            .query_row(
                "SELECT reservation_id FROM authority_signing_intents WHERE job_id=?",
                [&job],
                |r| r.get(0),
            )
            .unwrap();
        let tx = f.store.connection.transaction().unwrap();
        let saved = signing_quota::read(&tx, &f.tenant, &reservation).unwrap();
        assert!(saved.held());
        let cost =
            signing_quota::cost_for_plan(&tx, &f.tenant, f.plan["plan_id"].as_str().unwrap(), NOW)
                .unwrap();
        // Default genuine fixture limits leave spare capacity. Refusal below
        // must come from lost evidence rather than an already full bucket.
        signing_quota::reserve(&tx, &f.tenant, &new_id().unwrap(), &cost, NOW + 300, NOW).unwrap();
        tx.rollback().unwrap();
        assert_eq!(
            f.count("authority_signing_work_events"),
            f.count("authority_signing_work_audits")
        );
        let audit_rows = table_rows(&f.store.connection, "authority_audit");
        let events = table_rows(&f.store.connection, "authority_signing_work_events");
        let guard = if damage == "missing" {
            "authority_signing_work_audits_immutable_delete"
        } else {
            "authority_signing_work_audits_immutable_update"
        };
        let definition: String = f
            .store
            .connection
            .query_row(
                "SELECT sql FROM sqlite_schema WHERE type='trigger' AND name=?",
                [guard],
                |r| r.get(0),
            )
            .unwrap();
        f.store
            .connection
            .execute_batch(&format!("DROP TRIGGER {guard}"))
            .unwrap();
        match damage {
            "missing" => {
                assert_eq!(
                    f.store
                        .connection
                        .execute(
                            "DELETE FROM authority_signing_work_audits WHERE job_id=?",
                            [&job]
                        )
                        .unwrap(),
                    1
                );
            }
            "kind" => {
                assert_eq!(f.store.connection.execute("UPDATE authority_signing_work_audits SET kind='claimed' WHERE job_id=?",[&job]).unwrap(),1);
            }
            "time" => {
                assert_eq!(f.store.connection.execute("UPDATE authority_signing_work_audits SET updated_at=updated_at+1 WHERE job_id=?",[&job]).unwrap(),1);
            }
            "audit" => {
                // Use a real, retained, unbound audit from this same tenant.
                // Its FK and canonical hash are intact; it describes a
                // different mutation and cannot replace this event's evidence.
                let other:(Vec<u8>,Vec<u8>)=f.store.connection.query_row("SELECT a.sequence,a.event_hash FROM authority_audit a WHERE a.org_id=?1 AND a.project_id=?2 AND NOT EXISTS(SELECT 1 FROM authority_signing_work_audits b WHERE b.org_id=a.org_id AND b.project_id=a.project_id AND b.audit_sequence=a.sequence) ORDER BY a.sequence DESC LIMIT 1",params![f.tenant.org_id,f.tenant.project_id],|r|Ok((r.get(0)?,r.get(1)?))).unwrap();
                assert_eq!(f.store.connection.execute("UPDATE authority_signing_work_audits SET audit_sequence=?,audit_hash=? WHERE job_id=?",params![other.0,other.1,job]).unwrap(),1);
            }
            _ => unreachable!(),
        }
        f.store.connection.execute_batch(&definition).unwrap();
        assert!(
            !f.store
                .connection
                .query_row::<bool, _, _>(
                    "SELECT EXISTS(SELECT 1 FROM pragma_foreign_key_check)",
                    [],
                    |r| r.get(0)
                )
                .unwrap()
        );
        assert_eq!(
            table_rows(&f.store.connection, "authority_audit"),
            audit_rows
        );
        assert_eq!(
            table_rows(&f.store.connection, "authority_signing_work_events"),
            events
        );
        let damaged = snapshot(&f.store.connection);
        let tx = f.store.connection.transaction().unwrap();
        assert!(
            work_history(&tx, &f.tenant, &job, "signer").is_err(),
            "{damage}"
        );
        assert!(
            matches!(
                signing_quota::read(&tx, &f.tenant, &reservation),
                Err(AuthorityError::Invalid(_))
            ),
            "read {damage}"
        );
        assert!(
            matches!(
                signing_quota::reserve(&tx, &f.tenant, &new_id().unwrap(), &cost, NOW + 300, NOW),
                Err(AuthorityError::Invalid(_))
            ),
            "reserve {damage}"
        );
        tx.rollback().unwrap();
        assert!(AuthorityStore::open(&f.path).is_err(), "open {damage}");
        let backup = f.directory.path().join("current-rejected-backup.sqlite3");
        assert!(
            AuthorityStore::migrate(&f.path, &backup).is_err(),
            "maintenance {damage}"
        );
        assert!(!backup.exists());
        assert_eq!(snapshot(&f.store.connection), damaged);
    }
}
