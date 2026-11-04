// Real signed lifecycle fixtures with project-only policy accounting. These
// test capabilities never open the production signing or dispatch resolver.
use super::*;

const WORKER: &str = "dddddddd-dddd-4ddd-8ddd-dddddddddddd";
const ROOT: &str = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa";

fn rows(db: &Connection, table: &str) -> Vec<Vec<rusqlite::types::Value>> {
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

fn snapshot(db: &Connection) -> Vec<Vec<Vec<rusqlite::types::Value>>> {
    [
        "authority_signing_quota_reservations",
        "authority_signing_quota_transitions",
        "authority_signing_quota_transition_heads",
        "authority_signing_work_events",
        "authority_signing_work_heads",
        "authority_signing_work_audits",
        "authority_signing_results",
        "authority_signing_outbox",
        "authority_signing_deliveries",
        "authority_audit",
        "authority_audit_heads",
    ]
    .into_iter()
    .map(|table| rows(db, table))
    .collect()
}

fn project_pin(cap: i64) -> SigningProjectQuotaPin {
    let mut limits = limits();
    limits.concurrent_deployments = cap;
    SigningProjectQuotaPin {
        root_id: None,
        limits,
        not_before: NOW,
        not_after: NOW + 7200,
    }
}

fn rootless(cap: i64) -> (signing_test_support::Fixture, String, String) {
    let mut f = signing_test_support::Fixture::new();
    f.store
        .pin_signing_project_quota(&f.tenant, &project_pin(cap), None, NOW)
        .unwrap();
    let prepared = signing_intents::test_prepare(&mut f, NOW);
    assert_eq!(
        f.store
            .connection
            .query_row::<i64, _, _>(
                "SELECT count(*) FROM authority_signing_quota_pins WHERE bucket_kind='root'",
                [],
                |r| r.get(0)
            )
            .unwrap(),
        0
    );
    let job = prepared.intent.job_id;
    let reservation = prepared.intent.reservation_id;
    let tx = f.store.connection.transaction().unwrap();
    let saved = read(&tx, &f.tenant, &reservation).unwrap();
    assert_eq!(saved.schema_version, "fw.signing-budget-reservation/v2");
    assert!(saved.root_id.is_none());
    assert!(saved.root_revision.is_none());
    assert!(saved.root_pin_hash.is_none());
    assert!(saved.root_projected.is_none());
    assert_eq!(saved.active_slots, 0);
    assert_eq!(saved.cost.lease_seconds, 0);
    assert!(saved.cost.lease_id.is_none());
    assert!(saved.cost.destination_asset_ids.is_empty());
    tx.commit().unwrap();
    (f, job, reservation)
}

fn issue(f: &mut signing_test_support::Fixture, job: &str, now: i64) -> signing_jobs::SigningClaim {
    let tx = f.store.connection.transaction().unwrap();
    let claim =
        signing_jobs::fixture_claim(&tx, &f.tenant, job, "signer", WORKER, 0, 60, now).unwrap();
    tx.commit().unwrap();
    signing_intents::test_finalize(f, &claim, now).unwrap();
    claim
}

fn dispatch(
    f: &mut signing_test_support::Fixture,
    job: &str,
    unknown: bool,
    delivered: bool,
) -> i64 {
    let tx = f.store.connection.transaction().unwrap();
    let mut claim =
        signing_jobs::fixture_claim(&tx, &f.tenant, job, "dispatch", WORKER, 0, 60, NOW).unwrap();
    let mut now = NOW;
    if unknown {
        signing_jobs::fixture_unknown(&tx, &f.tenant, &claim, now).unwrap();
        if delivered {
            now=tx.query_row("SELECT available_at FROM authority_signing_work_heads WHERE job_id=? AND phase='dispatch'",[job],|r|r.get(0)).unwrap();
            claim =
                signing_jobs::fixture_claim(&tx, &f.tenant, job, "dispatch", WORKER, 1, 60, now)
                    .unwrap();
        }
    }
    if delivered {
        signing_jobs::fixture_deliver(&tx, &f.tenant, &claim, now).unwrap();
    }
    tx.commit().unwrap();
    now
}

fn assert_project_capacity(
    f: &mut signing_test_support::Fixture,
    reservation: &str,
    now: i64,
    expected: i64,
    cap: i64,
) {
    let tx = f.store.connection.transaction().unwrap();
    let saved = read(&tx, &f.tenant, reservation).unwrap();
    assert!(saved.held());
    assert_eq!(saved.effective_dispatch_slots(), 1);
    let usage = account(&tx, &f.tenant, AccountingScope::Project, now, None).unwrap();
    assert_eq!(usage.concurrent_deployments, expected);
    let prospective = account(
        &tx,
        &f.tenant,
        AccountingScope::Project,
        now,
        Some(&change(900)),
    )
    .unwrap();
    let mut limits = limits();
    limits.concurrent_deployments = cap;
    assert!(matches!(
        prospective.within(&limits),
        Err(AuthorityError::Quota)
    ));
}

#[test]
fn real_rootless_issued_unknown_and_unsigned_delivery_hold_capacity_after_expiry_reopen_and_day_window()
 {
    for state in ["issued", "unknown", "active", "unknown_then_active"] {
        let (mut f, job, reservation) = rootless(1);
        issue(&mut f, &job, NOW);
        let now = if state == "issued" {
            NOW
        } else {
            dispatch(
                &mut f,
                &job,
                state.starts_with("unknown"),
                state.ends_with("active"),
            )
        };
        assert!(f.store.cancel_signing_job(&f.tenant, &job, now).is_err());
        let original = snapshot(&f.store.connection);
        for observed in [now, NOW + 301, NOW + 86_401] {
            assert_project_capacity(&mut f, &reservation, observed, 1, 1);
            f.reopen();
            assert_project_capacity(&mut f, &reservation, observed, 1, 1);
            let tx = f.store.connection.transaction().unwrap();
            let status = signing_jobs::lifecycle_status(&tx, &f.tenant, &job, observed).unwrap();
            assert!(status.quota_held);
            assert_eq!(
                status.dispatch_state.as_deref(),
                Some(match state {
                    "issued" => "queued",
                    "unknown" => "unknown",
                    _ => "delivered",
                })
            );
            if state.starts_with("unknown") {
                assert!(signing_jobs::dispatch_unknown_seen(&tx, &f.tenant, &job).unwrap());
            }
            tx.commit().unwrap();
            assert_eq!(snapshot(&f.store.connection), original);
        }
        // Current pins and a prospective policy cannot obtain capacity even
        // before expiry. Later account checks isolate the retained slot
        // from the separately expiring approval/pin admission preconditions.
        let tx = f.store.connection.transaction().unwrap();
        assert!(matches!(
            reserve(
                &tx,
                &f.tenant,
                &new_id().unwrap(),
                &change(901),
                NOW + 300,
                now
            ),
            Err(AuthorityError::Quota)
        ));
    }
}

#[test]
fn genuine_unissued_rootless_cancellation_releases_once_with_retained_audit_and_genesis() {
    let (mut f, job, reservation) = rootless(1);
    f.store.cancel_signing_job(&f.tenant, &job, NOW).unwrap();
    let original = snapshot(&f.store.connection);
    f.store
        .cancel_signing_job(&f.tenant, &job, NOW + 1)
        .unwrap();
    assert_eq!(snapshot(&f.store.connection), original);
    f.reopen();
    let tx = f.store.connection.transaction().unwrap();
    let saved = read(&tx, &f.tenant, &reservation).unwrap();
    assert_eq!(saved.state, "released");
    assert!(saved.issued_at.is_none());
    assert!(!saved.held());
    assert_eq!(
        account(&tx, &f.tenant, AccountingScope::Project, NOW + 86_401, None)
            .unwrap()
            .concurrent_deployments,
        0
    );
    assert_eq!(
        tx.query_row::<i64, _, _>(
            "SELECT count(*) FROM authority_signing_work_audits WHERE job_id=?",
            [&job],
            |r| r.get(0)
        )
        .unwrap(),
        2
    );
    assert_eq!(
        tx.query_row::<i64, _, _>(
            "SELECT count(*) FROM authority_signing_quota_transitions WHERE reservation_id=?",
            [&reservation],
            |r| r.get(0)
        )
        .unwrap(),
        2
    );
}

fn next_plan(f: &mut signing_test_support::Fixture, now: i64) {
    let mut next = f.plan.clone();
    next["plan_id"] = new_id().unwrap().into();
    next["target_generation"] = "2".into();
    let next_id = next["plan_id"].as_str().unwrap().to_owned();
    f.store
        .register_reviewed_plan(&f.tenant, &next, &f.requirements, &f.review, now)
        .unwrap();
    f.store
        .register_native_compilation(&f.tenant, &next_id, 1, now)
        .unwrap();
    let compiled = fw_native_evidence::compile_evidence(&next, &f.review, &f.references).unwrap();
    let installation = signing_test_support::native::installation(compiled.baseline(), now);
    let challenge = f
        .store
        .challenge_native_observation(
            &f.tenant,
            &next_id,
            fw_native_evidence::ArtifactRole::Baseline,
            &installation,
            Some(&f.baseline_receipt_hash),
            1,
            2,
            now,
        )
        .unwrap();
    let proof = signing_test_support::native::proof(
        &challenge,
        installation.clone(),
        signing_test_support::native::snapshot(&installation.native),
        now,
    );
    let observation = f
        .store
        .admit_native_observation(&f.tenant, &proof, now)
        .unwrap();
    f.plan = next;
    f.baseline_receipt_hash = observation.receipt_hash;
    f.current_approval_hash = f.approve(&next_id, now);
}

#[test]
fn genuine_rooted_v1_and_rootless_v2_share_capacity_without_resetting_historical_root_membership() {
    let mut f = signing_test_support::Fixture::new();
    let first = signing_intents::test_prepare(&mut f, NOW);
    let first_intent = first.intent.intent_id.clone();
    let first_plan = f.plan["plan_id"].as_str().unwrap().to_owned();
    let tx = f.store.connection.transaction().unwrap();
    let original_request = signing_intents::intent_at(&tx, &f.tenant, &first_intent)
        .unwrap()
        .request;
    tx.commit().unwrap();
    let rooted = first.intent.reservation_id;
    let first_job = first.intent.job_id;
    let original_claim = issue(&mut f, &first_job, NOW);
    let original_result = signing_intents::test_sign(&mut f, &first_intent, NOW);
    dispatch(&mut f, &first_job, false, true);
    let rooted_bytes:Vec<u8>=f.store.connection.query_row("SELECT snapshot_bytes FROM authority_signing_quota_reservations WHERE reservation_id=?",[&rooted],|r|r.get(0)).unwrap();
    next_plan(&mut f, NOW + 1);
    f.store
        .pin_signing_project_quota(&f.tenant, &project_pin(2), Some(1), NOW + 1)
        .unwrap();
    let second = signing_intents::test_prepare(&mut f, NOW + 1);
    let rootless = second.intent.reservation_id;
    let second_job = second.intent.job_id;
    issue(&mut f, &second_job, NOW + 1);
    let tx = f.store.connection.transaction().unwrap();
    let claim = signing_jobs::fixture_claim(
        &tx,
        &f.tenant,
        &second_job,
        "dispatch",
        WORKER,
        0,
        60,
        NOW + 1,
    )
    .unwrap();
    signing_jobs::fixture_unknown(&tx, &f.tenant, &claim, NOW + 1).unwrap();
    tx.commit().unwrap();
    let original = snapshot(&f.store.connection);
    for now in [NOW + 1, NOW + 301, NOW + 86_401] {
        assert_project_capacity(&mut f, &rootless, now, 2, 2);
        let tx = f.store.connection.transaction().unwrap();
        let root_usage = account(&tx, &f.tenant, AccountingScope::Root(ROOT), now, None).unwrap();
        assert_eq!(root_usage.concurrent_deployments, 1);
        let rooted_saved = read(&tx, &f.tenant, &rooted).unwrap();
        let rootless_saved = read(&tx, &f.tenant, &rootless).unwrap();
        assert_eq!(
            rooted_saved.schema_version,
            "fw.signing-budget-reservation/v1"
        );
        assert_eq!(rooted_saved.root_id.as_deref(), Some(ROOT));
        assert_eq!(
            rootless_saved.schema_version,
            "fw.signing-budget-reservation/v2"
        );
        assert!(rootless_saved.root_id.is_none());
        for (reservation, root) in [(&rooted, None), (&rootless, Some(ROOT))] {
            assert!(tx.execute("UPDATE authority_signing_quota_transition_heads SET root_id=? WHERE reservation_id=?",params![root,reservation]).is_err());
            assert!(tx.execute("INSERT OR REPLACE INTO authority_signing_quota_transition_heads SELECT * FROM authority_signing_quota_transition_heads WHERE reservation_id=?",[reservation]).is_err());
            assert!(tx.execute("UPDATE OR REPLACE authority_signing_quota_transition_heads SET rowid=rowid+100 WHERE reservation_id=?",[reservation]).is_err());
        }
        tx.commit().unwrap();
        f.reopen();
        assert_eq!(snapshot(&f.store.connection), original);
        assert_eq!(f.store.connection.query_row::<Vec<u8>,_,_>("SELECT snapshot_bytes FROM authority_signing_quota_reservations WHERE reservation_id=?",[&rooted],|r|r.get(0)).unwrap(),rooted_bytes);
    }
    // A refused old rooted worker still advances that retained root's clock
    // after project cutover; project-only observations cannot reset it.
    assert!(
        f.store
            .claim_signing_dispatch(&f.tenant, &first_job, WORKER, 0, 60, NOW + 1000)
            .is_err()
    );
    assert_eq!(f.store.connection.query_row::<i64,_,_>("SELECT observed_at FROM authority_signing_quota_clocks WHERE org_id=? AND bucket_kind='root' AND bucket_id=?",params![f.tenant.org_id,ROOT],|r|r.get(0)).unwrap(),NOW+1000);
    assert!(
        f.store
            .read_signing_intent(&f.tenant, &first_intent, NOW + 1001)
            .unwrap()
            .is_some()
    );
    assert_eq!(f.store.connection.query_row::<i64,_,_>("SELECT observed_at FROM authority_signing_quota_clocks WHERE org_id=? AND bucket_kind='root' AND bucket_id=?",params![f.tenant.org_id,ROOT],|r|r.get(0)).unwrap(),NOW+1001);
    let readiness = f
        .store
        .signing_readiness_v2(&f.tenant, &first_plan, &f.verifier, NOW + 1002)
        .unwrap();
    assert!(!readiness.snapshot.signing_allowed);
    assert!(!readiness.snapshot.dispatch_allowed);
    assert_eq!(f.store.connection.query_row::<i64,_,_>("SELECT observed_at FROM authority_signing_quota_clocks WHERE org_id=? AND bucket_kind='root' AND bucket_id=?",params![f.tenant.org_id,ROOT],|r|r.get(0)).unwrap(),NOW+1002);
    assert!(
        f.store
            .prepare_signing_intent(&f.tenant, &f.verifier, &original_request, NOW + 1003)
            .is_err()
    );
    assert_eq!(f.store.connection.query_row::<i64,_,_>("SELECT observed_at FROM authority_signing_quota_clocks WHERE org_id=? AND bucket_kind='root' AND bucket_id=?",params![f.tenant.org_id,ROOT],|r|r.get(0)).unwrap(),NOW+1003);
    assert!(
        f.store
            .finalize_signing_intent(
                &f.tenant,
                &f.verifier,
                &original_claim,
                &original_result,
                NOW + 1004
            )
            .is_err()
    );
    assert_eq!(f.store.connection.query_row::<i64,_,_>("SELECT observed_at FROM authority_signing_quota_clocks WHERE org_id=? AND bucket_kind='root' AND bucket_id=?",params![f.tenant.org_id,ROOT],|r|r.get(0)).unwrap(),NOW+1004);
    f.reopen();
    assert!(matches!(
        f.store
            .observe_signing_job_quota_time(&f.tenant, &first_job, NOW + 1003),
        Err(AuthorityError::Time)
    ));
    assert_eq!(snapshot(&f.store.connection), original);
}

#[test]
fn rootless_reserve_and_real_finalize_refuse_every_missing_or_replaced_live_guard() {
    let (mut f, job, reservation) = rootless(2);
    let tx = f.store.connection.transaction().unwrap();
    let claim =
        signing_jobs::fixture_claim(&tx, &f.tenant, &job, "signer", WORKER, 0, 60, NOW).unwrap();
    tx.commit().unwrap();
    let intent_id = f
        .store
        .connection
        .query_row::<String, _, _>(
            "SELECT intent_id FROM authority_signing_jobs WHERE job_id=?",
            [&job],
            |r| r.get(0),
        )
        .unwrap();
    let signed = signing_intents::test_sign(&mut f, &intent_id, NOW);
    let original = snapshot(&f.store.connection);
    let mut forensic = Connection::open(&f.path).unwrap();
    for (name, sql) in migrations::signing_guard_definitions().unwrap() {
        let table: String = f
            .store
            .connection
            .query_row(
                "SELECT tbl_name FROM sqlite_schema WHERE type='trigger' AND name=?",
                [name],
                |r| r.get(0),
            )
            .unwrap();
        for replaced in [false, true] {
            forensic
                .execute_batch(&format!("DROP TRIGGER {name}"))
                .unwrap();
            if replaced {
                forensic
                    .execute_batch(&format!(
                        "CREATE TRIGGER {name} BEFORE INSERT ON {table} BEGIN SELECT 1; END;"
                    ))
                    .unwrap();
            }
            assert!(f.store.connection.transaction().is_err());
            let tx = forensic.transaction().unwrap();
            assert!(
                reserve(
                    &tx,
                    &f.tenant,
                    &new_id().unwrap(),
                    &change(902),
                    NOW + 300,
                    NOW
                )
                .is_err(),
                "reserve {name},replaced={replaced}"
            );
            tx.rollback().unwrap();
            assert!(
                signing_intents::test_finalize_result(&mut f, &claim, &signed, NOW).is_err(),
                "finalize {name},replaced={replaced}"
            );
            if replaced {
                forensic
                    .execute_batch(&format!("DROP TRIGGER {name}"))
                    .unwrap();
            }
            forensic.execute_batch(sql).unwrap();
            assert_eq!(snapshot(&forensic), original, "{name},replaced={replaced}");
        }
    }
    signing_intents::test_finalize_result(&mut f, &claim, &signed, NOW).unwrap();
    let tx = f.store.connection.transaction().unwrap();
    assert_eq!(
        read(&tx, &f.tenant, &reservation)
            .unwrap()
            .effective_dispatch_slots(),
        1
    );
}

#[test]
fn genuine_restored_root_clock_does_not_block_retained_rootless_v2_job() {
    let mut f = signing_test_support::Fixture::new();
    let rooted = signing_intents::test_prepare(&mut f, NOW);
    next_plan(&mut f, NOW + 1);
    f.store
        .pin_signing_project_quota(&f.tenant, &project_pin(2), Some(1), NOW + 1)
        .unwrap();
    let rootless = signing_intents::test_prepare(&mut f, NOW + 1);
    issue(&mut f, &rootless.intent.job_id, NOW + 1);
    let original: Vec<u8> = f.store.connection.query_row(
        "SELECT snapshot_bytes FROM authority_signing_quota_reservations WHERE reservation_id=?",
        [&rootless.intent.reservation_id], |row| row.get(0)).unwrap();

    let mut restored = project_pin(2);
    restored.root_id = Some(ROOT.into());
    assert_eq!(
        f.store
            .pin_signing_project_quota(&f.tenant, &restored, Some(2), NOW + 2)
            .unwrap(),
        3
    );
    // Another genuine project shares A and observes a later time. Its clock
    // cannot attach A retroactively to the old rootless reservation.
    let other = AuthorityTenant::new(&f.tenant.org_id, &new_id().unwrap()).unwrap();
    f.store
        .provision_target_metadata_project(&other, NOW + 2)
        .unwrap();
    f.store
        .pin_signing_project_quota(&other, &restored, None, NOW + 2)
        .unwrap();
    f.store
        .observe_signing_quota_time(&other, NOW + 100)
        .unwrap();
    assert!(
        f.store
            .read_signing_intent(&f.tenant, &rootless.intent.intent_id, NOW + 3)
            .unwrap()
            .is_some()
    );
    let dispatch =
        f.store
            .claim_signing_dispatch(&f.tenant, &rootless.intent.job_id, WORKER, 0, 60, NOW + 3);
    assert!(dispatch.is_err(), "production dispatch remains closed");
    assert!(
        !matches!(dispatch, Err(AuthorityError::Time)),
        "current root clock must not gate the retained rootless worker"
    );
    // The real fixture still exercises the successful retained claim path.
    let tx = f.store.connection.transaction().unwrap();
    let dispatch = signing_jobs::fixture_claim(
        &tx,
        &f.tenant,
        &rootless.intent.job_id,
        "dispatch",
        WORKER,
        0,
        60,
        NOW + 3,
    )
    .unwrap();
    assert_eq!(dispatch.job_id(), rootless.intent.job_id);
    tx.commit().unwrap();
    assert!(matches!(
        f.store
            .claim_signing_job(&f.tenant, &rooted.intent.job_id, WORKER, 0, 60, NOW + 4),
        Err(AuthorityError::Time)
    ));
    assert!(matches!(
        f.store.signing_readiness_v2(
            &f.tenant,
            f.plan["plan_id"].as_str().unwrap(),
            &f.verifier,
            NOW + 4
        ),
        Err(AuthorityError::Time)
    ));
    f.reopen();
    assert!(
        f.store
            .read_signing_intent(&f.tenant, &rootless.intent.intent_id, NOW + 4)
            .unwrap()
            .is_some()
    );
    let tx = f.store.connection.transaction().unwrap();
    let saved = read(&tx, &f.tenant, &rootless.intent.reservation_id).unwrap();
    assert_eq!(saved.schema_version, "fw.signing-budget-reservation/v2");
    assert!(saved.root_id.is_none());
    assert!(saved.held());
    assert_eq!(saved.effective_dispatch_slots(), 1);
    assert_eq!(
        account(&tx, &f.tenant, AccountingScope::Project, NOW + 4, None)
            .unwrap()
            .concurrent_deployments,
        2
    );
    assert_eq!(tx.query_row::<i64, _, _>("SELECT observed_at FROM authority_signing_quota_clocks WHERE org_id=? AND bucket_kind='root' AND bucket_id=?", params![f.tenant.org_id, ROOT], |row| row.get(0)).unwrap(), NOW + 100);
    assert_eq!(tx.query_row::<Vec<u8>, _, _>("SELECT snapshot_bytes FROM authority_signing_quota_reservations WHERE reservation_id=?", [&rootless.intent.reservation_id], |row| row.get(0)).unwrap(), original);
    tx.commit().unwrap();
    f.store.verify_audit_chain(&f.tenant).unwrap().unwrap();
}
