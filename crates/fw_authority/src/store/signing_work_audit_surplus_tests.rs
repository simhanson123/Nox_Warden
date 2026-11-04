//! Independently chained work audits must be consumed by exact retained events.
use super::*;

fn lifecycle(rootless: bool, state: &str) -> (Fixture, String, String, String) {
    let mut f = Fixture::new();
    if rootless {
        f.store
            .pin_signing_project_quota(
                &f.tenant,
                &SigningProjectQuotaPin {
                    root_id: None,
                    limits: SigningQuotaLimits {
                        active_leases: 10,
                        new_leases_per_day: 10,
                        unique_destinations_per_day: 10,
                        cumulative_seconds_per_day: 864_000,
                        concurrent_deployments: 10,
                    },
                    not_before: NOW,
                    not_after: NOW + 7200,
                },
                None,
                NOW,
            )
            .unwrap();
    }
    let prepared = signing_intents::test_prepare(&mut f, NOW);
    let job = prepared.intent.job_id;
    let intent = prepared.intent.intent_id;
    let reservation = prepared.intent.reservation_id;
    if state != "prepared" {
        let tx = f.store.connection.transaction().unwrap();
        let claim = fixture_claim(&tx, &f.tenant, &job, "signer", WORKER, 0, 60, NOW).unwrap();
        tx.commit().unwrap();
        signing_intents::test_finalize(&mut f, &claim, NOW).unwrap();
        if state == "unknown" {
            let tx = f.store.connection.transaction().unwrap();
            let claim =
                fixture_claim(&tx, &f.tenant, &job, "dispatch", WORKER, 0, 60, NOW).unwrap();
            fixture_unknown(&tx, &f.tenant, &claim, NOW).unwrap();
            tx.commit().unwrap();
        }
    }
    (f, job, intent, reservation)
}

#[test]
fn committed_surplus_work_audits_refuse_rooted_and_rootless_lifecycle_reads_and_admission() {
    for rootless in [false, true] {
        for state in ["prepared", "issued", "unknown"] {
            let (mut f, job, intent, reservation) = lifecycle(rootless, state);
            let tx = f.store.connection.transaction().unwrap();
            let cost = signing_quota::cost_for_plan(
                &tx,
                &f.tenant,
                f.plan["plan_id"].as_str().unwrap(),
                NOW,
            )
            .unwrap();
            // Confirm spare capacity, so refusal below depends on evidence.
            signing_quota::reserve(&tx, &f.tenant, &new_id().unwrap(), &cost, NOW + 300, NOW)
                .unwrap();
            tx.rollback().unwrap();
            let retained_work = table_rows(&f.store.connection, "authority_signing_work_events");
            let tx = f.store.connection.transaction().unwrap();
            // Use the real append primitive and valid chain/head projection on
            // the already-open connection, without schema or index tampering.
            audit(&tx, &f.tenant, "signing_signer_cancelled", &job, NOW).unwrap();
            tx.commit().unwrap();
            assert_eq!(
                table_rows(&f.store.connection, "authority_signing_work_events"),
                retained_work
            );
            let damaged = snapshot(&f.store.connection);
            assert!(
                f.store
                    .read_signing_intent(&f.tenant, &intent, NOW)
                    .is_err(),
                "intent {rootless} {state}"
            );
            let tx = f.store.connection.transaction().unwrap();
            assert!(signing_quota::read(&tx, &f.tenant, &reservation).is_err());
            assert!(
                signing_quota::reserve(&tx, &f.tenant, &new_id().unwrap(), &cost, NOW + 300, NOW)
                    .is_err(),
                "admission {rootless} {state}"
            );
            tx.rollback().unwrap();
            assert!(AuthorityStore::open(&f.path).is_err());
            let backup = f.directory.path().join("surplus-current-backup.sqlite3");
            assert!(AuthorityStore::migrate(&f.path, &backup).is_err());
            assert!(!backup.exists());
            assert_eq!(snapshot(&f.store.connection), damaged);
        }
    }
}

#[test]
fn closed_work_audit_set_rejects_every_surplus_phase_and_mutation() {
    let (mut f, job) = prepared();
    let before = snapshot(&f.store.connection);
    for phase in ["signer", "dispatch"] {
        for mutation in [
            "created",
            "claimed",
            "renewed",
            "retried",
            "cancelled",
            "finalized",
            "unknown",
            "delivered",
        ] {
            let tx = f.store.connection.transaction().unwrap();
            let kind = format!("signing_{phase}_{mutation}");
            audit(&tx, &f.tenant, &kind, &job, NOW).unwrap();
            assert!(
                validate_job_work_audits(&tx, &f.tenant, &job).is_err(),
                "{kind}"
            );
            assert!(validate_work_histories(&tx).is_err(), "{kind}");
            tx.rollback().unwrap();
            assert_eq!(snapshot(&f.store.connection), before);
        }
    }
}

#[test]
fn full_work_audit_validation_rejects_unknown_jobs_and_other_tenant_claims() {
    for other_tenant in [false, true] {
        let (mut f, job) = prepared();
        let other = AuthorityTenant::new(
            "eeeeeeee-eeee-4eee-8eee-eeeeeeeeeeee",
            "ffffffff-ffff-4fff-8fff-ffffffffffff",
        )
        .unwrap();
        f.store
            .provision_principal(&other, WORKER, "https://other.fixture.example", WORKER, NOW)
            .unwrap();
        let tenant = if other_tenant { &other } else { &f.tenant };
        let resource = if other_tenant {
            job.clone()
        } else {
            new_id().unwrap()
        };
        let tx = f.store.connection.transaction().unwrap();
        audit(&tx, tenant, "signing_dispatch_unknown", &resource, NOW).unwrap();
        // The valid job's scoped history remains intact; complete retained
        // validation must also inspect work evidence outside that scope.
        validate_job_work_audits(&tx, &f.tenant, &job).unwrap();
        assert!(validate_work_histories(&tx).is_err());
        tx.commit().unwrap();
        let damaged = snapshot(&f.store.connection);
        assert!(AuthorityStore::open(&f.path).is_err());
        let backup = f
            .directory
            .path()
            .join("unknown-job-current-backup.sqlite3");
        assert!(AuthorityStore::migrate(&f.path, &backup).is_err());
        assert!(!backup.exists());
        assert_eq!(snapshot(&f.store.connection), damaged);
    }
}

#[test]
fn unrelated_signing_audits_remain_independent_of_work_bindings() {
    let (mut f, job, intent, reservation) = lifecycle(true, "unknown");
    let original_events = table_rows(&f.store.connection, "authority_signing_work_events");
    let original_bindings = table_rows(&f.store.connection, "authority_signing_work_audits");
    let tx = f.store.connection.transaction().unwrap();
    for kind in [
        "signing_intent_prepared",
        "signing_result_finalized",
        "signing_budget_reserved",
        "signing_project_quota_pinned",
        "signing_signer_claimed_diagnostic",
    ] {
        audit(&tx, &f.tenant, kind, &job, NOW).unwrap();
    }
    validate_work_histories(&tx).unwrap();
    tx.commit().unwrap();
    f.store
        .read_signing_intent(&f.tenant, &intent, NOW)
        .unwrap();
    let tx = f.store.connection.transaction().unwrap();
    assert_eq!(
        signing_quota::read(&tx, &f.tenant, &reservation)
            .unwrap()
            .state,
        "unknown"
    );
    tx.rollback().unwrap();
    let before = snapshot(&f.store.connection);
    f.reopen();
    let backup = f.directory.path().join("benign-current-backup.sqlite3");
    AuthorityStore::migrate(&f.path, &backup).unwrap();
    assert!(!backup.exists());
    assert_eq!(snapshot(&f.store.connection), before);
    assert_eq!(
        table_rows(&f.store.connection, "authority_signing_work_events"),
        original_events
    );
    assert_eq!(
        table_rows(&f.store.connection, "authority_signing_work_audits"),
        original_bindings
    );
}

#[test]
fn audit_first_event_second_is_valid_and_rollback_preserves_both_histories() {
    let (mut f, job) = prepared();
    let before = snapshot(&f.store.connection);
    let tx = f.store.connection.transaction().unwrap();
    audit(&tx, &f.tenant, "signing_signer_claimed", &job, NOW).unwrap();
    assert!(validate_job_work_audits(&tx, &f.tenant, &job).is_err());
    raw_claim(&tx, &job, WORKER).unwrap();
    validate_work_histories(&tx).unwrap();
    assert_eq!(
        head(&tx, &f.tenant, &job, "signer").unwrap().unwrap().state,
        "claimed"
    );
    tx.rollback().unwrap();
    assert_eq!(snapshot(&f.store.connection), before);

    let tx = f.store.connection.transaction().unwrap();
    // Force event insertion to fail after its canonical audit is appended,
    // without installing any extra schema object that audit() would reject.
    let mut next = initial("claimed", NOW);
    next.generation = 1;
    next.attempts = 1;
    next.claim_hash = Some(vec![1; 32]);
    next.worker = Some(WORKER.into());
    next.until = Some(NOW); // invalid claim end; the SQL guard rejects it
    let old = head(&tx, &f.tenant, &job, "signer").unwrap().unwrap();
    assert!(
        write_head(
            &tx,
            &f.tenant,
            &job,
            "signer",
            Some(&old),
            next,
            "claimed",
            NOW
        )
        .is_err()
    );
    assert!(validate_work_histories(&tx).is_err());
    tx.rollback().unwrap();
    assert_eq!(snapshot(&f.store.connection), before);
    f.reopen();
}

#[test]
fn job_initialization_exception_cannot_excuse_retained_unbound_work_evidence() {
    let (mut f, job) = prepared();
    let before = snapshot(&f.store.connection);
    let mut db = Connection::open(&f.path).unwrap();
    db.pragma_update(None, "foreign_keys", true).unwrap();
    let tx = db.transaction().unwrap();
    let mut definitions = Vec::new();
    for guard in [
        "authority_signing_work_heads_no_delete",
        "authority_signing_work_events_immutable_delete",
        "authority_signing_work_audits_immutable_delete",
    ] {
        let definition: String = tx
            .query_row(
                "SELECT sql FROM sqlite_schema WHERE type='trigger' AND name=?",
                [guard],
                |row| row.get(0),
            )
            .unwrap();
        definitions.push(definition);
        tx.execute_batch(&format!("DROP TRIGGER {guard}")).unwrap();
    }
    // Recreate only the transient shape immediately preceding initialization,
    // while retaining the real job/intent/reservation and original audit. Its
    // surplus genesis audit must not acquire a second invented event meaning.
    for table in [
        "authority_signing_work_audits",
        "authority_signing_work_heads",
        "authority_signing_work_events",
    ] {
        assert_eq!(
            tx.execute(&format!("DELETE FROM {table} WHERE job_id=?"), [&job])
                .unwrap(),
            1
        );
    }
    for definition in definitions {
        tx.execute_batch(&definition).unwrap();
    }
    assert!(initialize_job(&tx, &f.tenant, &job, NOW).is_err());
    assert_eq!(
        tx.query_row::<i64, _, _>(
            "SELECT count(*) FROM authority_signing_work_events",
            [],
            |row| row.get(0)
        )
        .unwrap(),
        0
    );
    tx.rollback().unwrap();
    assert_eq!(snapshot(&f.store.connection), before);
    f.reopen();
}
