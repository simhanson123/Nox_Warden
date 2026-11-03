use super::*;

#[test]
fn primitive_fixture_setup_failure_cannot_leave_the_real_witness_path_disabled() {
    assert!(!PRIMITIVE_QUOTA_FIXTURE.get());
    let failure = std::panic::catch_unwind(|| {
        let mut invalid = limits();
        invalid.active_leases = 0;
        Fixture::new(invalid, limits())
    });
    assert!(failure.is_err());
    assert!(!PRIMITIVE_QUOTA_FIXTURE.get());
    let (mut f, _, reservation) = real_reservation("reserved");
    let tx = f.store.connection.transaction().unwrap();
    assert_eq!(
        read(&tx, &f.tenant, &reservation).unwrap().state,
        "reserved"
    );
    assert!(!PRIMITIVE_QUOTA_FIXTURE.get());
}

#[test]
fn ordinary_reserved_reads_reject_missing_work_genesis_and_cannot_use_initializer_read() {
    let (mut f, job, reservation) = real_reservation("reserved");
    let guard: String = f
        .store
        .connection
        .query_row(
            "SELECT sql FROM sqlite_schema WHERE name='authority_signing_work_heads_no_delete'",
            [],
            |r| r.get(0),
        )
        .unwrap();
    f.store
        .connection
        .execute_batch("DROP TRIGGER authority_signing_work_heads_no_delete")
        .unwrap();
    f.store
        .connection
        .execute(
            "DELETE FROM authority_signing_work_heads WHERE job_id=?",
            [&job],
        )
        .unwrap();
    f.store.connection.execute_batch(&guard).unwrap();
    let tx = f.store.connection.transaction().unwrap();
    assert!(read(&tx, &f.tenant, &reservation).is_err());
    assert!(read_initializing_job(&tx, &f.tenant, &reservation).is_err());
    assert!(reserve(&tx, &f.tenant, &id(930), &change(2), NOW + 300, NOW).is_err());
}

#[test]
fn replacement_cannot_remove_reserved_genesis_after_genuine_cancellation_work() {
    for foreign_keys in [false, true] {
        for recursive in [false, true] {
            let (mut f, job, reservation) = real_reservation("reserved");
            f.store
                .connection
                .pragma_update(None, "foreign_keys", foreign_keys)
                .unwrap();
            f.store
                .connection
                .pragma_update(None, "recursive_triggers", recursive)
                .unwrap();
            let original:Vec<(i64,i64,String)>=f.store.connection.prepare("SELECT rowid,revision,state FROM authority_signing_quota_transitions ORDER BY rowid").unwrap().query_map([],|r|Ok((r.get(0)?,r.get(1)?,r.get(2)?))).unwrap().collect::<rusqlite::Result<_>>().unwrap();
            let audit = f.count("authority_audit");
            {
                let tx = f.store.connection.transaction().unwrap();
                signing_jobs::fixture_cancel_work(&tx, &f.tenant, &job, NOW).unwrap();
                // This is a genuine next cancellation transition. Its explicit
                // rowid targets the old revision0 while revision1 is unused.
                let sql = "INSERT OR REPLACE INTO authority_signing_quota_transitions(rowid,org_id,project_id,reservation_id,revision,state,issued_at,active_slots,dispatch_slots,recorded_at,kind,job_id,work_phase,work_revision) SELECT t.rowid,t.org_id,t.project_id,t.reservation_id,1,'released',NULL,0,0,?1,'released',e.job_id,e.phase,e.revision FROM authority_signing_quota_transitions t JOIN authority_signing_work_events e ON e.job_id=?2 AND e.phase='signer' AND e.state='cancelled' WHERE t.reservation_id=?3 AND t.revision=0";
                assert!(tx.execute(sql, params![NOW, job, reservation]).is_err());
                assert!(tx.execute("INSERT OR REPLACE INTO authority_signing_quota_transitions SELECT * FROM authority_signing_quota_transitions WHERE reservation_id=?",[&reservation]).is_err());
                assert!(tx.execute("UPDATE OR REPLACE authority_signing_quota_transitions SET rowid=rowid+100 WHERE reservation_id=?",[&reservation]).is_err());
            }
            let after:Vec<(i64,i64,String)>=f.store.connection.prepare("SELECT rowid,revision,state FROM authority_signing_quota_transitions ORDER BY rowid").unwrap().query_map([],|r|Ok((r.get(0)?,r.get(1)?,r.get(2)?))).unwrap().collect::<rusqlite::Result<_>>().unwrap();
            assert_eq!(after, original);
            assert_eq!(f.count("authority_audit"), audit);
            let tx = f.store.connection.transaction().unwrap();
            assert_eq!(
                read(&tx, &f.tenant, &reservation).unwrap().state,
                "reserved"
            );
        }
    }
}

#[test]
fn imported_reserved_genesis_remains_valid_after_later_issuance() {
    let (mut f, job, reservation) = real_reservation("reserved");
    drop(f.store);
    migrations::legacy::restore_v7(&f.path);
    AuthorityStore::migrate(
        &f.path,
        f.directory.path().join("imported-before-upgrade.sqlite3"),
    )
    .unwrap();
    f.store = AuthorityStore::open(&f.path).unwrap();
    let claim = {
        let tx = f.store.connection.transaction().unwrap();
        let claim =
            signing_jobs::fixture_claim(&tx, &f.tenant, &job, "signer", &id(90), 0, 60, NOW)
                .unwrap();
        tx.commit().unwrap();
        claim
    };
    signing_intents::test_finalize(&mut f, &claim, NOW).unwrap();
    let tx = f.store.connection.transaction().unwrap();
    assert_eq!(read(&tx, &f.tenant, &reservation).unwrap().state, "issued");
    validate_retained_transitions(&tx).unwrap();
}

#[test]
fn removed_genesis_or_middle_transition_is_rejected_after_exact_guard_repair() {
    for missing in [0, 1] {
        let (mut f, job, reservation) = real_reservation("unknown");
        let guard: String=f.store.connection.query_row("SELECT sql FROM sqlite_schema WHERE name='authority_signing_quota_transitions_no_delete'",[],|r|r.get(0)).unwrap();
        f.store.connection.execute_batch("DROP TRIGGER authority_signing_quota_transitions_no_delete; PRAGMA foreign_keys=OFF").unwrap();
        assert_eq!(f.store.connection.execute("DELETE FROM authority_signing_quota_transitions WHERE reservation_id=? AND revision=?",params![reservation,missing]).unwrap(),1);
        f.store.connection.execute_batch(&guard).unwrap();
        f.store
            .connection
            .execute_batch("PRAGMA foreign_keys=ON")
            .unwrap();
        let tx = f.store.connection.transaction().unwrap();
        assert!(read(&tx, &f.tenant, &reservation).is_err());
        assert!(signing_jobs::lifecycle_status(&tx, &f.tenant, &job, NOW + 6).is_err());
        assert!(reserve(&tx, &f.tenant, &id(930), &change(2), NOW + 300, NOW + 6).is_err());
    }
}

#[test]
fn retained_transition_witness_must_match_exact_historical_event_time() {
    let (mut f, _, reservation) = real_reservation("unknown");
    let guard:String=f.store.connection.query_row("SELECT sql FROM sqlite_schema WHERE name='authority_signing_quota_transitions_no_update'",[],|r|r.get(0)).unwrap();
    f.store
        .connection
        .execute_batch("DROP TRIGGER authority_signing_quota_transitions_no_update")
        .unwrap();
    f.store.connection.execute("UPDATE authority_signing_quota_transitions SET recorded_at=recorded_at+1 WHERE reservation_id=? AND state='issued'",[&reservation]).unwrap();
    f.store.connection.execute_batch(&guard).unwrap();
    let tx = f.store.connection.transaction().unwrap();
    assert!(read(&tx, &f.tenant, &reservation).is_err());
}

#[test]
fn already_open_sensitive_accounting_rejects_a_missing_job_with_foreign_keys_disabled() {
    let (mut f, job, reservation) = real_reservation("issued");
    let guard: String = f
        .store
        .connection
        .query_row(
            "SELECT sql FROM sqlite_schema WHERE name='authority_signing_jobs_no_delete'",
            [],
            |r| r.get(0),
        )
        .unwrap();
    f.store
        .connection
        .execute_batch("DROP TRIGGER authority_signing_jobs_no_delete; PRAGMA foreign_keys=OFF")
        .unwrap();
    f.store
        .connection
        .execute("DELETE FROM authority_signing_jobs WHERE job_id=?", [&job])
        .unwrap();
    f.store.connection.execute_batch(&guard).unwrap();
    f.store
        .connection
        .execute_batch("PRAGMA foreign_keys=ON")
        .unwrap();
    let tx = f.store.connection.transaction().unwrap();
    assert!(read(&tx, &f.tenant, &reservation).is_err());
    assert!(reserve(&tx, &f.tenant, &id(930), &change(2), NOW + 300, NOW).is_err());
    assert_eq!(tx.query_row("SELECT dispatch_slots FROM authority_signing_quota_reservations WHERE reservation_id=?",[&reservation],|r|r.get::<_,i64>(0)).unwrap(),1);
}

#[test]
fn replacement_cannot_hide_a_genuinely_delivered_held_job() {
    let mut f = signing_test_support::Fixture::new();
    let first = signing_intents::test_prepare(&mut f, NOW);
    let victim = first.intent.job_id;
    let reservation = first.intent.reservation_id;
    {
        let tx = f.store.connection.transaction().unwrap();
        let claim =
            signing_jobs::fixture_claim(&tx, &f.tenant, &victim, "signer", &id(90), 0, 60, NOW)
                .unwrap();
        tx.commit().unwrap();
        signing_intents::test_finalize(&mut f, &claim, NOW).unwrap();
        let tx = f.store.connection.transaction().unwrap();
        let dispatch = signing_jobs::fixture_claim(
            &tx,
            &f.tenant,
            &victim,
            "dispatch",
            &id(91),
            0,
            60,
            NOW + 1,
        )
        .unwrap();
        signing_jobs::fixture_deliver(&tx, &f.tenant, &dispatch, NOW + 2).unwrap();
        tx.commit().unwrap();
    }
    let mut next = f.plan.clone();
    next["plan_id"] = new_id().unwrap().into();
    next["target_generation"] = "2".into();
    let next_id = next["plan_id"].as_str().unwrap().to_owned();
    f.store
        .register_reviewed_plan(&f.tenant, &next, &f.requirements, &f.review, NOW + 3)
        .unwrap();
    f.store
        .register_native_compilation(&f.tenant, &next_id, 1, NOW + 3)
        .unwrap();
    let compiled = fw_native_evidence::compile_evidence(&next, &f.review, &f.references).unwrap();
    let installation = signing_test_support::native::installation(compiled.baseline(), NOW + 3);
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
            NOW + 3,
        )
        .unwrap();
    let proof = signing_test_support::native::proof(
        &challenge,
        installation.clone(),
        signing_test_support::native::snapshot(&installation.native),
        NOW + 3,
    );
    let observation = f
        .store
        .admit_native_observation(&f.tenant, &proof, NOW + 3)
        .unwrap();
    f.plan = next;
    f.baseline_receipt_hash = observation.receipt_hash;
    f.current_approval_hash = f.approve(&next_id, NOW + 3);
    let second = signing_intents::test_prepare(&mut f, NOW + 3);
    let claim = {
        let tx = f.store.connection.transaction().unwrap();
        let claim = signing_jobs::fixture_claim(
            &tx,
            &f.tenant,
            &second.intent.job_id,
            "signer",
            &id(90),
            0,
            60,
            NOW + 3,
        )
        .unwrap();
        tx.commit().unwrap();
        claim
    };
    signing_intents::test_finalize(&mut f, &claim, NOW + 3).unwrap();

    for foreign_keys in [false, true] {
        for recursive in [false, true] {
            f.store
                .connection
                .pragma_update(None, "foreign_keys", foreign_keys)
                .unwrap();
            f.store
                .connection
                .pragma_update(None, "recursive_triggers", recursive)
                .unwrap();
            let original_audit = f.count("authority_audit");
            assert!(f.store.connection.execute("INSERT OR REPLACE INTO authority_signing_jobs(rowid,org_id,project_id,job_id,intent_id,payload_hash,created_at,deadline,canonical_bytes) SELECT (SELECT rowid FROM authority_signing_jobs WHERE job_id=?1),org_id,project_id,job_id,intent_id,payload_hash,created_at,deadline,canonical_bytes FROM authority_signing_jobs WHERE job_id=?2",params![victim,second.intent.job_id]).is_err());
            assert_eq!(f.count("authority_signing_jobs"), 2);
            assert_eq!(f.count("authority_audit"), original_audit);
            let tx = f.store.connection.transaction().unwrap();
            let saved = read(&tx, &f.tenant, &reservation).unwrap();
            assert_eq!(saved.state, "active");
            assert_eq!(saved.effective_dispatch_slots(), 1);
            assert!(
                signing_jobs::lifecycle_status(&tx, &f.tenant, &victim, NOW + 3)
                    .unwrap()
                    .quota_held
            );
        }
    }
    f.reopen();
    let tx = f.store.connection.transaction().unwrap();
    assert!(read(&tx, &f.tenant, &reservation).unwrap().held());
}
