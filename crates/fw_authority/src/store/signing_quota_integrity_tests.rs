use super::*;

fn accounting_head_rows(connection: &Connection) -> Vec<Vec<rusqlite::types::Value>> {
    let mut query = connection
        .prepare("SELECT rowid,* FROM authority_signing_quota_transition_heads ORDER BY rowid")
        .unwrap();
    let columns = query.column_count();
    query
        .query_map([], |row| {
            (0..columns)
                .map(|column| row.get(column))
                .collect::<rusqlite::Result<Vec<_>>>()
        })
        .unwrap()
        .collect::<rusqlite::Result<Vec<_>>>()
        .unwrap()
}

#[test]
fn replacing_a_released_accounting_head_cannot_erase_issued_membership() {
    let (mut f, released_job, released) = real_reservation("reserved");
    f.store
        .cancel_signing_job(&f.tenant, &released_job, NOW)
        .unwrap();

    // Prepare and genuinely sign a second approved/native-bound generation.
    // The first head is valid released history, not a malformed decoy row.
    let mut next = f.plan.clone();
    next["plan_id"] = new_id().unwrap().into();
    next["target_generation"] = "2".into();
    let next_id = next["plan_id"].as_str().unwrap().to_owned();
    f.store
        .register_reviewed_plan(&f.tenant, &next, &f.requirements, &f.review, NOW + 1)
        .unwrap();
    f.store
        .register_native_compilation(&f.tenant, &next_id, 1, NOW + 1)
        .unwrap();
    let compiled = fw_native_evidence::compile_evidence(&next, &f.review, &f.references).unwrap();
    let installation = signing_test_support::native::installation(compiled.baseline(), NOW + 1);
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
            NOW + 1,
        )
        .unwrap();
    let proof = signing_test_support::native::proof(
        &challenge,
        installation.clone(),
        signing_test_support::native::snapshot(&installation.native),
        NOW + 1,
    );
    let observation = f
        .store
        .admit_native_observation(&f.tenant, &proof, NOW + 1)
        .unwrap();
    f.plan = next;
    f.baseline_receipt_hash = observation.receipt_hash;
    f.current_approval_hash = f.approve(&next_id, NOW + 1);
    let second = signing_intents::test_prepare(&mut f, NOW + 1);
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
            NOW + 1,
        )
        .unwrap();
        tx.commit().unwrap();
        claim
    };
    signing_intents::test_finalize(&mut f, &claim, NOW + 1).unwrap();
    let issued = second.intent.reservation_id;
    let original_heads = accounting_head_rows(&f.store.connection);
    let original_audit_count = f.count("authority_audit");
    assert_eq!(original_heads.len(), 2);

    f.store
        .connection
        .execute_batch("PRAGMA foreign_keys=ON; PRAGMA recursive_triggers=OFF;")
        .unwrap();
    assert_eq!(
        f.store
            .connection
            .query_row::<i64, _, _>("PRAGMA foreign_keys", [], |r| r.get(0))
            .unwrap(),
        1
    );
    assert_eq!(
        f.store
            .connection
            .query_row::<i64, _, _>("PRAGMA recursive_triggers", [], |r| r.get(0))
            .unwrap(),
        0
    );
    for mutation in [
        "INSERT OR REPLACE INTO authority_signing_quota_transition_heads(rowid,org_id,project_id,reservation_id,root_id,lease_id,revision,state,issued_at) SELECT (SELECT rowid FROM authority_signing_quota_transition_heads WHERE reservation_id=?1),org_id,project_id,reservation_id,root_id,lease_id,revision,state,issued_at FROM authority_signing_quota_transition_heads WHERE reservation_id=?2",
        "UPDATE OR REPLACE authority_signing_quota_transition_heads SET rowid=(SELECT rowid FROM authority_signing_quota_transition_heads WHERE reservation_id=?1) WHERE reservation_id=?2",
        "INSERT OR REPLACE INTO authority_signing_quota_transition_heads SELECT org_id,project_id,reservation_id,root_id,lease_id,revision,state,issued_at FROM authority_signing_quota_transition_heads WHERE reservation_id=?2 AND EXISTS(SELECT 1 FROM authority_signing_quota_transition_heads WHERE reservation_id=?1)",
    ] {
        assert!(
            f.store
                .connection
                .execute(mutation, params![issued, released])
                .is_err(),
            "{mutation}"
        );
        assert_eq!(accounting_head_rows(&f.store.connection), original_heads);
        assert_eq!(f.count("authority_audit"), original_audit_count);
        for reopen in [false, true] {
            if reopen {
                f.reopen();
            }
            assert_eq!(accounting_head_rows(&f.store.connection), original_heads);
            let tx = f.store.connection.transaction().unwrap();
            assert!(!read(&tx, &f.tenant, &released).unwrap().held());
            assert!(read(&tx, &f.tenant, &issued).unwrap().held());
            let status =
                signing_jobs::lifecycle_status(&tx, &f.tenant, &second.intent.job_id, NOW + 1)
                    .unwrap();
            assert!(status.quota_held);
            assert_eq!(status.dispatch_state.as_deref(), Some("queued"));
            let cost = cost_for_plan(&tx, &f.tenant, &next_id, NOW + 1).unwrap();
            assert!(matches!(
                reserve(&tx, &f.tenant, &id(999), &cost, NOW + 250, NOW + 1),
                Err(AuthorityError::Quota)
            ));
        }
    }
}

#[test]
fn unsigned_delivery_keeps_issued_capacity_after_expiry_and_reopen() {
    let (mut f, job, reservation) = real_reservation("issued");
    let original: (Vec<u8>, Vec<u8>) = f.store.connection.query_row(
        "SELECT cost_bytes,snapshot_bytes FROM authority_signing_quota_reservations WHERE reservation_id=?",
        [&reservation], |r| Ok((r.get(0)?, r.get(1)?)),
    ).unwrap();
    {
        let tx = f.store.connection.transaction().unwrap();
        let claim =
            signing_jobs::fixture_claim(&tx, &f.tenant, &job, "dispatch", &id(91), 0, 60, NOW + 1)
                .unwrap();
        // This fixture follows the legitimate claimed -> delivered path with
        // every SQL guard intact, but has no authenticated target receipt.
        signing_jobs::fixture_deliver(&tx, &f.tenant, &claim, NOW + 2).unwrap();
        tx.commit().unwrap();
    }
    for now in [NOW + 2, NOW + 400] {
        f.reopen();
        let tx = f.store.connection.transaction().unwrap();
        let saved = read(&tx, &f.tenant, &reservation).unwrap();
        assert_eq!(saved.state, "active");
        assert_eq!(
            saved.dispatch_slots, 0,
            "historical stored projection is preserved"
        );
        assert_eq!(saved.effective_dispatch_slots(), 1);
        assert!(saved.held());
        let status = signing_jobs::lifecycle_status(&tx, &f.tenant, &job, now).unwrap();
        assert_eq!(status.dispatch_state.as_deref(), Some("delivered"));
        assert!(status.quota_held);
        assert!(matches!(
            reserve(&tx, &f.tenant, &id(212), &change(212), now + 300, now),
            Err(AuthorityError::Quota)
        ));
        let retained: (Vec<u8>, Vec<u8>) = tx.query_row(
            "SELECT cost_bytes,snapshot_bytes FROM authority_signing_quota_reservations WHERE reservation_id=?",
            [&reservation], |r| Ok((r.get(0)?, r.get(1)?)),
        ).unwrap();
        assert_eq!(retained, original);
    }
}

#[test]
fn active_lease_and_policy_records_both_keep_effective_dispatch_capacity() {
    for with_lease in [false, true] {
        let mut cap = limits();
        cap.concurrent_deployments = 1;
        let mut f = Fixture::new(cap.clone(), cap);
        let cost = if with_lease {
            lease(1, &[1])
        } else {
            change(1)
        };
        f.reserve(20, &cost, NOW).unwrap();
        f.finalize(20, NOW).unwrap();
        f.active(20, NOW);
        {
            let tx = f.store.connection.transaction().unwrap();
            let saved = read(&tx, &f.tenant, &id(20)).unwrap();
            assert_eq!(saved.active_slots, i64::from(with_lease));
            assert_eq!(saved.dispatch_slots, 0);
            assert_eq!(saved.effective_dispatch_slots(), 1);
            assert!(saved.held());
        }
        assert!(matches!(
            f.reserve(21, &change(2), NOW + WINDOW + 1),
            Err(AuthorityError::Quota)
        ));
    }
}

#[test]
fn every_expected_live_signing_guard_is_checked_before_admission() {
    let (mut f, _, _) = real_reservation("issued");
    let guards = migrations::signing_guard_definitions().unwrap();
    for required in [
        "authority_signing_quota_transitions_evidence",
        "authority_signing_quota_reservations_immutable",
        "authority_signing_quota_reservations_issuance",
        "authority_signing_quota_usage_no_update",
        "authority_signing_work_events_sequence",
        "authority_signing_deliveries_claim",
    ] {
        assert!(guards.iter().any(|(name, _)| name == required));
    }
    for (name, expected) in guards {
        f.store
            .connection
            .execute_batch(&format!("DROP TRIGGER {name}"))
            .unwrap();
        {
            let tx = f.store.connection.transaction().unwrap();
            assert!(
                matches!(
                    reserve(&tx, &f.tenant, &id(212), &change(212), NOW + 300, NOW),
                    Err(AuthorityError::Invalid(
                        "quota accounting guard missing or changed"
                    ))
                ),
                "missing {name}"
            );
        }
        f.store.connection.execute_batch(&format!("CREATE TRIGGER {name} BEFORE INSERT ON authority_signing_quota_reservations BEGIN SELECT 1; END;")).unwrap();
        {
            let tx = f.store.connection.transaction().unwrap();
            assert!(
                matches!(
                    reserve(&tx, &f.tenant, &id(212), &change(212), NOW + 300, NOW),
                    Err(AuthorityError::Invalid(
                        "quota accounting guard missing or changed"
                    ))
                ),
                "changed {name}"
            );
        }
        f.store
            .connection
            .execute_batch(&format!("DROP TRIGGER {name}; {expected};"))
            .unwrap();
    }
    assert_eq!(f.count("authority_signing_quota_reservations"), 1);
    let tx = f.store.connection.transaction().unwrap();
    assert!(matches!(
        reserve(&tx, &f.tenant, &id(212), &change(212), NOW + 300, NOW),
        Err(AuthorityError::Quota)
    ));
}

#[test]
fn restored_evidence_guard_cannot_hide_forged_active_capacity() {
    let (mut f, job, reservation) = real_reservation("issued");
    let guard: String = f.store.connection.query_row(
        "SELECT sql FROM sqlite_schema WHERE name='authority_signing_quota_transitions_evidence'",
        [], |r| r.get(0),
    ).unwrap();
    f.store
        .connection
        .execute_batch("DROP TRIGGER authority_signing_quota_transitions_evidence")
        .unwrap();
    f.store.connection.execute("INSERT INTO authority_signing_quota_transitions SELECT r.org_id,r.project_id,r.reservation_id,(SELECT MAX(t.revision)+1 FROM authority_signing_quota_transitions t WHERE t.org_id=r.org_id AND t.project_id=r.project_id AND t.reservation_id=r.reservation_id),'active',r.issued_at,r.active_slots,0,?,'active',NULL,NULL,NULL FROM authority_signing_quota_reservations r WHERE reservation_id=?", params![NOW, reservation]).unwrap();
    f.store.connection.execute("UPDATE authority_signing_quota_reservations SET state='active',dispatch_slots=0 WHERE reservation_id=?", [&reservation]).unwrap();
    {
        let tx = f.store.connection.transaction().unwrap();
        assert!(matches!(
            reserve(&tx, &f.tenant, &id(212), &change(212), NOW + 300, NOW),
            Err(AuthorityError::Invalid(
                "quota accounting guard missing or changed"
            ))
        ));
    }
    f.store.connection.execute_batch(&guard).unwrap();
    for reopen in [false, true] {
        if reopen {
            f.reopen();
        }
        let tx = f.store.connection.transaction().unwrap();
        assert!(read(&tx, &f.tenant, &reservation).is_err());
        assert!(signing_jobs::lifecycle_status(&tx, &f.tenant, &job, NOW).is_err());
        assert!(matches!(
            reserve(&tx, &f.tenant, &id(212), &change(212), NOW + 300, NOW),
            Err(AuthorityError::Invalid(_))
        ));
    }
}

#[test]
fn unsigned_active_history_remains_inside_the_accounted_row_bound() {
    let mut f = Fixture::new(limits(), limits());
    f.reserve(20, &change(1), NOW).unwrap();
    f.finalize(20, NOW).unwrap();
    f.active(20, NOW);
    let tx = f.store.connection.transaction().unwrap();
    // Primitive, structurally consistent rows test the accounting bound. The
    // separate real-fixture test above verifies ordinary work and delivery.
    primitive_transition(&tx, || {
        tx.execute_batch("WITH RECURSIVE n(x) AS (VALUES(1) UNION ALL SELECT x+1 FROM n WHERE x<10001)
          INSERT INTO authority_signing_quota_reservations SELECT org_id,project_id,printf('00000000-0000-0000-0001-%012x',n.x),root_id,plan_id,plan_hash,lease_id,lease_seconds,cost_hash,cost_bytes,CAST(json_set(CAST(snapshot_bytes AS TEXT),'$.reservation_id',printf('00000000-0000-0000-0001-%012x',n.x)) AS BLOB),reserved_at,reserved_until,'reserved',NULL,active_slots,1 FROM authority_signing_quota_reservations,n WHERE reservation_id='00000000-0000-0000-0000-000000000014';
          INSERT INTO authority_signing_quota_usage SELECT org_id,project_id,reservation_id,reserved_at,cost_hash FROM authority_signing_quota_reservations WHERE reservation_id LIKE '00000000-0000-0000-0001-%';
          INSERT INTO authority_signing_quota_transitions SELECT org_id,project_id,reservation_id,1,'issued',reserved_at,0,1,reserved_at,'issued',NULL,NULL,NULL FROM authority_signing_quota_reservations WHERE reservation_id LIKE '00000000-0000-0000-0001-%';
          UPDATE authority_signing_quota_reservations SET state='issued',issued_at=reserved_at WHERE reservation_id LIKE '00000000-0000-0000-0001-%';
          INSERT INTO authority_signing_quota_transitions SELECT org_id,project_id,reservation_id,2,'active',issued_at,0,0,issued_at,'active',NULL,NULL,NULL FROM authority_signing_quota_reservations WHERE reservation_id LIKE '00000000-0000-0000-0001-%';
          UPDATE authority_signing_quota_reservations SET state='active',dispatch_slots=0 WHERE reservation_id LIKE '00000000-0000-0000-0001-%';")?;
        Ok(())
    }).unwrap();
    assert_eq!(
        tx.query_row::<i64, _, _>(
            "SELECT COUNT(*) FROM authority_signing_quota_reservations",
            [],
            |r| r.get(0)
        )
        .unwrap(),
        10002
    );
    // account itself must refuse, independently of the later quota ceilings.
    assert!(matches!(
        account(&tx, &f.tenant, AccountingScope::Root(&id(10)), NOW, None),
        Err(AuthorityError::Quota)
    ));
}
