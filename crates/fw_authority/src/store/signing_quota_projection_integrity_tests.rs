use super::*;

const ROOT: &str = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa";

fn genuine_obligation(
    project_only: bool,
    state: &str,
) -> (signing_test_support::Fixture, String, String, i64) {
    if !project_only && state != "active" {
        let (f, job, reservation) = real_reservation(state);
        return (f, job, reservation, NOW + i64::from(state == "unknown") * 6);
    }
    let mut f = signing_test_support::Fixture::new();
    if project_only {
        let mut cap = limits();
        cap.concurrent_deployments = 1;
        f.store
            .pin_signing_project_quota(
                &f.tenant,
                &SigningProjectQuotaPin {
                    root_id: None,
                    limits: cap,
                    not_before: NOW,
                    not_after: NOW + 7200,
                },
                None,
                NOW,
            )
            .unwrap();
    } else {
        signing_intents::test_initialize(&mut f, NOW);
        let mut cap = limits();
        cap.concurrent_deployments = 1;
        let pin = SigningRootQuotaPin {
            root_id: ROOT.into(),
            limits: cap,
            not_before: NOW,
            not_after: NOW + 7200,
        };
        f.store
            .pin_signing_root_quota(&f.tenant, &pin, Some(1), NOW)
            .unwrap();
        f.store
            .pin_signing_project_quota(&f.tenant, &pin, Some(1), NOW)
            .unwrap();
    }
    let prepared = signing_intents::test_prepare(&mut f, NOW);
    let job = prepared.intent.job_id;
    let reservation = prepared.intent.reservation_id;
    if state != "reserved" {
        let claim = {
            let tx = f.store.connection.transaction().unwrap();
            let claim =
                signing_jobs::fixture_claim(&tx, &f.tenant, &job, "signer", &id(90), 0, 60, NOW)
                    .unwrap();
            tx.commit().unwrap();
            claim
        };
        signing_intents::test_finalize(&mut f, &claim, NOW).unwrap();
        if state != "issued" {
            let tx = f.store.connection.transaction().unwrap();
            let claim =
                signing_jobs::fixture_claim(&tx, &f.tenant, &job, "dispatch", &id(91), 0, 60, NOW)
                    .unwrap();
            if state == "unknown" {
                signing_jobs::fixture_unknown(&tx, &f.tenant, &claim, NOW).unwrap();
            } else {
                signing_jobs::fixture_deliver(&tx, &f.tenant, &claim, NOW).unwrap();
            }
            tx.commit().unwrap();
        }
    }
    (f, job, reservation, NOW)
}

fn hide_head(connection: &Connection, reservation: &str) {
    let guard: String = connection
        .query_row(
            "SELECT sql FROM sqlite_schema WHERE name='authority_signing_quota_transition_heads_update'",
            [],
            |r| r.get(0),
        )
        .unwrap();
    connection
        .execute_batch("DROP TRIGGER authority_signing_quota_transition_heads_update")
        .unwrap();
    assert_eq!(
        connection
            .execute(
                "UPDATE authority_signing_quota_transition_heads SET state='released' WHERE reservation_id=?",
                [reservation],
            )
            .unwrap(),
        1
    );
    connection.execute_batch(&guard).unwrap();
}

fn assert_hidden_head_refused(project_only: bool, state: &str) {
    let (mut f, _, reservation, now) = genuine_obligation(project_only, state);
    hide_head(&f.store.connection, &reservation);
    assert!(f.store.connection.transaction().is_err());
    let (read_refused, history_refused, project_refused, root_refused, reserve_refused) = {
        // Inspect the damaged rows separately: the live connection now refuses
        // before returning any transaction to its caller.
        let mut forensic = Connection::open(&f.path).unwrap();
        let tx = forensic.transaction().unwrap();
        let read_refused = read(&tx, &f.tenant, &reservation).is_err();
        let history_refused = validate_retained_transitions(&tx).is_err();
        let project_refused = account(&tx, &f.tenant, AccountingScope::Project, now, None).is_err();
        let root_refused = project_only
            || account(&tx, &f.tenant, AccountingScope::Root(ROOT), now, None).is_err();
        let reserve_refused =
            reserve(&tx, &f.tenant, &id(999), &change(999), now + 300, now).is_err();
        (
            read_refused,
            history_refused,
            project_refused,
            root_refused,
            reserve_refused,
        )
    };
    let open_refused = AuthorityStore::open(&f.path).is_err();
    assert!(
        read_refused
            && history_refused
            && project_refused
            && root_refused
            && reserve_refused
            && open_refused,
        "scope={}, state={state}: read={read_refused}, history={history_refused}, project={project_refused}, root={root_refused}, reserve={reserve_refused}, open={open_refused}",
        if project_only {
            "project-only"
        } else {
            "rooted"
        }
    );
}

#[test]
fn restored_head_guard_reserved_membership_is_revalidated() {
    for project_only in [false, true] {
        assert_hidden_head_refused(project_only, "reserved");
    }
}

#[test]
fn restored_head_guard_issued_membership_is_revalidated() {
    for project_only in [false, true] {
        assert_hidden_head_refused(project_only, "issued");
    }
}

#[test]
fn restored_head_guard_unknown_membership_is_revalidated() {
    for project_only in [false, true] {
        assert_hidden_head_refused(project_only, "unknown");
    }
}

#[test]
fn restored_head_guard_unsigned_delivery_membership_is_revalidated() {
    for project_only in [false, true] {
        assert_hidden_head_refused(project_only, "active");
    }
}

#[test]
fn a_committed_intentless_reservation_is_refused_by_open_reads_and_admission() {
    assert!(!PRIMITIVE_QUOTA_FIXTURE.get());
    let mut f = signing_test_support::Fixture::new();
    signing_intents::test_initialize(&mut f, NOW);
    let reservation = id(999);
    {
        let tx = f.store.connection.transaction().unwrap();
        let cost = cost_for_plan(&tx, &f.tenant, f.plan["plan_id"].as_str().unwrap(), NOW).unwrap();
        // Exercise the private same-transaction preparation step, then model
        // an invalid commit which omits its required intent/job/genesis.
        reserve(&tx, &f.tenant, &reservation, &cost, NOW + 300, NOW).unwrap();
        tx.commit().unwrap();
    }
    let (read_refused, history_refused, account_refused) = {
        assert!(!PRIMITIVE_QUOTA_FIXTURE.get());
        let tx = f.store.connection.transaction().unwrap();
        (
            read(&tx, &f.tenant, &reservation).is_err(),
            validate_retained_transitions(&tx).is_err(),
            account(&tx, &f.tenant, AccountingScope::Project, NOW, None).is_err(),
        )
    };
    assert!(!PRIMITIVE_QUOTA_FIXTURE.get());
    let open_refused = AuthorityStore::open(&f.path).is_err();
    let backup = f
        .directory
        .path()
        .join("orphan-before-rejected-maintenance.sqlite3");
    let maintenance_refused = AuthorityStore::migrate(&f.path, backup).is_err();
    assert!(
        read_refused && history_refused && account_refused && open_refused && maintenance_refused,
        "read={read_refused}, history={history_refused}, account={account_refused}, open={open_refused}, maintenance={maintenance_refused}"
    );
}

fn hide_both_projections(connection: &Connection, reservation: &str) {
    let guards = connection.prepare("SELECT name,sql FROM sqlite_schema WHERE type='trigger' AND tbl_name IN ('authority_signing_quota_reservations','authority_signing_quota_transition_heads') ORDER BY name")
        .unwrap().query_map([], |row| Ok((row.get::<_,String>(0)?, row.get::<_,String>(1)?)))
        .unwrap().collect::<rusqlite::Result<Vec<_>>>().unwrap();
    for (name, _) in &guards {
        connection
            .execute_batch(&format!("DROP TRIGGER {name}"))
            .unwrap();
    }
    assert_eq!(connection.execute("UPDATE authority_signing_quota_reservations SET state='released',active_slots=0,dispatch_slots=0,issued_at=NULL WHERE reservation_id=?", [reservation]).unwrap(), 1);
    assert_eq!(connection.execute("UPDATE authority_signing_quota_transition_heads SET state='released',issued_at=NULL WHERE reservation_id=?", [reservation]).unwrap(), 1);
    for (_, sql) in guards {
        connection.execute_batch(&sql).unwrap();
    }
    migrations::validate_live_schema(connection).unwrap();
}

fn empty_membership_index(connection: &Connection, index: &str) {
    let original: String = connection
        .query_row(
            "SELECT sql FROM sqlite_schema WHERE name=?",
            [index],
            |row| row.get(0),
        )
        .unwrap();
    let empty = if original.contains("WHERE ") {
        original.replacen("WHERE ", "WHERE 0 AND ", 1)
    } else {
        format!("{original} WHERE 0")
    };
    connection
        .execute_batch("PRAGMA writable_schema=ON")
        .unwrap();
    connection
        .execute(
            "UPDATE sqlite_schema SET sql=? WHERE name=?",
            params![empty, index],
        )
        .unwrap();
    connection
        .execute_batch("PRAGMA writable_schema=RESET")
        .unwrap();
    connection
        .execute_batch(&format!("REINDEX {index}"))
        .unwrap();
    connection
        .execute_batch("PRAGMA writable_schema=ON")
        .unwrap();
    connection
        .execute(
            "UPDATE sqlite_schema SET sql=? WHERE name=?",
            params![original, index],
        )
        .unwrap();
    connection
        .execute_batch("PRAGMA writable_schema=RESET")
        .unwrap();
}

fn membership_indexes(project_only: bool) -> Vec<&'static str> {
    let mut indexes = vec![
        "authority_signing_quota_project_states",
        "authority_signing_quota_transition_project_held",
    ];
    if !project_only {
        indexes.extend([
            "authority_signing_quota_root_states",
            "authority_signing_quota_transition_root_held",
        ]);
    }
    indexes
}

fn new_admission(f: &mut signing_test_support::Fixture, now: i64) -> Result<()> {
    let tx = f
        .store
        .connection
        .transaction_with_behavior(TransactionBehavior::Immediate)?;
    reserve(&tx, &f.tenant, &id(999), &change(999), now + 300, now)?;
    tx.commit()?;
    Ok(())
}

#[test]
fn peer_hiding_both_quota_projections_with_restored_guards_refuses_live_admission() {
    for project_only in [false, true] {
        for state in ["reserved", "issued", "unknown", "active"] {
            let (mut f, _, reservation, now) = genuine_obligation(project_only, state);
            assert!(!f.store.connection.is_forensic_arithmetic_fixture());
            assert!(matches!(
                new_admission(&mut f, now),
                Err(AuthorityError::Quota)
            ));
            let peer = Connection::open(&f.path).unwrap();
            hide_both_projections(&peer, &reservation);
            // Both bounded membership projections now agree on an empty set.
            // Complete snapshot evidence, not a third mutable index, refuses it.
            for _ in 0..2 {
                let error = new_admission(&mut f, now).unwrap_err();
                assert!(
                    matches!(error, AuthorityError::Invalid(_)),
                    "{project_only}/{state}: {error}"
                );
            }
            assert!(AuthorityStore::open(&f.path).is_err());
            assert_eq!(
                peer.query_row::<i64, _, _>(
                    "SELECT count(*) FROM authority_signing_quota_reservations NOT INDEXED",
                    [],
                    |row| row.get(0)
                )
                .unwrap(),
                1
            );
        }
    }
}

#[test]
fn jointly_empty_membership_indexes_refuse_live_admission_and_recheck_after_repair() {
    for project_only in [false, true] {
        for state in ["reserved", "issued", "unknown", "active"] {
            let (mut f, _, _, now) = genuine_obligation(project_only, state);
            assert!(!f.store.connection.is_forensic_arithmetic_fixture());
            let peer = Connection::open(&f.path).unwrap();
            let indexes = membership_indexes(project_only);
            for index in &indexes {
                empty_membership_index(&peer, index);
            }
            migrations::validate_live_schema(&peer).unwrap();
            // quick_check can notice wrong nonpartial index counts, but it
            // does not establish complete physical index membership. These
            // emptied held partial indexes still pass its table-scoped check.
            let source_quick: String = peer
                .query_row(
                    "PRAGMA quick_check(authority_signing_quota_reservations)",
                    [],
                    |row| row.get(0),
                )
                .unwrap();
            assert!(
                source_quick.starts_with("wrong # of entries in index authority_signing_quota_"),
                "{source_quick}"
            );
            assert_eq!(
                peer.query_row::<String, _, _>(
                    "PRAGMA quick_check(authority_signing_quota_transition_heads)",
                    [],
                    |row| row.get(0)
                )
                .unwrap(),
                "ok"
            );
            assert_ne!(
                peer.query_row::<String, _, _>("PRAGMA integrity_check(1)", [], |row| row.get(0))
                    .unwrap(),
                "ok"
            );
            for _ in 0..2 {
                assert!(matches!(
                    new_admission(&mut f, now),
                    Err(AuthorityError::Invalid(_))
                ));
            }
            assert!(AuthorityStore::open(&f.path).is_err());
            // Explicit external repair is not performed by refusal. It must be
            // validated afresh and must preserve the held quota, without refund.
            for index in &indexes {
                peer.execute_batch(&format!("REINDEX {index}")).unwrap();
            }
            assert_eq!(
                peer.query_row::<String, _, _>("PRAGMA integrity_check(1)", [], |row| row.get(0))
                    .unwrap(),
                "ok"
            );
            assert!(matches!(
                new_admission(&mut f, now),
                Err(AuthorityError::Quota)
            ));
            for index in &indexes {
                empty_membership_index(&peer, index);
            }
            assert!(matches!(
                new_admission(&mut f, now),
                Err(AuthorityError::Invalid(_))
            ));
        }
    }
}
