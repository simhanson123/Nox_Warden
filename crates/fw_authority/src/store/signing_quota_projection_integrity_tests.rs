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
    let (read_refused, history_refused, project_refused, root_refused, reserve_refused) = {
        let tx = f.store.connection.transaction().unwrap();
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
