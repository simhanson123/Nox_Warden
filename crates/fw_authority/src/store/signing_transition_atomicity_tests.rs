// Real cancellation and verified issuance reach the quota-transition write
// after mutating work/audit/result state. Private SQLite hooks inject a failure
// without altering the released schema or adding production fault controls.
use super::*;
use rusqlite::{
    OpenFlags,
    hooks::{Action, AuthAction, AuthContext, Authorization},
    types::Value as SqlValue,
};
use std::sync::{
    Arc, Mutex,
    atomic::{AtomicUsize, Ordering},
};

type Rows = Vec<Vec<SqlValue>>;

#[derive(Clone, Debug, PartialEq)]
struct Retained {
    schema: Rows,
    tables: Vec<(String, Rows)>,
}

fn rows(db: &Connection, sql: &str) -> Rows {
    let mut query = db.prepare(sql).unwrap();
    let columns = query.column_count();
    query
        .query_map([], |row| (0..columns).map(|index| row.get(index)).collect())
        .unwrap()
        .collect::<rusqlite::Result<_>>()
        .unwrap()
}

fn retained(f: &signing_test_support::Fixture) -> Retained {
    // An independent reader observes only retained rows after the failing API
    // has dropped its transaction. Value preserves NULL/INTEGER/TEXT/BLOB, and
    // rowid,* includes each hidden identity and every canonical/signature byte.
    let db = Connection::open_with_flags(&f.path, OpenFlags::SQLITE_OPEN_READ_ONLY).unwrap();
    let tables = db
        .prepare("SELECT name FROM sqlite_schema WHERE type='table' AND name NOT LIKE 'sqlite_%' ORDER BY name")
        .unwrap()
        .query_map([], |row| row.get::<_, String>(0))
        .unwrap()
        .collect::<rusqlite::Result<Vec<_>>>()
        .unwrap()
        .into_iter()
        .map(|table| {
            let sql = format!(
                "SELECT rowid,* FROM \"{}\" ORDER BY rowid",
                table.replace('"', "\"\"")
            );
            let values = rows(&db, &sql);
            (table, values)
        })
        .collect();
    Retained {
        schema: rows(&db, "SELECT rowid,* FROM sqlite_schema ORDER BY rowid"),
        tables,
    }
}

impl Retained {
    fn with_observed_quota_clocks(mut self, tenant: &AuthorityTenant, now: i64) -> Self {
        let (_, clocks) = self
            .tables
            .iter_mut()
            .find(|(table, _)| table == "authority_signing_quota_clocks")
            .unwrap();
        assert_eq!(clocks.len(), 2);
        for row in clocks {
            assert_eq!(row.len(), 5);
            assert_eq!(row[1], SqlValue::Text(tenant.org_id.clone()));
            match &row[2] {
                SqlValue::Text(kind) if kind == "project" => {
                    assert_eq!(row[3], SqlValue::Text(tenant.project_id.clone()));
                }
                SqlValue::Text(kind) if kind == "root" => {
                    assert_eq!(
                        row[3],
                        SqlValue::Text("aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa".into())
                    );
                }
                kind => panic!("unexpected quota clock: {kind:?}"),
            }
            assert_eq!(row[4], SqlValue::Integer(NOW));
            row[4] = SqlValue::Integer(now);
        }
        self
    }
}

#[derive(Default)]
struct FaultEvidence {
    attempts: AtomicUsize,
    changed: Mutex<BTreeSet<String>>,
    prior_commits: Mutex<BTreeSet<String>>,
    before_denial: Mutex<Option<BTreeSet<String>>>,
}

fn reject_transition(f: &signing_test_support::Fixture) -> Arc<FaultEvidence> {
    assert!(!f.store.connection.is_forensic_arithmetic_fixture());
    let evidence = Arc::new(FaultEvidence::default());
    let observed = evidence.clone();
    f.store.connection.update_hook(Some(
        move |_: Action, database: &str, table: &str, _: i64| {
            assert_eq!(database, "main");
            observed.changed.lock().unwrap().insert(table.to_owned());
        },
    ));
    let observed = evidence.clone();
    f.store.connection.commit_hook(Some(move || {
        // Public cancellation observes quota time in preceding transactions.
        // Keep their writes separate from the pending transaction denied below.
        let committed = std::mem::take(&mut *observed.changed.lock().unwrap());
        observed.prior_commits.lock().unwrap().extend(committed);
        false
    }));
    let observed = evidence.clone();
    // Installing this authorizer expires cached SQLite VMs. record_transition
    // itself uses uncached tx.execute; its preceding cached statements only
    // read. An authorization count alone is still not execution evidence:
    // capture prior update-hook mutations at denial, before rollback starts.
    f.store
        .connection
        .authorizer(Some(move |context: AuthContext<'_>| {
            if matches!(
                context.action,
                AuthAction::Insert {
                    table_name: "authority_signing_quota_transitions"
                }
            ) {
                assert_eq!(context.database_name, Some("main"));
                assert_eq!(
                    context.accessor, None,
                    "expected the direct transition write"
                );
                observed.attempts.fetch_add(1, Ordering::SeqCst);
                *observed.before_denial.lock().unwrap() =
                    Some(observed.changed.lock().unwrap().clone());
                Authorization::Deny
            } else {
                Authorization::Allow
            }
        }));
    evidence
}

fn assert_late_failure(error: AuthorityError, evidence: &FaultEvidence, issuance: bool) {
    assert!(
        matches!(error, AuthorityError::Storage(rusqlite::Error::SqliteFailure(ref code, _))
            if code.code == rusqlite::ErrorCode::AuthorizationForStatementDenied
                && code.extended_code == rusqlite::ffi::SQLITE_AUTH),
        "{error:?}"
    );
    assert_eq!(evidence.attempts.load(Ordering::SeqCst), 1);
    let expected_committed: BTreeSet<String> = if issuance {
        // The finalize helper has no independent observation transactions.
        BTreeSet::new()
    } else {
        ["authority_signing_quota_clocks".to_owned()].into()
    };
    assert_eq!(*evidence.prior_commits.lock().unwrap(), expected_committed);
    let before_denial = evidence.before_denial.lock().unwrap();
    let changed = before_denial
        .as_ref()
        .expect("transition write was not reached");
    for table in [
        "authority_audit",
        "authority_audit_heads",
        "authority_signing_work_events",
        "authority_signing_work_heads",
        "authority_signing_work_audits",
        "authority_signing_quota_clocks",
    ] {
        assert!(
            changed.contains(table),
            "no prior mutation of {table}: {changed:?}"
        );
    }
    for table in [
        "authority_signing_results",
        "authority_signing_outbox",
        "authority_signing_quota_usage",
    ] {
        assert_eq!(changed.contains(table), issuance, "{table}: {changed:?}");
    }
    for table in [
        // Work audit appends do not bump the project's security revision;
        // finalize's current-input checks also only read that revision.
        "authority_projects",
        "authority_signing_quota_transitions",
        "authority_signing_quota_transition_heads",
        "authority_signing_quota_reservations",
    ] {
        assert!(
            !changed.contains(table),
            "transition effect preceded denial: {changed:?}"
        );
    }
}

#[test]
fn failed_transition_rolls_back_cancellation_and_issuance_with_work_evidence() {
    for issuance in [false, true] {
        let (mut f, job, reservation) = real_reservation("reserved");
        let claim = {
            let tx = f.store.connection.transaction().unwrap();
            let claim =
                signing_jobs::fixture_claim(&tx, &f.tenant, &job, "signer", &id(90), 0, 60, NOW)
                    .unwrap();
            tx.commit().unwrap();
            claim
        };
        let signed = issuance.then(|| {
            let intent: String = f
                .store
                .connection
                .query_row(
                    "SELECT intent_id FROM authority_signing_jobs WHERE job_id=?",
                    [&job],
                    |row| row.get(0),
                )
                .unwrap();
            // The immutable payload was prepared at NOW. Sign at that original
            // time; finalization at NOW+1 verifies the same retained bytes.
            signing_intents::test_sign(&mut f, &intent, NOW)
        });
        let before = retained(&f);
        let expected = if issuance {
            // This existing test helper exercises the genuine finalize
            // transaction; its clock writes belong to that same transaction.
            before.clone()
        } else {
            // Public cancellation commits its independent project/root clock
            // observations before entering the transaction under test.
            before
                .clone()
                .with_observed_quota_clocks(&f.tenant, NOW + 1)
        };
        let evidence = reject_transition(&f);
        {
            // A normal validated transaction and retained read still succeed.
            // Prevalidation/cached SQL preparation cannot satisfy the fault
            // counter, and this read executes no pending mutation.
            let tx = f.store.connection.transaction().unwrap();
            assert_eq!(
                read(&tx, &f.tenant, &reservation).unwrap().state,
                "reserved"
            );
            tx.commit().unwrap();
            assert_eq!(evidence.attempts.load(Ordering::SeqCst), 0);
            assert!(evidence.changed.lock().unwrap().is_empty());
        }
        let error = if issuance {
            signing_intents::test_finalize_result(&mut f, &claim, signed.as_ref().unwrap(), NOW + 1)
                .unwrap_err()
        } else {
            f.store
                .cancel_signing_job(&f.tenant, &job, NOW + 1)
                .unwrap_err()
        };
        assert_late_failure(error, &evidence, issuance);
        assert_eq!(retained(&f), expected);
        f.reopen();
        assert!(!f.store.connection.is_forensic_arithmetic_fixture());
        assert_eq!(retained(&f), expected);
        {
            let tx = f.store.connection.transaction().unwrap();
            let quota = read(&tx, &f.tenant, &reservation).unwrap();
            assert_eq!(quota.state, "reserved");
            assert!(quota.issued_at.is_none());
            assert_eq!(quota.dispatch_slots, 1);
            let lifecycle = signing_jobs::lifecycle_status(&tx, &f.tenant, &job, NOW + 1).unwrap();
            assert_eq!(lifecycle.state, "claimed");
            assert!(lifecycle.quota_held);
        }
        if issuance {
            let issued = signing_intents::test_finalize_result(
                &mut f,
                &claim,
                signed.as_ref().unwrap(),
                NOW + 1,
            )
            .unwrap();
            assert!(!issued.replayed);
            assert_eq!(issued.intent.reservation_state, "issued");
            assert_eq!(f.count("authority_signing_results"), 1);
            assert_eq!(f.count("authority_signing_outbox"), 1);
            assert_eq!(f.count("authority_signing_quota_usage"), 1);
        } else {
            f.store
                .cancel_signing_job(&f.tenant, &job, NOW + 1)
                .unwrap();
            assert_eq!(f.count("authority_signing_results"), 0);
            assert_eq!(f.count("authority_signing_outbox"), 0);
            assert_eq!(f.count("authority_signing_quota_usage"), 0);
        }
        assert_eq!(f.count("authority_signing_quota_transitions"), 2);
        let committed = retained(&f);
        f.reopen();
        if issuance {
            assert!(
                signing_intents::test_finalize_result(
                    &mut f,
                    &claim,
                    signed.as_ref().unwrap(),
                    NOW + 1
                )
                .unwrap()
                .replayed
            );
            assert!(matches!(
                f.store.cancel_signing_job(&f.tenant, &job, NOW + 1),
                Err(AuthorityError::Conflict)
            ));
        } else {
            f.store
                .cancel_signing_job(&f.tenant, &job, NOW + 1)
                .unwrap();
        }
        assert_eq!(retained(&f), committed);
        let tx = f.store.connection.transaction().unwrap();
        let quota = read(&tx, &f.tenant, &reservation).unwrap();
        let lifecycle = signing_jobs::lifecycle_status(&tx, &f.tenant, &job, NOW + 1).unwrap();
        assert_eq!(quota.state, if issuance { "issued" } else { "released" });
        assert_eq!(quota.issued_at.is_some(), issuance);
        assert_eq!(quota.dispatch_slots, i64::from(issuance));
        assert_eq!(
            lifecycle.state,
            if issuance { "ready" } else { "cancelled" }
        );
        assert_eq!(lifecycle.quota_held, issuance);
        if issuance {
            // The only dispatch slot remains occupied after restart/replay and
            // refused cancellation. No issued capacity was refunded.
            assert!(matches!(
                reserve(&tx, &f.tenant, &id(21), &change(2), NOW + 301, NOW + 1),
                Err(AuthorityError::Quota)
            ));
        }
    }
}
