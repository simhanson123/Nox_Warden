use super::*;
use crate::store::signing_test_support::{Fixture, NOW};

fn append(store: &mut AuthorityStore, tenant: &AuthorityTenant, resource: &str) {
    let tx = store
        .connection
        .transaction_with_behavior(TransactionBehavior::Immediate)
        .unwrap();
    audit(&tx, tenant, "fixture_live_integrity", resource, NOW).unwrap();
    tx.commit().unwrap();
}

#[test]
fn ordinary_local_commits_reuse_evidence_and_peer_commits_require_revalidation() {
    use std::sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    };

    fn change_during_validations(
        mut peer: AuthorityStore,
        tenant: AuthorityTenant,
        remaining: usize,
        changes: Arc<AtomicUsize>,
    ) {
        migrations::OPEN_VALIDATION_HOOK.with(|hook| {
            *hook.borrow_mut() = Some(Box::new(move || {
                append(&mut peer, &tenant, "during-repeated-validation-race");
                changes.fetch_add(1, Ordering::SeqCst);
                if remaining > 1 {
                    change_during_validations(peer, tenant, remaining - 1, changes);
                }
            }));
        });
    }

    let mut f = Fixture::new();
    assert!(!f.store.connection.is_forensic_arithmetic_fixture());
    let before = f.store.connection.validations.get();
    for _ in 0..3 {
        append(&mut f.store, &f.tenant, "local");
    }
    assert_eq!(f.store.connection.validations.get(), before);
    let mut peer = AuthorityStore::open(&f.path).unwrap();
    append(&mut peer, &f.tenant, "peer");
    append(&mut f.store, &f.tenant, "after-peer");
    assert_eq!(f.store.connection.validations.get(), before + 1);
    append(&mut f.store, &f.tenant, "reuse-after-peer");
    assert_eq!(f.store.connection.validations.get(), before + 1);

    // A healthy writer may commit during the stale reader's complete check.
    // Preserve the old snapshot token and automatically acquire a newly
    // validated writer snapshot after the single peer commit.
    append(&mut peer, &f.tenant, "stale-before-race");
    let tenant = f.tenant.clone();
    migrations::OPEN_VALIDATION_HOOK.with(|hook| {
        *hook.borrow_mut() = Some(Box::new(move || {
            append(&mut peer, &tenant, "during-validation-race");
        }));
    });
    let before_race = f.store.connection.validations.get();
    f.store
        .connection
        .transaction_with_behavior(TransactionBehavior::Immediate)
        .unwrap()
        .commit()
        .unwrap();
    assert_eq!(f.store.connection.validations.get(), before_race + 2);
    append(&mut f.store, &f.tenant, "after-automatic-retry");

    // Continuous healthy changes exhaust the finite writer attempt budget.
    let mut peer = AuthorityStore::open(&f.path).unwrap();
    append(&mut peer, &f.tenant, "stale-before-continuous-race");
    let changes = Arc::new(AtomicUsize::new(0));
    change_during_validations(
        peer,
        f.tenant.clone(),
        WRITER_SNAPSHOT_ATTEMPTS,
        changes.clone(),
    );
    assert!(matches!(
        f.store
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate),
        Err(AuthorityError::Conflict)
    ));
    assert_eq!(changes.load(Ordering::SeqCst), WRITER_SNAPSHOT_ATTEMPTS);
    assert!(f.store.connection.validated.get().is_none());
    append(&mut f.store, &f.tenant, "retry-after-race");

    // A corrupt peer change must be rejected by the next deferred validation,
    // without consuming the remaining attempts or executing operation writes.
    let mut peer = AuthorityStore::open(&f.path).unwrap();
    append(&mut peer, &f.tenant, "stale-before-corrupt-race");
    let audit_count = f.count("authority_audit");
    let before_corruption = f.store.connection.validations.get();
    let path = f.path.clone();
    migrations::OPEN_VALIDATION_HOOK.with(|hook| {
        *hook.borrow_mut() = Some(Box::new(move || {
            let mut raw = Connection::open(&path).unwrap();
            let guard: String = raw.query_row("SELECT sql FROM sqlite_schema WHERE name='authority_audit_no_update'", [], |row| row.get(0)).unwrap();
            let tx = raw.transaction().unwrap();
            tx.execute_batch("DROP TRIGGER authority_audit_no_update").unwrap();
            tx.execute("UPDATE authority_audit SET canonical_bytes=x'7b7d' WHERE rowid=(SELECT MIN(rowid) FROM authority_audit)", []).unwrap();
            tx.execute_batch(&guard).unwrap();
            tx.commit().unwrap();
        }));
    });
    assert!(matches!(
        f.store
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate),
        Err(AuthorityError::Invalid(_))
    ));
    assert_eq!(f.store.connection.validations.get(), before_corruption + 1);
    assert!(f.store.connection.validated.get().is_none());
    assert_eq!(f.count("authority_audit"), audit_count);
}

#[test]
fn deferred_data_version_stays_bound_to_its_snapshot_and_does_not_mask_a_peer_commit() {
    let mut f = Fixture::new();
    let before = f.store.connection.validations.get();
    let mut peer = AuthorityStore::open(&f.path).unwrap();
    let tx = f.store.connection.transaction().unwrap();
    let version = data_version(&tx).unwrap();
    let count: i64 = tx
        .query_row("SELECT count(*) FROM authority_audit", [], |row| row.get(0))
        .unwrap();
    append(&mut peer, &f.tenant, "while-reader-is-open");
    assert_eq!(data_version(&tx).unwrap(), version);
    assert_eq!(
        tx.query_row::<i64, _, _>("SELECT count(*) FROM authority_audit", [], |row| row.get(0))
            .unwrap(),
        count
    );
    tx.commit().unwrap();
    append(&mut f.store, &f.tenant, "next-snapshot");
    assert_eq!(f.store.connection.validations.get(), before + 1);
}

#[test]
fn rollback_keeps_only_validated_committed_evidence() {
    let mut f = Fixture::new();
    let before = f.store.connection.validations.get();
    {
        let tx = f
            .store
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .unwrap();
        audit(&tx, &f.tenant, "fixture_rolled_back", "rollback", NOW).unwrap();
        tx.rollback().unwrap();
    }
    append(&mut f.store, &f.tenant, "after-rollback");
    assert_eq!(f.store.connection.validations.get(), before);
    assert_eq!(
        f.store
            .connection
            .query_row::<i64, _, _>(
                "SELECT count(*) FROM authority_audit WHERE kind='fixture_rolled_back'",
                [],
                |row| row.get(0)
            )
            .unwrap(),
        0
    );
}

#[test]
fn preparing_an_unsafe_statement_permanently_invalidates_that_connection() {
    let mut f = Fixture::new();
    let prepared = f
        .store
        .connection
        .prepare("DROP TRIGGER authority_signing_quota_transition_heads_update")
        .unwrap();
    // The statement has not executed. Even an unchecked constructor must not
    // clear preparation-time taint and let that statement execute afterward.
    assert!(f.store.connection.unchecked_transaction().is_err());
    drop(prepared);
    assert!(f.store.connection.transaction().is_err());
    assert!(
        f.store
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .is_err()
    );
    // Reopening establishes independent evidence of the still-valid database.
    let mut reopened = AuthorityStore::open(&f.path).unwrap();
    append(&mut reopened, &f.tenant, "reopened");
}

#[test]
fn unsafe_preparation_inside_a_live_transaction_is_denied_before_execution() {
    let mut f = Fixture::new();
    let tx = f.store.connection.transaction().unwrap();
    assert!(
        tx.prepare("DROP TRIGGER authority_signing_quota_transition_heads_update")
            .is_err()
    );
    tx.rollback().unwrap();
    assert!(f.store.connection.transaction().is_err());
    assert!(AuthorityStore::open(&f.path).is_ok());
}

#[test]
fn restoring_an_intact_local_guard_requires_independent_reopen_validation() {
    let mut f = Fixture::new();
    let sql: String = f.store.connection.query_row(
        "SELECT sql FROM sqlite_schema WHERE name='authority_signing_quota_transition_heads_update'",
        [],
        |row| row.get(0),
    ).unwrap();
    f.store
        .connection
        .execute_batch("DROP TRIGGER authority_signing_quota_transition_heads_update")
        .unwrap();
    f.store.connection.execute_batch(&sql).unwrap();
    migrations::validate_live_schema(&f.store.connection).unwrap();
    assert!(f.store.connection.transaction().is_err());
    let mut reopened = AuthorityStore::open(&f.path).unwrap();
    append(&mut reopened, &f.tenant, "restored-intact-guard");
}
