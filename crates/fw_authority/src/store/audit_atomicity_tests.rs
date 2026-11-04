//! Real API transactions fail at their audit write after composing mutations.
//! Private connection hooks inject faults without changing released schema or
//! introducing a production fault switch. Reopen restores the normal observer.
use super::super::signing_test_support::{
    Fixture, NOW,
    authenticator::{Authenticator, ORIGIN, PRINCIPAL},
};
use super::*;
use crate::{ApprovalDecision, ApprovalRole};
use rusqlite::hooks::{Action, AuthAction, AuthContext, Authorization};
use std::{
    collections::BTreeSet,
    sync::{
        Arc, Mutex,
        atomic::{AtomicUsize, Ordering},
    },
};

fn snapshot(db: &Connection) -> Vec<Vec<Vec<rusqlite::types::Value>>> {
    [
        "authority_credentials",
        "authority_activations",
        "authority_challenges",
        "authority_evidence",
        "authority_decisions",
        "authority_approval_sets",
        "authority_approval_set_members",
        "authority_set_heads",
        "authority_admission_results",
        "authority_decision_revocations",
        "authority_set_revocations",
        "authority_projects",
        "authority_audit",
        "authority_audit_heads",
    ]
    .map(|table| {
        let mut query = db
            .prepare(&format!("SELECT rowid,* FROM {table} ORDER BY rowid"))
            .unwrap();
        let columns = query.column_count();
        query
            .query_map([], |row| {
                (0..columns).map(|column| row.get(column)).collect()
            })
            .unwrap()
            .collect::<rusqlite::Result<Vec<_>>>()
            .unwrap()
    })
    .into()
}

#[derive(Default)]
struct FaultEvidence {
    attempts: AtomicUsize,
    changed: Mutex<BTreeSet<String>>,
}

fn reject_audit(store: &AuthorityStore, nth: usize) -> Arc<FaultEvidence> {
    let evidence = Arc::new(FaultEvidence::default());
    let observed = evidence.clone();
    store
        .connection
        .update_hook(Some(move |_: Action, _: &str, table: &str, _: i64| {
            observed.changed.lock().unwrap().insert(table.to_owned());
        }));
    let observed = evidence.clone();
    store
        .connection
        .authorizer(Some(move |context: AuthContext<'_>| {
            if matches!(
                context.action,
                AuthAction::Insert {
                    table_name: "authority_audit"
                }
            ) && observed.attempts.fetch_add(1, Ordering::SeqCst) + 1 == nth
            {
                Authorization::Deny
            } else {
                Authorization::Allow
            }
        }));
    evidence
}

fn assert_actual_fault(
    error: AuthorityError,
    evidence: &FaultEvidence,
    nth: usize,
    changed: &[&str],
) {
    assert!(
        matches!(error, AuthorityError::Storage(rusqlite::Error::SqliteFailure(ref code, _))
        if code.code == rusqlite::ErrorCode::AuthorizationForStatementDenied),
        "{error:?}"
    );
    assert_eq!(evidence.attempts.load(Ordering::SeqCst), nth);
    let observed = evidence.changed.lock().unwrap();
    for table in changed {
        assert!(
            observed.contains(*table),
            "no pending mutation of {table}: {observed:?}"
        );
    }
}

fn current(f: &mut Fixture) -> Value {
    f.store
        .current_approval_set(
            &f.tenant,
            f.plan["plan_id"].as_str().unwrap(),
            &f.verifier,
            NOW,
        )
        .unwrap()
        .unwrap()
        .content()
        .clone()
}

#[test]
fn audit_insert_failure_rolls_back_real_set_and_decision_withdrawals() {
    for withdraw_set in [false, true] {
        let mut f = Fixture::new();
        let retained = current(&mut f);
        let approval = retained["approvals"][0]["approval_id"].as_str().unwrap();
        let set = retained["approval_set_id"].as_str().unwrap();
        let before = snapshot(&f.store.connection);
        let evidence = reject_audit(&f.store, 1);
        let error = if withdraw_set {
            f.store
                .revoke_approval_set(&f.tenant, set, PRINCIPAL, NOW)
                .unwrap_err()
        } else {
            f.store
                .revoke_decision(&f.tenant, approval, PRINCIPAL, NOW)
                .unwrap_err()
        };
        let tombstones = if withdraw_set {
            "authority_set_revocations"
        } else {
            "authority_decision_revocations"
        };
        assert_actual_fault(error, &evidence, 1, &[tombstones, "authority_projects"]);
        assert_eq!(snapshot(&f.store.connection), before);
        f.reopen();
        assert_eq!(current(&mut f), retained);
        for _ in 0..2 {
            if withdraw_set {
                f.store
                    .revoke_approval_set(&f.tenant, set, PRINCIPAL, NOW)
                    .unwrap();
            } else {
                f.store
                    .revoke_decision(&f.tenant, approval, PRINCIPAL, NOW)
                    .unwrap();
            }
        }
        assert_eq!(f.count(tombstones), 1);
        assert!(
            f.store
                .current_approval_set(
                    &f.tenant,
                    f.plan["plan_id"].as_str().unwrap(),
                    &f.verifier,
                    NOW
                )
                .unwrap()
                .is_none()
        );
        f.reopen();
        assert_eq!(f.count(tombstones), 1);
    }
}

#[test]
fn audit_insert_failure_rolls_back_genuine_credential_activation() {
    let mut f = Fixture::new();
    let key = Authenticator::new(PRINCIPAL);
    let registration = f
        .verifier
        .begin_registration(PRINCIPAL, "Atomic activation", &[])
        .unwrap();
    let credential = f
        .verifier
        .finish_registration(
            &registration.state,
            &key.registration(&registration.options),
        )
        .unwrap();
    f.store
        .pin_credential(&f.tenant, &credential, NOW, NOW + 7200, NOW)
        .unwrap();
    let activation = f
        .store
        .begin_credential_activation(&f.tenant, &credential.id(), &f.verifier, NOW)
        .unwrap();
    let response = key.assertion(&activation.options, 1, 0x05, ORIGIN);
    let before = snapshot(&f.store.connection);
    let evidence = reject_audit(&f.store, 1);
    let error = f
        .store
        .finish_credential_activation(
            &f.tenant,
            &activation.activation_id,
            &response,
            &f.verifier,
            NOW,
        )
        .unwrap_err();
    assert_actual_fault(
        error,
        &evidence,
        1,
        &[
            "authority_credentials",
            "authority_activations",
            "authority_projects",
        ],
    );
    assert_eq!(snapshot(&f.store.connection), before);
    f.reopen();
    f.store
        .finish_credential_activation(
            &f.tenant,
            &activation.activation_id,
            &response,
            &f.verifier,
            NOW,
        )
        .unwrap();
    assert!(matches!(
        f.store.finish_credential_activation(
            &f.tenant,
            &activation.activation_id,
            &response,
            &f.verifier,
            NOW
        ),
        Err(AuthorityError::Conflict)
    ));
    f.reopen();
    let active: String = f
        .store
        .connection
        .query_row(
            "SELECT state FROM authority_credentials WHERE credential_id=?",
            [credential.id()],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(active, "active");
}

#[test]
fn audit_insert_failures_roll_back_genuine_decision_and_composed_approval_set() {
    for nth in [1, 2] {
        let mut f = Fixture::new();
        let original = current(&mut f);
        f.store
            .revoke_decision(
                &f.tenant,
                original["approvals"][0]["approval_id"].as_str().unwrap(),
                PRINCIPAL,
                NOW,
            )
            .unwrap();
        let plan = f.plan["plan_id"].as_str().unwrap().to_owned();
        let issued = f
            .store
            .issue_challenge(
                &f.tenant,
                PRINCIPAL,
                &f.credential_id,
                &plan,
                ApprovalRole::Owner,
                ApprovalDecision::Approve,
                &f.verifier,
                NOW,
            )
            .unwrap();
        let response = f.principal_key.assertion(&issued.options, 3, 0x05, ORIGIN);
        let idempotency = new_id().unwrap();
        let before = snapshot(&f.store.connection);
        // First INSERT records the newly composed set; the second records the
        // decision after the first audit and head have already been written.
        let evidence = reject_audit(&f.store, nth);
        let error = match f.store.admit_decision(
            &f.tenant,
            PRINCIPAL,
            issued.challenge.challenge_id(),
            &idempotency,
            &response,
            &f.verifier,
            NOW,
        ) {
            Err(error) => error,
            Ok(_) => panic!("decision survived audit failure {nth}"),
        };
        let mut changed = vec![
            "authority_credentials",
            "authority_challenges",
            "authority_evidence",
            "authority_decisions",
            "authority_approval_sets",
            "authority_approval_set_members",
            "authority_set_heads",
        ];
        if nth == 2 {
            changed.extend([
                "authority_admission_results",
                "authority_audit",
                "authority_audit_heads",
            ]);
        }
        assert_actual_fault(error, &evidence, nth, &changed);
        assert_eq!(snapshot(&f.store.connection), before);
        f.reopen();
        let admitted = f
            .store
            .admit_decision(
                &f.tenant,
                PRINCIPAL,
                issued.challenge.challenge_id(),
                &idempotency,
                &response,
                &f.verifier,
                NOW,
            )
            .unwrap();
        assert!(!admitted.replayed);
        assert!(matches!(
            admitted.aggregation,
            sets::AggregationOutcome::Approved { .. }
        ));
        let committed = snapshot(&f.store.connection);
        assert!(
            f.store
                .admit_decision(
                    &f.tenant,
                    PRINCIPAL,
                    issued.challenge.challenge_id(),
                    &idempotency,
                    &response,
                    &f.verifier,
                    NOW
                )
                .unwrap()
                .replayed
        );
        assert_eq!(snapshot(&f.store.connection), committed);
    }
}
