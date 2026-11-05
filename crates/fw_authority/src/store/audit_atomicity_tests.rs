//! Real API faults cover exact retained writes and rollback of prior statements.
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

type RetainedRows = Vec<(String, Vec<Vec<rusqlite::types::Value>>)>;

fn snapshot(db: &Connection) -> RetainedRows {
    let tables = db
        .prepare("SELECT name FROM sqlite_schema WHERE type='table' AND name GLOB 'authority_*' ORDER BY name")
        .unwrap()
        .query_map([], |row| row.get::<_, String>(0))
        .unwrap()
        .collect::<rusqlite::Result<Vec<_>>>()
        .unwrap();
    tables
        .into_iter()
        .map(|table| {
            let mut query = db
                .prepare(&format!("SELECT rowid,* FROM {table} ORDER BY rowid"))
                .unwrap();
            let columns = query.column_count();
            let rows = query
                .query_map([], |row| {
                    (0..columns).map(|column| row.get(column)).collect()
                })
                .unwrap()
                .collect::<rusqlite::Result<Vec<_>>>()
                .unwrap();
            (table, rows)
        })
        .collect()
}

#[derive(Default)]
struct FaultEvidence {
    attempts: AtomicUsize,
    changed: Mutex<BTreeSet<String>>,
    writes: Mutex<Vec<(Action, String)>>,
}

#[derive(Clone, Copy, Debug)]
struct WriteFault {
    table: &'static str,
    // None means INSERT; Some(column) means UPDATE of exactly that column.
    column: Option<&'static str>,
    accessor: Option<&'static str>,
    nth: usize,
}

impl WriteFault {
    const fn insert(table: &'static str, nth: usize) -> Self {
        Self {
            table,
            column: None,
            accessor: None,
            nth,
        }
    }

    const fn update(table: &'static str, column: &'static str) -> Self {
        Self {
            table,
            column: Some(column),
            accessor: None,
            nth: 1,
        }
    }

    fn matches(self, context: AuthContext<'_>) -> bool {
        context.database_name == Some("main")
            && context.accessor == self.accessor
            && match context.action {
                AuthAction::Insert { table_name } => {
                    self.column.is_none() && table_name == self.table
                }
                AuthAction::Update {
                    table_name,
                    column_name,
                } => self.column == Some(column_name) && table_name == self.table,
                _ => false,
            }
    }
}

// The authorizer runs when the selected real statement is prepared, after all
// earlier statements have executed. It changes neither schema nor SQL guards.
// Reopening restores IntegrityConnection's normal authorizer. In particular,
// an audit-head denial targets preparation of the released AFTER-INSERT trigger;
// that audit row has not executed yet. The second-audit tests separately prove
// rollback after a complete earlier audit INSERT and head UPDATE.
fn reject_write(store: &AuthorityStore, fault: WriteFault) -> Arc<FaultEvidence> {
    let evidence = Arc::new(FaultEvidence::default());
    let observed = evidence.clone();
    store
        .connection
        .update_hook(Some(move |action: Action, _: &str, table: &str, _: i64| {
            observed.changed.lock().unwrap().insert(table.to_owned());
            observed
                .writes
                .lock()
                .unwrap()
                .push((action, table.to_owned()));
        }));
    let observed = evidence.clone();
    store
        .connection
        .authorizer(Some(move |context: AuthContext<'_>| {
            if fault.matches(context)
                && observed.attempts.fetch_add(1, Ordering::SeqCst) + 1 == fault.nth
            {
                Authorization::Deny
            } else {
                Authorization::Allow
            }
        }));
    evidence
}

fn reject_audit(store: &AuthorityStore, nth: usize) -> Arc<FaultEvidence> {
    reject_write(store, WriteFault::insert("authority_audit", nth))
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

const FIRST_REVIEWER: &str = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa";
const SECOND_REVIEWER: &str = "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb";

fn add_reviewer(f: &mut Fixture, principal: &str, role: ApprovalRole) -> (Authenticator, String) {
    f.store
        .provision_principal(&f.tenant, principal, ORIGIN, principal, NOW)
        .unwrap();
    let key = Authenticator::new(principal);
    let registration = f
        .verifier
        .begin_registration(principal, "Atomic quorum reviewer", &[])
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
    f.store
        .finish_credential_activation(
            &f.tenant,
            &activation.activation_id,
            &key.assertion(&activation.options, 1, 5, ORIGIN),
            &f.verifier,
            NOW,
        )
        .unwrap();
    f.store
        .grant_role(&f.tenant, principal, role, NOW, NOW + 7200, NOW)
        .unwrap();
    f.store
        .bind_human_identity(&f.tenant, principal, principal, NOW)
        .unwrap();
    (key, credential.id())
}

struct PreparedQuorum {
    f: Fixture,
    issued: crate::IssuedApproval,
    response: fw_webauthn::AuthenticationResponse,
    idempotency: String,
}

impl PreparedQuorum {
    fn new() -> Self {
        let mut f = Fixture::new();
        f.requirements["profile"] = "team_dual".into();
        f.requirements["minimum_humans"] = 2.into();
        f.requirements["required_roles"] =
            json!([ApprovalRole::NetworkReviewer, ApprovalRole::ServiceReviewer]);
        f.requirements["author_may_approve"] = false.into();
        f.plan["plan_id"] = new_id().unwrap().into();
        f.plan["approval_requirements_hash"] = canonical_hash(&f.requirements).unwrap().into();
        f.store
            .register_plan(&f.tenant, &f.plan, &f.requirements, NOW)
            .unwrap();
        let (first, first_credential) =
            add_reviewer(&mut f, FIRST_REVIEWER, ApprovalRole::NetworkReviewer);
        let (second, second_credential) =
            add_reviewer(&mut f, SECOND_REVIEWER, ApprovalRole::ServiceReviewer);
        let plan = f.plan["plan_id"].as_str().unwrap();
        let issued = f
            .store
            .issue_challenge(
                &f.tenant,
                FIRST_REVIEWER,
                &first_credential,
                plan,
                ApprovalRole::NetworkReviewer,
                ApprovalDecision::Approve,
                &f.verifier,
                NOW + 1,
            )
            .unwrap();
        let admitted = f
            .store
            .admit_decision(
                &f.tenant,
                FIRST_REVIEWER,
                issued.challenge.challenge_id(),
                &new_id().unwrap(),
                &first.assertion(&issued.options, 2, 5, ORIGIN),
                &f.verifier,
                NOW + 1,
            )
            .unwrap();
        assert!(matches!(
            admitted.aggregation,
            sets::AggregationOutcome::Pending
        ));
        assert_eq!(
            f.store
                .connection
                .query_row::<i64, _, _>(
                    "SELECT count(*) FROM authority_set_heads WHERE plan_id=?",
                    [plan],
                    |row| row.get(0),
                )
                .unwrap(),
            0
        );
        let issued = f
            .store
            .issue_challenge(
                &f.tenant,
                SECOND_REVIEWER,
                &second_credential,
                plan,
                ApprovalRole::ServiceReviewer,
                ApprovalDecision::Approve,
                &f.verifier,
                NOW + 2,
            )
            .unwrap();
        let response = second.assertion(&issued.options, 2, 5, ORIGIN);
        Self {
            f,
            issued,
            response,
            idempotency: new_id().unwrap(),
        }
    }

    fn admit(&mut self) -> Result<crate::DecisionResult> {
        self.f.store.admit_decision(
            &self.f.tenant,
            SECOND_REVIEWER,
            self.issued.challenge.challenge_id(),
            &self.idempotency,
            &self.response,
            &self.f.verifier,
            NOW + 3,
        )
    }
}

#[test]
fn retained_decision_and_quorum_write_faults_roll_back_each_exact_stage() {
    use Action::{SQLITE_INSERT as INSERT, SQLITE_UPDATE as UPDATE};
    let writes = [
        (UPDATE, "authority_credentials"),
        (UPDATE, "authority_challenges"),
        (INSERT, "authority_evidence"),
        (INSERT, "authority_decisions"),
        (INSERT, "authority_approval_sets"),
        (INSERT, "authority_approval_set_members"),
        (INSERT, "authority_approval_set_members"),
        (INSERT, "authority_set_heads"),
        (INSERT, "authority_audit"),
        (UPDATE, "authority_audit_heads"),
        (INSERT, "authority_admission_results"),
        (INSERT, "authority_audit"),
        (UPDATE, "authority_audit_heads"),
    ];
    for (fault, prior_writes) in [
        (
            WriteFault::update("authority_credentials", "credential_bytes"),
            0,
        ),
        (WriteFault::update("authority_challenges", "consumed_at"), 1),
        (WriteFault::insert("authority_evidence", 1), 2),
        (WriteFault::insert("authority_decisions", 1), 3),
        (WriteFault::insert("authority_approval_sets", 1), 4),
        (WriteFault::insert("authority_approval_set_members", 1), 5),
        // Two independently enrolled humans are selected; the first member
        // INSERT must execute before denial of the second (position=1).
        (WriteFault::insert("authority_approval_set_members", 2), 6),
        (WriteFault::insert("authority_set_heads", 1), 7),
        (WriteFault::insert("authority_audit", 1), 8),
        (
            WriteFault {
                accessor: Some("authority_audit_project_head"),
                ..WriteFault::update("authority_audit_heads", "sequence")
            },
            8,
        ),
        (WriteFault::insert("authority_admission_results", 1), 10),
        (WriteFault::insert("authority_audit", 2), 11),
        (
            WriteFault {
                accessor: Some("authority_audit_project_head"),
                nth: 2,
                ..WriteFault::update("authority_audit_heads", "sequence")
            },
            11,
        ),
    ] {
        let mut quorum = PreparedQuorum::new();
        let before = snapshot(&quorum.f.store.connection);
        let evidence = reject_write(&quorum.f.store, fault);
        let error = match quorum.admit() {
            Err(error) => error,
            Ok(_) => panic!("decision survived {fault:?}"),
        };
        assert_actual_fault(error, &evidence, fault.nth, &[]);
        let expected: Vec<_> = writes[..prior_writes]
            .iter()
            .map(|(action, table)| (*action, (*table).to_owned()))
            .collect();
        assert_eq!(*evidence.writes.lock().unwrap(), expected, "{fault:?}");
        assert_eq!(snapshot(&quorum.f.store.connection), before, "{fault:?}");
        quorum.f.reopen();
        assert_eq!(snapshot(&quorum.f.store.connection), before, "{fault:?}");
        assert!(
            quorum
                .f
                .store
                .current_approval_set(
                    &quorum.f.tenant,
                    quorum.f.plan["plan_id"].as_str().unwrap(),
                    &quorum.f.verifier,
                    NOW + 3,
                )
                .unwrap()
                .is_none()
        );
        let admitted = quorum.admit().unwrap();
        assert!(!admitted.replayed);
        let sets::AggregationOutcome::Approved {
            approval_set_id, ..
        } = admitted.aggregation
        else {
            panic!("healthy quorum retry did not approve after {fault:?}");
        };
        let members: Vec<i64> = quorum
            .f
            .store
            .connection
            .prepare("SELECT position FROM authority_approval_set_members WHERE approval_set_id=? ORDER BY position")
            .unwrap()
            .query_map([&approval_set_id], |row| row.get(0))
            .unwrap()
            .collect::<rusqlite::Result<_>>()
            .unwrap();
        assert_eq!(members, [0, 1]);
        let committed = snapshot(&quorum.f.store.connection);
        quorum.f.reopen();
        assert!(quorum.admit().unwrap().replayed);
        assert_eq!(snapshot(&quorum.f.store.connection), committed, "{fault:?}");
        assert_eq!(
            quorum
                .f
                .store
                .current_approval_set(
                    &quorum.f.tenant,
                    quorum.f.plan["plan_id"].as_str().unwrap(),
                    &quorum.f.verifier,
                    NOW + 3,
                )
                .unwrap()
                .unwrap()
                .content()["approval_set_id"],
            approval_set_id
        );
        quorum.f.store.verify_audit_chain(&quorum.f.tenant).unwrap();
    }
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
