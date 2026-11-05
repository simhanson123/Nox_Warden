use super::*;
use rusqlite::hooks::{AuthAction, AuthContext, Authorization, TransactionOperation};
use signing_test_support::{Fixture, NOW};
use std::{
    path::Path,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
};

const FORGED_JOB: &str = "not-an-authenticated-job";

fn rewrite_job(path: &Path, intent: &str, job: &str) {
    let mut peer = Connection::open(path).unwrap();
    let guard: String = peer
        .query_row(
            "SELECT sql FROM sqlite_schema WHERE name='authority_signing_intents_no_update'",
            [],
            |row| row.get(0),
        )
        .unwrap();
    let tx = peer.transaction().unwrap();
    tx.execute_batch("DROP TRIGGER authority_signing_intents_no_update")
        .unwrap();
    assert_eq!(
        tx.execute(
            "UPDATE authority_signing_intents SET job_id=? WHERE intent_id=?",
            params![job, intent],
        )
        .unwrap(),
        1
    );
    tx.execute_batch(&guard).unwrap();
    tx.commit().unwrap();
    migrations::validate_live_schema(&peer).unwrap();
}

fn quota_clocks(f: &Fixture) -> Vec<(String, String, i64)> {
    let peer = Connection::open(&f.path).unwrap();
    peer.prepare("SELECT bucket_kind,bucket_id,observed_at FROM authority_signing_quota_clocks ORDER BY bucket_kind,bucket_id")
        .unwrap()
        .query_map([], |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)))
        .unwrap()
        .collect::<std::result::Result<Vec<_>, _>>()
        .unwrap()
}

#[derive(Clone, Copy, Debug)]
enum Lookup {
    Prepare,
    Read,
    Readiness,
    ReadinessV2,
}

impl Lookup {
    fn invoke(
        self,
        f: &mut Fixture,
        intent: &str,
        request: &SigningRequest,
        now: i64,
    ) -> Result<()> {
        match self {
            Self::Prepare => f
                .store
                .prepare_signing_intent(&f.tenant, &f.verifier, request, now)
                .map(|_| ()),
            Self::Read => f
                .store
                .read_signing_intent(&f.tenant, intent, now)
                .map(|value| assert!(value.is_some())),
            Self::Readiness => f
                .store
                .signing_readiness(&f.tenant, &request.plan_id, &f.verifier, now)
                .map(|value| {
                    assert!(!value.signing_allowed);
                    assert!(!value.dispatch_allowed);
                }),
            Self::ReadinessV2 => f
                .store
                .signing_readiness_v2(&f.tenant, &request.plan_id, &f.verifier, now)
                .map(|value| {
                    assert!(!value.snapshot.signing_allowed);
                    assert!(!value.snapshot.dispatch_allowed);
                }),
        }
    }
}

#[test]
fn tampered_retained_lookup_is_rejected_before_returning_an_unauthenticated_job() {
    let mut f = Fixture::new();
    let prepared = test_prepare(&mut f, NOW);
    let before = quota_clocks(&f);
    rewrite_job(&f.path, &prepared.intent.intent_id, FORGED_JOB);
    // The old unchecked selector returned FORGED_JOB and failed its identifier
    // check. Full snapshot validation must reject the broken binding first.
    assert!(matches!(
        f.store
            .read_signing_intent(&f.tenant, &prepared.intent.intent_id, NOW + 1),
        Err(AuthorityError::Invalid(
            "authority signing retained reference graph"
        ))
    ));
    assert_eq!(quota_clocks(&f), before);
    rewrite_job(&f.path, &prepared.intent.intent_id, &prepared.intent.job_id);
    assert!(
        f.store
            .read_signing_intent(&f.tenant, &prepared.intent.intent_id, NOW + 1)
            .unwrap()
            .unwrap()
            .reservation_held
    );
}

#[test]
fn each_retained_clock_selector_uses_its_validated_snapshot_during_a_peer_commit() {
    for lookup in [
        Lookup::Prepare,
        Lookup::Read,
        Lookup::Readiness,
        Lookup::ReadinessV2,
    ] {
        let mut f = Fixture::new();
        let prepared = test_prepare(&mut f, NOW);
        let request = {
            let tx = f.store.connection.transaction().unwrap();
            intent_at(&tx, &f.tenant, &prepared.intent.intent_id)
                .unwrap()
                .request
        };
        let audit_before = f.count("authority_audit");
        let path = f.path.clone();
        let intent = prepared.intent.intent_id.clone();
        let injected = Arc::new(AtomicBool::new(false));
        let selected_in_transaction = Arc::new(AtomicBool::new(false));
        let observed_injection = injected.clone();
        let observed_transaction = selected_in_transaction.clone();
        let mut in_transaction = false;
        // Existing cfg(test) raw hooks only schedule a peer commit. They do not
        // alter transaction validation, schema expectations or production gates.
        // Injection occurs while preparing the first retained job selector:
        // earlier plan/current-clock snapshots have already completed.
        f.store
            .connection
            .authorizer(Some(move |context: AuthContext<'_>| {
                if let AuthAction::Transaction { operation } = context.action {
                    match operation {
                        TransactionOperation::Begin => in_transaction = true,
                        TransactionOperation::Release
                        | TransactionOperation::Rollback
                        | TransactionOperation::Unknown => in_transaction = false,
                        _ => {}
                    }
                }
                if matches!(
                    context.action,
                    AuthAction::Read {
                        table_name: "authority_signing_intents",
                        column_name: "job_id"
                    }
                ) && !observed_injection.swap(true, Ordering::SeqCst)
                {
                    observed_transaction.store(in_transaction, Ordering::SeqCst);
                    rewrite_job(&path, &intent, FORGED_JOB);
                }
                Authorization::Allow
            }));
        let outcome = lookup.invoke(&mut f, &prepared.intent.intent_id, &request, NOW + 1);
        assert!(injected.load(Ordering::SeqCst), "{lookup:?}");
        assert!(
            selected_in_transaction.load(Ordering::SeqCst),
            "{lookup:?}: selector lacked a snapshot"
        );
        // Its already-validated snapshot retains the genuine job. The next
        // writer validation refuses the peer change before advancing its quota
        // clocks, rather than accepting FORGED_JOB as a clock selector.
        assert!(
            matches!(
                outcome,
                Err(AuthorityError::Invalid(
                    "authority signing retained reference graph"
                ))
            ),
            "{lookup:?}: {outcome:?}"
        );
        let expected = if matches!(lookup, Lookup::Readiness | Lookup::ReadinessV2) {
            NOW + 1 // Readiness independently observes current configuration.
        } else {
            NOW
        };
        assert!(
            quota_clocks(&f).iter().all(|(_, _, at)| *at == expected),
            "{lookup:?}"
        );
        assert_eq!(f.count("authority_audit"), audit_before);
        assert_eq!(f.count("authority_signing_intents"), 1);
        assert_eq!(f.count("authority_signing_quota_reservations"), 1);
        rewrite_job(&f.path, &prepared.intent.intent_id, &prepared.intent.job_id);
        let healthy = lookup.invoke(&mut f, &prepared.intent.intent_id, &request, NOW + 1);
        if matches!(lookup, Lookup::Prepare) {
            assert!(matches!(
                healthy,
                Err(AuthorityError::Invalid(
                    "protected signing authority unavailable"
                ))
            ));
        } else {
            healthy.unwrap();
        }
        assert!(quota_clocks(&f).iter().all(|(_, _, at)| *at == NOW + 1));
    }
}
