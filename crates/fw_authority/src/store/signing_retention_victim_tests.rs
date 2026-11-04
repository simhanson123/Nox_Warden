use super::super::signing_test_support::{self, NOW};
use super::*;

const WORKER: &str = "dddddddd-dddd-4ddd-8ddd-dddddddddddd";

fn job_rows(connection: &Connection) -> Vec<Vec<rusqlite::types::Value>> {
    let mut statement = connection
        .prepare("SELECT rowid,* FROM authority_signing_jobs ORDER BY rowid")
        .unwrap();
    let columns = statement.column_count();
    statement
        .query_map([], |row| (0..columns).map(|i| row.get(i)).collect())
        .unwrap()
        .collect::<rusqlite::Result<_>>()
        .unwrap()
}

#[test]
fn another_genuine_job_cannot_replace_a_delivered_held_victim_rowid() {
    let mut f = signing_test_support::Fixture::new();
    let first = signing_intents::test_prepare(&mut f, NOW);
    let victim = first.intent.job_id;
    let reservation = first.intent.reservation_id;
    {
        let tx = f.store.connection.transaction().unwrap();
        let claim =
            signing_jobs::fixture_claim(&tx, &f.tenant, &victim, "signer", WORKER, 0, 60, NOW)
                .unwrap();
        tx.commit().unwrap();
        signing_intents::test_finalize(&mut f, &claim, NOW).unwrap();
        let tx = f.store.connection.transaction().unwrap();
        let dispatch = signing_jobs::fixture_claim(
            &tx,
            &f.tenant,
            &victim,
            "dispatch",
            WORKER,
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
            WORKER,
            0,
            60,
            NOW + 3,
        )
        .unwrap();
        tx.commit().unwrap();
        claim
    };
    signing_intents::test_finalize(&mut f, &claim, NOW + 3).unwrap();

    // Every retained job and signature is genuine test mechanics, including the
    // delivered victim. The takeover reuses the second job's exact stored bytes.
    let original = job_rows(&f.store.connection);
    let audit_count = f.count("authority_audit");
    assert_eq!(original.len(), 2);
    // Connection settings belong to the forensic writer. The live store keeps
    // its validated guards while SQL must independently refuse each takeover.
    let db = Connection::open(&f.path).unwrap();
    for foreign_keys in [false, true] {
        for recursive in [false, true] {
            db.pragma_update(None, "foreign_keys", foreign_keys)
                .unwrap();
            db.pragma_update(None, "recursive_triggers", recursive)
                .unwrap();
            let takeover = db.execute(
                "INSERT OR REPLACE INTO authority_signing_jobs(rowid,org_id,project_id,job_id,intent_id,payload_hash,created_at,deadline,canonical_bytes) SELECT (SELECT rowid FROM authority_signing_jobs WHERE job_id=?1),org_id,project_id,job_id,intent_id,payload_hash,created_at,deadline,canonical_bytes FROM authority_signing_jobs WHERE job_id=?2",
                params![victim, second.intent.job_id],
            );
            assert!(
                takeover.is_err(),
                "foreign_keys={foreign_keys}, recursive={recursive}"
            );
            assert_eq!(job_rows(&f.store.connection), original);
            assert_eq!(f.count("authority_audit"), audit_count);
            for reopen in [false, true] {
                if reopen {
                    f.reopen();
                }
                assert_eq!(job_rows(&f.store.connection), original);
                let tx = f.store.connection.transaction().unwrap();
                let held = signing_quota::read(&tx, &f.tenant, &reservation).unwrap();
                assert_eq!(held.state, "active");
                assert!(held.held());
                let delivered = lifecycle_status(&tx, &f.tenant, &victim, NOW + 3).unwrap();
                assert_eq!(delivered.dispatch_state.as_deref(), Some("delivered"));
                assert!(delivered.quota_held);
                let second_status =
                    lifecycle_status(&tx, &f.tenant, &second.intent.job_id, NOW + 3).unwrap();
                assert_eq!(second_status.dispatch_state.as_deref(), Some("queued"));
                assert!(second_status.quota_held);
                // Exercise sensitive accounting across both intact witnesses.
                // This prospective reservation is rolled back after validation.
                let cost = signing_quota::cost_for_plan(&tx, &f.tenant, &next_id, NOW + 3).unwrap();
                signing_quota::reserve(
                    &tx,
                    &f.tenant,
                    &new_id().unwrap(),
                    &cost,
                    NOW + 250,
                    NOW + 3,
                )
                .unwrap();
                tx.rollback().unwrap();
                f.store.verify_audit_chain(&f.tenant).unwrap();
                assert_eq!(f.count("authority_audit"), audit_count);
            }
        }
    }
}
