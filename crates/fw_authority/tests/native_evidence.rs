#![cfg(feature = "approval-proofs")]
#[allow(dead_code)]
#[path = "support/authority_legacy.rs"]
mod authority_legacy;
#[path = "support/native_fixture.rs"]
mod fixture;
#[path = "support/private_directory.rs"]
mod private_directory;
use fixture::*;
use fw_authority::*;
use fw_backend_linux::*;
use fw_contracts::{canonical_bytes, hash_bytes};
use fw_native_evidence::*;
use rusqlite::{Connection, params};
use serde_json::{Value, json};
use std::{
    path::PathBuf,
    sync::{Arc, Barrier},
};
const NOW: i64 = 1_800_000_000;
struct Fixture {
    _dir: tempfile::TempDir,
    path: PathBuf,
    store: AuthorityStore,
    tenant: AuthorityTenant,
    plan: Value,
    requirements: Value,
    review: fw_planner::PolicyReviewEvidence,
    refs: LabReferences,
    artifact: PortableArtifact,
}
impl Fixture {
    fn new() -> Self {
        let dir = private_directory::private_directory();
        let path = dir.path().join("authority.sqlite3");
        let mut store = AuthorityStore::open(&path).unwrap();
        let (tenant, plan, requirements, review, refs) = setup(&mut store, NOW);
        compile_portable(&review.before, &refs).unwrap();
        fw_native_evidence::compile_evidence(&plan, &review, &refs).unwrap();
        let artifact = compile_portable(&review.after, &refs).unwrap();
        Self {
            _dir: dir,
            path,
            store,
            tenant,
            plan,
            requirements,
            review,
            refs,
            artifact,
        }
    }
    fn compile(&mut self, now: i64) -> NativeCompilationReceipt {
        self.store
            .register_native_compilation(&self.tenant, PLAN, 1, now)
            .unwrap()
    }
    fn signed(&mut self, now: i64, head: Option<&str>) -> SignedNativeObservation {
        let (ch, installed) = challenge(
            &mut self.store,
            &self.tenant,
            PLAN,
            &self.artifact,
            head,
            now,
        );
        let raw = snapshot(&installed.native);
        proof(&ch, installed, raw, now + 1)
    }
    fn count(&self, table: &str) -> i64 {
        Connection::open(&self.path)
            .unwrap()
            .query_row(&format!("SELECT count(*) FROM {table}"), [], |r| r.get(0))
            .unwrap()
    }
    fn counts(&self) -> Vec<i64> {
        [
            "authority_native_compilations",
            "authority_native_challenges",
            "authority_native_observations",
            "authority_native_observation_heads",
            "authority_audit",
        ]
        .map(|t| self.count(t))
        .into()
    }
    fn status(&mut self, now: i64) -> NativeEvidenceStatus {
        self.store
            .native_evidence_status(&self.tenant, PLAN, now)
            .unwrap()
    }
}
#[test]
fn recomputed_compilation_signed_admission_restart_and_revocation_preserve_history_only() {
    let mut f = Fixture::new();
    let c = f.compile(NOW);
    assert!(!c.production_qualified && !c.dispatch_allowed);
    assert_ne!(c.metadata_report_hash, f.plan["target_capability_hash"]);
    assert_eq!(f.compile(NOW).compilation_id, c.compilation_id);
    let signed = f.signed(NOW, None);
    let a = f
        .store
        .admit_native_observation(&f.tenant, &signed, NOW + 1)
        .unwrap();
    assert_eq!(a.receipt.comparison, "match");
    assert_eq!(
        a.receipt.observed_state_hash,
        Some(f.artifact.desired_state_hash.clone())
    );
    assert!(!a.replayed);
    let before = f.counts();
    assert!(
        f.store
            .admit_native_observation(&f.tenant, &signed, NOW + 1)
            .unwrap()
            .replayed
    );
    assert_eq!(f.counts(), before);
    f.store = AuthorityStore::open(&f.path).unwrap();
    let status = f.status(NOW + 2);
    assert!(status.compilation.unwrap().current);
    let o = status.observation.unwrap();
    assert!(o.current && o.signature_valid);
    assert_eq!(o.provenance, "signed_lab_observer_claim");
    assert!(!status.dispatch_allowed && !status.production_qualified);
    f.store
        .revoke_native_observer(&f.tenant, TARGET, 1, NOW + 3)
        .unwrap();
    assert!(!f.status(NOW + 3).observation.unwrap().current);
    assert!(
        f.store
            .admit_native_observation(&f.tenant, &signed, NOW + 4)
            .unwrap()
            .replayed
    );
}
#[test]
fn compilation_checks_actual_bytes_and_current_metadata_without_replacing_lab_capability() {
    let mut f = Fixture::new();
    let mut bad = f.plan.clone();
    bad["plan_id"] = json!("aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa");
    bad["artifact_hash"] = json!(hash_bytes(b"fake artifact"));
    f.store
        .register_reviewed_plan(&f.tenant, &bad, &f.requirements, &f.review, NOW)
        .unwrap();
    let before = f.counts();
    assert!(
        f.store
            .register_native_compilation(&f.tenant, bad["plan_id"].as_str().unwrap(), 1, NOW)
            .is_err()
    );
    assert_eq!(f.counts(), before);
    let old = f.compile(NOW);
    metadata(&mut f.store, &f.tenant, NOW + 1);
    assert!(!f.status(NOW + 1).compilation.unwrap().current);
    let fresh = f.compile(NOW + 1);
    assert_ne!(old.compilation_id, fresh.compilation_id);
    assert_eq!(old.evidence_hash, fresh.evidence_hash);
    assert_ne!(old.metadata_receipt_hash, fresh.metadata_receipt_hash);
}
#[test]
fn observer_keys_are_independent_owned_and_permanently_revoked() {
    let mut f = Fixture::new();
    let reused = NativeObserverPin {
        target_id: TARGET.into(),
        public_key: ed25519_dalek::SigningKey::from_bytes(&METADATA_SEED)
            .verifying_key()
            .to_bytes(),
        not_before: NOW,
        not_after: NOW + 3600,
    };
    assert!(
        f.store
            .pin_native_observer(&f.tenant, &reused, Some(1), NOW)
            .is_err()
    );
    f.store
        .revoke_native_observer(&f.tenant, TARGET, 1, NOW)
        .unwrap();
    let mut p = reused;
    p.public_key = ed25519_dalek::SigningKey::from_bytes(&OBSERVER_SEED)
        .verifying_key()
        .to_bytes();
    p.not_after += 1;
    assert!(
        f.store
            .pin_native_observer(&f.tenant, &p, Some(1), NOW)
            .is_err()
    );
    p.public_key = ed25519_dalek::SigningKey::from_bytes(&[98; 32])
        .verifying_key()
        .to_bytes();
    assert_eq!(
        f.store
            .pin_native_observer(&f.tenant, &p, Some(1), NOW)
            .unwrap(),
        2
    );
    assert!(
        f.store
            .revoke_native_observer(&f.tenant, TARGET, 1, NOW)
            .is_err()
    );
}
#[test]
fn reference_revision_cas_and_revocation_invalidate_pending_proofs() {
    let mut f = Fixture::new();
    f.compile(NOW);
    let signed = f.signed(NOW, None);
    let pin = NativeReferencePin {
        target_id: TARGET.into(),
        references: f.refs.clone(),
        not_before: NOW,
        not_after: NOW + 4000,
    };
    assert!(
        f.store
            .pin_native_references(&f.tenant, &pin, None, NOW)
            .is_err()
    );
    assert_eq!(
        f.store
            .pin_native_references(&f.tenant, &pin, Some(1), NOW)
            .unwrap(),
        2
    );
    assert!(!f.status(NOW).compilation.unwrap().current);
    f.store
        .register_native_compilation(&f.tenant, PLAN, 2, NOW)
        .unwrap();
    assert!(
        f.store
            .admit_native_observation(&f.tenant, &signed, NOW + 1)
            .is_err()
    );
    f.store
        .revoke_native_references(&f.tenant, TARGET, 2, NOW + 2)
        .unwrap();
    assert!(!f.status(NOW + 2).compilation.unwrap().current);
}
#[test]
fn live_challenge_quota_is_bounded_and_expiry_observation_prevents_clock_revival() {
    let mut f = Fixture::new();
    f.compile(NOW);
    for _ in 0..4 {
        let _ = f.signed(NOW, None);
    }
    let before = f.counts();
    let installed = installation(&f.artifact, NOW);
    assert!(matches!(
        f.store.challenge_native_observation(
            &f.tenant,
            PLAN,
            ArtifactRole::Candidate,
            &installed,
            None,
            1,
            1,
            NOW
        ),
        Err(AuthorityError::Quota)
    ));
    assert_eq!(f.counts(), before);
    let expired = f.status(NOW + 300);
    assert!(!expired.compilation.unwrap().current);
    assert!(
        f.store
            .native_evidence_status(&f.tenant, PLAN, NOW + 1)
            .is_err()
    );
    assert!(
        f.store
            .register_native_compilation(&f.tenant, PLAN, 1, NOW + 1)
            .is_err()
    );
}
#[test]
fn expired_failed_compilation_persists_clock_before_refusal() {
    let mut f = Fixture::new();
    assert!(
        f.store
            .register_native_compilation(&f.tenant, PLAN, 1, NOW + 300)
            .is_err()
    );
    assert!(
        f.store
            .current_target_metadata(&f.tenant, TARGET, NOW + 1)
            .is_err()
    );
}
#[test]
fn mandatory_audit_failure_rolls_back_compilation_challenge_and_observation() {
    let mut f = Fixture::new();
    let db = Connection::open(&f.path).unwrap();
    let block = |kind: &str| {
        db.execute_batch(&format!("CREATE TRIGGER injected_native_audit BEFORE INSERT ON authority_audit WHEN NEW.kind='{kind}' BEGIN SELECT RAISE(ABORT,'injected'); END;")).unwrap()
    };
    block("native_compilation_admitted");
    let before = f.counts();
    assert!(
        f.store
            .register_native_compilation(&f.tenant, PLAN, 1, NOW)
            .is_err()
    );
    assert_eq!(f.counts(), before);
    db.execute_batch("DROP TRIGGER injected_native_audit;")
        .unwrap();
    f.compile(NOW);
    block("native_observation_challenge_issued");
    let before = f.counts();
    let installed = installation(&f.artifact, NOW);
    assert!(
        f.store
            .challenge_native_observation(
                &f.tenant,
                PLAN,
                ArtifactRole::Candidate,
                &installed,
                None,
                1,
                1,
                NOW
            )
            .is_err()
    );
    assert_eq!(f.counts(), before);
    db.execute_batch("DROP TRIGGER injected_native_audit;")
        .unwrap();
    let signed = f.signed(NOW, None);
    block("native_observation_admitted");
    let before = f.counts();
    assert!(
        f.store
            .admit_native_observation(&f.tenant, &signed, NOW + 1)
            .is_err()
    );
    assert_eq!(f.counts(), before);
    db.execute_batch("DROP TRIGGER injected_native_audit;")
        .unwrap();
    assert!(
        !f.store
            .admit_native_observation(&f.tenant, &signed, NOW + 1)
            .unwrap()
            .replayed
    );
}
#[test]
fn concurrent_same_proof_consumes_once_and_competing_head_requires_new_challenge() {
    let mut f = Fixture::new();
    f.compile(NOW);
    let signed = f.signed(NOW, None);
    let stale = f.signed(NOW, None);
    let barrier = Arc::new(Barrier::new(2));
    let mut joins = Vec::new();
    for _ in 0..2 {
        let path = f.path.clone();
        let tenant = f.tenant.clone();
        let proof = signed.clone();
        let gate = barrier.clone();
        joins.push(std::thread::spawn(move || {
            let mut s = AuthorityStore::open(path).unwrap();
            gate.wait();
            s.admit_native_observation(&tenant, &proof, NOW + 1)
                .unwrap()
        }));
    }
    let results = joins
        .into_iter()
        .map(|j| j.join().unwrap())
        .collect::<Vec<_>>();
    assert_eq!(results.iter().filter(|r| !r.replayed).count(), 1);
    assert_eq!(results[0].receipt_hash, results[1].receipt_hash);
    assert_eq!(f.count("authority_native_observations"), 1);
    assert!(matches!(
        f.store.admit_native_observation(&f.tenant, &stale, NOW + 1),
        Err(AuthorityError::Conflict)
    ));
    let fresh = f.signed(NOW + 1, Some(&results[0].receipt_hash));
    assert!(
        !f.store
            .admit_native_observation(&f.tenant, &fresh, NOW + 2)
            .unwrap()
            .replayed
    );
}
#[test]
fn mismatch_and_unknown_are_retained_without_observed_state_hash_or_older_fallback() {
    let mut f = Fixture::new();
    f.compile(NOW);
    let signed = f.signed(NOW, None);
    let first = f
        .store
        .admit_native_observation(&f.tenant, &signed, NOW + 1)
        .unwrap();
    let (ch, installed) = challenge(
        &mut f.store,
        &f.tenant,
        PLAN,
        &f.artifact,
        Some(&first.receipt_hash),
        NOW + 1,
    );
    let mut raw = snapshot(&installed.native);
    raw["nftables"].as_array_mut().unwrap().pop();
    let bad = proof(&ch, installed, raw, NOW + 2);
    let second = f
        .store
        .admit_native_observation(&f.tenant, &bad, NOW + 2)
        .unwrap();
    assert_ne!(second.receipt.comparison, "match");
    assert!(second.receipt.observed_state_hash.is_none());
    let status = f.status(NOW + 2);
    assert_eq!(status.observation_head_hash, Some(second.receipt_hash));
    assert!(status.observation.unwrap().observed_state_hash.is_none());
}
#[test]
fn target_global_head_is_explicit_when_the_selected_plan_has_no_observation() {
    let mut f = Fixture::new();
    f.compile(NOW);
    let signed = f.signed(NOW, None);
    let first = f
        .store
        .admit_native_observation(&f.tenant, &signed, NOW + 1)
        .unwrap();
    let mut next = f.plan.clone();
    next["plan_id"] = json!("aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa");
    let id = next["plan_id"].as_str().unwrap();
    f.store
        .register_reviewed_plan(&f.tenant, &next, &f.requirements, &f.review, NOW + 1)
        .unwrap();
    f.store
        .register_native_compilation(&f.tenant, id, 1, NOW + 1)
        .unwrap();
    let status = f
        .store
        .native_evidence_status(&f.tenant, id, NOW + 1)
        .unwrap();
    assert!(status.compilation.unwrap().current);
    assert!(status.observation.is_none());
    assert_eq!(
        status.observation_head_hash,
        Some(first.receipt_hash.clone())
    );
    let installed = installation(&f.artifact, NOW + 1);
    assert!(
        f.store
            .challenge_native_observation(
                &f.tenant,
                id,
                ArtifactRole::Candidate,
                &installed,
                None,
                1,
                1,
                NOW + 1
            )
            .is_err()
    );
    assert!(
        f.store
            .challenge_native_observation(
                &f.tenant,
                id,
                ArtifactRole::Candidate,
                &installed,
                Some(&first.receipt_hash),
                1,
                1,
                NOW + 1
            )
            .is_ok()
    );
}
#[test]
fn current_status_retains_verified_history_after_plan_retirement() {
    let mut f = Fixture::new();
    f.compile(NOW);
    let signed = f.signed(NOW, None);
    f.store
        .admit_native_observation(&f.tenant, &signed, NOW + 1)
        .unwrap();
    f.store.retire_plan(&f.tenant, PLAN, NOW + 2).unwrap();
    let status = f.status(NOW + 2);
    assert!(!status.compilation.unwrap().current);
    assert!(!status.observation.unwrap().current);
}
#[test]
fn tampered_signature_other_tenant_and_mutated_retry_do_not_consume() {
    let mut f = Fixture::new();
    f.compile(NOW);
    let signed = f.signed(NOW, None);
    let mut bad = signed.clone();
    bad.signature.replace_range(
        0..1,
        if &bad.signature[0..1] == "A" {
            "B"
        } else {
            "A"
        },
    );
    let before = f.counts();
    assert!(
        f.store
            .admit_native_observation(&f.tenant, &bad, NOW + 1)
            .is_err()
    );
    assert_eq!(f.counts(), before);
    let other = AuthorityTenant::new(ORG, "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa").unwrap();
    assert!(
        f.store
            .admit_native_observation(&other, &signed, NOW + 1)
            .is_err()
    );
    assert_eq!(f.counts(), before);
    f.store
        .admit_native_observation(&f.tenant, &signed, NOW + 1)
        .unwrap();
    assert!(matches!(
        f.store.admit_native_observation(&f.tenant, &bad, NOW + 1),
        Err(AuthorityError::Conflict)
    ));
}
#[test]
fn v5_backup_migration_preserves_metadata_and_invents_no_native_trust() {
    let f = Fixture::new();
    drop(f.store);
    authority_legacy::restore_v5(&f.path);
    assert!(matches!(
        AuthorityStore::open(&f.path),
        Err(AuthorityError::MigrationRequired {
            found: 5,
            required: 8
        })
    ));
    let backup = f.path.with_file_name("before-v6.sqlite3");
    AuthorityStore::migrate(&f.path, &backup).unwrap();
    let mut s = AuthorityStore::open(&f.path).unwrap();
    assert!(
        s.current_target_metadata(&f.tenant, TARGET, NOW)
            .unwrap()
            .is_some()
    );
    let status = s.native_evidence_status(&f.tenant, PLAN, NOW).unwrap();
    assert!(status.compilation.is_none() && status.observation.is_none());
    assert_eq!(
        Connection::open(backup)
            .unwrap()
            .query_row::<i64, _, _>("PRAGMA user_version", [], |r| r.get(0))
            .unwrap(),
        5
    );
}

#[test]
fn signed_unknown_is_retained_with_closed_reason_and_no_observed_hash() {
    let mut f = Fixture::new();
    f.compile(NOW);
    let (ch, installed) = challenge(&mut f.store, &f.tenant, PLAN, &f.artifact, None, NOW);
    let mut raw = snapshot(&installed.native);
    raw["nftables"]
        .as_array_mut()
        .unwrap()
        .push(json!({"unsupported":{"private":"no interpretation"}}));
    let proof = proof(&ch, installed, raw, NOW + 1);
    let result = f
        .store
        .admit_native_observation(&f.tenant, &proof, NOW + 1)
        .unwrap();
    assert_eq!(result.receipt.comparison, "unknown");
    assert!(result.receipt.observed_state_hash.is_none());
    let status = f.status(NOW + 1);
    assert!(status.reasons.contains(&"OBSERVATION_UNKNOWN".into()));
    assert!(!status.dispatch_allowed);
    assert!(status.observation.unwrap().observed_state_hash.is_none());
}
#[test]
fn challenge_epoch_generation_must_match_immutable_plan() {
    let mut f = Fixture::new();
    f.compile(NOW);
    let installed = installation(&f.artifact, NOW);
    let before = f.counts();
    for (epoch, generation) in [(0, 1), (1, 0), (2, 1), (1, 2)] {
        assert!(
            f.store
                .challenge_native_observation(
                    &f.tenant,
                    PLAN,
                    ArtifactRole::Candidate,
                    &installed,
                    None,
                    epoch,
                    generation,
                    NOW
                )
                .is_err()
        );
    }
    assert_eq!(f.counts(), before);
}
#[test]
fn stored_compilation_and_observation_projections_reject_coherent_corruption() {
    for case in 0..7 {
        let mut f = Fixture::new();
        f.compile(NOW);
        let signed = f.signed(NOW, None);
        let admitted = f
            .store
            .admit_native_observation(&f.tenant, &signed, NOW + 1)
            .unwrap();
        let db = Connection::open(&f.path).unwrap();
        match case {
            0 => {
                db.execute_batch("DROP TRIGGER authority_native_compilations_no_update; UPDATE authority_native_compilations SET evidence_bytes=x'7b7d';").unwrap();
            }
            1 => {
                db.execute_batch("DROP TRIGGER authority_native_observations_no_update;")
                    .unwrap();
                let mut receipt = serde_json::to_value(&admitted.receipt).unwrap();
                receipt["observer_revision"] = json!("2");
                let encoded = canonical_bytes(&receipt).unwrap();
                db.execute(
                    "UPDATE authority_native_observations SET receipt_bytes=?,receipt_hash=?",
                    params![encoded, hex_digest(&hash_bytes(&encoded))],
                )
                .unwrap();
            }
            2 => {
                db.execute_batch("DROP TRIGGER authority_native_challenges_no_update; UPDATE authority_native_challenges SET expires_at=expires_at+1;").unwrap();
            }
            3 => {
                db.execute_batch("DELETE FROM authority_native_observation_heads;")
                    .unwrap();
            }
            4 => {
                db.execute_batch("PRAGMA ignore_check_constraints=ON; DROP TRIGGER authority_native_observations_no_update; UPDATE authority_native_observations SET proof_bytes=zeroblob(3145729);").unwrap();
            }
            5 => {
                db.execute_batch("DROP TRIGGER authority_native_observations_no_update;")
                    .unwrap();
                let mut receipt = serde_json::to_value(&admitted.receipt).unwrap();
                receipt["sequence"] = json!("2");
                let encoded = canonical_bytes(&receipt).unwrap();
                db.execute("UPDATE authority_native_observations SET sequence=?,receipt_bytes=?,receipt_hash=?",params![2u64.to_be_bytes().as_slice(),encoded,hex_digest(&hash_bytes(&encoded))]).unwrap();
            }
            6 => {
                db.execute_batch("DROP TRIGGER authority_native_compilations_no_update;")
                    .unwrap();
                let encoded: Vec<u8> = db
                    .query_row(
                        "SELECT receipt_bytes FROM authority_native_compilations",
                        [],
                        |r| r.get(0),
                    )
                    .unwrap();
                let mut receipt: Value = serde_json::from_slice(&encoded).unwrap();
                receipt["metadata_receipt_hash"] = json!(hash_bytes(b"substitution"));
                db.execute(
                    "UPDATE authority_native_compilations SET receipt_bytes=?",
                    [canonical_bytes(&receipt).unwrap()],
                )
                .unwrap();
            }
            _ => unreachable!(),
        }
        assert!(
            f.store
                .native_evidence_status(&f.tenant, PLAN, NOW + 2)
                .is_err(),
            "corruption {case}"
        );
    }
}
fn hex_digest(hash: &str) -> Vec<u8> {
    (7..71)
        .step_by(2)
        .map(|i| u8::from_str_radix(&hash[i..i + 2], 16).unwrap())
        .collect()
}
#[test]
fn signature_binds_exact_previous_receipt_even_if_old_projection_is_rehashed() {
    let mut f = Fixture::new();
    f.compile(NOW);
    let first = f.signed(NOW, None);
    let a = f
        .store
        .admit_native_observation(&f.tenant, &first, NOW + 1)
        .unwrap();
    let next = f.signed(NOW + 1, Some(&a.receipt_hash));
    f.store
        .admit_native_observation(&f.tenant, &next, NOW + 2)
        .unwrap();
    let db = Connection::open(&f.path).unwrap();
    db.execute_batch("DROP TRIGGER authority_native_observations_no_update;")
        .unwrap();
    let mut changed = serde_json::to_value(a.receipt).unwrap();
    changed["provenance"] = json!("replaced");
    let encoded = canonical_bytes(&changed).unwrap();
    db.execute(
        "UPDATE authority_native_observations SET receipt_bytes=?,receipt_hash=? WHERE sequence=?",
        params![
            encoded,
            hex_digest(&hash_bytes(&encoded)),
            1u64.to_be_bytes().as_slice()
        ],
    )
    .unwrap();
    assert!(
        f.store
            .native_evidence_status(&f.tenant, PLAN, NOW + 2)
            .is_err()
    );
}
#[test]
fn reference_and_observer_pin_audit_failure_does_not_leave_partial_trust() {
    let mut f = Fixture::new();
    let db = Connection::open(&f.path).unwrap();
    let refs = f.count("authority_native_pins");
    let keys = f.count("authority_native_observer_keys");
    db.execute_batch("CREATE TRIGGER fail_pin_audit BEFORE INSERT ON authority_audit WHEN NEW.kind IN ('native_references_pinned','native_observer_pinned') BEGIN SELECT RAISE(ABORT,'injected'); END;").unwrap();
    let mut pin = NativeReferencePin {
        target_id: TARGET.into(),
        references: f.refs.clone(),
        not_before: NOW,
        not_after: NOW + 4000,
    };
    assert!(
        f.store
            .pin_native_references(&f.tenant, &pin, Some(1), NOW)
            .is_err()
    );
    assert_eq!(f.count("authority_native_pins"), refs);
    let observer = NativeObserverPin {
        target_id: TARGET.into(),
        public_key: ed25519_dalek::SigningKey::from_bytes(&[99; 32])
            .verifying_key()
            .to_bytes(),
        not_before: NOW,
        not_after: NOW + 4000,
    };
    assert!(
        f.store
            .pin_native_observer(&f.tenant, &observer, Some(1), NOW)
            .is_err()
    );
    assert_eq!(f.count("authority_native_pins"), refs);
    assert_eq!(f.count("authority_native_observer_keys"), keys);
    assert_eq!(f.count("authority_native_observer_revocations"), 0);
    db.execute_batch("DROP TRIGGER fail_pin_audit;").unwrap();
    pin.not_after += 1;
    assert_eq!(
        f.store
            .pin_native_references(&f.tenant, &pin, Some(1), NOW)
            .unwrap(),
        2
    );
}

#[test]
fn observer_key_cannot_later_become_transport_identity_even_after_revocation() {
    let mut f = Fixture::new();
    let pin = TargetTransportPin {
        target_id: TARGET.into(),
        public_key: ed25519_dalek::SigningKey::from_bytes(&OBSERVER_SEED)
            .verifying_key()
            .to_bytes(),
        certificate_fingerprint: hash_bytes(b"new transport certificate"),
        platform: "linux".into(),
        not_before: NOW,
        not_after: NOW + 3600,
    };
    let before = f.count("authority_target_pins");
    assert!(
        f.store
            .pin_target_transport(&f.tenant, &pin, Some(1), NOW)
            .is_err()
    );
    f.store
        .revoke_native_observer(&f.tenant, TARGET, 1, NOW + 1)
        .unwrap();
    assert!(
        f.store
            .pin_target_transport(&f.tenant, &pin, Some(1), NOW + 1)
            .is_err()
    );
    assert_eq!(f.count("authority_target_pins"), before);
}
#[test]
fn observer_key_ownership_is_organization_wide_across_projects() {
    let mut f = Fixture::new();
    let other = AuthorityTenant::new(ORG, "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa").unwrap();
    f.store
        .provision_target_metadata_project(&other, NOW)
        .unwrap();
    let key = ed25519_dalek::SigningKey::from_bytes(&[95; 32])
        .verifying_key()
        .to_bytes();
    f.store
        .pin_target_transport(
            &other,
            &TargetTransportPin {
                target_id: TARGET.into(),
                public_key: key,
                certificate_fingerprint: hash_bytes(b"other project certificate"),
                platform: "linux".into(),
                not_before: NOW,
                not_after: NOW + 3600,
            },
            None,
            NOW,
        )
        .unwrap();
    let pin = NativeObserverPin {
        target_id: TARGET.into(),
        public_key: ed25519_dalek::SigningKey::from_bytes(&OBSERVER_SEED)
            .verifying_key()
            .to_bytes(),
        not_before: NOW,
        not_after: NOW + 3600,
    };
    assert!(matches!(
        f.store.pin_native_observer(&other, &pin, None, NOW),
        Err(AuthorityError::Conflict)
    ));
}

#[test]
fn independently_signed_other_platform_metadata_cannot_support_linux_compilation() {
    let mut f = Fixture::new();
    let pin = TargetTransportPin {
        target_id: TARGET.into(),
        public_key: ed25519_dalek::SigningKey::from_bytes(&METADATA_SEED)
            .verifying_key()
            .to_bytes(),
        certificate_fingerprint: hash_bytes(b"windows certificate"),
        platform: "windows".into(),
        not_before: NOW,
        not_after: NOW + 3600,
    };
    f.store
        .pin_target_transport(&f.tenant, &pin, Some(1), NOW + 1)
        .unwrap();
    let challenge = f
        .store
        .issue_target_report_challenge(&f.tenant, TARGET, NOW + 1)
        .unwrap();
    let mut report = metadata_report(NOW + 1);
    report["platform"] = json!("windows");
    report["enforcement_backend"] = json!("windows_wfp");
    let proof = fw_target_evidence::sign_report(
        &challenge,
        &canonical_bytes(&report).unwrap(),
        &METADATA_SEED,
        NOW + 1,
    )
    .unwrap();
    f.store
        .admit_target_report(&f.tenant, &proof, NOW + 1)
        .unwrap();
    assert!(
        f.store
            .register_native_compilation(&f.tenant, PLAN, 1, NOW + 1)
            .is_err()
    );
    assert_eq!(f.count("authority_native_compilations"), 0);
}

#[test]
fn selected_plan_history_survives_target_head_changes_without_becoming_current() {
    let mut f = Fixture::new();
    f.compile(NOW);
    let signed_a = f.signed(NOW, None);
    let a = f
        .store
        .admit_native_observation(&f.tenant, &signed_a, NOW + 1)
        .unwrap();
    let mut plan_b = f.plan.clone();
    plan_b["plan_id"] = json!("aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa");
    let b_id = plan_b["plan_id"].as_str().unwrap();
    f.store
        .register_reviewed_plan(&f.tenant, &plan_b, &f.requirements, &f.review, NOW + 1)
        .unwrap();
    f.store
        .register_native_compilation(&f.tenant, b_id, 1, NOW + 1)
        .unwrap();
    let (ch, installed) = challenge(
        &mut f.store,
        &f.tenant,
        b_id,
        &f.artifact,
        Some(&a.receipt_hash),
        NOW + 1,
    );
    let raw = snapshot(&installed.native);
    let signed_b = proof(&ch, installed, raw, NOW + 2);
    let b = f
        .store
        .admit_native_observation(&f.tenant, &signed_b, NOW + 2)
        .unwrap();
    let status_a = f.status(NOW + 2);
    assert_eq!(status_a.observation_head_hash, Some(b.receipt_hash.clone()));
    let retained_a = status_a
        .observation
        .expect("selected plan's verified history remains visible");
    assert_eq!(retained_a.receipt_hash, a.receipt_hash);
    assert!(!retained_a.current);
    assert!(status_a.reasons.contains(&"OBSERVATION_STALE".into()));
    assert!(!status_a.reasons.contains(&"OBSERVATION_MISSING".into()));
    assert!(
        f.store
            .native_evidence_status(&f.tenant, b_id, NOW + 2)
            .unwrap()
            .observation
            .unwrap()
            .current
    );
    assert!(
        f.store
            .admit_native_observation(&f.tenant, &signed_a, NOW + 2)
            .unwrap()
            .replayed
    );
    assert_eq!(
        f.status(NOW + 2).observation_head_hash,
        Some(b.receipt_hash.clone())
    );
    let again = f.signed(NOW + 2, Some(&b.receipt_hash));
    let new_a = f
        .store
        .admit_native_observation(&f.tenant, &again, NOW + 3)
        .unwrap();
    let status_a = f.status(NOW + 3);
    assert!(status_a.observation.unwrap().current);
    assert_eq!(
        status_a.observation_head_hash,
        Some(new_a.receipt_hash.clone())
    );
    let status_b = f
        .store
        .native_evidence_status(&f.tenant, b_id, NOW + 3)
        .unwrap();
    let retained_b = status_b.observation.unwrap();
    assert_eq!(retained_b.receipt_hash, b.receipt_hash);
    assert!(!retained_b.current);
    assert_eq!(status_b.observation_head_hash, Some(new_a.receipt_hash));
}
