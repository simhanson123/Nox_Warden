//! Synthetic signed/native fixtures verify durable authorization boundaries here.
//! Actual nft syntax, readback and packets belong to the isolated native suite.
use super::*;
use ed25519_dalek::{Signer, SigningKey};
use fw_authority::{sign_grant, verify_grant, AuthorityEvidence, GrantContext, SignedGrant};
use fw_contracts::canonical_hash;
use serde_json::{json, Value};

const NOW: i64 = 1_793_350_800;
const OP: &str = "33333333-3333-4333-8333-333333333333";
const NEXT: &str = "44444444-4444-4444-8444-444444444444";
fn digest(value: &impl Serialize) -> String {
    canonical_hash(value).unwrap()
}
fn h(c: char) -> String {
    format!("sha256:{}", c.to_string().repeat(64))
}
struct FixtureEvidence(GrantContext);
impl AuthorityEvidence for FixtureEvidence {
    fn verify_for_signing(&self, _: &Value, _: i64) -> fw_authority::Result<GrantContext> {
        Ok(self.0.clone())
    }
}
fn fixture() -> (VerifiedGrant, ExecutionMaterial, TrustKey) {
    let mut payload = serde_json::from_str::<Value>(include_str!(
        "../../../docs/specs/F_기준자료/F_개발계약/F_계약_예제.json"
    ))
    .unwrap()["grant"]["payload"]
        .clone();
    payload["target_generation"] = "1".into();
    let target = payload["target_id"].clone();
    let baseline = json!({"target_id":target,"unit_fixture":"baseline"});
    let candidate = json!({"target_id":target,"unit_fixture":"candidate"});
    let recovery = json!({"target_id":target,"unit_fixture":"restrictive recovery"});
    let scope = json!({"target_id":target,"unit_fixture":"isolated scope"});
    let artifact =
        json!({"desired_state_hash":digest(&candidate),"unit_fixture":"absolute deadlines"});
    let recovery_artifact =
        json!({"desired_state_hash":digest(&recovery),"unit_fixture":"deny only"});
    payload["baseline_hash"] = digest(&baseline).into();
    payload["desired_state_hash"] = digest(&candidate).into();
    payload["artifact_hash"] = digest(&artifact).into();
    payload["rollback_authority"]["baseline_hash"] = digest(&baseline).into();
    payload["rollback_authority"]["artifact_hash"] = digest(&recovery_artifact).into();
    payload["rollback_authority"]["scope_bound_hash"] = digest(&scope).into();
    let context = GrantContext {
        org_id: payload["org_id"].as_str().unwrap().into(),
        project_id: payload["project_id"].as_str().unwrap().into(),
        target_id: payload["target_id"].as_str().unwrap().into(),
        plan_hash: payload["plan_hash"].as_str().unwrap().into(),
        artifact_hash: digest(&artifact),
        baseline_hash: digest(&baseline),
        desired_state_hash: digest(&candidate),
        approval_set_hash: payload["approval_set_hash"].as_str().unwrap().into(),
        authority_epoch: 1,
        now_unix: NOW,
    };
    let key = SigningKey::from_bytes(&[71; 32]);
    let signed: SignedGrant = sign_grant(
        payload,
        "unit-fixture-key",
        &key,
        &FixtureEvidence(context.clone()),
        NOW,
    )
    .unwrap();
    let trust = TrustKey {
        key_id: "unit-fixture-key".into(),
        org_id: context.org_id.clone(),
        payload_type: fw_authority::CORE_GRANT_TYPE.into(),
        public_key: key.verifying_key().to_bytes(),
        not_before: NOW - 1,
        not_after: NOW + 3600,
        revoked: false,
    };
    let verified = verify_grant(&signed, &trust, &context).unwrap();
    let material = ExecutionMaterial {
        signed_grant: signed,
        baseline_state: baseline,
        candidate_state: candidate,
        candidate_artifact: artifact,
        recovery_state: recovery,
        recovery_artifact,
        recovery_scope: scope,
        installation_manifest: json!({"unit_fixture":"manifest"}),
        tombstone_watermark: json!([]),
    };
    (verified, material, trust)
}
fn journal(path: &Path, grant: &VerifiedGrant) -> ExecutorJournal {
    ExecutorJournal::create(
        path,
        grant.org_id(),
        grant.target_id(),
        grant.authority_epoch(),
        grant.baseline_hash(),
    )
    .unwrap()
}
fn accept_and_submit(
    journal: &mut ExecutorJournal,
    grant: &VerifiedGrant,
    material: &ExecutionMaterial,
) {
    journal.accept_execution(grant, OP, material, NOW).unwrap();
    journal
        .arm_watchdog(OP, &material.content_hash().unwrap(), &h('a'))
        .unwrap();
    journal.mark_submitted(OP, NOW + 1).unwrap();
}

#[test]
fn exact_material_is_atomic_durable_and_never_rebound_by_retry() {
    let (grant, material, _) = fixture();
    let dir = private_test_directory();
    let path = dir.path().join("journal");
    let mut j = journal(&path, &grant);
    j.accept_execution(&grant, OP, &material, NOW).unwrap();
    drop(j);
    let mut j = ExecutorJournal::open(&path).unwrap();
    assert_eq!(j.operation(OP).unwrap().unwrap().state, State::NotApplied);
    assert_eq!(
        canonical_bytes(&j.execution_material(OP).unwrap().unwrap()).unwrap(),
        canonical_bytes(&material).unwrap()
    );
    assert_eq!(
        j.accept_execution(&grant, OP, &material, NOW + 500)
            .unwrap()
            .generation,
        "1"
    );
    let mut changed = material.clone();
    changed.installation_manifest["retry_time"] = json!(NOW + 500);
    assert!(matches!(
        j.accept_execution(&grant, OP, &changed, NOW + 500),
        Err(ExecutorError::Conflict)
    ));
    assert_eq!(j.highest_generation().unwrap(), 1);
    assert!(matches!(
        j.mark_submitted(OP, NOW + 500),
        Err(ExecutorError::Transition)
    ));
}

#[test]
fn restart_closes_unsubmitted_material_without_releasing_generation_fence() {
    let (grant, material, _) = fixture();
    let dir = private_test_directory();
    let path = dir.path().join("journal");
    let mut j = journal(&path, &grant);
    j.accept_execution(&grant, OP, &material, NOW).unwrap();
    j.arm_watchdog(OP, &material.content_hash().unwrap(), &h('a'))
        .unwrap();
    drop(j);
    let mut j = ExecutorJournal::open(&path).unwrap();
    let closed = j.operation(OP).unwrap().unwrap();
    assert_eq!(closed.state, State::NotApplied);
    assert_eq!(closed.submitted_at, None);
    assert_eq!(closed.confirm_deadline, None);
    assert_eq!(j.highest_generation().unwrap(), 1);
    assert_eq!(j.current_state_hash().unwrap(), grant.baseline_hash());
    assert!(matches!(
        j.mark_submitted(OP, NOW + 1),
        Err(ExecutorError::Transition)
    ));
    j.accept_fields(
        &Acceptance {
            org_id: grant.org_id(),
            target_id: grant.target_id(),
            epoch: 1,
            generation: 2,
            grant_hash: &h('d'),
            baseline_hash: grant.baseline_hash(),
            desired_state_hash: grant.desired_state_hash(),
            issued_at: NOW,
            not_after: NOW + 240,
            confirm_not_after: NOW + 300,
        },
        NEXT,
        NOW + 2,
    )
    .unwrap();
    assert_eq!(j.highest_generation().unwrap(), 2);
}

#[test]
fn restart_never_closes_corrupt_unsubmitted_material() {
    let (grant, material, _) = fixture();
    let dir = private_test_directory();
    let path = dir.path().join("journal");
    let mut j = journal(&path, &grant);
    j.accept_execution(&grant, OP, &material, NOW).unwrap();
    j.connection
        .execute("UPDATE execution_material SET material_hash=?1", [h('f')])
        .unwrap();
    drop(j);
    assert!(matches!(
        ExecutorJournal::open(&path),
        Err(ExecutorError::Binding)
    ));
    let raw = Connection::open(&path).unwrap();
    let stored: String = raw
        .query_row("SELECT state FROM operations", [], |r| r.get(0))
        .unwrap();
    assert_eq!(stored, "PREPARED");
}

#[cfg(unix)]
#[test]
fn native_child_keeps_journal_fenced_after_owner_exit() {
    use std::io::{Read, Write};
    use std::process::{Command, Stdio};
    let (grant, _, _) = fixture();
    let dir = private_test_directory();
    let path = dir.path().join("journal");
    let j = journal(&path, &grant);
    let mut command = Command::new("/bin/sh");
    command
        .args(["-c", "printf ready; read line"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped());
    j.fence_native_command(&mut command).unwrap();
    let mut child = command.spawn().unwrap();
    let mut ready = [0; 5];
    child.stdout.take().unwrap().read_exact(&mut ready).unwrap();
    assert_eq!(&ready, b"ready");
    drop(command);
    drop(j);
    let blocked = matches!(ExecutorJournal::open(&path), Err(ExecutorError::Io(error)) if error.kind() == std::io::ErrorKind::WouldBlock);
    child.stdin.take().unwrap().write_all(b"done\n").unwrap();
    assert!(child.wait().unwrap().success());
    assert!(
        blocked,
        "a live native child must retain the durable operation fence"
    );
    assert!(ExecutorJournal::open(&path).is_ok());
}

#[test]
fn recovery_attempts_preserve_uncertain_submission_and_immutable_material() {
    let (grant, material, _) = fixture();
    let dir = private_test_directory();
    let path = dir.path().join("journal");
    let mut j = journal(&path, &grant);
    accept_and_submit(&mut j, &grant, &material);
    let hash = material.content_hash().unwrap();
    let first = j
        .prepare_recovery_attempt(OP, &hash, &json!({"binding":"first"}), NOW + 61)
        .unwrap();
    j.claim_recovery(OP, 1, grant.desired_state_hash(), NOW + 61)
        .unwrap();
    drop(j);
    let mut j = ExecutorJournal::open(&path).unwrap();
    assert_eq!(j.latest_recovery_attempt(OP).unwrap().unwrap(), first);
    let refreshed = j
        .prepare_recovery_attempt(OP, &hash, &json!({"binding":"fresh"}), NOW + 66)
        .unwrap();
    assert_eq!(refreshed.sequence, first.sequence + 1);
    j.mark_recovery_submitted(OP, refreshed.sequence, NOW + 66)
        .unwrap();
    drop(j);
    let mut j = ExecutorJournal::open(&path).unwrap();
    assert!(matches!(
        j.prepare_recovery_attempt(
            OP,
            &hash,
            &json!({"binding":"must not replace uncertainty"}),
            NOW + 67
        ),
        Err(ExecutorError::Transition)
    ));
    assert!(j
        .record_recovery_attempt_not_applied(
            OP,
            refreshed.sequence,
            grant.baseline_hash(),
            &h('b'),
            NOW + 67
        )
        .is_err());
    j.record_recovery_attempt_not_applied(
        OP,
        refreshed.sequence,
        grant.desired_state_hash(),
        &h('b'),
        NOW + 67,
    )
    .unwrap();
    let last = j
        .prepare_recovery_attempt(
            OP,
            &hash,
            &json!({"binding":"after actual candidate observation"}),
            NOW + 68,
        )
        .unwrap();
    assert_eq!(last.sequence, refreshed.sequence + 1);
    assert_eq!(j.highest_generation().unwrap(), 1);
    let original: Vec<u8> = j
        .connection
        .query_row(
            "SELECT installation_bytes FROM recovery_attempts WHERE operation_id=?1 AND sequence=1",
            [OP],
            |r| r.get(0),
        )
        .unwrap();
    assert_eq!(original, canonical_bytes(&first.installation).unwrap());
}

#[test]
fn recovery_attempts_reject_wrong_material_expiry_and_unsubmitted_completion() {
    let (grant, material, _) = fixture();
    let dir = private_test_directory();
    let mut j = journal(&dir.path().join("journal"), &grant);
    accept_and_submit(&mut j, &grant, &material);
    let hash = material.content_hash().unwrap();
    let installation = json!({"binding":"test"});
    assert!(j
        .prepare_recovery_attempt(OP, &hash, &installation, NOW + 60)
        .is_err());
    assert!(j
        .prepare_recovery_attempt(OP, &h('d'), &installation, NOW + 61)
        .is_err());
    let attempt = j
        .prepare_recovery_attempt(OP, &hash, &installation, NOW + 61)
        .unwrap();
    j.claim_recovery(OP, 1, grant.desired_state_hash(), NOW + 61)
        .unwrap();
    assert!(j
        .record_recovery_completion(
            OP,
            1,
            grant.desired_state_hash(),
            &hash,
            &digest(&material.recovery_state),
            &h('b'),
            NOW + 62
        )
        .is_err());
    let expiry = grant.rollback_authority().valid_until_unix().unwrap();
    assert!(matches!(
        j.mark_recovery_submitted(OP, attempt.sequence, expiry),
        Err(ExecutorError::Expired)
    ));
    assert!(matches!(
        j.prepare_recovery_attempt(OP, &hash, &installation, expiry),
        Err(ExecutorError::Expired)
    ));
    j.mark_recovery_submitted(OP, attempt.sequence, NOW + 62)
        .unwrap();
    assert_eq!(
        j.record_recovery_completion(
            OP,
            1,
            grant.desired_state_hash(),
            &hash,
            &digest(&material.recovery_state),
            &h('b'),
            NOW + 63
        )
        .unwrap(),
        State::RolledBack
    );
}

#[test]
fn failed_material_write_consumes_neither_generation_nor_operation() {
    let (grant, material, _) = fixture();
    let dir = private_test_directory();
    let mut j = journal(&dir.path().join("journal"), &grant);
    j.connection.execute_batch("CREATE TRIGGER fail_material BEFORE INSERT ON execution_material BEGIN SELECT RAISE(ABORT,'injected durable failure'); END;").unwrap();
    assert!(j.accept_execution(&grant, OP, &material, NOW).is_err());
    assert_eq!(j.highest_generation().unwrap(), 0);
    assert!(j.operation(OP).unwrap().is_none());
    assert!(j.execution_material(OP).unwrap().is_none());
}

#[test]
fn mismatched_signed_objects_and_legacy_upgrade_fail_closed() {
    let (grant, material, _) = fixture();
    let dir = private_test_directory();
    let mut j = journal(&dir.path().join("journal"), &grant);
    for field in 0..6 {
        let mut bad = material.clone();
        match field {
            0 => bad.candidate_state["tamper"] = true.into(),
            1 => bad.recovery_scope["tamper"] = true.into(),
            2 => bad.recovery_artifact["tamper"] = true.into(),
            3 => bad.baseline_state["tamper"] = true.into(),
            4 => bad.candidate_artifact["tamper"] = true.into(),
            _ => bad.signed_grant.payload["target_generation"] = "2".into(),
        }
        assert!(j.accept_execution(&grant, OP, &bad, NOW).is_err());
        assert_eq!(j.highest_generation().unwrap(), 0);
    }
    j.accept(&grant, OP, NOW).unwrap();
    assert!(matches!(
        j.accept_execution(&grant, OP, &material, NOW),
        Err(ExecutorError::Conflict)
    ));
}

#[test]
fn native_submission_requires_matching_immutable_acknowledgement() {
    let (grant, material, _) = fixture();
    let dir = private_test_directory();
    let mut j = journal(&dir.path().join("journal"), &grant);
    j.accept_execution(&grant, OP, &material, NOW).unwrap();
    assert!(matches!(
        j.mark_submitted(OP, NOW),
        Err(ExecutorError::Transition)
    ));
    assert!(j.arm_watchdog(OP, &h('e'), &h('a')).is_err());
    j.arm_watchdog(OP, &material.content_hash().unwrap(), &h('a'))
        .unwrap();
    j.arm_watchdog(OP, &material.content_hash().unwrap(), &h('a'))
        .unwrap();
    assert!(matches!(
        j.arm_watchdog(OP, &material.content_hash().unwrap(), &h('b')),
        Err(ExecutorError::Conflict)
    ));
    j.mark_submitted(OP, NOW + 1).unwrap();
    assert!(j.mark_submitted(OP, NOW + 2).is_err());
    assert_eq!(
        j.operation(OP).unwrap().unwrap().confirm_deadline,
        Some(NOW + 61)
    );
}

#[test]
fn claimed_recovery_survives_crash_and_only_exact_observation_completes() {
    let (grant, material, _) = fixture();
    let dir = private_test_directory();
    let path = dir.path().join("journal");
    let mut j = journal(&path, &grant);
    accept_and_submit(&mut j, &grant, &material);
    j.record_observation(OP, grant.desired_state_hash(), NOW + 2)
        .unwrap();
    j.claim_recovery(OP, 1, grant.desired_state_hash(), NOW + 61)
        .unwrap();
    drop(j);
    let mut j = ExecutorJournal::open(&path).unwrap();
    assert_eq!(
        j.operation(OP).unwrap().unwrap().state,
        State::RecoveryClaimed
    );
    assert!(j
        .record_recovery_completion(
            OP,
            1,
            grant.desired_state_hash(),
            &material.content_hash().unwrap(),
            &h('f'),
            &h('e'),
            NOW + 62
        )
        .is_err());
    assert_eq!(
        j.operation(OP).unwrap().unwrap().state,
        State::RecoveryClaimed
    );
    let recovered = digest(&material.recovery_state);
    assert_eq!(
        j.record_recovery_completion(
            OP,
            1,
            grant.desired_state_hash(),
            &material.content_hash().unwrap(),
            &recovered,
            &h('e'),
            NOW + 62
        )
        .unwrap(),
        State::RolledBack
    );
    assert_eq!(j.current_state_hash().unwrap(), recovered);
    assert_eq!(j.highest_generation().unwrap(), 1);
    let next_hash = h('d');
    j.accept_fields(
        &Acceptance {
            org_id: grant.org_id(),
            target_id: grant.target_id(),
            epoch: 1,
            generation: 2,
            grant_hash: &next_hash,
            baseline_hash: &recovered,
            desired_state_hash: grant.desired_state_hash(),
            issued_at: NOW,
            not_after: NOW + 240,
            confirm_not_after: NOW + 300,
        },
        NEXT,
        NOW + 63,
    )
    .unwrap();
    assert_eq!(j.highest_generation().unwrap(), 2);
    assert_eq!(j.latest_operation().unwrap().unwrap().operation_id, NEXT);
    assert!(j
        .record_recovery_completion(
            OP,
            1,
            grant.desired_state_hash(),
            &material.content_hash().unwrap(),
            &recovered,
            &h('e'),
            NOW + 64
        )
        .is_err());
}

#[test]
fn expired_recovery_authority_never_becomes_new_write_permission() {
    let (grant, material, _) = fixture();
    let dir = private_test_directory();
    let mut j = journal(&dir.path().join("journal"), &grant);
    accept_and_submit(&mut j, &grant, &material);
    assert!(matches!(
        j.claim_recovery(OP, 1, grant.desired_state_hash(), NOW + 300),
        Err(ExecutorError::Expired)
    ));
    j.claim_recovery(OP, 1, grant.desired_state_hash(), NOW + 61)
        .unwrap();
    assert!(matches!(
        j.record_recovery_completion(
            OP,
            1,
            grant.desired_state_hash(),
            &material.content_hash().unwrap(),
            &digest(&material.recovery_state),
            &h('e'),
            NOW + 300
        ),
        Err(ExecutorError::Expired)
    ));
    assert_eq!(
        j.operation(OP).unwrap().unwrap().state,
        State::RecoveryClaimed
    );
    assert_eq!(j.current_state_hash().unwrap(), grant.baseline_hash());
}

#[test]
fn actual_drift_withdraws_confirmation_and_blocks_new_generation() {
    let (grant, material, _) = fixture();
    let dir = private_test_directory();
    let mut j = journal(&dir.path().join("journal"), &grant);
    accept_and_submit(&mut j, &grant, &material);
    j.record_observation(OP, grant.desired_state_hash(), NOW + 2)
        .unwrap();
    let confirmation = Confirmation {
        schema_version: "fw.experimental-confirm/v1".into(),
        operation_id: OP.into(),
        org_id: grant.org_id().into(),
        target_id: grant.target_id().into(),
        authority_epoch: "1".into(),
        target_generation: "1".into(),
        grant_hash: grant.grant_hash().into(),
        state_hash: grant.desired_state_hash().into(),
        probe_report_hash: h('e'),
        issued_at_unix: NOW + 2,
        not_after_unix: NOW + 60,
    };
    let key = SigningKey::from_bytes(&[72; 32]);
    let bytes = canonical_bytes(&confirmation).unwrap();
    let envelope = DsseEnvelope {
        payload_type: CONFIRM_TYPE.into(),
        payload: STANDARD.encode(&bytes),
        signatures: vec![fw_authority::DsseSignature {
            keyid: "confirm-fixture".into(),
            sig: STANDARD.encode(key.sign(&pae(CONFIRM_TYPE, &bytes)).to_bytes()),
        }],
    };
    let trust = TrustKey {
        key_id: "confirm-fixture".into(),
        org_id: grant.org_id().into(),
        payload_type: CONFIRM_TYPE.into(),
        public_key: key.verifying_key().to_bytes(),
        not_before: NOW,
        not_after: NOW + 3600,
        revoked: false,
    };
    j.confirm(&envelope, &trust, NOW + 3).unwrap();
    assert_eq!(j.mark_drift(OP, NOW + 4).unwrap(), State::Unknown);
    assert_eq!(
        j.record_observation(OP, grant.baseline_hash(), NOW + 5)
            .unwrap(),
        State::Unknown
    );
    assert_eq!(j.current_state_hash().unwrap(), grant.desired_state_hash());
    assert_eq!(j.highest_generation().unwrap(), 1);
    assert!(j.confirm(&envelope, &trust, NOW + 5).is_err());
}

#[test]
fn observed_candidate_cannot_be_reclassified_as_unapplied_after_restart() {
    let (grant, material, _) = fixture();
    let dir = private_test_directory();
    let path = dir.path().join("journal");
    let mut j = journal(&path, &grant);
    accept_and_submit(&mut j, &grant, &material);
    j.record_observation(OP, grant.desired_state_hash(), NOW + 2)
        .unwrap();
    drop(j);
    let mut j = ExecutorJournal::open(&path).unwrap();
    assert_eq!(
        j.record_observation(OP, grant.baseline_hash(), NOW + 3)
            .unwrap(),
        State::Unknown
    );
    let observed: String = j
        .connection
        .query_row(
            "SELECT observed_hash FROM operations WHERE operation_id=?1",
            [OP],
            |r| r.get(0),
        )
        .unwrap();
    assert_eq!(observed, grant.desired_state_hash());
    assert_eq!(j.current_state_hash().unwrap(), grant.baseline_hash());
}

#[test]
fn prepared_recovery_is_prior_application_evidence_even_without_observation_row() {
    let (grant, material, _) = fixture();
    let dir = private_test_directory();
    let path = dir.path().join("journal");
    let mut j = journal(&path, &grant);
    accept_and_submit(&mut j, &grant, &material);
    j.prepare_recovery_attempt(
        OP,
        &material.content_hash().unwrap(),
        &json!({"binding":"fresh candidate was observed"}),
        NOW + 61,
    )
    .unwrap();
    drop(j);
    let mut j = ExecutorJournal::open(&path).unwrap();
    assert_eq!(
        j.record_observation(OP, grant.baseline_hash(), NOW + 62)
            .unwrap(),
        State::Unknown
    );
    assert_eq!(j.latest_recovery_attempt(OP).unwrap().unwrap().sequence, 1);
}

#[cfg(unix)]
#[test]
fn journal_rejects_public_parents_and_linked_database_lock_or_sidecar() {
    use std::os::unix::fs::{symlink, PermissionsExt};
    let (grant, _, _) = fixture();
    let dir = private_test_directory();
    let path = dir.path().join("journal");
    std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o755)).unwrap();
    assert!(ExecutorJournal::create(
        &path,
        grant.org_id(),
        grant.target_id(),
        1,
        grant.baseline_hash()
    )
    .is_err());
    std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
    let j = journal(&path, &grant);
    drop(j);
    let linked = dir.path().join("linked");
    symlink(&path, &linked).unwrap();
    assert!(ExecutorJournal::open(&linked).is_err());
    let hard = dir.path().join("hard");
    std::fs::hard_link(&path, &hard).unwrap();
    assert!(ExecutorJournal::open(&path).is_err());
    std::fs::remove_file(&hard).unwrap();
    let lock = dir.path().join("journal.lock");
    std::fs::remove_file(&lock).unwrap();
    symlink(&path, &lock).unwrap();
    assert!(ExecutorJournal::open(&path).is_err());
    std::fs::remove_file(&lock).unwrap();
    let sidecar = dir.path().join("journal-journal");
    symlink(&path, &sidecar).unwrap();
    assert!(ExecutorJournal::open(&path).is_err());
    std::fs::remove_file(&sidecar).unwrap();
    assert!(ExecutorJournal::open(&path).is_ok());
}

#[test]
fn version_one_migration_preserves_fencing_without_inventing_native_material() {
    let (grant, _, _) = fixture();
    let dir = private_test_directory();
    let path = dir.path().join("journal");
    let mut j = journal(&path, &grant);
    j.accept(&grant, OP, NOW).unwrap();
    j.connection
        .execute_batch(
            "DROP TABLE recovery_attempts; DROP TABLE execution_material; PRAGMA user_version=1;",
        )
        .unwrap();
    drop(j);
    let j = ExecutorJournal::open(&path).unwrap();
    assert_eq!(j.highest_generation().unwrap(), 1);
    assert_eq!(j.operation(OP).unwrap().unwrap().state, State::Unknown);
    assert!(j.execution_material(OP).unwrap().is_none());
    assert_eq!(
        j.connection
            .query_row("PRAGMA user_version", [], |r| r.get::<_, u32>(0))
            .unwrap(),
        3
    );
}

#[test]
fn logical_metadata_corruption_cannot_extend_signed_or_derived_windows() {
    let (grant, material, _) = fixture();
    for mutation in [
        "UPDATE operations SET issued_at=issued_at+1",
        "UPDATE operations SET not_after=not_after+1",
        "UPDATE operations SET confirm_not_after=confirm_not_after+1",
        "UPDATE operations SET generation='2'",
        "UPDATE operations SET submitted_at=submitted_at+1",
        "UPDATE operations SET confirm_deadline=confirm_deadline+1",
        "UPDATE operations SET submitted_at=NULL",
        "UPDATE execution_material SET recovery_valid_until=recovery_valid_until+1",
    ] {
        let dir = private_test_directory();
        let mut j = journal(&dir.path().join("journal"), &grant);
        accept_and_submit(&mut j, &grant, &material);
        j.connection.execute_batch(mutation).unwrap();
        assert_eq!(
            j.connection
                .query_row("PRAGMA integrity_check", [], |r| r.get::<_, String>(0))
                .unwrap(),
            "ok"
        );
        assert!(
            matches!(j.execution_material(OP), Err(ExecutorError::Binding)),
            "{mutation}"
        );
        assert!(j.operation(OP).is_err(), "{mutation}");
        assert!(
            j.record_observation(OP, grant.desired_state_hash(), NOW + 2)
                .is_err(),
            "{mutation}"
        );
        assert!(
            j.claim_recovery(OP, 1, grant.desired_state_hash(), NOW + 61)
                .is_err(),
            "{mutation}"
        );
        assert_eq!(j.highest_generation().unwrap(), 1);
    }
}

#[test]
fn rehashed_material_still_has_to_resolve_exact_signed_artifact_and_scope() {
    let (grant, material, _) = fixture();
    for field in 0..3 {
        let dir = private_test_directory();
        let mut j = journal(&dir.path().join("journal"), &grant);
        j.accept_execution(&grant, OP, &material, NOW).unwrap();
        let mut bad = material.clone();
        match field {
            0 => bad.candidate_artifact["tampered"] = true.into(),
            1 => bad.recovery_artifact["tampered"] = true.into(),
            _ => bad.recovery_scope["tampered"] = true.into(),
        }
        j.connection
            .execute(
                "UPDATE execution_material SET material_bytes=?1,material_hash=?2",
                params![canonical_bytes(&bad).unwrap(), bad.content_hash().unwrap()],
            )
            .unwrap();
        assert!(matches!(
            j.execution_material(OP),
            Err(ExecutorError::Binding)
        ));
        assert_eq!(j.highest_generation().unwrap(), 1);
    }
}
