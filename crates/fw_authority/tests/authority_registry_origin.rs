#![cfg(feature = "approval-proofs")]
#[allow(dead_code)]
#[path = "support/approval_authenticator.rs"]
mod approval_authenticator;
#[path = "support/private_directory.rs"]
mod private_directory;
#[path = "support/registry_fixture.rs"]
mod registry_fixture;

use fw_authority::{AuthorityError, BootstrapApprovalOriginPin};
use registry_fixture::{Fixture, NOW, OWNER, at};
use rusqlite::Connection;

#[test]
fn repinning_a_revoked_registry_key_reports_conflict_without_restoring_authority() {
    let directory = private_directory::private_directory();
    let mut fixture = Fixture::new(directory.path(), NOW);
    fixture
        .store
        .revoke_registry_trust_key(&fixture.tenant, &fixture.issuer_pin.key_id, NOW + 1)
        .unwrap();
    let db = Connection::open(&fixture.path).unwrap();
    let before: i64 = db
        .query_row("SELECT count(*) FROM authority_audit", [], |row| row.get(0))
        .unwrap();
    assert!(matches!(
        fixture
            .store
            .pin_registry_trust_key(&fixture.tenant, &fixture.issuer_pin, NOW + 1,),
        Err(AuthorityError::Conflict)
    ));
    assert_eq!(
        db.query_row(
            "SELECT count(*) FROM authority_registry_keys WHERE key_id=?",
            [&fixture.issuer_pin.key_id],
            |row| row.get::<_, i64>(0)
        )
        .unwrap(),
        1
    );
    assert_eq!(
        db.query_row(
            "SELECT count(*) FROM authority_registry_key_revocations WHERE key_id=?",
            [&fixture.issuer_pin.key_id],
            |row| row.get::<_, i64>(0)
        )
        .unwrap(),
        1
    );
    assert_eq!(
        db.query_row("SELECT count(*) FROM authority_audit", [], |row| row
            .get::<_, i64>(0))
            .unwrap(),
        before
    );
    let status = fixture
        .store
        .read_registry_object(
            &fixture.tenant,
            "workload_binding",
            &fixture.workload.payload.binding_id,
            NOW + 1,
        )
        .unwrap()
        .unwrap();
    assert!(!status.current && !status.signing_allowed && !status.dispatch_allowed);
}

#[test]
fn a_proof_from_an_unpinned_localhost_port_is_never_current_owner_approval() {
    let directory = private_directory::private_directory();
    let mut fixture = Fixture::new(directory.path(), NOW);
    let other_origin = "http://localhost:8899";
    let other_verifier = fw_webauthn::WebAuthn::new(other_origin).unwrap();
    let issued = fixture.store.issue_bootstrap_challenge(
        &fixture.tenant,
        OWNER,
        &fixture.credential.id(),
        &fixture.manifest.manifest_id,
        &other_verifier,
        NOW,
    );
    // A valid current implementation can refuse before issuing any challenge
    // or proof. If it retains cryptographic history, it cannot call that proof
    // a current project-owner approval for an independently untrusted origin.
    let issued = match issued {
        Err(AuthorityError::Binding) => return,
        result => result.unwrap(),
    };
    let assertion = fixture
        .authenticator
        .assertion(&issued.options, 2, 5, other_origin);
    let proof = fixture.store.admit_bootstrap_proof(
        &fixture.tenant,
        OWNER,
        issued.challenge.challenge_id(),
        &assertion,
        &other_verifier,
        NOW,
    );
    match proof {
        Err(AuthorityError::Binding) => return,
        result => {
            result.unwrap();
        }
    }
    let status = fixture
        .store
        .read_registry_object(
            &fixture.tenant,
            "bootstrap_manifest",
            &fixture.manifest.manifest_id,
            NOW,
        )
        .unwrap()
        .unwrap();
    assert_ne!(status.state, "owner_approved");
}

fn origin_pin(
    fixture: &Fixture,
    revision: u64,
    origin: &str,
    end: i64,
) -> BootstrapApprovalOriginPin {
    BootstrapApprovalOriginPin {
        schema_version: "fw.bootstrap-approval-origin-pin/v1".into(),
        org_id: fixture.tenant.org_id().into(),
        project_id: fixture.tenant.project_id().into(),
        revision: revision.to_string(),
        origin: origin.into(),
        rp_id: "localhost".into(),
        not_before: at(NOW - 60),
        not_after: at(end),
    }
}

#[test]
fn caller_origin_is_not_an_independent_project_pin() {
    let directory = private_directory::private_directory();
    let mut f = Fixture::new_unpinned(directory.path(), NOW);
    assert!(
        f.store
            .read_bootstrap_approval_origin(&f.tenant, NOW)
            .unwrap()
            .is_none()
    );
    assert!(matches!(
        f.store.issue_bootstrap_challenge(
            &f.tenant,
            OWNER,
            &f.credential.id(),
            &f.manifest.manifest_id,
            &f.verifier,
            NOW
        ),
        Err(AuthorityError::Binding)
    ));
    let status = f
        .store
        .read_registry_object(
            &f.tenant,
            "bootstrap_manifest",
            &f.manifest.manifest_id,
            NOW,
        )
        .unwrap()
        .unwrap();
    assert_eq!(status.state, "staged");
    assert!(
        status
            .gates
            .iter()
            .any(|gate| gate == "BOOTSTRAP_APPROVAL_ORIGIN_REQUIRED")
    );
    let pin = origin_pin(&f, 1, approval_authenticator::ORIGIN, NOW + 3600);
    let pinned = f
        .store
        .pin_bootstrap_approval_origin(&f.tenant, &pin, None, NOW)
        .unwrap();
    assert!(pinned.current);
    assert_eq!(pinned.revision, "1");
    let proof = f.approve(2);
    assert!(!proof.replayed);
    assert_eq!(
        f.store
            .read_registry_object(
                &f.tenant,
                "bootstrap_manifest",
                &f.manifest.manifest_id,
                NOW
            )
            .unwrap()
            .unwrap()
            .state,
        "owner_approved"
    );
}

#[test]
fn explicit_project_pin_rejects_other_port_at_challenge_and_admission() {
    let directory = private_directory::private_directory();
    let mut f = Fixture::new(directory.path(), NOW);
    let other_origin = "http://localhost:8899";
    let other = fw_webauthn::WebAuthn::new(other_origin).unwrap();
    assert!(matches!(
        f.store.issue_bootstrap_challenge(
            &f.tenant,
            OWNER,
            &f.credential.id(),
            &f.manifest.manifest_id,
            &other,
            NOW
        ),
        Err(AuthorityError::Binding)
    ));
    let issued = f
        .store
        .issue_bootstrap_challenge(
            &f.tenant,
            OWNER,
            &f.credential.id(),
            &f.manifest.manifest_id,
            &f.verifier,
            NOW,
        )
        .unwrap();
    let wrong = f
        .authenticator
        .assertion(&issued.options, 2, 5, other_origin);
    assert!(matches!(
        f.store.admit_bootstrap_proof(
            &f.tenant,
            OWNER,
            issued.challenge.challenge_id(),
            &wrong,
            &other,
            NOW
        ),
        Err(AuthorityError::Binding)
    ));
    let correct = f
        .authenticator
        .assertion(&issued.options, 2, 5, approval_authenticator::ORIGIN);
    f.store
        .admit_bootstrap_proof(
            &f.tenant,
            OWNER,
            issued.challenge.challenge_id(),
            &correct,
            &f.verifier,
            NOW,
        )
        .unwrap();
    assert_eq!(
        f.store
            .read_registry_object(
                &f.tenant,
                "bootstrap_manifest",
                &f.manifest.manifest_id,
                NOW
            )
            .unwrap()
            .unwrap()
            .state,
        "owner_approved"
    );
}

#[test]
fn origin_rotation_invalidates_old_challenges_and_current_proofs_without_rewriting_authorization() {
    let directory = private_directory::private_directory();
    let mut f = Fixture::new(directory.path(), NOW);
    f.approve(2);
    let authorized = f.authorize();
    let original = fw_contracts::canonical_bytes(&authorized.authorization).unwrap();
    let pending = f
        .store
        .issue_bootstrap_challenge(
            &f.tenant,
            OWNER,
            &f.credential.id(),
            &f.manifest.manifest_id,
            &f.verifier,
            NOW,
        )
        .unwrap();
    let next_origin = "http://localhost:8899";
    let pin = origin_pin(&f, 2, next_origin, NOW + 3600);
    f.store
        .pin_bootstrap_approval_origin(&f.tenant, &pin, Some(1), NOW + 1)
        .unwrap();
    let stale = f
        .authenticator
        .assertion(&pending.options, 3, 5, approval_authenticator::ORIGIN);
    assert!(matches!(
        f.store.admit_bootstrap_proof(
            &f.tenant,
            OWNER,
            pending.challenge.challenge_id(),
            &stale,
            &f.verifier,
            NOW + 1
        ),
        Err(AuthorityError::Binding)
    ));
    assert_eq!(
        f.store
            .read_registry_object(
                &f.tenant,
                "bootstrap_manifest",
                &f.manifest.manifest_id,
                NOW + 1
            )
            .unwrap()
            .unwrap()
            .state,
        "staged"
    );
    let history = f
        .store
        .read_registry_object(
            &f.tenant,
            "bootstrap_authorization",
            &f.manifest.manifest_id,
            NOW + 1,
        )
        .unwrap()
        .unwrap();
    assert_eq!(history.state, "historical");
    assert!(!history.current && !history.signing_allowed && !history.dispatch_allowed);
    let next = fw_webauthn::WebAuthn::new(next_origin).unwrap();
    let fresh = f
        .store
        .issue_bootstrap_challenge(
            &f.tenant,
            OWNER,
            &f.credential.id(),
            &f.manifest.manifest_id,
            &next,
            NOW + 1,
        )
        .unwrap();
    let assertion = f.authenticator.assertion(&fresh.options, 3, 5, next_origin);
    f.store
        .admit_bootstrap_proof(
            &f.tenant,
            OWNER,
            fresh.challenge.challenge_id(),
            &assertion,
            &next,
            NOW + 1,
        )
        .unwrap();
    assert_eq!(
        f.store
            .read_registry_object(
                &f.tenant,
                "bootstrap_manifest",
                &f.manifest.manifest_id,
                NOW + 1
            )
            .unwrap()
            .unwrap()
            .state,
        "owner_approved"
    );
    let replay = f
        .store
        .authorize_retained_bootstrap(
            &f.tenant,
            &f.manifest.manifest_id,
            &f.bootstrap_pin.key_id,
            &f.bootstrap_key,
            &next,
            NOW + 1,
        )
        .unwrap();
    assert_eq!(
        fw_contracts::canonical_bytes(&replay.authorization).unwrap(),
        original
    );
    assert_eq!(replay.status.state, "historical");
    drop(f.store);
    let mut store = fw_authority::AuthorityStore::open(&f.path).unwrap();
    let current = store
        .read_bootstrap_approval_origin(&f.tenant, NOW + 1)
        .unwrap()
        .unwrap();
    assert_eq!(current.revision, "2");
    assert_eq!(current.origin, next_origin);
}

#[test]
fn same_origin_new_revision_requires_a_fresh_owner_ceremony() {
    let directory = private_directory::private_directory();
    let mut f = Fixture::new(directory.path(), NOW);
    f.approve(2);
    let pin = origin_pin(&f, 2, approval_authenticator::ORIGIN, NOW + 3600);
    f.store
        .pin_bootstrap_approval_origin(&f.tenant, &pin, Some(1), NOW + 1)
        .unwrap();
    assert_eq!(
        f.store
            .read_registry_object(
                &f.tenant,
                "bootstrap_manifest",
                &f.manifest.manifest_id,
                NOW + 1
            )
            .unwrap()
            .unwrap()
            .state,
        "staged"
    );
}

#[test]
fn origin_pin_cas_and_exact_retry_preserve_audit_and_original_pin_lifetime() {
    let directory = private_directory::private_directory();
    let mut f = Fixture::new(directory.path(), NOW);
    let pin = origin_pin(&f, 1, approval_authenticator::ORIGIN, NOW + 3600);
    let original = f
        .store
        .read_bootstrap_approval_origin(&f.tenant, NOW)
        .unwrap()
        .unwrap();
    let db = Connection::open(&f.path).unwrap();
    let before: i64 = db
        .query_row("SELECT count(*) FROM authority_audit", [], |row| row.get(0))
        .unwrap();
    let retry = f
        .store
        .pin_bootstrap_approval_origin(&f.tenant, &pin, None, NOW + 1)
        .unwrap();
    assert_eq!(retry.pin_hash, original.pin_hash);
    assert_eq!(retry.pinned_at, original.pinned_at);
    assert_eq!(
        db.query_row("SELECT count(*) FROM authority_audit", [], |row| row
            .get::<_, i64>(0))
            .unwrap(),
        before
    );
    let mut skipped = origin_pin(&f, 3, "http://localhost:8899", NOW + 3600);
    assert!(matches!(
        f.store
            .pin_bootstrap_approval_origin(&f.tenant, &skipped, Some(1), NOW + 1),
        Err(AuthorityError::Conflict)
    ));
    skipped.revision = "2".into();
    assert!(matches!(
        f.store
            .pin_bootstrap_approval_origin(&f.tenant, &skipped, None, NOW + 1),
        Err(AuthorityError::Conflict)
    ));
    f.store
        .pin_bootstrap_approval_origin(&f.tenant, &skipped, Some(1), NOW + 1)
        .unwrap();
    let again = f
        .store
        .pin_bootstrap_approval_origin(&f.tenant, &skipped, Some(1), NOW + 2)
        .unwrap();
    assert_eq!(again.revision, "2");
    assert_eq!(again.pinned_at, at(NOW + 1));
}

#[test]
fn malformed_origin_trust_is_rejected_before_observing_time() {
    let directory = private_directory::private_directory();
    let mut f = Fixture::new_unpinned(directory.path(), NOW);
    let mut pin = origin_pin(&f, 1, approval_authenticator::ORIGIN, NOW + 3600);
    pin.rp_id = "other.example".into();
    assert!(matches!(
        f.store
            .pin_bootstrap_approval_origin(&f.tenant, &pin, None, NOW + 100),
        Err(AuthorityError::Binding)
    ));
    pin.rp_id = "localhost".into();
    pin.project_id = "ffffffff-ffff-4fff-8fff-ffffffffffff".into();
    assert!(
        f.store
            .pin_bootstrap_approval_origin(&f.tenant, &pin, None, NOW + 100)
            .is_err()
    );
    let observed: i64 = Connection::open(&f.path)
        .unwrap()
        .query_row(
            "SELECT observed_at FROM authority_registry_clocks",
            [],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(observed, NOW);
}

#[test]
fn owner_proof_deadline_is_bounded_by_origin_and_observed_expiry_cannot_revert() {
    let directory = private_directory::private_directory();
    let mut f = Fixture::new_unpinned(directory.path(), NOW);
    let pin = origin_pin(&f, 1, approval_authenticator::ORIGIN, NOW + 10);
    f.store
        .pin_bootstrap_approval_origin(&f.tenant, &pin, None, NOW)
        .unwrap();
    let proof = f.approve(2);
    assert_eq!(proof.proof.valid_until, at(NOW + 10));
    let expired = f
        .store
        .read_bootstrap_approval_origin(&f.tenant, NOW + 10)
        .unwrap()
        .unwrap();
    assert!(!expired.current);
    assert!(matches!(
        f.store.issue_bootstrap_challenge(
            &f.tenant,
            OWNER,
            &f.credential.id(),
            &f.manifest.manifest_id,
            &f.verifier,
            NOW + 9
        ),
        Err(AuthorityError::Time)
    ));
    drop(f.store);
    let mut store = fw_authority::AuthorityStore::open(&f.path).unwrap();
    assert!(
        !store
            .read_bootstrap_approval_origin(&f.tenant, NOW + 10)
            .unwrap()
            .unwrap()
            .current
    );
    assert!(matches!(
        store.read_bootstrap_approval_origin(&f.tenant, NOW + 9),
        Err(AuthorityError::Time)
    ));
}

#[test]
fn signed_workload_admission_preserves_independent_asset_hash_sets() {
    let directory = private_directory::private_directory();
    let mut f = Fixture::new(directory.path(), NOW);
    let mut payload = f.workload.payload.clone();
    payload.binding_id = "dddddddd-dddd-4ddd-8ddd-dddddddddddd".into();
    payload.workload_id = "independent-hash-set-workload".into();
    payload.asset_revision_hashes.push(fw_contracts::hash_bytes(
        b"independent second immutable revision",
    ));
    payload.asset_revision_hashes.sort();
    assert_eq!(payload.asset_ids.len(), 1);
    assert_eq!(payload.asset_revision_hashes.len(), 2);
    let binding = registry_fixture::sign_workload(payload, &f.issuer_key, &f.issuer_pin.key_id);
    let admitted = f
        .store
        .admit_workload_binding(&f.tenant, &binding, NOW)
        .unwrap();
    assert!(admitted.current);
    assert!(!admitted.signing_allowed && !admitted.dispatch_allowed);
}

#[test]
fn extra_unverified_dsse_signature_cannot_occupy_new_registry_identity() {
    use base64::{Engine, engine::general_purpose::STANDARD};
    let directory = private_directory::private_directory();
    let mut f = Fixture::new(directory.path(), NOW);
    let mut payload = f.workload.payload.clone();
    payload.binding_id = "dddddddd-dddd-4ddd-8ddd-dddddddddddd".into();
    payload.workload_id = "single-authoritative-signature".into();
    let original = registry_fixture::sign_workload(payload, &f.issuer_key, &f.issuer_pin.key_id);
    let mut surplus = original.clone();
    surplus.dsse.signatures.push(fw_authority::DsseSignature {
        keyid: "untrusted-extra-key".into(),
        sig: STANDARD.encode([0u8; 64]),
    });
    assert!(matches!(
        f.store.admit_workload_binding(&f.tenant, &surplus, NOW),
        Err(AuthorityError::Invalid(
            "unsupported registry signature profile"
        ))
    ));
    let admitted = f
        .store
        .admit_workload_binding(&f.tenant, &original, NOW)
        .unwrap();
    assert!(admitted.current);
}
