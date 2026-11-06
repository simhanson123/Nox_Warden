#![cfg(feature = "approval-proofs")]
use base64::{Engine, engine::general_purpose::STANDARD};
use ed25519_dalek::{Signer, SigningKey};
use fw_authority::*;
use fw_contracts::{canonical_bytes, canonical_hash};
use serde::Serialize;
use serde_json::json;

#[path = "support/core_access_fixture.rs"]
mod core_fixture;
const NOW: i64 = 1793491200;
fn id(n: u8) -> String {
    format!("00000000-0000-4000-8000-{n:012}")
}
fn hash(n: u8) -> String {
    format!("sha256:{n:064x}")
}
fn at(t: i64) -> String {
    chrono::DateTime::<chrono::Utc>::from_timestamp(t, 0)
        .unwrap()
        .format("%Y-%m-%dT%H:%M:%SZ")
        .to_string()
}
fn trust(purpose: &str) -> (SigningKey, RegistryTrustKey) {
    let key = SigningKey::from_bytes(&[53; 32]);
    let pin = RegistryTrustKey {
        key_id: "issuer-1".into(),
        org_id: id(1),
        project_id: id(2),
        target_id: id(3),
        payload_type: purpose.into(),
        public_key: key.verifying_key().to_bytes(),
        not_before: NOW - 100,
        not_after: NOW + 2000,
        revoked: false,
    };
    (key, pin)
}
fn sign<T: Serialize>(payload: &T, key: &SigningKey, trust: &RegistryTrustKey) -> DsseEnvelope {
    let bytes = canonical_bytes(payload).unwrap();
    DsseEnvelope {
        payload_type: trust.payload_type.clone(),
        payload: STANDARD.encode(&bytes),
        signatures: vec![DsseSignature {
            keyid: trust.key_id.clone(),
            sig: STANDARD.encode(key.sign(&pae(&trust.payload_type, &bytes)).to_bytes()),
        }],
    }
}
fn workload() -> (WorkloadBinding, RegistryTrustKey, SigningKey) {
    let (key, pin) = trust(WORKLOAD_BINDING_TYPE);
    let payload = WorkloadBindingPayload {
        schema_version: "f.workload-binding/v1".into(),
        binding_id: id(4),
        org_id: id(1),
        project_id: id(2),
        principal_id: id(5),
        issuer_key_id: pin.key_id.clone(),
        workload_id: "workload-a".into(),
        target_id: id(3),
        platform: "linux".into(),
        asset_ids: vec![id(6)],
        asset_revision_hashes: vec![hash(1)],
        addresses: vec![RegistryAssetAddress {
            family: "ipv4".into(),
            cidr: "192.0.2.1/32".into(),
            interface: None,
        }],
        isolation: WorkloadIsolation::Host {
            host_asset_id: id(6),
        },
        issued_at: at(NOW - 10),
        not_before: at(NOW - 10),
        expires_at: at(NOW + 1000),
        binding_epoch: "1".into(),
        attestation_evidence: RegistryEvidenceRef {
            store_id: "evidence".into(),
            object_hash: hash(8),
            media_type: "application/json".into(),
            size_bytes: 64,
        },
        audience: "fw_controller".into(),
    };
    let dsse = sign(&payload, &key, &pin);
    (WorkloadBinding { payload, dsse }, pin, key)
}
fn manifest() -> AuthorityBootstrapManifest {
    AuthorityBootstrapManifest {
        schema_version: "f.authority-bootstrap-manifest/v1".into(),
        manifest_id: id(10),
        org_id: id(1),
        project_id: id(2),
        target_id: id(3),
        old_epoch: None,
        new_epoch: "1".into(),
        created_at: at(NOW - 20),
        expires_at: at(NOW + 1000),
        trust_root_hash: hash(1),
        management_baseline_hash: hash(2),
        envelope_hashes: vec![hash(3)],
        delegation_hashes: vec![hash(4)],
        capability_hash: hash(5),
        reason: "Initial out-of-band authority ceremony".into(),
    }
}
fn bootstrap() -> (
    AuthorityBootstrapManifest,
    Vec<BootstrapApprovalProof>,
    BootstrapAuthorization,
    RegistryTrustKey,
    SigningKey,
) {
    let (key, pin) = trust(BOOTSTRAP_AUTHORIZATION_TYPE);
    let mut manifest = manifest();
    manifest.trust_root_hash = canonical_hash(&pin).unwrap();
    let proof = BootstrapApprovalProof {
        schema_version: "f.bootstrap-approval-proof/v1".into(),
        proof_id: id(11),
        subject_type: "authority_bootstrap".into(),
        subject_hash: manifest.hash().unwrap(),
        approver_id: id(12),
        webauthn_assertion_hash: hash(6),
        role_snapshot_hash: hash(7),
        approved_at: at(NOW - 10),
        valid_until: at(NOW + 900),
    };
    let payload = BootstrapAuthorizationPayload {
        schema_version: "f.bootstrap-authorization/v1".into(),
        manifest_hash: manifest.hash().unwrap(),
        approval_proof_hashes: vec![proof.hash().unwrap()],
        signer_key_id: pin.key_id.clone(),
        issued_at: at(NOW),
        not_after: at(NOW + 800),
    };
    let dsse = sign(&payload, &key, &pin);
    (
        manifest,
        vec![proof],
        BootstrapAuthorization {
            schema_version: "f.bootstrap-authorization-envelope/v1".into(),
            payload,
            dsse,
        },
        pin,
        key,
    )
}

#[test]
fn signed_workload_preserves_exact_original_bytes_and_separate_payload_hash() {
    let (binding, pin, _) = workload();
    let verified = verify_workload_binding(&binding, &pin, NOW).unwrap();
    assert_eq!(verified.hash(), canonical_hash(&binding).unwrap());
    assert_eq!(
        verified.payload_hash(),
        canonical_hash(&binding.payload).unwrap()
    );
    assert_eq!(
        verified.canonical_bytes(),
        canonical_bytes(&binding).unwrap()
    );
    assert_eq!(verified.binding_epoch(), 1);
    assert_eq!(verified.not_after(), NOW + 1000);
    let parsed = WorkloadBinding::from_bytes(verified.canonical_bytes()).unwrap();
    assert_eq!(
        verify_workload_binding(&parsed, &pin, NOW).unwrap().hash(),
        verified.hash()
    );
}

#[test]
fn workload_signature_rejects_payload_substitution_noncanonical_bytes_and_forgery() {
    let (binding, pin, key) = workload();
    let mut changed = binding.clone();
    changed.payload.workload_id.push('x');
    assert!(verify_workload_binding(&changed, &pin, NOW).is_err());
    let mut pretty = binding.clone();
    let bytes = serde_json::to_vec_pretty(&pretty.payload).unwrap();
    pretty.dsse.payload = STANDARD.encode(&bytes);
    pretty.dsse.signatures[0].sig =
        STANDARD.encode(key.sign(&pae(WORKLOAD_BINDING_TYPE, &bytes)).to_bytes());
    assert!(verify_workload_binding(&pretty, &pin, NOW).is_err());
    let mut forged = binding;
    forged.dsse.signatures[0].sig = STANDARD.encode([0u8; 64]);
    assert!(verify_workload_binding(&forged, &pin, NOW).is_err());
}

#[test]
fn workload_pin_tenant_target_purpose_revocation_and_lifetime_are_independent() {
    let (binding, pin, _) = workload();
    for mutate in [
        |p: &mut RegistryTrustKey| p.org_id = id(90),
        |p: &mut RegistryTrustKey| p.project_id = id(90),
        |p: &mut RegistryTrustKey| p.target_id = id(90),
        |p: &mut RegistryTrustKey| p.payload_type = BOOTSTRAP_AUTHORIZATION_TYPE.into(),
        |p: &mut RegistryTrustKey| p.revoked = true,
        |p: &mut RegistryTrustKey| p.not_after = NOW + 999,
        |p: &mut RegistryTrustKey| p.not_before = NOW - 9,
        |p: &mut RegistryTrustKey| p.key_id = "other".into(),
    ] {
        let mut other = pin.clone();
        mutate(&mut other);
        assert!(verify_workload_binding(&binding, &other, NOW).is_err());
    }
    assert!(verify_workload_binding(&binding, &pin, NOW - 11).is_err());
    assert!(verify_workload_binding(&binding, &pin, NOW + 1000).is_err());
}

#[test]
fn workload_contract_rejects_closed_shape_aliases_unsorted_sets_and_platform_claims() {
    let (binding, pin, key) = workload();
    let mut value = serde_json::to_value(&binding).unwrap();
    value["payload"]["isolation"]["unverified"] = json!(true);
    assert!(WorkloadBinding::from_bytes(&serde_json::to_vec(&value).unwrap()).is_err());
    let mut wrong = binding.clone();
    wrong.payload.asset_ids = vec![id(7), id(6)];
    wrong.payload.asset_revision_hashes = vec![hash(1), hash(2)];
    wrong.dsse = sign(&wrong.payload, &key, &pin);
    assert!(verify_workload_binding(&wrong, &pin, NOW).is_err());
    let mut platform = binding;
    platform.payload.isolation = WorkloadIsolation::MacosHost {
        host_asset_id: id(6),
        boot_id: id(8),
    };
    platform.dsse = sign(&platform.payload, &key, &pin);
    assert!(verify_workload_binding(&platform, &pin, NOW).is_err());
}

#[test]
fn workload_duplicate_json_keys_and_duplicate_signer_ids_are_rejected() {
    let (binding, pin, _) = workload();
    let bytes = serde_json::to_string(&binding).unwrap().replacen(
        "\"binding_id\":",
        &format!("\"binding_id\":\"{}\",\"binding_id\":", id(4)),
        1,
    );
    assert!(WorkloadBinding::from_bytes(bytes.as_bytes()).is_err());
    let mut duplicate = binding;
    duplicate
        .dsse
        .signatures
        .push(duplicate.dsse.signatures[0].clone());
    assert!(verify_workload_binding(&duplicate, &pin, NOW).is_err());
}

#[test]
fn original_required_nullable_fields_must_be_present() {
    let (binding, _, _) = workload();
    let mut value = serde_json::to_value(&binding).unwrap();
    value["payload"]["addresses"][0]
        .as_object_mut()
        .unwrap()
        .remove("interface");
    assert!(WorkloadBinding::from_bytes(&serde_json::to_vec(&value).unwrap()).is_err());
    let mut value = serde_json::to_value(manifest()).unwrap();
    value.as_object_mut().unwrap().remove("old_epoch");
    assert!(AuthorityBootstrapManifest::from_bytes(&serde_json::to_vec(&value).unwrap()).is_err());
}

#[test]
fn preflight_shape_does_not_create_signature_or_current_authority() {
    let (mut binding, pin, _) = workload();
    binding.dsse.signatures[0].sig = STANDARD.encode([0u8; 64]);
    binding.validate_shape().unwrap();
    assert!(verify_workload_binding(&binding, &pin, NOW).is_err());
    let (manifest, proofs, mut authorization, pin, _) = bootstrap();
    authorization.validate_shape().unwrap();
    assert!(
        verify_bootstrap_authorization(&authorization, &manifest, &proofs, &pin, NOW + 800)
            .is_err()
    );
    authorization.payload.schema_version = "f.bootstrap-authorization/v2".into();
    assert!(authorization.validate_shape().is_err());
}

#[test]
fn bootstrap_verifies_exact_signature_and_proof_references_without_claiming_human_consent() {
    let (manifest, proofs, authorization, pin, _) = bootstrap();
    let verified =
        verify_bootstrap_authorization(&authorization, &manifest, &proofs, &pin, NOW).unwrap();
    assert_eq!(verified.hash(), canonical_hash(&authorization).unwrap());
    assert_eq!(verified.manifest_hash(), manifest.hash().unwrap());
    assert_eq!(
        verified.canonical_bytes(),
        canonical_bytes(&authorization).unwrap()
    );
    assert_eq!(verified.not_after(), NOW + 800);
}

#[test]
fn bootstrap_does_not_accept_subject_proof_substitution_self_asserted_signer_or_wrong_context() {
    let (manifest, proofs, authorization, pin, _) = bootstrap();
    let mut modified = manifest.clone();
    modified.reason.push('x');
    assert!(verify_bootstrap_authorization(&authorization, &modified, &proofs, &pin, NOW).is_err());
    let mut wrong = proofs.clone();
    wrong[0].webauthn_assertion_hash = hash(99);
    assert!(verify_bootstrap_authorization(&authorization, &manifest, &wrong, &pin, NOW).is_err());
    let mut trust = pin.clone();
    trust.public_key = SigningKey::from_bytes(&[99; 32]).verifying_key().to_bytes();
    assert!(
        verify_bootstrap_authorization(&authorization, &manifest, &proofs, &trust, NOW).is_err()
    );
    let mut tenant = pin;
    tenant.target_id = id(99);
    assert!(
        verify_bootstrap_authorization(&authorization, &manifest, &proofs, &tenant, NOW).is_err()
    );
}

#[test]
fn another_valid_scoped_bootstrap_key_cannot_replace_the_manifest_root() {
    let (manifest, proofs, mut authorization, mut pin, _) = bootstrap();
    let key = SigningKey::from_bytes(&[91; 32]);
    pin.public_key = key.verifying_key().to_bytes();
    pin.key_id = "different-valid-bootstrap-root".into();
    pin.validate(NOW).unwrap();
    authorization.payload.signer_key_id = pin.key_id.clone();
    authorization.dsse = sign(&authorization.payload, &key, &pin);
    assert!(verify_bootstrap_authorization(&authorization, &manifest, &proofs, &pin, NOW).is_err());
}

#[test]
fn bootstrap_requires_monotonic_epoch_and_exclusive_all_object_expiry() {
    let (mut manifest, proofs, authorization, pin, _) = bootstrap();
    assert!(
        verify_bootstrap_authorization(&authorization, &manifest, &proofs, &pin, NOW + 800)
            .is_err()
    );
    manifest.old_epoch = Some("1".into());
    assert!(manifest.validate().is_err());
    manifest.new_epoch = "2".into();
    assert!(manifest.validate().is_ok());
    manifest.new_epoch = "18446744073709551616".into();
    assert!(manifest.validate().is_err());
    manifest.new_epoch = "02".into();
    assert!(manifest.validate().is_err());
}

#[test]
fn bootstrap_rejects_duplicate_human_and_proofs_and_signature_lifetime_extension() {
    let (manifest, proofs, mut authorization, pin, key) = bootstrap();
    let mut duplicates = proofs.clone();
    duplicates.push(proofs[0].clone());
    assert!(
        verify_bootstrap_authorization(&authorization, &manifest, &duplicates, &pin, NOW).is_err()
    );
    authorization.payload.not_after = at(NOW + 901);
    authorization.dsse = sign(&authorization.payload, &key, &pin);
    assert!(verify_bootstrap_authorization(&authorization, &manifest, &proofs, &pin, NOW).is_err());
}

#[test]
fn envelope_delegation_requires_exact_original_scope_limits_and_root_only() {
    let (_, provenance) = core_fixture::fixture();
    validate_access_envelope(&provenance.envelope).unwrap();
    validate_delegation(&provenance.delegation, &provenance.envelope).unwrap();
    let mut changed = provenance.delegation.clone();
    changed.can_delegate = true;
    assert!(validate_delegation(&changed, &provenance.envelope).is_err());
    changed = provenance.delegation.clone();
    changed.max_lease_seconds = provenance.envelope.max_lease_seconds + 1;
    assert!(validate_delegation(&changed, &provenance.envelope).is_err());
    changed = provenance.delegation.clone();
    changed.source_asset_ids = vec![id(99)];
    assert!(validate_delegation(&changed, &provenance.envelope).is_err());
}

#[test]
fn original_delegation_service_identifiers_preserve_bounded_string_semantics() {
    let (_, mut provenance) = core_fixture::fixture();
    provenance.delegation.service_ids = vec!["DB/read".into(), "Service:資料".into()];
    validate_delegation(&provenance.delegation, &provenance.envelope).unwrap();
    provenance.delegation.service_ids.push("DB/read".into());
    assert!(validate_delegation(&provenance.delegation, &provenance.envelope).is_err());
}
