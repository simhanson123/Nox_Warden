//! Explicit synthetic trust and a real software WebAuthn authenticator.
//! This fixture establishes cryptographic mechanics, never human consent or
//! native workload isolation. No fixture seed is used by product code.
#![allow(dead_code)]
use crate::approval_authenticator::{Authenticator, ORIGIN};
use base64::{Engine, engine::general_purpose::STANDARD};
use ed25519_dalek::{Signer, SigningKey};
use fw_authority::*;
use fw_contracts::{canonical_bytes, canonical_hash, hash_bytes};
use fw_webauthn::{Credential, WebAuthn};
use serde_json::Value;
use std::path::{Path, PathBuf};

pub const OWNER: &str = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa";
pub const NOW: i64 = 1_800_000_000;
pub fn at(now: i64) -> String {
    chrono::DateTime::from_timestamp(now, 0)
        .unwrap()
        .format("%Y-%m-%dT%H:%M:%SZ")
        .to_string()
}

pub struct Fixture {
    pub path: PathBuf,
    pub store: AuthorityStore,
    pub tenant: AuthorityTenant,
    pub verifier: WebAuthn,
    pub authenticator: Authenticator,
    pub credential: Credential,
    pub membership: String,
    pub bootstrap_key: SigningKey,
    pub issuer_key: SigningKey,
    pub bootstrap_pin: RegistryTrustKey,
    pub issuer_pin: RegistryTrustKey,
    pub workload: WorkloadBinding,
    pub envelope: AccessEnvelope,
    pub delegation: Delegation,
    pub manifest: AuthorityBootstrapManifest,
    pub now: i64,
}
impl Fixture {
    pub fn new(directory: &Path, now: i64) -> Self {
        let original: Value = serde_json::from_str(include_str!(
            "../../../../docs/specs/F_기준자료/F_개발계약/F_계약_예제.json"
        ))
        .unwrap();
        let mut envelope: AccessEnvelope =
            serde_json::from_value(original["envelope"].clone()).unwrap();
        envelope.valid_from = at(now - 60);
        envelope.valid_until = at(now + 3600);
        let mut delegation: Delegation =
            serde_json::from_value(original["delegation"].clone()).unwrap();
        delegation.valid_from = envelope.valid_from.clone();
        delegation.valid_until = envelope.valid_until.clone();
        delegation.envelope_hash = canonical_hash(&envelope).unwrap();
        let tenant = AuthorityTenant::new(&envelope.org_id, &envelope.project_id).unwrap();
        let path = directory.join("authority.sqlite3");
        let mut store = AuthorityStore::open(&path).unwrap();
        store
            .provision_principal(
                &tenant,
                OWNER,
                "https://fixture.identity.example",
                OWNER,
                now,
            )
            .unwrap();
        let verifier = WebAuthn::new(ORIGIN).unwrap();
        let authenticator = Authenticator::new(OWNER);
        let registration = verifier
            .begin_registration(OWNER, "Synthetic owner", &[])
            .unwrap();
        let credential = verifier
            .finish_registration(
                &registration.state,
                &authenticator.registration(&registration.options),
            )
            .unwrap();
        store
            .pin_credential(&tenant, &credential, now - 60, now + 3600, now)
            .unwrap();
        let activation = store
            .begin_credential_activation(&tenant, &credential.id(), &verifier, now)
            .unwrap();
        store
            .finish_credential_activation(
                &tenant,
                &activation.activation_id,
                &authenticator.assertion(&activation.options, 1, 5, ORIGIN),
                &verifier,
                now,
            )
            .unwrap();
        let membership = store
            .grant_role(
                &tenant,
                OWNER,
                ApprovalRole::Owner,
                now - 60,
                now + 3600,
                now,
            )
            .unwrap();
        store
            .bind_human_identity(&tenant, OWNER, OWNER, now)
            .unwrap();
        let issuer_key = SigningKey::from_bytes(&[41; 32]);
        let bootstrap_key = SigningKey::from_bytes(&[42; 32]);
        let pin = |key_id: &str, key: &SigningKey, payload_type: &str| RegistryTrustKey {
            key_id: key_id.into(),
            org_id: envelope.org_id.clone(),
            project_id: envelope.project_id.clone(),
            target_id: envelope.target_id.clone(),
            payload_type: payload_type.into(),
            public_key: key.verifying_key().to_bytes(),
            not_before: now - 60,
            not_after: now + 3600,
            revoked: false,
        };
        let issuer_pin = pin(
            "fixture-workload-issuer",
            &issuer_key,
            WORKLOAD_BINDING_TYPE,
        );
        let bootstrap_pin = pin(
            "fixture-bootstrap-signer",
            &bootstrap_key,
            BOOTSTRAP_AUTHORIZATION_TYPE,
        );
        store
            .pin_registry_trust_key(&tenant, &issuer_pin, now)
            .unwrap();
        store
            .pin_registry_trust_key(&tenant, &bootstrap_pin, now)
            .unwrap();
        let payload = WorkloadBindingPayload {
            schema_version: "f.workload-binding/v1".into(),
            binding_id: delegation.workload_binding_ids[0].clone(),
            org_id: envelope.org_id.clone(),
            project_id: envelope.project_id.clone(),
            principal_id: delegation.allowed_principal_ids[0].clone(),
            issuer_key_id: issuer_pin.key_id.clone(),
            workload_id: "synthetic-workload".into(),
            target_id: envelope.target_id.clone(),
            platform: "linux".into(),
            asset_ids: delegation.source_asset_ids.clone(),
            asset_revision_hashes: vec![hash_bytes(b"fixture immutable source asset")],
            addresses: vec![RegistryAssetAddress {
                family: "ipv4".into(),
                cidr: "10.20.1.0/24".into(),
                interface: None,
            }],
            isolation: WorkloadIsolation::Host {
                host_asset_id: delegation.source_asset_ids[0].clone(),
            },
            issued_at: at(now - 1),
            not_before: at(now - 1),
            expires_at: at(now + 3600),
            binding_epoch: "1".into(),
            attestation_evidence: RegistryEvidenceRef {
                store_id: "fixture".into(),
                object_hash: hash_bytes(b"synthetic workload provenance, not attestation"),
                media_type: "application/json".into(),
                size_bytes: 51,
            },
            audience: "fw_controller".into(),
        };
        let workload = sign_workload(payload, &issuer_key, &issuer_pin.key_id);
        store
            .admit_workload_binding(&tenant, &workload, now)
            .unwrap();
        store
            .stage_access_envelope(&tenant, &envelope, now)
            .unwrap();
        store.stage_delegation(&tenant, &delegation, now).unwrap();
        let manifest = AuthorityBootstrapManifest {
            schema_version: "f.authority-bootstrap-manifest/v1".into(),
            manifest_id: "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb".into(),
            org_id: envelope.org_id.clone(),
            project_id: envelope.project_id.clone(),
            target_id: envelope.target_id.clone(),
            old_epoch: None,
            new_epoch: "1".into(),
            created_at: at(now),
            expires_at: at(now + 300),
            trust_root_hash: canonical_hash(&bootstrap_pin).unwrap(),
            management_baseline_hash: hash_bytes(
                b"staged synthetic baseline; target confirmation absent",
            ),
            envelope_hashes: vec![canonical_hash(&envelope).unwrap()],
            delegation_hashes: vec![canonical_hash(&delegation).unwrap()],
            capability_hash: hash_bytes(b"synthetic unqualified capabilities"),
            reason: "Synthetic isolated signer integration fixture".into(),
        };
        store
            .stage_bootstrap_manifest(&tenant, &manifest, now)
            .unwrap();
        Self {
            path,
            store,
            tenant,
            verifier,
            authenticator,
            credential,
            membership,
            bootstrap_key,
            issuer_key,
            bootstrap_pin,
            issuer_pin,
            workload,
            envelope,
            delegation,
            manifest,
            now,
        }
    }
    pub fn approve(&mut self, counter: u32) -> BootstrapProofResult {
        let challenge = self
            .store
            .issue_bootstrap_challenge(
                &self.tenant,
                OWNER,
                &self.credential.id(),
                &self.manifest.manifest_id,
                &self.verifier,
                self.now,
            )
            .unwrap();
        self.store
            .admit_bootstrap_proof(
                &self.tenant,
                OWNER,
                challenge.challenge.challenge_id(),
                &self
                    .authenticator
                    .assertion(&challenge.options, counter, 5, ORIGIN),
                &self.verifier,
                self.now,
            )
            .unwrap()
    }
    pub fn authorize(&mut self) -> AuthorizedBootstrapResult {
        self.store
            .authorize_retained_bootstrap(
                &self.tenant,
                &self.manifest.manifest_id,
                &self.bootstrap_pin.key_id,
                &self.bootstrap_key,
                &self.verifier,
                self.now,
            )
            .unwrap()
    }
}

pub fn sign_workload(
    payload: WorkloadBindingPayload,
    key: &SigningKey,
    key_id: &str,
) -> WorkloadBinding {
    let canonical = canonical_bytes(&payload).unwrap();
    let signature = key.sign(&pae(WORKLOAD_BINDING_TYPE, &canonical));
    WorkloadBinding {
        payload,
        dsse: DsseEnvelope {
            payload_type: WORKLOAD_BINDING_TYPE.into(),
            payload: STANDARD.encode(&canonical),
            signatures: vec![DsseSignature {
                keyid: key_id.into(),
                sig: STANDARD.encode(signature.to_bytes()),
            }],
        },
    }
}
