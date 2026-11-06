#![cfg(feature = "approval-proofs")]
use base64::{Engine, engine::general_purpose::STANDARD};
use ed25519_dalek::{Signer, SigningKey};
use fw_authority::*;
use fw_backend_linux::*;
use fw_contracts::{MAX_DEPTH, canonical_bytes, hash_bytes};
use serde_json::{Value, json};

const NOW: i64 = 1793491200;
fn id(n: u8) -> String {
    format!("00000000-0000-4000-8000-{n:012}")
}
fn at(time: i64) -> String {
    chrono::DateTime::<chrono::Utc>::from_timestamp(time, 0)
        .unwrap()
        .format("%Y-%m-%dT%H:%M:%SZ")
        .to_string()
}
struct Fixture {
    baseline: BootstrapManagementBaseline,
    capability: BootstrapCapabilitySnapshot,
    pin: TargetBootstrapKeyPin,
    target_key: SigningKey,
    peer_key: SigningKey,
    payload: TargetBootstrapConfirmationPayload,
}
impl Fixture {
    fn new() -> Self {
        let peer_key = SigningKey::from_bytes(&[71; 32]);
        let target_key = SigningKey::from_bytes(&[72; 32]);
        let baseline = BootstrapManagementBaseline {
            schema_version: BOOTSTRAP_BASELINE_SCHEMA.into(),
            org_id: id(1),
            project_id: id(2),
            target_id: id(3),
            network_namespace: "net:[42]".into(),
            interface_name: "mgmt0".into(),
            interface_index: 2,
            local_address: "192.0.2.1".into(),
            peer_address: "192.0.2.2".into(),
            prefix_length: 30,
            management_tcp_port: 19443,
            positive_udp_port: 19444,
            negative_udp_port: 19445,
            peer_probe_public_key: peer_key.verifying_key().to_bytes(),
        };
        let capability = BootstrapCapabilitySnapshot {
            schema_version: BOOTSTRAP_CAPABILITY_SCHEMA.into(),
            platform: "linux".into(),
            backend: "nftables".into(),
            profile: BOOTSTRAP_PROFILE.into(),
            kernel_release: "6.1.0-synthetic-unit".into(),
            architecture: "x86_64".into(),
            nft_version: "nftables v1.0.6".into(),
        };
        let pin = TargetBootstrapKeyPin {
            schema_version: TARGET_BOOTSTRAP_KEY_SCHEMA.into(),
            org_id: id(1),
            project_id: id(2),
            target_id: id(3),
            key_id: "target-bootstrap-1".into(),
            revision: "1".into(),
            public_key: target_key.verifying_key().to_bytes(),
            not_before: at(NOW - 60),
            not_after: at(NOW + 600),
            profile: BOOTSTRAP_PROFILE.into(),
        };
        let program = compile_bootstrap_baseline(&baseline, &capability).unwrap();
        let challenge = TargetBootstrapChallenge {
            schema_version: TARGET_BOOTSTRAP_CHALLENGE_SCHEMA.into(),
            challenge_id: id(4),
            org_id: id(1),
            project_id: id(2),
            target_id: id(3),
            manifest_id: id(5),
            manifest_hash: hash_bytes(b"unit manifest"),
            authorization_hash: hash_bytes(b"unit authorization"),
            management_baseline_hash: baseline.hash().unwrap(),
            capability_hash: capability.hash().unwrap(),
            baseline_program_hash: program.hash().unwrap(),
            old_epoch: None,
            new_epoch: "1".into(),
            highest_generation: "0".into(),
            previous_confirmation_hash: None,
            key_id: pin.key_id.clone(),
            key_revision: pin.revision.clone(),
            key_fingerprint: pin.fingerprint(),
            nonce: STANDARD.encode([80; 32]),
            issued_at: at(NOW),
            expires_at: at(NOW + 60),
        };
        let mut probes = Vec::new();
        for (index, kind) in [
            BootstrapProbeKind::ManagementTcp,
            BootstrapProbeKind::PositiveUdp,
            BootstrapProbeKind::NegativeUdp,
        ]
        .into_iter()
        .enumerate()
        {
            let request = BootstrapProbeRequest {
                schema_version: BOOTSTRAP_PROBE_REQUEST_SCHEMA.into(),
                challenge_hash: challenge.hash().unwrap(),
                kind,
                nonce: STANDARD.encode([81 + index as u8; 32]),
            };
            let response = if kind == BootstrapProbeKind::NegativeUdp {
                None
            } else {
                Some(sign_bootstrap_probe_response(&request, &peer_key).unwrap())
            };
            probes.push(BootstrapProbeObservation {
                bytes_sent: request.wire_bytes().unwrap().len() as u64,
                bytes_received: response
                    .as_ref()
                    .map(|v| v.wire_bytes().unwrap().len() as u64)
                    .unwrap_or(0),
                outcome: if response.is_some() {
                    "reply"
                } else {
                    "timeout"
                }
                .into(),
                os_error: None,
                request,
                response,
            });
        }
        let payload = TargetBootstrapConfirmationPayload {
            schema_version: TARGET_BOOTSTRAP_PAYLOAD_SCHEMA.into(),
            challenge,
            journal_id: id(6),
            boot_id: id(7),
            network_namespace: baseline.network_namespace.clone(),
            accepted_epoch: "1".into(),
            highest_generation: "0".into(),
            accepted_at: at(NOW),
            observation_started_at: at(NOW),
            observation_finished_at: at(NOW + 1),
            observation_started_millis: "1000".into(),
            observation_finished_millis: "2000".into(),
            readback: json!({"nftables":program.nft_json["nftables"].as_array().unwrap().iter().map(|e|e["add"].clone()).collect::<Vec<_>>()}),
            probes,
        };
        Self {
            baseline,
            capability,
            pin,
            target_key,
            peer_key,
            payload,
        }
    }
    fn signed(
        &self,
        payload: TargetBootstrapConfirmationPayload,
    ) -> SignedTargetBootstrapConfirmation {
        // Deliberately signs even malformed observations so verifier tests reach
        // semantic checks rather than stopping at a stale target signature.
        let bytes = canonical_bytes(&payload).unwrap();
        SignedTargetBootstrapConfirmation {
            schema_version: TARGET_BOOTSTRAP_CONFIRMATION_SCHEMA.into(),
            payload,
            dsse: DsseEnvelope {
                payload_type: TARGET_BOOTSTRAP_CONFIRMATION_TYPE.into(),
                payload: STANDARD.encode(&bytes),
                signatures: vec![DsseSignature {
                    keyid: self.pin.key_id.clone(),
                    sig: STANDARD.encode(
                        self.target_key
                            .sign(&pae(TARGET_BOOTSTRAP_CONFIRMATION_TYPE, &bytes))
                            .to_bytes(),
                    ),
                }],
            },
        }
    }
    fn verify(
        &self,
        receipt: &SignedTargetBootstrapConfirmation,
    ) -> Result<VerifiedTargetBootstrapConfirmation> {
        verify_target_bootstrap_confirmation(
            receipt,
            &self.payload.challenge,
            &self.pin,
            &self.baseline,
            &self.capability,
            NOW + 1,
        )
    }
}

#[test]
fn signed_confirmation_preserves_exact_bytes_and_distinct_accepted_epoch_generation() {
    let f = Fixture::new();
    let receipt = sign_target_bootstrap_confirmation(
        f.payload.clone(),
        &f.pin,
        &f.target_key,
        &f.baseline,
        &f.capability,
        NOW + 1,
    )
    .unwrap();
    let bytes = receipt.canonical_bytes().unwrap();
    let decoded = SignedTargetBootstrapConfirmation::from_bytes(&bytes).unwrap();
    let verified = f.verify(&decoded).unwrap();
    assert_eq!(verified.canonical_bytes(), bytes);
    assert_eq!(verified.hash(), hash_bytes(&bytes));
    assert_eq!(verified.accepted_epoch(), 1);
    assert_eq!(verified.highest_generation(), 0);
    assert_eq!(verified.valid_until(), NOW + 60);
    assert_eq!(
        verified.readback_hash(),
        hash_bytes(&canonical_bytes(&f.payload.readback).unwrap())
    );
    assert_eq!(
        verified.program_hash(),
        f.payload.challenge.baseline_program_hash
    );
    assert!(
        verify_target_bootstrap_confirmation(
            &receipt,
            &f.payload.challenge,
            &f.pin,
            &f.baseline,
            &f.capability,
            NOW + 60
        )
        .is_err()
    );
    assert_eq!(receipt.canonical_bytes().unwrap(), bytes);
}

#[test]
fn signed_peer_exchange_is_bound_to_nonce_kind_challenge_and_independent_key() {
    let f = Fixture::new();
    let mut variants = Vec::new();
    let mut value = f.payload.clone();
    value.probes[0].response = value.probes[1].response.clone();
    variants.push(value);
    let mut value = f.payload.clone();
    value.probes[1].request.nonce = value.probes[0].request.nonce.clone();
    value.probes[1].response =
        Some(sign_bootstrap_probe_response(&value.probes[1].request, &f.peer_key).unwrap());
    variants.push(value);
    let mut value = f.payload.clone();
    value.probes[0].response.as_mut().unwrap().signature = STANDARD.encode([0; 64]);
    variants.push(value);
    let mut value = f.payload.clone();
    value.probes[2].outcome = "blocked".into();
    variants.push(value);
    let mut value = f.payload.clone();
    value.probes[2].response =
        Some(sign_bootstrap_probe_response(&value.probes[2].request, &f.peer_key).unwrap());
    variants.push(value);
    let mut value = f.payload.clone();
    value.probes[0].bytes_received += 1;
    variants.push(value);
    for payload in variants {
        assert!(f.verify(&f.signed(payload)).is_err());
    }
}

#[test]
fn local_send_denial_records_only_observed_linux_eperm_without_sent_packets() {
    let f = Fixture::new();
    let mut denied = f.payload.clone();
    denied.probes[2].outcome = "local_send_denied".into();
    denied.probes[2].os_error = Some(1);
    denied.probes[2].bytes_sent = 0;
    let receipt = f.signed(denied.clone());
    assert!(f.verify(&receipt).is_ok());
    assert_ne!(
        receipt.hash().unwrap(),
        f.signed(f.payload.clone()).hash().unwrap()
    );

    let mut variants = Vec::new();
    for error in [None, Some(0), Some(-1), Some(13), Some(110)] {
        let mut value = denied.clone();
        value.probes[2].os_error = error;
        variants.push(value);
    }
    let mut value = denied.clone();
    value.probes[2].bytes_sent = 1;
    variants.push(value);
    let mut value = denied.clone();
    value.probes[2].bytes_received = 1;
    variants.push(value);
    let mut value = denied.clone();
    value.probes[2].response =
        Some(sign_bootstrap_probe_response(&value.probes[2].request, &f.peer_key).unwrap());
    variants.push(value);
    let mut value = denied.clone();
    value.probes[2].outcome = "timeout".into();
    variants.push(value);
    for index in [0, 1] {
        let mut value = denied.clone();
        value.probes[index].outcome = "local_send_denied".into();
        value.probes[index].os_error = Some(1);
        value.probes[index].bytes_sent = 0;
        value.probes[index].bytes_received = 0;
        value.probes[index].response = None;
        variants.push(value);
    }
    for index in 0..3 {
        let mut value = f.payload.clone();
        value.probes[index].os_error = Some(1);
        variants.push(value);
    }
    for payload in variants {
        assert!(f.verify(&f.signed(payload)).is_err());
    }
    // Every observation declares the field, including successful replies and
    // actual receive timeouts. A missing field is not an inferred null.
    for index in 0..3 {
        let mut value = serde_json::to_value(&receipt).unwrap();
        value["payload"]["probes"][index]
            .as_object_mut()
            .unwrap()
            .remove("os_error");
        assert!(
            SignedTargetBootstrapConfirmation::from_bytes(&canonical_bytes(&value).unwrap())
                .is_err()
        );
    }
}

#[test]
fn target_signature_cannot_authorize_broader_readback_or_changed_epoch_context() {
    let f = Fixture::new();
    let mut variants = Vec::new();
    let mut value = f.payload.clone();
    value.readback["nftables"].as_array_mut().unwrap().push(
        json!({"rule":{"family":"inet","table":"other","chain":"output","expr":[{"accept":null}]}}),
    );
    variants.push(value);
    let mut value = f.payload.clone();
    value.accepted_epoch = "2".into();
    variants.push(value);
    let mut value = f.payload.clone();
    value.highest_generation = "1".into();
    variants.push(value);
    let mut value = f.payload.clone();
    value.network_namespace = "net:[43]".into();
    variants.push(value);
    let mut value = f.payload.clone();
    value.observation_finished_millis = "4001".into();
    variants.push(value);
    let mut value = f.payload.clone();
    value.challenge.previous_confirmation_hash = Some(hash_bytes(b"unretained"));
    variants.push(value);
    for payload in variants {
        assert!(f.verify(&f.signed(payload)).is_err());
    }
    let mut receipt = f.signed(f.payload.clone());
    receipt
        .dsse
        .signatures
        .push(receipt.dsse.signatures[0].clone());
    assert!(f.verify(&receipt).is_err());
}

#[test]
fn challenge_requires_explicit_predecessor_and_current_scoped_nonweak_target_pin() {
    let f = Fixture::new();
    let mut challenge = f.payload.challenge.clone();
    challenge.old_epoch = Some("1".into());
    challenge.new_epoch = "2".into();
    assert!(challenge.validate_shape().is_err());
    challenge.previous_confirmation_hash = Some(hash_bytes(b"retained predecessor"));
    challenge.validate_shape().unwrap();
    challenge.old_epoch = Some("2".into());
    assert!(challenge.validate_shape().is_err());
    let mut pin = f.pin.clone();
    pin.target_id = id(8);
    assert!(validate_target_bootstrap_key(&f.payload.challenge, &pin, NOW).is_err());
    let mut pin = f.pin.clone();
    pin.public_key = [0; 32];
    assert!(pin.validate_shape().is_err());
    let mut value = serde_json::to_value(&f.payload.challenge).unwrap();
    value.as_object_mut().unwrap().remove("old_epoch");
    assert!(serde_json::from_value::<TargetBootstrapChallenge>(value).is_err());
}

#[test]
fn typed_large_and_deep_inputs_are_rejected_before_unbounded_canonicalization() {
    let f = Fixture::new();
    let mut challenge = f.payload.challenge.clone();
    challenge.nonce = "A".repeat(1024 * 1024);
    assert!(challenge.validate_shape().is_err());
    let mut response = f.payload.probes[0].response.clone().unwrap();
    response.signature = "A".repeat(1024 * 1024);
    assert!(response.wire_bytes().is_err());
    let mut receipt = f.signed(f.payload.clone());
    receipt.payload.readback = json!({"oversize":"x".repeat(MAX_TARGET_BOOTSTRAP_BYTES)});
    assert!(receipt.canonical_bytes().is_err());
    let mut value = Value::Null;
    for _ in 0..MAX_DEPTH + 1 {
        value = Value::Array(vec![value]);
    }
    receipt.payload.readback = value;
    assert!(receipt.canonical_bytes().is_err());
    let mut raw = serde_json::to_value(&f.payload).unwrap();
    raw["negative_preflight"] = json!(null);
    assert!(serde_json::from_value::<TargetBootstrapConfirmationPayload>(raw).is_err());
}
