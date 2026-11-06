//! Synthetic readback with real independent target/peer signatures. Actual
//! owner proofs come from registry_fixture; this is not native qualification.
#![allow(dead_code)]
use crate::registry_fixture::{Fixture, at};
use base64::{Engine, engine::general_purpose::STANDARD};
use ed25519_dalek::SigningKey;
use fw_authority::*;
use fw_backend_linux::*;
use serde_json::json;

pub struct TargetFixture {
    pub target_key: SigningKey,
    pub peer_key: SigningKey,
    pub pin: TargetBootstrapKeyPin,
    pub baseline: BootstrapManagementBaseline,
    pub capability: BootstrapCapabilitySnapshot,
    pub journal_id: String,
}
impl TargetFixture {
    pub fn new(f: &mut Fixture) -> Self {
        let target_key = SigningKey::from_bytes(&[72; 32]);
        let peer_key = SigningKey::from_bytes(&[73; 32]);
        let pin = TargetBootstrapKeyPin {
            schema_version: TARGET_BOOTSTRAP_KEY_SCHEMA.into(),
            org_id: f.tenant.org_id().into(),
            project_id: f.tenant.project_id().into(),
            target_id: f.manifest.target_id.clone(),
            key_id: "target-bootstrap-1".into(),
            revision: "1".into(),
            public_key: target_key.verifying_key().to_bytes(),
            not_before: at(f.now - 60),
            not_after: at(f.now + 3600),
            profile: BOOTSTRAP_PROFILE.into(),
        };
        let baseline = BootstrapManagementBaseline {
            schema_version: BOOTSTRAP_BASELINE_SCHEMA.into(),
            org_id: pin.org_id.clone(),
            project_id: pin.project_id.clone(),
            target_id: pin.target_id.clone(),
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
        let fixture = Self {
            target_key,
            peer_key,
            pin,
            baseline,
            capability,
            journal_id: uuid::Uuid::new_v4().to_string(),
        };
        fixture.stage(f, None, 1);
        fixture
    }
    pub fn stage(&self, f: &mut Fixture, old: Option<u64>, next: u64) {
        f.manifest.manifest_id = uuid::Uuid::new_v4().to_string();
        f.manifest.old_epoch = old.map(|v| v.to_string());
        f.manifest.new_epoch = next.to_string();
        f.manifest.created_at = at(f.now);
        f.manifest.expires_at = at(f.now + 300);
        f.manifest.management_baseline_hash = self.baseline.hash().unwrap();
        f.manifest.capability_hash = self.capability.hash().unwrap();
        f.store
            .stage_bootstrap_manifest(&f.tenant, &f.manifest, f.now)
            .unwrap();
    }
    pub fn receipt(
        &self,
        challenge: TargetBootstrapChallenge,
        now: i64,
    ) -> SignedTargetBootstrapConfirmation {
        let program = compile_bootstrap_baseline(&self.baseline, &self.capability).unwrap();
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
                Some(sign_bootstrap_probe_response(&request, &self.peer_key).unwrap())
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
            accepted_epoch: challenge.new_epoch.clone(),
            highest_generation: "0".into(),
            challenge,
            journal_id: self.journal_id.clone(),
            boot_id: "99999999-9999-4999-8999-999999999999".into(),
            network_namespace: self.baseline.network_namespace.clone(),
            accepted_at: at(now),
            observation_started_at: at(now),
            observation_finished_at: at(now + 1),
            observation_started_millis: "1000".into(),
            observation_finished_millis: "2000".into(),
            readback: json!({"nftables":program.nft_json["nftables"].as_array().unwrap().iter().map(|e|e["add"].clone()).collect::<Vec<_>>()}),
            probes,
        };
        sign_target_bootstrap_confirmation(
            payload,
            &self.pin,
            &self.target_key,
            &self.baseline,
            &self.capability,
            now + 1,
        )
        .unwrap()
    }
}
