//! Explicitly isolated execution-test contracts. These are not production
//! approval, bootstrap, capability, management probe or deployment contracts.
use fw_authority::{DsseEnvelope, SignedGrant};
use fw_backend_linux::{Installation, PortableArtifact};
use serde::{Deserialize, Serialize};

pub const CONFIRM_TYPE: &str = "application/vnd.fw.experimental-confirm.v1+json";
pub const PROBE_TYPE: &str = "application/vnd.fw.isolated-probes.v1+json";

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LabKey {
    pub key_id: String,
    pub payload_type: String,
    /// Base64-encoded Ed25519 public key; private keys never enter the driver.
    pub public_key: String,
    pub not_before_unix: i64,
    pub not_after_unix: i64,
    pub revoked: bool,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LabTrust {
    pub schema_version: String,
    pub org_id: String,
    pub project_id: String,
    pub target_id: String,
    pub authority_epoch: String,
    pub network_namespace: String,
    pub boot_id: String,
    pub production_authorized: bool,
    pub grant_key: LabKey,
    pub confirm_key: LabKey,
}
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ProbeSpec {
    pub name: String,
    pub family: String,
    pub protocol: String,
    pub port: u16,
    pub expect_reply: bool,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LabPlan {
    pub schema_version: String,
    pub plan_id: String,
    pub org_id: String,
    pub project_id: String,
    pub target_id: String,
    pub authority_epoch: String,
    pub target_generation: String,
    pub baseline_hash: String,
    pub desired_state_hash: String,
    pub artifact_hash: String,
    pub recovery_artifact_hash: String,
    pub recovery_scope_hash: String,
    pub valid_until_unix: i64,
    pub probes: Vec<ProbeSpec>,
}
/// Unmistakable fixture provenance; not an F HumanApproval or WebAuthn proof.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LabApproval {
    pub schema_version: String,
    pub kind: String,
    pub plan_hash: String,
    pub principal_id: String,
    pub valid_until_unix: i64,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExecutionBundle {
    pub schema_version: String,
    pub operation_id: String,
    pub plan: LabPlan,
    pub approval: LabApproval,
    pub grant: SignedGrant,
    pub previous: PortableArtifact,
    pub candidate: PortableArtifact,
    pub recovery: PortableArtifact,
    /// The preinstalled initial fixture is independently read from the kernel.
    pub previous_installation: Installation,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProbeObservation {
    pub specification: ProbeSpec,
    pub nonce: String,
    pub bytes_sent: usize,
    pub bytes_received: usize,
    pub outcome: String,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProbeReport {
    pub schema_version: String,
    pub operation_id: String,
    pub grant_hash: String,
    pub state_hash: String,
    pub target_generation: String,
    pub boot_id: String,
    pub network_namespace: String,
    pub started_at_unix: i64,
    pub finished_at_unix: i64,
    pub readback_hash: String,
    pub observations: Vec<ProbeObservation>,
    pub production_management_probe: bool,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ConfirmationEvidence {
    pub schema_version: String,
    pub confirmation: DsseEnvelope,
    pub probes: ProbeReport,
}
