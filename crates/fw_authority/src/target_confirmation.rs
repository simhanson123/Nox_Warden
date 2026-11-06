//! Authenticated, bounded isolated-target bootstrap observations. Successful
//! cryptography is not production build/native qualification or dispatch authority.
use crate::{
    AuthorityBootstrapManifest, AuthorityError, BootstrapApprovalProof, BootstrapAuthorization,
    DsseEnvelope, DsseSignature, RegistryTrustKey, Result,
};
use base64::{Engine, engine::general_purpose::STANDARD};
use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use fw_backend_linux::{
    BOOTSTRAP_PROFILE, BootstrapCapabilitySnapshot, BootstrapManagementBaseline,
    compile_bootstrap_baseline, verify_bootstrap_baseline_readback,
};
use fw_contracts::{canonical_bytes_with_limit, hash_bytes, parse_strict_with_limit};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::BTreeSet;

pub const TARGET_BOOTSTRAP_KEY_SCHEMA: &str = "fw.target-bootstrap-key-pin/v1";
pub const TARGET_BOOTSTRAP_CHALLENGE_SCHEMA: &str = "fw.target-bootstrap-challenge/v1";
pub const TARGET_BOOTSTRAP_PAYLOAD_SCHEMA: &str = "fw.target-bootstrap-confirmation/v1";
pub const TARGET_BOOTSTRAP_CONFIRMATION_SCHEMA: &str =
    "fw.target-bootstrap-confirmation-envelope/v1";
pub const TARGET_BOOTSTRAP_CONFIRMATION_TYPE: &str =
    "application/vnd.fw.target-bootstrap-confirmation.v1+json";
pub const MAX_TARGET_BOOTSTRAP_BYTES: usize = 262144;
pub const BOOTSTRAP_PROBE_REQUEST_SCHEMA: &str = "fw.bootstrap-probe-request/v1";
pub const BOOTSTRAP_PROBE_RESPONSE_SCHEMA: &str = "fw.bootstrap-probe-response/v1";
const PEER_DOMAIN: &[u8] = b"fw.bootstrap-probe-peer/ed25519/v1\0";

fn invalid() -> AuthorityError {
    AuthorityError::Invalid("isolated target bootstrap contract")
}
fn canonical<T: Serialize>(value: &T) -> Result<Vec<u8>> {
    canonical_bytes_with_limit(value, MAX_TARGET_BOOTSTRAP_BYTES).map_err(|_| invalid())
}
fn digest<T: Serialize>(value: &T) -> Result<String> {
    Ok(hash_bytes(&canonical(value)?))
}
fn fixed<const N: usize>(value: &str) -> Result<[u8; N]> {
    if value.len() != N.div_ceil(3) * 4 {
        return Err(invalid());
    }
    let decoded = STANDARD.decode(value).map_err(|_| invalid())?;
    if STANDARD.encode(&decoded) != value {
        return Err(invalid());
    }
    decoded.try_into().map_err(|_| invalid())
}
fn nullable<'de, D: serde::Deserializer<'de>>(
    deserializer: D,
) -> std::result::Result<Option<String>, D::Error> {
    Option::<String>::deserialize(deserializer)
}
fn utc(value: &str) -> Result<i64> {
    let value = crate::timestamp(value)?;
    if !(0..=253402300799).contains(&value) {
        return Err(invalid());
    }
    Ok(value)
}
fn current(start: i64, end: i64, now: i64) -> Result<()> {
    if start >= end || now < start || now >= end {
        return Err(AuthorityError::Time);
    }
    Ok(())
}
fn key_id(value: &str) -> bool {
    !value.is_empty() && value.len() <= 256 && !value.chars().any(char::is_control)
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct TargetBootstrapKeyPin {
    pub schema_version: String,
    pub org_id: String,
    pub project_id: String,
    pub target_id: String,
    pub key_id: String,
    pub revision: String,
    pub public_key: [u8; 32],
    pub not_before: String,
    pub not_after: String,
    pub profile: String,
}
impl TargetBootstrapKeyPin {
    pub fn validate_shape(&self) -> Result<()> {
        if self.schema_version != TARGET_BOOTSTRAP_KEY_SCHEMA
            || self.profile != BOOTSTRAP_PROFILE
            || [&self.org_id, &self.project_id, &self.target_id]
                .iter()
                .any(|id| !crate::uuid_ok(id))
            || !key_id(&self.key_id)
            || crate::counter(&self.revision)? == 0
            || utc(&self.not_before)? >= utc(&self.not_after)?
        {
            return Err(invalid());
        }
        let key =
            VerifyingKey::from_bytes(&self.public_key).map_err(|_| AuthorityError::Signature)?;
        if key.is_weak() {
            return Err(AuthorityError::Signature);
        }
        Ok(())
    }
    pub fn validate(&self, now: i64) -> Result<()> {
        self.validate_shape()?;
        current(utc(&self.not_before)?, utc(&self.not_after)?, now)
    }
    pub fn fingerprint(&self) -> String {
        hash_bytes(&self.public_key)
    }
    pub fn hash(&self) -> Result<String> {
        self.validate_shape()?;
        digest(self)
    }
    pub fn canonical_bytes(&self) -> Result<Vec<u8>> {
        self.validate_shape()?;
        canonical(self)
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct TargetBootstrapChallenge {
    pub schema_version: String,
    pub challenge_id: String,
    pub org_id: String,
    pub project_id: String,
    pub target_id: String,
    pub manifest_id: String,
    pub manifest_hash: String,
    pub authorization_hash: String,
    pub management_baseline_hash: String,
    pub capability_hash: String,
    pub baseline_program_hash: String,
    #[serde(deserialize_with = "nullable")]
    pub old_epoch: Option<String>,
    pub new_epoch: String,
    pub highest_generation: String,
    #[serde(deserialize_with = "nullable")]
    pub previous_confirmation_hash: Option<String>,
    pub key_id: String,
    pub key_revision: String,
    pub key_fingerprint: String,
    pub nonce: String,
    pub issued_at: String,
    pub expires_at: String,
}
impl TargetBootstrapChallenge {
    pub fn validate_shape(&self) -> Result<()> {
        if self.schema_version != TARGET_BOOTSTRAP_CHALLENGE_SCHEMA
            || [
                &self.challenge_id,
                &self.org_id,
                &self.project_id,
                &self.target_id,
                &self.manifest_id,
            ]
            .iter()
            .any(|id| !crate::uuid_ok(id))
            || [
                &self.manifest_hash,
                &self.authorization_hash,
                &self.management_baseline_hash,
                &self.capability_hash,
                &self.baseline_program_hash,
                &self.key_fingerprint,
            ]
            .iter()
            .any(|hash| !crate::hash_ok(hash))
            || !key_id(&self.key_id)
            || crate::counter(&self.key_revision)? == 0
            || self.highest_generation != "0"
        {
            return Err(invalid());
        }
        let next = crate::counter(&self.new_epoch)?;
        let old = self.old_epoch.as_deref().map(crate::counter).transpose()?;
        if next == 0
            || old.is_some_and(|old| old == 0 || old >= next)
            || old.is_some() != self.previous_confirmation_hash.is_some()
            || self
                .previous_confirmation_hash
                .as_ref()
                .is_some_and(|h| !crate::hash_ok(h))
        {
            return Err(AuthorityError::Binding);
        }
        fixed::<32>(&self.nonce)?;
        let start = utc(&self.issued_at)?;
        let end = utc(&self.expires_at)?;
        if end <= start || end - start > 300 {
            return Err(AuthorityError::Time);
        }
        if canonical(self)?.len() > 8192 {
            return Err(invalid());
        }
        Ok(())
    }
    pub fn validate(&self, now: i64) -> Result<()> {
        self.validate_shape()?;
        current(utc(&self.issued_at)?, utc(&self.expires_at)?, now)
    }
    pub fn canonical_bytes(&self) -> Result<Vec<u8>> {
        self.validate_shape()?;
        canonical(self)
    }
    pub fn hash(&self) -> Result<String> {
        self.validate_shape()?;
        digest(self)
    }
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        let value: Self = parse_strict_with_limit(bytes, 8192).map_err(|_| invalid())?;
        value.validate_shape()?;
        Ok(value)
    }
}

#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "snake_case")]
pub enum BootstrapProbeKind {
    ManagementTcp,
    PositiveUdp,
    NegativeUdp,
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct BootstrapProbeRequest {
    pub schema_version: String,
    pub challenge_hash: String,
    pub kind: BootstrapProbeKind,
    pub nonce: String,
}
impl BootstrapProbeRequest {
    pub fn canonical_bytes(&self) -> Result<Vec<u8>> {
        if self.schema_version != BOOTSTRAP_PROBE_REQUEST_SCHEMA
            || !crate::hash_ok(&self.challenge_hash)
        {
            return Err(invalid());
        }
        fixed::<32>(&self.nonce)?;
        canonical(self)
    }
    pub fn wire_bytes(&self) -> Result<Vec<u8>> {
        let mut bytes = self.canonical_bytes()?;
        bytes.push(b'\n');
        Ok(bytes)
    }
    pub fn hash(&self) -> Result<String> {
        Ok(hash_bytes(&self.canonical_bytes()?))
    }
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct BootstrapPeerResponse {
    pub schema_version: String,
    pub request_hash: String,
    pub signature: String,
}
impl BootstrapPeerResponse {
    pub fn wire_bytes(&self) -> Result<Vec<u8>> {
        if self.schema_version != BOOTSTRAP_PROBE_RESPONSE_SCHEMA
            || !crate::hash_ok(&self.request_hash)
        {
            return Err(invalid());
        }
        fixed::<64>(&self.signature)?;
        let mut bytes = canonical(self)?;
        bytes.push(b'\n');
        Ok(bytes)
    }
}
pub fn sign_bootstrap_probe_response(
    request: &BootstrapProbeRequest,
    key: &SigningKey,
) -> Result<BootstrapPeerResponse> {
    let bytes = request.canonical_bytes()?;
    let mut message = PEER_DOMAIN.to_vec();
    message.extend_from_slice(&bytes);
    Ok(BootstrapPeerResponse {
        schema_version: BOOTSTRAP_PROBE_RESPONSE_SCHEMA.into(),
        request_hash: hash_bytes(&bytes),
        signature: STANDARD.encode(key.sign(&message).to_bytes()),
    })
}
pub fn verify_bootstrap_probe_response(
    request: &BootstrapProbeRequest,
    response: &BootstrapPeerResponse,
    baseline: &BootstrapManagementBaseline,
) -> Result<()> {
    baseline.validate().map_err(|_| invalid())?;
    response.wire_bytes()?;
    if response.request_hash != request.hash()? {
        return Err(AuthorityError::Binding);
    }
    let mut message = PEER_DOMAIN.to_vec();
    message.extend(request.canonical_bytes()?);
    let signature = Signature::from_bytes(&fixed::<64>(&response.signature)?);
    VerifyingKey::from_bytes(&baseline.peer_probe_public_key)
        .map_err(|_| AuthorityError::Signature)?
        .verify_strict(&message, &signature)
        .map_err(|_| AuthorityError::Signature)
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct BootstrapProbeObservation {
    pub request: BootstrapProbeRequest,
    #[serde(deserialize_with = "required_response")]
    pub response: Option<BootstrapPeerResponse>,
    pub bytes_sent: u64,
    pub bytes_received: u64,
    pub outcome: String,
    #[serde(deserialize_with = "required_os_error")]
    pub os_error: Option<i32>,
}
fn required_response<'de, D: serde::Deserializer<'de>>(
    deserializer: D,
) -> std::result::Result<Option<BootstrapPeerResponse>, D::Error> {
    Option::<BootstrapPeerResponse>::deserialize(deserializer)
}
fn required_os_error<'de, D: serde::Deserializer<'de>>(
    deserializer: D,
) -> std::result::Result<Option<i32>, D::Error> {
    Option::<i32>::deserialize(deserializer)
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TargetBootstrapConfirmationPayload {
    pub schema_version: String,
    pub challenge: TargetBootstrapChallenge,
    pub journal_id: String,
    pub boot_id: String,
    pub network_namespace: String,
    pub accepted_epoch: String,
    pub highest_generation: String,
    pub accepted_at: String,
    pub observation_started_at: String,
    pub observation_finished_at: String,
    pub observation_started_millis: String,
    pub observation_finished_millis: String,
    pub readback: Value,
    pub probes: Vec<BootstrapProbeObservation>,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SignedTargetBootstrapConfirmation {
    pub schema_version: String,
    pub payload: TargetBootstrapConfirmationPayload,
    pub dsse: DsseEnvelope,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TargetBootstrapBundle {
    pub schema_version: String,
    pub manifest: AuthorityBootstrapManifest,
    pub authorization: BootstrapAuthorization,
    pub proofs: Vec<BootstrapApprovalProof>,
    pub challenge: TargetBootstrapChallenge,
    pub baseline: BootstrapManagementBaseline,
    pub capability: BootstrapCapabilitySnapshot,
}
impl TargetBootstrapBundle {
    pub fn validate(&self, root: &RegistryTrustKey, now: i64) -> Result<()> {
        if self.schema_version != "fw.target-bootstrap-bundle/v1" {
            return Err(invalid());
        }
        canonical(self)?;
        validate_target_bootstrap_material(
            &self.challenge,
            &self.manifest,
            &self.authorization,
            &self.proofs,
            root,
            &self.baseline,
            &self.capability,
            now,
        )
    }
    pub fn canonical_bytes(&self) -> Result<Vec<u8>> {
        canonical(self)
    }
    pub fn hash(&self) -> Result<String> {
        self.canonical_bytes()?;
        digest(self)
    }
}

pub fn validate_target_bootstrap_key(
    challenge: &TargetBootstrapChallenge,
    pin: &TargetBootstrapKeyPin,
    now: i64,
) -> Result<()> {
    challenge.validate(now)?;
    pin.validate(now)?;
    if challenge.org_id != pin.org_id
        || challenge.project_id != pin.project_id
        || challenge.target_id != pin.target_id
        || challenge.key_id != pin.key_id
        || challenge.key_revision != pin.revision
        || challenge.key_fingerprint != pin.fingerprint()
        || utc(&challenge.issued_at)? < utc(&pin.not_before)?
        || utc(&challenge.expires_at)? > utc(&pin.not_after)?
    {
        return Err(AuthorityError::Binding);
    }
    Ok(())
}
impl SignedTargetBootstrapConfirmation {
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        let value: Self =
            parse_strict_with_limit(bytes, MAX_TARGET_BOOTSTRAP_BYTES).map_err(|_| invalid())?;
        value.canonical_bytes()?;
        Ok(value)
    }
    pub fn canonical_bytes(&self) -> Result<Vec<u8>> {
        canonical(self)
    }
    pub fn hash(&self) -> Result<String> {
        self.canonical_bytes()?;
        digest(self)
    }
}

pub struct VerifiedTargetBootstrapConfirmation {
    canonical: Vec<u8>,
    hash: String,
    challenge_hash: String,
    journal_id: String,
    accepted_epoch: u64,
    highest_generation: u64,
    observed_at: i64,
    valid_until: i64,
    readback_hash: String,
    program_hash: String,
}
impl VerifiedTargetBootstrapConfirmation {
    pub fn canonical_bytes(&self) -> &[u8] {
        &self.canonical
    }
    pub fn hash(&self) -> &str {
        &self.hash
    }
    pub fn challenge_hash(&self) -> &str {
        &self.challenge_hash
    }
    pub fn journal_id(&self) -> &str {
        &self.journal_id
    }
    pub fn accepted_epoch(&self) -> u64 {
        self.accepted_epoch
    }
    pub fn highest_generation(&self) -> u64 {
        self.highest_generation
    }
    pub fn observed_at(&self) -> i64 {
        self.observed_at
    }
    pub fn valid_until(&self) -> i64 {
        self.valid_until
    }
    pub fn readback_hash(&self) -> &str {
        &self.readback_hash
    }
    pub fn program_hash(&self) -> &str {
        &self.program_hash
    }
}

/// Verifies the immutable authorization supplied to the target against its
/// independently configured bootstrap root. Actual WebAuthn assertion checking
/// belongs to the authority signer; a supplied proof object is not owner consent.
#[allow(clippy::too_many_arguments)]
pub fn validate_target_bootstrap_material(
    challenge: &TargetBootstrapChallenge,
    manifest: &AuthorityBootstrapManifest,
    authorization: &BootstrapAuthorization,
    proofs: &[BootstrapApprovalProof],
    root: &RegistryTrustKey,
    baseline: &BootstrapManagementBaseline,
    capability: &BootstrapCapabilitySnapshot,
    now: i64,
) -> Result<()> {
    challenge.validate(now)?;
    authorization.validate_current_admission_profile()?;
    let verified =
        crate::verify_bootstrap_authorization(authorization, manifest, proofs, root, now)?;
    let program = compile_bootstrap_baseline(baseline, capability).map_err(|_| invalid())?;
    let peer = VerifyingKey::from_bytes(&baseline.peer_probe_public_key)
        .map_err(|_| AuthorityError::Signature)?;
    if peer.is_weak() || baseline.peer_probe_public_key == root.public_key {
        return Err(AuthorityError::Signature);
    }
    if challenge.org_id != manifest.org_id
        || challenge.project_id != manifest.project_id
        || challenge.target_id != manifest.target_id
        || challenge.manifest_id != manifest.manifest_id
        || challenge.manifest_hash != manifest.hash()?
        || challenge.authorization_hash != verified.hash()
        || challenge.old_epoch != manifest.old_epoch
        || challenge.new_epoch != manifest.new_epoch
        || challenge.management_baseline_hash != manifest.management_baseline_hash
        || challenge.capability_hash != manifest.capability_hash
        || challenge.org_id != baseline.org_id
        || challenge.project_id != baseline.project_id
        || challenge.target_id != baseline.target_id
        || challenge.management_baseline_hash != baseline.hash().map_err(|_| invalid())?
        || challenge.capability_hash != capability.hash().map_err(|_| invalid())?
        || challenge.baseline_program_hash != program.hash().map_err(|_| invalid())?
        || utc(&challenge.issued_at)? < utc(&authorization.payload.issued_at)?
        || utc(&challenge.expires_at)? > utc(&authorization.payload.not_after)?
    {
        return Err(AuthorityError::Binding);
    }
    Ok(())
}

pub fn verify_target_bootstrap_confirmation(
    receipt: &SignedTargetBootstrapConfirmation,
    expected: &TargetBootstrapChallenge,
    pin: &TargetBootstrapKeyPin,
    baseline: &BootstrapManagementBaseline,
    capability: &BootstrapCapabilitySnapshot,
    now: i64,
) -> Result<VerifiedTargetBootstrapConfirmation> {
    expected.validate(now)?;
    pin.validate(now)?;
    let payload = &receipt.payload;
    let program = compile_bootstrap_baseline(baseline, capability).map_err(|_| invalid())?;
    if baseline.peer_probe_public_key == pin.public_key {
        return Err(AuthorityError::Signature);
    }
    if receipt.schema_version != TARGET_BOOTSTRAP_CONFIRMATION_SCHEMA
        || payload.schema_version != TARGET_BOOTSTRAP_PAYLOAD_SCHEMA
        || &payload.challenge != expected
        || expected.org_id != pin.org_id
        || expected.project_id != pin.project_id
        || expected.target_id != pin.target_id
        || expected.key_id != pin.key_id
        || expected.key_revision != pin.revision
        || expected.key_fingerprint != pin.fingerprint()
        || expected.org_id != baseline.org_id
        || expected.project_id != baseline.project_id
        || expected.target_id != baseline.target_id
        || expected.management_baseline_hash != baseline.hash().map_err(|_| invalid())?
        || expected.capability_hash != capability.hash().map_err(|_| invalid())?
        || expected.baseline_program_hash != program.hash().map_err(|_| invalid())?
        || !crate::uuid_ok(&payload.journal_id)
        || !crate::uuid_ok(&payload.boot_id)
        || payload.network_namespace != baseline.network_namespace
        || payload.accepted_epoch != expected.new_epoch
        || payload.highest_generation != expected.highest_generation
        || utc(&expected.issued_at)? < utc(&pin.not_before)?
        || utc(&expected.expires_at)? > utc(&pin.not_after)?
    {
        return Err(AuthorityError::Binding);
    }
    let accepted = utc(&payload.accepted_at)?;
    let start = utc(&payload.observation_started_at)?;
    let end = utc(&payload.observation_finished_at)?;
    let start_millis = crate::counter(&payload.observation_started_millis)?;
    let end_millis = crate::counter(&payload.observation_finished_millis)?;
    let elapsed = end_millis
        .checked_sub(start_millis)
        .ok_or(AuthorityError::Time)?;
    if accepted < utc(&expected.issued_at)?
        || start < accepted
        || end < start
        || end > now
        || end >= utc(&expected.expires_at)?
        || elapsed > 300000
        || elapsed.abs_diff((end - start) as u64 * 1000) > 1000
    {
        return Err(AuthorityError::Time);
    }
    let bytes = canonical(payload)?;
    if receipt.dsse.payload_type != TARGET_BOOTSTRAP_CONFIRMATION_TYPE
        || receipt.dsse.signatures.len() != 1
        || receipt.dsse.signatures[0].keyid != pin.key_id
        || STANDARD.encode(&bytes) != receipt.dsse.payload
    {
        return Err(AuthorityError::Signature);
    }
    let signature = Signature::from_bytes(&fixed::<64>(&receipt.dsse.signatures[0].sig)?);
    VerifyingKey::from_bytes(&pin.public_key)
        .map_err(|_| AuthorityError::Signature)?
        .verify_strict(
            &crate::pae(TARGET_BOOTSTRAP_CONFIRMATION_TYPE, &bytes),
            &signature,
        )
        .map_err(|_| AuthorityError::Signature)?;
    let readback = verify_bootstrap_baseline_readback(baseline, capability, &payload.readback)
        .map_err(|_| AuthorityError::Binding)?;
    let expected_hash = expected.hash()?;
    let mut kinds = BTreeSet::new();
    let mut nonces = BTreeSet::new();
    if payload.probes.len() != 3 {
        return Err(AuthorityError::Binding);
    }
    for probe in &payload.probes {
        if probe.request.challenge_hash != expected_hash
            || !kinds.insert(probe.request.kind)
            || !nonces.insert(&probe.request.nonce)
        {
            return Err(AuthorityError::Binding);
        }
        let request_bytes = probe.request.wire_bytes()?.len() as u64;
        if probe.request.kind == BootstrapProbeKind::NegativeUdp {
            // A local Linux EPERM is an observed failed send, not a packet
            // transmission, timeout or cryptographic proof of remote denial.
            let outcome = match probe.outcome.as_str() {
                "timeout" => probe.os_error.is_none() && probe.bytes_sent == request_bytes,
                "local_send_denied" => probe.os_error == Some(1) && probe.bytes_sent == 0,
                _ => false,
            };
            if probe.response.is_some() || !outcome || probe.bytes_received != 0 {
                return Err(AuthorityError::Binding);
            }
        } else {
            let response = probe.response.as_ref().ok_or(AuthorityError::Binding)?;
            verify_bootstrap_probe_response(&probe.request, response, baseline)?;
            if probe.outcome != "reply"
                || probe.os_error.is_some()
                || probe.bytes_sent != request_bytes
                || probe.bytes_received != response.wire_bytes()?.len() as u64
            {
                return Err(AuthorityError::Binding);
            }
        }
    }
    let canonical = receipt.canonical_bytes()?;
    Ok(VerifiedTargetBootstrapConfirmation {
        hash: hash_bytes(&canonical),
        canonical,
        challenge_hash: expected_hash,
        journal_id: payload.journal_id.clone(),
        accepted_epoch: crate::counter(&payload.accepted_epoch)?,
        highest_generation: crate::counter(&payload.highest_generation)?,
        observed_at: end,
        valid_until: utc(&expected.expires_at)?,
        readback_hash: readback.readback_hash().into(),
        program_hash: readback.program_hash().into(),
    })
}

pub fn sign_target_bootstrap_confirmation(
    payload: TargetBootstrapConfirmationPayload,
    pin: &TargetBootstrapKeyPin,
    key: &SigningKey,
    baseline: &BootstrapManagementBaseline,
    capability: &BootstrapCapabilitySnapshot,
    now: i64,
) -> Result<SignedTargetBootstrapConfirmation> {
    if pin.public_key != key.verifying_key().to_bytes() {
        return Err(AuthorityError::Signature);
    }
    let bytes = canonical(&payload)?;
    let dsse = DsseEnvelope {
        payload_type: TARGET_BOOTSTRAP_CONFIRMATION_TYPE.into(),
        payload: STANDARD.encode(&bytes),
        signatures: vec![DsseSignature {
            keyid: pin.key_id.clone(),
            sig: STANDARD.encode(
                key.sign(&crate::pae(TARGET_BOOTSTRAP_CONFIRMATION_TYPE, &bytes))
                    .to_bytes(),
            ),
        }],
    };
    let receipt = SignedTargetBootstrapConfirmation {
        schema_version: TARGET_BOOTSTRAP_CONFIRMATION_SCHEMA.into(),
        payload,
        dsse,
    };
    verify_target_bootstrap_confirmation(
        &receipt,
        &receipt.payload.challenge,
        pin,
        baseline,
        capability,
        now,
    )?;
    Ok(receipt)
}
