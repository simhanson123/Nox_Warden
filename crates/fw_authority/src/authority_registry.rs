//! Exact F authority objects and cryptographic verification for an independent
//! registry. Verified bytes establish a signature and its binding, not observed
//! workload isolation, human consent, target epoch acceptance or grant eligibility.
use crate::{
    AccessEnvelope, AuthorityError, Delegation, DsseEnvelope, Result, hash_ok, pae, timestamp,
    uuid_ok,
};
use base64::{Engine, engine::general_purpose::STANDARD};
use ed25519_dalek::{Signature, VerifyingKey};
use fw_contracts::{canonical_bytes, canonical_hash, parse_strict_with_limit};
use ipnet::IpNet;
use serde::{Deserialize, Serialize};
use std::{collections::BTreeSet, io::Write};

pub const WORKLOAD_BINDING_TYPE: &str = "application/vnd.f.workload-binding.v1+json";
pub const BOOTSTRAP_AUTHORIZATION_TYPE: &str = "application/vnd.f.authority-bootstrap.v1+json";
pub const MAX_AUTHORITY_REGISTRY_BYTES: usize = 128 * 1024;

/// Provision only through a protected local/OOB authority procedure. A key ID,
/// controller account, self-signature or a caller-provided copy is not a pin.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct RegistryTrustKey {
    pub key_id: String,
    pub org_id: String,
    pub project_id: String,
    pub target_id: String,
    pub payload_type: String,
    pub public_key: [u8; 32],
    pub not_before: i64,
    pub not_after: i64,
    pub revoked: bool,
}
impl RegistryTrustKey {
    pub fn validate(&self, now: i64) -> Result<()> {
        self.validate_shape()?;
        current(self.not_before, self.not_after, now)?;
        if self.revoked {
            return Err(AuthorityError::Signature);
        }
        Ok(())
    }
    pub fn validate_shape(&self) -> Result<()> {
        if !short(&self.key_id, 256)
            || [&self.org_id, &self.project_id, &self.target_id]
                .iter()
                .any(|id| !uuid_ok(id))
            || ![WORKLOAD_BINDING_TYPE, BOOTSTRAP_AUTHORIZATION_TYPE]
                .contains(&self.payload_type.as_str())
        {
            return Err(invalid());
        }
        interval(self.not_before, self.not_after)?;
        let key =
            VerifyingKey::from_bytes(&self.public_key).map_err(|_| AuthorityError::Signature)?;
        if key.is_weak() {
            return Err(AuthorityError::Signature);
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct RegistryAssetAddress {
    pub family: String,
    pub cidr: String,
    #[serde(deserialize_with = "required_nullable")]
    pub interface: Option<String>,
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct RegistryEvidenceRef {
    pub store_id: String,
    pub object_hash: String,
    pub media_type: String,
    pub size_bytes: u64,
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum WorkloadIsolation {
    Host {
        host_asset_id: String,
    },
    Vm {
        vm_asset_id: String,
        hypervisor_id: String,
        instance_identity_hash: String,
    },
    NetworkNamespace {
        host_asset_id: String,
        namespace_inode: String,
        boot_id: String,
        veth_ifindex: u32,
        network_identity_hash: String,
    },
    WindowsAppIdentity {
        host_asset_id: String,
        boot_id: String,
        app_id_hash: String,
        service_sid: String,
        token_binding_hash: String,
    },
    MacosHost {
        host_asset_id: String,
        boot_id: String,
    },
}
impl WorkloadIsolation {
    pub fn kind(&self) -> &'static str {
        match self {
            Self::Host { .. } => "host",
            Self::Vm { .. } => "vm",
            Self::NetworkNamespace { .. } => "network_namespace",
            Self::WindowsAppIdentity { .. } => "windows_app_identity",
            Self::MacosHost { .. } => "macos_host",
        }
    }
    fn validate(&self, platform: &str, assets: &[String]) -> Result<()> {
        let (asset, ids, hashes): (&String, Vec<&String>, Vec<&String>) = match self {
            Self::Host { host_asset_id } => (host_asset_id, vec![], vec![]),
            Self::Vm {
                vm_asset_id,
                hypervisor_id,
                instance_identity_hash,
            } => (
                vm_asset_id,
                vec![hypervisor_id],
                vec![instance_identity_hash],
            ),
            Self::NetworkNamespace {
                host_asset_id,
                namespace_inode,
                boot_id,
                veth_ifindex,
                network_identity_hash,
            } => {
                if platform != "linux" || !(1..=i32::MAX as u32).contains(veth_ifindex) {
                    return Err(invalid());
                }
                crate::counter(namespace_inode)?;
                (host_asset_id, vec![boot_id], vec![network_identity_hash])
            }
            Self::WindowsAppIdentity {
                host_asset_id,
                boot_id,
                app_id_hash,
                service_sid,
                token_binding_hash,
            } => {
                if platform != "windows" || !short(service_sid, 184) {
                    return Err(invalid());
                }
                (
                    host_asset_id,
                    vec![boot_id],
                    vec![app_id_hash, token_binding_hash],
                )
            }
            Self::MacosHost {
                host_asset_id,
                boot_id,
            } => {
                if platform != "macos" {
                    return Err(invalid());
                }
                (host_asset_id, vec![boot_id], vec![])
            }
        };
        if !uuid_ok(asset)
            || !assets.contains(asset)
            || ids.iter().any(|id| !uuid_ok(id))
            || hashes.iter().any(|h| !hash_ok(h))
        {
            return Err(invalid());
        }
        Ok(())
    }
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct WorkloadBindingPayload {
    pub schema_version: String,
    pub binding_id: String,
    pub org_id: String,
    pub project_id: String,
    pub principal_id: String,
    pub issuer_key_id: String,
    pub workload_id: String,
    pub target_id: String,
    pub platform: String,
    pub asset_ids: Vec<String>,
    pub asset_revision_hashes: Vec<String>,
    pub addresses: Vec<RegistryAssetAddress>,
    pub isolation: WorkloadIsolation,
    pub issued_at: String,
    pub not_before: String,
    pub expires_at: String,
    pub binding_epoch: String,
    pub attestation_evidence: RegistryEvidenceRef,
    pub audience: String,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WorkloadBinding {
    pub payload: WorkloadBindingPayload,
    pub dsse: DsseEnvelope,
}

/// Cryptographic issuer attestation only. Registry snapshots must separately
/// match ID→revision relationships, scope, current epoch and retained revocation.
#[derive(Clone, Debug)]
pub struct VerifiedWorkloadBinding {
    binding: WorkloadBinding,
    canonical: Vec<u8>,
    hash: String,
    payload_hash: String,
    epoch: u64,
    not_before: i64,
    not_after: i64,
}
impl VerifiedWorkloadBinding {
    pub fn payload(&self) -> &WorkloadBindingPayload {
        &self.binding.payload
    }
    pub fn binding(&self) -> &WorkloadBinding {
        &self.binding
    }
    pub fn hash(&self) -> &str {
        &self.hash
    }
    pub fn payload_hash(&self) -> &str {
        &self.payload_hash
    }
    pub fn canonical_bytes(&self) -> &[u8] {
        &self.canonical
    }
    pub fn binding_id(&self) -> &str {
        &self.payload().binding_id
    }
    pub fn principal_id(&self) -> &str {
        &self.payload().principal_id
    }
    pub fn target_id(&self) -> &str {
        &self.payload().target_id
    }
    pub fn binding_epoch(&self) -> u64 {
        self.epoch
    }
    pub fn not_before(&self) -> i64 {
        self.not_before
    }
    pub fn not_after(&self) -> i64 {
        self.not_after
    }
}
impl WorkloadBinding {
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        let binding: Self =
            parse_strict_with_limit(bytes, MAX_AUTHORITY_REGISTRY_BYTES).map_err(|_| invalid())?;
        binding.validate_shape()?;
        Ok(binding)
    }
    /// Closed contract and exact DSSE bytes only; this does not verify the
    /// cryptographic signature, current trust, revocation or current time.
    pub fn validate_shape(&self) -> Result<()> {
        bounded(self)?;
        self.payload.validate()?;
        dsse_shape(&self.dsse, &self.payload, WORKLOAD_BINDING_TYPE, 8)?;
        Ok(())
    }
}
impl WorkloadBindingPayload {
    pub fn validate(&self) -> Result<()> {
        bounded(self)?;
        if self.schema_version != "f.workload-binding/v1"
            || self.audience != "fw_controller"
            || [
                &self.binding_id,
                &self.org_id,
                &self.project_id,
                &self.principal_id,
                &self.target_id,
            ]
            .iter()
            .any(|id| !uuid_ok(id))
            || !short(&self.issuer_key_id, 256)
            || !short(&self.workload_id, 256)
            || !["linux", "windows", "macos"].contains(&self.platform.as_str())
        {
            return Err(invalid());
        }
        ordered(&self.asset_ids, 1, 16, uuid_ok)?;
        ordered(&self.asset_revision_hashes, 1, 16, hash_ok)?;
        // The sets are independent: never zip their sorted arrays to infer an ID→hash mapping.
        if self.asset_ids.len() != self.asset_revision_hashes.len()
            || !(1..=16).contains(&self.addresses.len())
        {
            return Err(invalid());
        }
        let mut addresses = BTreeSet::new();
        for address in &self.addresses {
            let network: IpNet = address.cidr.parse().map_err(|_| invalid())?;
            if network.trunc() != network
                || network.to_string() != address.cidr
                || address.family
                    != if matches!(network, IpNet::V4(_)) {
                        "ipv4"
                    } else {
                        "ipv6"
                    }
                || address.interface.as_ref().is_some_and(|s| !short(s, 128))
                || !addresses.insert((&address.family, &address.cidr, &address.interface))
            {
                return Err(invalid());
            }
        }
        self.isolation.validate(&self.platform, &self.asset_ids)?;
        let evidence = &self.attestation_evidence;
        if evidence.store_id.is_empty()
            || evidence.store_id.len() > 64
            || !evidence.store_id.as_bytes()[0].is_ascii_lowercase()
            || !evidence
                .store_id
                .bytes()
                .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == b'_' || c == b'-')
            || !hash_ok(&evidence.object_hash)
            || !["application/json", "application/octet-stream", "text/plain"]
                .contains(&evidence.media_type.as_str())
            || evidence.size_bytes > 16 * 1024 * 1024
        {
            return Err(invalid());
        }
        let issued = timestamp(&self.issued_at)?;
        let start = timestamp(&self.not_before)?;
        let end = timestamp(&self.expires_at)?;
        interval(start, end)?;
        if issued < 0 || issued > start {
            return Err(AuthorityError::Time);
        }
        crate::counter(&self.binding_epoch)?;
        Ok(())
    }
}
pub fn verify_workload_binding(
    binding: &WorkloadBinding,
    trust: &RegistryTrustKey,
    now: i64,
) -> Result<VerifiedWorkloadBinding> {
    bounded(binding)?;
    binding.payload.validate()?;
    let p = &binding.payload;
    let start = timestamp(&p.not_before)?;
    let end = timestamp(&p.expires_at)?;
    current(start, end, now)?;
    identity(
        trust,
        &p.org_id,
        &p.project_id,
        &p.target_id,
        WORKLOAD_BINDING_TYPE,
        now,
    )?;
    if p.issuer_key_id != trust.key_id {
        return Err(AuthorityError::Signature);
    }
    if timestamp(&p.issued_at)? < trust.not_before || end > trust.not_after {
        return Err(AuthorityError::Time);
    }
    verify_dsse(&binding.dsse, p, trust, 8)?;
    Ok(VerifiedWorkloadBinding {
        binding: binding.clone(),
        canonical: canonical(binding)?,
        hash: digest(binding)?,
        payload_hash: digest(p)?,
        epoch: crate::counter(&p.binding_epoch)?,
        not_before: start,
        not_after: end,
    })
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct AuthorityBootstrapManifest {
    pub schema_version: String,
    pub manifest_id: String,
    pub org_id: String,
    pub project_id: String,
    pub target_id: String,
    #[serde(deserialize_with = "required_nullable")]
    pub old_epoch: Option<String>,
    pub new_epoch: String,
    pub created_at: String,
    pub expires_at: String,
    pub trust_root_hash: String,
    pub management_baseline_hash: String,
    pub envelope_hashes: Vec<String>,
    pub delegation_hashes: Vec<String>,
    pub capability_hash: String,
    pub reason: String,
}
impl AuthorityBootstrapManifest {
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        let result: Self =
            parse_strict_with_limit(bytes, MAX_AUTHORITY_REGISTRY_BYTES).map_err(|_| invalid())?;
        result.validate()?;
        Ok(result)
    }
    pub fn validate(&self) -> Result<()> {
        bounded(self)?;
        if self.schema_version != "f.authority-bootstrap-manifest/v1"
            || [
                &self.manifest_id,
                &self.org_id,
                &self.project_id,
                &self.target_id,
            ]
            .iter()
            .any(|id| !uuid_ok(id))
            || [
                &self.trust_root_hash,
                &self.management_baseline_hash,
                &self.capability_hash,
            ]
            .iter()
            .any(|h| !hash_ok(h))
            || !short(&self.reason, 2048)
        {
            return Err(invalid());
        }
        let next = crate::counter(&self.new_epoch)?;
        if next == 0
            || self
                .old_epoch
                .as_ref()
                .map(|v| crate::counter(v))
                .transpose()?
                .is_some_and(|old| next <= old)
        {
            return Err(AuthorityError::Binding);
        }
        ordered(&self.envelope_hashes, 1, 256, hash_ok)?;
        ordered(&self.delegation_hashes, 1, 256, hash_ok)?;
        interval(timestamp(&self.created_at)?, timestamp(&self.expires_at)?)?;
        Ok(())
    }
    pub fn canonical_bytes(&self) -> Result<Vec<u8>> {
        self.validate()?;
        canonical(self)
    }
    pub fn hash(&self) -> Result<String> {
        self.validate()?;
        digest(self)
    }
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct BootstrapApprovalProof {
    pub schema_version: String,
    pub proof_id: String,
    pub subject_type: String,
    pub subject_hash: String,
    pub approver_id: String,
    pub webauthn_assertion_hash: String,
    pub role_snapshot_hash: String,
    pub approved_at: String,
    pub valid_until: String,
}
impl BootstrapApprovalProof {
    /// Checks reference shape and lifetime only. Admission must independently
    /// verify retained WebAuthn assertion, credential, owner role and freshness.
    pub fn validate(&self, manifest: &AuthorityBootstrapManifest, now: i64) -> Result<()> {
        bounded(self)?;
        manifest.validate()?;
        if self.schema_version != "f.bootstrap-approval-proof/v1"
            || self.subject_type != "authority_bootstrap"
            || !uuid_ok(&self.proof_id)
            || !uuid_ok(&self.approver_id)
            || !hash_ok(&self.webauthn_assertion_hash)
            || !hash_ok(&self.role_snapshot_hash)
            || self.subject_hash != manifest.hash()?
        {
            return Err(AuthorityError::Binding);
        }
        let start = timestamp(&self.approved_at)?;
        let end = timestamp(&self.valid_until)?;
        current(start, end, now)?;
        if start < timestamp(&manifest.created_at)? || end > timestamp(&manifest.expires_at)? {
            return Err(AuthorityError::Time);
        }
        Ok(())
    }
    pub fn hash(&self) -> Result<String> {
        bounded(self)?;
        digest(self)
    }
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct BootstrapAuthorizationPayload {
    pub schema_version: String,
    pub manifest_hash: String,
    pub approval_proof_hashes: Vec<String>,
    pub signer_key_id: String,
    pub issued_at: String,
    pub not_after: String,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BootstrapAuthorization {
    pub schema_version: String,
    pub payload: BootstrapAuthorizationPayload,
    pub dsse: DsseEnvelope,
}
impl BootstrapAuthorization {
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        let authorization: Self =
            parse_strict_with_limit(bytes, MAX_AUTHORITY_REGISTRY_BYTES).map_err(|_| invalid())?;
        authorization.validate_shape()?;
        Ok(authorization)
    }
    /// Allows malformed input rejection before observing a durable clock.
    /// Current manifest/proof/trust eligibility still requires verification.
    pub fn validate_shape(&self) -> Result<()> {
        bounded(self)?;
        let payload = &self.payload;
        if self.schema_version != "f.bootstrap-authorization-envelope/v1"
            || payload.schema_version != "f.bootstrap-authorization/v1"
            || !hash_ok(&payload.manifest_hash)
            || !short(&payload.signer_key_id, 256)
        {
            return Err(invalid());
        }
        ordered(&payload.approval_proof_hashes, 1, 16, hash_ok)?;
        interval(
            timestamp(&payload.issued_at)?,
            timestamp(&payload.not_after)?,
        )?;
        dsse_shape(&self.dsse, payload, BOOTSTRAP_AUTHORIZATION_TYPE, 16)?;
        Ok(())
    }
}
/// DSSE signature and proof references, never an assertion that supplied proofs
/// are genuine owner approvals. The store must resolve their retained originals.
#[derive(Clone, Debug)]
pub struct VerifiedBootstrapAuthorization {
    authorization: BootstrapAuthorization,
    canonical: Vec<u8>,
    hash: String,
    not_after: i64,
}
impl VerifiedBootstrapAuthorization {
    pub fn authorization(&self) -> &BootstrapAuthorization {
        &self.authorization
    }
    pub fn manifest_hash(&self) -> &str {
        &self.authorization.payload.manifest_hash
    }
    pub fn hash(&self) -> &str {
        &self.hash
    }
    pub fn canonical_bytes(&self) -> &[u8] {
        &self.canonical
    }
    pub fn not_after(&self) -> i64 {
        self.not_after
    }
}
pub fn verify_bootstrap_authorization(
    authorization: &BootstrapAuthorization,
    manifest: &AuthorityBootstrapManifest,
    proofs: &[BootstrapApprovalProof],
    trust: &RegistryTrustKey,
    now: i64,
) -> Result<VerifiedBootstrapAuthorization> {
    bounded(authorization)?;
    manifest.validate()?;
    identity(
        trust,
        &manifest.org_id,
        &manifest.project_id,
        &manifest.target_id,
        BOOTSTRAP_AUTHORIZATION_TYPE,
        now,
    )?;
    // This registry profile represents its independently provisioned trust root
    // by the exact scoped pin, matching the store's bootstrap import contract.
    if manifest.trust_root_hash != digest(trust)? {
        return Err(AuthorityError::Binding);
    }
    current(
        timestamp(&manifest.created_at)?,
        timestamp(&manifest.expires_at)?,
        now,
    )?;
    let p = &authorization.payload;
    if authorization.schema_version != "f.bootstrap-authorization-envelope/v1"
        || p.schema_version != "f.bootstrap-authorization/v1"
        || p.manifest_hash != manifest.hash()?
        || p.signer_key_id != trust.key_id
        || !(1..=16).contains(&proofs.len())
    {
        return Err(AuthorityError::Binding);
    }
    ordered(&p.approval_proof_hashes, 1, 16, hash_ok)?;
    let start = timestamp(&p.issued_at)?;
    let end = timestamp(&p.not_after)?;
    current(start, end, now)?;
    if start < timestamp(&manifest.created_at)?
        || end > timestamp(&manifest.expires_at)?
        || start < trust.not_before
        || end > trust.not_after
    {
        return Err(AuthorityError::Time);
    }
    let mut expected = Vec::with_capacity(proofs.len());
    let mut principals = BTreeSet::new();
    let mut ids = BTreeSet::new();
    for proof in proofs {
        proof.validate(manifest, now)?;
        if !principals.insert(&proof.approver_id)
            || !ids.insert(&proof.proof_id)
            || timestamp(&proof.approved_at)? > start
            || end > timestamp(&proof.valid_until)?
        {
            return Err(AuthorityError::Binding);
        }
        expected.push(proof.hash()?);
    }
    expected.sort();
    if expected != p.approval_proof_hashes {
        return Err(AuthorityError::Binding);
    }
    verify_dsse(&authorization.dsse, p, trust, 16)?;
    Ok(VerifiedBootstrapAuthorization {
        authorization: authorization.clone(),
        canonical: canonical(authorization)?,
        hash: digest(authorization)?,
        not_after: end,
    })
}

pub fn validate_access_envelope(envelope: &AccessEnvelope) -> Result<()> {
    bounded(envelope)?;
    if envelope.schema_version != "f.access-envelope/v1"
        || envelope.revision == 0
        || envelope.revision > i32::MAX as u32
        || [
            &envelope.envelope_id,
            &envelope.org_id,
            &envelope.project_id,
            &envelope.target_id,
        ]
        .iter()
        .any(|id| !uuid_ok(id))
        || !hash_ok(&envelope.approval_hash)
        || !(60..=86400).contains(&envelope.max_lease_seconds)
    {
        return Err(invalid());
    }
    envelope.scope.validate().map_err(|_| invalid())?;
    if envelope.excluded_destination_cidrs.len() > 128 {
        return Err(invalid());
    }
    let mut seen = BTreeSet::new();
    for cidr in &envelope.excluded_destination_cidrs {
        let n: IpNet = cidr.parse().map_err(|_| invalid())?;
        if n.trunc() != n || n.to_string() != *cidr || !seen.insert(cidr) {
            return Err(invalid());
        }
    }
    interval(
        timestamp(&envelope.valid_from)?,
        timestamp(&envelope.valid_until)?,
    )?;
    Ok(())
}
pub fn validate_delegation(delegation: &Delegation, envelope: &AccessEnvelope) -> Result<()> {
    bounded(delegation)?;
    validate_access_envelope(envelope)?;
    if delegation.schema_version != "f.delegation/v1"
        || delegation.revision == 0
        || delegation.revision > i32::MAX as u32
        || !uuid_ok(&delegation.root_id)
        || delegation.org_id != envelope.org_id
        || delegation.project_id != envelope.project_id
        || delegation.target_id != envelope.target_id
        || delegation.envelope_id != envelope.envelope_id
        || delegation.envelope_hash != digest(envelope)?
        || !hash_ok(&delegation.approval_hash)
        || delegation.can_delegate
    {
        return Err(AuthorityError::Binding);
    }
    for values in [
        &delegation.allowed_principal_ids,
        &delegation.workload_binding_ids,
        &delegation.source_asset_ids,
        &delegation.destination_asset_ids,
    ] {
        ordered(values, 1, 256, uuid_ok)?;
    }
    unique(&delegation.service_ids, 1, 128, |value| short(value, 128))?;
    unique(&delegation.allowed_tools, 1, 6, |s| {
        [
            "request_access",
            "get_plan",
            "get_operation",
            "request_deployment",
            "release_access",
            "get_capabilities",
        ]
        .contains(&s)
    })?;
    if !delegation
        .source_asset_ids
        .iter()
        .all(|id| envelope.scope.source_asset_ids.contains(id))
        || !delegation
            .destination_asset_ids
            .iter()
            .all(|id| envelope.scope.destination_asset_ids.contains(id))
    {
        return Err(AuthorityError::Binding);
    }
    for (value, min, max) in [
        (delegation.max_lease_seconds, 60, envelope.max_lease_seconds),
        (delegation.max_active_leases, 1, 10000),
        (delegation.max_new_leases_per_day, 1, 100000),
        (delegation.max_unique_destinations_per_day, 1, 100000),
        (
            delegation.max_cumulative_lease_seconds_per_day,
            60,
            i32::MAX as u64,
        ),
        (delegation.max_concurrent_deployments, 1, 10000),
    ] {
        if !(min..=max).contains(&value) {
            return Err(invalid());
        }
    }
    let budget = &delegation.budget_window;
    if budget.kind != "rolling"
        || budget.seconds != 86400
        || budget.interval != "(as_of-86400s,as_of]"
        || budget.lease_seconds_measure != "approved-duration-per-lease"
        || budget.rounding != "integer-seconds-no-rounding"
    {
        return Err(invalid());
    }
    let start = timestamp(&delegation.valid_from)?;
    let end = timestamp(&delegation.valid_until)?;
    interval(start, end)?;
    if start < timestamp(&envelope.valid_from)? || end > timestamp(&envelope.valid_until)? {
        return Err(AuthorityError::Time);
    }
    Ok(())
}

fn invalid() -> AuthorityError {
    AuthorityError::Invalid("authority registry object")
}
fn required_nullable<'de, D, T>(deserializer: D) -> std::result::Result<Option<T>, D::Error>
where
    D: serde::Deserializer<'de>,
    T: Deserialize<'de>,
{
    Option::<T>::deserialize(deserializer)
}
fn short(value: &str, max: usize) -> bool {
    !value.trim().is_empty() && value.chars().count() <= max && !value.chars().any(char::is_control)
}
fn interval(start: i64, end: i64) -> Result<()> {
    if start < 0 || start >= end || end > 253402300799 {
        Err(AuthorityError::Time)
    } else {
        Ok(())
    }
}
fn current(start: i64, end: i64, now: i64) -> Result<()> {
    interval(start, end)?;
    if now < start || now >= end {
        Err(AuthorityError::Time)
    } else {
        Ok(())
    }
}
fn ordered(values: &[String], min: usize, max: usize, check: impl Fn(&str) -> bool) -> Result<()> {
    if !(min..=max).contains(&values.len())
        || values.iter().any(|v| !check(v))
        || values.windows(2).any(|pair| pair[0] >= pair[1])
    {
        Err(invalid())
    } else {
        Ok(())
    }
}
fn unique(values: &[String], min: usize, max: usize, check: impl Fn(&str) -> bool) -> Result<()> {
    if !(min..=max).contains(&values.len())
        || values.iter().any(|value| !check(value))
        || values.iter().collect::<BTreeSet<_>>().len() != values.len()
    {
        Err(invalid())
    } else {
        Ok(())
    }
}
struct Budget(usize);
impl Write for Budget {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        self.0 = self
            .0
            .checked_sub(bytes.len())
            .ok_or_else(|| std::io::Error::other("authority registry size"))?;
        Ok(bytes.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}
fn bounded<T: Serialize>(value: &T) -> Result<()> {
    serde_json::to_writer(Budget(MAX_AUTHORITY_REGISTRY_BYTES), value).map_err(|_| invalid())
}
fn canonical<T: Serialize>(value: &T) -> Result<Vec<u8>> {
    bounded(value)?;
    canonical_bytes(value).map_err(|_| invalid())
}
fn digest<T: Serialize>(value: &T) -> Result<String> {
    bounded(value)?;
    canonical_hash(value).map_err(|_| invalid())
}
fn identity(
    trust: &RegistryTrustKey,
    org: &str,
    project: &str,
    target: &str,
    purpose: &str,
    now: i64,
) -> Result<()> {
    trust.validate(now)?;
    if trust.org_id != org
        || trust.project_id != project
        || trust.target_id != target
        || trust.payload_type != purpose
    {
        Err(AuthorityError::Signature)
    } else {
        Ok(())
    }
}
fn verify_dsse<T: Serialize>(
    dsse: &DsseEnvelope,
    payload: &T,
    trust: &RegistryTrustKey,
    max_signatures: usize,
) -> Result<()> {
    let bytes = dsse_shape(dsse, payload, &trust.payload_type, max_signatures)?;
    let signature = dsse
        .signatures
        .iter()
        .find(|value| value.keyid == trust.key_id)
        .ok_or(AuthorityError::Signature)?;
    let raw = STANDARD
        .decode(&signature.sig)
        .map_err(|_| AuthorityError::Signature)?;
    let signature = Signature::from_slice(&raw).map_err(|_| AuthorityError::Signature)?;
    let key = VerifyingKey::from_bytes(&trust.public_key).map_err(|_| AuthorityError::Signature)?;
    key.verify_strict(&pae(&trust.payload_type, &bytes), &signature)
        .map_err(|_| AuthorityError::Signature)
}
fn dsse_shape<T: Serialize>(
    dsse: &DsseEnvelope,
    payload: &T,
    payload_type: &str,
    max_signatures: usize,
) -> Result<Vec<u8>> {
    if dsse.payload_type != payload_type
        || dsse.signatures.is_empty()
        || dsse.signatures.len() > max_signatures
    {
        return Err(AuthorityError::Signature);
    }
    let bytes = canonical(payload)?;
    let decoded = STANDARD
        .decode(&dsse.payload)
        .map_err(|_| AuthorityError::Signature)?;
    if decoded != bytes || STANDARD.encode(&decoded) != dsse.payload {
        return Err(AuthorityError::Signature);
    }
    let mut ids = BTreeSet::new();
    for sig in &dsse.signatures {
        if !short(&sig.keyid, 256) || !ids.insert(&sig.keyid) {
            return Err(AuthorityError::Signature);
        }
        let raw = STANDARD
            .decode(&sig.sig)
            .map_err(|_| AuthorityError::Signature)?;
        if raw.len() != 64 || STANDARD.encode(&raw) != sig.sig {
            return Err(AuthorityError::Signature);
        }
    }
    Ok(bytes)
}
