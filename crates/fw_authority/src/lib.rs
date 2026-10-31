//! Pure grant verification and persistent quota primitives for an isolated authority.
//! Bound WebAuthn proof primitives do not provide a production approval/signing
//! service or an API that accepts client-supplied approval booleans.
mod approval;
pub use approval::*;
#[cfg(feature = "approval-proofs")]
mod challenge;
#[cfg(feature = "approval-proofs")]
pub use challenge::*;
#[cfg(feature = "approval-proofs")]
mod proof;
#[cfg(feature = "approval-proofs")]
pub use proof::*;
#[cfg(feature = "approval-proofs")]
mod store;
#[cfg(feature = "approval-proofs")]
pub use store::*;
mod quota;
pub use quota::*;

use base64::{Engine, engine::general_purpose::STANDARD};
use chrono::{DateTime, Utc};
use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use fw_contracts::{canonical_bytes, canonical_hash};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::BTreeSet;
use thiserror::Error;

pub const CORE_GRANT_TYPE: &str = "application/vnd.f.grant.v1+json";
pub const POLICY_CHANGE_GRANT_TYPE: &str = "application/vnd.f.policy-change-grant.v1+json";

#[derive(Debug, Error)]
pub enum AuthorityError {
    #[error("invalid grant: {0}")]
    Invalid(&'static str),
    #[error("signature is not authorized")]
    Signature,
    #[error("grant or trust key is expired, revoked, or not yet valid")]
    Time,
    #[error("grant does not match the independently resolved authority context")]
    Binding,
    #[error("quota exceeded")]
    Quota,
    #[error("reservation conflicts with an existing immutable reservation")]
    Conflict,
    #[error("authority storage failure")]
    Storage(#[from] rusqlite::Error),
}
pub type Result<T> = std::result::Result<T, AuthorityError>;

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DsseSignature {
    pub keyid: String,
    pub sig: String,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DsseEnvelope {
    #[serde(rename = "payloadType")]
    pub payload_type: String,
    pub payload: String,
    pub signatures: Vec<DsseSignature>,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SignedGrant {
    pub payload: Value,
    pub dsse: DsseEnvelope,
}

/// The exact recovery restriction carried inside the signed grant. This value
/// identifies immutable objects; it does not authorize a caller-supplied ruleset.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct RollbackAuthority {
    pub profile: String,
    pub scope_bound_hash: String,
    pub baseline_hash: String,
    pub artifact_hash: String,
    pub valid_until: String,
}
impl RollbackAuthority {
    pub fn valid_until_unix(&self) -> Result<i64> {
        timestamp(&self.valid_until)
    }
}

/// A registry-resolved public key. `key_id` is a lookup hint, never authority.
#[derive(Debug, Clone)]
pub struct TrustKey {
    pub key_id: String,
    pub org_id: String,
    pub payload_type: String,
    pub public_key: [u8; 32],
    pub not_before: i64,
    pub not_after: i64,
    pub revoked: bool,
}
/// Resolved from immutable plan, approval, artifact, and current target registry.
/// Do not construct this from submitted client claims.
#[derive(Debug, Clone)]
pub struct GrantContext {
    pub org_id: String,
    pub project_id: String,
    pub target_id: String,
    pub plan_hash: String,
    pub artifact_hash: String,
    pub baseline_hash: String,
    pub desired_state_hash: String,
    pub approval_set_hash: String,
    pub authority_epoch: u64,
    pub now_unix: i64,
}
/// Only cryptographic verification creates this value. Persistence of generation
/// and idempotency remains the executor's responsibility.
#[derive(Debug, Clone)]
pub struct VerifiedGrant {
    grant_id: String,
    org_id: String,
    project_id: String,
    target_id: String,
    authority_epoch: u64,
    generation: u64,
    grant_hash: String,
    issued_at: i64,
    not_after: i64,
    confirm_not_after: i64,
    plan_hash: String,
    artifact_hash: String,
    baseline_hash: String,
    desired_state_hash: String,
    approval_set_hash: String,
    rollback_authority: RollbackAuthority,
    signed_grant: SignedGrant,
}
impl VerifiedGrant {
    pub fn grant_id(&self) -> &str {
        &self.grant_id
    }
    pub fn org_id(&self) -> &str {
        &self.org_id
    }
    pub fn project_id(&self) -> &str {
        &self.project_id
    }
    pub fn target_id(&self) -> &str {
        &self.target_id
    }
    pub fn authority_epoch(&self) -> u64 {
        self.authority_epoch
    }
    pub fn generation(&self) -> u64 {
        self.generation
    }
    pub fn grant_hash(&self) -> &str {
        &self.grant_hash
    }
    pub fn issued_at(&self) -> i64 {
        self.issued_at
    }
    pub fn not_after(&self) -> i64 {
        self.not_after
    }
    pub fn confirm_not_after(&self) -> i64 {
        self.confirm_not_after
    }
    pub fn plan_hash(&self) -> &str {
        &self.plan_hash
    }
    pub fn artifact_hash(&self) -> &str {
        &self.artifact_hash
    }
    pub fn baseline_hash(&self) -> &str {
        &self.baseline_hash
    }
    pub fn desired_state_hash(&self) -> &str {
        &self.desired_state_hash
    }
    pub fn approval_set_hash(&self) -> &str {
        &self.approval_set_hash
    }
    pub fn rollback_authority(&self) -> &RollbackAuthority {
        &self.rollback_authority
    }
    /// Retains the already verified exact canonical envelope for durable replay
    /// and recovery checks. Trust must still be resolved independently on reuse.
    pub fn signed_grant(&self) -> &SignedGrant {
        &self.signed_grant
    }
}

/// DSSE v1 pre-authentication encoding, byte lengths (not character counts).
pub fn pae(payload_type: &str, payload: &[u8]) -> Vec<u8> {
    let mut out = format!(
        "DSSEv1 {} {} {} ",
        payload_type.len(),
        payload_type,
        payload.len()
    )
    .into_bytes();
    out.extend_from_slice(payload);
    out
}
fn hash_ok(s: &str) -> bool {
    s.len() == 71
        && s.starts_with("sha256:")
        && s[7..]
            .bytes()
            .all(|c| c.is_ascii_digit() || (b'a'..=b'f').contains(&c))
}
fn string<'a>(v: &'a Value, key: &str) -> Result<&'a str> {
    v.get(key)
        .and_then(Value::as_str)
        .ok_or(AuthorityError::Invalid("missing string field"))
}
fn uuid_ok(s: &str) -> bool {
    uuid::Uuid::parse_str(s).is_ok_and(|u| u.to_string() == s)
}
fn timestamp(s: &str) -> Result<i64> {
    let t = DateTime::parse_from_rfc3339(s)
        .map_err(|_| AuthorityError::Invalid("invalid UTC timestamp"))?;
    if t.with_timezone(&Utc)
        .format("%Y-%m-%dT%H:%M:%SZ")
        .to_string()
        != s
    {
        return Err(AuthorityError::Invalid("noncanonical UTC timestamp"));
    }
    Ok(t.timestamp())
}
fn counter(s: &str) -> Result<u64> {
    let n = s
        .parse::<u64>()
        .map_err(|_| AuthorityError::Invalid("invalid u64 counter"))?;
    if n.to_string() != s {
        return Err(AuthorityError::Invalid("noncanonical u64 counter"));
    }
    Ok(n)
}
fn closed(v: &Value, keys: &[&str]) -> Result<()> {
    let map = v
        .as_object()
        .ok_or(AuthorityError::Invalid("expected object"))?;
    if map.len() != keys.len() || keys.iter().any(|k| !map.contains_key(*k)) {
        return Err(AuthorityError::Invalid("unknown or missing field"));
    }
    Ok(())
}

fn validate_payload(v: &Value) -> Result<&'static str> {
    let schema = string(v, "schema_version")?;
    let core = schema == "f.grant/v1";
    if !core && schema != "f.policy-change-grant/v1" {
        return Err(AuthorityError::Invalid("unsupported grant schema"));
    }
    let mut keys = vec![
        "schema_version",
        "grant_id",
        "plan_id",
        "plan_hash",
        "org_id",
        "project_id",
        "target_id",
        "principal_id",
        "approval_set_hash",
        "authority_epoch",
        "target_generation",
        "issued_at",
        "not_after",
        "artifact_hash",
        "baseline_hash",
        "confirm_timeout_seconds",
        "confirm_not_after",
        "rollback_authority",
        "change_kind",
        "request_patch_hash",
        "desired_state_hash",
    ];
    if core {
        keys.extend([
            "lease_id",
            "request_id",
            "workload_binding_id",
            "requested_policy_hashes",
            "envelope_hash",
            "delegation_hash",
            "reservation",
        ]);
    } else {
        keys.push("dispatch_reservation_id");
    }
    closed(v, &keys)?;
    for key in &keys {
        if key.ends_with("_hash") && !hash_ok(string(v, key)?) {
            return Err(AuthorityError::Invalid("invalid hash"));
        }
        if key.ends_with("_id") && !uuid_ok(string(v, key)?) {
            return Err(AuthorityError::Invalid("noncanonical UUID"));
        }
    }
    if string(v, "change_kind")?
        != if core {
            "add_access_lease"
        } else {
            "policy_change"
        }
        || v["confirm_timeout_seconds"] != 60
    {
        return Err(AuthorityError::Invalid(
            "invalid grant kind or confirm timeout",
        ));
    }
    counter(string(v, "authority_epoch")?)?;
    counter(string(v, "target_generation")?)?;
    let issued = timestamp(string(v, "issued_at")?)?;
    let until = timestamp(string(v, "not_after")?)?;
    let confirm = timestamp(string(v, "confirm_not_after")?)?;
    if until <= issued || until - issued > 300 || confirm < until || confirm > until + 60 {
        return Err(AuthorityError::Invalid(
            "invalid dispatch or confirm window",
        ));
    }
    let rollback = &v["rollback_authority"];
    closed(
        rollback,
        &[
            "profile",
            "scope_bound_hash",
            "baseline_hash",
            "artifact_hash",
            "valid_until",
        ],
    )?;
    if !["preserve-current-restrictions", "preapproved-scope"]
        .contains(&string(rollback, "profile")?)
    {
        return Err(AuthorityError::Invalid("rollback profile"));
    }
    for k in ["scope_bound_hash", "baseline_hash", "artifact_hash"] {
        if !hash_ok(string(rollback, k)?) {
            return Err(AuthorityError::Invalid("rollback hash"));
        }
    }
    if rollback["baseline_hash"] != v["baseline_hash"]
        || timestamp(string(rollback, "valid_until")?)? < confirm
    {
        return Err(AuthorityError::Invalid("rollback binding or lifetime"));
    }
    if core {
        let hashes = v["requested_policy_hashes"]
            .as_array()
            .ok_or(AuthorityError::Invalid("policy hashes"))?;
        if hashes.is_empty()
            || hashes.len() > 256
            || hashes.iter().any(|h| !h.as_str().is_some_and(hash_ok))
        {
            return Err(AuthorityError::Invalid("policy hashes"));
        }
        let sorted: BTreeSet<_> = hashes.iter().map(|x| x.as_str().unwrap()).collect();
        if sorted.len() != hashes.len()
            || sorted
                .iter()
                .copied()
                .ne(hashes.iter().map(|x| x.as_str().unwrap()))
        {
            return Err(AuthorityError::Invalid(
                "policy hashes must be sorted and unique",
            ));
        }
        let r = &v["reservation"];
        closed(
            r,
            &[
                "reservation_id",
                "root_id",
                "status",
                "reserved_until",
                "projected_active_leases",
                "projected_new_leases_per_day",
                "projected_unique_destinations_per_day",
                "projected_cumulative_lease_seconds_per_day",
                "projected_concurrent_deployments",
                "window_start",
                "window_end",
            ],
        )?;
        if !uuid_ok(string(r, "reservation_id")?)
            || !uuid_ok(string(r, "root_id")?)
            || r["status"] != "reserved"
            || timestamp(string(r, "reserved_until")?)? < until
        {
            return Err(AuthorityError::Invalid("reservation"));
        }
        let start = timestamp(string(r, "window_start")?)?;
        let end = timestamp(string(r, "window_end")?)?;
        if end != issued || end - start != 86400 {
            return Err(AuthorityError::Invalid("reservation rolling window"));
        }
        for (k, max, min) in [
            ("projected_active_leases", 10000, 1),
            ("projected_new_leases_per_day", 100000, 1),
            ("projected_unique_destinations_per_day", 100000, 1),
            ("projected_cumulative_lease_seconds_per_day", 2147483647, 60),
            ("projected_concurrent_deployments", 10000, 1),
        ] {
            if !r[k].as_i64().is_some_and(|n| n >= min && n <= max) {
                return Err(AuthorityError::Invalid("reservation counter"));
            }
        }
    }
    Ok(if core {
        CORE_GRANT_TYPE
    } else {
        POLICY_CHANGE_GRANT_TYPE
    })
}

pub fn verify_grant(
    grant: &SignedGrant,
    trust: &TrustKey,
    context: &GrantContext,
) -> Result<VerifiedGrant> {
    let kind = validate_payload(&grant.payload)?;
    if grant.dsse.payload_type != kind
        || trust.payload_type != kind
        || trust.org_id != context.org_id
        || trust.revoked
    {
        return Err(AuthorityError::Signature);
    }
    let now = context.now_unix;
    if now < trust.not_before || now >= trust.not_after {
        return Err(AuthorityError::Time);
    }
    let bytes = canonical_bytes(&grant.payload)
        .map_err(|_| AuthorityError::Invalid("canonical payload"))?;
    if STANDARD
        .decode(&grant.dsse.payload)
        .map_err(|_| AuthorityError::Invalid("payload base64"))?
        != bytes
        || grant.dsse.signatures.len() != 1
    {
        return Err(AuthorityError::Signature);
    }
    let signature = &grant.dsse.signatures[0];
    if signature.keyid != trust.key_id {
        return Err(AuthorityError::Signature);
    }
    let sig_bytes = STANDARD
        .decode(&signature.sig)
        .map_err(|_| AuthorityError::Signature)?;
    let sig = Signature::from_slice(&sig_bytes).map_err(|_| AuthorityError::Signature)?;
    let key = VerifyingKey::from_bytes(&trust.public_key).map_err(|_| AuthorityError::Signature)?;
    key.verify_strict(&pae(kind, &bytes), &sig)
        .map_err(|_| AuthorityError::Signature)?;
    let p = &grant.payload;
    let issued = timestamp(string(p, "issued_at")?)?;
    let until = timestamp(string(p, "not_after")?)?;
    if now < issued || now >= until || issued < trust.not_before || until > trust.not_after {
        return Err(AuthorityError::Time);
    }
    for (k, expected) in [
        ("org_id", &context.org_id),
        ("project_id", &context.project_id),
        ("target_id", &context.target_id),
        ("plan_hash", &context.plan_hash),
        ("artifact_hash", &context.artifact_hash),
        ("baseline_hash", &context.baseline_hash),
        ("desired_state_hash", &context.desired_state_hash),
        ("approval_set_hash", &context.approval_set_hash),
    ] {
        if string(p, k)? != expected {
            return Err(AuthorityError::Binding);
        }
    }
    let epoch = counter(string(p, "authority_epoch")?)?;
    if epoch != context.authority_epoch {
        return Err(AuthorityError::Binding);
    }
    Ok(VerifiedGrant {
        grant_id: string(p, "grant_id")?.into(),
        org_id: context.org_id.clone(),
        project_id: context.project_id.clone(),
        target_id: context.target_id.clone(),
        authority_epoch: epoch,
        generation: counter(string(p, "target_generation")?)?,
        grant_hash: canonical_hash(grant)
            .map_err(|_| AuthorityError::Invalid("envelope canonicalization"))?,
        issued_at: issued,
        not_after: until,
        confirm_not_after: timestamp(string(p, "confirm_not_after")?)?,
        plan_hash: context.plan_hash.clone(),
        artifact_hash: context.artifact_hash.clone(),
        baseline_hash: context.baseline_hash.clone(),
        desired_state_hash: context.desired_state_hash.clone(),
        approval_set_hash: context.approval_set_hash.clone(),
        rollback_authority: serde_json::from_value(p["rollback_authority"].clone())
            .map_err(|_| AuthorityError::Invalid("rollback authority"))?,
        signed_grant: grant.clone(),
    })
}

/// Reverify a persisted grant for its separately bounded recovery authority.
/// Dispatch expiry is not recovery expiry, but current key validity/revocation,
/// exact original signature and all independently resolved bindings still apply.
/// The returned grant retains its original dispatch window; executor acceptance
/// or submission after that window remains forbidden.
pub fn verify_recovery_grant(
    grant: &SignedGrant,
    trust: &TrustKey,
    context: &GrantContext,
) -> Result<VerifiedGrant> {
    validate_payload(&grant.payload)?;
    let now = context.now_unix;
    let issued = timestamp(string(&grant.payload, "issued_at")?)?;
    let recovery_until = timestamp(string(&grant.payload["rollback_authority"], "valid_until")?)?;
    if trust.revoked || now < trust.not_before || now >= trust.not_after {
        return Err(AuthorityError::Time);
    }
    if now < issued || now >= recovery_until {
        return Err(AuthorityError::Time);
    }
    let mut original = context.clone();
    original.now_unix = issued;
    verify_grant(grant, trust, &original)
}

/// Independent approval verifier interface. Implementations MUST resolve immutable
/// plan, proof, current role/credential/revocation, quota and registry data from the
/// authority's own store. No implementation is supplied that trusts a JSON boolean.
pub trait AuthorityEvidence {
    fn verify_for_signing(&self, payload: &Value, now_unix: i64) -> Result<GrantContext>;
}
/// Low-level isolated signer entry point; not exposed by the control HTTP server.
/// A valid Ed25519 signature alone does not certify the AuthorityEvidence adapter.
pub fn sign_grant(
    payload: Value,
    key_id: &str,
    key: &SigningKey,
    evidence: &impl AuthorityEvidence,
    now_unix: i64,
) -> Result<SignedGrant> {
    let kind = validate_payload(&payload)?;
    let context = evidence.verify_for_signing(&payload, now_unix)?;
    let bytes =
        canonical_bytes(&payload).map_err(|_| AuthorityError::Invalid("canonical payload"))?;
    let sig = key.sign(&pae(kind, &bytes));
    let grant = SignedGrant {
        payload,
        dsse: DsseEnvelope {
            payload_type: kind.into(),
            payload: STANDARD.encode(&bytes),
            signatures: vec![DsseSignature {
                keyid: key_id.into(),
                sig: STANDARD.encode(sig.to_bytes()),
            }],
        },
    };
    let trust = TrustKey {
        key_id: key_id.into(),
        org_id: context.org_id.clone(),
        payload_type: kind.into(),
        public_key: key.verifying_key().to_bytes(),
        not_before: now_unix,
        not_after: now_unix + 3600,
        revoked: false,
    };
    verify_grant(&grant, &trust, &context)?;
    Ok(grant)
}

#[cfg(test)]
mod tests;
