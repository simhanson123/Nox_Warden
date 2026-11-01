//! Bounded immutable jobs and cryptographically checked signer replies.
//!
//! A validated job proves its shape and exact content, not permission to sign.
//! Callers must independently resolve the originals and current authority before
//! signing, and revalidate them transactionally before creating an outbox entry.
//! Nothing in this module promotes development evidence into AuthorityEvidence.

use crate::{
    AuthorityError, GrantContext, Result, SignedGrant, TrustKey, VerifiedGrant, hash_ok, uuid_ok,
    validate_payload, verify_grant,
};
use fw_contracts::{canonical_bytes, canonical_hash, parse_strict_with_limit};
use serde::{Deserialize, Serialize};
use serde_json::Value;

pub const SIGNING_JOB_SCHEMA: &str = "f.signing-job/v1";
pub const SIGNER_RESULT_SCHEMA: &str = "f.signer-result/v1";
pub const MAX_SIGNING_JOB_BYTES: usize = 128 * 1024;
pub const MAX_SIGNER_RESULT_BYTES: usize = 256 * 1024;

/// The complete grant payload is immutable, including its generation,
/// reservation, issuance window, and rollback authority. Identifiers and the
/// payload hash bind a reply to one retained job; they are not authorization.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct SigningJob {
    pub schema_version: String,
    pub job_id: String,
    pub intent_id: String,
    pub payload: Value,
    pub payload_hash: String,
}

/// The envelope's canonical JSON bytes define its durable identity, as in
/// verify_grant. Transport whitespace/order is irrelevant; the DSSE payload
/// itself must contain the exact canonical payload bytes, without normalization.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SignerResult {
    pub schema_version: String,
    pub job_id: String,
    pub intent_id: String,
    pub payload_hash: String,
    pub signed_grant: SignedGrant,
}

/// Structurally valid immutable content. This is deliberately not an
/// AuthorityEvidence implementation or a production signing eligibility token.
#[derive(Debug, Clone)]
pub struct PreparedSigningJob {
    job: SigningJob,
    payload_bytes: Vec<u8>,
    canonical_job_bytes: Vec<u8>,
}

impl PreparedSigningJob {
    pub fn job(&self) -> &SigningJob {
        &self.job
    }
    pub fn payload_bytes(&self) -> &[u8] {
        &self.payload_bytes
    }
    pub fn canonical_job_bytes(&self) -> &[u8] {
        &self.canonical_job_bytes
    }
}

/// Only exact-payload and real Ed25519 verification constructs this result.
/// It does not preserve current eligibility across transactions or authorize
/// dispatch. The store must revalidate its current authority and reservations.
#[derive(Debug, Clone)]
pub struct VerifiedSigningResult {
    verified_grant: VerifiedGrant,
    canonical_grant_bytes: Vec<u8>,
    canonical_result_bytes: Vec<u8>,
}

impl VerifiedSigningResult {
    pub fn verified_grant(&self) -> &VerifiedGrant {
        &self.verified_grant
    }
    pub fn grant_hash(&self) -> &str {
        self.verified_grant.grant_hash()
    }
    pub fn canonical_grant_bytes(&self) -> &[u8] {
        &self.canonical_grant_bytes
    }
    pub fn canonical_result_bytes(&self) -> &[u8] {
        &self.canonical_result_bytes
    }
}

fn invalid() -> AuthorityError {
    AuthorityError::Invalid("signing contract")
}

// Direct Rust callers can construct enormous/deep Values without the parser.
// Count an upper bound for escaped strings and punctuation before serializing or
// cloning. Work and temporary allocation are bounded even for rejected inputs.
fn preflight(value: &Value, remaining: &mut usize, depth: usize) -> Result<()> {
    if depth >= fw_contracts::MAX_DEPTH {
        return Err(invalid());
    }
    let cost = match value {
        Value::String(s) => s.len().checked_mul(6).and_then(|n| n.checked_add(2)),
        Value::Array(values) => values.len().checked_add(2),
        Value::Object(values) => values.len().checked_mul(4).and_then(|n| n.checked_add(2)),
        _ => Some(24),
    }
    .ok_or_else(invalid)?;
    *remaining = remaining.checked_sub(cost).ok_or_else(invalid)?;
    match value {
        Value::Array(values) => {
            for value in values {
                preflight(value, remaining, depth + 1)?;
            }
        }
        Value::Object(values) => {
            for (key, value) in values {
                if !key.is_ascii() {
                    return Err(invalid());
                }
                *remaining = remaining
                    .checked_sub(key.len().checked_mul(6).ok_or_else(invalid)?)
                    .ok_or_else(invalid)?;
                preflight(value, remaining, depth + 1)?;
            }
        }
        _ => {}
    }
    Ok(())
}

fn bounded_payload(value: &Value) -> Result<Vec<u8>> {
    // Six accounts for the JSON escaping expansion without rejecting long
    // ordinary strings merely because their worst-case escaping is larger.
    preflight(value, &mut (MAX_SIGNING_JOB_BYTES * 6), 0)?;
    let bytes = canonical_bytes(value).map_err(|_| invalid())?;
    if bytes.len() > MAX_SIGNING_JOB_BYTES {
        return Err(invalid());
    }
    Ok(bytes)
}

fn bounded_canonical<T: Serialize>(value: &T, maximum: usize) -> Result<Vec<u8>> {
    let bytes = canonical_bytes(value).map_err(|_| invalid())?;
    if bytes.len() > maximum {
        return Err(invalid());
    }
    Ok(bytes)
}

pub fn validate_signing_job(job: &SigningJob) -> Result<PreparedSigningJob> {
    if job.schema_version != SIGNING_JOB_SCHEMA
        || !uuid_ok(&job.job_id)
        || !uuid_ok(&job.intent_id)
        || !hash_ok(&job.payload_hash)
    {
        return Err(invalid());
    }
    let payload_bytes = bounded_payload(&job.payload)?;
    validate_payload(&job.payload)?;
    if canonical_hash(&job.payload).map_err(|_| invalid())? != job.payload_hash {
        return Err(AuthorityError::Binding);
    }
    let canonical_job_bytes = bounded_canonical(job, MAX_SIGNING_JOB_BYTES)?;
    Ok(PreparedSigningJob {
        job: job.clone(),
        payload_bytes,
        canonical_job_bytes,
    })
}

pub fn parse_signing_job(bytes: &[u8]) -> Result<PreparedSigningJob> {
    let job = parse_strict_with_limit(bytes, MAX_SIGNING_JOB_BYTES).map_err(|_| invalid())?;
    validate_signing_job(&job)
}

fn validate_result_shape(result: &SignerResult) -> Result<()> {
    if result.schema_version != SIGNER_RESULT_SCHEMA
        || !uuid_ok(&result.job_id)
        || !uuid_ok(&result.intent_id)
        || !hash_ok(&result.payload_hash)
    {
        return Err(invalid());
    }
    bounded_payload(&result.signed_grant.payload)?;
    let kind = validate_payload(&result.signed_grant.payload)?;
    let envelope = &result.signed_grant.dsse;
    if envelope.payload_type != kind
        || envelope.payload.len() > MAX_SIGNER_RESULT_BYTES
        || envelope.signatures.len() != 1
        || envelope.signatures[0].keyid.is_empty()
        || envelope.signatures[0].keyid.len() > 256
        || envelope.signatures[0].sig.len() != 88
    {
        return Err(invalid());
    }
    Ok(())
}

/// Bounded syntax and closed-shape admission only; callers must subsequently
/// verify against the retained job and an independently pinned current key.
pub fn parse_signer_result(bytes: &[u8]) -> Result<SignerResult> {
    let result = parse_strict_with_limit(bytes, MAX_SIGNER_RESULT_BYTES).map_err(|_| invalid())?;
    validate_result_shape(&result)?;
    Ok(result)
}

pub fn verify_signer_result(
    job: &PreparedSigningJob,
    result: &SignerResult,
    trust: &TrustKey,
    context: &GrantContext,
) -> Result<VerifiedSigningResult> {
    validate_result_shape(result)?;
    if result.job_id != job.job.job_id
        || result.intent_id != job.job.intent_id
        || result.payload_hash != job.job.payload_hash
        || bounded_payload(&result.signed_grant.payload)? != job.payload_bytes
    {
        return Err(AuthorityError::Binding);
    }
    // Bound the complete envelope before verify_grant decodes or clones it.
    let canonical_result_bytes = bounded_canonical(result, MAX_SIGNER_RESULT_BYTES)?;
    let verified_grant = verify_grant(&result.signed_grant, trust, context)?;
    let canonical_grant_bytes = bounded_canonical(&result.signed_grant, MAX_SIGNER_RESULT_BYTES)?;
    Ok(VerifiedSigningResult {
        verified_grant,
        canonical_grant_bytes,
        canonical_result_bytes,
    })
}
