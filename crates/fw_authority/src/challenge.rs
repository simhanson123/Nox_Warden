//! Immutable, subject-bound inputs for an approval WebAuthn assertion.
//!
//! Construct the context from independently resolved authority state, never a
//! submitted `approved` flag. A challenge is not an approval: this module does
//! not verify current roles, consume a ceremony or persist a HumanApproval.
use crate::{AuthorityError, Result, hash_ok, uuid_ok};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use chrono::{DateTime, Utc};
use fw_contracts::{canonical_bytes, hash_bytes, parse_strict_with_limit};
use fw_webauthn::WebAuthn;
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};

const SCHEMA: &str = "fw.approval-challenge-payload/v1";
const PLAN_DOMAIN: &[u8] = b"fw.approval.plan-challenge.v1\0";
const BOOTSTRAP_DOMAIN: &[u8] = b"fw.approval.authority-bootstrap-challenge.v1\0";
const MAX_TIME: i64 = 253_402_300_799;
const MAX_PAYLOAD_BYTES: usize = 8192;
pub const APPROVAL_CHALLENGE_SECONDS: i64 = 300;

#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ApprovalPlanKind {
    AddAccessLease,
    PolicyChange,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ApprovalPlanRef {
    pub plan_kind: ApprovalPlanKind,
    pub plan_id: String,
    pub plan_hash: String,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(tag = "subject_type", rename_all = "snake_case", deny_unknown_fields)]
pub enum ApprovalChallengeSubject {
    Plan {
        plan_ref: ApprovalPlanRef,
    },
    AuthorityBootstrap {
        manifest_id: String,
        subject_hash: String,
    },
}

#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ApprovalDecision {
    Approve,
    Reject,
}

#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ApprovalRole {
    Owner,
    NetworkReviewer,
    ServiceReviewer,
    SecurityReviewer,
}

/// This context binds a proof to resolved inputs; it does not attest that its
/// principal possesses the named role. The independent authority must resolve
/// the immutable subject, requirements and current membership itself.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ApprovalChallengeContext {
    pub org_id: String,
    pub project_id: String,
    pub principal_id: String,
    pub subject: ApprovalChallengeSubject,
    pub requirements_hash: String,
    pub decision: ApprovalDecision,
    pub role: ApprovalRole,
    pub subject_valid_until: i64,
}

impl ApprovalChallengeContext {
    fn validate(&self) -> Result<()> {
        if ![&self.org_id, &self.project_id, &self.principal_id]
            .into_iter()
            .all(|id| uuid_ok(id))
            || !hash_ok(&self.requirements_hash)
        {
            return Err(invalid("approval challenge identity or requirements"));
        }
        valid_time(self.subject_valid_until)?;
        match &self.subject {
            ApprovalChallengeSubject::Plan { plan_ref } => {
                if !uuid_ok(&plan_ref.plan_id) || !hash_ok(&plan_ref.plan_hash) {
                    return Err(invalid("approval challenge plan reference"));
                }
            }
            ApprovalChallengeSubject::AuthorityBootstrap {
                manifest_id,
                subject_hash,
            } => {
                if !uuid_ok(manifest_id)
                    || !hash_ok(subject_hash)
                    || self.role != ApprovalRole::Owner
                {
                    return Err(invalid("approval challenge bootstrap reference or role"));
                }
            }
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Payload {
    schema_version: String,
    challenge_id: String,
    nonce: String,
    org_id: String,
    project_id: String,
    principal_id: String,
    subject: ApprovalChallengeSubject,
    requirements_hash: String,
    decision: ApprovalDecision,
    role: ApprovalRole,
    rp_id: String,
    origin: String,
    issued_at: String,
    expires_at: String,
    subject_valid_until: String,
}

/// A validated immutable payload. Serialization contains only the closed payload,
/// not the cached hashes; deserialization revalidates and recomputes every cache.
/// Loaded payloads are still not authority: use `validate_context` against current
/// independently resolved inputs before verifying a retained assertion.
#[derive(Clone, Debug)]
pub struct ApprovalChallenge {
    payload: Payload,
    canonical: Vec<u8>,
    payload_hash: String,
    challenge_bytes: [u8; 32],
    issued_at: i64,
    expires_at: i64,
    subject_valid_until: i64,
}

impl Serialize for ApprovalChallenge {
    fn serialize<S: Serializer>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error> {
        self.payload.serialize(serializer)
    }
}
impl<'de> Deserialize<'de> for ApprovalChallenge {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> std::result::Result<Self, D::Error> {
        Self::from_payload(Payload::deserialize(deserializer)?).map_err(serde::de::Error::custom)
    }
}

fn invalid(reason: &'static str) -> AuthorityError {
    AuthorityError::Invalid(reason)
}
fn valid_time(at: i64) -> Result<()> {
    if (0..=MAX_TIME).contains(&at) {
        Ok(())
    } else {
        Err(invalid("approval challenge timestamp"))
    }
}
fn format_time(at: i64) -> Result<String> {
    valid_time(at)?;
    Ok(DateTime::<Utc>::from_timestamp(at, 0)
        .ok_or_else(|| invalid("approval challenge timestamp"))?
        .format("%Y-%m-%dT%H:%M:%SZ")
        .to_string())
}
fn parse_time(value: &str) -> Result<i64> {
    let at = crate::timestamp(value)?;
    valid_time(at)?;
    Ok(at)
}

impl ApprovalChallenge {
    /// Issue a new challenge using the configured verifier's exact RP and origin.
    /// Both the nonce and challenge ID are generated server-side with OpenSSL's
    /// CSPRNG. Context validation does not replace current role authorization.
    pub fn issue(
        context: &ApprovalChallengeContext,
        verifier: &WebAuthn,
        now: i64,
    ) -> Result<Self> {
        context.validate()?;
        valid_time(now)?;
        if now >= context.subject_valid_until {
            return Err(AuthorityError::Time);
        }
        let mut nonce = [0u8; 32];
        let mut identifier = [0u8; 16];
        openssl::rand::rand_bytes(&mut nonce)
            .and_then(|_| openssl::rand::rand_bytes(&mut identifier))
            .map_err(|_| invalid("approval challenge randomness unavailable"))?;
        Self::with_material(
            context,
            verifier,
            now,
            uuid::Builder::from_random_bytes(identifier)
                .into_uuid()
                .to_string(),
            nonce,
        )
    }

    // Only issue() exposes construction. Deterministic material is confined to
    // this private helper and tests; HTTP callers cannot submit nonce or ID.
    fn with_material(
        context: &ApprovalChallengeContext,
        verifier: &WebAuthn,
        now: i64,
        challenge_id: String,
        nonce: [u8; 32],
    ) -> Result<Self> {
        context.validate()?;
        valid_time(now)?;
        if now >= context.subject_valid_until {
            return Err(AuthorityError::Time);
        }
        let expires = (now + APPROVAL_CHALLENGE_SECONDS).min(context.subject_valid_until);
        Self::from_payload(Payload {
            schema_version: SCHEMA.into(),
            challenge_id,
            nonce: URL_SAFE_NO_PAD.encode(nonce),
            org_id: context.org_id.clone(),
            project_id: context.project_id.clone(),
            principal_id: context.principal_id.clone(),
            subject: context.subject.clone(),
            requirements_hash: context.requirements_hash.clone(),
            decision: context.decision,
            role: context.role,
            rp_id: verifier.rp_id().into(),
            origin: verifier.origin().into(),
            issued_at: format_time(now)?,
            expires_at: format_time(expires)?,
            subject_valid_until: format_time(context.subject_valid_until)?,
        })
    }

    fn from_payload(payload: Payload) -> Result<Self> {
        if payload.schema_version != SCHEMA || !uuid_ok(&payload.challenge_id) {
            return Err(invalid("approval challenge schema or identifier"));
        }
        if payload.nonce.len() != 43 || payload.origin.len() > 2048 {
            return Err(invalid("approval challenge encoded field bounds"));
        }
        let nonce = URL_SAFE_NO_PAD
            .decode(&payload.nonce)
            .map_err(|_| invalid("approval challenge nonce"))?;
        if nonce.len() != 32 || URL_SAFE_NO_PAD.encode(&nonce) != payload.nonce {
            return Err(invalid("approval challenge nonce"));
        }
        let verifier = WebAuthn::new(&payload.origin)
            .map_err(|_| invalid("approval challenge local origin"))?;
        if verifier.rp_id() != payload.rp_id {
            return Err(invalid("approval challenge RP binding"));
        }
        let issued_at = parse_time(&payload.issued_at)?;
        let expires_at = parse_time(&payload.expires_at)?;
        let subject_valid_until = parse_time(&payload.subject_valid_until)?;
        if expires_at <= issued_at
            || expires_at - issued_at > APPROVAL_CHALLENGE_SECONDS
            || expires_at > subject_valid_until
        {
            return Err(invalid("approval challenge lifetime"));
        }
        let context = ApprovalChallengeContext {
            org_id: payload.org_id.clone(),
            project_id: payload.project_id.clone(),
            principal_id: payload.principal_id.clone(),
            subject: payload.subject.clone(),
            requirements_hash: payload.requirements_hash.clone(),
            decision: payload.decision,
            role: payload.role,
            subject_valid_until,
        };
        context.validate()?;
        let canonical = canonical_bytes(&payload)
            .map_err(|_| invalid("approval challenge canonicalization"))?;
        if canonical.len() > MAX_PAYLOAD_BYTES {
            return Err(invalid("approval challenge payload too large"));
        }
        let domain = match payload.subject {
            ApprovalChallengeSubject::Plan { .. } => PLAN_DOMAIN,
            ApprovalChallengeSubject::AuthorityBootstrap { .. } => BOOTSTRAP_DOMAIN,
        };
        let mut digest = Sha256::new();
        digest.update(domain);
        digest.update(&canonical);
        let challenge_bytes = digest.finalize().into();
        let payload_hash = hash_bytes(&canonical);
        Ok(Self {
            payload,
            canonical,
            payload_hash,
            challenge_bytes,
            issued_at,
            expires_at,
            subject_valid_until,
        })
    }

    /// Bounded, duplicate-free admission of retained server-side payload bytes.
    /// Successful parsing is not a claim that these bytes came from an authority.
    pub fn from_json(bytes: &[u8]) -> Result<Self> {
        parse_strict_with_limit(bytes, MAX_PAYLOAD_BYTES)
            .map_err(|_| invalid("approval challenge payload"))
    }

    pub fn validate_now(&self, now: i64) -> Result<()> {
        valid_time(now)?;
        if now < self.issued_at || now >= self.expires_at {
            return Err(AuthorityError::Time);
        }
        Ok(())
    }

    /// Reject any changed authority input or verifier configuration. The caller
    /// must additionally check current roles, credential state and single use.
    pub fn validate_context(
        &self,
        context: &ApprovalChallengeContext,
        verifier: &WebAuthn,
        now: i64,
    ) -> Result<()> {
        context.validate()?;
        self.validate_now(now)?;
        if self.payload.org_id != context.org_id
            || self.payload.project_id != context.project_id
            || self.payload.principal_id != context.principal_id
            || self.payload.subject != context.subject
            || self.payload.requirements_hash != context.requirements_hash
            || self.payload.decision != context.decision
            || self.payload.role != context.role
            || self.subject_valid_until != context.subject_valid_until
            || self.payload.origin != verifier.origin()
            || self.payload.rp_id != verifier.rp_id()
        {
            return Err(AuthorityError::Binding);
        }
        Ok(())
    }

    pub fn challenge_id(&self) -> &str {
        &self.payload.challenge_id
    }
    pub fn principal_id(&self) -> &str {
        &self.payload.principal_id
    }
    pub fn org_id(&self) -> &str {
        &self.payload.org_id
    }
    pub fn project_id(&self) -> &str {
        &self.payload.project_id
    }
    pub fn origin(&self) -> &str {
        &self.payload.origin
    }
    pub fn rp_id(&self) -> &str {
        &self.payload.rp_id
    }
    pub fn issued_at(&self) -> i64 {
        self.issued_at
    }
    pub fn expires_at(&self) -> i64 {
        self.expires_at
    }
    pub fn subject_valid_until(&self) -> i64 {
        self.subject_valid_until
    }
    pub fn subject(&self) -> &ApprovalChallengeSubject {
        &self.payload.subject
    }
    pub fn decision(&self) -> ApprovalDecision {
        self.payload.decision
    }
    pub fn role(&self) -> ApprovalRole {
        self.payload.role
    }
    pub fn requirements_hash(&self) -> &str {
        &self.payload.requirements_hash
    }
    pub fn canonical_payload(&self) -> &[u8] {
        &self.canonical
    }
    pub fn payload_hash(&self) -> &str {
        &self.payload_hash
    }
    pub fn challenge_bytes(&self) -> [u8; 32] {
        self.challenge_bytes
    }

    /// The original closed F ApprovalChallenge response for a policy/access plan.
    /// Authority bootstrap uses a distinct subject and has no plan response.
    pub fn plan_challenge_response(&self) -> Option<Value> {
        let ApprovalChallengeSubject::Plan { plan_ref } = &self.payload.subject else {
            return None;
        };
        Some(json!({
            "plan_ref":plan_ref,"decision":self.payload.decision,"role":self.payload.role,
            "challenge_id":self.payload.challenge_id,"nonce":self.payload.nonce,
            "expires_at":self.payload.expires_at,"rp_id":self.payload.rp_id,
            "origin":self.payload.origin,"challenge_payload_hash":self.payload_hash
        }))
    }
}

#[cfg(test)]
#[path = "challenge_tests.rs"]
mod tests;
