//! Cryptographic binding of a WebAuthn assertion to one immutable challenge.
//!
//! This is deliberately below the authority's authorization transaction. Its
//! caller must load an issued challenge, current active credential and current
//! roles from protected authority storage, then consume the challenge, retain
//! the original proof and update the credential atomically. A verified assertion
//! alone is neither a HumanApproval nor permission to sign or dispatch a policy.
use crate::{ApprovalChallenge, ApprovalChallengeContext, AuthorityError, Result, hash_ok};
use fw_webauthn::{AuthenticationResponse, BoundAuthenticationState, Credential, WebAuthn};
use serde::{Deserialize, Serialize};
use serde_json::Value;

const STATE_SCHEMA: &str = "fw.approval-proof-state/v1";

/// Server-only state. Never accept it from a browser or put it in a cookie.
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ApprovalProofState {
    schema_version: String,
    challenge_payload_hash: String,
    webauthn: BoundAuthenticationState,
}
impl ApprovalProofState {
    /// Bounded admission for a record loaded from protected authority storage.
    /// Parsing does not establish that this record was issued or is unconsumed.
    pub fn from_json(bytes: &[u8]) -> Result<Self> {
        let state: Self = fw_contracts::parse_strict(bytes)
            .map_err(|_| AuthorityError::Invalid("approval proof state"))?;
        state.validate()?;
        Ok(state)
    }
    fn validate(&self) -> Result<()> {
        if self.schema_version != STATE_SCHEMA || !hash_ok(&self.challenge_payload_hash) {
            return Err(AuthorityError::Invalid("approval proof state"));
        }
        Ok(())
    }
}

pub struct ApprovalProofCeremony {
    /// Public navigator.credentials.get options; these are not authorization.
    pub options: Value,
    pub state: ApprovalProofState,
}

/// A signature-verified result with immutable subject binding, not an approval.
/// No Serialize implementation or public constructor can turn an unchecked
/// client flag into this result. The authority still has to authorize and commit.
pub struct VerifiedBoundAssertion {
    challenge: ApprovalChallenge,
    assertion: AuthenticationResponse,
    updated_credential: Credential,
    verified_at: i64,
}
impl VerifiedBoundAssertion {
    pub fn challenge(&self) -> &ApprovalChallenge {
        &self.challenge
    }
    /// Retains original clientDataJSON/authenticator/signature bytes in their
    /// admitted base64url representation for restricted proof storage.
    pub fn assertion(&self) -> &AuthenticationResponse {
        &self.assertion
    }
    /// Persist this with challenge consumption, not as a separate later write.
    pub fn updated_credential(&self) -> &Credential {
        &self.updated_credential
    }
    pub fn verified_at(&self) -> i64 {
        self.verified_at
    }
}

fn proof_error(error: fw_webauthn::Error) -> AuthorityError {
    match error {
        fw_webauthn::Error::Verification => AuthorityError::Signature,
        fw_webauthn::Error::Stale | fw_webauthn::Error::Configuration => AuthorityError::Binding,
        fw_webauthn::Error::Input => AuthorityError::Invalid("approval WebAuthn proof"),
    }
}

/// `context` is independently resolved authority data, not the HTTP request.
pub fn begin_approval_proof(
    verifier: &WebAuthn,
    challenge: &ApprovalChallenge,
    context: &ApprovalChallengeContext,
    credentials: &[Credential],
    now_unix: i64,
) -> Result<ApprovalProofCeremony> {
    challenge.validate_context(context, verifier, now_unix)?;
    let ceremony = verifier
        .begin_bound_authentication(
            challenge.principal_id(),
            credentials,
            challenge.challenge_bytes(),
        )
        .map_err(proof_error)?;
    Ok(ApprovalProofCeremony {
        options: ceremony.options,
        state: ApprovalProofState {
            schema_version: STATE_SCHEMA.into(),
            challenge_payload_hash: challenge.payload_hash().into(),
            webauthn: ceremony.state,
        },
    })
}

/// Verify the exact issued challenge against freshly resolved subject binding.
/// The caller must reject revoked/unverified credentials and stale roles, and
/// perform this operation in its one-use challenge/credential transaction.
pub fn finish_approval_proof(
    verifier: &WebAuthn,
    state: &ApprovalProofState,
    challenge: &ApprovalChallenge,
    context: &ApprovalChallengeContext,
    response: &AuthenticationResponse,
    current_credential: &Credential,
    now_unix: i64,
) -> Result<VerifiedBoundAssertion> {
    state.validate()?;
    challenge.validate_context(context, verifier, now_unix)?;
    if state.challenge_payload_hash != challenge.payload_hash()
        || current_credential.principal_id() != challenge.principal_id()
        || current_credential.rp_id() != challenge.rp_id()
    {
        return Err(AuthorityError::Binding);
    }
    let updated_credential = verifier
        .finish_bound_authentication(
            &state.webauthn,
            response,
            current_credential,
            challenge.challenge_bytes(),
        )
        .map_err(proof_error)?;
    Ok(VerifiedBoundAssertion {
        challenge: challenge.clone(),
        assertion: response.clone(),
        updated_credential,
        verified_at: now_unix,
    })
}
