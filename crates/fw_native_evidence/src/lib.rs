//! Recomputed development compilation and authenticated isolated-lab captures.
//! A producer signature authenticates bytes, not kernel provenance or native
//! qualification. No result implements signing or dispatch authority.
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use fw_backend_linux::{
    Comparison, Installation, LabReferences, ObservationContext, PortableArtifact,
    compile_portable, validate_installation, verify_installation_readback_at,
};
use fw_contracts::{Counter, canonical_bytes, canonical_hash, hash_bytes, parse_strict_with_limit};
use fw_planner::PolicyReviewEvidence;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

pub use fw_target_evidence::{fingerprint, parse_time, timestamp};
pub const COMPILATION_SCHEMA: &str = "fw.lab-compilation-evidence/v1";
pub const CHALLENGE_SCHEMA: &str = "fw.lab-native-observation-challenge/v1";
pub const PAYLOAD_SCHEMA: &str = "fw.lab-native-observation-payload/v1";
pub const PROOF_SCHEMA: &str = "fw.lab-native-observation-proof/v1";
pub const MAX_COMPILATION_BYTES: usize = 1024 * 1024;
pub const MAX_CHALLENGE_BYTES: usize = 4096;
pub const MAX_PAYLOAD_BYTES: usize = 2 * 1024 * 1024;
pub const MAX_PROOF_BYTES: usize = 3 * 1024 * 1024;
pub const MAX_LIFETIME_SECONDS: i64 = 300;
const SIGNATURE_DOMAIN: &[u8] = b"fw.lab-native-observation/ed25519/v1\0";

#[derive(Debug, thiserror::Error)]
pub enum EvidenceError {
    #[error("invalid native development evidence: {0}")]
    Invalid(&'static str),
    #[error("native evidence is outside its validity interval")]
    Time,
    #[error("native observation signature is invalid")]
    Signature,
}
pub type Result<T> = std::result::Result<T, EvidenceError>;

/// Independently recomputed bytes; constructing a wire record creates no such
/// value. Pin provenance, current revisions and transaction CAS belong to store.
pub struct VerifiedCompilation {
    canonical: Vec<u8>,
    hash: String,
    plan_hash: String,
    review_hash: String,
    references_hash: String,
    baseline: PortableArtifact,
    candidate: PortableArtifact,
}
impl VerifiedCompilation {
    pub fn canonical_bytes(&self) -> &[u8] {
        &self.canonical
    }
    pub fn evidence_hash(&self) -> &str {
        &self.hash
    }
    pub fn plan_hash(&self) -> &str {
        &self.plan_hash
    }
    pub fn review_hash(&self) -> &str {
        &self.review_hash
    }
    pub fn references_hash(&self) -> &str {
        &self.references_hash
    }
    pub fn baseline(&self) -> &PortableArtifact {
        &self.baseline
    }
    pub fn candidate(&self) -> &PortableArtifact {
        &self.candidate
    }
    pub fn artifact(&self, role: ArtifactRole) -> &PortableArtifact {
        match role {
            ArtifactRole::Baseline => &self.baseline,
            ArtifactRole::Candidate => &self.candidate,
        }
    }
}

/// Rebuild both complete states from the separately reviewed immutable plan and
/// resolved lab references. Caller-supplied PASS strings are never evidence.
pub fn compile_evidence(
    plan: &Value,
    review: &PolicyReviewEvidence,
    references: &LabReferences,
) -> Result<VerifiedCompilation> {
    let verified = review.verify(plan).map_err(|_| invalid("review binding"))?;
    bounded_canonical(references, MAX_COMPILATION_BYTES)?;
    if plan["org_id"] != references.scope.org_id
        || plan["project_id"] != references.scope.project_id
        || plan["target_id"] != references.scope.target_id
    {
        return Err(invalid("reference tenant"));
    }
    let baseline = compile_portable(&review.before, references)
        .map_err(|_| invalid("baseline compilation"))?;
    let candidate = compile_portable(&review.after, references)
        .map_err(|_| invalid("candidate compilation"))?;
    let candidate_hash = candidate
        .artifact_hash()
        .map_err(|_| invalid("candidate artifact hash"))?;
    if plan["artifact_hash"] != candidate_hash {
        return Err(invalid("plan artifact hash"));
    }
    let references_hash = canonical_hash(references).map_err(|_| invalid("references hash"))?;
    #[derive(Serialize)]
    struct Record<'a> {
        schema_version: &'static str,
        plan_hash: &'a str,
        review_hash: &'a str,
        references_hash: &'a str,
        baseline: &'a PortableArtifact,
        candidate: &'a PortableArtifact,
        production_qualified: bool,
        dispatch_allowed: bool,
    }
    let record = Record {
        schema_version: COMPILATION_SCHEMA,
        plan_hash: verified.plan_hash(),
        review_hash: verified.evidence_hash(),
        references_hash: &references_hash,
        baseline: &baseline,
        candidate: &candidate,
        production_qualified: false,
        dispatch_allowed: false,
    };
    let canonical = bounded_canonical(&record, MAX_COMPILATION_BYTES)?;
    Ok(VerifiedCompilation {
        hash: hash_bytes(&canonical),
        canonical,
        plan_hash: verified.plan_hash().into(),
        review_hash: verified.evidence_hash().into(),
        references_hash,
        baseline,
        candidate,
    })
}

#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum ArtifactRole {
    Baseline,
    Candidate,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct NativeObservationChallenge {
    pub schema_version: String,
    pub challenge_id: String,
    pub org_id: String,
    pub project_id: String,
    pub target_id: String,
    pub observer_revision: String,
    pub observer_key_fingerprint: String,
    pub reference_revision: String,
    pub compilation_hash: String,
    /// Hash of the independently admitted metadata receipt, not lab capability.
    pub metadata_receipt_hash: String,
    pub metadata_report_hash: String,
    pub baseline_state_hash: String,
    /// Expected prior observation receipt; absence explicitly means first head.
    pub expected_head: Option<String>,
    pub authority_epoch: String,
    pub generation: String,
    pub artifact_role: ArtifactRole,
    pub artifact_hash: String,
    pub installation_hash: String,
    pub nonce: String,
    pub issued_at: String,
    pub expires_at: String,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ChallengeWindow {
    pub issued_at: i64,
    pub expires_at: i64,
}
impl NativeObservationChallenge {
    pub fn parse(bytes: &[u8]) -> Result<Self> {
        let value: Self = parse_strict_with_limit(bytes, MAX_CHALLENGE_BYTES)
            .map_err(|_| invalid("challenge JSON"))?;
        value.window()?;
        Ok(value)
    }
    pub fn validate(&self, now: i64) -> Result<ChallengeWindow> {
        let w = self.window()?;
        if !(w.issued_at..w.expires_at).contains(&now) {
            return Err(EvidenceError::Time);
        }
        Ok(w)
    }
    pub fn canonical_bytes(&self) -> Result<Vec<u8>> {
        self.window()?;
        bounded_canonical(self, MAX_CHALLENGE_BYTES)
    }
    pub fn hash(&self) -> Result<String> {
        Ok(hash_bytes(&self.canonical_bytes()?))
    }
    fn window(&self) -> Result<ChallengeWindow> {
        if self.schema_version != CHALLENGE_SCHEMA {
            return Err(invalid("challenge purpose"));
        }
        for id in [
            &self.challenge_id,
            &self.org_id,
            &self.project_id,
            &self.target_id,
        ] {
            identifier(id)?;
        }
        for rev in [&self.observer_revision, &self.reference_revision] {
            counter(rev, true)?;
        }
        for n in [&self.authority_epoch, &self.generation] {
            counter(n, false)?;
        }
        for h in [
            &self.observer_key_fingerprint,
            &self.compilation_hash,
            &self.metadata_receipt_hash,
            &self.metadata_report_hash,
            &self.baseline_state_hash,
            &self.artifact_hash,
            &self.installation_hash,
        ] {
            digest(h)?;
        }
        if let Some(h) = &self.expected_head {
            digest(h)?;
        }
        decode_fixed::<32>(&self.nonce)?;
        let issued_at = parse_time(&self.issued_at).map_err(|_| invalid("issued time"))?;
        let expires_at = parse_time(&self.expires_at).map_err(|_| invalid("expiry time"))?;
        if expires_at <= issued_at || expires_at - issued_at > MAX_LIFETIME_SECONDS {
            return Err(invalid("challenge interval"));
        }
        Ok(ChallengeWindow {
            issued_at,
            expires_at,
        })
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NativeObservationPayload {
    pub schema_version: String,
    pub production_qualified: bool,
    pub installation: Installation,
    pub observation: ObservationContext,
    pub readback: Value,
}
impl NativeObservationPayload {
    pub fn parse(bytes: &[u8]) -> Result<Self> {
        let p: Self = parse_strict_with_limit(bytes, MAX_PAYLOAD_BYTES)
            .map_err(|_| invalid("payload JSON"))?;
        p.shape()?;
        if p.canonical_bytes()?.as_slice() != bytes {
            return Err(invalid("noncanonical payload"));
        }
        Ok(p)
    }
    pub fn canonical_bytes(&self) -> Result<Vec<u8>> {
        self.shape()?;
        bounded_canonical(self, MAX_PAYLOAD_BYTES)
    }
    fn shape(&self) -> Result<()> {
        if self.schema_version != PAYLOAD_SCHEMA || self.production_qualified {
            return Err(invalid("unqualified observation purpose"));
        }
        value_depth(&self.readback)?;
        value_depth(&self.installation.native.nft_json)?;
        identifier(&self.observation.boot_id)?;
        identifier(&self.installation.manifest.binding.boot_id)?;
        timestamp(self.observation.wall_time_unix).map_err(|_| invalid("observation time"))?;
        namespace(&self.observation.network_namespace)?;
        namespace(&self.installation.manifest.binding.network_namespace)?;
        Ok(())
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SignedNativeObservation {
    pub schema_version: String,
    pub challenge: NativeObservationChallenge,
    pub payload_base64: String,
    pub signature: String,
}
impl SignedNativeObservation {
    pub fn parse(bytes: &[u8]) -> Result<Self> {
        let value: Self =
            parse_strict_with_limit(bytes, MAX_PROOF_BYTES).map_err(|_| invalid("proof JSON"))?;
        value.shape()?;
        Ok(value)
    }
    pub fn canonical_bytes(&self) -> Result<Vec<u8>> {
        self.shape()?;
        bounded_canonical(self, MAX_PROOF_BYTES)
    }
    fn shape(&self) -> Result<()> {
        if self.schema_version != PROOF_SCHEMA {
            return Err(invalid("proof purpose"));
        }
        self.challenge.window()?;
        decode_fixed::<64>(&self.signature)?;
        decode_payload(&self.payload_base64)?;
        Ok(())
    }
}

pub struct VerifiedObservation {
    payload: Vec<u8>,
    payload_hash: String,
    challenge_hash: String,
    comparison: Comparison,
    observed_state_hash: Option<String>,
    readback_hash: String,
    checked_at: i64,
    valid_until: i64,
    reason_code: Option<&'static str>,
}
impl VerifiedObservation {
    pub fn payload_bytes(&self) -> &[u8] {
        &self.payload
    }
    pub fn payload_hash(&self) -> &str {
        &self.payload_hash
    }
    pub fn challenge_hash(&self) -> &str {
        &self.challenge_hash
    }
    pub fn comparison(&self) -> Comparison {
        self.comparison
    }
    pub fn observed_state_hash(&self) -> Option<&str> {
        self.observed_state_hash.as_deref()
    }
    pub fn readback_hash(&self) -> &str {
        &self.readback_hash
    }
    pub fn checked_at(&self) -> i64 {
        self.checked_at
    }
    pub fn valid_until(&self) -> i64 {
        self.valid_until
    }
    pub fn reason_code(&self) -> Option<&'static str> {
        self.reason_code
    }
}

/// The producer must authenticate the challenge and collect actual bytes using
/// its own scoped lab observer key. Signing this payload does not attest its truth.
pub fn sign_observation(
    challenge: &NativeObservationChallenge,
    payload: &NativeObservationPayload,
    seed: &[u8; 32],
    now: i64,
) -> Result<SignedNativeObservation> {
    let window = challenge.validate(now)?;
    let bytes = payload.canonical_bytes()?;
    payload_binding(challenge, payload, window, now)?;
    let key = SigningKey::from_bytes(seed);
    if fingerprint(key.verifying_key().as_bytes()).map_err(|_| EvidenceError::Signature)?
        != challenge.observer_key_fingerprint
    {
        return Err(EvidenceError::Signature);
    }
    let signature = key.sign(&signing_message(challenge, &bytes)?);
    Ok(SignedNativeObservation {
        schema_version: PROOF_SCHEMA.into(),
        challenge: challenge.clone(),
        payload_base64: URL_SAFE_NO_PAD.encode(bytes),
        signature: URL_SAFE_NO_PAD.encode(signature.to_bytes()),
    })
}

/// Resolve challenge/key/artifact from independently retained authority context.
/// Current pin/reference/metadata/head checks and one-use consumption are store
/// responsibilities, never inferred from a supplied challenge or this result.
pub fn verify_observation(
    expected: &NativeObservationChallenge,
    proof: &SignedNativeObservation,
    public_key: &[u8; 32],
    artifact: &PortableArtifact,
    now: i64,
    trust_not_after: i64,
) -> Result<VerifiedObservation> {
    let window = expected.validate(now)?;
    timestamp(trust_not_after).map_err(|_| EvidenceError::Time)?;
    if now >= trust_not_after {
        return Err(EvidenceError::Time);
    }
    if proof.schema_version != PROOF_SCHEMA || proof.challenge != *expected {
        return Err(invalid("proof challenge binding"));
    }
    if fingerprint(public_key).map_err(|_| EvidenceError::Signature)?
        != expected.observer_key_fingerprint
    {
        return Err(EvidenceError::Signature);
    }
    let bytes = decode_payload(&proof.payload_base64)?;
    let key = VerifyingKey::from_bytes(public_key).map_err(|_| EvidenceError::Signature)?;
    let signature = Signature::from_bytes(&decode_fixed::<64>(&proof.signature)?);
    key.verify_strict(&signing_message(expected, &bytes)?, &signature)
        .map_err(|_| EvidenceError::Signature)?;
    let payload = NativeObservationPayload::parse(&bytes)?;
    payload_binding(expected, &payload, window, now)?;
    value_depth(&artifact.nft_template)?;
    bounded_canonical(artifact, MAX_COMPILATION_BYTES)?;
    if artifact
        .artifact_hash()
        .map_err(|_| invalid("artifact hash"))?
        != expected.artifact_hash
        || artifact.references.scope.org_id != expected.org_id
        || artifact.references.scope.project_id != expected.project_id
        || artifact.references.scope.target_id != expected.target_id
        || (expected.artifact_role == ArtifactRole::Baseline
            && artifact.desired_state_hash != expected.baseline_state_hash)
    {
        return Err(invalid("compiled artifact binding"));
    }
    validate_installation(artifact, &payload.installation)
        .map_err(|_| invalid("installation binding"))?;
    let result = verify_installation_readback_at(
        artifact,
        &payload.installation,
        &payload.readback,
        &payload.observation,
    );
    let observed_state_hash = if result.comparison == Comparison::Match {
        result.observed_semantic_hash
    } else {
        None
    };
    Ok(VerifiedObservation {
        payload_hash: hash_bytes(&bytes),
        challenge_hash: expected.hash()?,
        comparison: result.comparison,
        observed_state_hash,
        readback_hash: canonical_hash(&payload.readback).map_err(|_| invalid("readback hash"))?,
        checked_at: payload.observation.wall_time_unix,
        valid_until: window.expires_at.min(trust_not_after),
        reason_code: result.reason_code,
        payload: bytes,
    })
}

fn payload_binding(
    c: &NativeObservationChallenge,
    p: &NativeObservationPayload,
    w: ChallengeWindow,
    now: i64,
) -> Result<()> {
    if canonical_hash(&p.installation).map_err(|_| invalid("installation hash"))?
        != c.installation_hash
        || p.installation.manifest.portable_artifact_hash != c.artifact_hash
    {
        return Err(invalid("expected installation"));
    }
    if p.observation.wall_time_unix < w.issued_at || p.observation.wall_time_unix > now {
        return Err(EvidenceError::Time);
    }
    Ok(())
}
fn signing_message(c: &NativeObservationChallenge, payload: &[u8]) -> Result<Vec<u8>> {
    let body=canonical_bytes(&json!({"schema_version":PROOF_SCHEMA,"challenge":c,"challenge_hash":c.hash()?,"payload_hash":hash_bytes(payload),"payload_size":payload.len()})).map_err(|_|invalid("signature payload"))?;
    let mut bytes = Vec::with_capacity(SIGNATURE_DOMAIN.len() + body.len());
    bytes.extend_from_slice(SIGNATURE_DOMAIN);
    bytes.extend_from_slice(&body);
    Ok(bytes)
}
fn invalid(s: &'static str) -> EvidenceError {
    EvidenceError::Invalid(s)
}
fn identifier(s: &str) -> Result<()> {
    if s.len() != 36 || !uuid::Uuid::parse_str(s).is_ok_and(|u| u.to_string() == s) {
        return Err(invalid("identity"));
    }
    Ok(())
}
fn digest(s: &str) -> Result<()> {
    if s.len() != 71
        || !s.starts_with("sha256:")
        || !s[7..]
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    {
        return Err(invalid("digest"));
    }
    Ok(())
}
fn counter(s: &str, positive: bool) -> Result<()> {
    if s.len() > 20 || Counter::parse(s).is_err() || (positive && s == "0") {
        return Err(invalid("counter"));
    }
    Ok(())
}
fn namespace(s: &str) -> Result<()> {
    if !s
        .strip_prefix("net:[")
        .and_then(|s| s.strip_suffix(']'))
        .is_some_and(|n| {
            n.len() <= 20 && n.parse::<u64>().is_ok_and(|v| v > 0 && v.to_string() == n)
        })
    {
        return Err(invalid("namespace"));
    }
    Ok(())
}
fn decode_fixed<const N: usize>(s: &str) -> Result<[u8; N]> {
    if s.len() != (N * 8).div_ceil(6) {
        return Err(invalid("base64 length"));
    }
    let b = URL_SAFE_NO_PAD.decode(s).map_err(|_| invalid("base64"))?;
    if URL_SAFE_NO_PAD.encode(&b) != s {
        return Err(invalid("canonical base64"));
    }
    b.try_into().map_err(|_| invalid("base64 size"))
}
fn decode_payload(s: &str) -> Result<Vec<u8>> {
    if s.is_empty() || s.len() > (MAX_PAYLOAD_BYTES * 8).div_ceil(6) {
        return Err(invalid("payload size"));
    }
    let b = URL_SAFE_NO_PAD
        .decode(s)
        .map_err(|_| invalid("payload base64"))?;
    if b.len() > MAX_PAYLOAD_BYTES || URL_SAFE_NO_PAD.encode(&b) != s {
        return Err(invalid("payload encoding"));
    }
    Ok(b)
}
fn value_depth(root: &Value) -> Result<()> {
    fn visit(v: &Value, d: usize, remaining: &mut usize) -> Result<()> {
        if d >= fw_contracts::MAX_DEPTH || *remaining == 0 {
            return Err(invalid("JSON depth or nodes"));
        }
        *remaining -= 1;
        match v {
            Value::Array(a) => {
                for child in a {
                    visit(child, d + 1, remaining)?;
                }
            }
            Value::Object(o) => {
                for child in o.values() {
                    visit(child, d + 1, remaining)?;
                }
            }
            _ => {}
        }
        Ok(())
    }
    let mut remaining = MAX_PAYLOAD_BYTES;
    visit(root, 0, &mut remaining)
}
fn bounded_canonical<T: Serialize>(value: &T, max: usize) -> Result<Vec<u8>> {
    struct Bounded {
        bytes: Vec<u8>,
        max: usize,
    }
    impl std::io::Write for Bounded {
        fn write(&mut self, b: &[u8]) -> std::io::Result<usize> {
            if b.len() > self.max.saturating_sub(self.bytes.len()) {
                return Err(std::io::Error::other("size"));
            }
            self.bytes.extend_from_slice(b);
            Ok(b.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }
    let mut w = Bounded {
        bytes: Vec::new(),
        max,
    };
    serde_json::to_writer(&mut w, value).map_err(|_| invalid("serialized size"))?;
    let parsed: Value =
        parse_strict_with_limit(&w.bytes, max).map_err(|_| invalid("closed canonical profile"))?;
    let bytes = canonical_bytes(&parsed).map_err(|_| invalid("canonical bytes"))?;
    if bytes.len() > max {
        return Err(invalid("canonical size"));
    }
    Ok(bytes)
}
