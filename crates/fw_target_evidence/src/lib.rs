//! Portable device metadata proofs. A verified report authenticates bytes and
//! freshness against an independently pinned device key; it does not establish
//! native capability qualification, observed firewall state or signing authority.
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use chrono::{DateTime, TimeZone, Utc};
use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use fw_contracts::{Counter, canonical_bytes, hash_bytes, parse_strict_with_limit};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::collections::BTreeSet;

pub const CHALLENGE_SCHEMA: &str = "fw.target-metadata-challenge/v1";
pub const PROOF_SCHEMA: &str = "fw.target-metadata-proof/v1";
pub const MAX_CHALLENGE_BYTES: usize = 4096;
pub const MAX_REPORT_BYTES: usize = 65_536;
pub const MAX_PROOF_BYTES: usize = 131_072;
pub const MAX_LIFETIME_SECONDS: i64 = 300;
const MAX_TIME: i64 = 253_402_300_799;
const SIGNATURE_DOMAIN: &[u8] = b"fw.target-metadata-proof/ed25519/v1\0";

#[derive(Debug, thiserror::Error)]
pub enum EvidenceError {
    #[error("invalid target metadata evidence: {0}")]
    Invalid(&'static str),
    #[error("target metadata evidence is not currently valid")]
    Time,
    #[error("target metadata signature is invalid")]
    Signature,
}
pub type Result<T> = std::result::Result<T, EvidenceError>;

/// This public wire object is not authority merely because it deserializes.
/// The authority retains its exact canonical challenge before exporting it.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct TargetMetadataChallenge {
    pub schema_version: String,
    pub challenge_id: String,
    pub org_id: String,
    pub project_id: String,
    pub target_id: String,
    pub key_revision: String,
    pub key_fingerprint: String,
    pub certificate_fingerprint: String,
    pub nonce: String,
    pub issued_at: String,
    pub expires_at: String,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ChallengeWindow {
    pub issued_at: i64,
    pub expires_at: i64,
}

impl TargetMetadataChallenge {
    pub fn parse(bytes: &[u8]) -> Result<Self> {
        let challenge: Self = parse_strict_with_limit(bytes, MAX_CHALLENGE_BYTES)
            .map_err(|_| invalid("challenge JSON"))?;
        challenge.window()?;
        Ok(challenge)
    }
    /// Validate shape and current admission interval. Expiry is exclusive.
    pub fn validate(&self, now: i64) -> Result<ChallengeWindow> {
        let window = self.window()?;
        if !(window.issued_at..window.expires_at).contains(&now) {
            return Err(EvidenceError::Time);
        }
        Ok(window)
    }
    pub fn canonical_bytes(&self) -> Result<Vec<u8>> {
        self.window()?;
        let bytes = canonical_bytes(self).map_err(|_| invalid("challenge canonical bytes"))?;
        if bytes.len() > MAX_CHALLENGE_BYTES {
            return Err(invalid("challenge size"));
        }
        Ok(bytes)
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
        if self.key_revision.len() > 20
            || Counter::parse(&self.key_revision)
                .map_err(|_| invalid("key revision"))?
                .0
                == 0
        {
            return Err(invalid("key revision"));
        }
        digest(&self.key_fingerprint)?;
        digest(&self.certificate_fingerprint)?;
        decode_fixed::<32>(&self.nonce)?;
        let issued_at = parse_time(&self.issued_at)?;
        let expires_at = parse_time(&self.expires_at)?;
        if expires_at <= issued_at || expires_at - issued_at > MAX_LIFETIME_SECONDS {
            return Err(invalid("challenge interval"));
        }
        Ok(ChallengeWindow {
            issued_at,
            expires_at,
        })
    }
}

/// The report is encoded so its exact canonical bytes survive transport.
/// Possession of a proof does not bypass the authority's one-use challenge,
/// current pin/certificate validity or revocation checks.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SignedMetadataReport {
    pub schema_version: String,
    pub challenge: TargetMetadataChallenge,
    pub report_base64: String,
    pub signature: String,
}
impl SignedMetadataReport {
    pub fn parse(bytes: &[u8]) -> Result<Self> {
        let proof: Self =
            parse_strict_with_limit(bytes, MAX_PROOF_BYTES).map_err(|_| invalid("proof JSON"))?;
        proof.shape()?;
        Ok(proof)
    }
    pub fn canonical_bytes(&self) -> Result<Vec<u8>> {
        self.shape()?;
        let bytes = canonical_bytes(self).map_err(|_| invalid("proof canonical bytes"))?;
        if bytes.len() > MAX_PROOF_BYTES {
            return Err(invalid("proof size"));
        }
        Ok(bytes)
    }
    fn shape(&self) -> Result<()> {
        if self.schema_version != PROOF_SCHEMA {
            return Err(invalid("proof purpose"));
        }
        self.challenge.window()?;
        decode_fixed::<64>(&self.signature)?;
        decode_report(&self.report_base64)?;
        Ok(())
    }
}

/// Only a successful strict signature and report verification creates this
/// value. Retained receipts must separately recheck the current trust pin and
/// effective deadline; verification at an old admission time is not fresh trust.
pub struct VerifiedMetadataReport {
    report: Vec<u8>,
    report_hash: String,
    challenge_hash: String,
    checked_at: i64,
    report_valid_until: i64,
    valid_until: i64,
}
impl VerifiedMetadataReport {
    pub fn report_bytes(&self) -> &[u8] {
        &self.report
    }
    pub fn report_hash(&self) -> &str {
        &self.report_hash
    }
    pub fn challenge_hash(&self) -> &str {
        &self.challenge_hash
    }
    pub fn checked_at(&self) -> i64 {
        self.checked_at
    }
    pub fn report_valid_until(&self) -> i64 {
        self.report_valid_until
    }
    pub fn valid_until(&self) -> i64 {
        self.valid_until
    }
}

/// The caller must authenticate the challenge's authority and compare every
/// identity binding with the locally verified enrollment before invoking this.
/// This function checks the signing key fingerprint and report semantics, but
/// has no certificate chain, revocation registry or authority-admin trust root.
pub fn sign_report(
    challenge: &TargetMetadataChallenge,
    report_bytes: &[u8],
    seed: &[u8; 32],
    now: i64,
) -> Result<SignedMetadataReport> {
    let window = challenge.validate(now)?;
    let report = parse_report(report_bytes)?;
    let platform = string(&report, "platform")?;
    validate_capability(
        &report,
        &challenge.target_id,
        platform,
        now,
        window.issued_at,
    )?;
    let key = SigningKey::from_bytes(seed);
    if fingerprint(key.verifying_key().as_bytes())? != challenge.key_fingerprint {
        return Err(EvidenceError::Signature);
    }
    let signature = key.sign(&signing_message(challenge, report_bytes)?);
    Ok(SignedMetadataReport {
        schema_version: PROOF_SCHEMA.into(),
        challenge: challenge.clone(),
        report_base64: URL_SAFE_NO_PAD.encode(report_bytes),
        signature: URL_SAFE_NO_PAD.encode(signature.to_bytes()),
    })
}

/// `expected_challenge` and public key must be resolved from independently
/// protected authority records. The caller checks current pin revision,
/// certificate fingerprint, validity/revocation and atomically consumes the
/// challenge. A client-supplied copy is not that authority context.
pub fn verify_report(
    expected_challenge: &TargetMetadataChallenge,
    proof: &SignedMetadataReport,
    public_key: &[u8; 32],
    expected_platform: &str,
    now: i64,
    trust_not_after: i64,
) -> Result<VerifiedMetadataReport> {
    let window = expected_challenge.validate(now)?;
    if proof.schema_version != PROOF_SCHEMA || proof.challenge != *expected_challenge {
        return Err(invalid("proof challenge binding"));
    }
    if trust_not_after <= now || trust_not_after > MAX_TIME {
        return Err(EvidenceError::Time);
    }
    if fingerprint(public_key)? != expected_challenge.key_fingerprint {
        return Err(EvidenceError::Signature);
    }
    let key = verification_key(public_key)?;
    let bytes = decode_report(&proof.report_base64)?;
    let signature = Signature::from_bytes(&decode_fixed::<64>(&proof.signature)?);
    key.verify_strict(&signing_message(expected_challenge, &bytes)?, &signature)
        .map_err(|_| EvidenceError::Signature)?;
    let report = parse_report(&bytes)?;
    let (checked_at, report_valid_until) = validate_capability(
        &report,
        &expected_challenge.target_id,
        expected_platform,
        now,
        window.issued_at,
    )?;
    Ok(VerifiedMetadataReport {
        report_hash: hash_bytes(&bytes),
        challenge_hash: expected_challenge.hash()?,
        checked_at,
        report_valid_until,
        valid_until: report_valid_until
            .min(window.expires_at)
            .min(trust_not_after),
        report: bytes,
    })
}

fn signing_message(challenge: &TargetMetadataChallenge, report: &[u8]) -> Result<Vec<u8>> {
    let challenge_hash = challenge.hash()?;
    let body = canonical_bytes(&json!({
        "schema_version": PROOF_SCHEMA,
        "challenge": challenge,
        "challenge_hash": challenge_hash,
        "report_hash": hash_bytes(report),
        "report_size": report.len()
    }))
    .map_err(|_| invalid("signature payload"))?;
    let mut message = Vec::with_capacity(SIGNATURE_DOMAIN.len() + body.len());
    message.extend_from_slice(SIGNATURE_DOMAIN);
    message.extend_from_slice(&body);
    Ok(message)
}

/// SHA-256 of canonical Ed25519 SubjectPublicKeyInfo DER, identical to the
/// existing enrollment fingerprint (not a digest of the raw 32 bytes).
pub fn fingerprint(public_key: &[u8; 32]) -> Result<String> {
    verification_key(public_key)?;
    const ED25519_SPKI_PREFIX: &[u8] = &[
        0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x03, 0x21, 0x00,
    ];
    let mut der = Vec::with_capacity(44);
    der.extend_from_slice(ED25519_SPKI_PREFIX);
    der.extend_from_slice(public_key);
    Ok(hash_bytes(&der))
}
fn verification_key(bytes: &[u8; 32]) -> Result<VerifyingKey> {
    // Reject alternate compressed field encodings even if a curve decoder
    // would reduce y modulo p. The sign bit is separate from the y coordinate.
    let mut y = *bytes;
    y[31] &= 0x7f;
    let mut modulus = [0xff; 32];
    modulus[0] = 0xed;
    modulus[31] = 0x7f;
    if y.iter().rev().cmp(modulus.iter().rev()) != std::cmp::Ordering::Less {
        return Err(EvidenceError::Signature);
    }
    let key = VerifyingKey::from_bytes(bytes).map_err(|_| EvidenceError::Signature)?;
    if key.is_weak() {
        return Err(EvidenceError::Signature);
    }
    Ok(key)
}

pub fn parse_time(value: &str) -> Result<i64> {
    if value.len() != 20 {
        return Err(invalid("timestamp"));
    }
    let at = DateTime::parse_from_rfc3339(value)
        .map_err(|_| invalid("timestamp"))?
        .timestamp();
    if timestamp(at)? != value {
        return Err(invalid("canonical UTC timestamp"));
    }
    Ok(at)
}
pub fn timestamp(at: i64) -> Result<String> {
    if !(0..=MAX_TIME).contains(&at) {
        return Err(invalid("timestamp range"));
    }
    Ok(Utc
        .timestamp_opt(at, 0)
        .single()
        .ok_or(invalid("timestamp"))?
        .format("%Y-%m-%dT%H:%M:%SZ")
        .to_string())
}
fn invalid(detail: &'static str) -> EvidenceError {
    EvidenceError::Invalid(detail)
}
fn identifier(value: &str) -> Result<()> {
    if value.len() != 36 || !uuid::Uuid::parse_str(value).is_ok_and(|id| id.to_string() == value) {
        return Err(invalid("identity"));
    }
    Ok(())
}
fn digest(value: &str) -> Result<()> {
    if value.len() != 71
        || !value.starts_with("sha256:")
        || !value[7..]
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    {
        return Err(invalid("digest"));
    }
    Ok(())
}
fn decode_fixed<const N: usize>(value: &str) -> Result<[u8; N]> {
    if value.len() != (N * 8).div_ceil(6) {
        return Err(invalid("base64 length"));
    }
    let bytes = URL_SAFE_NO_PAD
        .decode(value)
        .map_err(|_| invalid("base64"))?;
    if URL_SAFE_NO_PAD.encode(&bytes) != value {
        return Err(invalid("canonical base64"));
    }
    bytes.try_into().map_err(|_| invalid("base64 size"))
}
fn decode_report(value: &str) -> Result<Vec<u8>> {
    if value.is_empty() || value.len() > (MAX_REPORT_BYTES * 8).div_ceil(6) {
        return Err(invalid("report size"));
    }
    let bytes = URL_SAFE_NO_PAD
        .decode(value)
        .map_err(|_| invalid("report base64"))?;
    if bytes.len() > MAX_REPORT_BYTES || URL_SAFE_NO_PAD.encode(&bytes) != value {
        return Err(invalid("canonical report base64"));
    }
    Ok(bytes)
}
fn parse_report(bytes: &[u8]) -> Result<Value> {
    let report: Value =
        parse_strict_with_limit(bytes, MAX_REPORT_BYTES).map_err(|_| invalid("report JSON"))?;
    if canonical_bytes(&report).map_err(|_| invalid("report canonical bytes"))? != bytes {
        return Err(invalid("noncanonical report bytes"));
    }
    Ok(report)
}
fn string<'a>(value: &'a Value, key: &str) -> Result<&'a str> {
    value
        .get(key)
        .and_then(Value::as_str)
        .ok_or(invalid("string field"))
}
fn closed(value: &Value, keys: &[&str]) -> Result<()> {
    let map = value.as_object().ok_or(invalid("object"))?;
    if map.len() != keys.len() || keys.iter().any(|key| !map.contains_key(*key)) {
        return Err(invalid("closed fields"));
    }
    Ok(())
}
fn text(value: &str, max: usize) -> Result<()> {
    if value.trim().is_empty() || value.len() > max || value.chars().any(char::is_control) {
        return Err(invalid("text"));
    }
    Ok(())
}
fn string_set(value: &Value, allowed: &[&str], max: usize) -> Result<()> {
    let array = value.as_array().ok_or(invalid("set"))?;
    let mut seen = BTreeSet::new();
    if array.len() > max {
        return Err(invalid("set size"));
    }
    for item in array {
        let item = item.as_str().ok_or(invalid("set item"))?;
        if !allowed.contains(&item) || !seen.insert(item) {
            return Err(invalid("set item"));
        }
    }
    Ok(())
}

fn validate_capability(
    report: &Value,
    target: &str,
    platform: &str,
    now: i64,
    challenge_issued: i64,
) -> Result<(i64, i64)> {
    closed(
        report,
        &[
            "schema_version",
            "target_id",
            "platform",
            "enforcement_backend",
            "capability_version",
            "os_version",
            "backend_version",
            "executor_build_hash",
            "checked_at",
            "valid_until",
            "profiles",
            "families",
            "directions",
            "protocols",
            "binding_kinds",
            "features",
            "max_policies",
            "max_rules",
            "max_artifact_bytes",
            "qualification_profiles",
            "interfaces",
        ],
    )?;
    let backend = match platform {
        "linux" => "nftables",
        "windows" => "windows_wfp",
        "macos" => "macos_network_extension",
        _ => return Err(invalid("platform")),
    };
    if report["schema_version"] != "f.target-capability/v1"
        || report["capability_version"] != "f.target-capability/v1"
        || report["target_id"] != target
        || report["platform"] != platform
        || report["enforcement_backend"] != backend
    {
        return Err(invalid("report identity"));
    }
    text(string(report, "os_version")?, 128)?;
    text(string(report, "backend_version")?, 128)?;
    digest(string(report, "executor_build_hash")?)?;
    let checked = parse_time(string(report, "checked_at")?)?;
    let until = parse_time(string(report, "valid_until")?)?;
    if checked < challenge_issued
        || checked > now
        || until <= now
        || until <= checked
        || until - checked > MAX_LIFETIME_SECONDS
    {
        return Err(EvidenceError::Time);
    }
    string_set(&report["profiles"], &[], 0)?;
    string_set(&report["qualification_profiles"], &[], 0)?;
    string_set(&report["families"], &["ipv4", "ipv6"], 2)?;
    string_set(&report["directions"], &["input", "output"], 2)?;
    string_set(&report["protocols"], &["tcp", "udp", "icmp", "icmpv6"], 4)?;
    let kinds: &[&str] = match platform {
        "linux" => &["host", "vm", "network_namespace"],
        "windows" => &["host", "vm", "windows_app_identity"],
        _ => &["macos_host"],
    };
    string_set(&report["binding_kinds"], kinds, 5)?;
    let features = [
        "timed_allow",
        "persistent_deny",
        "strict_current_union",
        "atomic_apply",
        "semantic_readback",
        "writer_fencing",
        "independent_watchdog",
        "new_management_probe",
        "interface_scope",
        "process_binding",
        "independent_expiry",
        "boot_guard",
        "crash_fail_closed",
        "absolute_deadline_guard",
    ];
    closed(&report["features"], &features)?;
    for name in features {
        let feature = &report["features"][name];
        closed(feature, &["state", "reason_code", "evidence_hash"])?;
        if feature["state"] != "unverified" && feature["state"] != "unsupported" {
            return Err(invalid("unqualified enforcement claim"));
        }
        let reason = string(feature, "reason_code")?;
        if reason.is_empty()
            || reason.len() > 64
            || !reason.as_bytes()[0].is_ascii_uppercase()
            || !reason
                .bytes()
                .all(|b| b.is_ascii_uppercase() || b.is_ascii_digit() || b == b'_')
        {
            return Err(invalid("feature reason"));
        }
        if !feature["evidence_hash"].is_null() {
            digest(string(feature, "evidence_hash")?)?;
        }
    }
    for (name, max) in [
        ("max_policies", 4096),
        ("max_rules", 100000),
        ("max_artifact_bytes", 16777216),
    ] {
        if !report[name]
            .as_u64()
            .is_some_and(|n| (1..=max).contains(&n))
        {
            return Err(invalid("metadata limit"));
        }
    }
    let interfaces = report["interfaces"]
        .as_array()
        .ok_or(invalid("interfaces"))?;
    if interfaces.len() > 64 {
        return Err(invalid("interface limit"));
    }
    let mut seen = BTreeSet::new();
    for interface in interfaces {
        closed(
            interface,
            &[
                "logical_name",
                "native_id",
                "native_identity_hash",
                "direction",
                "present",
            ],
        )?;
        let name = string(interface, "logical_name")?;
        let direction = string(interface, "direction")?;
        if name.is_empty()
            || name.len() > 15
            || !name
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b"_.:-".contains(&b))
            || !["input", "output"].contains(&direction)
            || !seen.insert((name, direction))
        {
            return Err(invalid("interface identity"));
        }
        text(string(interface, "native_id")?, 256)?;
        digest(string(interface, "native_identity_hash")?)?;
        if !interface["present"].is_boolean() {
            return Err(invalid("interface presence"));
        }
    }
    Ok((checked, until))
}
