//! Portable challenge-bound metadata, never policy signing or native authority.
use crate::*;
use fw_target_evidence::{TargetMetadataChallenge, sign_report};
use openssl::pkey::{Id, PKey};

pub(super) fn sign(
    state: &Directory,
    controller: &str,
    ca: &str,
    trust_hash: &str,
    challenge_path: &Path,
    output_path: &Path,
) -> Result<Value> {
    let now = Utc::now().timestamp();
    let identity = read_identity(state).map_err(|_| "METADATA_DEVICE_IDENTITY_INVALID")?;
    let saved: Enrolled = parse(
        &state
            .read("enrollment.json")
            .map_err(|_| "METADATA_ENROLLMENT_UNAVAILABLE")?,
    )
    .map_err(|_| "METADATA_ENROLLMENT_INVALID")?;
    validate_saved(&saved, &identity, ca, controller, trust_hash, now)
        .map_err(|_| "METADATA_ENROLLMENT_INVALID")?;
    let target = fw_enrollment::verify_enrollment_response(
        &saved.response,
        &identity,
        ca,
        &saved.response.target_id,
        now,
    )
    .map_err(|_| "METADATA_CERTIFICATE_INVALID")?;

    let challenge_bytes =
        files::read_path(challenge_path, true).map_err(|_| "METADATA_CHALLENGE_FILE_INVALID")?;
    if challenge_bytes.len() > fw_target_evidence::MAX_CHALLENGE_BYTES {
        return Err("METADATA_CHALLENGE_INVALID".into());
    }
    let challenge: TargetMetadataChallenge =
        parse(&challenge_bytes).map_err(|_| "METADATA_CHALLENGE_INVALID")?;
    challenge
        .validate(now)
        .map_err(|_| "METADATA_CHALLENGE_INVALID")?;
    if challenge.org_id != target.org_id
        || challenge.project_id != target.project_id
        || challenge.target_id != target.target_id
        || challenge.key_fingerprint != target.key_fingerprint
        || challenge.certificate_fingerprint != target.certificate_fingerprint
    {
        return Err("METADATA_CHALLENGE_IDENTITY_MISMATCH".into());
    }
    // Validate the destination before collecting state or using the private key.
    // Directory writes atomically publish a new file and refuse every alias.
    let parent = output_path
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    let filename = output_path
        .file_name()
        .and_then(|name| name.to_str())
        .ok_or("METADATA_OUTPUT_INVALID")?;
    let output =
        Directory::open(parent, false, true).map_err(|_| "METADATA_OUTPUT_DIRECTORY_INVALID")?;
    if output
        .read_optional(filename, true)
        .map_err(|_| "METADATA_OUTPUT_INVALID")?
        .is_some()
    {
        return Err("METADATA_OUTPUT_EXISTS".into());
    }

    let version = std::fs::read_to_string("/proc/sys/kernel/osrelease")
        .map_err(|_| "METADATA_KERNEL_UNAVAILABLE")?;
    let version = version.trim();
    if version.is_empty() || version.len() > 128 {
        return Err("METADATA_KERNEL_INVALID".into());
    }
    let backend = backend_version();
    let build_hash = binary_hash().map_err(|_| "METADATA_BUILD_UNAVAILABLE")?;
    // Measurements may take time. Recheck exclusive certificate/challenge
    // deadlines at signing rather than extending the original request window.
    let signed_at = Utc::now().timestamp();
    if signed_at < now {
        return Err("METADATA_CLOCK_UNCERTAIN".into());
    }
    validate_saved(&saved, &identity, ca, controller, trust_hash, signed_at)
        .map_err(|_| "METADATA_ENROLLMENT_INVALID")?;
    let report = capability(&target.target_id, signed_at, version, &backend, &build_hash)
        .map_err(|_| "METADATA_REPORT_INVALID")?;
    let report_bytes =
        fw_contracts::canonical_bytes(&report).map_err(|_| "METADATA_REPORT_INVALID")?;
    let private = PKey::private_key_from_pem(identity.private_key_pem.as_bytes())
        .map_err(|_| "METADATA_DEVICE_IDENTITY_INVALID")?;
    if private.id() != Id::ED25519 {
        return Err("METADATA_DEVICE_IDENTITY_INVALID".into());
    }
    let mut seed: [u8; 32] = private
        .raw_private_key()
        .map_err(|_| "METADATA_DEVICE_IDENTITY_INVALID")?
        .try_into()
        .map_err(|_| "METADATA_DEVICE_IDENTITY_INVALID")?;
    let proof = sign_report(&challenge, &report_bytes, &seed, signed_at);
    // Best-effort clear of this temporary copy; OpenSSL owns the loaded key.
    seed.fill(0);
    let proof = proof.map_err(|_| "METADATA_SIGNING_REJECTED")?;
    let proof_bytes = proof
        .canonical_bytes()
        .map_err(|_| "METADATA_PROOF_INVALID")?;
    if proof_bytes.len() > files::LIMIT {
        return Err("METADATA_PROOF_STORAGE_LIMIT".into());
    }
    output
        .write(filename, &proof_bytes, false)
        .map_err(|_| "METADATA_OUTPUT_WRITE_FAILED")?;
    Ok(json!({
        "schema_version":"fw.target-metadata-export/v1",
        "target_id":target.target_id,
        "challenge_id":challenge.challenge_id,
        "report_hash":fw_contracts::hash_bytes(&report_bytes),
        "proof_hash":fw_contracts::hash_bytes(&proof_bytes),
        "state":"signed_metadata_not_admitted",
        "enforcement":false
    }))
}
