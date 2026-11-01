//! Read-only capture of actual native state for a purpose-scoped lab observer.
//! Supplied artifact/installation bytes declare the expected correspondence;
//! they do not establish an approved journal operation or install provenance.
use super::{Error, Result, files, hash, native};
use ed25519_dalek::SigningKey;
use fw_backend_linux::{Installation, ObservationContext, PortableArtifact, validate_installation};
use fw_contracts::{MAX_INTERNAL_BYTES, parse_strict_with_limit};
use fw_native_evidence::{
    ArtifactRole, MAX_CHALLENGE_BYTES, MAX_PAYLOAD_BYTES, NativeObservationChallenge,
    NativeObservationPayload, PAYLOAD_SCHEMA, fingerprint, sign_observation,
};
use serde::{Deserialize, de::DeserializeOwned};
use serde_json::{Value, json};
use std::{collections::BTreeMap, path::Path};

const KEY_LIMIT: usize = 4096;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ObserverKey {
    schema_version: String,
    org_id: String,
    project_id: String,
    target_id: String,
    observer_revision: String,
    not_before_unix: i64,
    not_after_unix: i64,
    seed: [u8; 32],
}

fn read<T: DeserializeOwned>(path: &Path, maximum: usize) -> Result<T> {
    let bytes = files::read_bytes(path, maximum)?;
    parse_strict_with_limit(&bytes, maximum).map_err(|_| Error::new("PRIVATE_FILE_JSON"))
}

fn options(arguments: impl Iterator<Item = String>) -> Result<BTreeMap<String, String>> {
    let allowed = [
        "--artifact",
        "--installation",
        "--observer-key",
        "--challenge",
        "--output",
    ];
    let mut arguments = arguments;
    let mut options = BTreeMap::new();
    while let Some(name) = arguments.next() {
        let value = arguments.next().ok_or(Error::new("ARGUMENT_REQUIRED"))?;
        if !allowed.contains(&name.as_str())
            || value.is_empty()
            || options.insert(name, value).is_some()
        {
            return Err(Error::new("ARGUMENT"));
        }
    }
    if options.len() != allowed.len() {
        return Err(Error::new("ARGUMENT_REQUIRED"));
    }
    Ok(options)
}

fn scope(
    challenge: &NativeObservationChallenge,
    artifact: &PortableArtifact,
    installation: &Installation,
    observed: &ObservationContext,
    now: i64,
) -> Result<()> {
    challenge
        .validate(now)
        .map_err(|_| Error::new("NATIVE_EVIDENCE_CHALLENGE"))?;
    artifact.validate()?;
    validate_installation(artifact, installation)?;
    let scope = &artifact.references.scope;
    let binding = &installation.manifest.binding;
    if challenge.org_id != scope.org_id
        || challenge.project_id != scope.project_id
        || challenge.target_id != scope.target_id
        || challenge.artifact_hash != artifact.artifact_hash()?
        || challenge.installation_hash != hash(installation)?
        || (challenge.artifact_role == ArtifactRole::Baseline
            && challenge.baseline_state_hash != artifact.desired_state_hash)
        || artifact.production_qualified
        || scope.network_namespace != observed.network_namespace
        || binding.network_namespace != observed.network_namespace
        || binding.boot_id != observed.boot_id
        || binding.monotonic_millis > observed.monotonic_millis
        || binding.wall_time_unix > observed.wall_time_unix
    {
        return Err(Error::new("NATIVE_EVIDENCE_SCOPE"));
    }
    Ok(())
}

fn key_current(key: &ObserverKey, challenge: &NativeObservationChallenge, now: i64) -> Result<()> {
    let issued = chrono::DateTime::parse_from_rfc3339(&challenge.issued_at)
        .map_err(|_| Error::new("NATIVE_EVIDENCE_CHALLENGE"))?
        .timestamp();
    let expires = chrono::DateTime::parse_from_rfc3339(&challenge.expires_at)
        .map_err(|_| Error::new("NATIVE_EVIDENCE_CHALLENGE"))?
        .timestamp();
    let public = SigningKey::from_bytes(&key.seed).verifying_key().to_bytes();
    let key_fingerprint = fingerprint(&public).map_err(|_| Error::new("OBSERVER_KEY_REJECTED"))?;
    if key.schema_version != "fw.lab-observer-key/v1"
        || key.org_id != challenge.org_id
        || key.project_id != challenge.project_id
        || key.target_id != challenge.target_id
        || key.observer_revision != challenge.observer_revision
        || key_fingerprint != challenge.observer_key_fingerprint
        || now < key.not_before_unix
        || now >= key.not_after_unix
        || issued < key.not_before_unix
        || expires > key.not_after_unix
    {
        return Err(Error::new("OBSERVER_KEY_REJECTED"));
    }
    Ok(())
}

fn capture_window(before: &ObservationContext, after: &ObservationContext) -> Result<()> {
    if before.boot_id != after.boot_id
        || before.network_namespace != after.network_namespace
        || after.wall_time_unix < before.wall_time_unix
        || after
            .monotonic_millis
            .checked_sub(before.monotonic_millis)
            .is_none_or(|n| n > 2500)
    {
        return Err(Error::new("NATIVE_CAPTURE_CLOCK"));
    }
    Ok(())
}

pub(super) fn run(arguments: impl Iterator<Item = String>) -> Result<Value> {
    let args = options(arguments)?;
    let challenge_bytes = files::read_bytes(Path::new(&args["--challenge"]), MAX_CHALLENGE_BYTES)?;
    let challenge = NativeObservationChallenge::parse(&challenge_bytes)
        .map_err(|_| Error::new("NATIVE_EVIDENCE_CHALLENGE"))?;
    let artifact: PortableArtifact = read(Path::new(&args["--artifact"]), MAX_INTERNAL_BYTES)?;
    let installation: Installation = read(Path::new(&args["--installation"]), MAX_PAYLOAD_BYTES)?;
    // Authenticate all declared scope and exact hashes before reading any key.
    let observed = native::guard()?;
    scope(
        &challenge,
        &artifact,
        &installation,
        &observed,
        native::now()?,
    )?;
    let key: ObserverKey = read(Path::new(&args["--observer-key"]), KEY_LIMIT)?;
    key_current(&key, &challenge, native::now()?)?;

    // The only readback source is the fixed nft command, under the same native
    // guard as the disposable executor. No CLI file can supply captured rows.
    let before = native::observation()?;
    let readback = native::readback(&artifact.table)?;
    let after = native::observation()?;
    capture_window(&before, &after)?;
    let now = native::now()?;
    scope(&challenge, &artifact, &installation, &after, now)?;
    key_current(&key, &challenge, now)?;
    let payload = NativeObservationPayload {
        schema_version: PAYLOAD_SCHEMA.into(),
        installation,
        observation: after,
        readback,
        production_qualified: false,
    };
    let proof = sign_observation(&challenge, &payload, &key.seed, now)
        .map_err(|_| Error::new("NATIVE_EVIDENCE_REJECTED"))?;
    files::write(Path::new(&args["--output"]), &proof)?;
    Ok(
        json!({"schema_version":"fw.lab-native-collector-result/v1", "captured":true,
        "proof_hash":hash(&proof)?, "production_qualified":false, "dispatch_allowed":false}),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn collection_options_require_exact_inputs_and_no_caller_readback() {
        let args = [
            "--artifact",
            "a",
            "--installation",
            "i",
            "--observer-key",
            "k",
            "--challenge",
            "c",
            "--output",
            "o",
        ];
        assert_eq!(
            options(args.into_iter().map(String::from)).unwrap().len(),
            5
        );
        for altered in [
            vec!["--artifact", "a"],
            vec!["--artifact", "a", "--artifact", "b"],
            vec!["--readback", "caller-native.json"],
            vec!["--output"],
        ] {
            assert!(options(altered.into_iter().map(String::from)).is_err());
        }
    }

    #[test]
    fn capture_cannot_cross_boot_namespace_rollback_or_unbounded_delay() {
        let before = ObservationContext {
            boot_id: "11111111-1111-4111-8111-111111111111".into(),
            network_namespace: "net:[123]".into(),
            wall_time_unix: 100,
            monotonic_millis: 1000,
        };
        let after = ObservationContext {
            wall_time_unix: 102,
            monotonic_millis: 3000,
            ..before.clone()
        };
        assert!(capture_window(&before, &after).is_ok());
        for after in [
            ObservationContext {
                boot_id: "22222222-2222-4222-8222-222222222222".into(),
                ..after.clone()
            },
            ObservationContext {
                network_namespace: "net:[124]".into(),
                ..after.clone()
            },
            ObservationContext {
                wall_time_unix: 99,
                ..after.clone()
            },
            ObservationContext {
                monotonic_millis: 999,
                ..after.clone()
            },
            ObservationContext {
                monotonic_millis: 3501,
                ..after.clone()
            },
        ] {
            assert!(capture_window(&before, &after).is_err());
        }
    }

    #[test]
    fn observer_key_identity_revision_and_exclusive_window_are_enforced() {
        use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
        use fw_native_evidence::{CHALLENGE_SCHEMA, timestamp};
        let seed = [71; 32];
        let key = ObserverKey {
            schema_version: "fw.lab-observer-key/v1".into(),
            org_id: "11111111-1111-4111-8111-111111111111".into(),
            project_id: "22222222-2222-4222-8222-222222222222".into(),
            target_id: "33333333-3333-4333-8333-333333333333".into(),
            observer_revision: "1".into(),
            not_before_unix: 100,
            not_after_unix: 200,
            seed,
        };
        let h = format!("sha256:{}", "1".repeat(64));
        let challenge = NativeObservationChallenge {
            schema_version: CHALLENGE_SCHEMA.into(),
            challenge_id: "44444444-4444-4444-8444-444444444444".into(),
            org_id: key.org_id.clone(),
            project_id: key.project_id.clone(),
            target_id: key.target_id.clone(),
            observer_revision: "1".into(),
            observer_key_fingerprint: fingerprint(
                SigningKey::from_bytes(&seed).verifying_key().as_bytes(),
            )
            .unwrap(),
            reference_revision: "1".into(),
            compilation_hash: h.clone(),
            metadata_receipt_hash: h.clone(),
            metadata_report_hash: h.clone(),
            baseline_state_hash: h.clone(),
            expected_head: None,
            authority_epoch: "1".into(),
            generation: "0".into(),
            artifact_role: ArtifactRole::Baseline,
            artifact_hash: h.clone(),
            installation_hash: h,
            nonce: URL_SAFE_NO_PAD.encode([4; 32]),
            issued_at: timestamp(100).unwrap(),
            expires_at: timestamp(200).unwrap(),
        };
        assert!(key_current(&key, &challenge, 150).is_ok());
        assert!(key_current(&key, &challenge, 99).is_err());
        assert!(key_current(&key, &challenge, 200).is_err());
        for changed in [
            NativeObservationChallenge {
                org_id: "55555555-5555-4555-8555-555555555555".into(),
                ..challenge.clone()
            },
            NativeObservationChallenge {
                project_id: "55555555-5555-4555-8555-555555555555".into(),
                ..challenge.clone()
            },
            NativeObservationChallenge {
                target_id: "55555555-5555-4555-8555-555555555555".into(),
                ..challenge.clone()
            },
            NativeObservationChallenge {
                observer_revision: "2".into(),
                ..challenge.clone()
            },
            NativeObservationChallenge {
                observer_key_fingerprint: format!("sha256:{}", "2".repeat(64)),
                ..challenge.clone()
            },
            NativeObservationChallenge {
                issued_at: timestamp(99).unwrap(),
                ..challenge.clone()
            },
            NativeObservationChallenge {
                expires_at: timestamp(201).unwrap(),
                ..challenge.clone()
            },
        ] {
            assert!(key_current(&key, &changed, 150).is_err());
        }
    }
}
