//! Synthetic test inputs for the isolated native evidence smoke. This helper
//! writes no authority database, signs no policy and performs no native action.
#[cfg(unix)]
mod fixture {
    use ed25519_dalek::SigningKey;
    use fw_backend_linux::{
        Installation, PortableArtifact, compile_portable, restrictive_recovery,
    };
    use fw_contracts::{canonical_bytes, canonical_hash, hash_bytes, parse_strict_with_limit};
    use fw_planner::{PolicyMutation, PolicyReviewEvidence, compose_policy_change};
    use fw_target_evidence::{TargetMetadataChallenge, sign_report, timestamp};
    use serde::Serialize;
    use serde_json::{Value, json};
    use std::{fs, io::Write, path::Path};

    type Result<T> = std::result::Result<T, Box<dyn std::error::Error>>;
    const PLAN: &str = "b1111111-1111-4111-8111-111111111111";
    const PRINCIPAL: &str = "b2222222-2222-4222-8222-222222222222";
    const REQUEST: &str = "b3333333-3333-4333-8333-333333333333";

    fn read<T: serde::de::DeserializeOwned>(path: &Path) -> Result<T> {
        use std::os::unix::fs::MetadataExt;
        let m = fs::symlink_metadata(path)?;
        if !m.is_file() || m.file_type().is_symlink() || m.nlink() != 1 || m.mode() & 0o077 != 0 {
            return Err("private fixture input required".into());
        }
        Ok(parse_strict_with_limit(&fs::read(path)?, 4 * 1024 * 1024)?)
    }
    fn save<T: Serialize>(path: &Path, value: &T) -> Result<()> {
        use std::os::unix::fs::OpenOptionsExt;
        let mut file = fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(path)?;
        file.write_all(&canonical_bytes(value)?)?;
        file.sync_all()?;
        Ok(())
    }
    fn prepare(directory: &Path, bundle_path: &Path) -> Result<()> {
        use std::os::unix::fs::DirBuilderExt;
        let bundle: Value = read(bundle_path)?;
        let baseline: PortableArtifact = serde_json::from_value(bundle["previous"].clone())?;
        let source: PortableArtifact = serde_json::from_value(bundle["candidate"].clone())?;
        let installation: Installation =
            serde_json::from_value(bundle["previous_installation"].clone())?;
        baseline.validate()?;
        source.validate()?;
        fw_backend_linux::validate_installation(&baseline, &installation)?;
        let policy = source
            .state
            .policies
            .iter()
            .find(|p| p.action == fw_domain::Action::Deny)
            .ok_or("fixture deny policy")?
            .clone();
        let policy_hash = canonical_hash(&policy)?;
        let association = source
            .state
            .associations
            .iter()
            .find(|a| a.policy_hash == policy_hash)
            .ok_or("fixture association")?
            .clone();
        let operations = vec![PolicyMutation::AddDeny {
            policy: Box::new(policy),
        }];
        let candidate = compose_policy_change(
            &baseline.state,
            &operations,
            &[association],
            &Default::default(),
        )?;
        let artifact = compile_portable(&candidate.state, &source.references)?;
        let recovery = restrictive_recovery(&baseline, &artifact)?;
        let now = chrono::Utc::now().timestamp();
        let scope = &source.references.scope;
        let fixture_hash =
            hash_bytes(b"synthetic native evidence fixture; not an approved native gate");
        let requirements = json!({"schema_version":"f.approval-requirements/v1","profile":"lab_owner","minimum_humans":1,"required_roles":["owner"],"distinct_principals":true,"author_may_approve":true,"max_approval_age_seconds":3600,"require_webauthn":true,"role_policy_hash":fixture_hash});
        let gates: Vec<Value> = [
            "schema",
            "identity",
            "scope",
            "quota",
            "semantic",
            "expiry",
            "capability",
            "baseline",
        ]
        .into_iter()
        .map(
            |id| json!({"gate_id":id,"required":true,"result":"PASS","evidence_hash":fixture_hash}),
        )
        .collect();
        let plan = json!({
            "schema_version":"f.policy-change-plan/v1","change_kind":"policy_change","plan_id":PLAN,
            "request_id":REQUEST,"request_revision":1,"request_hash":fixture_hash,
            "org_id":scope.org_id,"project_id":scope.project_id,"target_id":scope.target_id,"principal_id":PRINCIPAL,
            "created_at":timestamp(now)?,"valid_until":timestamp(now+3600)?,
            "request_patch_hash":candidate.request_patch_hash,"operations":operations,
            "baseline_hash":candidate.baseline_hash,"desired_state_hash":candidate.desired_state_hash,
            "candidate_state_ref":{"store_id":"native_evidence_fixture","object_hash":candidate.desired_state_hash,"media_type":"application/json","size_bytes":canonical_bytes(&candidate.state)?.len()},
            "source_snapshot_hash":baseline.state.source_snapshot_hash,"target_capability_hash":baseline.state.target_capability_hash,
            "guardrail_hash":fixture_hash,"compiler_hash":fixture_hash,"validator_hash":fixture_hash,
            "artifact_hash":artifact.artifact_hash()?,"validation_report_hash":fixture_hash,
            "effect_summary":{"relation":candidate.relation,"newly_allowed_region_hash":candidate.semantic_diff.newly_allowed_region_hash,"removed_region_hash":candidate.semantic_diff.removed_region_hash,"counterexample_hashes":[],"analysis_profile":"native-union-minus-deny/v1","complete":candidate.semantic_complete},
            "gates":gates,"approval_requirements_hash":canonical_hash(&requirements)?,"probe_spec_hash":fixture_hash,
            "authority_epoch":"1","target_generation":"1","confirm_timeout_seconds":60,
            "rollback_authority":{"profile":"preserve-current-restrictions","scope_bound_hash":canonical_hash(scope)?,"baseline_hash":candidate.baseline_hash,"artifact_hash":recovery.artifact_hash()?,"valid_until":timestamp(now+3600)?},
            "normalization_version":"f.normalize/nfc-v1"
        });
        let evidence = PolicyReviewEvidence {
            before: baseline.state.clone(),
            after: candidate.state,
        };
        evidence.verify(&plan)?;
        fw_native_evidence::compile_evidence(&plan, &evidence, &source.references)?;
        let mut transport = [0_u8; 32];
        let mut observer = [0_u8; 32];
        openssl::rand::rand_bytes(&mut transport)?;
        openssl::rand::rand_bytes(&mut observer)?;
        fs::DirBuilder::new().mode(0o700).create(directory)?;
        save(&directory.join("transport-seed.json"), &transport)?;
        save(
            &directory.join("observer-key.json"),
            &json!({"schema_version":"fw.lab-observer-key/v1","org_id":scope.org_id,"project_id":scope.project_id,"target_id":scope.target_id,"observer_revision":"1","not_before_unix":now-1,"not_after_unix":now+3600,"seed":observer}),
        )?;
        save(
            &directory.join("target-pin.json"),
            &json!({"pin":{"target_id":scope.target_id,"public_key":SigningKey::from_bytes(&transport).verifying_key().to_bytes(),"certificate_fingerprint":hash_bytes(b"synthetic fixture certificate, not actual enrollment"),"platform":"linux","not_before":now-1,"not_after":now+3600},"expected_revision":null}),
        )?;
        save(
            &directory.join("observer-pin.json"),
            &json!({"pin":{"target_id":scope.target_id,"public_key":SigningKey::from_bytes(&observer).verifying_key().to_bytes(),"not_before":now-1,"not_after":now+3600},"expected_revision":null}),
        )?;
        save(
            &directory.join("reference-pin.json"),
            &json!({"pin":{"target_id":scope.target_id,"references":source.references,"not_before":now-1,"not_after":now+3600},"expected_revision":null}),
        )?;
        save(
            &directory.join("reviewed-plan.json"),
            &json!({"plan":plan,"requirements":requirements,"evidence":evidence}),
        )?;
        save(&directory.join("artifact.json"), &baseline)?;
        save(&directory.join("installation.json"), &installation)?;
        save(
            &directory.join("fixture.json"),
            &json!({"org_id":scope.org_id,"project_id":scope.project_id,"target_id":scope.target_id,"plan_id":PLAN,"table":baseline.table,"synthetic_fixture_authority":true,"production_qualified":false,"dispatch_allowed":false}),
        )?;
        Ok(())
    }
    fn metadata(directory: &Path, challenge_path: &Path, output: &Path) -> Result<()> {
        let challenge: TargetMetadataChallenge = read(challenge_path)?;
        let seed: [u8; 32] = read(&directory.join("transport-seed.json"))?;
        let fixture: Value = read(&directory.join("fixture.json"))?;
        if fixture["target_id"] != challenge.target_id
            || fixture["org_id"] != challenge.org_id
            || fixture["project_id"] != challenge.project_id
        {
            return Err("fixture metadata binding".into());
        }
        let now = chrono::Utc::now().timestamp();
        let features = ["timed_allow","persistent_deny","strict_current_union","atomic_apply","semantic_readback","writer_fencing","independent_watchdog","new_management_probe","interface_scope","process_binding","independent_expiry","boot_guard","crash_fail_closed","absolute_deadline_guard"].into_iter()
        .map(|name|(name.to_owned(),json!({"state":"unverified","reason_code":"CAPABILITY_NOT_QUALIFIED","evidence_hash":null}))).collect::<serde_json::Map<_,_>>();
        let report = json!({"schema_version":"f.target-capability/v1","capability_version":"f.target-capability/v1","target_id":challenge.target_id,"platform":"linux","enforcement_backend":"nftables","os_version":"synthetic native evidence fixture","backend_version":"unavailable","executor_build_hash":hash_bytes(b"synthetic fixture executable"),"checked_at":timestamp(now)?,"valid_until":timestamp(now+300)?,"profiles":[],"families":[],"directions":[],"protocols":[],"binding_kinds":[],"features":features,"max_policies":4096,"max_rules":100000,"max_artifact_bytes":16777216,"qualification_profiles":[],"interfaces":[]});
        save(
            output,
            &sign_report(&challenge, &canonical_bytes(&report)?, &seed, now)?,
        )
    }
    fn run() -> Result<()> {
        let args = std::env::args_os()
            .skip(1)
            .map(|s| s.into_string().map_err(|_| "fixture arguments"))
            .collect::<std::result::Result<Vec<_>, _>>()?;
        match args.as_slice() {
            [command, directory, bundle] if command == "prepare" => {
                prepare(Path::new(directory), Path::new(bundle))
            }
            [command, directory, challenge, output] if command == "sign-metadata" => metadata(
                Path::new(directory),
                Path::new(challenge),
                Path::new(output),
            ),
            _ => Err("fixture arguments".into()),
        }
    }
    pub fn main() {
        if run().is_err() {
            eprintln!("NATIVE_EVIDENCE_FIXTURE_FAILED");
            std::process::exit(1);
        }
        println!(
            "{{\"synthetic_fixture_authority\":true,\"production_qualified\":false,\"dispatch_allowed\":false}}"
        );
    }
}

#[cfg(unix)]
fn main() {
    fixture::main();
}
#[cfg(not(unix))]
fn main() {
    eprintln!("NATIVE_EVIDENCE_FIXTURE_UNSUPPORTED");
    std::process::exit(2);
}
