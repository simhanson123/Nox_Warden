//! Synthetic public fixtures with actual device/observer signatures. Never
//! treated as independent native collection or production qualification.
#![allow(dead_code)]
mod authenticator {
    pub const PRINCIPAL: &str = "11111111-1111-4111-8111-111111111111";
}
#[path = "../../../fw_authority_service/tests/support/plans.rs"]
pub mod plans;
use ed25519_dalek::SigningKey;
use fw_authority::{
    AuthorityStore, AuthorityTenant, NativeObserverPin, NativeReferencePin, TargetTransportPin,
};
use fw_backend_linux::*;
use fw_contracts::{canonical_bytes, canonical_hash, hash_bytes};
use fw_native_evidence::{
    ArtifactRole, NativeObservationChallenge, NativeObservationPayload, SignedNativeObservation,
    sign_observation, timestamp,
};
use fw_planner::{PolicyMutation, PolicyReviewEvidence, compose_policy_change};
use serde_json::{Value, json};
use std::collections::BTreeSet;
pub const ORG: &str = plans::ORG;
pub const PROJECT: &str = plans::PROJECT;
pub const TARGET: &str = plans::OTHER;
pub const PLAN: &str = plans::PLAN;
pub const BOOT: &str = "77777777-7777-4777-8777-777777777777";
pub const OBSERVER_SEED: [u8; 32] = [97; 32];
pub const METADATA_SEED: [u8; 32] = [91; 32];

pub fn native_plan(now: i64) -> (Value, Value, PolicyReviewEvidence, LabReferences) {
    let (mut plan, requirements, mut review) = plans::complete_plan(now);
    let scope = LabScope {
        schema_version: "fw.isolated-lab-scope/v1".into(),
        org_id: ORG.into(),
        project_id: PROJECT.into(),
        target_id: TARGET.into(),
        network_namespace: "net:[12345]".into(),
        interfaces: vec!["lo".into()],
        conntrack_zone: 0,
    };
    let scope_hash = canonical_hash(&scope).unwrap();
    let mut policy = serde_json::to_value(&review.before.policies[0]).unwrap();
    policy["log_mode"] = json!("none");
    policy["scope"]["family"] = json!("ipv4");
    policy["scope"]["direction"] = json!("input");
    policy["scope"]["source_cidrs"] = json!(["127.0.0.1/32"]);
    policy["scope"]["destination_cidrs"] = json!(["127.0.0.1/32"]);
    policy["scope"]["ingress_interfaces"] = json!(["lo"]);
    policy["scope"]["egress_interfaces"] = json!([]);
    let mut assets = BTreeSet::new();
    for field in ["source_asset_ids", "destination_asset_ids"] {
        for id in policy["scope"][field].as_array().unwrap() {
            assets.insert(id.as_str().unwrap().to_owned());
        }
    }
    let refs = LabReferences {
        baseline: LabBaseline {
            schema_version: "fw.isolated-lab-baseline/v1".into(),
            scope_hash: scope_hash.clone(),
            management_paths: vec![],
            default_action: "drop".into(),
        },
        source_snapshot: LabSourceSnapshot {
            schema_version: "fw.isolated-lab-snapshot/v1".into(),
            scope_hash: scope_hash.clone(),
            assets: assets
                .into_iter()
                .map(|asset_id| LabAsset {
                    asset_id,
                    cidrs: vec!["127.0.0.1/32".into()],
                })
                .collect(),
        },
        capability: LabCapability {
            schema_version: "fw.isolated-lab-capability/v1".into(),
            scope_hash,
            platform: "linux".into(),
            profile: "host-tcp-udp-lab".into(),
            production_qualified: false,
        },
        scope,
    };
    review.before.policies = vec![serde_json::from_value(policy.clone()).unwrap()];
    review.before.associations[0].policy_hash = canonical_hash(&policy).unwrap();
    review.before.management_baseline_hash = canonical_hash(&refs.baseline).unwrap();
    review.before.source_snapshot_hash = canonical_hash(&refs.source_snapshot).unwrap();
    review.before.target_capability_hash = canonical_hash(&refs.capability).unwrap();
    review.before = review.before.normalized().unwrap();
    plan["operations"] = json!([{"op":"remove_policy","policy_id":policy["policy_id"],"expected_revision":1,"expected_policy_hash":canonical_hash(&policy).unwrap()}]);
    let operations: Vec<PolicyMutation> =
        serde_json::from_value(plan["operations"].clone()).unwrap();
    let candidate =
        compose_policy_change(&review.before, &operations, &[], &BTreeSet::new()).unwrap();
    review.after = candidate.state;
    plan["baseline_hash"] = json!(candidate.baseline_hash);
    plan["desired_state_hash"] = json!(candidate.desired_state_hash);
    plan["request_patch_hash"] = json!(candidate.request_patch_hash);
    plan["source_snapshot_hash"] = json!(review.before.source_snapshot_hash);
    plan["target_capability_hash"] = json!(review.before.target_capability_hash);
    plan["candidate_state_ref"]["object_hash"] = plan["desired_state_hash"].clone();
    plan["candidate_state_ref"]["size_bytes"] =
        json!(canonical_bytes(&review.after).unwrap().len());
    plan["effect_summary"]["relation"] = serde_json::to_value(candidate.relation).unwrap();
    plan["effect_summary"]["newly_allowed_region_hash"] =
        json!(candidate.semantic_diff.newly_allowed_region_hash);
    plan["effect_summary"]["removed_region_hash"] =
        json!(candidate.semantic_diff.removed_region_hash);
    plan["rollback_authority"]["baseline_hash"] = plan["baseline_hash"].clone();
    plan["artifact_hash"] = json!(
        compile_portable(&review.after, &refs)
            .unwrap()
            .artifact_hash()
            .unwrap()
    );
    (plan, requirements, review, refs)
}
pub fn metadata_report(now: i64) -> Value {
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
    let features=features.into_iter().map(|k|(k.to_string(),json!({"state":"unverified","reason_code":"QUALIFICATION_REQUIRED","evidence_hash":null}))).collect::<serde_json::Map<_,_>>();
    json!({"schema_version":"f.target-capability/v1","target_id":TARGET,"platform":"linux","enforcement_backend":"nftables","capability_version":"f.target-capability/v1","os_version":"synthetic","backend_version":"unverified","executor_build_hash":hash_bytes(b"fixture"),"checked_at":timestamp(now).unwrap(),"valid_until":timestamp(now+300).unwrap(),"profiles":[],"families":["ipv4","ipv6"],"directions":["input","output"],"protocols":[],"binding_kinds":["host"],"features":features,"max_policies":1,"max_rules":1,"max_artifact_bytes":1,"qualification_profiles":[],"interfaces":[]})
}
pub fn metadata(store: &mut AuthorityStore, tenant: &AuthorityTenant, now: i64) {
    let ch = store
        .issue_target_report_challenge(tenant, TARGET, now)
        .unwrap();
    let proof = fw_target_evidence::sign_report(
        &ch,
        &canonical_bytes(&metadata_report(now)).unwrap(),
        &METADATA_SEED,
        now,
    )
    .unwrap();
    store.admit_target_report(tenant, &proof, now).unwrap();
}
pub fn setup(
    store: &mut AuthorityStore,
    now: i64,
) -> (
    AuthorityTenant,
    Value,
    Value,
    PolicyReviewEvidence,
    LabReferences,
) {
    let tenant = AuthorityTenant::new(ORG, PROJECT).unwrap();
    store
        .provision_target_metadata_project(&tenant, now)
        .unwrap();
    store
        .pin_target_transport(
            &tenant,
            &TargetTransportPin {
                target_id: TARGET.into(),
                public_key: SigningKey::from_bytes(&METADATA_SEED)
                    .verifying_key()
                    .to_bytes(),
                certificate_fingerprint: hash_bytes(b"test certificate"),
                platform: "linux".into(),
                not_before: now,
                not_after: now + 7200,
            },
            None,
            now,
        )
        .unwrap();
    metadata(store, &tenant, now);
    let (plan, requirements, review, refs) = native_plan(now);
    store
        .register_reviewed_plan(&tenant, &plan, &requirements, &review, now)
        .unwrap();
    store
        .pin_native_references(
            &tenant,
            &NativeReferencePin {
                target_id: TARGET.into(),
                references: refs.clone(),
                not_before: now,
                not_after: now + 3600,
            },
            None,
            now,
        )
        .unwrap();
    store
        .pin_native_observer(
            &tenant,
            &NativeObserverPin {
                target_id: TARGET.into(),
                public_key: SigningKey::from_bytes(&OBSERVER_SEED)
                    .verifying_key()
                    .to_bytes(),
                not_before: now,
                not_after: now + 3600,
            },
            None,
            now,
        )
        .unwrap();
    (tenant, plan, requirements, review, refs)
}
pub fn installation(artifact: &PortableArtifact, now: i64) -> Installation {
    bind_at(
        artifact,
        &BindingContext {
            operation_id: PLAN.into(),
            grant_hash: hash_bytes(b"test-only installation binding"),
            boot_id: BOOT.into(),
            network_namespace: "net:[12345]".into(),
            wall_time_unix: now,
            monotonic_millis: 10_000,
            clock_uncertainty_seconds: 0,
            elapsed_seconds: 0,
            commit_budget_seconds: 2,
        },
    )
    .unwrap()
}
pub fn snapshot(artifact: &Artifact) -> Value {
    let mut entries =
        vec![json!({"metainfo":{"version":"1.0.6","release_name":"test","json_schema_version":1}})];
    for (i, command) in artifact.nft_json["nftables"]
        .as_array()
        .unwrap()
        .iter()
        .enumerate()
    {
        let mut entry = command["add"].clone();
        let (_, object) = entry.as_object_mut().unwrap().iter_mut().next().unwrap();
        object["handle"] = json!(i + 1);
        if let Some(elements) = object.get_mut("elem") {
            for element in elements.as_array_mut().unwrap() {
                let timeout = element["elem"]["timeout"].as_u64().unwrap();
                element["elem"]["expires"] = json!(timeout - 1);
            }
        }
        entries.push(entry);
    }
    json!({"nftables":entries})
}
pub fn proof(
    ch: &NativeObservationChallenge,
    installation: Installation,
    readback: Value,
    now: i64,
) -> SignedNativeObservation {
    let elapsed = now - installation.manifest.binding.wall_time_unix;
    let payload = NativeObservationPayload {
        schema_version: fw_native_evidence::PAYLOAD_SCHEMA.into(),
        production_qualified: false,
        observation: ObservationContext {
            boot_id: BOOT.into(),
            network_namespace: "net:[12345]".into(),
            wall_time_unix: now,
            monotonic_millis: 10_000 + elapsed as u64 * 1000,
        },
        installation,
        readback,
    };
    sign_observation(ch, &payload, &OBSERVER_SEED, now).unwrap()
}
pub fn challenge(
    store: &mut AuthorityStore,
    tenant: &AuthorityTenant,
    plan_id: &str,
    artifact: &PortableArtifact,
    head: Option<&str>,
    now: i64,
) -> (NativeObservationChallenge, Installation) {
    let installation = installation(artifact, now);
    let challenge = store
        .challenge_native_observation(
            tenant,
            plan_id,
            ArtifactRole::Candidate,
            &installation,
            head,
            1,
            1,
            now,
        )
        .unwrap();
    (challenge, installation)
}
