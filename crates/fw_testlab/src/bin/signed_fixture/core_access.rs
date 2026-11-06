//! Real core wire semantics under explicitly synthetic, disposable lab trust.
//! This fixture does not provision protected humans, workload/delegation signing
//! authority, a production signer, or a production dispatch capability.
use super::*;
use fw_authority::{
    AuthorityError, CoreAccessLeaseWindow, CoreAccessProvenance, QuotaLedger, QuotaLimits,
    ReservationRequest,
};
use fw_linux_executor::CoreAccessExecutionBundle;
use fw_native_evidence::{ArtifactRole, NativeObservationChallenge, SignedNativeObservation};
use fw_planner::{
    compose_access_patch, core_access_authority_basis_hash, core_access_effect_summary,
    PolicyReviewEvidence,
};
use std::collections::BTreeSet;

const LEASE_SECONDS: i64 = 60;
const BASELINE_LEASE: &str = "99999999-9999-4999-8999-999999999991";
const BASELINE_REQUEST: &str = "99999999-9999-4999-8999-999999999992";

/// Independently provisioned local lab input, never copied from submitted
/// artifact references while challenging or verifying an observation.
#[derive(Clone, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct CoreLabReferencePin {
    schema_version: String,
    reference_revision: String,
    production_authorized: bool,
    references: LabReferences,
}

impl CoreLabReferencePin {
    fn bind_artifacts(
        &self,
        previous: &fw_backend_linux::PortableArtifact,
        candidate: &fw_backend_linux::PortableArtifact,
    ) -> Result<()> {
        let revision = self.reference_revision.parse::<u64>()?;
        if self.schema_version != "fw.core-lab-reference-pin/v1"
            || self.production_authorized
            || revision == 0
            || revision.to_string() != self.reference_revision
        {
            return Err("invalid synthetic reference pin".into());
        }
        for artifact in [previous, candidate] {
            let independently_compiled = compile_portable(&artifact.state, &self.references)?;
            if artifact.references != self.references || h(artifact)? != h(&independently_compiled)?
            {
                return Err("artifact differs from independently pinned references".into());
            }
        }
        Ok(())
    }
}

fn pinned_compilation(
    path: &Path,
    bundle: &CoreAccessExecutionBundle,
) -> Result<(CoreLabReferencePin, fw_native_evidence::VerifiedCompilation)> {
    let pin: CoreLabReferencePin = checked_stage(
        read(&path.join("reference-pin.json")),
        "CORE_OBS_REFERENCE_PIN_READ",
    )?;
    checked_stage(
        pin.bind_artifacts(&bundle.previous, &bundle.candidate),
        "CORE_OBS_REFERENCE_PIN_BINDING",
    )?;
    let compilation = checked_stage(
        fw_native_evidence::compile_evidence(&bundle.plan, &bundle.review, &pin.references),
        "CORE_OBS_PINNED_COMPILATION",
    )?;
    if h(compilation.baseline())? != h(&bundle.previous)?
        || h(compilation.candidate())? != h(&bundle.candidate)?
        || bundle.recovery.references != pin.references
    {
        return Err("pinned compilation differs from submitted artifacts".into());
    }
    Ok((pin, compilation))
}

// Fixed stage codes identify a failed fixture obligation without printing raw
// objects, keys, paths or arbitrary underlying diagnostics.
fn checked_stage<T, E>(
    result: std::result::Result<T, E>,
    code: &'static str,
) -> std::result::Result<T, E> {
    result.inspect_err(|_| eprintln!("{code}"))
}

/// The development adapter verifies real immutable core inputs and a local quota
/// reservation. Its synthetic LabApproval is deliberately not HumanApproval or
/// an independently provisioned production authority boundary.
struct CoreFixtureAuthority<'a> {
    plan: &'a Value,
    review: &'a PolicyReviewEvidence,
    provenance: &'a CoreAccessProvenance,
    window: &'a CoreAccessLeaseWindow,
    approval: &'a LabApproval,
    reservation_id: &'a str,
}
impl AuthorityEvidence for CoreFixtureAuthority<'_> {
    fn verify_for_signing(&self, payload: &Value, at: i64) -> fw_authority::Result<GrantContext> {
        let reject = || AuthorityError::Binding;
        guard().map_err(|_| reject())?;
        let review = self.review.verify(self.plan).map_err(|_| reject())?;
        let provenance = self.provenance.verify(self.plan)?;
        let window = self
            .window
            .verify(self.plan, self.provenance, self.review)?;
        let binding = review.core_binding().ok_or_else(reject)?;
        let plan_hash = canonical_hash(self.plan).map_err(|_| reject())?;
        let approval_hash = canonical_hash(self.approval).map_err(|_| reject())?;
        if binding.lease_id() != provenance.lease_id()
            || binding.request_id() != provenance.request_id()
            || window.lease_seconds() != LEASE_SECONDS
            || at < window.not_before()
            || at >= window.expires_at()
            || self.approval.schema_version != "fw.isolated-lab-approval/v1"
            || self.approval.kind != "synthetic_test_fixture"
            || self.approval.plan_hash != plan_hash
            || self.approval.principal_id != PRINCIPAL
            || at >= self.approval.valid_until_unix
            || payload["approval_set_hash"] != approval_hash
            || payload["lease_id"] != provenance.lease_id()
            || payload["reservation"]["reservation_id"] != self.reservation_id
            || payload["reservation"]["root_id"] != provenance.root_id()
            || payload["reservation"]["status"] != "reserved"
            || payload["reservation"]["projected_active_leases"] != 1
            || payload["reservation"]["projected_new_leases_per_day"] != 1
            || payload["reservation"]["projected_unique_destinations_per_day"] != 1
            || payload["reservation"]["projected_cumulative_lease_seconds_per_day"] != LEASE_SECONDS
            || payload["reservation"]["projected_concurrent_deployments"] != 1
        {
            return Err(reject());
        }
        for field in [
            "plan_id",
            "request_id",
            "org_id",
            "project_id",
            "target_id",
            "principal_id",
            "workload_binding_id",
            "requested_policy_hashes",
            "authority_epoch",
            "target_generation",
            "envelope_hash",
            "delegation_hash",
            "artifact_hash",
            "baseline_hash",
            "confirm_timeout_seconds",
            "rollback_authority",
            "change_kind",
            "request_patch_hash",
            "desired_state_hash",
        ] {
            if payload[field] != self.plan[field] {
                return Err(reject());
            }
        }
        if payload["plan_hash"] != plan_hash {
            return Err(reject());
        }
        Ok(GrantContext {
            org_id: ORG.into(),
            project_id: PROJECT.into(),
            target_id: TARGET.into(),
            plan_hash,
            artifact_hash: self.plan["artifact_hash"]
                .as_str()
                .ok_or_else(reject)?
                .into(),
            baseline_hash: self.plan["baseline_hash"]
                .as_str()
                .ok_or_else(reject)?
                .into(),
            desired_state_hash: self.plan["desired_state_hash"]
                .as_str()
                .ok_or_else(reject)?
                .into(),
            approval_set_hash: approval_hash,
            authority_epoch: 1,
            now_unix: at,
        })
    }
}

fn lease_policy(
    number: usize,
    direction: &str,
    protocol: &str,
    port: u16,
    start: i64,
    end: i64,
) -> Result<Policy> {
    let mut p = policy(
        number,
        "ipv4",
        protocol,
        direction,
        port,
        "allow",
        (start, end),
    )?;
    p.lifetime = serde_json::from_value(
        json!({"kind":"lease","not_before":iso(start),"expires_at":iso(end)}),
    )?;
    Ok(p)
}

pub(super) fn prepare(path: &Path, recovery_profile: bool) -> Result<Value> {
    let (namespace, boot) = guard()?;
    directory(path, true)?;
    let start = now();
    let end = start + LEASE_SECONDS;
    // Distinct fresh fixtures have fixed signed windows chosen before any
    // acceptance. Both retain the same full original sixty-second lease.
    let dispatch_until = start + if recovery_profile { 18 } else { 45 };
    let plan_until = start + if recovery_profile { 20 } else { 50 };
    let plan_id = id()?;
    let workload = id()?;
    let root = id()?;
    let envelope_id = id()?;
    let operation = id()?;
    let reservation_id = id()?;
    let fixture_hash = h(
        &json!({"profile":"isolated-core-access","synthetic_fixture_authority":true,"production_authorized":false}),
    )?;
    let scope = json!({"schema_version":"fw.isolated-lab-scope/v1","org_id":ORG,"project_id":PROJECT,"target_id":TARGET,"network_namespace":namespace,"interfaces":["lo"],"conntrack_zone":0});
    let scope_hash = h(&scope)?;
    let refs: LabReferences = serde_json::from_value(json!({
        "scope":scope,
        "baseline":{"schema_version":"fw.isolated-lab-baseline/v1","scope_hash":scope_hash,"management_paths":[],"default_action":"drop"},
        "source_snapshot":{"schema_version":"fw.isolated-lab-snapshot/v1","scope_hash":scope_hash,"assets":[{"asset_id":SOURCE,"cidrs":["127.0.0.1/32"]},{"asset_id":DESTINATION,"cidrs":["127.0.0.1/32"]}]},
        "capability":{"schema_version":"fw.isolated-lab-capability/v1","scope_hash":scope_hash,"platform":"linux","profile":"host-tcp-udp-lab","production_qualified":false}
    }))?;
    // The lab administrator's scope/reference input is saved before artifact
    // construction. Observation commands must load this separate closed file.
    save(
        &path.join("reference-pin.json"),
        &CoreLabReferencePin {
            schema_version: "fw.core-lab-reference-pin/v1".into(),
            reference_revision: "1".into(),
            production_authorized: false,
            references: refs.clone(),
        },
    )?;

    // Loopback traverses both OUTPUT and INPUT. These explicit old fixture
    // policies provide the companion traversal and independent positive control;
    // the new request itself grants IPv4 INPUT TCP only.
    // Pinned nft 1.0.6 prints an anonymous multiport ct.proto-dst set as
    // "[invalid type]" values. Keep that native observation unqualified and
    // preserve exactly the same old union with separate scalar-port revisions;
    // the verifier must continue rejecting the unsupported representation.
    let baseline_policies = vec![
        policy(
            1000,
            "ipv4",
            "tcp",
            "input",
            18082,
            "deny",
            (start, start + 180),
        )?,
        lease_policy(1001, "output", "tcp", 18080, start - 40, start + 180)?,
        lease_policy(1002, "input", "tcp", 18084, start - 40, start + 180)?,
        lease_policy(1003, "input", "udp", 18081, start - 40, start + 180)?,
        lease_policy(1004, "output", "udp", 18081, start - 40, start + 180)?,
        lease_policy(1005, "output", "tcp", 18082, start - 40, start + 180)?,
        lease_policy(1006, "output", "tcp", 18084, start - 40, start + 180)?,
    ];
    let before = StateIr {
        schema_version: "f.state-ir/v1".into(),
        target_id: TARGET.into(),
        platform: "linux".into(),
        profile: "lab".into(),
        management_baseline_hash: h(&refs.baseline)?,
        associations: baseline_policies
            .iter()
            .map(|p| {
                Ok(PolicyAssociation {
                    policy_hash: h(p)?,
                    lease_id: (p.action == fw_domain::Action::Allow).then(|| BASELINE_LEASE.into()),
                    request_id: BASELINE_REQUEST.into(),
                    authority_basis_hash: fixture_hash.clone(),
                })
            })
            .collect::<Result<_>>()?,
        policies: baseline_policies,
        tombstone_hashes: vec![],
        source_snapshot_hash: h(&refs.source_snapshot)?,
        target_capability_hash: h(&refs.capability)?,
        normalization_version: "f.normalize/nfc-v1".into(),
    }
    .normalized()?;
    let requested = vec![
        lease_policy(2000, "input", "tcp", 18080, start, end)?,
        lease_policy(2001, "input", "tcp", 18082, start, end)?,
    ];
    let mut envelope_scope = serde_json::to_value(&requested[0].scope)?;
    envelope_scope["transport"]["destination_ports"] = json!([{"start":18080,"end":18084}]);
    let request = json!({"schema_version":"f.access-request/v1","idempotency_key":id()?,"workflow_id":"isolated-core-lab","workload_binding_id":workload,"source_asset_ids":[SOURCE],"destination_asset_ids":[DESTINATION],"service_id":"isolated-core-tcp","lease_seconds":LEASE_SECONDS,"purpose":"Synthetic authority tests real core wire semantics and absolute native expiry"});
    let envelope = json!({"schema_version":"f.access-envelope/v1","envelope_id":envelope_id,"revision":1,"org_id":ORG,"project_id":PROJECT,"target_id":TARGET,"scope":envelope_scope,"excluded_destination_cidrs":[],"valid_from":iso(start-60),"valid_until":iso(start+3600),"max_lease_seconds":LEASE_SECONDS,"approval_hash":fixture_hash});
    let delegation = json!({"schema_version":"f.delegation/v1","root_id":root,"revision":1,"org_id":ORG,"project_id":PROJECT,"target_id":TARGET,"envelope_id":envelope_id,"envelope_hash":h(&envelope)?,"allowed_principal_ids":[PRINCIPAL],"workload_binding_ids":[workload],"source_asset_ids":[SOURCE],"destination_asset_ids":[DESTINATION],"service_ids":["isolated-core-tcp"],"allowed_tools":["get_capabilities","get_operation","get_plan","release_access","request_access","request_deployment"],"valid_from":iso(start-60),"valid_until":iso(start+3600),"max_lease_seconds":LEASE_SECONDS,"max_active_leases":1,"max_new_leases_per_day":1,"max_unique_destinations_per_day":1,"max_cumulative_lease_seconds_per_day":LEASE_SECONDS,"approval_hash":fixture_hash,"can_delegate":false,"max_concurrent_deployments":1,"budget_window":{"kind":"rolling","seconds":86400,"interval":"(as_of-86400s,as_of]","lease_seconds_measure":"approved-duration-per-lease","rounding":"integer-seconds-no-rounding"}});
    let provenance: CoreAccessProvenance = serde_json::from_value(
        json!({"schema_version":"fw.core-access-provenance/v1","request_id":REQUEST,"request_revision":1,"lease_id":LEASE,"request":request,"envelope":envelope,"delegation":delegation}),
    )?;
    let requirements = json!({"schema_version":"f.approval-requirements/v1","profile":"lab_owner","minimum_humans":1,"required_roles":["owner"],"distinct_principals":true,"author_may_approve":true,"max_approval_age_seconds":300,"require_webauthn":true,"role_policy_hash":fixture_hash});
    let probes = vec![
        ProbeSpec {
            name: "core-tcp-allowed".into(),
            family: "ipv4".into(),
            protocol: "tcp".into(),
            port: 18080,
            expect_reply: true,
        },
        ProbeSpec {
            name: "baseline-udp-preserved".into(),
            family: "ipv4".into(),
            protocol: "udp".into(),
            port: 18081,
            expect_reply: true,
        },
        ProbeSpec {
            name: "existing-deny-preserved".into(),
            family: "ipv4".into(),
            protocol: "tcp".into(),
            port: 18082,
            expect_reply: false,
        },
    ];
    let gates = ["schema","identity","scope","quota","semantic","expiry","capability","baseline"].into_iter().map(|gate_id|json!({"gate_id":gate_id,"required":true,"result":"PASS","evidence_hash":fixture_hash})).collect::<Vec<_>>();
    let original: Value = serde_json::from_str(include_str!(
        "../../../../../docs/specs/F_기준자료/F_개발계약/F_계약_예제.json"
    ))?;
    let mut plan = original["plan"].clone();
    for (key, value) in [
        ("plan_id", json!(plan_id)),
        ("request_id", json!(REQUEST)),
        ("request_revision", json!(1)),
        ("request_hash", json!(h(&provenance.request)?)),
        ("org_id", json!(ORG)),
        ("project_id", json!(PROJECT)),
        ("target_id", json!(TARGET)),
        ("principal_id", json!(PRINCIPAL)),
        ("workload_binding_id", json!(workload)),
        ("created_at", json!(iso(start))),
        ("valid_until", json!(iso(plan_until))),
        ("authority_epoch", json!("1")),
        ("target_generation", json!("1")),
        ("requested_policies", serde_json::to_value(&requested)?),
        (
            "requested_policy_hashes",
            serde_json::to_value(requested.iter().map(h).collect::<Result<BTreeSet<_>>>()?)?,
        ),
        ("request_patch_hash", json!(h(&requested)?)),
        ("source_snapshot_hash", json!(before.source_snapshot_hash)),
        (
            "target_capability_hash",
            json!(before.target_capability_hash),
        ),
        ("envelope_hash", json!(h(&provenance.envelope)?)),
        ("delegation_hash", json!(h(&provenance.delegation)?)),
        ("workload_binding_hash", json!(fixture_hash)),
        ("workload_binding_valid_until", json!(iso(start + 3600))),
        ("gates", json!(gates)),
        ("guardrail_hash", json!(fixture_hash)),
        ("compiler_hash", json!(fixture_hash)),
        ("validator_hash", json!(fixture_hash)),
        ("validation_report_hash", json!(fixture_hash)),
        ("approval_requirements_hash", json!(h(&requirements)?)),
        ("probe_spec_hash", json!(h(&probes)?)),
    ] {
        plan[key] = value;
    }
    let authority_basis_hash = core_access_authority_basis_hash(&plan)?;
    let associations = requested
        .iter()
        .map(|p| {
            Ok(PolicyAssociation {
                policy_hash: h(p)?,
                lease_id: Some(LEASE.into()),
                request_id: REQUEST.into(),
                authority_basis_hash: authority_basis_hash.clone(),
            })
        })
        .collect::<Result<Vec<_>>>()?;
    let composed = checked_stage(
        compose_access_patch(&before, &requested, &associations, &BTreeSet::new()),
        "CORE_FIXTURE_COMPOSITION",
    )?;
    let previous = checked_stage(
        compile_portable(&before, &refs),
        "CORE_FIXTURE_BASELINE_COMPILE",
    )?;
    let candidate = checked_stage(
        compile_portable(&composed.state, &refs),
        "CORE_FIXTURE_CANDIDATE_COMPILE",
    )?;
    let recovery = checked_stage(
        restrictive_recovery(&previous, &candidate),
        "CORE_FIXTURE_RECOVERY_COMPILE",
    )?;
    plan["baseline_hash"] = json!(composed.baseline_hash);
    plan["desired_state_hash"] = json!(composed.desired_state_hash);
    plan["artifact_hash"] = json!(candidate.artifact_hash()?);
    plan["effect_summary"] =
        serde_json::to_value(core_access_effect_summary(&before, &composed.state)?)?;
    plan["rollback_authority"] = json!({"profile":"preserve-current-restrictions","scope_bound_hash":scope_hash,"baseline_hash":previous.desired_state_hash,"artifact_hash":recovery.artifact_hash()?,"valid_until":iso(start+180)});
    let review = PolicyReviewEvidence {
        before,
        after: composed.state,
    };
    checked_stage(review.verify(&plan), "CORE_FIXTURE_REVIEW")?;
    let verified = checked_stage(provenance.verify(&plan), "CORE_FIXTURE_PROVENANCE")?;
    let lease_window: CoreAccessLeaseWindow = serde_json::from_value(
        json!({"schema_version":"fw.core-access-lease-window/v1","org_id":ORG,"project_id":PROJECT,"target_id":TARGET,"request_id":REQUEST,"request_revision":1,"request_hash":plan["request_hash"],"provenance_hash":verified.hash(),"lease_id":LEASE,"not_before":iso(start),"expires_at":iso(end)}),
    )?;
    checked_stage(
        lease_window.verify(&plan, &provenance, &review),
        "CORE_FIXTURE_WINDOW",
    )?;
    let previous_installation = checked_stage(
        bind_at(
            &previous,
            &BindingContext {
                operation_id: id()?,
                grant_hash: fixture_hash.clone(),
                boot_id: boot.clone(),
                network_namespace: namespace.clone(),
                wall_time_unix: now(),
                monotonic_millis: monotonic_millis()?,
                clock_uncertainty_seconds: 0,
                elapsed_seconds: 0,
                commit_budget_seconds: 5,
            },
        ),
        "CORE_FIXTURE_INSTALLATION",
    )?;
    let approval = LabApproval {
        schema_version: "fw.isolated-lab-approval/v1".into(),
        kind: "synthetic_test_fixture".into(),
        plan_hash: h(&plan)?,
        principal_id: PRINCIPAL.into(),
        valid_until_unix: plan_until,
    };
    let quota_limits = QuotaLimits {
        active_leases: 1,
        new_leases_per_day: 1,
        unique_destinations_per_day: 1,
        cumulative_seconds_per_day: LEASE_SECONDS,
        concurrent_deployments: 1,
    };
    let mut quota = checked_stage(
        QuotaLedger::open(path.join("core-quota.sqlite3")),
        "CORE_FIXTURE_QUOTA_OPEN",
    )?;
    fs::set_permissions(
        path.join("core-quota.sqlite3"),
        std::os::unix::fs::PermissionsExt::from_mode(0o600),
    )?;
    checked_stage(
        quota.reserve(
            &ReservationRequest {
                reservation_id: reservation_id.clone(),
                org_id: ORG.into(),
                root_id: root.clone(),
                project_id: PROJECT.into(),
                lease_not_before: start,
                lease_expires_at: end,
                issued_at: start,
                destination_ids: vec![DESTINATION.into()],
                plan_hash: h(&plan)?,
            },
            quota_limits,
            quota_limits,
        ),
        "CORE_FIXTURE_QUOTA_RESERVATION",
    )?;
    let mut payload = original["grant"]["payload"].clone();
    for field in [
        "plan_id",
        "request_id",
        "org_id",
        "project_id",
        "target_id",
        "principal_id",
        "workload_binding_id",
        "requested_policy_hashes",
        "authority_epoch",
        "target_generation",
        "envelope_hash",
        "delegation_hash",
        "artifact_hash",
        "baseline_hash",
        "confirm_timeout_seconds",
        "rollback_authority",
        "change_kind",
        "request_patch_hash",
        "desired_state_hash",
    ] {
        payload[field] = plan[field].clone();
    }
    payload["grant_id"] = json!(id()?);
    payload["plan_hash"] = json!(h(&plan)?);
    payload["approval_set_hash"] = json!(h(&approval)?);
    payload["issued_at"] = json!(iso(start));
    payload["not_after"] = json!(iso(dispatch_until));
    payload["confirm_not_after"] = json!(iso(plan_until));
    payload["lease_id"] = json!(LEASE);
    payload["reservation"] = json!({"reservation_id":reservation_id,"root_id":root,"status":"reserved","reserved_until":iso(dispatch_until),"projected_active_leases":1,"projected_new_leases_per_day":1,"projected_unique_destinations_per_day":1,"projected_cumulative_lease_seconds_per_day":LEASE_SECONDS,"projected_concurrent_deployments":1,"window_start":iso(start-86400),"window_end":iso(start)});
    let grant_key = SigningKey::from_bytes(&random_bytes()?);
    let confirm_key = SigningKey::from_bytes(&random_bytes()?);
    // Issuance is sampled after preparation. Its current clock must agree with
    // sign_grant's current temporary trust floor. The lease's original S/E and
    // every absolute dispatch/confirmation/recovery deadline stay unchanged;
    // preparation can therefore only shorten the remaining dispatch window.
    let issued = now();
    payload["issued_at"] = json!(iso(issued));
    payload["reservation"]["window_start"] = json!(iso(issued - 86400));
    payload["reservation"]["window_end"] = json!(iso(issued));
    let grant = checked_stage(
        sign_grant(
            payload,
            "isolated-grant",
            &grant_key,
            &CoreFixtureAuthority {
                plan: &plan,
                review: &review,
                provenance: &provenance,
                window: &lease_window,
                approval: &approval,
                reservation_id: &reservation_id,
            },
            issued,
        )
        .inspect_err(|error| {
            if matches!(error, AuthorityError::Time) {
                eprintln!("CORE_FIXTURE_SIGNING_TIME");
            }
        }),
        "CORE_FIXTURE_SIGNING",
    )?;
    let mut bundle = CoreAccessExecutionBundle {
        schema_version: "fw.isolated-core-access-execution-bundle/v1".into(),
        operation_id: operation.clone(),
        plan,
        review,
        provenance,
        lease_window,
        approval,
        probes,
        grant,
        previous,
        candidate,
        recovery,
        previous_installation,
    };
    let lab_key = |name: &str, purpose: &str, key: &SigningKey| LabKey {
        key_id: name.into(),
        payload_type: purpose.into(),
        public_key: STANDARD.encode(key.verifying_key().to_bytes()),
        not_before_unix: start - 1,
        not_after_unix: start + 3600,
        revoked: false,
    };
    let trust = LabTrust {
        schema_version: "fw.isolated-lab-trust/v1".into(),
        org_id: ORG.into(),
        project_id: PROJECT.into(),
        target_id: TARGET.into(),
        authority_epoch: "1".into(),
        network_namespace: namespace,
        boot_id: boot,
        production_authorized: false,
        grant_key: lab_key("isolated-grant", CORE_GRANT_TYPE, &grant_key),
        confirm_key: lab_key("isolated-confirm", CONFIRM_TYPE, &confirm_key),
    };
    save(
        &path.join("grant-secret.json"),
        &STANDARD.encode(grant_key.to_bytes()),
    )?;
    save(
        &path.join("confirm-secret.json"),
        &STANDARD.encode(confirm_key.to_bytes()),
    )?;
    let observer_seed = random_bytes()?;
    let observer_public = SigningKey::from_bytes(&observer_seed)
        .verifying_key()
        .to_bytes();
    save(
        &path.join("observer-key.json"),
        &json!({"schema_version":"fw.lab-observer-key/v1","org_id":ORG,"project_id":PROJECT,"target_id":TARGET,"observer_revision":"1","not_before_unix":start-1,"not_after_unix":start+3600,"seed":observer_seed}),
    )?;
    save(&path.join("observer-public.json"), &observer_public)?;
    save(&path.join("trust.json"), &trust)?;
    // Preflight the semantic/core wire shape before the live baseline binding.
    // The final bound external file is parsed and verified by real driver init.
    let serialized = canonical_bytes(&bundle)?;
    let parsed = checked_stage(
        fw_linux_executor::parse_execution_bundle(&serialized),
        "CORE_FIXTURE_SERIALIZED_PROJECTION",
    )?;
    checked_stage(
        fw_linux_executor::verify_core_access_execution(&parsed, &trust, issued, false),
        "CORE_FIXTURE_SERIALIZED_AUTHORITY",
    )?;
    let requested_hashes = requested.iter().map(h).collect::<Result<BTreeSet<_>>>()?;
    let token_names = bundle
        .candidate
        .tokens
        .iter()
        .filter(|t| requested_hashes.contains(&t.policy_hash))
        .map(|t| t.token_name.clone())
        .collect::<Vec<_>>();
    // This unsigned initial installation has not been accepted by a journal.
    // Bind once immediately before publishing its exact final bundle/bootstrap;
    // all original policy deadlines, portable artifacts and signed bytes remain.
    let mut binding = bundle.previous_installation.manifest.binding.clone();
    binding.monotonic_millis = monotonic_millis()?;
    binding.wall_time_unix = now();
    bundle.previous_installation = checked_stage(
        bind_at(&bundle.previous, &binding),
        "CORE_FIXTURE_FINAL_BASELINE_BINDING",
    )?;
    save(&path.join("bundle.json"), &bundle)?;
    save(
        &path.join("bootstrap.json"),
        &bundle.previous_installation.native.nft_json,
    )?;
    let metadata = json!({"operation_id":operation,"table":bundle.candidate.table,"not_before_unix":start,"expires_at_unix":end,"lease_seconds":LEASE_SECONDS,"issued_at_unix":issued,"prepared_at_unix":now(),"dispatch_not_after_unix":dispatch_until,"core_projection_preverified":true,"fixture_execution_profile":if recovery_profile {"recovery"} else {"expiry"},"plan_valid_until_unix":plan_until,"confirm_not_after_unix":plan_until,"recovery_valid_until_unix":start+180,"core_token_names":token_names,"synthetic_fixture_authority":true,"synthetic_approval":true,"development_quota_ledger_reserved":true,"human_approval_tested":false,"workload_delegation_authority_verified":false,"production_authorized":false});
    save(&path.join("metadata.json"), &metadata)?;
    Ok(metadata)
}

/// Pure explicit-clock tests run after the live operation has been confirmed or
/// recovered, so repeated immutable verification cannot consume dispatch time.
/// They reuse exact saved bytes and never rewrite original S/E or native state.
pub(super) fn verify_time_model(path: &Path) -> Result<Value> {
    guard()?;
    directory(path, false)?;
    let serialized = fs::read(path.join("bundle.json"))?;
    let runtime = checked_stage(
        fw_linux_executor::parse_execution_bundle(&serialized),
        "CORE_FIXTURE_TIME_MODEL_PROJECTION",
    )?;
    let context = runtime
        .core_access
        .as_ref()
        .ok_or("missing core clock model context")?;
    let trust: LabTrust = read(&path.join("trust.json"))?;
    let issued = DateTime::parse_from_rfc3339(
        runtime.grant.payload["issued_at"]
            .as_str()
            .ok_or("core issued time")?,
    )?
    .timestamp();
    let end = DateTime::parse_from_rfc3339(&context.lease_window.expires_at)?.timestamp();
    let plan_until = runtime.plan.valid_until_unix;
    let recovery_until = DateTime::parse_from_rfc3339(
        runtime.grant.payload["rollback_authority"]["valid_until"]
            .as_str()
            .ok_or("core recovery time")?,
    )?
    .timestamp();
    checked_stage(
        fw_linux_executor::verify_core_access_execution(&runtime, &trust, issued, false),
        "CORE_FIXTURE_TIME_MODEL_DISPATCH",
    )?;
    if fw_linux_executor::verify_core_access_execution(&runtime, &trust, plan_until, false).is_ok()
        || fw_linux_executor::verify_core_access_execution(&runtime, &trust, end, false).is_ok()
        || fw_linux_executor::verify_core_access_execution(&runtime, &trust, recovery_until, true)
            .is_ok()
    {
        return Err("core authority time model accepted expired authority".into());
    }
    checked_stage(
        fw_linux_executor::verify_core_access_execution(&runtime, &trust, plan_until, true),
        "CORE_FIXTURE_TIME_MODEL_PLAN_RECOVERY",
    )?;
    checked_stage(
        fw_linux_executor::verify_core_access_execution(&runtime, &trust, end, true),
        "CORE_FIXTURE_TIME_MODEL_LEASE_RECOVERY",
    )?;
    Ok(
        json!({"verified":true,"profile":"pure-original-core-clock-model",
        "not_before":context.lease_window.not_before,"expires_at":context.lease_window.expires_at,
        "issued_at_unix":issued,"normal_plan_valid_until_unix":plan_until,"recovery_valid_until_unix":recovery_until,
        "production_authorized":false}),
    )
}

/// Verify dispatch or historical recovery against a newly sampled real clock.
/// The caller receives evidence only; this command never writes native state.
pub(super) fn verify_authority(path: &Path, mode: &str) -> Result<Value> {
    guard()?;
    directory(path, false)?;
    let recovery = match mode {
        "dispatch" => false,
        "recovery" => true,
        _ => return Err("unsupported core authority purpose".into()),
    };
    let bundle: CoreAccessExecutionBundle = read(&path.join("bundle.json"))?;
    let trust: LabTrust = read(&path.join("trust.json"))?;
    let at = now();
    let runtime = bundle.clone().into_execution_bundle()?;
    let verified = fw_linux_executor::verify_core_access_execution(&runtime, &trust, at, recovery)?;
    Ok(json!({"verified":true,"purpose":mode,"checked_at_unix":at,
        "grant_hash":verified.grant_hash(),"not_before":bundle.lease_window.not_before,
        "expires_at":bundle.lease_window.expires_at,"production_authorized":false}))
}

#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct ReadonlyJournalSnapshot {
    schema_version: String,
    journal_version: u32,
    query_only: bool,
    total_changes: u64,
    material_hash: String,
    operation_id: String,
    grant_hash: String,
    generation: String,
    baseline_hash: String,
    desired_state_hash: String,
    issued_at: i64,
    not_after: i64,
    confirm_not_after: i64,
    submitted_at: i64,
    confirm_deadline: i64,
    org_id: String,
    target_id: String,
    authority_epoch: String,
    highest_generation: String,
}
#[derive(serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct ObservedInstallation {
    schema_version: String,
    bundle: ExecutionBundle,
    installation: fw_backend_linux::Installation,
    trust_hash: String,
    native_write_fenced: bool,
}

fn readonly_candidate_installation(
    path: &Path,
    bundle: &CoreAccessExecutionBundle,
) -> Result<fw_backend_linux::Installation> {
    let snapshot: ReadonlyJournalSnapshot = checked_stage(
        read(&path.join("candidate-journal-snapshot.json")),
        "CORE_OBS_SNAPSHOT_DESCRIPTOR",
    )?;
    let material_path = path.join("candidate-material.json");
    if checked_stage(
        fs::symlink_metadata(&material_path),
        "CORE_OBS_MATERIAL_FILE",
    )?
    .len()
        > 1024 * 1024
    {
        eprintln!("CORE_OBS_MATERIAL_SIZE");
        return Err("bounded readonly material required".into());
    }
    let material: fw_executor::ExecutionMaterial =
        checked_stage(read(&material_path), "CORE_OBS_MATERIAL_SCHEMA")?;
    let bytes = checked_stage(fs::read(&material_path), "CORE_OBS_MATERIAL_BYTES")?;
    if canonical_bytes(&material)? != bytes || material.content_hash()? != snapshot.material_hash {
        eprintln!("CORE_OBS_CANONICAL_MATERIAL");
        return Err("readonly material content mismatch".into());
    }
    let stored: ObservedInstallation = checked_stage(
        serde_json::from_value(material.installation_manifest.clone()),
        "CORE_OBS_INSTALLATION_SCHEMA",
    )?;
    let expected_bundle = bundle.clone().into_execution_bundle()?;
    let trust: LabTrust = read(&path.join("trust.json"))?;
    let issued = DateTime::parse_from_rfc3339(
        bundle.grant.payload["issued_at"]
            .as_str()
            .ok_or("issued time")?,
    )?
    .timestamp();
    let not_after = DateTime::parse_from_rfc3339(
        bundle.grant.payload["not_after"]
            .as_str()
            .ok_or("dispatch time")?,
    )?
    .timestamp();
    let confirm_not_after = DateTime::parse_from_rfc3339(
        bundle.grant.payload["confirm_not_after"]
            .as_str()
            .ok_or("confirm time")?,
    )?
    .timestamp();
    let expected = fw_executor::ExecutionMaterial {
        signed_grant: bundle.grant.clone(),
        baseline_state: serde_json::to_value(&bundle.previous.state)?,
        candidate_state: serde_json::to_value(&bundle.candidate.state)?,
        candidate_artifact: serde_json::to_value(&bundle.candidate)?,
        recovery_state: serde_json::to_value(&bundle.recovery.state)?,
        recovery_artifact: serde_json::to_value(&bundle.recovery)?,
        recovery_scope: serde_json::to_value(&bundle.recovery.references.scope)?,
        installation_manifest: serde_json::to_value(&stored)?,
        tombstone_watermark: json!({"schema_version":"fw.isolated-tombstones/v1","hashes":bundle.candidate.state.tombstone_hashes}),
    };
    let binding = &stored.installation.manifest.binding;
    if snapshot.schema_version != "fw.core-lab-readonly-material/v1"
        || snapshot.journal_version != 3
        || !snapshot.query_only
        || snapshot.total_changes != 0
        || snapshot.operation_id != bundle.operation_id
        || snapshot.grant_hash != h(&bundle.grant)?
        || snapshot.generation != bundle.plan["target_generation"]
        || snapshot.highest_generation != snapshot.generation
        || snapshot.org_id != bundle.plan["org_id"]
        || snapshot.target_id != bundle.plan["target_id"]
        || snapshot.authority_epoch != bundle.plan["authority_epoch"]
        || snapshot.baseline_hash != bundle.previous.desired_state_hash
        || snapshot.desired_state_hash != bundle.candidate.desired_state_hash
        || snapshot.issued_at != issued
        || snapshot.not_after != not_after
        || snapshot.confirm_not_after != confirm_not_after
        || snapshot.submitted_at < issued
        || snapshot.submitted_at >= not_after
        || snapshot.submitted_at >= confirm_not_after
        || snapshot
            .submitted_at
            .checked_add(60)
            .map(|until| until.min(confirm_not_after))
            != Some(snapshot.confirm_deadline)
        || stored.schema_version != "fw.isolated-installation/v1"
        || !stored.native_write_fenced
        || h(&stored.bundle)? != h(&expected_bundle)?
        || stored.trust_hash != h(&trust)?
        || binding.operation_id != bundle.operation_id
        || binding.grant_hash != snapshot.grant_hash
        || binding.boot_id != trust.boot_id
        || binding.network_namespace != trust.network_namespace
        || canonical_bytes(&expected)? != bytes
    {
        eprintln!("CORE_OBS_RETAINED_BINDING");
        return Err("readonly journal binding mismatch".into());
    }
    checked_stage(
        fw_backend_linux::validate_installation(&bundle.candidate, &stored.installation),
        "CORE_OBS_INSTALLATION_BINDING",
    )?;
    Ok(stored.installation)
}

fn observation_objects(
    path: &Path,
    role: &str,
) -> Result<(
    CoreAccessExecutionBundle,
    ArtifactRole,
    fw_backend_linux::Installation,
)> {
    let bundle: CoreAccessExecutionBundle =
        checked_stage(read(&path.join("bundle.json")), "CORE_OBS_BUNDLE_READ")?;
    match role {
        "baseline" => {
            let installation = bundle.previous_installation.clone();
            Ok((bundle, ArtifactRole::Baseline, installation))
        }
        "candidate" => {
            let installation = readonly_candidate_installation(path, &bundle)?;
            Ok((bundle, ArtifactRole::Candidate, installation))
        }
        _ => Err("unsupported core observation role".into()),
    }
}

pub(super) fn challenge_observation(path: &Path, role: &str) -> Result<Value> {
    guard()?;
    directory(path, false)?;
    let (bundle, artifact_role, installation) = observation_objects(path, role)?;
    let (pin, compilation) = pinned_compilation(path, &bundle)?;
    let artifact = compilation.artifact(artifact_role);
    let submitted_artifact_hash = match artifact_role {
        ArtifactRole::Baseline => bundle.previous.artifact_hash()?,
        ArtifactRole::Candidate => bundle.candidate.artifact_hash()?,
    };
    let public: [u8; 32] = read(&path.join("observer-public.json"))?;
    let at = now();
    let synthetic_metadata = h(&json!({"synthetic_fixture_metadata":true,"target_id":TARGET}))?;
    let challenge = NativeObservationChallenge {
        schema_version: fw_native_evidence::CHALLENGE_SCHEMA.into(),
        challenge_id: id()?,
        org_id: ORG.into(),
        project_id: PROJECT.into(),
        target_id: TARGET.into(),
        observer_revision: "1".into(),
        observer_key_fingerprint: fw_native_evidence::fingerprint(&public)?,
        reference_revision: pin.reference_revision.clone(),
        compilation_hash: compilation.evidence_hash().into(),
        metadata_receipt_hash: synthetic_metadata.clone(),
        metadata_report_hash: synthetic_metadata,
        baseline_state_hash: bundle.previous.desired_state_hash,
        expected_head: None,
        authority_epoch: "1".into(),
        generation: "1".into(),
        artifact_role,
        artifact_hash: artifact.artifact_hash()?,
        installation_hash: h(&installation)?,
        nonce: base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(random_bytes()?),
        issued_at: iso(at),
        expires_at: iso(at + 120),
    };
    checked_stage(challenge.validate(at), "CORE_OBS_CHALLENGE_WINDOW")?;
    checked_stage(
        save(&path.join(format!("artifact-{role}.json")), artifact),
        "CORE_OBS_ARTIFACT_SAVE",
    )?;
    checked_stage(
        save(
            &path.join(format!("installation-{role}.json")),
            &installation,
        ),
        "CORE_OBS_INSTALLATION_SAVE",
    )?;
    checked_stage(
        save(&path.join(format!("challenge-{role}.json")), &challenge),
        "CORE_OBS_CHALLENGE_SAVE",
    )?;
    Ok(
        json!({"compilation_hash":compilation.evidence_hash(),"challenge_hash":challenge.hash()?,
            "reference_pin_hash":h(&pin)?,"references_hash":compilation.references_hash(),
            "expected_artifact_hash":challenge.artifact_hash,"submitted_artifact_hash":submitted_artifact_hash,
            "reference_revision":pin.reference_revision,"reference_source":"separate-trusted-lab-input",
            "synthetic_observer_trust":true,"authority_admission_performed":false,"production_authorized":false}),
    )
}

pub(super) fn verify_observation(path: &Path, role: &str, proof_path: &Path) -> Result<Value> {
    guard()?;
    directory(path, false)?;
    let (bundle, artifact_role, _) = observation_objects(path, role)?;
    let (pin, compilation) = pinned_compilation(path, &bundle)?;
    let submitted_artifact_hash = match artifact_role {
        ArtifactRole::Baseline => bundle.previous.artifact_hash()?,
        ArtifactRole::Candidate => bundle.candidate.artifact_hash()?,
    };
    let challenge: NativeObservationChallenge = read(&path.join(format!("challenge-{role}.json")))?;
    let proof: SignedNativeObservation = read(proof_path)?;
    let public: [u8; 32] = read(&path.join("observer-public.json"))?;
    let metadata: Value = read(&path.join("metadata.json"))?;
    let trust_until = metadata["not_before_unix"].as_i64().ok_or("fixture time")? + 3600;
    if challenge.artifact_role != artifact_role
        || challenge.compilation_hash != compilation.evidence_hash()
        || challenge.reference_revision != pin.reference_revision
    {
        return Err("core observation binding".into());
    }
    let verified = fw_native_evidence::verify_observation(
        &challenge,
        &proof,
        &public,
        compilation.artifact(artifact_role),
        now(),
        trust_until,
    )?;
    if verified.comparison() != fw_backend_linux::Comparison::Match
        || verified.observed_state_hash()
            != Some(
                compilation
                    .artifact(artifact_role)
                    .desired_state_hash
                    .as_str(),
            )
    {
        return Err("core native observation mismatch".into());
    }
    Ok(
        json!({"comparison":"match","observed_state_hash":verified.observed_state_hash(),"readback_hash":verified.readback_hash(),"proof_hash":h(&proof)?,
            "reference_pin_hash":h(&pin)?,"references_hash":compilation.references_hash(),
            "expected_artifact_hash":challenge.artifact_hash,"submitted_artifact_hash":submitted_artifact_hash,
            "reference_revision":pin.reference_revision,"reference_source":"separate-trusted-lab-input",
            "synthetic_observer_trust":true,"authority_admission_performed":false,"production_authorized":false}),
    )
}

pub(super) fn forge_target(path: &Path, output: &Path) -> Result<Value> {
    guard()?;
    directory(path, false)?;
    let mut bundle: CoreAccessExecutionBundle = read(&path.join("bundle.json"))?;
    bundle.grant.payload["target_id"] = json!(id()?);
    let key = secret(&path.join("grant-secret.json"))?;
    let bytes = canonical_bytes(&bundle.grant.payload)?;
    bundle.grant.dsse.payload = STANDARD.encode(&bytes);
    bundle.grant.dsse.signatures[0].sig =
        STANDARD.encode(key.sign(&pae(CORE_GRANT_TYPE, &bytes)).to_bytes());
    save(output, &bundle)?;
    Ok(json!({"valid_signature_wrong_target":true,"production_authorized":false}))
}

pub(super) fn confirmation(path: &Path, probe_path: &Path, output: &Path) -> Result<Value> {
    guard()?;
    directory(path, false)?;
    let bundle: CoreAccessExecutionBundle = read(&path.join("bundle.json"))?;
    let probes: ProbeReport = read(probe_path)?;
    if probes.operation_id != bundle.operation_id
        || probes.grant_hash != h(&bundle.grant)?
        || probes.state_hash != bundle.candidate.desired_state_hash
        || probes.observations.len() != bundle.probes.len()
        || probes.production_management_probe
    {
        return Err("core fixture probe binding".into());
    }
    let cap = DateTime::parse_from_rfc3339(
        bundle.grant.payload["confirm_not_after"]
            .as_str()
            .ok_or("confirm cap")?,
    )?
    .timestamp();
    let payload = Confirmation {
        schema_version: "fw.experimental-confirm/v1".into(),
        operation_id: bundle.operation_id,
        org_id: ORG.into(),
        target_id: TARGET.into(),
        authority_epoch: "1".into(),
        target_generation: bundle.plan["target_generation"]
            .as_str()
            .ok_or("generation")?
            .into(),
        grant_hash: h(&bundle.grant)?,
        state_hash: bundle.candidate.desired_state_hash,
        probe_report_hash: h(&probes)?,
        issued_at_unix: now(),
        not_after_unix: cap,
    };
    let bytes = canonical_bytes(&payload)?;
    let key = secret(&path.join("confirm-secret.json"))?;
    let envelope = DsseEnvelope {
        payload_type: CONFIRM_TYPE.into(),
        payload: STANDARD.encode(&bytes),
        signatures: vec![DsseSignature {
            keyid: "isolated-confirm".into(),
            sig: STANDARD.encode(key.sign(&pae(CONFIRM_TYPE, &bytes)).to_bytes()),
        }],
    };
    save(
        output,
        &ConfirmationEvidence {
            schema_version: "fw.isolated-confirmation-evidence/v1".into(),
            confirmation: envelope,
            probes,
        },
    )?;
    Ok(json!({"synthetic_confirmation_authority":true,"production_authorized":false}))
}

#[cfg(test)]
mod reference_pin_tests {
    use super::*;

    fn fixture() -> (CoreLabReferencePin, fw_backend_linux::PortableArtifact) {
        let scope = json!({"schema_version":"fw.isolated-lab-scope/v1","org_id":ORG,
            "project_id":PROJECT,"target_id":TARGET,"network_namespace":"net:[12345]",
            "interfaces":["lo"],"conntrack_zone":0});
        let scope_hash = h(&scope).unwrap();
        let refs: LabReferences = serde_json::from_value(json!({"scope":scope,
            "baseline":{"schema_version":"fw.isolated-lab-baseline/v1","scope_hash":scope_hash,"management_paths":[],"default_action":"drop"},
            "source_snapshot":{"schema_version":"fw.isolated-lab-snapshot/v1","scope_hash":scope_hash,"assets":[]},
            "capability":{"schema_version":"fw.isolated-lab-capability/v1","scope_hash":scope_hash,"platform":"linux","profile":"host-tcp-udp-lab","production_qualified":false}})).unwrap();
        let state = state_for(&refs);
        let artifact = compile_portable(&state, &refs).unwrap();
        (
            CoreLabReferencePin {
                schema_version: "fw.core-lab-reference-pin/v1".into(),
                reference_revision: "1".into(),
                production_authorized: false,
                references: refs,
            },
            artifact,
        )
    }

    fn state_for(refs: &LabReferences) -> StateIr {
        serde_json::from_value(json!({"schema_version":"f.state-ir/v1","target_id":TARGET,
            "platform":"linux","profile":"lab","policies":[],"associations":[],"tombstone_hashes":[],
            "management_baseline_hash":h(&refs.baseline).unwrap(),
            "source_snapshot_hash":h(&refs.source_snapshot).unwrap(),
            "target_capability_hash":h(&refs.capability).unwrap(),"normalization_version":"f.normalize/nfc-v1"})).unwrap()
    }

    #[test]
    fn separate_reference_pin_binds_both_artifacts_and_is_closed_lab_only_input() {
        let (pin, artifact) = fixture();
        pin.bind_artifacts(&artifact, &artifact).unwrap();
        let mut production = pin.clone();
        production.production_authorized = true;
        assert!(production.bind_artifacts(&artifact, &artifact).is_err());
        for revision in ["0", "01", "", "18446744073709551616"] {
            let mut invalid = pin.clone();
            invalid.reference_revision = revision.into();
            assert!(invalid.bind_artifacts(&artifact, &artifact).is_err());
        }
        let mut extra = serde_json::to_value(&pin).unwrap();
        extra["trust_submitted_references"] = json!(true);
        assert!(serde_json::from_value::<CoreLabReferencePin>(extra).is_err());
    }

    #[test]
    fn coherent_submitted_reference_replacement_cannot_supply_its_own_pin() {
        let (pin, original) = fixture();
        let mut untrusted = pin.references.clone();
        untrusted.scope.network_namespace = "net:[54321]".into();
        let changed_scope_hash = h(&untrusted.scope).unwrap();
        untrusted.baseline.scope_hash = changed_scope_hash.clone();
        untrusted.source_snapshot.scope_hash = changed_scope_hash.clone();
        untrusted.capability.scope_hash = changed_scope_hash;
        let replacement = compile_portable(&state_for(&untrusted), &untrusted).unwrap();
        // The old self-reference path validates this coherent artifact. Its
        // independent original pin must reject either role's substitution.
        replacement.validate().unwrap();
        assert!(pin.bind_artifacts(&original, &replacement).is_err());
        assert!(pin.bind_artifacts(&replacement, &original).is_err());
        assert!(pin.bind_artifacts(&replacement, &replacement).is_err());
    }

    #[test]
    fn matching_references_do_not_hide_changed_native_artifact_bytes() {
        let (pin, original) = fixture();
        let mut changed = original.clone();
        changed.nft_template = json!({"nftables":[{"flush":{"ruleset":null}}]});
        assert!(pin.bind_artifacts(&original, &changed).is_err());
        assert!(pin.bind_artifacts(&changed, &original).is_err());
    }
}
