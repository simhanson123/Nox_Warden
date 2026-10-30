//! Synthetic signing material exclusively for the disposable signed-execution lab.
//! This binary does not implement WebAuthn, human approval or production authority.
//! It refuses to generate or use keys outside the explicitly isolated namespace.
use base64::{engine::general_purpose::STANDARD, Engine};
use chrono::{DateTime, Utc};
use ed25519_dalek::{Signer, SigningKey};
use fw_authority::{
    pae, sign_grant, AuthorityEvidence, DsseEnvelope, DsseSignature, GrantContext, CORE_GRANT_TYPE,
};
use fw_backend_linux::{
    bind_at, compile_portable, restrictive_recovery, BindingContext, LabReferences,
};
use fw_contracts::{canonical_bytes, canonical_hash, parse_strict_with_limit};
use fw_domain::Policy;
use fw_executor::Confirmation;
use fw_linux_executor::{
    ConfirmationEvidence, ExecutionBundle, LabApproval, LabKey, LabPlan, LabTrust, ProbeReport,
    ProbeSpec, CONFIRM_TYPE,
};
use fw_planner::{PolicyAssociation, StateIr};
use serde::{de::DeserializeOwned, Serialize};
use serde_json::{json, Value};
use std::{
    fs::{self, OpenOptions},
    io::{Read, Write},
    os::unix::fs::{DirBuilderExt, MetadataExt, OpenOptionsExt},
    path::{Component, Path},
    time::{SystemTime, UNIX_EPOCH},
};

const ORG: &str = "11111111-1111-4111-8111-111111111111";
const PROJECT: &str = "22222222-2222-4222-8222-222222222222";
const TARGET: &str = "33333333-3333-4333-8333-333333333333";
const PRINCIPAL: &str = "44444444-4444-4444-8444-444444444444";
const SOURCE: &str = "55555555-5555-4555-8555-555555555555";
const DESTINATION: &str = "66666666-6666-4666-8666-666666666666";
const LEASE: &str = "77777777-7777-4777-8777-777777777777";
const REQUEST: &str = "88888888-8888-4888-8888-888888888888";
type Result<T> = std::result::Result<T, Box<dyn std::error::Error>>;
fn now() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64
}
fn iso(time: i64) -> String {
    DateTime::<Utc>::from_timestamp(time, 0)
        .unwrap()
        .format("%Y-%m-%dT%H:%M:%SZ")
        .to_string()
}
fn h<T: Serialize>(value: &T) -> Result<String> {
    Ok(canonical_hash(value)?)
}
fn random_bytes() -> Result<[u8; 32]> {
    let mut bytes = [0; 32];
    fs::File::open("/dev/urandom")?.read_exact(&mut bytes)?;
    Ok(bytes)
}
fn id() -> Result<String> {
    let mut bytes = random_bytes()?;
    bytes[6] = (bytes[6] & 15) | 64;
    bytes[8] = (bytes[8] & 63) | 128;
    let hex: String = bytes[..16].iter().map(|b| format!("{b:02x}")).collect();
    Ok(format!(
        "{}-{}-{}-{}-{}",
        &hex[..8],
        &hex[8..12],
        &hex[12..16],
        &hex[16..20],
        &hex[20..]
    ))
}
fn guard() -> Result<(String, String)> {
    if fs::read_to_string("/lab/DISPOSABLE_NETWORK_NAMESPACE")? != "nox-linux-loopback-lab-v1\n" {
        return Err("lab marker".into());
    }
    let namespace = fs::read_link("/proc/self/ns/net")?
        .to_string_lossy()
        .into_owned();
    let outer = std::env::var("NOX_LAB_OUTER_NETNS")?;
    if !outer.starts_with("net:[") || outer == namespace {
        return Err("namespace separation".into());
    }
    let names = fs::read_dir("/sys/class/net")?
        .map(|e| e.map(|v| v.file_name()))
        .collect::<std::result::Result<Vec<_>, _>>()?;
    if names.len() != 1 || names[0] != "lo" {
        return Err("loopback-only scope".into());
    }
    let boot = fs::read_to_string("/proc/sys/kernel/random/boot_id")?
        .trim()
        .to_owned();
    Ok((namespace, boot))
}
fn directory(path: &Path, create: bool) -> Result<()> {
    if !path.is_absolute()
        || !path.starts_with("/lab")
        || path.components().any(|c| matches!(c, Component::ParentDir))
    {
        return Err("private lab path".into());
    }
    if create {
        fs::DirBuilder::new().mode(0o700).create(path)?;
    }
    let metadata = fs::symlink_metadata(path)?;
    if !metadata.is_dir()
        || metadata.file_type().is_symlink()
        || metadata.uid() != 0
        || metadata.mode() & 0o077 != 0
    {
        return Err("private lab directory".into());
    }
    Ok(())
}
fn write(path: &Path, bytes: &[u8]) -> Result<()> {
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)?;
    file.write_all(bytes)?;
    file.sync_all()?;
    Ok(())
}
fn save<T: Serialize>(path: &Path, value: &T) -> Result<()> {
    write(path, &canonical_bytes(value)?)
}
fn read<T: DeserializeOwned>(path: &Path) -> Result<T> {
    let m = fs::symlink_metadata(path)?;
    if !m.is_file()
        || m.file_type().is_symlink()
        || m.uid() != 0
        || m.nlink() != 1
        || m.mode() & 0o077 != 0
        || m.len() > 16 * 1024 * 1024
    {
        return Err("private fixture input".into());
    }
    Ok(parse_strict_with_limit(&fs::read(path)?, 16 * 1024 * 1024)?)
}
fn secret(path: &Path) -> Result<SigningKey> {
    let encoded: String = read(path)?;
    let bytes: [u8; 32] = STANDARD
        .decode(encoded)?
        .try_into()
        .map_err(|_| "fixture key length")?;
    Ok(SigningKey::from_bytes(&bytes))
}
struct FixtureAuthority(GrantContext);
impl AuthorityEvidence for FixtureAuthority {
    fn verify_for_signing(&self, _: &Value, _: i64) -> fw_authority::Result<GrantContext> {
        Ok(self.0.clone())
    }
}
fn policy(
    number: usize,
    family: &str,
    protocol: &str,
    direction: &str,
    port: u16,
    action: &str,
    time_bounds: (i64, i64),
) -> Result<Policy> {
    let (at, expiry) = time_bounds;
    let address = if family == "ipv4" {
        "127.0.0.1/32"
    } else {
        "::1/128"
    };
    Ok(serde_json::from_value(
        json!({"schema_version":"f.policy/v1", "policy_id":format!("00000000-0000-4000-8000-{number:012}"),
        "policy_revision":1,"org_id":ORG,"project_id":PROJECT,"target_id":TARGET,"owner_id":PRINCIPAL,
        "reason":"Synthetic isolated signed execution fixture","scope":{"family":family,"direction":direction,
        "source_asset_ids":[SOURCE],"destination_asset_ids":[DESTINATION],"source_cidrs":[address],"destination_cidrs":[address],
        "transport":{"protocol":protocol,"destination_ports":[{"start":port,"end":port}]},
        "ingress_interfaces":if direction=="input" { vec!["lo"] } else { vec![] },
        "egress_interfaces":if direction=="output" { vec!["lo"] } else { vec![] }},
        "action":action,"log_mode":"none","lifetime":if action=="allow" {
            json!({"kind":"lease","not_before":iso(at-40),"expires_at":iso(expiry)})
        } else { json!({"kind":"review","not_before":iso(at-40),"review_at":iso(at+3600)}) }}),
    )?)
}
fn prepare(path: &Path, mode: &str) -> Result<Value> {
    let (namespace, boot) = guard()?;
    directory(path, true)?;
    let at = now();
    let expiry = at + 35;
    let operation = id()?;
    let plan_id = id()?;
    let grant_key = SigningKey::from_bytes(&random_bytes()?);
    let confirm_key = SigningKey::from_bytes(&random_bytes()?);
    save(
        &path.join("grant-secret.json"),
        &STANDARD.encode(grant_key.to_bytes()),
    )?;
    save(
        &path.join("confirm-secret.json"),
        &STANDARD.encode(confirm_key.to_bytes()),
    )?;
    let scope = json!({"schema_version":"fw.isolated-lab-scope/v1","org_id":ORG,"project_id":PROJECT,"target_id":TARGET,
        "network_namespace":namespace,"interfaces":["lo"],"conntrack_zone":0});
    let scope_hash = h(&scope)?;
    let baseline = json!({"schema_version":"fw.isolated-lab-baseline/v1","scope_hash":scope_hash,"management_paths":[],"default_action":"drop"});
    let snapshot = json!({"schema_version":"fw.isolated-lab-snapshot/v1","scope_hash":scope_hash,"assets":[
        {"asset_id":SOURCE,"cidrs":["127.0.0.1/32","::1/128"]},{"asset_id":DESTINATION,"cidrs":["127.0.0.1/32","::1/128"]}]});
    let capability = json!({"schema_version":"fw.isolated-lab-capability/v1","scope_hash":scope_hash,"platform":"linux","profile":"host-tcp-udp-lab","production_qualified":false});
    let refs: LabReferences = serde_json::from_value(
        json!({"scope":scope,"baseline":baseline,"source_snapshot":snapshot,"capability":capability}),
    )?;
    let previous_state = StateIr {
        schema_version: "f.state-ir/v1".into(),
        target_id: TARGET.into(),
        platform: "linux".into(),
        profile: "lab".into(),
        management_baseline_hash: h(&refs.baseline)?,
        policies: vec![],
        associations: vec![],
        tombstone_hashes: vec![],
        source_snapshot_hash: h(&refs.source_snapshot)?,
        target_capability_hash: h(&refs.capability)?,
        normalization_version: "f.normalize/nfc-v1".into(),
    };
    let previous = compile_portable(&previous_state, &refs)?;
    let mut state = previous_state.clone();
    for family in ["ipv4", "ipv6"] {
        for direction in ["input", "output"] {
            for (protocol, port, action) in [
                ("tcp", 18080, "allow"),
                ("udp", 18081, "allow"),
                ("tcp", 18082, "deny"),
            ] {
                state.policies.push(policy(
                    state.policies.len() + 1,
                    family,
                    protocol,
                    direction,
                    port,
                    action,
                    (at, expiry),
                )?);
            }
        }
    }
    for p in &state.policies {
        state.associations.push(PolicyAssociation {
            policy_hash: h(p)?,
            lease_id: if p.action == fw_domain::Action::Allow {
                Some(LEASE.into())
            } else {
                None
            },
            request_id: REQUEST.into(),
            authority_basis_hash: h(&json!({"synthetic_fixture_authority":true}))?,
        });
    }
    let candidate = compile_portable(&state, &refs)?;
    let recovery = restrictive_recovery(&previous, &candidate)?;
    let previous_installation = bind_at(
        &previous,
        &BindingContext {
            operation_id: id()?,
            grant_hash: h(&json!({"synthetic_bootstrap_fixture":true}))?,
            boot_id: boot.clone(),
            network_namespace: namespace.clone(),
            wall_time_unix: at,
            monotonic_millis: monotonic_millis()?,
            clock_uncertainty_seconds: 0,
            elapsed_seconds: 0,
            commit_budget_seconds: 1,
        },
    )?;
    let confirm_cap = at + 22;
    let recovery_until = if mode == "expired-recovery" {
        confirm_cap
    } else {
        at + 180
    };
    let mut probes = Vec::new();
    for family in ["ipv4", "ipv6"] {
        for (protocol, port, expect_reply) in [
            ("tcp", 18080, true),
            ("udp", 18081, true),
            ("tcp", 18082, false),
        ] {
            probes.push(ProbeSpec {
                name: format!("{family}-{protocol}-{port}"),
                family: family.into(),
                protocol: protocol.into(),
                port,
                expect_reply,
            });
        }
    }
    let plan = LabPlan {
        schema_version: "fw.isolated-lab-plan/v1".into(),
        plan_id: plan_id.clone(),
        org_id: ORG.into(),
        project_id: PROJECT.into(),
        target_id: TARGET.into(),
        authority_epoch: "1".into(),
        target_generation: "1".into(),
        baseline_hash: previous.desired_state_hash.clone(),
        desired_state_hash: candidate.desired_state_hash.clone(),
        artifact_hash: candidate.artifact_hash()?,
        recovery_artifact_hash: recovery.artifact_hash()?,
        recovery_scope_hash: scope_hash.clone(),
        valid_until_unix: confirm_cap,
        probes,
    };
    let approval = LabApproval {
        schema_version: "fw.isolated-lab-approval/v1".into(),
        kind: "synthetic_test_fixture".into(),
        plan_hash: h(&plan)?,
        principal_id: PRINCIPAL.into(),
        valid_until_unix: confirm_cap,
    };
    let requested = state
        .policies
        .iter()
        .filter(|p| p.action == fw_domain::Action::Allow)
        .map(h)
        .collect::<Result<std::collections::BTreeSet<_>>>()?;
    let payload = json!({"schema_version":"f.grant/v1","grant_id":id()?,"plan_id":plan_id,"plan_hash":h(&plan)?,"org_id":ORG,"project_id":PROJECT,"target_id":TARGET,"principal_id":PRINCIPAL,"approval_set_hash":h(&approval)?,"authority_epoch":"1","target_generation":"1","issued_at":iso(at),"not_after":iso(at+20),"artifact_hash":candidate.artifact_hash()?,"baseline_hash":previous.desired_state_hash,"confirm_timeout_seconds":60,"confirm_not_after":iso(confirm_cap),"rollback_authority":{"profile":"preserve-current-restrictions","scope_bound_hash":scope_hash,"baseline_hash":previous.desired_state_hash,"artifact_hash":recovery.artifact_hash()?,"valid_until":iso(recovery_until)},"change_kind":"add_access_lease","request_patch_hash":h(&json!({"synthetic_patch":state.policies}))?,"desired_state_hash":candidate.desired_state_hash,"lease_id":LEASE,"request_id":REQUEST,"workload_binding_id":id()?,"requested_policy_hashes":requested,"envelope_hash":h(&json!({"synthetic_envelope":true}))?,"delegation_hash":h(&json!({"synthetic_delegation":true}))?,"reservation":{"reservation_id":id()?,"root_id":id()?,"status":"reserved","reserved_until":iso(at+20),"projected_active_leases":1,"projected_new_leases_per_day":1,"projected_unique_destinations_per_day":1,"projected_cumulative_lease_seconds_per_day":75,"projected_concurrent_deployments":1,"window_start":iso(at-86400),"window_end":iso(at)}});
    let context = GrantContext {
        org_id: ORG.into(),
        project_id: PROJECT.into(),
        target_id: TARGET.into(),
        plan_hash: h(&plan)?,
        artifact_hash: candidate.artifact_hash()?,
        baseline_hash: previous.desired_state_hash.clone(),
        desired_state_hash: candidate.desired_state_hash.clone(),
        approval_set_hash: h(&approval)?,
        authority_epoch: 1,
        now_unix: at,
    };
    let grant = sign_grant(
        payload,
        "isolated-grant",
        &grant_key,
        &FixtureAuthority(context),
        at,
    )?;
    let bundle = ExecutionBundle {
        schema_version: "fw.isolated-execution-bundle/v1".into(),
        operation_id: operation.clone(),
        plan,
        approval,
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
        not_before_unix: at - 1,
        not_after_unix: at + 3600,
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
    save(&path.join("bundle.json"), &bundle)?;
    save(&path.join("trust.json"), &trust)?;
    save(
        &path.join("bootstrap.json"),
        &bundle.previous_installation.native.nft_json,
    )?;
    let metadata = json!({"operation_id":operation,"table":bundle.candidate.table,"expires_at_unix":expiry,"confirm_not_after_unix":confirm_cap,"recovery_valid_until_unix":recovery_until,"synthetic_fixture_authority":true,"production_authorized":false});
    save(&path.join("metadata.json"), &metadata)?;
    Ok(metadata)
}
fn monotonic_millis() -> Result<u64> {
    let mut sample = libc::timespec {
        tv_sec: 0,
        tv_nsec: 0,
    };
    // SAFETY: sample is a valid initialized timespec pointer and CLOCK_BOOTTIME
    // is a supported Linux clock. The fixture shares the driver's host clock.
    if unsafe { libc::clock_gettime(libc::CLOCK_BOOTTIME, &mut sample) } != 0 {
        return Err("monotonic clock".into());
    }
    Ok((sample.tv_sec as u64) * 1000 + (sample.tv_nsec as u64) / 1_000_000)
}
fn confirmation(path: &Path, probe_path: &Path, output: &Path, bundle_name: &str) -> Result<Value> {
    guard()?;
    directory(path, false)?;
    let bundle: ExecutionBundle = read(&path.join(bundle_name))?;
    let probes: ProbeReport = read(probe_path)?;
    let grant_hash = h(&bundle.grant)?;
    if probes.operation_id != bundle.operation_id
        || probes.grant_hash != grant_hash
        || probes.state_hash != bundle.candidate.desired_state_hash
        || probes.observations.len() != bundle.plan.probes.len()
        || probes.production_management_probe
    {
        return Err("fixture probe binding".into());
    }
    let at = now();
    let until = DateTime::parse_from_rfc3339(
        bundle.grant.payload["confirm_not_after"]
            .as_str()
            .ok_or("confirm cap")?,
    )?
    .timestamp();
    let payload = Confirmation {
        schema_version: "fw.experimental-confirm/v1".into(),
        operation_id: bundle.operation_id.clone(),
        org_id: ORG.into(),
        target_id: TARGET.into(),
        authority_epoch: "1".into(),
        target_generation: bundle.plan.target_generation.clone(),
        grant_hash,
        state_hash: bundle.candidate.desired_state_hash,
        probe_report_hash: h(&probes)?,
        issued_at_unix: at,
        not_after_unix: until,
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
fn forge(path: &Path, kind: &str, output: &Path) -> Result<Value> {
    guard()?;
    directory(path, false)?;
    let mut bundle: ExecutionBundle = read(&path.join("bundle.json"))?;
    match kind {
        "wrong-target" => bundle.grant.payload["target_id"] = id()?.into(),
        "old-generation" => {
            bundle.operation_id = id()?;
            bundle.plan.target_generation = "0".into();
            bundle.approval.plan_hash = h(&bundle.plan)?;
            bundle.grant.payload["target_generation"] = "0".into();
            bundle.grant.payload["plan_hash"] = h(&bundle.plan)?.into();
            bundle.grant.payload["approval_set_hash"] = h(&bundle.approval)?.into();
        }
        _ => return Err("unsupported negative fixture".into()),
    }
    // Deliberately valid cryptography for an invalid binding, rather than merely
    // corrupting a signature. The real driver must reject the exact scope/fence.
    let key = secret(&path.join("grant-secret.json"))?;
    let bytes = canonical_bytes(&bundle.grant.payload)?;
    bundle.grant.dsse.payload = STANDARD.encode(&bytes);
    bundle.grant.dsse.signatures[0].sig =
        STANDARD.encode(key.sign(&pae(CORE_GRANT_TYPE, &bytes)).to_bytes());
    save(output, &bundle)?;
    Ok(json!({"negative_fixture":kind,"production_authorized":false}))
}
fn successor(path: &Path) -> Result<Value> {
    guard()?;
    directory(path, false)?;
    let original: ExecutionBundle = read(&path.join("bundle.json"))?;
    let sidecar: Value =
        read(&path.join(format!("state/recovery-{}.json", original.operation_id)))?;
    let previous_installation = serde_json::from_value(sidecar["installation"].clone())?;
    let previous = original.recovery.clone();
    let at = now();
    let expiry = at + 35;
    let lease_id = id()?;
    let request_id = id()?;
    let mut state = previous.state.clone();
    for family in ["ipv4", "ipv6"] {
        for direction in ["input", "output"] {
            for (protocol, port) in [("tcp", 18080), ("udp", 18081)] {
                let mut p = policy(
                    state.policies.len() + 101,
                    family,
                    protocol,
                    direction,
                    port,
                    "allow",
                    (at, expiry),
                )?;
                p.policy_id = id()?;
                state.associations.push(PolicyAssociation {
                    policy_hash: h(&p)?,
                    lease_id: Some(lease_id.clone()),
                    request_id: request_id.clone(),
                    authority_basis_hash: h(
                        &json!({"synthetic_fixture_authority":true,"generation":2}),
                    )?,
                });
                state.policies.push(p);
            }
        }
    }
    let candidate = compile_portable(&state, &previous.references)?;
    let recovery = restrictive_recovery(&previous, &candidate)?;
    let mut plan = original.plan.clone();
    plan.plan_id = id()?;
    plan.target_generation = "2".into();
    plan.baseline_hash = previous.desired_state_hash.clone();
    plan.desired_state_hash = candidate.desired_state_hash.clone();
    plan.artifact_hash = candidate.artifact_hash()?;
    plan.recovery_artifact_hash = recovery.artifact_hash()?;
    plan.valid_until_unix = at + 22;
    let mut approval = original.approval.clone();
    approval.plan_hash = h(&plan)?;
    approval.valid_until_unix = plan.valid_until_unix;
    let mut payload = original.grant.payload.clone();
    payload["grant_id"] = id()?.into();
    payload["plan_id"] = plan.plan_id.clone().into();
    payload["plan_hash"] = h(&plan)?.into();
    payload["approval_set_hash"] = h(&approval)?.into();
    payload["target_generation"] = "2".into();
    payload["issued_at"] = iso(at).into();
    payload["not_after"] = iso(at + 20).into();
    payload["confirm_not_after"] = iso(at + 22).into();
    payload["artifact_hash"] = candidate.artifact_hash()?.into();
    payload["baseline_hash"] = previous.desired_state_hash.clone().into();
    payload["desired_state_hash"] = candidate.desired_state_hash.clone().into();
    payload["lease_id"] = lease_id.into();
    payload["request_id"] = request_id.into();
    payload["request_patch_hash"] = h(&state.policies)?.into();
    payload["requested_policy_hashes"] = serde_json::to_value(
        state
            .policies
            .iter()
            .filter(|p| p.action == fw_domain::Action::Allow)
            .map(h)
            .collect::<Result<std::collections::BTreeSet<_>>>()?,
    )?;
    payload["rollback_authority"]["baseline_hash"] = previous.desired_state_hash.clone().into();
    payload["rollback_authority"]["artifact_hash"] = recovery.artifact_hash()?.into();
    payload["rollback_authority"]["valid_until"] = iso(at + 180).into();
    payload["reservation"]["reservation_id"] = id()?.into();
    payload["reservation"]["reserved_until"] = iso(at + 20).into();
    payload["reservation"]["window_start"] = iso(at - 86400).into();
    payload["reservation"]["window_end"] = iso(at).into();
    payload["reservation"]["projected_new_leases_per_day"] = 2.into();
    payload["reservation"]["projected_cumulative_lease_seconds_per_day"] = 150.into();
    let context = GrantContext {
        org_id: ORG.into(),
        project_id: PROJECT.into(),
        target_id: TARGET.into(),
        plan_hash: h(&plan)?,
        artifact_hash: candidate.artifact_hash()?,
        baseline_hash: previous.desired_state_hash.clone(),
        desired_state_hash: candidate.desired_state_hash.clone(),
        approval_set_hash: h(&approval)?,
        authority_epoch: 1,
        now_unix: at,
    };
    let key = secret(&path.join("grant-secret.json"))?;
    let grant = sign_grant(
        payload,
        "isolated-grant",
        &key,
        &FixtureAuthority(context),
        at,
    )?;
    let operation = id()?;
    let bundle = ExecutionBundle {
        schema_version: original.schema_version,
        operation_id: operation.clone(),
        plan,
        approval,
        grant,
        previous,
        candidate,
        recovery,
        previous_installation,
    };
    save(&path.join("bundle-next.json"), &bundle)?;
    let metadata = json!({"operation_id":operation,"table":bundle.candidate.table,"expires_at_unix":expiry,
        "confirm_not_after_unix":at+22,"recovery_valid_until_unix":at+180,"synthetic_fixture_authority":true,"production_authorized":false});
    save(&path.join("metadata-next.json"), &metadata)?;
    Ok(metadata)
}

fn run() -> Result<Value> {
    let args: Vec<String> = std::env::args().skip(1).collect();
    match args.as_slice() {
        [command, path, mode] if command == "prepare" && ["confirmed", "crash", "timeout", "expired-recovery"].contains(&mode.as_str()) => prepare(Path::new(path), mode),
        [command, path, probe, output] if command == "confirm" || command == "confirm-next" => confirmation(Path::new(path), Path::new(probe), Path::new(output), if command == "confirm-next" { "bundle-next.json" } else { "bundle.json" }),
        [command, path] if command == "successor" => successor(Path::new(path)),
        [command, path, kind, output] if command == "forge" => forge(Path::new(path), kind, Path::new(output)),
        _ => Err("usage: fw_signed_lab_fixture prepare DIR MODE; confirm|confirm-next DIR PROBE OUTPUT; successor DIR; forge DIR KIND OUTPUT".into())
    }
}

pub fn run_main() {
    match run() {
        Ok(value) => println!("{value}"),
        Err(_) => {
            eprintln!("ISOLATED_FIXTURE_FAILED");
            std::process::exit(1)
        }
    }
}
