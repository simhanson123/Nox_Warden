//! Native writes are confined to the deliberately disposable, loopback-only lab.
//! This binary has no signing key, approval endpoint, or production enable switch.
#[path = "files.rs"]
mod files;
#[path = "native.rs"]
pub(crate) mod native;
#[path = "probes.rs"]
mod probes;

use base64::{Engine, engine::general_purpose::STANDARD};
use fw_authority::{GrantContext, TrustKey, VerifiedGrant};
use fw_backend_linux::{
    Comparison, Installation, bind_at, restrictive_recovery, verify_installation_readback_at,
};
use fw_contracts::{canonical_hash, parse_strict};
use fw_executor::{ExecutionMaterial, ExecutorJournal, State};
use fw_linux_executor::*;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::collections::BTreeMap;
use std::fmt;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::thread;
use std::time::{Duration, Instant};

#[derive(Debug)]
pub struct Error(&'static str);
impl Error {
    fn new(code: &'static str) -> Self {
        Self(code)
    }
}
impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.0)
    }
}
impl std::error::Error for Error {}
impl From<std::io::Error> for Error {
    fn from(_: std::io::Error) -> Self {
        Self("PRIVATE_OR_NATIVE_IO")
    }
}
impl From<fw_executor::ExecutorError> for Error {
    fn from(error: fw_executor::ExecutorError) -> Self {
        // Only stable categories cross the process boundary; SQLite messages,
        // paths, original input and credential material never enter stderr.
        use fw_executor::ExecutorError;
        Self(match error {
            ExecutorError::Io(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                "JOURNAL_BUSY"
            }
            ExecutorError::Io(_) => "JOURNAL_IO_ERROR",
            ExecutorError::Db(_) => "JOURNAL_DATABASE_ERROR",
            ExecutorError::Replay => "JOURNAL_REPLAY",
            ExecutorError::Conflict => "JOURNAL_CONFLICT",
            ExecutorError::Binding => "JOURNAL_INVALID_BINDING",
            ExecutorError::Unresolved => "JOURNAL_UNRESOLVED",
            ExecutorError::Expired => "JOURNAL_EXPIRED",
            ExecutorError::Transition => "JOURNAL_INVALID_TRANSITION",
            ExecutorError::Signature => "JOURNAL_INVALID_SIGNATURE",
        })
    }
}
impl From<fw_backend_linux::CompileError> for Error {
    fn from(_: fw_backend_linux::CompileError) -> Self {
        Self("ARTIFACT_REJECTED")
    }
}
impl From<fw_authority::AuthorityError> for Error {
    fn from(_: fw_authority::AuthorityError) -> Self {
        Self("SIGNATURE_OR_BINDING_REJECTED")
    }
}
pub type Result<T> = std::result::Result<T, Error>;
fn hash<T: Serialize>(value: &T) -> Result<String> {
    canonical_hash(value).map_err(|_| Error::new("CANONICALIZATION"))
}
fn value<T: Serialize>(value: &T) -> Result<Value> {
    serde_json::to_value(value).map_err(|_| Error::new("SERIALIZATION"))
}
fn decode<T: serde::de::DeserializeOwned>(value: Value) -> Result<T> {
    serde_json::from_value(value).map_err(|_| Error::new("PERSISTED_SHAPE"))
}
fn number(text: &str) -> Result<u64> {
    text.parse::<u64>()
        .ok()
        .filter(|n| n.to_string() == text)
        .ok_or(Error::new("COUNTER"))
}
fn uuid(text: &str) -> Result<()> {
    if uuid::Uuid::parse_str(text).is_ok_and(|id| id.to_string() == text) {
        Ok(())
    } else {
        Err(Error::new("UUID"))
    }
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct InitialState {
    schema_version: String,
    trust_hash: String,
    boot_id: String,
    network_namespace: String,
    baseline: fw_backend_linux::PortableArtifact,
    installation: Installation,
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct StoredInstallation {
    schema_version: String,
    bundle: ExecutionBundle,
    installation: Installation,
    trust_hash: String,
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct WatchRequest {
    schema_version: String,
    operation_id: String,
    material_hash: String,
    nonce: String,
    stored: StoredInstallation,
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct WatchAck {
    schema_version: String,
    operation_id: String,
    material_hash: String,
    nonce: String,
    process_id: u32,
    boot_id: String,
    network_namespace: String,
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct RecoveryInstallation {
    schema_version: String,
    material_hash: String,
    installation: Installation,
}

fn trust(path: &Path) -> Result<LabTrust> {
    let t: LabTrust = files::read(path)?;
    let observed = native::guard()?;
    if t.schema_version != "fw.isolated-lab-trust/v1"
        || t.production_authorized
        || t.network_namespace != observed.network_namespace
        || t.boot_id != observed.boot_id
        || number(&t.authority_epoch)? == 0
    {
        return Err(Error::new("LAB_TRUST_BINDING"));
    }
    for id in [&t.org_id, &t.project_id, &t.target_id, &t.boot_id] {
        uuid(id)?;
    }
    if t.grant_key.key_id == t.confirm_key.key_id
        || t.grant_key.public_key == t.confirm_key.public_key
    {
        return Err(Error::new("KEY_PURPOSE_SEPARATION"));
    }
    Ok(t)
}
fn key(t: &LabTrust, k: &LabKey, expected_type: &str, now: i64) -> Result<TrustKey> {
    let bytes = STANDARD
        .decode(&k.public_key)
        .map_err(|_| Error::new("TRUST_KEY"))?;
    let public_key: [u8; 32] = bytes.try_into().map_err(|_| Error::new("TRUST_KEY"))?;
    if k.key_id.is_empty()
        || k.key_id.len() > 128
        || k.payload_type != expected_type
        || k.revoked
        || now < k.not_before_unix
        || now >= k.not_after_unix
        || k.not_after_unix <= k.not_before_unix
    {
        return Err(Error::new("TRUST_KEY_CURRENTNESS"));
    }
    Ok(TrustKey {
        key_id: k.key_id.clone(),
        org_id: t.org_id.clone(),
        payload_type: k.payload_type.clone(),
        public_key,
        not_before: k.not_before_unix,
        not_after: k.not_after_unix,
        revoked: k.revoked,
    })
}
fn verify_bundle(
    bundle: &ExecutionBundle,
    trust: &LabTrust,
    recovery: bool,
) -> Result<VerifiedGrant> {
    let p = &bundle.plan;
    let a = &bundle.approval;
    uuid(&bundle.operation_id)?;
    uuid(&p.plan_id)?;
    uuid(&a.principal_id)?;
    let now = native::now()?;
    if bundle.schema_version != "fw.isolated-execution-bundle/v1"
        || p.schema_version != "fw.isolated-lab-plan/v1"
        || a.schema_version != "fw.isolated-lab-approval/v1"
        || a.kind != "synthetic_test_fixture"
        || p.org_id != trust.org_id
        || p.project_id != trust.project_id
        || p.target_id != trust.target_id
        || p.authority_epoch != trust.authority_epoch
        || number(&p.target_generation)? == 0
        || p.baseline_hash != bundle.previous.desired_state_hash
        || p.desired_state_hash != bundle.candidate.desired_state_hash
        || p.artifact_hash != bundle.candidate.artifact_hash()?
        || p.recovery_artifact_hash != bundle.recovery.artifact_hash()?
        || p.recovery_scope_hash != bundle.recovery.scope_hash()?
        || a.plan_hash != hash(p)?
        || p.valid_until_unix > a.valid_until_unix
        || (!recovery && now >= p.valid_until_unix)
    {
        return Err(Error::new("IMMUTABLE_BUNDLE_BINDING"));
    }
    for artifact in [&bundle.previous, &bundle.candidate, &bundle.recovery] {
        artifact.validate()?;
        let scope = &artifact.references.scope;
        if scope.org_id != trust.org_id
            || scope.project_id != trust.project_id
            || scope.target_id != trust.target_id
            || scope.network_namespace != trust.network_namespace
            || artifact.table != bundle.candidate.table
        {
            return Err(Error::new("ARTIFACT_SCOPE"));
        }
    }
    if hash(&restrictive_recovery(&bundle.previous, &bundle.candidate)?)? != hash(&bundle.recovery)?
    {
        return Err(Error::new("RECOVERY_PROJECTION"));
    }
    probes::validate(&p.probes)?;
    let context = GrantContext {
        org_id: trust.org_id.clone(),
        project_id: trust.project_id.clone(),
        target_id: trust.target_id.clone(),
        plan_hash: hash(p)?,
        artifact_hash: p.artifact_hash.clone(),
        baseline_hash: p.baseline_hash.clone(),
        desired_state_hash: p.desired_state_hash.clone(),
        approval_set_hash: hash(a)?,
        authority_epoch: number(&trust.authority_epoch)?,
        now_unix: now,
    };
    let trusted_key = key(
        trust,
        &trust.grant_key,
        &bundle.grant.dsse.payload_type,
        now,
    )?;
    let verified = if recovery {
        fw_authority::verify_recovery_grant(&bundle.grant, &trusted_key, &context)?
    } else {
        fw_authority::verify_grant(&bundle.grant, &trusted_key, &context)?
    };
    let rollback = verified.rollback_authority();
    if verified.generation() != number(&p.target_generation)?
        || bundle.grant.payload["plan_id"] != p.plan_id
        || bundle.grant.payload["principal_id"] != a.principal_id
        || rollback.profile != "preserve-current-restrictions"
        || rollback.artifact_hash != p.recovery_artifact_hash
        || rollback.scope_bound_hash != p.recovery_scope_hash
        || p.valid_until_unix < verified.confirm_not_after()
        || a.valid_until_unix < verified.confirm_not_after()
    {
        return Err(Error::new("SIGNED_PLAN_RECOVERY_BINDING"));
    }
    Ok(verified)
}
fn initial(state: &Path, trust: &LabTrust) -> Result<InitialState> {
    files::directory(state)?;
    let saved: InitialState = files::read(&state.join("initial.json"))?;
    if saved.schema_version != "fw.isolated-executor-state/v1"
        || saved.trust_hash != hash(trust)?
        || saved.boot_id != trust.boot_id
        || saved.network_namespace != trust.network_namespace
    {
        return Err(Error::new("PINNED_STATE_MISMATCH"));
    }
    Ok(saved)
}
fn open_journal(path: &Path) -> Result<ExecutorJournal> {
    let started = Instant::now();
    Ok(loop {
        match ExecutorJournal::open(path) {
            Ok(journal) => break journal,
            Err(fw_executor::ExecutorError::Io(error))
                if error.kind() == std::io::ErrorKind::WouldBlock
                    && started.elapsed() < Duration::from_secs(5) =>
            {
                thread::sleep(Duration::from_millis(10));
            }
            Err(error) => return Err(error.into()),
        }
    })
}
fn journal(state: &Path, trusted: &LabTrust, trust_path: &Path) -> Result<ExecutorJournal> {
    initial(state, trusted)?;
    // A legitimate recovery owns the same fence across its bounded 2s native
    // write, readback and durable completion. One second was too short for a
    // concurrent reader. Retry only OS lock contention, for at most five seconds.
    let journal = open_journal(&state.join("journal.sqlite3"))?;
    // Waiting grants no extra authority: check current protected trust again
    // after acquiring the fence, and still verify every operation's time bounds.
    let current_trust = trust(trust_path)?;
    initial(state, &current_trust)?;
    if hash(&current_trust)? != hash(trusted)? {
        return Err(Error::new("PINNED_STATE_MISMATCH"));
    }
    let id = journal.identity()?;
    if id.org_id != trusted.org_id
        || id.target_id != trusted.target_id
        || id.authority_epoch != number(&trusted.authority_epoch)?
    {
        return Err(Error::new("JOURNAL_IDENTITY"));
    }
    Ok(journal)
}
fn stored(
    journal: &ExecutorJournal,
    id: &str,
    trust: &LabTrust,
) -> Result<(ExecutionMaterial, StoredInstallation)> {
    let material = journal
        .execution_material(id)?
        .ok_or(Error::new("MATERIAL_MISSING"))?;
    let saved: StoredInstallation = decode(material.installation_manifest.clone())?;
    if saved.schema_version != "fw.isolated-installation/v1"
        || saved.trust_hash != hash(trust)?
        || saved.bundle.operation_id != id
        || hash(&saved.bundle.grant)? != hash(&material.signed_grant)?
    {
        return Err(Error::new("MATERIAL_BINDING"));
    }
    Ok((material, saved))
}
fn read_match(
    artifact: &fw_backend_linux::PortableArtifact,
    install: &Installation,
) -> Result<fw_backend_linux::ReadbackVerification> {
    let actual = native::readback(&artifact.table)?;
    let result =
        verify_installation_readback_at(artifact, install, &actual, &native::observation()?);
    if result.comparison != Comparison::Match {
        return Err(Error::new("ACTUAL_READBACK_MISMATCH"));
    }
    Ok(result)
}
fn status_value(j: &ExecutorJournal, id: &str, extra: Value) -> Result<Value> {
    Ok(
        json!({"schema_version":"fw.isolated-executor-result/v1","operation":j.operation(id)?,
        "highest_generation":j.highest_generation()?.to_string(),"production_authorized":false,"evidence":extra}),
    )
}
fn init(state: &Path, bundle: &ExecutionBundle, trust: &LabTrust) -> Result<Value> {
    verify_bundle(bundle, trust, false)?;
    if !bundle.previous.tokens.is_empty() {
        return Err(Error::new("INITIAL_BASELINE_MUST_BE_RESTRICTIVE"));
    }
    read_match(&bundle.previous, &bundle.previous_installation)?;
    files::create_directory(state)?;
    let initial = InitialState {
        schema_version: "fw.isolated-executor-state/v1".into(),
        trust_hash: hash(trust)?,
        boot_id: trust.boot_id.clone(),
        network_namespace: trust.network_namespace.clone(),
        baseline: bundle.previous.clone(),
        installation: bundle.previous_installation.clone(),
    };
    files::write(&state.join("initial.json"), &initial)?;
    let j = ExecutorJournal::create(
        state.join("journal.sqlite3"),
        &trust.org_id,
        &trust.target_id,
        number(&trust.authority_epoch)?,
        &bundle.previous.desired_state_hash,
    )?;
    Ok(
        json!({"schema_version":"fw.isolated-executor-result/v1","initialized":true,"highest_generation":j.highest_generation()?.to_string(),"production_authorized":false}),
    )
}
fn observe(state: &Path, j: &mut ExecutorJournal, saved: &StoredInstallation) -> Result<Value> {
    let id = &saved.bundle.operation_id;
    let operation = j.operation(id)?.ok_or(Error::new("OPERATION_MISSING"))?;
    let observed = if operation.state == State::RolledBack {
        let recovery: RecoveryInstallation =
            files::read(&state.join(format!("recovery-{id}.json")))?;
        if recovery.schema_version != "fw.isolated-recovery-installation/v1"
            || Some(recovery.material_hash) != j.execution_material_hash(id)?
        {
            return Err(Error::new("RECOVERY_MATERIAL_BINDING"));
        }
        read_match(&saved.bundle.recovery, &recovery.installation)
    } else {
        read_match(&saved.bundle.candidate, &saved.installation)
    };
    match observed {
        Ok(report) => {
            if operation.state == State::Unknown {
                j.record_observation(
                    id,
                    &saved.bundle.candidate.desired_state_hash,
                    native::now()?,
                )?;
            }
            status_value(j, id, value(&report)?)
        }
        Err(error) => {
            if matches!(operation.state, State::Confirmed | State::RolledBack) {
                j.mark_drift(id, native::now()?)?;
            }
            Err(error)
        }
    }
}

fn material(saved: &StoredInstallation) -> Result<ExecutionMaterial> {
    let b = &saved.bundle;
    Ok(ExecutionMaterial {
        signed_grant: b.grant.clone(),
        baseline_state: value(&b.previous.state)?,
        candidate_state: value(&b.candidate.state)?,
        candidate_artifact: value(&b.candidate)?,
        recovery_state: value(&b.recovery.state)?,
        recovery_artifact: value(&b.recovery)?,
        recovery_scope: value(&b.recovery.references.scope)?,
        installation_manifest: value(saved)?,
        tombstone_watermark: json!({"schema_version":"fw.isolated-tombstones/v1","hashes":b.candidate.state.tombstone_hashes}),
    })
}
fn actual_baseline(
    state: &Path,
    j: &ExecutorJournal,
    trusted: &LabTrust,
) -> Result<(fw_backend_linux::PortableArtifact, Installation)> {
    if j.highest_generation()? == 0 {
        let initial = initial(state, trusted)?;
        return Ok((initial.baseline, initial.installation));
    }
    let latest = j
        .latest_operation()?
        .ok_or(Error::new("CURRENT_OPERATION_MISSING"))?;
    let (_, saved) = stored(j, &latest.operation_id, trusted)?;
    match latest.state {
        State::Confirmed => Ok((saved.bundle.candidate, saved.installation)),
        State::RolledBack => {
            let recovery: RecoveryInstallation =
                files::read(&state.join(format!("recovery-{}.json", latest.operation_id)))?;
            if Some(recovery.material_hash) != j.execution_material_hash(&latest.operation_id)? {
                return Err(Error::new("RECOVERY_MATERIAL_BINDING"));
            }
            Ok((saved.bundle.recovery, recovery.installation))
        }
        _ => Err(Error::new("CURRENT_OPERATION_UNRESOLVED")),
    }
}
fn within_commit_budget(installation: &Installation) -> Result<()> {
    let b = &installation.manifest.binding;
    let observed = native::guard()?;
    let elapsed = observed
        .monotonic_millis
        .checked_sub(b.monotonic_millis)
        .ok_or(Error::new("CLOCK_REGRESSED"))?;
    if observed.boot_id != b.boot_id
        || observed.network_namespace != b.network_namespace
        || elapsed.saturating_add(2000) > b.commit_budget_seconds.saturating_mul(1000)
        || observed.wall_time_unix < b.wall_time_unix
    {
        return Err(Error::new("INSTALLATION_BUDGET_EXPIRED"));
    }
    Ok(())
}
fn apply(
    state: &Path,
    bundle: &ExecutionBundle,
    trusted: &LabTrust,
    trust_path: &Path,
    crash: bool,
) -> Result<Value> {
    let mut j = journal(state, trusted, trust_path)?;
    if let Some(operation) = j.operation(&bundle.operation_id)? {
        let (_, saved) = stored(&j, &bundle.operation_id, trusted)?;
        if hash(&saved.bundle)? != hash(bundle)?
            || operation.generation != j.highest_generation()?.to_string()
        {
            return Err(Error::new("REPLAY_CONFLICT"));
        }
        // An accepted retry is observation only, even if the dispatch window has
        // expired. It never creates a fresh installation or touches native state.
        return observe(state, &mut j, &saved);
    }
    let grant = verify_bundle(bundle, trusted, false)?;
    let (baseline, previous_installation) = actual_baseline(state, &j, trusted)?;
    if hash(&baseline)? != hash(&bundle.previous)?
        || baseline.desired_state_hash != j.current_state_hash()?
        || hash(&previous_installation)? != hash(&bundle.previous_installation)?
    {
        return Err(Error::new("TRUSTED_BASELINE_MISMATCH"));
    }
    read_match(&baseline, &previous_installation)?;
    let installation = bind_at(
        &bundle.candidate,
        &native::binding(&bundle.operation_id, grant.grant_hash())?,
    )?;
    let saved = StoredInstallation {
        schema_version: "fw.isolated-installation/v1".into(),
        bundle: bundle.clone(),
        installation,
        trust_hash: hash(trusted)?,
    };
    let execution = material(&saved)?;
    j.accept_execution(&grant, &bundle.operation_id, &execution, native::now()?)?;
    let material_hash = execution.content_hash()?;
    let request = WatchRequest {
        schema_version: "fw.isolated-recovery-watch/v1".into(),
        operation_id: bundle.operation_id.clone(),
        material_hash: material_hash.clone(),
        nonce: uuid::Uuid::new_v4().to_string(),
        stored: saved.clone(),
    };
    let snapshot = state.join(format!("watch-{}.json", bundle.operation_id));
    files::write(&snapshot, &request)?;
    let mut child = Command::new(std::env::current_exe()?)
        .args(["watch", "--state-dir"])
        .arg(state)
        .arg("--operation-id")
        .arg(&bundle.operation_id)
        .arg("--trust")
        .arg(trust_path)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()?;
    let acknowledgement = state.join(format!("ack-{}.json", bundle.operation_id));
    let start = Instant::now();
    let ack: WatchAck = loop {
        if acknowledgement.try_exists()? {
            break files::read(&acknowledgement)?;
        }
        if start.elapsed() > Duration::from_secs(2) || child.try_wait()?.is_some() {
            let _ = child.kill();
            let _ = child.wait();
            return Err(Error::new("RECOVERY_WATCH_NOT_READY"));
        }
        thread::sleep(Duration::from_millis(10));
    };
    if ack.schema_version != "fw.isolated-recovery-ack/v1"
        || ack.operation_id != bundle.operation_id
        || ack.material_hash != material_hash
        || ack.nonce != request.nonce
        || ack.process_id != child.id()
        || ack.boot_id != trusted.boot_id
        || ack.network_namespace != trusted.network_namespace
        || child.try_wait()?.is_some()
    {
        let _ = child.kill();
        let _ = child.wait();
        return Err(Error::new("RECOVERY_ACK_BINDING"));
    }
    j.arm_watchdog(&bundle.operation_id, &material_hash, &hash(&ack)?)?;
    within_commit_budget(&saved.installation)?;
    // Recheck current keys, signed dispatch window and all immutable material
    // immediately before the durable UNKNOWN and bounded native transaction.
    let current_trust = trust(trust_path)?;
    initial(state, &current_trust)?;
    verify_bundle(bundle, &current_trust, false)?;
    j.mark_submitted(&bundle.operation_id, native::now()?)?;
    within_commit_budget(&saved.installation)?;
    native::replace(
        &bundle.candidate.table,
        &saved.installation.native.nft_json,
        &saved.installation.manifest.binding,
        grant
            .not_after()
            .min(current_trust.grant_key.not_after_unix),
    )?;
    if crash {
        crash_self();
    }
    let report = read_match(&bundle.candidate, &saved.installation)?;
    j.record_observation(
        &bundle.operation_id,
        &bundle.candidate.desired_state_hash,
        native::now()?,
    )?;
    status_value(
        &j,
        &bundle.operation_id,
        json!({"readback":report,"recovery_process_id":child.id(),"material_hash":material_hash}),
    )
}
fn crash_self() -> ! {
    // SAFETY: explicit isolated fault injection kills only this process.
    unsafe {
        libc::kill(libc::getpid(), libc::SIGKILL);
    }
    std::process::abort()
}
fn collect_probes(
    state: &Path,
    j: &mut ExecutorJournal,
    saved: &StoredInstallation,
    output: &Path,
) -> Result<Value> {
    observe(state, j, saved)?;
    let id = &saved.bundle.operation_id;
    let operation = j.operation(id)?.ok_or(Error::new("OPERATION_MISSING"))?;
    if operation.state != State::Verifying
        || operation
            .confirm_deadline
            .is_none_or(|d| native::now().is_ok_and(|n| n >= d))
    {
        return Err(Error::new("PROBE_WINDOW_CLOSED"));
    }
    let start = native::observation()?;
    let observations = saved
        .bundle
        .plan
        .probes
        .iter()
        .map(probes::execute)
        .collect::<Result<Vec<_>>>()?;
    let readback = read_match(&saved.bundle.candidate, &saved.installation)?;
    let end = native::observation()?;
    if end.wall_time_unix
        >= operation
            .confirm_deadline
            .ok_or(Error::new("PROBE_WINDOW_CLOSED"))?
    {
        return Err(Error::new("PROBE_WINDOW_CLOSED"));
    }
    let report = ProbeReport {
        schema_version: "fw.isolated-probe-report/v1".into(),
        operation_id: id.clone(),
        grant_hash: operation.grant_hash,
        state_hash: operation.desired_state_hash,
        target_generation: operation.generation,
        boot_id: end.boot_id,
        network_namespace: end.network_namespace,
        started_at_unix: start.wall_time_unix,
        finished_at_unix: end.wall_time_unix,
        readback_hash: readback.readback_hash.ok_or(Error::new("READBACK_HASH"))?,
        observations,
        production_management_probe: false,
    };
    files::write(&state.join(format!("probe-{id}.json")), &report)?;
    files::write(output, &report)?;
    status_value(
        j,
        id,
        json!({"probe_report_hash":hash(&report)?,"packet_probes":report.observations.len()}),
    )
}
fn confirm(
    state: &Path,
    j: &mut ExecutorJournal,
    saved: &StoredInstallation,
    trusted: &LabTrust,
    evidence: &ConfirmationEvidence,
) -> Result<Value> {
    let id = &saved.bundle.operation_id;
    observe(state, j, saved)?;
    let local: ProbeReport = files::read(&state.join(format!("probe-{id}.json")))?;
    let report_hash = hash(&local)?;
    let operation = j.operation(id)?.ok_or(Error::new("OPERATION_MISSING"))?;
    let mut nonces = std::collections::BTreeSet::new();
    for observation in &local.observations {
        let nonce = &observation.nonce;
        if nonce.len() != 32
            || !nonce
                .bytes()
                .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase())
            || !nonces.insert(nonce)
            || if observation.specification.expect_reply {
                observation.outcome != "reply"
                    || observation.bytes_sent != 32
                    || observation.bytes_received != 32
            } else {
                observation.outcome != "timeout"
                    || observation.bytes_received != 0
                    || ![0, 32].contains(&observation.bytes_sent)
                    || (observation.specification.protocol == "udp" && observation.bytes_sent != 32)
            }
        {
            return Err(Error::new("PROBE_OBSERVATION_SHAPE"));
        }
    }
    if evidence.schema_version != "fw.isolated-confirmation-evidence/v1"
        || hash(&evidence.probes)? != report_hash
        || local.schema_version != "fw.isolated-probe-report/v1"
        || local.production_management_probe
        || local.operation_id != *id
        || local.grant_hash != hash(&saved.bundle.grant)?
        || local.state_hash != saved.bundle.candidate.desired_state_hash
        || local.target_generation != saved.bundle.plan.target_generation
        || local.boot_id != trusted.boot_id
        || local.network_namespace != trusted.network_namespace
        || local.started_at_unix > local.finished_at_unix
        || local.finished_at_unix > native::now()?
        || local.started_at_unix < operation.submitted_at.ok_or(Error::new("NO_SUBMISSION"))?
        || local.finished_at_unix
            >= operation
                .confirm_deadline
                .ok_or(Error::new("NO_SUBMISSION"))?
        || local
            .observations
            .iter()
            .map(|o| &o.specification)
            .ne(saved.bundle.plan.probes.iter())
    {
        return Err(Error::new("PROBE_EVIDENCE_BINDING"));
    }
    let payload = STANDARD
        .decode(&evidence.confirmation.payload)
        .map_err(|_| Error::new("CONFIRM_PAYLOAD"))?;
    let confirmation: fw_executor::Confirmation =
        parse_strict(&payload).map_err(|_| Error::new("CONFIRM_PAYLOAD"))?;
    if confirmation.probe_report_hash != report_hash
        || confirmation.issued_at_unix < local.finished_at_unix
    {
        return Err(Error::new("CONFIRM_PROBE_BINDING"));
    }
    let trusted_key = key(trusted, &trusted.confirm_key, CONFIRM_TYPE, native::now()?)?;
    j.confirm(&evidence.confirmation, &trusted_key, native::now()?)?;
    status_value(j, id, json!({"probe_report_hash":report_hash}))
}
fn recover(
    state: &Path,
    j: &mut ExecutorJournal,
    saved: &StoredInstallation,
    trusted: &LabTrust,
    trust_path: &Path,
    crash: bool,
) -> Result<Value> {
    let id = &saved.bundle.operation_id;
    let operation = j.operation(id)?.ok_or(Error::new("OPERATION_MISSING"))?;
    if operation.generation != j.highest_generation()?.to_string() {
        return Err(Error::new("STALE_RECOVERY"));
    }
    if operation.state == State::RolledBack {
        return observe(state, j, saved);
    }
    let grant = verify_bundle(&saved.bundle, trusted, true)?;
    let material_hash = j
        .execution_material_hash(id)?
        .ok_or(Error::new("MATERIAL_MISSING"))?;
    let path = state.join(format!("recovery-{id}.json"));
    let recovery: RecoveryInstallation;
    if operation.state == State::RecoveryClaimed {
        recovery = files::read(&path)?;
        if recovery.material_hash != material_hash
            || recovery.schema_version != "fw.isolated-recovery-installation/v1"
        {
            return Err(Error::new("RECOVERY_MATERIAL_BINDING"));
        }
        // A lost native response is resolved by actual readback only. Never
        // blindly repeat even a restrictive write after a claimed recovery.
        read_match(&saved.bundle.recovery, &recovery.installation)?;
    } else {
        if !matches!(operation.state, State::Unknown | State::Verifying) {
            return Err(Error::new("RECOVERY_TRANSITION"));
        }
        read_match(&saved.bundle.candidate, &saved.installation)?;
        let now = native::now()?;
        if now
            < operation
                .confirm_deadline
                .ok_or(Error::new("NO_SUBMISSION"))?
            || now
                .checked_add(3)
                .is_none_or(|n| n >= grant.rollback_authority().valid_until_unix().unwrap_or(0))
        {
            return Err(Error::new("RECOVERY_WINDOW"));
        }
        recovery = RecoveryInstallation {
            schema_version: "fw.isolated-recovery-installation/v1".into(),
            material_hash: material_hash.clone(),
            installation: bind_at(
                &saved.bundle.recovery,
                &native::binding(id, grant.grant_hash())?,
            )?,
        };
        files::write(&path, &recovery)?;
        j.claim_recovery(id, grant.generation(), grant.desired_state_hash(), now)?;
        let current_trust = trust(trust_path)?;
        initial(state, &current_trust)?;
        verify_bundle(&saved.bundle, &current_trust, true)?;
        within_commit_budget(&recovery.installation)?;
        native::replace(
            &saved.bundle.recovery.table,
            &recovery.installation.native.nft_json,
            &recovery.installation.manifest.binding,
            grant
                .rollback_authority()
                .valid_until_unix()?
                .min(current_trust.grant_key.not_after_unix),
        )?;
        if crash {
            crash_self();
        }
    }
    let readback = read_match(&saved.bundle.recovery, &recovery.installation)?;
    j.record_recovery_completion(
        id,
        grant.generation(),
        grant.desired_state_hash(),
        &material_hash,
        &saved.bundle.recovery.desired_state_hash,
        &hash(&readback)?,
        native::now()?,
    )?;
    status_value(j, id, value(&readback)?)
}
fn watch(state: &Path, id: &str, trusted: &LabTrust, trust_path: &Path) -> Result<()> {
    uuid(id)?;
    initial(state, trusted)?;
    let request: WatchRequest = files::read(&state.join(format!("watch-{id}.json")))?;
    if request.schema_version != "fw.isolated-recovery-watch/v1"
        || request.operation_id != id
        || request.stored.bundle.operation_id != id
        || request.stored.trust_hash != hash(trusted)?
        || material(&request.stored)?.content_hash()? != request.material_hash
    {
        return Err(Error::new("RECOVERY_WATCH_BINDING"));
    }
    verify_bundle(&request.stored.bundle, trusted, false)?;
    let ack = WatchAck {
        schema_version: "fw.isolated-recovery-ack/v1".into(),
        operation_id: id.into(),
        material_hash: request.material_hash.clone(),
        nonce: request.nonce,
        process_id: std::process::id(),
        boot_id: trusted.boot_id.clone(),
        network_namespace: trusted.network_namespace.clone(),
    };
    files::write(&state.join(format!("ack-{id}.json")), &ack)?;
    let maximum = Instant::now();
    loop {
        if maximum.elapsed() > Duration::from_secs(720) {
            return Err(Error::new("RECOVERY_WATCH_EXPIRED"));
        }
        thread::sleep(Duration::from_millis(100));
        // A permanent/hung owner may hold the lock: this is explicitly bounded
        // crash recovery, not qualification of an independent production watchdog.
        let current_trust = trust(trust_path)?;
        let mut j = match journal(state, &current_trust, trust_path) {
            Ok(j) => j,
            Err(_) => continue,
        };
        let operation = j.operation(id)?.ok_or(Error::new("OPERATION_MISSING"))?;
        if operation.generation != j.highest_generation()?.to_string()
            || matches!(
                operation.state,
                State::Confirmed | State::RolledBack | State::NotApplied
            )
        {
            return Ok(());
        }
        if operation.state == State::Prepared && native::now()? >= operation.confirm_not_after {
            return Ok(());
        }
        if operation
            .confirm_deadline
            .is_some_and(|deadline| native::now().is_ok_and(|now| now >= deadline))
        {
            let (_, saved) = stored(&j, id, &current_trust)?;
            recover(state, &mut j, &saved, &current_trust, trust_path, false)?;
            return Ok(());
        }
    }
}

pub fn run_main() {
    let result = run();
    match result {
        Ok(Some(output)) => println!("{output}"),
        Ok(None) => {}
        Err(error) => {
            eprintln!("{error}");
            std::process::exit(1);
        }
    }
}
fn run() -> Result<Option<Value>> {
    let mut arguments = std::env::args().skip(1);
    let command = arguments.next().ok_or(Error::new("COMMAND_REQUIRED"))?;
    if command == "--help" {
        println!(
            "fw_linux_executor init|apply --state-dir DIR --bundle FILE --trust FILE\nfw_linux_executor observe|status|recover --state-dir DIR --operation-id UUID --trust FILE\nfw_linux_executor probe [same options] --output FILE\nfw_linux_executor confirm [same options] --confirmation FILE\nDisposable loopback lab only; never a production firewall command."
        );
        return Ok(None);
    }
    native::guard()?;
    let mut options = BTreeMap::new();
    let mut crash_commit = false;
    let mut crash_recovery = false;
    while let Some(option) = arguments.next() {
        if option == "--crash-after-commit" {
            crash_commit = true;
            continue;
        }
        if option == "--crash-after-recovery-write" {
            crash_recovery = true;
            continue;
        }
        if ![
            "--state-dir",
            "--bundle",
            "--trust",
            "--operation-id",
            "--output",
            "--confirmation",
        ]
        .contains(&option.as_str())
            || options.contains_key(&option)
        {
            return Err(Error::new("ARGUMENT"));
        }
        options.insert(option, arguments.next().ok_or(Error::new("ARGUMENT"))?);
    }
    let required = |name: &str| -> Result<&str> {
        options
            .get(name)
            .map(String::as_str)
            .ok_or(Error::new("ARGUMENT_REQUIRED"))
    };
    let state = PathBuf::from(required("--state-dir")?);
    let trust_path = PathBuf::from(required("--trust")?);
    let trusted = trust(&trust_path)?;
    match command.as_str() {
        "init" => Ok(Some(init(
            &state,
            &files::read(Path::new(required("--bundle")?))?,
            &trusted,
        )?)),
        "apply" => Ok(Some(apply(
            &state,
            &files::read(Path::new(required("--bundle")?))?,
            &trusted,
            &trust_path,
            crash_commit,
        )?)),
        "watch" => {
            watch(&state, required("--operation-id")?, &trusted, &trust_path)?;
            Ok(None)
        }
        "observe" | "status" | "probe" | "confirm" | "recover" => {
            let id = required("--operation-id")?;
            uuid(id)?;
            let mut j = journal(&state, &trusted, &trust_path)?;
            let (_, saved) = stored(&j, id, &trusted)?;
            let result = match command.as_str() {
                "observe" | "status" => observe(&state, &mut j, &saved)?,
                "probe" => {
                    collect_probes(&state, &mut j, &saved, Path::new(required("--output")?))?
                }
                "confirm" => confirm(
                    &state,
                    &mut j,
                    &saved,
                    &trusted,
                    &files::read(Path::new(required("--confirmation")?))?,
                )?,
                _ => recover(
                    &state,
                    &mut j,
                    &saved,
                    &trusted,
                    &trust_path,
                    crash_recovery,
                )?,
            };
            Ok(Some(result))
        }
        _ => Err(Error::new("COMMAND")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn legitimate_recovery_lock_can_outlast_one_second_without_resetting_identity() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("journal.sqlite3");
        let owner_path = path.clone();
        let org = "11111111-1111-4111-8111-111111111111";
        let target = "22222222-2222-4222-8222-222222222222";
        let baseline = format!("sha256:{}", "1".repeat(64));
        let owner_baseline = baseline.clone();
        let (ready_send, ready_receive) = std::sync::mpsc::channel();
        let (begin_send, begin_receive) = std::sync::mpsc::channel();
        let owner = thread::spawn(move || {
            let journal =
                ExecutorJournal::create(owner_path, org, target, 1, &owner_baseline).unwrap();
            ready_send.send(()).unwrap();
            begin_receive.recv().unwrap();
            // A native operation is bounded at two seconds before its readback
            // and fsync. This valid owner duration exceeded the old 1s waiter.
            thread::sleep(Duration::from_millis(1250));
            drop(journal);
        });
        ready_receive.recv().unwrap();
        let started = Instant::now();
        begin_send.send(()).unwrap();
        let journal = open_journal(&path).unwrap();
        assert!(started.elapsed() >= Duration::from_millis(1200));
        assert_eq!(journal.highest_generation().unwrap(), 0);
        assert_eq!(journal.current_state_hash().unwrap(), baseline);
        assert_eq!(journal.identity().unwrap().target_id, target);
        owner.join().unwrap();
    }

    #[test]
    fn journal_errors_are_specific_without_exposing_input_or_paths() {
        let busy = fw_executor::ExecutorError::Io(std::io::Error::new(
            std::io::ErrorKind::WouldBlock,
            "sensitive fixture path must not be rendered",
        ));
        assert_eq!(Error::from(busy).to_string(), "JOURNAL_BUSY");
        assert_eq!(
            Error::from(fw_executor::ExecutorError::Binding).to_string(),
            "JOURNAL_INVALID_BINDING"
        );
        assert_eq!(
            Error::from(fw_executor::ExecutorError::Expired).to_string(),
            "JOURNAL_EXPIRED"
        );
        assert_eq!(
            Error::from(fw_executor::ExecutorError::Transition).to_string(),
            "JOURNAL_INVALID_TRANSITION"
        );
    }
}
