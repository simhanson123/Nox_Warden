//! Actual isolated target bootstrap: signed material, durable epoch fence,
//! atomic exact management baseline, kernel readback and authenticated probes.
use super::{Error, Result, bootstrap_files as files, bootstrap_guard, bootstrap_probes, native};
use ed25519_dalek::SigningKey;
use fw_authority::{
    AuthorityGate, BootstrapProbeKind, MAX_TARGET_BOOTSTRAP_BYTES,
    SignedTargetBootstrapConfirmation, TARGET_BOOTSTRAP_PAYLOAD_SCHEMA,
    TargetBootstrapConfirmationPayload, authority_gate_codes, sign_target_bootstrap_confirmation,
    validate_target_bootstrap_key, verify_target_bootstrap_confirmation,
};
use fw_backend_linux::{
    BootstrapBaselineProgram, compile_bootstrap_baseline, verify_bootstrap_baseline_readback,
};
use fw_contracts::{
    canonical_bytes, canonical_hash, hash_bytes, parse_strict_with_limit, parse_value_with_limit,
};
use fw_executor::{BootstrapIntent, BootstrapJournal, BootstrapPreparation};
use fw_linux_executor::{
    TARGET_BOOTSTRAP_CONFIG_SCHEMA, TargetBootstrapBundle, TargetBootstrapConfig,
};
use serde_json::{Value, json};
use std::{collections::BTreeMap, fs, path::Path};

const CONFIG_LIMIT: usize = 16384;
fn timestamp(value: &str) -> Result<i64> {
    chrono::DateTime::parse_from_rfc3339(value)
        .map(|v| v.timestamp())
        .map_err(|_| Error::new("BOOTSTRAP_TIME"))
}
fn at(now: i64) -> Result<String> {
    chrono::DateTime::from_timestamp(now, 0)
        .map(|v| v.format("%Y-%m-%dT%H:%M:%SZ").to_string())
        .ok_or(Error::new("BOOTSTRAP_TIME"))
}
fn options(arguments: impl Iterator<Item = String>) -> Result<BTreeMap<String, String>> {
    let mut arguments = arguments;
    let mut options = BTreeMap::new();
    while let Some(name) = arguments.next() {
        let value = arguments.next().ok_or(Error::new("ARGUMENT_REQUIRED"))?;
        if !["--config", "--bundle"].contains(&name.as_str())
            || value.is_empty()
            || options.insert(name, value).is_some()
        {
            return Err(Error::new("ARGUMENT"));
        }
    }
    if options.len() != 2 {
        return Err(Error::new("ARGUMENT_REQUIRED"));
    }
    Ok(options)
}
fn harden() -> Result<()> {
    let limit = libc::rlimit {
        rlim_cur: 0,
        rlim_max: 0,
    };
    // SAFETY: initialized limit and scalar prctl arguments affect this process.
    if unsafe { libc::getuid() } != 0
        || unsafe { libc::geteuid() } != 0
        || unsafe { libc::getgid() } != unsafe { libc::getegid() }
        || unsafe { libc::setrlimit(libc::RLIMIT_CORE, &limit) } != 0
        || unsafe { libc::prctl(libc::PR_SET_DUMPABLE, 0, 0, 0, 0) } != 0
        || unsafe { libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) } != 0
    {
        return Err(Error::new("BOOTSTRAP_PROCESS_IDENTITY"));
    }
    // No other threads exist in this new command process.
    unsafe {
        libc::umask(0o077);
    }
    Ok(())
}
fn reject_legacy(state: &Path) -> Result<()> {
    for name in [
        "journal.sqlite3",
        "journal.sqlite3.lock",
        "journal.sqlite3-journal",
        "journal.sqlite3-wal",
        "journal.sqlite3-shm",
        "initial.json",
    ] {
        match fs::symlink_metadata(state.join(name)) {
            Ok(_) => return Err(Error::new("BOOTSTRAP_EXISTING_EXECUTION_HISTORY")),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(_) => return Err(Error::new("BOOTSTRAP_STATE")),
        }
    }
    Ok(())
}
fn binding(bundle: &TargetBootstrapBundle, material: &[u8]) -> Result<BootstrapIntent> {
    let challenge = &bundle.challenge;
    Ok(BootstrapIntent {
        org_id: challenge.org_id.clone(),
        project_id: challenge.project_id.clone(),
        target_id: challenge.target_id.clone(),
        manifest_id: challenge.manifest_id.clone(),
        manifest_hash: challenge.manifest_hash.clone(),
        authorization_hash: challenge.authorization_hash.clone(),
        challenge_id: challenge.challenge_id.clone(),
        challenge_hash: challenge.hash()?,
        baseline_program_hash: challenge.baseline_program_hash.clone(),
        material_hash: hash_bytes(material),
        old_epoch: challenge.old_epoch.clone(),
        new_epoch: challenge.new_epoch.clone(),
        highest_generation: challenge.highest_generation.clone(),
        previous_confirmation_hash: challenge.previous_confirmation_hash.clone(),
        valid_until_unix: timestamp(&challenge.expires_at)?,
    })
}
fn validate_config(
    config: &TargetBootstrapConfig,
    bundle: &TargetBootstrapBundle,
    key: &SigningKey,
) -> Result<()> {
    config.bootstrap_trust.validate_shape()?;
    config.target_key_pin.validate_shape()?;
    bundle.challenge.validate_shape()?;
    if config.schema_version != TARGET_BOOTSTRAP_CONFIG_SCHEMA
        || config.bootstrap_trust.payload_type != fw_authority::BOOTSTRAP_AUTHORIZATION_TYPE
        || config.org_id != bundle.challenge.org_id
        || config.project_id != bundle.challenge.project_id
        || config.target_id != bundle.challenge.target_id
        || config.org_id != config.bootstrap_trust.org_id
        || config.project_id != config.bootstrap_trust.project_id
        || config.target_id != config.bootstrap_trust.target_id
        || config.org_id != config.target_key_pin.org_id
        || config.project_id != config.target_key_pin.project_id
        || config.target_id != config.target_key_pin.target_id
        || config.target_key_pin.public_key != key.verifying_key().to_bytes()
        || config.target_key_pin.public_key == config.bootstrap_trust.public_key
        || config.target_key_pin.public_key == bundle.baseline.peer_probe_public_key
        || config.bootstrap_trust.public_key == bundle.baseline.peer_probe_public_key
        || !Path::new(&config.state_dir).is_absolute()
        || !Path::new(&config.state_dir).starts_with("/lab")
    {
        return Err(Error::new("BOOTSTRAP_CONFIG_BINDING"));
    }
    Ok(())
}
fn verify_history(
    config: &TargetBootstrapConfig,
    bundle: &TargetBootstrapBundle,
    bytes: &[u8],
    journal_id: &str,
) -> Result<SignedTargetBootstrapConfirmation> {
    let receipt = SignedTargetBootstrapConfirmation::from_bytes(bytes)?;
    let historical = timestamp(&receipt.payload.observation_finished_at)?;
    // The signed original observation time verifies history; current time never
    // renews the challenge or creates permission for another baseline write.
    bundle.validate(&config.bootstrap_trust, historical)?;
    let verified = verify_target_bootstrap_confirmation(
        &receipt,
        &bundle.challenge,
        &config.target_key_pin,
        &bundle.baseline,
        &bundle.capability,
        historical,
    )?;
    if verified.canonical_bytes() != bytes || verified.journal_id() != journal_id {
        return Err(Error::new("BOOTSTRAP_RETAINED_BINDING"));
    }
    Ok(receipt)
}
fn ruleset(journal: Option<&BootstrapJournal>) -> Result<Value> {
    let bytes = match journal {
        Some(journal) => native::bootstrap_command(journal, &["-j", "list", "ruleset"], None)?,
        None => native::command("/usr/sbin/nft", &["-j", "list", "ruleset"], None)?,
    };
    parse_value_with_limit(&bytes, MAX_TARGET_BOOTSTRAP_BYTES)
        .map_err(|_| Error::new("BOOTSTRAP_NATIVE_READBACK"))
}
fn empty_ruleset(raw: &Value) -> Result<()> {
    let object = raw
        .as_object()
        .ok_or(Error::new("BOOTSTRAP_INITIAL_RULESET"))?;
    let entries = raw["nftables"]
        .as_array()
        .ok_or(Error::new("BOOTSTRAP_INITIAL_RULESET"))?;
    if object.len() != 1
        || entries.iter().any(|entry| {
            !entry
                .as_object()
                .is_some_and(|entry| entry.len() == 1 && entry.contains_key("metainfo"))
        })
    {
        return Err(Error::new("BOOTSTRAP_INITIAL_RULESET"));
    }
    Ok(())
}
fn predecessor(
    journal: &BootstrapJournal,
    config: &TargetBootstrapConfig,
    bundle: &TargetBootstrapBundle,
    current: &Value,
    boot_id: &str,
) -> Result<bool> {
    let head = journal.head()?;
    if head.state == "EMPTY" {
        if bundle.challenge.old_epoch.is_some()
            || bundle.challenge.previous_confirmation_hash.is_some()
        {
            return Err(Error::new("BOOTSTRAP_PREDECESSOR"));
        }
        empty_ruleset(current)?;
        return Ok(false);
    }
    if head.state != "CONFIRMED"
        || bundle.challenge.old_epoch.as_deref() != Some(head.authority_epoch.as_str())
        || bundle.challenge.previous_confirmation_hash != head.confirmation_hash
    {
        return Err(Error::new("BOOTSTRAP_PREDECESSOR"));
    }
    let saved = journal
        .confirmed_predecessor()?
        .ok_or(Error::new("BOOTSTRAP_PREDECESSOR"))?;
    let previous: TargetBootstrapBundle =
        parse_strict_with_limit(&saved.material_bytes, MAX_TARGET_BOOTSTRAP_BYTES)
            .map_err(|_| Error::new("BOOTSTRAP_RETAINED_BINDING"))?;
    let receipt = verify_history(config, &previous, &saved.receipt_bytes, &head.journal_id)?;
    if receipt.payload.boot_id != boot_id
        || previous.baseline.network_namespace != bundle.baseline.network_namespace
        || receipt.payload.accepted_epoch != head.authority_epoch
        || head.highest_generation != "0"
    {
        return Err(Error::new("BOOTSTRAP_RECOVERY_UNSUPPORTED"));
    }
    verify_bootstrap_baseline_readback(&previous.baseline, &previous.capability, current)?;
    Ok(true)
}
fn outcome(
    journal: &BootstrapJournal,
    receipt: SignedTargetBootstrapConfirmation,
    replayed: bool,
    now: i64,
) -> Result<Value> {
    let head = journal.head()?;
    Ok(
        json!({"schema_version":"fw.target-bootstrap-result/v1","confirmation_hash":receipt.hash()?,"accepted_epoch":receipt.payload.accepted_epoch,"current_epoch":head.authority_epoch,"current_journal_state":head.state,"highest_generation":head.highest_generation,"challenge_unexpired":now<timestamp(&receipt.payload.challenge.expires_at)?,"state":"target_confirmed_pending_qualification","confirmation":receipt,"replayed":replayed,"production_signing_allowed":false,"dispatch_allowed":false,"qualification_gates":authority_gate_codes(&[AuthorityGate::BuildIdentityRequired,AuthorityGate::NativeQualificationRequired,AuthorityGate::PolicySignerKeyRequired,AuthorityGate::WorkloadSourceAttestationRequired])}),
    )
}

#[allow(clippy::too_many_arguments)]
fn apply(
    journal: &mut BootstrapJournal,
    config: &TargetBootstrapConfig,
    bundle: &TargetBootstrapBundle,
    key: &SigningKey,
    intent: &BootstrapIntent,
    program: &BootstrapBaselineProgram,
    replace: bool,
    accepted_at: i64,
    inputs: &[&files::Input],
    marker: &bootstrap_guard::Marker,
) -> Result<SignedTargetBootstrapConfirmation> {
    let started = native::observation()?;
    bundle.validate(&config.bootstrap_trust, started.wall_time_unix)?;
    validate_target_bootstrap_key(
        &bundle.challenge,
        &config.target_key_pin,
        started.wall_time_unix,
    )?;
    for input in inputs {
        input.recheck()?;
    }
    reject_legacy(Path::new(&config.state_dir))?;
    let mut batch = program.nft_json.clone();
    if replace {
        batch["nftables"]
            .as_array_mut()
            .ok_or(Error::new("BOOTSTRAP_PROGRAM"))?
            .insert(
                0,
                json!({"delete":{"table":{"family":"inet","name":program.table}}}),
            );
    }
    native::bootstrap_command(
        journal,
        &["-j", "-f", "-"],
        Some(canonical_bytes(&batch).map_err(|_| Error::new("BOOTSTRAP_PROGRAM"))?),
    )?;
    verify_bootstrap_baseline_readback(
        &bundle.baseline,
        &bundle.capability,
        &ruleset(Some(journal))?,
    )?;
    let challenge_hash = bundle.challenge.hash()?;
    let mut probes = Vec::new();
    for kind in [
        BootstrapProbeKind::ManagementTcp,
        BootstrapProbeKind::PositiveUdp,
        BootstrapProbeKind::NegativeUdp,
    ] {
        probes.push(bootstrap_probes::execute(
            kind,
            &challenge_hash,
            &bundle.baseline,
        )?);
    }
    let readback = ruleset(Some(journal))?;
    verify_bootstrap_baseline_readback(&bundle.baseline, &bundle.capability, &readback)?;
    let finished = bootstrap_guard::check(&bundle.baseline, &bundle.capability, marker)?;
    if started.boot_id != finished.boot_id
        || started.network_namespace != finished.network_namespace
        || finished.network_namespace != bundle.baseline.network_namespace
    {
        return Err(Error::new("BOOTSTRAP_OBSERVATION_CHANGED"));
    }
    for input in inputs {
        input.recheck()?;
    }
    reject_legacy(Path::new(&config.state_dir))?;
    let signing_now = native::now()?;
    bundle.validate(&config.bootstrap_trust, signing_now)?;
    validate_target_bootstrap_key(&bundle.challenge, &config.target_key_pin, signing_now)?;
    let payload = TargetBootstrapConfirmationPayload {
        schema_version: TARGET_BOOTSTRAP_PAYLOAD_SCHEMA.into(),
        challenge: bundle.challenge.clone(),
        journal_id: journal.head()?.journal_id,
        boot_id: finished.boot_id,
        network_namespace: finished.network_namespace,
        accepted_epoch: bundle.challenge.new_epoch.clone(),
        highest_generation: "0".into(),
        accepted_at: at(accepted_at)?,
        observation_started_at: at(started.wall_time_unix)?,
        observation_finished_at: at(finished.wall_time_unix)?,
        observation_started_millis: started.monotonic_millis.to_string(),
        observation_finished_millis: finished.monotonic_millis.to_string(),
        readback,
        probes,
    };
    let receipt = sign_target_bootstrap_confirmation(
        payload,
        &config.target_key_pin,
        key,
        &bundle.baseline,
        &bundle.capability,
        signing_now,
    )?;
    let commit_now = native::now()?;
    let verified = verify_target_bootstrap_confirmation(
        &receipt,
        &bundle.challenge,
        &config.target_key_pin,
        &bundle.baseline,
        &bundle.capability,
        commit_now,
    )?;
    bundle.validate(&config.bootstrap_trust, commit_now)?;
    journal.confirm(intent, &verified, commit_now)?;
    Ok(receipt)
}

pub(super) fn run(arguments: impl Iterator<Item = String>) -> Result<Value> {
    harden()?;
    let options = options(arguments)?;
    // Every potentially aliasable input fd is opened before the journal. Local
    // drop order closes the later SQLite connection before these retained fds.
    let marker = bootstrap_guard::Marker::load()?;
    let config_input = files::Input::load(Path::new(&options["--config"]), CONFIG_LIMIT)?;
    let config: TargetBootstrapConfig = parse_strict_with_limit(config_input.bytes(), CONFIG_LIMIT)
        .map_err(|_| Error::new("BOOTSTRAP_CONFIG"))?;
    let bundle_input =
        files::Input::load(Path::new(&options["--bundle"]), MAX_TARGET_BOOTSTRAP_BYTES)?;
    let bundle: TargetBootstrapBundle =
        parse_strict_with_limit(bundle_input.bytes(), MAX_TARGET_BOOTSTRAP_BYTES)
            .map_err(|_| Error::new("BOOTSTRAP_BUNDLE"))?;
    let seed_input = files::Input::load(Path::new(&config.seed_file), 32)?;
    let seed: &[u8; 32] = seed_input
        .bytes()
        .try_into()
        .map_err(|_| Error::new("BOOTSTRAP_TARGET_KEY"))?;
    let key = SigningKey::from_bytes(seed);
    validate_config(&config, &bundle, &key)?;
    let observed = bootstrap_guard::check(&bundle.baseline, &bundle.capability, &marker)?;
    let material = bundle.canonical_bytes()?;
    let intent = binding(&bundle, &material)?;
    let anchor=canonical_bytes(&json!({"schema_version":"fw.target-bootstrap-anchor/v1","config_hash":canonical_hash(&config).map_err(|_|Error::new("BOOTSTRAP_CONFIG"))?,"boot_id":observed.boot_id})).map_err(|_|Error::new("BOOTSTRAP_STATE"))?;
    let state = Path::new(&config.state_dir);
    let fresh = match fs::symlink_metadata(state) {
        Ok(_) => {
            files::directory(state)?;
            false
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            files::create_directory(state)?;
            files::write_new(&state.join("bootstrap.anchor.json"), &anchor)?;
            true
        }
        Err(_) => return Err(Error::new("BOOTSTRAP_STATE")),
    };
    reject_legacy(state)?;
    let anchor_input = files::Input::load(&state.join("bootstrap.anchor.json"), CONFIG_LIMIT)?;
    if anchor_input.bytes() != anchor {
        return Err(Error::new("BOOTSTRAP_STATE_RECOVERY_UNSUPPORTED"));
    }
    let now = native::now()?;
    let mut journal = if fresh {
        BootstrapJournal::create(
            state.join("bootstrap.sqlite3"),
            &config.org_id,
            &config.project_id,
            &config.target_id,
            now,
        )?
    } else {
        BootstrapJournal::open(state.join("bootstrap.sqlite3"))?
    };
    let head = journal.head()?;
    if head.org_id != config.org_id
        || head.project_id != config.project_id
        || head.target_id != config.target_id
    {
        return Err(Error::new("BOOTSTRAP_STATE_BINDING"));
    }
    if let Some(saved) = journal.retained_material(&intent.manifest_id)? {
        if saved != material {
            return Err(Error::new("BOOTSTRAP_EXACT_RETRY_CONFLICT"));
        }
        // Historical retry does not require a new valid challenge or signature.
        match journal.prepare(&intent, &material, now)? {
            BootstrapPreparation::Retained { receipt_bytes } => {
                let receipt = verify_history(&config, &bundle, &receipt_bytes, &head.journal_id)?;
                return outcome(&journal, receipt, true, now);
            }
            BootstrapPreparation::Pending { .. } => {
                return Err(Error::new("BOOTSTRAP_STATE_BINDING"));
            }
        }
    }
    bundle.validate(&config.bootstrap_trust, now)?;
    validate_target_bootstrap_key(&bundle.challenge, &config.target_key_pin, now)?;
    let current = ruleset(None)?;
    let replace = predecessor(&journal, &config, &bundle, &current, &observed.boot_id)?;
    let program = compile_bootstrap_baseline(&bundle.baseline, &bundle.capability)?;
    let inputs = [&config_input, &bundle_input, &seed_input, &anchor_input];
    for input in &inputs {
        input.recheck()?;
    }
    let accepted = native::now()?;
    bundle.validate(&config.bootstrap_trust, accepted)?;
    validate_target_bootstrap_key(&bundle.challenge, &config.target_key_pin, accepted)?;
    match journal.prepare(&intent, &material, accepted)? {
        BootstrapPreparation::Pending { .. } => {}
        BootstrapPreparation::Retained { receipt_bytes } => {
            let receipt = verify_history(&config, &bundle, &receipt_bytes, &head.journal_id)?;
            return outcome(&journal, receipt, true, accepted);
        }
    }
    match apply(
        &mut journal,
        &config,
        &bundle,
        &key,
        &intent,
        &program,
        replace,
        accepted,
        &inputs,
        &marker,
    ) {
        Ok(receipt) => outcome(&journal, receipt, false, native::now()?),
        Err(error) => {
            journal.mark_unknown(&intent.manifest_id, native::now()?)?;
            Err(error)
        }
    }
}
