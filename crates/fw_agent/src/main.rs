//! A Linux device identity and certificate enrollment client. No command changes
//! firewall rules or promotes an enrolled target into an authorized executor.
mod files;

use chrono::{DateTime, Utc};
use files::Directory;
use fw_enrollment::{DeviceIdentity, EnrollmentRequest, EnrollmentResponse};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::{
    collections::BTreeMap,
    error::Error,
    fs::File,
    io::Read,
    path::Path,
    process::{Command, Stdio},
    sync::Arc,
    time::{Duration, Instant},
};
use ureq::tls::{Certificate, ClientCert, PemItem, PrivateKey, RootCerts, TlsConfig};
use uuid::Uuid;

type Result<T> = std::result::Result<T, Box<dyn Error>>;
const VERSION: &str = env!("CARGO_PKG_VERSION");
const HELP: &str = "fw_agent init --state-dir PATH\nfw_agent enroll --state-dir PATH --controller HTTPS_ORIGIN --ca-file FILE --trust-bundle-hash SHA256 --invitation-file FILE\nfw_agent report --state-dir PATH --controller HTTPS_ORIGIN --ca-file FILE --trust-bundle-hash SHA256\nfw_agent status --state-dir PATH --controller HTTPS_ORIGIN --ca-file FILE --trust-bundle-hash SHA256\n\nEnrollment requires a separately verified controller CA hash and a private invitation file. Tokens and private keys are never command-line arguments or output. This Linux client registers transport identity and reports unverified capabilities; it never applies firewall rules. Certificate renewal is not implemented.";

struct Arguments {
    command: String,
    values: BTreeMap<String, String>,
}
impl Arguments {
    fn parse(args: Vec<String>) -> Result<Self> {
        let command = args.first().ok_or("command required; see --help")?.clone();
        let allowed: &[&str] = match command.as_str() {
            "init" => &["--state-dir"],
            "enroll" => &[
                "--state-dir",
                "--controller",
                "--ca-file",
                "--trust-bundle-hash",
                "--invitation-file",
            ],
            "report" | "status" => &[
                "--state-dir",
                "--controller",
                "--ca-file",
                "--trust-bundle-hash",
            ],
            _ => return Err("unknown command; see --help".into()),
        };
        if args.len() != 1 + 2 * allowed.len() {
            return Err("missing or repeated option; see --help".into());
        }
        let mut values = BTreeMap::new();
        for pair in args[1..].as_chunks::<2>().0 {
            if !allowed.contains(&pair[0].as_str())
                || pair[1].is_empty()
                || values.insert(pair[0].clone(), pair[1].clone()).is_some()
            {
                return Err("invalid or repeated option; see --help".into());
            }
        }
        Ok(Self { command, values })
    }
    fn value(&self, option: &str) -> Result<&str> {
        self.values
            .get(option)
            .map(String::as_str)
            .ok_or_else(|| "required option missing".into())
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Invitation {
    schema_version: String,
    api_origin: String,
    token: String,
    idempotency_key: String,
    name: String,
    platform: String,
    expected_key_fingerprint: String,
    target_id: Option<String>,
    token_id: Option<String>,
    expires_at: Option<String>,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Pending {
    schema_version: String,
    request_id: String,
    nonce: String,
    agent_version: String,
    invitation_hash: String,
    target_id: String,
    key_fingerprint: String,
    controller_origin: String,
    trust_bundle_hash: String,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Enrolled {
    schema_version: String,
    controller_origin: String,
    trust_bundle_hash: String,
    response: EnrollmentResponse,
}

fn canonical_uuid(value: &str) -> bool {
    Uuid::parse_str(value).is_ok_and(|u| u.to_string() == value)
}
fn hex64(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|c| c.is_ascii_digit() || (b'a'..=b'f').contains(&c))
}
fn fingerprint(value: &str) -> bool {
    value.strip_prefix("sha256:").is_some_and(hex64)
}
fn time(value: &str) -> Result<i64> {
    let date = DateTime::parse_from_rfc3339(value).map_err(|_| "invalid canonical timestamp")?;
    if date
        .with_timezone(&Utc)
        .format("%Y-%m-%dT%H:%M:%SZ")
        .to_string()
        != value
    {
        return Err("invalid canonical timestamp".into());
    }
    Ok(date.timestamp())
}
fn platform() -> Result<&'static str> {
    if cfg!(target_os = "linux") {
        Ok("linux")
    } else {
        Err("this device client currently supports Linux only".into())
    }
}
fn origin(value: &str) -> Result<String> {
    if value.contains(['#', '\\']) || value.bytes().any(|b| b.is_ascii_whitespace()) {
        return Err("controller must be an HTTPS origin without fragments or escapes".into());
    }
    let uri: ureq::http::Uri = value
        .parse()
        .map_err(|_| "invalid HTTPS controller origin")?;
    let authority = uri.authority().ok_or("controller host is required")?;
    if uri.scheme_str() != Some("https")
        || authority.as_str().contains('@')
        || uri.host().is_none()
        || uri.query().is_some()
        || !["", "/"].contains(&uri.path())
    {
        return Err(
            "controller must be an HTTPS origin without credentials, query, or path".into(),
        );
    }
    Ok(value.trim_end_matches('/').to_owned())
}
fn text(bytes: Vec<u8>) -> Result<String> {
    String::from_utf8(bytes).map_err(|_| "credential file is not UTF-8".into())
}
fn parse<T: serde::de::DeserializeOwned>(bytes: &[u8]) -> Result<T> {
    fw_contracts::parse_strict(bytes)
        .map_err(|_| "invalid or oversized structured response/state".into())
}
fn read_identity(state: &Directory) -> Result<DeviceIdentity> {
    fw_enrollment::load_device_identity(
        &text(state.read("key.pem")?)?,
        &text(state.read("csr.pem")?)?,
    )
    .map_err(Into::into)
}
fn init(state: &Directory) -> Result<Value> {
    for file in [
        "key.pem",
        "csr.pem",
        "pending-enrollment.json",
        "enrollment.json",
        "certificate.pem",
    ] {
        if state.read_optional(file, true)?.is_some() {
            return Err("device identity already exists; refusing to overwrite it".into());
        }
    }
    let identity = fw_enrollment::generate_device_identity()?;
    state.write("key.pem", identity.private_key_pem.as_bytes(), false)?;
    state.write("csr.pem", identity.csr_pem.as_bytes(), false)?;
    Ok(
        json!({"platform":platform()?,"agent_version":VERSION,"key_fingerprint":identity.key_fingerprint,"csr_file":state.path.join("csr.pem"),"state":"not_enrolled","enforcement":false}),
    )
}
fn pinned_ca(path: &Path, expected: &str) -> Result<String> {
    if !fingerprint(expected) {
        return Err("explicit controller trust-bundle hash is required".into());
    }
    let bytes = files::read_path(path, false)?;
    if fw_enrollment::hash_bytes(&bytes) != expected {
        return Err("controller CA does not match the explicitly supplied trust pin".into());
    }
    text(bytes)
}
fn certificates(pem: &str) -> Result<Vec<Certificate<'static>>> {
    let mut certificates = Vec::new();
    for item in ureq::tls::parse_pem(pem.as_bytes()) {
        match item.map_err(|_| "invalid certificate PEM")? {
            PemItem::Certificate(cert) => certificates.push(cert),
            _ => return Err("certificate bundle contains a non-certificate item".into()),
        }
    }
    if certificates.is_empty() {
        return Err("certificate bundle is empty".into());
    }
    Ok(certificates)
}
fn tls_provider() -> rustls::crypto::CryptoProvider {
    let mut provider = rustls::crypto::ring::default_provider();
    // Rustls only advertises protocol versions with an enabled cipher suite.
    // Restrict the maintained provider's suites, keeping its normal PKIX verifier.
    provider
        .cipher_suites
        .retain(|suite| matches!(suite, rustls::SupportedCipherSuite::Tls13(_)));
    provider
}
fn client(
    ca: &str,
    identity: Option<(&DeviceIdentity, &EnrollmentResponse)>,
) -> Result<ureq::Agent> {
    let roots = certificates(ca)?;
    let cert = if let Some((key, response)) = identity {
        Some(ClientCert::new_with_certs(
            &certificates(&response.certificate_chain_pem)?,
            PrivateKey::from_pem(key.private_key_pem.as_bytes())
                .map_err(|_| "invalid device private key")?,
        ))
    } else {
        None
    };
    let tls = TlsConfig::builder()
        .root_certs(RootCerts::new_with_certs(&roots))
        .client_cert(cert)
        .unversioned_rustls_crypto_provider(Arc::new(tls_provider()))
        .build();
    Ok(ureq::Agent::config_builder()
        .tls_config(tls)
        .max_redirects(0)
        .timeout_global(Some(Duration::from_secs(30)))
        .build()
        .new_agent())
}
fn transport(error: ureq::Error) -> Box<dyn Error> {
    match error {
        ureq::Error::StatusCode(status) => format!("controller rejected the request with HTTP {status}").into(),
        _ => "controller TLS/transport request failed; verify the origin, trust pin and device registration".into(),
    }
}
fn response_bytes(mut response: ureq::http::Response<ureq::Body>) -> Result<Vec<u8>> {
    response
        .body_mut()
        .with_config()
        .limit(files::LIMIT as u64)
        .read_to_vec()
        .map_err(|_| "controller response is invalid or too large".into())
}
fn invite(bytes: &[u8], identity: &DeviceIdentity, now: i64) -> Result<Invitation> {
    let invitation: Invitation = parse(bytes)?;
    let target = invitation
        .target_id
        .as_deref()
        .ok_or("invitation has not been registered by the controller")?;
    if invitation.schema_version != "fw.enrollment-invitation/v1"
        || !hex64(&invitation.token)
        || !canonical_uuid(&invitation.idempotency_key)
        || !canonical_uuid(target)
        || !invitation.token_id.as_deref().is_some_and(canonical_uuid)
        || invitation.name.is_empty()
        || invitation.name.len() > 128
        || invitation.platform != platform()?
        || invitation.expected_key_fingerprint != identity.key_fingerprint
        || invitation.api_origin.is_empty()
    {
        return Err("invitation does not match this device or is incomplete".into());
    }
    if now
        >= time(
            invitation
                .expires_at
                .as_deref()
                .ok_or("invitation expiry missing")?,
        )?
    {
        return Err("enrollment invitation expired".into());
    }
    Ok(invitation)
}
fn pending(
    state: &Directory,
    invitation: &Invitation,
    invitation_hash: &str,
    identity: &DeviceIdentity,
    controller: &str,
    trust_hash: &str,
) -> Result<Pending> {
    let target = invitation
        .target_id
        .as_deref()
        .ok_or("incomplete invitation")?;
    if let Some(bytes) = state.read_optional("pending-enrollment.json", true)? {
        let pending: Pending = parse(&bytes)?;
        if pending.schema_version != "fw.pending-enrollment/v1"
            || pending.invitation_hash != invitation_hash
            || pending.target_id != target
            || pending.key_fingerprint != identity.key_fingerprint
            || pending.controller_origin != controller
            || pending.trust_bundle_hash != trust_hash
            || !canonical_uuid(&pending.request_id)
            || !hex64(&pending.nonce)
            || pending.agent_version.is_empty()
            || pending.agent_version.len() > 256
        {
            return Err(
                "pending enrollment belongs to a different invitation, identity, or controller"
                    .into(),
            );
        }
        return Ok(pending);
    }
    let pending = Pending {
        schema_version: "fw.pending-enrollment/v1".into(),
        request_id: Uuid::new_v4().to_string(),
        nonce: fw_enrollment::random_token()?,
        agent_version: VERSION.into(),
        invitation_hash: invitation_hash.into(),
        target_id: target.into(),
        key_fingerprint: identity.key_fingerprint.clone(),
        controller_origin: controller.into(),
        trust_bundle_hash: trust_hash.into(),
    };
    state.write(
        "pending-enrollment.json",
        &serde_json::to_vec(&pending)?,
        false,
    )?;
    Ok(pending)
}
fn validate_saved(
    saved: &Enrolled,
    identity: &DeviceIdentity,
    ca: &str,
    controller: &str,
    trust_hash: &str,
    now: i64,
) -> Result<()> {
    if saved.schema_version != "fw.device-enrollment/v1"
        || saved.controller_origin != controller
        || saved.trust_bundle_hash != trust_hash
        || saved.response.trust_bundle_hash != trust_hash
    {
        return Err("saved enrollment is bound to a different controller or trust pin".into());
    }
    fw_enrollment::verify_enrollment_response(
        &saved.response,
        identity,
        ca,
        &saved.response.target_id,
        now,
    )?;
    Ok(())
}
fn enroll(
    state: &Directory,
    controller: &str,
    ca: &str,
    trust_hash: &str,
    invitation_path: &Path,
) -> Result<Value> {
    let identity = read_identity(state)?;
    let bytes = files::read_path(invitation_path, true)?;
    let invitation = invite(&bytes, &identity, Utc::now().timestamp())?;
    if let Some(bytes) = state.read_optional("enrollment.json", true)? {
        let saved: Enrolled = parse(&bytes)?;
        validate_saved(
            &saved,
            &identity,
            ca,
            controller,
            trust_hash,
            Utc::now().timestamp(),
        )?;
        if invitation.target_id.as_deref() != Some(saved.response.target_id.as_str()) {
            return Err("device is already enrolled for a different target".into());
        }
        return Ok(
            json!({"target_id":saved.response.target_id,"state":"already_enrolled","mode":"observe","enforcement":false}),
        );
    }
    let pending = pending(
        state,
        &invitation,
        &fw_enrollment::hash_bytes(&bytes),
        &identity,
        controller,
        trust_hash,
    )?;
    let request = EnrollmentRequest {
        schema_version: "f.enrollment-request/v1".into(),
        request_id: pending.request_id.clone(),
        token: invitation.token,
        csr_pem: identity.csr_pem.clone(),
        expected_key_fingerprint: identity.key_fingerprint.clone(),
        nonce: pending.nonce,
        platform: invitation.platform,
        agent_version: pending.agent_version,
    };
    let response: EnrollmentResponse = parse(&response_bytes(
        client(ca, None)?
            .post(format!("{controller}/internal/v1/enroll"))
            .send_json(&request)
            .map_err(transport)?,
    )?)?;
    if response.request_id != pending.request_id || response.trust_bundle_hash != trust_hash {
        return Err("enrollment response does not match the pinned request".into());
    }
    fw_enrollment::verify_enrollment_response(
        &response,
        &identity,
        ca,
        &pending.target_id,
        Utc::now().timestamp(),
    )?;
    let summary = json!({"target_id":response.target_id,"mode":"observe","enforcement":false,"certificate_file":state.path.join("certificate.pem"),"expires_at":response.expires_at});
    // enrollment.json is the authoritative atomic state. A crash after writing
    // the public certificate retries the same persisted issuance request.
    state.write(
        "certificate.pem",
        response.certificate_chain_pem.as_bytes(),
        true,
    )?;
    let saved = Enrolled {
        schema_version: "fw.device-enrollment/v1".into(),
        controller_origin: controller.into(),
        trust_bundle_hash: trust_hash.into(),
        response,
    };
    state.write("enrollment.json", &serde_json::to_vec(&saved)?, false)?;
    Ok(summary)
}
fn binary_hash() -> Result<String> {
    let mut file = File::open(std::env::current_exe()?)?;
    let mut digest = Sha256::new();
    let mut bytes = [0u8; 65_536];
    loop {
        let count = file.read(&mut bytes)?;
        if count == 0 {
            break;
        }
        digest.update(&bytes[..count]);
    }
    Ok(format!("sha256:{:x}", digest.finalize()))
}
fn backend_version() -> String {
    for executable in ["/usr/sbin/nft", "/usr/bin/nft", "/sbin/nft"] {
        if !Path::new(executable).is_file() {
            continue;
        }
        let Ok(mut child) = Command::new(executable)
            .arg("--version")
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()
        else {
            continue;
        };
        let deadline = Instant::now() + Duration::from_secs(2);
        loop {
            match child.try_wait() {
                Ok(Some(status)) => {
                    let mut output = String::new();
                    if status.success()
                        && child
                            .stdout
                            .take()
                            .is_some_and(|out| out.take(4096).read_to_string(&mut output).is_ok())
                    {
                        let version = output.trim();
                        if !version.is_empty()
                            && version.len() <= 128
                            && !version.contains(['\n', '\r'])
                        {
                            return version.to_owned();
                        }
                    }
                    return "unavailable".into();
                }
                _ if Instant::now() >= deadline => {
                    let _ = child.kill();
                    let _ = child.wait();
                    return "unavailable".into();
                }
                Err(_) => {
                    let _ = child.kill();
                    let _ = child.wait();
                    return "unavailable".into();
                }
                _ => std::thread::sleep(Duration::from_millis(20)),
            }
        }
    }
    "unavailable".into()
}
fn capability(
    target: &str,
    checked_at: i64,
    os_version: &str,
    backend: &str,
    build_hash: &str,
) -> Result<Value> {
    let timestamp = |seconds| {
        Utc.timestamp_opt(seconds, 0)
            .single()
            .map(|t| t.format("%Y-%m-%dT%H:%M:%SZ").to_string())
            .ok_or("invalid capability time")
    };
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
    let feature_map:serde_json::Map<String,Value>=features.into_iter().map(|name|(name.to_owned(),json!({"state":"unverified","reason_code":"CAPABILITY_NOT_QUALIFIED","evidence_hash":null}))).collect();
    Ok(
        json!({"schema_version":"f.target-capability/v1","target_id":target,"platform":platform()?,"enforcement_backend":"nftables","capability_version":"f.target-capability/v1","os_version":os_version,"backend_version":backend,"executor_build_hash":build_hash,"checked_at":timestamp(checked_at)?,"valid_until":timestamp(checked_at.checked_add(300).ok_or("capability time overflow")?)?,"profiles":[],"families":[],"directions":[],"protocols":[],"binding_kinds":[],"features":feature_map,"max_policies":4096,"max_rules":100000,"max_artifact_bytes":16777216,"qualification_profiles":[],"interfaces":[]}),
    )
}
fn authenticated(
    state: &Directory,
    controller: &str,
    ca: &str,
    trust_hash: &str,
    report: bool,
) -> Result<Value> {
    let identity = read_identity(state)?;
    let saved: Enrolled = parse(&state.read("enrollment.json")?)?;
    validate_saved(
        &saved,
        &identity,
        ca,
        controller,
        trust_hash,
        Utc::now().timestamp(),
    )?;
    let agent = client(ca, Some((&identity, &saved.response)))?;
    let response = if report {
        let version = std::fs::read_to_string("/proc/sys/kernel/osrelease")?;
        let version = version.trim();
        if version.is_empty() || version.len() > 128 {
            return Err("kernel version is not representable in a capability report".into());
        }
        let body = capability(
            &saved.response.target_id,
            Utc::now().timestamp(),
            version,
            &backend_version(),
            &binary_hash()?,
        )?;
        agent
            .post(format!("{controller}/internal/v1/capabilities"))
            .send_json(body)
            .map_err(transport)?
    } else {
        agent
            .get(format!("{controller}/internal/v1/device-status"))
            .call()
            .map_err(transport)?
    };
    let value: Value = parse(&response_bytes(response)?)?;
    if value
        .get("data")
        .and_then(|v| v.get("target_id"))
        .and_then(Value::as_str)
        != Some(saved.response.target_id.as_str())
    {
        return Err("controller returned a response for a different device".into());
    }
    Ok(value)
}
fn run(args: Vec<String>) -> Result<Value> {
    let args = Arguments::parse(args)?;
    platform()?;
    let state = Directory::open(
        Path::new(args.value("--state-dir")?),
        args.command == "init",
        true,
    )?;
    let _lock = state.lock()?;
    if args.command == "init" {
        return init(&state);
    }
    let controller = origin(args.value("--controller")?)?;
    // Validate the out-of-band pin before reading an invitation or constructing
    // any network request carrying its token.
    let pin = args.value("--trust-bundle-hash")?;
    let ca = pinned_ca(Path::new(args.value("--ca-file")?), pin)?;
    match args.command.as_str() {
        "enroll" => enroll(
            &state,
            &controller,
            &ca,
            pin,
            Path::new(args.value("--invitation-file")?),
        ),
        "report" => authenticated(&state, &controller, &ca, pin, true),
        "status" => authenticated(&state, &controller, &ca, pin, false),
        _ => Err("unknown command".into()),
    }
}
fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    if args.is_empty() || args == ["--help"] {
        println!("{HELP}");
        return;
    }
    match run(args) {
        Ok(value) => println!(
            "{}",
            serde_json::to_string_pretty(&value).expect("JSON value serializes")
        ),
        Err(error) => {
            eprintln!("{}", json!({"error":error.to_string()}));
            std::process::exit(1);
        }
    }
}
use chrono::TimeZone;

#[cfg(test)]
mod tests;
