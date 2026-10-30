use super::{
    Result, agent, load_session, prepare_destination, read_private_file, request_error,
    write_private_file,
};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::{
    collections::BTreeMap,
    fs::{self, OpenOptions},
    io::Write,
    path::{Path, PathBuf},
};
use uuid::Uuid;

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Invitation {
    schema_version: String,
    api_origin: String,
    token: String,
    idempotency_key: String,
    name: String,
    platform: String,
    expected_key_fingerprint: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    target_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    token_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    expires_at: Option<String>,
}

struct Options {
    name: String,
    platform: String,
    fingerprint: String,
    output: PathBuf,
}

fn options(args: &[String]) -> Result<Options> {
    if args.len() != 8 {
        return Err(
            "use enroll-token --name NAME --platform PLATFORM --fingerprint SHA256 --output FILE"
                .into(),
        );
    }
    let mut values = BTreeMap::new();
    for index in (0..args.len()).step_by(2) {
        let pair = &args[index..index + 2];
        if !["--name", "--platform", "--fingerprint", "--output"].contains(&pair[0].as_str())
            || values.insert(pair[0].as_str(), pair[1].as_str()).is_some()
        {
            return Err("unknown or repeated enrollment option".into());
        }
    }
    let name = values["--name"];
    let platform = values["--platform"];
    let fingerprint = values["--fingerprint"];
    if name.trim().is_empty()
        || name.chars().count() > 128
        || name.chars().any(char::is_control)
        || !["linux", "windows", "macos"].contains(&platform)
        || !hash_value(fingerprint)
        || values["--output"].is_empty()
    {
        return Err("invalid target name, platform, fingerprint or destination".into());
    }
    Ok(Options {
        name: name.into(),
        platform: platform.into(),
        fingerprint: fingerprint.into(),
        output: values["--output"].into(),
    })
}

fn hash_value(value: &str) -> bool {
    value.strip_prefix("sha256:").is_some_and(|digest| {
        digest.len() == 64
            && digest
                .bytes()
                .all(|c| c.is_ascii_digit() || (b'a'..=b'f').contains(&c))
    })
}

fn canonical_uuid(value: &str) -> bool {
    Uuid::parse_str(value).is_ok_and(|uuid| uuid.to_string() == value)
}

fn validate_invitation(invite: &Invitation, input: &Options, base: &str) -> Result<()> {
    if invite.schema_version != "fw.enrollment-invitation/v1"
        || invite.api_origin != base
        || invite.name != input.name
        || invite.platform != input.platform
        || invite.expected_key_fingerprint != input.fingerprint
        || !canonical_uuid(&invite.idempotency_key)
        || invite.token.len() != 64
        || !invite
            .token
            .bytes()
            .all(|c| c.is_ascii_digit() || (b'a'..=b'f').contains(&c))
    {
        return Err("existing invitation belongs to another origin or target; use its original arguments or a new output file".into());
    }
    let metadata = [
        invite.target_id.is_some(),
        invite.token_id.is_some(),
        invite.expires_at.is_some(),
    ];
    if metadata.iter().any(|v| *v) && !metadata.iter().all(|v| *v) {
        return Err("incomplete invitation metadata".into());
    }
    if let (Some(target), Some(token), Some(expires)) =
        (&invite.target_id, &invite.token_id, &invite.expires_at)
    {
        validate_receipt(target, token, expires)?;
    }
    Ok(())
}

fn validate_receipt(target: &str, token: &str, expires: &str) -> Result<()> {
    let time = DateTime::parse_from_rfc3339(expires).map_err(|_| "invalid invitation expiry")?;
    if !canonical_uuid(target)
        || !canonical_uuid(token)
        || time
            .with_timezone(&Utc)
            .format("%Y-%m-%dT%H:%M:%SZ")
            .to_string()
            != expires
    {
        return Err("invalid enrollment invitation receipt".into());
    }
    Ok(())
}

#[cfg(unix)]
fn create_invitation(path: &Path, bytes: &[u8]) -> Result<()> {
    use std::os::unix::fs::OpenOptionsExt;
    let path = prepare_destination(path)?;
    // The credential is durable before an issuance request. A retry reuses it,
    // including after a response is lost; an existing file is never replaced here.
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW)
        .open(&path)?;
    file.write_all(bytes)?;
    file.sync_all()?;
    fs::File::open(path.parent().ok_or("invitation parent missing")?)?.sync_all()?;
    Ok(())
}

#[cfg(not(unix))]
fn create_invitation(_: &Path, _: &[u8]) -> Result<()> {
    Err("protected invitation files are not implemented on this platform".into())
}

fn admin_post(base: &str, session: &Value, route: &str, key: &str, body: Value) -> Result<Value> {
    let mut response = agent()
        .post(format!("{base}{route}"))
        .header("Origin", base)
        .header(
            "Cookie",
            session["cookie"].as_str().ok_or("invalid session file")?,
        )
        .header(
            "X-CSRF-Token",
            session["csrf_token"]
                .as_str()
                .ok_or("invalid session file")?,
        )
        .header("Idempotency-Key", key)
        .header("Content-Type", "application/json")
        .send_json(body)
        .map_err(request_error)?;
    let bytes = response
        .body_mut()
        .with_config()
        .limit(65_536)
        .read_to_vec()
        .map_err(|_| "invalid or oversized enrollment response")?;
    fw_contracts::parse_strict(&bytes).map_err(|_| "invalid enrollment response".into())
}

pub(super) fn issue(args: &[String], base: &str, session_path: &Path) -> Result<()> {
    let input = options(args)?;
    let session = load_session(session_path, base)?;
    let mut invite = match fs::symlink_metadata(&input.output) {
        Ok(_) => fw_contracts::parse_strict::<Invitation>(&read_private_file(&input.output)?)
            .map_err(|_| "invalid existing invitation file")?,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            let invite = Invitation {
                schema_version: "fw.enrollment-invitation/v1".into(),
                api_origin: base.into(),
                token: fw_enrollment::random_token()?,
                idempotency_key: Uuid::new_v4().to_string(),
                name: input.name.clone(),
                platform: input.platform.clone(),
                expected_key_fingerprint: input.fingerprint.clone(),
                target_id: None,
                token_id: None,
                expires_at: None,
            };
            create_invitation(&input.output, &serde_json::to_vec(&invite)?)?;
            invite
        }
        Err(error) => return Err(error.into()),
    };
    validate_invitation(&invite, &input, base)?;
    let response = admin_post(
        base,
        &session,
        "/api/v1/enrollment-tokens",
        &invite.idempotency_key,
        json!({"name":invite.name,"platform":invite.platform,"expected_key_fingerprint":invite.expected_key_fingerprint,"token_hash":fw_contracts::hash_bytes(invite.token.as_bytes())}),
    )?;
    let data = &response["data"];
    let target = data["target_id"]
        .as_str()
        .ok_or("invalid enrollment receipt")?;
    let token_id = data["token_id"]
        .as_str()
        .ok_or("invalid enrollment receipt")?;
    let expires = data["expires_at"]
        .as_str()
        .ok_or("invalid enrollment receipt")?;
    validate_receipt(target, token_id, expires)?;
    if invite.target_id.as_deref().is_some_and(|id| id != target)
        || invite.token_id.as_deref().is_some_and(|id| id != token_id)
        || invite
            .expires_at
            .as_deref()
            .is_some_and(|time| time != expires)
    {
        return Err("controller changed an existing invitation receipt".into());
    }
    invite.target_id = Some(target.into());
    invite.token_id = Some(token_id.into());
    invite.expires_at = Some(expires.into());
    write_private_file(&input.output, &serde_json::to_vec(&invite)?)?;
    println!(
        "{}",
        json!({"invitation_file":input.output,"target_id":target,"expires_at":expires,"mode":"observe","native_enforcement":false})
    );
    Ok(())
}

pub(super) fn revoke(args: &[String], base: &str, session_path: &Path) -> Result<()> {
    if args.len() != 1 || !canonical_uuid(&args[0]) {
        return Err("use revoke-target TARGET_UUID".into());
    }
    let session = load_session(session_path, base)?;
    let response = admin_post(
        base,
        &session,
        &format!("/api/v1/enrollments/{}/revoke", args[0]),
        &Uuid::new_v4().to_string(),
        json!({}),
    )?;
    if response["data"]["target_id"] != args[0] || response["data"]["revoked"] != true {
        return Err("controller did not confirm credential revocation".into());
    }
    println!(
        "{}",
        json!({"target_id":args[0],"revoked":true,"native_firewall_changed":false})
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    fn input() -> Options {
        Options {
            name: "Device".into(),
            platform: "linux".into(),
            fingerprint: format!("sha256:{}", "a".repeat(64)),
            output: "unused".into(),
        }
    }
    fn invitation() -> Invitation {
        let args = input();
        Invitation {
            schema_version: "fw.enrollment-invitation/v1".into(),
            api_origin: "http://127.0.0.1:8787".into(),
            token: "b".repeat(64),
            idempotency_key: Uuid::new_v4().to_string(),
            name: args.name,
            platform: args.platform,
            expected_key_fingerprint: args.fingerprint,
            target_id: None,
            token_id: None,
            expires_at: None,
        }
    }
    #[test]
    fn invitation_retries_cannot_switch_origin_identity_or_binding() {
        let mut invite = invitation();
        let args = input();
        let origin = "http://127.0.0.1:8787";
        validate_invitation(&invite, &args, origin).unwrap();
        assert!(validate_invitation(&invite, &args, "http://127.0.0.1:8790").is_err());
        invite.expected_key_fingerprint = format!("sha256:{}", "c".repeat(64));
        assert!(validate_invitation(&invite, &args, origin).is_err());
        invite = invitation();
        invite.target_id = Some(Uuid::new_v4().to_string());
        assert!(validate_invitation(&invite, &args, origin).is_err());
    }
    #[test]
    fn options_reject_duplicate_parameters_and_noncanonical_fingerprints() {
        let args = [
            "--name",
            "Device",
            "--platform",
            "linux",
            "--fingerprint",
            "sha256:no",
            "--output",
            "file",
        ]
        .map(str::to_owned);
        assert!(options(&args).is_err());
        let mut args = args;
        args[5] = format!("sha256:{}", "a".repeat(64));
        options(&args).unwrap();
        args[6] = "--name".into();
        assert!(options(&args).is_err());
    }
    #[cfg(unix)]
    #[test]
    fn invitation_creation_cannot_overwrite_an_existing_credential() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("private/invitation.json");
        create_invitation(&path, b"original").unwrap();
        assert!(create_invitation(&path, b"replacement").is_err());
        assert_eq!(read_private_file(&path).unwrap(), b"original");
    }
}
