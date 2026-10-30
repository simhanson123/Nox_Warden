//! Local development login and read-only controller client.
use serde_json::{Value, json};
use std::{
    error::Error,
    fs::{self, File, OpenOptions},
    io::{Read, Write},
    path::{Component, Path, PathBuf},
    time::Duration,
};
use uuid::Uuid;
type Result<T> = std::result::Result<T, Box<dyn Error>>;
const FILE_LIMIT: u64 = 16_384;

fn agent() -> ureq::Agent {
    ureq::Agent::config_builder()
        .max_redirects(0)
        .timeout_global(Some(Duration::from_secs(10)))
        .build()
        .new_agent()
}
fn request_error(error: ureq::Error) -> Box<dyn Error> {
    match error {
        ureq::Error::StatusCode(code) => {
            format!("controller returned HTTP {code}; authenticate again if the session expired")
                .into()
        }
        _ => "controller transport failed; check the configured origin and TLS trust".into(),
    }
}
fn run() -> Result<()> {
    let args: Vec<String> = std::env::args().skip(1).collect();
    if args.is_empty() || args == ["--help"] {
        println!(
            "fw_cli <login|health|status|requests|operations|audit|capabilities|assets|services>\nEnvironment:\n  FW_API_URL: controller origin (default http://127.0.0.1:8787)\n  FW_BOOTSTRAP_FILE: protected token file (default state/bootstrap-token)\n  FW_SESSION_FILE: private local session file (default state/cli-session.json)\nRun login once after starting the controller, then use authenticated read commands.\nLogin currently requires Unix private-file protections. No command changes the host firewall."
        );
        return Ok(());
    }
    if args.len() != 1 {
        return Err(
            "one command is required; token values are never command-line arguments".into(),
        );
    }
    let base = std::env::var("FW_API_URL").unwrap_or_else(|_| "http://127.0.0.1:8787".into());
    validate_base(&base)?;
    let base = base.trim_end_matches('/');
    let session_path = PathBuf::from(
        std::env::var("FW_SESSION_FILE").unwrap_or_else(|_| "state/cli-session.json".into()),
    );
    if args[0] == "login" {
        let token_path = PathBuf::from(
            std::env::var("FW_BOOTSTRAP_FILE").unwrap_or_else(|_| "state/bootstrap-token".into()),
        );
        login(base, &token_path, &session_path)?;
        println!(
            "{}",
            json!({"authenticated":true,"session_file":session_path,"profile":"local-development"})
        );
        return Ok(());
    }
    let route = match args[0].as_str() {
        "health" => "/healthz",
        "status" => "/api/v1/status",
        "requests" => "/api/v1/access-requests",
        "operations" => "/api/v1/operations",
        "audit" => "/api/v1/audit/events",
        "capabilities" => "/api/v1/capabilities",
        "assets" => "/api/v1/assets",
        "services" => "/api/v1/services",
        _ => return Err("unknown command; see --help".into()),
    };
    let client = agent();
    let mut req = client.get(format!("{base}{route}"));
    if args[0] != "health" {
        let session = load_session(&session_path, base)?;
        req = req.header(
            "Cookie",
            session["cookie"].as_str().ok_or("invalid session file")?,
        );
    }
    let response: Value = req
        .call()
        .map_err(request_error)?
        .body_mut()
        .with_config()
        .limit(262_144)
        .read_json()
        .map_err(|_| "invalid or oversized controller response")?;
    println!("{}", serde_json::to_string_pretty(&response)?);
    Ok(())
}
fn login(base: &str, token_path: &Path, session_path: &Path) -> Result<()> {
    // Validate destination before consuming the server's one-use credential.
    prepare_destination(session_path)?;
    let bytes = read_private_file(token_path)?;
    let token = std::str::from_utf8(&bytes)
        .map_err(|_| "invalid bootstrap token file")?
        .trim();
    if !token_value(token) {
        return Err("invalid bootstrap token file".into());
    }
    let mut response = agent()
        .post(format!("{base}/api/v1/session/bootstrap"))
        .header("Origin", base)
        .header("Idempotency-Key", Uuid::new_v4().to_string())
        .header("Content-Type", "application/json")
        .send_json(json!({"token":token}))
        .map_err(request_error)?;
    if response.status() != 200 {
        return Err("unexpected bootstrap response status".into());
    }
    let cookies: Vec<String> = response
        .headers()
        .get_all("set-cookie")
        .iter()
        .map(|v| v.to_str().map(str::to_owned))
        .collect::<std::result::Result<_, _>>()
        .map_err(|_| "invalid bootstrap cookie")?;
    let body: Value = response
        .body_mut()
        .with_config()
        .limit(65_536)
        .read_json()
        .map_err(|_| "invalid bootstrap response")?;
    let session = session_from_response(base, &cookies, &body)?;
    write_private_file(session_path, &serde_json::to_vec(&session)?)?;
    Ok(())
}
fn token_value(s: &str) -> bool {
    (32..=256).contains(&s.len())
        && s.bytes()
            .all(|c| c.is_ascii_alphanumeric() || b"-_".contains(&c))
}
fn session_from_response(base: &str, cookies: &[String], body: &Value) -> Result<Value> {
    if body["data"]["authenticated"] != true {
        return Err("controller did not authenticate the session".into());
    }
    let csrf = body["data"]["csrf_token"]
        .as_str()
        .filter(|s| token_value(s))
        .ok_or("invalid bootstrap response")?;
    let matching: Vec<_> = cookies
        .iter()
        .filter(|s| {
            s.split(';')
                .next()
                .is_some_and(|part| part.starts_with("fw_session="))
        })
        .collect();
    if matching.len() != 1 {
        return Err("bootstrap response requires one session cookie".into());
    }
    let cookie = matching[0]
        .split(';')
        .next()
        .ok_or("invalid bootstrap cookie")?;
    if !cookie.strip_prefix("fw_session=").is_some_and(token_value) {
        return Err("invalid bootstrap cookie".into());
    }
    let attributes: Vec<_> = matching[0]
        .split(';')
        .skip(1)
        .map(|s| s.trim().to_ascii_lowercase())
        .collect();
    if !attributes.iter().any(|s| s == "httponly")
        || !attributes.iter().any(|s| s == "samesite=strict")
        || !attributes.iter().any(|s| s == "path=/")
    {
        return Err("bootstrap cookie lacks required restrictions".into());
    }
    if base.starts_with("https://") && !attributes.iter().any(|s| s == "secure") {
        return Err("HTTPS session cookie requires Secure".into());
    }
    Ok(
        json!({"schema_version":"fw.local-cli-session/v1","api_origin":base,"cookie":cookie,"csrf_token":csrf}),
    )
}
fn load_session(path: &Path, base: &str) -> Result<Value> {
    let bytes = read_private_file(path)?;
    let session: Value = serde_json::from_slice(&bytes).map_err(|_| "invalid session file")?;
    if session["schema_version"] != "fw.local-cli-session/v1"
        || session["api_origin"] != base
        || !session["cookie"]
            .as_str()
            .and_then(|s| s.strip_prefix("fw_session="))
            .is_some_and(token_value)
        || !session["csrf_token"].as_str().is_some_and(token_value)
    {
        return Err("session is invalid or belongs to a different API origin; run login".into());
    }
    Ok(session)
}
fn validate_base(base: &str) -> Result<()> {
    let uri: ureq::http::Uri = base.parse().map_err(|_| "invalid controller origin")?;
    let authority = uri.authority().ok_or("API authority missing")?;
    let local = uri.scheme_str() == Some("http") && uri.host() == Some("127.0.0.1");
    if authority.as_str().contains('@')
        || uri.query().is_some()
        || !["", "/"].contains(&uri.path())
        || !(local || uri.scheme_str() == Some("https"))
    {
        return Err(
            "API must be an HTTPS origin or loopback HTTP origin without credentials".into(),
        );
    }
    Ok(())
}
fn absolute_without_symlinks(path: &Path) -> Result<PathBuf> {
    let path = if path.is_absolute() {
        path.to_path_buf()
    } else {
        std::env::current_dir()?.join(path)
    };
    let mut checked = PathBuf::new();
    for component in path.components() {
        match component {
            Component::ParentDir => {
                return Err("credential paths must not contain parent traversal".into());
            }
            Component::CurDir => continue,
            _ => checked.push(component.as_os_str()),
        }
        match fs::symlink_metadata(&checked) {
            Ok(m) if m.file_type().is_symlink() => {
                return Err("credential paths must not contain symbolic links".into());
            }
            Ok(_) => {}
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(e) => return Err(e.into()),
        }
    }
    Ok(checked)
}
#[cfg(unix)]
fn private_metadata(metadata: &fs::Metadata) -> Result<()> {
    use std::os::unix::fs::{MetadataExt, PermissionsExt};
    // geteuid has no preconditions and reads the current process's identity.
    let uid = unsafe { libc::geteuid() };
    if metadata.uid() != uid || metadata.permissions().mode() & 0o077 != 0 {
        return Err("credential files and directories must be private to the current user".into());
    }
    Ok(())
}
#[cfg(unix)]
fn prepare_destination(path: &Path) -> Result<PathBuf> {
    use std::os::unix::fs::DirBuilderExt;
    let path = absolute_without_symlinks(path)?;
    let parent = path
        .parent()
        .ok_or("session file needs a parent directory")?;
    let mut builder = fs::DirBuilder::new();
    builder.recursive(true).mode(0o700);
    builder.create(parent)?;
    let parent_meta = fs::symlink_metadata(parent)?;
    if !parent_meta.is_dir() || parent_meta.file_type().is_symlink() {
        return Err("session parent must be a real directory".into());
    }
    private_metadata(&parent_meta)?;
    match fs::symlink_metadata(&path) {
        Ok(m) if !m.is_file() || m.file_type().is_symlink() => {
            return Err("session destination must be a regular file".into());
        }
        Ok(m) => private_metadata(&m)?,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
        Err(e) => return Err(e.into()),
    }
    Ok(path)
}
#[cfg(not(unix))]
fn prepare_destination(_: &Path) -> Result<PathBuf> {
    Err("native protected credential-file support is not yet implemented on this platform".into())
}
#[cfg(unix)]
fn read_private_file(path: &Path) -> Result<Vec<u8>> {
    use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
    let path = absolute_without_symlinks(path)?;
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW)
        .open(path)?;
    let metadata = file.metadata()?;
    private_metadata(&metadata)?;
    if !metadata.is_file() || metadata.nlink() != 1 || metadata.len() > FILE_LIMIT {
        return Err("credential must be a bounded regular file with a single link".into());
    }
    let mut bytes = Vec::new();
    file.take(FILE_LIMIT + 1).read_to_end(&mut bytes)?;
    if bytes.len() as u64 > FILE_LIMIT {
        return Err("credential file exceeds size limit".into());
    }
    Ok(bytes)
}
#[cfg(not(unix))]
fn read_private_file(_: &Path) -> Result<Vec<u8>> {
    Err("native protected credential-file support is not yet implemented on this platform".into())
}
#[cfg(unix)]
fn write_private_file(path: &Path, bytes: &[u8]) -> Result<()> {
    use std::os::unix::fs::OpenOptionsExt;
    let path = prepare_destination(path)?;
    let parent = path.parent().ok_or("session parent missing")?;
    let temporary = parent.join(format!(".fw-session-{}.tmp", Uuid::new_v4()));
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW)
        .open(&temporary)?;
    let result = (|| -> Result<()> {
        file.write_all(bytes)?;
        file.sync_all()?;
        drop(file);
        fs::rename(&temporary, &path)?;
        File::open(parent)?.sync_all()?;
        Ok(())
    })();
    if result.is_err() {
        let _ = fs::remove_file(&temporary);
    }
    result
}
#[cfg(not(unix))]
fn write_private_file(_: &Path, _: &[u8]) -> Result<()> {
    Err("native protected credential-file support is not yet implemented on this platform".into())
}
fn main() {
    if let Err(error) = run() {
        eprintln!("{}", json!({"error":error.to_string()}));
        std::process::exit(1);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn token() -> String {
        "a".repeat(64)
    }
    fn valid_response() -> (Vec<String>, Value) {
        (
            vec![format!(
                "fw_session={}; HttpOnly; SameSite=Strict; Path=/; Max-Age=28800",
                token()
            )],
            json!({"data":{"authenticated":true,"csrf_token":token()}}),
        )
    }
    #[test]
    fn origin_validation_rejects_credential_confusion() {
        for bad in [
            "http://127.0.0.1:8787@evil.example",
            "http://example.com",
            "https://user:pass@example.com",
            "https://example.com/path",
            "https://example.com/?query=yes",
        ] {
            assert!(validate_base(bad).is_err());
        }
        assert!(validate_base("http://127.0.0.1:8787").is_ok());
        assert!(validate_base("https://firewall.example").is_ok());
    }
    #[test]
    fn bootstrap_response_requires_safe_cookie_and_csrf() {
        let (cookies, body) = valid_response();
        let session = session_from_response("http://127.0.0.1:8787", &cookies, &body).unwrap();
        assert_eq!(session["api_origin"], "http://127.0.0.1:8787");
        assert!(
            session_from_response(
                "http://127.0.0.1:8787",
                &[cookies[0].clone(), cookies[0].clone()],
                &body
            )
            .is_err()
        );
        assert!(
            session_from_response(
                "http://127.0.0.1:8787",
                &[format!("fw_session={}; Path=/", token())],
                &body
            )
            .is_err()
        );
        assert!(
            session_from_response(
                "http://127.0.0.1:8787",
                &cookies,
                &json!({"data":{"authenticated":true,"csrf_token":"bad\nvalue"}})
            )
            .is_err()
        );
    }
    #[test]
    fn https_cookie_requires_secure() {
        let (cookies, body) = valid_response();
        assert!(session_from_response("https://example.com", &cookies, &body).is_err());
        assert!(
            session_from_response(
                "https://example.com",
                &[format!("{}; Secure", cookies[0])],
                &body
            )
            .is_ok()
        );
    }
    #[test]
    #[cfg(unix)]
    fn private_session_round_trip_is_origin_bound() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("nested/session.json");
        let (cookies, body) = valid_response();
        let session = session_from_response("http://127.0.0.1:8787", &cookies, &body).unwrap();
        write_private_file(&path, &serde_json::to_vec(&session).unwrap()).unwrap();
        assert_eq!(
            fs::metadata(&path).unwrap().permissions().mode() & 0o777,
            0o600
        );
        assert_eq!(
            load_session(&path, "http://127.0.0.1:8787").unwrap(),
            session
        );
        assert!(load_session(&path, "https://elsewhere.example").is_err());
    }
    #[test]
    #[cfg(unix)]
    fn symlink_paths_and_public_files_are_rejected() {
        use std::os::unix::fs::{PermissionsExt, symlink};
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("token");
        fs::write(&path, token()).unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o644)).unwrap();
        assert!(read_private_file(&path).is_err());
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
        let link = dir.path().join("link");
        symlink(&path, &link).unwrap();
        assert!(read_private_file(&link).is_err());
        assert!(write_private_file(&link, b"replacement").is_err());
        let parent_link = dir.path().join("parent-link");
        symlink(dir.path(), &parent_link).unwrap();
        assert!(write_private_file(&parent_link.join("session"), b"replacement").is_err());
        assert_eq!(fs::read(&path).unwrap(), token().as_bytes());
    }
    #[test]
    #[cfg(unix)]
    fn atomic_replacement_preserves_hardlink_target() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        // TempDir inherits the process umask; this positive fixture needs a
        // private parent independently of the runner's default permissions.
        fs::set_permissions(dir.path(), fs::Permissions::from_mode(0o700)).unwrap();
        let original = dir.path().join("original");
        fs::write(&original, b"original").unwrap();
        fs::set_permissions(&original, fs::Permissions::from_mode(0o600)).unwrap();
        let dest = dir.path().join("session");
        fs::hard_link(&original, &dest).unwrap();
        assert!(read_private_file(&dest).is_err());
        write_private_file(&dest, b"replacement").unwrap();
        assert_eq!(fs::read(original).unwrap(), b"original");
        assert_eq!(read_private_file(&dest).unwrap(), b"replacement");
    }
    #[test]
    #[cfg(unix)]
    fn oversized_credentials_and_shared_parent_fail() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        let token = dir.path().join("large");
        fs::write(&token, vec![b'a'; FILE_LIMIT as usize + 1]).unwrap();
        fs::set_permissions(&token, fs::Permissions::from_mode(0o600)).unwrap();
        assert!(read_private_file(&token).is_err());
        let shared = dir.path().join("shared");
        fs::create_dir(&shared).unwrap();
        fs::set_permissions(&shared, fs::Permissions::from_mode(0o755)).unwrap();
        assert!(write_private_file(&shared.join("session"), b"data").is_err());
    }
}
