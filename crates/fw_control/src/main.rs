use std::{
    fs::{self, OpenOptions},
    io::{self, Write},
    path::{Path, PathBuf},
    sync::Arc,
};

fn prepare_state_dir(path: &Path) -> io::Result<()> {
    // Refuse an existing symlink before chmod: following it could modify the
    // permissions of an unrelated directory supplied by another local process.
    match fs::symlink_metadata(path) {
        Ok(metadata) if metadata.file_type().is_symlink() || !metadata.is_dir() => {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "state directory must be a real directory",
            ));
        }
        Ok(_) => {}
        Err(error) if error.kind() == io::ErrorKind::NotFound => fs::create_dir_all(path)?,
        Err(error) => return Err(error),
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(path, fs::Permissions::from_mode(0o700))?;
    }
    Ok(())
}

fn write_bootstrap_token(state_dir: &Path, token: &str) -> io::Result<PathBuf> {
    let destination = state_dir.join("bootstrap-token");
    match fs::symlink_metadata(&destination) {
        Ok(metadata) if metadata.file_type().is_symlink() || !metadata.is_file() => {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "bootstrap token path must be a regular file",
            ));
        }
        Ok(_) => {}
        Err(error) if error.kind() == io::ErrorKind::NotFound => {}
        Err(error) => return Err(error),
    }
    // create_new rejects symlinks/existing names; rename replaces the directory
    // entry rather than truncating its target, including an existing hard link.
    let temporary = state_dir.join(format!(".bootstrap-{}.tmp", uuid::Uuid::new_v4()));
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut file = options.open(&temporary)?;
    let result = (|| {
        file.write_all(token.as_bytes())?;
        file.sync_all()?;
        drop(file);
        fs::rename(&temporary, &destination)?;
        #[cfg(unix)]
        fs::File::open(state_dir)?.sync_all()?;
        Ok(destination)
    })();
    if result.is_err() {
        let _ = fs::remove_file(&temporary);
    }
    result
}

fn remove_bootstrap_token(state_dir: &Path) -> io::Result<()> {
    let path = state_dir.join("bootstrap-token");
    match fs::symlink_metadata(&path) {
        Ok(metadata) if metadata.is_file() && !metadata.file_type().is_symlink() => {
            fs::remove_file(path)?;
            #[cfg(unix)]
            fs::File::open(state_dir)?.sync_all()?;
            Ok(())
        }
        Ok(_) => Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "bootstrap token path must be a regular file",
        )),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error),
    }
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let state_dir = PathBuf::from(std::env::var("FW_STATE_DIR").unwrap_or_else(|_| "state".into()));
    let args: Vec<String> = std::env::args().skip(1).collect();
    if args == ["--help"] {
        println!(
            "fw_control [init-enrollment-ca]\nFW_STATE_DIR: private controller state (default state)\nFW_PUBLIC_ORIGIN: exact localhost origin (default http://localhost:8787; port follows FW_PORT)\nAn explicit http://127.0.0.1 origin keeps legacy bootstrap access but disables passkeys.\nFW_ENROLLMENT_DIR: optional private enrollment PKI directory\nFW_ENROLLMENT_PORT: separate loopback TLS port (default 8791)\ninit-enrollment-ca creates fresh keys once; it never replaces existing keys.\nDevice enrollment does not enable host firewall enforcement."
        );
        return Ok(());
    }
    if args == ["init-enrollment-ca"] {
        let directory = if let Some(directory) = std::env::var_os("FW_ENROLLMENT_DIR") {
            PathBuf::from(directory)
        } else {
            prepare_state_dir(&state_dir)?;
            state_dir.join("enrollment")
        };
        let pki = fw_enrollment::init_controller_pki(&directory, chrono::Utc::now().timestamp())?;
        println!(
            "{}",
            serde_json::json!({
                "pki_directory": directory,
                "ca_file": directory.join("ca.pem"),
                "trust_bundle_hash": pki.authority.trust_bundle_hash(),
                "mode": "observe"
            })
        );
        return Ok(());
    }
    if !args.is_empty() {
        return Err("unknown command; see --help".into());
    }
    prepare_state_dir(&state_dir)?;
    let port: u16 = std::env::var("FW_PORT")
        .unwrap_or_else(|_| "8787".into())
        .parse()?;
    let address = std::net::SocketAddr::from(([127, 0, 0, 1], port));
    let listener = tokio::net::TcpListener::bind(address).await?;
    let address = listener.local_addr()?;
    let default_origin = format!("http://localhost:{}", address.port());
    let origin = std::env::var("FW_PUBLIC_ORIGIN").unwrap_or_else(|_| default_origin.clone());
    if origin != default_origin && origin != format!("http://{address}") {
        return Err(
            "FW_PUBLIC_ORIGIN must exactly match the bound localhost or 127.0.0.1 origin".into(),
        );
    }
    // Validate and bind enrollment before serving the public API. Missing/bad TLS
    // configuration must fail startup instead of leaving a usable token issuer.
    let enrollment = if let Some(directory) = std::env::var_os("FW_ENROLLMENT_DIR") {
        let pki = fw_enrollment::load_controller_pki(
            Path::new(&directory),
            chrono::Utc::now().timestamp(),
        )?;
        let enrollment_port: u16 = std::env::var("FW_ENROLLMENT_PORT")
            .unwrap_or_else(|_| "8791".into())
            .parse()?;
        let enrollment_address = std::net::SocketAddr::from(([127, 0, 0, 1], enrollment_port));
        let listener = fw_control::tls::EnrollmentListener::bind(enrollment_address, &pki).await?;
        Some((listener, pki.authority))
    } else {
        None
    };
    let token = fw_control::generate_token();
    let store = fw_store::Store::open(state_dir.join("controller.sqlite3"))?;
    let tenant = fw_store::Tenant::new(fw_control::ORG, fw_control::PROJECT)?;
    store.ensure_tenant(
        fw_control::ORG,
        fw_control::PROJECT,
        "Local development",
        chrono::Utc::now().timestamp(),
    )?;
    store.ensure_principal(
        &tenant,
        fw_control::PRINCIPAL,
        "human",
        chrono::Utc::now().timestamp(),
    )?;
    let owner_enrolled = store.passkey_owner_enrolled(&tenant, fw_control::PRINCIPAL)?;
    let token_path = if owner_enrolled {
        remove_bootstrap_token(&state_dir)?;
        None
    } else {
        Some(write_bootstrap_token(&state_dir, &token)?)
    };
    let mut state = fw_control::AppState::new(store, origin.clone(), &token)?;
    if let Some(path) = &token_path {
        state = state.with_bootstrap_token_file(path.clone())?;
    }
    let (state, enrollment_listener) = match enrollment {
        Some((listener, authority)) => (state.with_enrollment(authority), Some(listener)),
        None => (state, None),
    };
    let state = Arc::new(state);
    let flush_state = state.clone();
    let denial_flush = tokio::spawn(async move {
        let mut interval = tokio::time::interval(std::time::Duration::from_secs(60));
        loop {
            interval.tick().await;
            flush_state.flush_authentication_denials();
        }
    });
    let web = PathBuf::from(std::env::var("FW_WEB_DIR").unwrap_or_else(|_| "web/dist".into()));
    eprintln!(
        "fw_control listening on {address}; open {origin}; observe-only development profile; no native enforcement"
    );
    if let Some(token_path) = token_path {
        eprintln!(
            "One-use local login token (10-minute lifetime) stored at {}",
            token_path.display()
        );
    } else {
        eprintln!(
            "Local owner is enrolled; passkey authentication required; bootstrap login disabled."
        );
    }
    async fn shutdown() {
        let _ = tokio::signal::ctrl_c().await;
    }
    let public = async {
        axum::serve(listener, fw_control::router(state.clone(), web))
            .with_graceful_shutdown(shutdown())
            .await
    };
    if let Some(listener) = enrollment_listener {
        eprintln!(
            "Device enrollment listening on https://{}; transport registration only",
            listener.local_socket_addr()?
        );
        let internal = async {
            axum::serve(
                listener,
                fw_control::enrollment_router(state.clone())
                    .into_make_service_with_connect_info::<fw_control::tls::TlsPeer>(),
            )
            .with_graceful_shutdown(shutdown())
            .await
        };
        tokio::try_join!(public, internal)?;
    } else {
        public.await?;
    }
    denial_flush.abort();
    Ok(())
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;
    use std::os::unix::fs::{PermissionsExt, symlink};

    struct Scratch(PathBuf);
    impl Scratch {
        fn new() -> Self {
            let path = std::env::temp_dir().join(format!("fw-token-test-{}", uuid::Uuid::new_v4()));
            fs::create_dir(&path).unwrap();
            Self(path)
        }
    }
    impl Drop for Scratch {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    #[test]
    fn token_replacement_is_private_and_does_not_modify_hardlink_target() {
        let scratch = Scratch::new();
        let state = scratch.0.join("state");
        prepare_state_dir(&state).unwrap();
        let original = scratch.0.join("unrelated");
        fs::write(&original, "original").unwrap();
        fs::set_permissions(&original, fs::Permissions::from_mode(0o644)).unwrap();
        fs::hard_link(&original, state.join("bootstrap-token")).unwrap();
        let token_file = write_bootstrap_token(&state, "local-test-token").unwrap();
        assert_eq!(fs::read_to_string(&original).unwrap(), "original");
        assert_eq!(fs::read_to_string(&token_file).unwrap(), "local-test-token");
        assert_eq!(
            fs::metadata(&token_file).unwrap().permissions().mode() & 0o777,
            0o600
        );
        assert_eq!(
            fs::metadata(&state).unwrap().permissions().mode() & 0o777,
            0o700
        );
        assert_eq!(fs::read_dir(&state).unwrap().count(), 1);
        remove_bootstrap_token(&state).unwrap();
        remove_bootstrap_token(&state).unwrap();
        assert!(!token_file.exists());
        assert_eq!(fs::read_to_string(&original).unwrap(), "original");
    }

    #[test]
    fn token_and_directory_symlinks_are_rejected() {
        let scratch = Scratch::new();
        let victim = scratch.0.join("victim");
        fs::create_dir(&victim).unwrap();
        fs::set_permissions(&victim, fs::Permissions::from_mode(0o755)).unwrap();
        let linked = scratch.0.join("linked");
        symlink(&victim, &linked).unwrap();
        assert!(prepare_state_dir(&linked).is_err());
        assert_eq!(
            fs::metadata(&victim).unwrap().permissions().mode() & 0o777,
            0o755
        );
        let state = scratch.0.join("state");
        prepare_state_dir(&state).unwrap();
        let target = victim.join("file");
        fs::write(&target, "original").unwrap();
        symlink(&target, state.join("bootstrap-token")).unwrap();
        assert!(write_bootstrap_token(&state, "local-test-token").is_err());
        assert!(remove_bootstrap_token(&state).is_err());
        assert_eq!(fs::read_to_string(&target).unwrap(), "original");
    }
}
