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

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let state_dir = PathBuf::from(std::env::var("FW_STATE_DIR").unwrap_or_else(|_| "state".into()));
    prepare_state_dir(&state_dir)?;
    let port: u16 = std::env::var("FW_PORT")
        .unwrap_or_else(|_| "8787".into())
        .parse()?;
    let address = std::net::SocketAddr::from(([127, 0, 0, 1], port));
    let listener = tokio::net::TcpListener::bind(address).await?;
    let token = fw_control::generate_token();
    let token_path = write_bootstrap_token(&state_dir, &token)?;
    let store = fw_store::Store::open(state_dir.join("controller.sqlite3"))?;
    let state = Arc::new(fw_control::AppState::new(
        store,
        format!("http://{address}"),
        &token,
    )?);
    let web = PathBuf::from(std::env::var("FW_WEB_DIR").unwrap_or_else(|_| "web/dist".into()));
    eprintln!(
        "fw_control listening on {address}; observe-only development profile; no native enforcement"
    );
    eprintln!(
        "One-use local login token (10-minute lifetime) stored at {}",
        token_path.display()
    );
    axum::serve(listener, fw_control::router(state, web))
        .with_graceful_shutdown(async {
            let _ = tokio::signal::ctrl_c().await;
        })
        .await?;
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
        assert_eq!(fs::read_to_string(&target).unwrap(), "original");
    }
}
