//! Cleanup of the exact console token file configured by the trusted launcher.
//! Paths never come from HTTP. Unix identity and permissions are checked before
//! removal; non-Unix metadata checks do not establish platform ACL qualification.
#[cfg(unix)]
use std::{fs::File, os::unix::fs::MetadataExt};
use std::{
    fs::{self, Metadata},
    io,
    path::{Path, PathBuf},
};

pub(super) struct BootstrapFile {
    path: PathBuf,
    parent: PathBuf,
    token_metadata: Metadata,
    parent_metadata: Metadata,
    #[cfg(unix)]
    directory: File,
}

fn invalid(reason: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidInput, reason)
}

fn parent_metadata(path: &Path) -> io::Result<Metadata> {
    let metadata = fs::symlink_metadata(path)?;
    if !metadata.is_dir() || metadata.file_type().is_symlink() {
        return Err(invalid("bootstrap token parent must be a real directory"));
    }
    #[cfg(unix)]
    if metadata.mode() & 0o777 != 0o700 {
        return Err(invalid("bootstrap token parent must be private"));
    }
    Ok(metadata)
}

fn validate_token(metadata: &Metadata, parent: &Metadata) -> io::Result<()> {
    if !metadata.is_file() || metadata.file_type().is_symlink() {
        return Err(invalid("bootstrap token must be a regular file"));
    }
    #[cfg(unix)]
    if metadata.mode() & 0o777 != 0o600 || metadata.uid() != parent.uid() || metadata.nlink() != 1 {
        return Err(invalid("bootstrap token must be private and singly linked"));
    }
    #[cfg(not(unix))]
    let _ = parent;
    Ok(())
}

#[cfg(unix)]
fn same_object(before: &Metadata, after: &Metadata) -> bool {
    before.dev() == after.dev() && before.ino() == after.ino() && before.uid() == after.uid()
}

#[cfg(not(unix))]
fn same_object(before: &Metadata, after: &Metadata) -> bool {
    // There is no portable std file identity/ACL API. These checks detect
    // ordinary replacement without claiming the Unix identity guarantee.
    before.file_type() == after.file_type() && before.created().ok() == after.created().ok()
}

impl BootstrapFile {
    pub(super) fn open(path: PathBuf) -> io::Result<Self> {
        let name = path
            .file_name()
            .ok_or_else(|| invalid("bootstrap token path must name a file"))?
            .to_owned();
        let requested_parent = path
            .parent()
            .filter(|parent| !parent.as_os_str().is_empty())
            .unwrap_or(Path::new("."));
        let before = parent_metadata(requested_parent)?;
        let parent = requested_parent.canonicalize()?;
        let parent_metadata = parent_metadata(&parent)?;
        if !same_object(&before, &parent_metadata) {
            return Err(invalid(
                "bootstrap token parent changed during configuration",
            ));
        }
        let path = parent.join(name);
        let token_metadata = fs::symlink_metadata(&path)?;
        validate_token(&token_metadata, &parent_metadata)?;
        #[cfg(unix)]
        let directory = {
            let directory = File::open(&parent)?;
            if !same_object(&parent_metadata, &directory.metadata()?) {
                return Err(invalid(
                    "bootstrap token parent changed during configuration",
                ));
            }
            directory
        };
        Ok(Self {
            path,
            parent,
            token_metadata,
            parent_metadata,
            #[cfg(unix)]
            directory,
        })
    }

    pub(super) fn consume(&self) -> io::Result<()> {
        let parent = parent_metadata(&self.parent)?;
        if !same_object(&self.parent_metadata, &parent) {
            return Err(invalid("bootstrap token parent was replaced"));
        }
        let token = match fs::symlink_metadata(&self.path) {
            Ok(metadata) => metadata,
            Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(()),
            Err(error) => return Err(error),
        };
        validate_token(&token, &parent)?;
        if !same_object(&self.token_metadata, &token)
            || self.token_metadata.len() != token.len()
            || self.token_metadata.modified().ok() != token.modified().ok()
        {
            return Err(invalid("bootstrap token file was replaced or changed"));
        }
        // The pinned parent is private and owned by the configured token owner.
        // Other users cannot race this final unlink; same-UID compromise is not
        // a boundary this helper can provide. remove_file never follows a link.
        fs::remove_file(&self.path)?;
        #[cfg(unix)]
        self.directory.sync_all()?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[cfg(unix)]
    use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt, PermissionsExt, symlink};
    use std::{fs::OpenOptions, io::Write};

    struct Scratch(PathBuf);
    impl Scratch {
        fn new() -> Self {
            let path =
                std::env::temp_dir().join(format!("fw-bootstrap-cleanup-{}", uuid::Uuid::new_v4()));
            private_directory(&path);
            Self(path)
        }
    }
    impl Drop for Scratch {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }
    fn private_directory(path: &Path) {
        let mut builder = fs::DirBuilder::new();
        #[cfg(unix)]
        builder.mode(0o700);
        builder.create(path).unwrap();
    }
    fn token(path: &Path, content: &str) {
        let mut options = OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        options.mode(0o600);
        let mut file = options.open(path).unwrap();
        file.write_all(content.as_bytes()).unwrap();
        file.sync_all().unwrap();
    }

    #[test]
    fn consumed_token_is_removed_and_a_second_consume_does_not_recreate_it() {
        let scratch = Scratch::new();
        let path = scratch.0.join("bootstrap-token");
        token(&path, "unit token");
        let configured = BootstrapFile::open(path.clone()).unwrap();
        configured.consume().unwrap();
        configured.consume().unwrap();
        assert!(!path.exists());
        assert_eq!(fs::read_dir(&scratch.0).unwrap().count(), 0);
    }

    #[test]
    fn a_replacement_file_is_not_deleted() {
        let scratch = Scratch::new();
        let path = scratch.0.join("bootstrap-token");
        token(&path, "original token");
        let configured = BootstrapFile::open(path.clone()).unwrap();
        let retained = scratch.0.join("retained");
        fs::rename(&path, &retained).unwrap();
        token(&path, "replacement token");
        assert!(configured.consume().is_err());
        assert_eq!(fs::read_to_string(&path).unwrap(), "replacement token");
        assert_eq!(fs::read_to_string(&retained).unwrap(), "original token");
    }

    #[test]
    fn replacing_the_parent_cannot_delete_a_different_directorys_file() {
        let scratch = Scratch::new();
        let parent = scratch.0.join("state");
        private_directory(&parent);
        let path = parent.join("bootstrap-token");
        token(&path, "original token");
        let configured = BootstrapFile::open(path.clone()).unwrap();
        let retained = scratch.0.join("retained");
        fs::rename(&parent, &retained).unwrap();
        private_directory(&parent);
        token(&path, "different token");
        assert!(configured.consume().is_err());
        assert_eq!(fs::read_to_string(&path).unwrap(), "different token");
        assert_eq!(
            fs::read_to_string(retained.join("bootstrap-token")).unwrap(),
            "original token"
        );
    }

    #[cfg(unix)]
    #[test]
    fn symlink_inputs_and_replacements_leave_their_targets_untouched() {
        let scratch = Scratch::new();
        let target = scratch.0.join("target");
        token(&target, "unrelated content");
        let path = scratch.0.join("bootstrap-token");
        symlink(&target, &path).unwrap();
        assert!(BootstrapFile::open(path.clone()).is_err());
        fs::remove_file(&path).unwrap();
        token(&path, "original token");
        let configured = BootstrapFile::open(path.clone()).unwrap();
        fs::remove_file(&path).unwrap();
        symlink(&target, &path).unwrap();
        assert!(configured.consume().is_err());
        assert!(
            fs::symlink_metadata(&path)
                .unwrap()
                .file_type()
                .is_symlink()
        );
        assert_eq!(fs::read_to_string(&target).unwrap(), "unrelated content");
        let linked_parent = scratch.0.join("linked-parent");
        symlink(&scratch.0, &linked_parent).unwrap();
        assert!(BootstrapFile::open(linked_parent.join("target")).is_err());
    }

    #[cfg(unix)]
    #[test]
    fn existing_and_later_hardlinks_are_rejected() {
        let scratch = Scratch::new();
        let path = scratch.0.join("bootstrap-token");
        let linked = scratch.0.join("linked");
        token(&path, "unit token");
        fs::hard_link(&path, &linked).unwrap();
        assert!(BootstrapFile::open(path.clone()).is_err());
        fs::remove_file(&linked).unwrap();
        let configured = BootstrapFile::open(path.clone()).unwrap();
        fs::hard_link(&path, &linked).unwrap();
        assert!(configured.consume().is_err());
        assert_eq!(fs::read_to_string(&path).unwrap(), "unit token");
        assert_eq!(fs::read_to_string(&linked).unwrap(), "unit token");
    }

    #[cfg(unix)]
    #[test]
    fn public_file_or_parent_permissions_are_rejected() {
        let scratch = Scratch::new();
        let path = scratch.0.join("bootstrap-token");
        token(&path, "unit token");
        fs::set_permissions(&path, fs::Permissions::from_mode(0o644)).unwrap();
        assert!(BootstrapFile::open(path.clone()).is_err());
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
        let configured = BootstrapFile::open(path.clone()).unwrap();
        fs::set_permissions(&scratch.0, fs::Permissions::from_mode(0o755)).unwrap();
        assert!(BootstrapFile::open(path.clone()).is_err());
        assert!(configured.consume().is_err());
        assert!(path.exists());
    }
}
