//! Private journal paths. The immediate directory and every database/lock file
//! are caller-owned and private; symlinks and hardlinks are never accepted.
use crate::{ExecutorError, Result};
use std::{
    fs::{self, File, OpenOptions},
    path::{Component, Path, PathBuf},
};

#[cfg(unix)]
pub(crate) fn directory(path: &Path) -> Result<File> {
    use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
    // SAFETY: geteuid has no memory or argument preconditions.
    let uid = unsafe { libc::geteuid() };
    // A managed user namespace may map the filesystem root owner to its overflow
    // UID. The root inode itself cannot be exchanged by an unprivileged user.
    let root_owner = fs::metadata("/")?.uid();
    let mut current = PathBuf::new();
    for component in path.components() {
        if matches!(component, Component::ParentDir) {
            return Err(ExecutorError::Binding);
        }
        current.push(component.as_os_str());
        let metadata = fs::symlink_metadata(&current)?;
        if !metadata.is_dir() || metadata.file_type().is_symlink() {
            return Err(ExecutorError::Binding);
        }
        // A shared non-sticky ancestor permits another OS user to replace a
        // private child directory between validation and SQLite's own open.
        if metadata.mode() & 0o022 != 0 && metadata.mode() & libc::S_ISVTX == 0 {
            return Err(ExecutorError::Binding);
        }
        let trusted_shared_root =
            metadata.mode() & libc::S_ISVTX != 0 && metadata.uid() == root_owner;
        if current != Path::new("/")
            && metadata.uid() != uid
            && metadata.uid() != 0
            && !trusted_shared_root
        {
            return Err(ExecutorError::Binding);
        }
    }
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(path)?;
    let metadata = file.metadata()?;
    if metadata.uid() != uid || metadata.mode() & 0o077 != 0 {
        return Err(ExecutorError::Binding);
    }
    Ok(file)
}

#[cfg(not(unix))]
pub(crate) fn directory(_path: &Path) -> Result<File> {
    Err(ExecutorError::Binding)
}

pub(crate) fn parent(path: &Path) -> Result<File> {
    if path.file_name().is_none() {
        return Err(ExecutorError::Binding);
    }
    directory(
        path.parent()
            .filter(|p| !p.as_os_str().is_empty())
            .unwrap_or(Path::new(".")),
    )
}

#[cfg(unix)]
fn validate(file: &File) -> Result<()> {
    use std::os::unix::fs::MetadataExt;
    let metadata = file.metadata()?;
    // SAFETY: geteuid has no memory or argument preconditions.
    let uid = unsafe { libc::geteuid() };
    if !metadata.is_file()
        || metadata.uid() != uid
        || metadata.nlink() != 1
        || metadata.mode() & 0o077 != 0
    {
        return Err(ExecutorError::Binding);
    }
    Ok(())
}

#[cfg(unix)]
pub(crate) fn open(path: &Path, create: bool, exclusive: bool) -> Result<File> {
    use std::os::unix::fs::OpenOptionsExt;
    let mut options = OpenOptions::new();
    options
        .read(true)
        .write(true)
        .create(create)
        .create_new(exclusive)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK);
    let file = options.open(path)?;
    validate(&file)?;
    Ok(file)
}

#[cfg(not(unix))]
pub(crate) fn open(_path: &Path, _create: bool, _exclusive: bool) -> Result<File> {
    Err(ExecutorError::Binding)
}

pub(crate) fn sidecars(path: &Path) -> Result<()> {
    for suffix in ["-journal", "-wal", "-shm"] {
        let mut name = path.as_os_str().to_os_string();
        name.push(suffix);
        let name = PathBuf::from(name);
        match fs::symlink_metadata(&name) {
            Ok(_) => {
                open(&name, false, false)?;
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => return Err(error.into()),
        }
    }
    Ok(())
}

#[cfg(unix)]
pub(crate) fn unchanged(path: &Path, before: &File) -> Result<()> {
    use std::os::unix::fs::MetadataExt;
    let after = open(path, false, false)?;
    let before = before.metadata()?;
    let after = after.metadata()?;
    if before.dev() != after.dev() || before.ino() != after.ino() {
        return Err(ExecutorError::Binding);
    }
    Ok(())
}

#[cfg(not(unix))]
pub(crate) fn unchanged(_path: &Path, _before: &File) -> Result<()> {
    Err(ExecutorError::Binding)
}
