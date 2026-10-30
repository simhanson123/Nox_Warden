use crate::{Error, Result};
use fw_contracts::{MAX_INTERNAL_BYTES, canonical_bytes, parse_strict_with_limit};
use serde::{Serialize, de::DeserializeOwned};
use std::fs::{self, File, OpenOptions};
use std::io::{Read, Write};
use std::os::unix::fs::{DirBuilderExt, MetadataExt, OpenOptionsExt};
use std::path::{Component, Path};

fn owner() -> u32 {
    // SAFETY: geteuid has no arguments or memory preconditions.
    unsafe { libc::geteuid() }
}
pub fn directory(path: &Path) -> Result<()> {
    if !path.is_absolute() || !path.starts_with("/lab") {
        return Err(Error::new("PRIVATE_PATH_OUTSIDE_LAB"));
    }
    let mut current = std::path::PathBuf::new();
    for component in path.components() {
        if matches!(component, Component::ParentDir | Component::CurDir) {
            return Err(Error::new("PRIVATE_PATH_TRAVERSAL"));
        }
        current.push(component.as_os_str());
        let meta = fs::symlink_metadata(&current)?;
        if !meta.is_dir() || meta.file_type().is_symlink() {
            return Err(Error::new("PRIVATE_PATH_SYMLINK"));
        }
        if current.starts_with("/lab") && (meta.uid() != owner() || meta.mode() & 0o077 != 0) {
            return Err(Error::new("PRIVATE_DIRECTORY_PERMISSIONS"));
        }
    }
    Ok(())
}
pub fn create_directory(path: &Path) -> Result<()> {
    let parent = path.parent().ok_or(Error::new("PRIVATE_PATH"))?;
    directory(parent)?;
    fs::DirBuilder::new().mode(0o700).create(path)?;
    directory(path)?;
    File::open(parent)?.sync_all()?;
    Ok(())
}
pub fn read_bytes(path: &Path, maximum: usize) -> Result<Vec<u8>> {
    directory(path.parent().ok_or(Error::new("PRIVATE_PATH"))?)?;
    let mut file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_CLOEXEC)
        .open(path)?;
    let meta = file.metadata()?;
    if !meta.is_file()
        || meta.uid() != owner()
        || meta.mode() & 0o077 != 0
        || meta.nlink() != 1
        || meta.len() > maximum as u64
    {
        return Err(Error::new("PRIVATE_FILE_PERMISSIONS_OR_SIZE"));
    }
    let mut bytes = Vec::new();
    (&mut file)
        .take(maximum as u64 + 1)
        .read_to_end(&mut bytes)?;
    if bytes.len() > maximum {
        return Err(Error::new("PRIVATE_FILE_SIZE"));
    }
    Ok(bytes)
}
pub fn read<T: DeserializeOwned>(path: &Path) -> Result<T> {
    let bytes = read_bytes(path, MAX_INTERNAL_BYTES)?;
    parse_strict_with_limit(&bytes, MAX_INTERNAL_BYTES).map_err(|_| Error::new("PRIVATE_FILE_JSON"))
}
pub fn write<T: Serialize>(path: &Path, value: &T) -> Result<()> {
    let bytes = canonical_bytes(value).map_err(|_| Error::new("PRIVATE_FILE_CANONICAL"))?;
    if bytes.len() > MAX_INTERNAL_BYTES {
        return Err(Error::new("PRIVATE_FILE_SIZE"));
    }
    directory(path.parent().ok_or(Error::new("PRIVATE_PATH"))?)?;
    let temporary = path
        .parent()
        .ok_or(Error::new("PRIVATE_PATH"))?
        .join(format!(".pending-{}", uuid::Uuid::new_v4()));
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_CLOEXEC)
        .open(&temporary)?;
    file.write_all(&bytes)?;
    file.sync_all()?;
    let source = std::ffi::CString::new(temporary.as_os_str().as_encoded_bytes())
        .map_err(|_| Error::new("PRIVATE_PATH"))?;
    let destination = std::ffi::CString::new(path.as_os_str().as_encoded_bytes())
        .map_err(|_| Error::new("PRIVATE_PATH"))?;
    // SAFETY: paths are NUL-terminated, both belong to the validated private
    // directory. NOREPLACE publishes complete bytes without overwriting state.
    let renamed = unsafe {
        libc::renameat2(
            libc::AT_FDCWD,
            source.as_ptr(),
            libc::AT_FDCWD,
            destination.as_ptr(),
            libc::RENAME_NOREPLACE,
        )
    };
    if renamed != 0 {
        let _ = fs::remove_file(&temporary);
        return Err(Error::new("PRIVATE_FILE_ALREADY_EXISTS"));
    }
    File::open(path.parent().ok_or(Error::new("PRIVATE_PATH"))?)?.sync_all()?;
    Ok(())
}
