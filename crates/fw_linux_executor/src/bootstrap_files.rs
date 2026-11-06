//! Protected bootstrap inputs are opened before SQLite and never reopened.
use super::{Error, Result};
use std::{
    ffi::{CString, OsStr},
    fs::{File, OpenOptions},
    io::Write,
    os::{
        fd::{AsRawFd, FromRawFd},
        unix::{
            ffi::OsStrExt,
            fs::{DirBuilderExt, FileExt, MetadataExt, OpenOptionsExt},
        },
    },
    path::{Component, Path, PathBuf},
};
use zeroize::Zeroizing;

fn owner() -> u32 {
    unsafe { libc::geteuid() }
}
fn name(value: &OsStr) -> Result<CString> {
    CString::new(value.as_bytes()).map_err(|_| Error::new("BOOTSTRAP_PRIVATE_PATH"))
}
fn parent(path: &Path) -> Result<(File, CString)> {
    if !path.is_absolute() || !path.starts_with("/lab") {
        return Err(Error::new("BOOTSTRAP_PRIVATE_PATH"));
    }
    let components: Vec<_> = path.components().collect();
    let Some(Component::Normal(leaf)) = components.last() else {
        return Err(Error::new("BOOTSTRAP_PRIVATE_PATH"));
    };
    let mut directory = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open("/")?;
    let root = directory.metadata()?;
    if ![0, owner()].contains(&root.uid()) || root.mode() & 0o022 != 0 {
        return Err(Error::new("BOOTSTRAP_PRIVATE_PATH"));
    }
    for component in &components[1..components.len() - 1] {
        let Component::Normal(component) = component else {
            return Err(Error::new("BOOTSTRAP_PRIVATE_PATH"));
        };
        let component = name(component)?;
        // SAFETY: live directory and NUL-terminated name; O_DIRECTORY refuses
        // regular files without creating a leaf descriptor.
        let fd = unsafe {
            libc::openat(
                directory.as_raw_fd(),
                component.as_ptr(),
                libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
            )
        };
        if fd < 0 {
            return Err(Error::new("BOOTSTRAP_PRIVATE_PATH"));
        }
        // SAFETY: successful openat returned one newly owned descriptor.
        directory = unsafe { File::from_raw_fd(fd) };
        let meta = directory.metadata()?;
        if ![0, owner()].contains(&meta.uid()) || meta.mode() & 0o022 != 0 {
            return Err(Error::new("BOOTSTRAP_PRIVATE_PATH"));
        }
    }
    let meta = directory.metadata()?;
    if meta.uid() != owner() || meta.mode() & 0o077 != 0 {
        return Err(Error::new("BOOTSTRAP_PRIVATE_PATH"));
    }
    Ok((directory, name(leaf)?))
}
pub(super) fn directory(path: &Path) -> Result<()> {
    let _ = parent(&path.join("private-check"))?;
    Ok(())
}
pub(super) fn create_directory(path: &Path) -> Result<()> {
    let (parent, _) = parent(path)?;
    std::fs::DirBuilder::new().mode(0o700).create(path)?;
    parent.sync_all()?;
    directory(path)
}
pub(super) fn write_new(path: &Path, bytes: &[u8]) -> Result<()> {
    let (directory, leaf) = parent(path)?;
    // SAFETY: validated parent/name, exclusive private creation before SQLite.
    let fd = unsafe {
        libc::openat(
            directory.as_raw_fd(),
            leaf.as_ptr(),
            libc::O_WRONLY | libc::O_CREAT | libc::O_EXCL | libc::O_NOFOLLOW | libc::O_CLOEXEC,
            0o600,
        )
    };
    if fd < 0 {
        return Err(Error::new("BOOTSTRAP_PRIVATE_FILE"));
    }
    // SAFETY: successful openat returned one newly owned descriptor.
    let mut file = unsafe { File::from_raw_fd(fd) };
    file.write_all(bytes)?;
    file.sync_all()?;
    drop(file);
    directory.sync_all()?;
    Ok(())
}
fn inspect(directory: &File, leaf: &CString, maximum: usize) -> Result<(libc::dev_t, libc::ino_t)> {
    let mut meta = std::mem::MaybeUninit::<libc::stat>::uninit();
    loop {
        // SAFETY: valid parent/name and writable stat storage; no leaf opens.
        if unsafe {
            libc::fstatat(
                directory.as_raw_fd(),
                leaf.as_ptr(),
                meta.as_mut_ptr(),
                libc::AT_SYMLINK_NOFOLLOW,
            )
        } == 0
        {
            break;
        }
        if std::io::Error::last_os_error().kind() != std::io::ErrorKind::Interrupted {
            return Err(Error::new("BOOTSTRAP_PRIVATE_FILE"));
        }
    }
    // SAFETY: successful fstatat initialized every stat field.
    let meta = unsafe { meta.assume_init() };
    if meta.st_mode & libc::S_IFMT != libc::S_IFREG
        || meta.st_uid != owner()
        || meta.st_nlink != 1
        || meta.st_mode & 0o077 != 0
        || meta.st_mode & 0o400 == 0
        || meta.st_size < 0
        || meta.st_size as u64 > maximum as u64
    {
        return Err(Error::new("BOOTSTRAP_PRIVATE_FILE"));
    }
    Ok((meta.st_dev, meta.st_ino))
}
pub(super) struct Input {
    file: File,
    path: PathBuf,
    identity: (libc::dev_t, libc::ino_t),
    maximum: usize,
    bytes: Zeroizing<Vec<u8>>,
}
impl Input {
    pub(super) fn load(path: &Path, maximum: usize) -> Result<Self> {
        let (directory, leaf) = parent(path)?;
        let identity = inspect(&directory, &leaf, maximum)?;
        // This is called only before the bootstrap journal is opened.
        let fd = unsafe {
            libc::openat(
                directory.as_raw_fd(),
                leaf.as_ptr(),
                libc::O_RDONLY | libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_CLOEXEC,
            )
        };
        if fd < 0 {
            return Err(Error::new("BOOTSTRAP_PRIVATE_FILE"));
        }
        // SAFETY: successful openat returned one newly owned descriptor.
        let file = unsafe { File::from_raw_fd(fd) };
        let actual = file.metadata()?;
        if (actual.dev(), actual.ino()) != identity {
            return Err(Error::new("BOOTSTRAP_PRIVATE_FILE"));
        }
        let mut input = Self {
            file,
            path: path.into(),
            identity,
            maximum,
            bytes: Zeroizing::new(Vec::new()),
        };
        input.bytes = input.current()?;
        Ok(input)
    }
    fn current(&self) -> Result<Zeroizing<Vec<u8>>> {
        let (directory, leaf) = parent(&self.path)?;
        if inspect(&directory, &leaf, self.maximum)? != self.identity {
            return Err(Error::new("BOOTSTRAP_PRIVATE_FILE"));
        }
        let mut bytes = Zeroizing::new(vec![0; self.maximum + 1]);
        let mut offset = 0;
        loop {
            match self.file.read_at(&mut bytes[offset..], offset as u64) {
                Ok(0) => break,
                Ok(count) => {
                    offset += count;
                    if offset > self.maximum {
                        return Err(Error::new("BOOTSTRAP_PRIVATE_FILE"));
                    }
                }
                Err(error) if error.kind() == std::io::ErrorKind::Interrupted => {}
                Err(_) => return Err(Error::new("BOOTSTRAP_PRIVATE_FILE")),
            }
        }
        if inspect(&directory, &leaf, self.maximum)? != self.identity {
            return Err(Error::new("BOOTSTRAP_PRIVATE_FILE"));
        }
        bytes.truncate(offset);
        Ok(bytes)
    }
    pub(super) fn bytes(&self) -> &[u8] {
        &self.bytes
    }
    pub(super) fn recheck(&self) -> Result<()> {
        if *self.current()? != *self.bytes {
            return Err(Error::new("BOOTSTRAP_PRIVATE_FILE_CHANGED"));
        }
        Ok(())
    }
}
